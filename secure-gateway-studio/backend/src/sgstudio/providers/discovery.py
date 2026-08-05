from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import quote

from google.auth.exceptions import DefaultCredentialsError, RefreshError

from sgstudio.domain.models import (
    BackendKind,
    CertificateStrategy,
    DeploymentSpec,
    DiscoverySnapshot,
    NetworkStrategy,
    PreflightDiagnostic,
    PreflightResult,
)
from sgstudio.domain.naming import service_account_email, service_account_id
from sgstudio.domain.planner import (
    certificate_configuration_hash,
    required_apis,
    required_permissions,
)
from sgstudio.providers.certificates import CertificateIssuer
from sgstudio.providers.google_rest import (
    GoogleApiError,
    GoogleAuthorizedTransport,
    JsonTransport,
)
from sgstudio.providers.local_artifacts import CertificateArtifactStore

SECURE_GATEWAY_SOURCE_CIDR = "136.124.16.0/20"


class DiscoveryProvider(Protocol):
    def preflight(self, spec: DeploymentSpec) -> PreflightResult: ...


@dataclass(frozen=True)
class ResourceProbe:
    key: str
    url: str


class GoogleDiscoveryProvider:
    """Read-only discovery across GCP resources used by the desired-state planner."""

    def __init__(
        self,
        transport: JsonTransport,
        *,
        cloud_identity: str,
        credential_kind: str | None = None,
        quota_project_id: str | None = None,
        artifact_store: CertificateArtifactStore | None = None,
    ) -> None:
        self._transport = transport
        self._cloud_identity = cloud_identity
        self._credential_kind = credential_kind
        self._quota_project_id = quota_project_id
        self._artifact_store = artifact_store

    def preflight(self, spec: DeploymentSpec) -> PreflightResult:
        diagnostics: list[PreflightDiagnostic] = []
        enabled_apis: set[str] = set()
        existing_keys: set[str] = set()
        conflicting_keys: set[str] = set()
        granted_permissions: set[str] = set()
        billing_enabled: bool | None = None
        secret_name = (
            spec.public_certificate_secret.rsplit("/", maxsplit=1)[-1]
            if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            and spec.public_certificate_secret
            else f"{spec.name}-tls"
        )

        try:
            enabled_apis = self._enabled_apis(spec.project_id)
            if enabled_apis >= required_apis(spec):
                existing_keys.add("serviceusage:project_services:required-apis")
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("service-usage", error))
        try:
            granted_permissions = self._granted_permissions(
                spec.project_id, required_permissions(spec)
            )
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("project-permissions", error))
        try:
            billing_enabled = self._billing_enabled(spec.project_id)
            if not billing_enabled:
                diagnostics.append(
                    PreflightDiagnostic(
                        code="billing-disabled",
                        severity="error",
                        message="The deployment project has no active billing association.",
                        remediation=("Link an active billing account to the project before Apply."),
                    )
                )
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("cloud-billing", error))

        for probe in self._resource_probes(spec):
            try:
                status_code, payload = self._transport.request_json(
                    "GET",
                    probe.url,
                    accepted_statuses=(200, 404),
                )
                if status_code == 200:
                    if self._compatible(probe.key, payload, spec):
                        existing_keys.add(probe.key)
                        if probe.key.startswith("accesscontextmanager:access_level:"):
                            granted_permissions.add(
                                "accesscontextmanager.accessLevels.get"
                            )
                    else:
                        conflicting_keys.add(probe.key)
            except GoogleApiError as error:
                diagnostics.append(self._api_diagnostic(probe.key, error))

        if spec.backend_kind is not BackendKind.DIRECT_HTTPS:
            self._discover_local_poc_certificate(
                spec,
                secret_name,
                existing_keys,
                diagnostics,
            )
            self._discover_dns_record(
                spec,
                existing_keys,
                conflicting_keys,
                diagnostics,
            )
        self._discover_iam_bindings(spec, existing_keys, diagnostics)
        self._discover_chrome_policies(spec, existing_keys, diagnostics)
        chrome_extension_group_conflicts = self._discover_chrome_group_policy_conflicts(
            spec,
            conflicting_keys,
            diagnostics,
        )
        (
            managed_chrome_profile_count,
            profile_only_count,
            latest_chrome_policy_sync,
            endpoint_verification_installed,
            secure_enterprise_browser_installed,
            endpoint_verification_version,
            secure_enterprise_browser_version,
        ) = self._discover_chrome_profile_readiness(spec, diagnostics)
        chrome_enterprise_premium_license_count = (
            self._discover_chrome_enterprise_premium_licenses(spec, diagnostics)
        )
        # Public Chrome APIs do not expose the Admin-console Root Store
        # certificate details or the OU binding reliably enough to attest this
        # manual handoff. End-to-end trust is verified by the selected
        # platform's operator-confirmed T07 result instead.
        chrome_root_store_config_count = None
        chrome_root_store_config_names: list[str] = []
        chrome_root_store_enabled = self._discover_chrome_root_store_enabled(
            spec,
            diagnostics,
        )

        if (
            spec.backend_kind is not BackendKind.DIRECT_HTTPS
            and
            spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            and spec.public_certificate_secret
        ):
            secret_key = f"secretmanager:secret:{secret_name}"
            try:
                self._validate_certificate_secret(spec, secret_name)
            except GoogleApiError as error:
                conflicting_keys.add(secret_key)
                diagnostics.append(self._api_diagnostic(secret_key, error))
            except ValueError as error:
                conflicting_keys.add(secret_key)
                diagnostics.append(
                    PreflightDiagnostic(
                        code="invalid-public-certificate-secret",
                        severity="error",
                        message="The referenced TLS secret failed certificate validation.",
                        remediation=str(error),
                    )
                )
        elif (
            spec.backend_kind is not BackendKind.DIRECT_HTTPS
            and
            spec.certificate_strategy is CertificateStrategy.ENTERPRISE_CA
            and f"secretmanager:secret:{secret_name}" in existing_keys
        ):
            version_key = f"secretmanager:secret_version:{secret_name}"
            try:
                _, metadata = self._transport.request_json(
                    "GET",
                    (
                        f"https://secretmanager.googleapis.com/v1/projects/"
                        f"{spec.project_id}/secrets/{secret_name}"
                    ),
                )
                aliases = metadata.get("versionAliases")
                active_version = aliases.get("active") if isinstance(aliases, dict) else None
                if not isinstance(active_version, str) or not active_version:
                    self._validate_certificate_secret(
                        spec,
                        secret_name,
                        version="latest",
                    )
                    diagnostics.append(
                        PreflightDiagnostic(
                            code="managed-certificate-alias-migration-required",
                            severity="warning",
                            message=(
                                "The managed TLS secret does not have an active version alias."
                            ),
                            remediation=(
                                "Approve a new certificate version; Apply will "
                                "create the active alias before restarting the "
                                "offload tier."
                            ),
                        )
                    )
                else:
                    self._validate_certificate_secret(
                        spec,
                        secret_name,
                        version="active",
                    )
                    existing_keys.add(version_key)
            except GoogleApiError as error:
                if error.status_code != 404:
                    conflicting_keys.add(version_key)
                    diagnostics.append(self._api_diagnostic(version_key, error))
            except ValueError as error:
                if "expires too soon" in str(error):
                    diagnostics.append(
                        PreflightDiagnostic(
                            code="managed-certificate-rotation-required",
                            severity="warning",
                            message=(
                                "The existing managed TLS certificate is inside "
                                "the Production rotation window."
                            ),
                            remediation=(
                                "Approve the planned certificate issuance and "
                                "Secret Manager version rotation."
                            ),
                        )
                    )
                else:
                    conflicting_keys.add(version_key)
                    diagnostics.append(
                        PreflightDiagnostic(
                            code="invalid-managed-certificate-secret",
                            severity="error",
                            message=("The existing app-managed TLS secret failed validation."),
                            remediation=str(error),
                        )
                    )

        if spec.backend_kind is not BackendKind.DIRECT_HTTPS:
            try:
                if self._cloud_nat_exists(spec):
                    existing_keys.add(f"compute:cloud_nat:{spec.name}-nat")
            except GoogleApiError as error:
                diagnostics.append(self._api_diagnostic("compute:cloud_nat", error))
        private_egress_available: bool | None = None
        if (
            spec.network_strategy is NetworkStrategy.EXISTING
            and spec.backend_kind is not BackendKind.DIRECT_HTTPS
        ):
            try:
                private_egress_available = self._existing_private_egress_available(spec)
            except GoogleApiError as error:
                diagnostics.append(self._api_diagnostic("compute:private-egress", error))

        diagnostics.append(
            PreflightDiagnostic(
                code="workspace-oauth-required",
                severity="warning",
                message=(
                    "Google Cloud ADC is valid; the impersonated service account's "
                    "Chrome administrator role still requires validation."
                ),
                remediation=(
                    "Assign the service account a Chrome admin role for the test OU, "
                    "then validate Chrome Policy API access before Apply."
                ),
            )
        )
        return PreflightResult(
            snapshot=DiscoverySnapshot(
                existing_resource_keys=existing_keys,
                conflicting_resource_keys=conflicting_keys,
                enabled_apis=enabled_apis,
                granted_permissions=granted_permissions,
                cloud_identity=self._cloud_identity,
                workspace_identity=None,
                private_egress_available=private_egress_available,
                billing_enabled=billing_enabled,
                managed_chrome_profile_count=managed_chrome_profile_count,
                profile_only_count=profile_only_count,
                latest_chrome_policy_sync=latest_chrome_policy_sync,
                endpoint_verification_installed=endpoint_verification_installed,
                secure_enterprise_browser_installed=secure_enterprise_browser_installed,
                endpoint_verification_version=endpoint_verification_version,
                secure_enterprise_browser_version=secure_enterprise_browser_version,
                chrome_extension_group_conflicts=chrome_extension_group_conflicts,
                chrome_enterprise_premium_license_count=(
                    chrome_enterprise_premium_license_count
                ),
                chrome_root_store_config_count=chrome_root_store_config_count,
                chrome_root_store_config_names=chrome_root_store_config_names,
                chrome_root_store_enabled=chrome_root_store_enabled,
            ),
            diagnostics=diagnostics,
            credential_kind=self._credential_kind,
            quota_project_id=self._quota_project_id,
        )

    def _enabled_apis(self, project_id: str) -> set[str]:
        enabled: set[str] = set()
        page_token: str | None = None
        for _ in range(10):
            params: dict[str, str | int] = {
                "filter": "state:ENABLED",
                "pageSize": 200,
            }
            if page_token:
                params["pageToken"] = page_token
            _, payload = self._transport.request_json(
                "GET",
                f"https://serviceusage.googleapis.com/v1/projects/{project_id}/services",
                params=params,
            )
            services = payload.get("services", [])
            if isinstance(services, list):
                for service in services:
                    if isinstance(service, dict):
                        name = service.get("config", {}).get("name")
                        if isinstance(name, str):
                            enabled.add(name)
            next_page = payload.get("nextPageToken")
            if not isinstance(next_page, str) or not next_page:
                break
            page_token = next_page
        return enabled

    def _billing_enabled(self, project_id: str) -> bool:
        _, payload = self._transport.request_json(
            "GET",
            (
                f"https://cloudbilling.googleapis.com/v1/projects/"
                f"{project_id}/billingInfo"
            ),
        )
        return payload.get("billingEnabled") is True

    def _validate_certificate_secret(
        self,
        spec: DeploymentSpec,
        secret_name: str,
        *,
        version: str = "latest",
    ) -> None:
        _, payload = self._transport.request_json(
            "GET",
            (
                f"https://secretmanager.googleapis.com/v1/projects/{spec.project_id}/"
                f"secrets/{secret_name}/versions/{version}:access"
            ),
        )
        secret_payload = payload.get("payload")
        encoded = secret_payload.get("data") if isinstance(secret_payload, dict) else None
        if not isinstance(encoded, str):
            raise ValueError("Secret Manager response is missing payload.data")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("Secret Manager payload is not valid base64") from error
        CertificateIssuer.validate_secret_payload(
            decoded,
            hostname=spec.private_hostname,
            minimum_validity_days=30 if spec.mode.value == "production" else 1,
        )

    def _granted_permissions(self, project_id: str, permissions: set[str]) -> set[str]:
        project_permissions = sorted(
            permissions - {"accesscontextmanager.accessLevels.get"}
        )
        granted: set[str] = set()
        for offset in range(0, len(project_permissions), 100):
            _, payload = self._transport.request_json(
                "POST",
                (
                    f"https://cloudresourcemanager.googleapis.com/v1/projects/"
                    f"{project_id}:testIamPermissions"
                ),
                json_body={"permissions": project_permissions[offset : offset + 100]},
            )
            returned = payload.get("permissions", [])
            if isinstance(returned, list):
                granted.update(item for item in returned if isinstance(item, str))
        return granted

    def _discover_local_poc_certificate(
        self,
        spec: DeploymentSpec,
        secret_name: str,
        existing_keys: set[str],
        diagnostics: list[PreflightDiagnostic],
    ) -> None:
        if spec.certificate_strategy is not CertificateStrategy.LOCAL_POC:
            return
        secret_key = f"secretmanager:secret:{secret_name}"
        if secret_key not in existing_keys:
            return
        try:
            status_code, metadata = self._transport.request_json(
                "GET",
                (
                    f"https://secretmanager.googleapis.com/v1/projects/"
                    f"{spec.project_id}/secrets/{secret_name}"
                ),
                accepted_statuses=(200, 404),
            )
            if status_code == 404:
                return
            aliases = metadata.get("versionAliases")
            labels = metadata.get("labels")
            active = aliases.get("active") if isinstance(aliases, dict) else None
            certificate_hash = (
                labels.get("certificate-spec-hash") if isinstance(labels, dict) else None
            )
            matches = (
                isinstance(active, str)
                and bool(active)
                and isinstance(labels, dict)
                and labels.get("managed-by") == "secure-gateway-studio"
                and (
                    certificate_hash is None
                    or certificate_hash == certificate_configuration_hash(spec)[:32]
                )
            )
            if not matches:
                return
            if self._artifact_store is None:
                return
            certificate = self._artifact_store.read_root_certificate(spec.name)
            if not certificate.startswith(b"-----BEGIN CERTIFICATE-----\n"):
                raise ValueError("PoC root artifact is not a PEM certificate")
            existing_keys.add(f"secretmanager:secret_version:{secret_name}")
            existing_keys.add(f"local:root_certificate_artifact:{spec.name}-poc-root")
        except FileNotFoundError:
            diagnostics.append(
                PreflightDiagnostic(
                    code="poc-root-artifact-missing",
                    severity="warning",
                    message="The active PoC certificate has no matching local root artifact.",
                    remediation=(
                        "Approve certificate rotation so Apply can export a new public root."
                    ),
                )
            )
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("secretmanager:secret_version", error))
        except ValueError as error:
            diagnostics.append(
                PreflightDiagnostic(
                    code="invalid-poc-root-artifact",
                    severity="warning",
                    message="The local PoC root artifact is invalid.",
                    remediation=str(error),
                )
            )

    def _discover_dns_record(
        self,
        spec: DeploymentSpec,
        existing_keys: set[str],
        conflicting_keys: set[str],
        diagnostics: list[PreflightDiagnostic],
    ) -> None:
        zone_key = f"dns:private_zone:{spec.name}-zone"
        if zone_key not in existing_keys:
            return
        record_key = f"dns:record_set:{spec.private_hostname}"
        try:
            address_status, address = self._transport.request_json(
                "GET",
                (
                    f"https://compute.googleapis.com/compute/v1/projects/"
                    f"{spec.project_id}/regions/{spec.region}/addresses/"
                    f"{spec.name}-offload-ip"
                ),
                accepted_statuses=(200, 404),
            )
            record_name = quote(f"{spec.private_hostname}.", safe="")
            record_status, record = self._transport.request_json(
                "GET",
                (
                    f"https://dns.googleapis.com/dns/v1/projects/{spec.project_id}/"
                    f"managedZones/{spec.name}-zone/rrsets/{record_name}/A"
                ),
                accepted_statuses=(200, 404),
            )
            if address_status == 404 or record_status == 404:
                return
            expected_address = address.get("address")
            if (
                isinstance(expected_address, str)
                and record.get("name") == f"{spec.private_hostname}."
                and record.get("type") == "A"
                and record.get("rrdatas") == [expected_address]
            ):
                existing_keys.add(record_key)
            else:
                conflicting_keys.add(record_key)
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic(record_key, error))

    @staticmethod
    def _policy_has_binding(
        policy: dict[str, object],
        *,
        role: str,
        members: set[str],
        condition: dict[str, str] | None = None,
    ) -> bool:
        bindings = policy.get("bindings")
        if not isinstance(bindings, list):
            return False
        return any(
            isinstance(binding, dict)
            and binding.get("role") == role
            and binding.get("condition") == condition
            and members
            <= {
                member
                for member in binding.get("members", [])
                if isinstance(member, str)
            }
            for binding in bindings
        )

    def _discover_iam_binding(
        self,
        *,
        key: str,
        method: str,
        url: str,
        role: str,
        members: set[str],
        existing_keys: set[str],
        diagnostics: list[PreflightDiagnostic],
        condition: dict[str, str] | None = None,
        body: dict[str, object] | None = None,
    ) -> None:
        try:
            status_code, policy = self._transport.request_json(
                method,
                url,
                json_body=body,
                accepted_statuses=(200, 404),
            )
            if status_code == 200 and self._policy_has_binding(
                policy,
                role=role,
                members=members,
                condition=condition,
            ):
                existing_keys.add(key)
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic(key, error))

    def _discover_iam_bindings(
        self,
        spec: DeploymentSpec,
        existing_keys: set[str],
        diagnostics: list[PreflightDiagnostic],
    ) -> None:
        members = {principal.iam_member for principal in spec.principals}
        gateway = (
            f"https://beyondcorp.googleapis.com/v1/projects/{spec.project_id}/"
            f"locations/global/securityGateways/{spec.gateway_id}"
        )
        secret_name = (
            spec.public_certificate_secret.rsplit("/", maxsplit=1)[-1]
            if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            and spec.public_certificate_secret
            else f"{spec.name}-tls"
        )
        if spec.backend_kind is not BackendKind.DIRECT_HTTPS:
            secret = (
                f"https://secretmanager.googleapis.com/v1/projects/{spec.project_id}/"
                f"secrets/{secret_name}"
            )
            self._discover_iam_binding(
                key=f"secretmanager:secret_iam:{spec.name}-tls-accessor",
                method="GET",
                url=f"{secret}:getIamPolicy",
                role="roles/secretmanager.secretAccessor",
                members={
                    "serviceAccount:"
                    + service_account_email(spec.name, spec.project_id, "offload")
                },
                existing_keys=existing_keys,
                diagnostics=diagnostics,
            )
        self._discover_iam_binding(
            key=f"beyondcorp:gateway_iam:{spec.gateway_id}-service-discovery-users",
            method="GET",
            url=f"{gateway}:getIamPolicy",
            role="roles/beyondcorp.serviceDiscoveryUser",
            members=members,
            existing_keys=existing_keys,
            diagnostics=diagnostics,
        )
        gateway_account: str | None = None
        try:
            status_code, payload = self._transport.request_json(
                "GET", gateway, accepted_statuses=(200, 404)
            )
            account = payload.get("delegatingServiceAccount")
            if status_code == 200 and isinstance(account, str):
                gateway_account = account
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("beyondcorp:security_gateway", error))
        if gateway_account:
            self._discover_iam_binding(
                key=f"cloudresourcemanager:project_iam:{spec.name}-upstream-access",
                method="POST",
                url=(
                    f"https://cloudresourcemanager.googleapis.com/v1/projects/"
                    f"{spec.project_id}:getIamPolicy"
                ),
                body={},
                role="roles/beyondcorp.upstreamAccess",
                members={f"serviceAccount:{gateway_account}"},
                existing_keys=existing_keys,
                diagnostics=diagnostics,
            )
        condition = (
            {
                "title": "Managed Chrome required",
                "description": "Allow only profiles or browsers managed by this enterprise",
                "expression": (
                    f"'{spec.managed_chrome_access_level}' in request.auth.access_levels"
                ),
            }
            if spec.managed_chrome_access_level
            else None
        )
        self._discover_iam_binding(
            key=f"beyondcorp:application_iam:{spec.name}-app-access",
            method="GET",
            url=f"{gateway}/applications/{spec.name}-app:getIamPolicy",
            role="roles/beyondcorp.sgApplicationUser",
            members=members,
            condition=condition,
            existing_keys=existing_keys,
            diagnostics=diagnostics,
        )

    def _resolve_chrome_policy(
        self,
        spec: DeploymentSpec,
        *,
        schema: str,
        app_id: str,
    ) -> dict[str, object] | None:
        _, payload = self._transport.request_json(
            "POST",
            (
                f"https://chromepolicy.googleapis.com/v1/customers/"
                f"{spec.customer_id}/policies:resolve"
            ),
            json_body={
                "policyTargetKey": {
                    "targetResource": f"orgunits/{spec.target_ou_id}",
                    "additionalTargetKeys": {"app_id": f"chrome:{app_id}"},
                },
                "policySchemaFilter": schema,
            },
        )
        policies = payload.get("resolvedPolicies")
        if not isinstance(policies, list):
            return None
        for policy in policies:
            source_key = policy.get("sourceKey") if isinstance(policy, dict) else None
            if isinstance(source_key, dict) and source_key.get("targetResource") == (
                f"orgunits/{spec.target_ou_id}"
            ):
                value = policy.get("value", {}).get("value")
                return value if isinstance(value, dict) else None
        return None

    def _resolve_chrome_user_policy(
        self,
        spec: DeploymentSpec,
        *,
        schema: str,
    ) -> tuple[dict[str, object] | None, str | None]:
        _, payload = self._transport.request_json(
            "POST",
            (
                f"https://chromepolicy.googleapis.com/v1/customers/"
                f"{spec.customer_id}/policies:resolve"
            ),
            json_body={
                "policyTargetKey": {
                    "targetResource": f"orgunits/{spec.target_ou_id}",
                },
                "policySchemaFilter": schema,
            },
        )
        policies = payload.get("resolvedPolicies")
        if not isinstance(policies, list):
            return None, None
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            policy_value = policy.get("value")
            value = policy_value.get("value") if isinstance(policy_value, dict) else None
            source_key = policy.get("sourceKey")
            source = (
                source_key.get("targetResource")
                if isinstance(source_key, dict)
                else None
            )
            return (value if isinstance(value, dict) else None), (
                source if isinstance(source, str) else None
            )
        return None, None

    def _discover_chrome_policies(
        self,
        spec: DeploymentSpec,
        existing_keys: set[str],
        diagnostics: list[PreflightDiagnostic],
    ) -> None:
        companion = "ekajlcmdfcigmdbphhifahdfjbkciflj"
        endpoint_verification = "callobklhcbilhphinckomhgkigmfocg"
        for app_id in (companion, endpoint_verification):
            key = f"chromepolicy:extension_install:{app_id}"
            try:
                value = self._resolve_chrome_policy(
                    spec,
                    schema="chrome.users.apps.InstallType",
                    app_id=app_id,
                )
                if value and value.get("appInstallType") == "FORCED":
                    existing_keys.add(key)
            except GoogleApiError as error:
                diagnostics.append(self._api_diagnostic(key, error))

        proxy_key = f"chromepolicy:service_discovery_proxy:{spec.target_ou_id}"
        try:
            value, source = self._resolve_chrome_user_policy(
                spec,
                schema="chrome.users.SimpleProxySettings",
            )
            mode = value.get("simpleProxyMode") if value else None
            if mode != "PROXY_MODE_ENUM_PAC_SCRIPT":
                existing_keys.add(proxy_key)
            else:
                pac_url = value.get("simpleProxyPacUrl") if value else None
                diagnostics.append(
                    PreflightDiagnostic(
                        code="legacy-pac-policy-detected",
                        severity="warning",
                        message=(
                            "An inherited legacy PAC policy is active for the test OU "
                            f"from {source or 'an unknown source'} "
                            f"({pac_url if isinstance(pac_url, str) else 'unknown URL'})."
                        ),
                        remediation=(
                            "A hostname omitted from the PAC falls through to DIRECT and "
                            "can fail with ERR_NAME_NOT_RESOLVED on private DNS. Apply will "
                            "override SimpleProxySettings to Allow user to configure only "
                            "in the test OU so Service Discovery can capture private routes."
                        ),
                    )
                )
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic(proxy_key, error))

        configuration_key = f"chromepolicy:extension_configuration:{companion}"
        try:
            value = self._resolve_chrome_policy(
                spec,
                schema="chrome.users.apps.ManagedConfiguration",
                app_id=companion,
            )
            encoded = value.get("managedConfiguration") if value else None
            decoded = json.loads(encoded) if isinstance(encoded, str) else None
            resource = (
                decoded.get("securityGateway", {})
                .get("Value", {})
                .get("context", {})
                .get("resource")
                if isinstance(decoded, dict)
                else None
            )
            expected = (
                f"projects/{spec.project_id}/locations/global/"
                f"securityGateways/{spec.gateway_id}"
            )
            if resource == expected:
                existing_keys.add(configuration_key)
        except (GoogleApiError, json.JSONDecodeError) as error:
            if isinstance(error, GoogleApiError):
                diagnostics.append(self._api_diagnostic(configuration_key, error))
            else:
                diagnostics.append(
                    PreflightDiagnostic(
                        code="invalid-chrome-managed-configuration",
                        severity="warning",
                        message="The existing Chrome extension configuration is invalid JSON.",
                        remediation=(
                            "Apply will replace it with the approved gateway configuration."
                        ),
                    )
                )

    def _discover_chrome_group_policy_conflicts(
        self,
        spec: DeploymentSpec,
        conflicting_keys: set[str],
        diagnostics: list[PreflightDiagnostic],
    ) -> list[str]:
        """Find group app policies that take precedence over the selected OU."""

        group_principals = {
            principal.value
            for principal in spec.principals
            if principal.type.value == "group"
        }
        user_principals = {
            principal.value
            for principal in spec.principals
            if principal.type.value == "user"
        }
        if not group_principals and not user_principals:
            return []

        groups: list[dict[str, object]] = []
        page_token = ""
        try:
            while len(groups) < 2000:
                params: dict[str, str | int] = {
                    "customer": spec.customer_id,
                    "maxResults": 200,
                    "orderBy": "email",
                }
                if page_token:
                    params["pageToken"] = page_token
                _, payload = self._transport.request_json(
                    "GET",
                    "https://admin.googleapis.com/admin/directory/v1/groups",
                    params=params,
                )
                groups.extend(
                    item for item in payload.get("groups", []) if isinstance(item, dict)
                )
                next_token = payload.get("nextPageToken")
                if not isinstance(next_token, str) or not next_token:
                    break
                page_token = next_token
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("chrome-group-policy-membership", error))
            return []

        candidate_groups: dict[str, str] = {}
        for group in groups:
            email = group.get("email")
            group_id = group.get("id")
            if not isinstance(email, str) or not isinstance(group_id, str):
                continue
            normalized_email = email.lower()
            if normalized_email in group_principals:
                candidate_groups[normalized_email] = group_id
                continue
            for user_email in user_principals:
                try:
                    _, membership = self._transport.request_json(
                        "GET",
                        (
                            "https://admin.googleapis.com/admin/directory/v1/groups/"
                            f"{quote(normalized_email, safe='')}/hasMember/"
                            f"{quote(user_email, safe='')}"
                        ),
                    )
                except GoogleApiError as error:
                    diagnostics.append(
                        self._api_diagnostic("chrome-group-policy-membership", error)
                    )
                    continue
                if membership.get("isMember") is True:
                    candidate_groups[normalized_email] = group_id
                    break

        expected_resource = (
            f"projects/{spec.project_id}/locations/global/"
            f"securityGateways/{spec.gateway_id}"
        )
        conflicts: list[str] = []
        for email, group_id in sorted(candidate_groups.items()):
            try:
                value = self._resolve_chrome_policy_target(
                    spec,
                    schema="chrome.users.apps.ManagedConfiguration",
                    app_id="ekajlcmdfcigmdbphhifahdfjbkciflj",
                    target_resource=f"groups/{group_id}",
                )
            except GoogleApiError as error:
                diagnostics.append(self._api_diagnostic("chrome-group-policy", error))
                continue
            encoded = value.get("managedConfiguration") if value else None
            if not isinstance(encoded, str):
                continue
            try:
                decoded = json.loads(encoded)
            except json.JSONDecodeError:
                decoded = None
            resource = (
                decoded.get("securityGateway", {})
                .get("Value", {})
                .get("context", {})
                .get("resource")
                if isinstance(decoded, dict)
                else None
            )
            if resource == expected_resource:
                continue
            conflicts.append(email)
            conflicting_keys.add(
                f"chromepolicy:group_extension_configuration:{email}"
            )
            diagnostics.append(
                PreflightDiagnostic(
                    code="chrome-extension-group-policy-conflict",
                    severity="error",
                    message=(
                        f"Group {email} overrides Secure Enterprise Browser managed "
                        "configuration for an approved principal."
                    ),
                    remediation=(
                        "Review the group-scoped app configuration. Remove the empty or "
                        "incompatible override, or set it to the same Secure Gateway "
                        "configuration as the target OU before approving Apply."
                    ),
                )
            )
        return conflicts

    def _resolve_chrome_policy_target(
        self,
        spec: DeploymentSpec,
        *,
        schema: str,
        app_id: str,
        target_resource: str,
    ) -> dict[str, object] | None:
        _, payload = self._transport.request_json(
            "POST",
            (
                f"https://chromepolicy.googleapis.com/v1/customers/"
                f"{spec.customer_id}/policies:resolve"
            ),
            json_body={
                "policyTargetKey": {
                    "targetResource": target_resource,
                    "additionalTargetKeys": {"app_id": f"chrome:{app_id}"},
                },
                "policySchemaFilter": schema,
            },
        )
        policies = payload.get("resolvedPolicies")
        if not isinstance(policies, list):
            return None
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            source_key = policy.get("sourceKey")
            if not isinstance(source_key, dict) or source_key.get("targetResource") != (
                target_resource
            ):
                continue
            policy_value = policy.get("value")
            value = policy_value.get("value") if isinstance(policy_value, dict) else None
            return value if isinstance(value, dict) else None
        return None

    def _discover_chrome_profile_readiness(
        self,
        spec: DeploymentSpec,
        diagnostics: list[PreflightDiagnostic],
    ) -> tuple[
        int | None,
        int | None,
        str | None,
        bool | None,
        bool | None,
        str | None,
        str | None,
    ]:
        endpoint_verification_id = "callobklhcbilhphinckomhgkigmfocg"
        secure_enterprise_browser_id = "ekajlcmdfcigmdbphhifahdfjbkciflj"
        try:
            _, payload = self._transport.request_json(
                "GET",
                (
                    f"https://chromemanagement.googleapis.com/v1/customers/"
                    f"{spec.customer_id}/profiles"
                ),
                params={
                    "pageSize": 200,
                    "filter": f"ouId = {spec.target_ou_id}",
                    "orderBy": "lastPolicySyncTime desc",
                },
            )
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("chrome-profile-readiness", error))
            return None, None, None, None, None, None, None

        profiles = payload.get("chromeBrowserProfiles")
        if not isinstance(profiles, list):
            profiles = []
        managed_profiles = [profile for profile in profiles if isinstance(profile, dict)]
        profile_only_count = sum(
            profile.get("affiliationState") == "PROFILE_ONLY"
            for profile in managed_profiles
        )
        sync_times = [
            value
            for profile in managed_profiles
            if isinstance((value := profile.get("lastPolicySyncTime")), str)
            and value
        ]
        latest_sync = max(sync_times) if sync_times else None

        extension_versions: dict[str, str] = {}
        for profile in managed_profiles:
            reporting = profile.get("reportingData")
            extensions = (
                reporting.get("extensionData") if isinstance(reporting, dict) else None
            )
            if not isinstance(extensions, list):
                continue
            for extension in extensions:
                if not isinstance(extension, dict) or extension.get("isDisabled") is True:
                    continue
                extension_id = extension.get("extensionId")
                version = extension.get("version")
                if isinstance(extension_id, str):
                    extension_versions[extension_id] = (
                        version if isinstance(version, str) else "installed"
                    )

        return (
            len(managed_profiles),
            profile_only_count,
            latest_sync,
            endpoint_verification_id in extension_versions,
            secure_enterprise_browser_id in extension_versions,
            extension_versions.get(endpoint_verification_id),
            extension_versions.get(secure_enterprise_browser_id),
        )

    def _discover_chrome_enterprise_premium_licenses(
        self,
        spec: DeploymentSpec,
        diagnostics: list[PreflightDiagnostic],
    ) -> int | None:
        """Count API-visible Chrome Enterprise Premium user assignments."""

        count = 0
        page_token: str | None = None
        try:
            for _ in range(20):
                params: dict[str, str | int] = {
                    "customerId": spec.customer_id,
                    "maxResults": 1000,
                }
                if page_token:
                    params["pageToken"] = page_token
                _, payload = self._transport.request_json(
                    "GET",
                    (
                        "https://licensing.googleapis.com/apps/licensing/v1/"
                        "product/101040/sku/1010400001/users"
                    ),
                    params=params,
                    accepted_statuses=(200, 404),
                )
                items = payload.get("items")
                if isinstance(items, list):
                    count += sum(isinstance(item, dict) for item in items)
                next_token = payload.get("nextPageToken")
                if not isinstance(next_token, str) or not next_token:
                    break
                page_token = next_token
        except GoogleApiError as error:
            del error
            diagnostics.append(
                PreflightDiagnostic(
                    code="chrome-enterprise-premium-manual-confirmation",
                    severity="info",
                    message=(
                        "Chrome Enterprise Premium entitlement could not be reliably "
                        "verified through the Enterprise License Manager API."
                    ),
                    remediation=(
                        "Confirm the target users' license or domain-wide entitlement "
                        "in Google Admin console."
                    ),
                )
            )
            return None
        if count == 0:
            diagnostics.append(
                PreflightDiagnostic(
                    code="chrome-enterprise-premium-license-not-detected",
                    severity="warning",
                    message=(
                        "No Chrome Enterprise Premium user assignment was returned by "
                        "the Enterprise License Manager API."
                    ),
                    remediation=(
                        "Assign Chrome Enterprise Premium SKU 1010400001 to at least "
                        "one target user, or verify a domain-wide entitlement in Admin console."
                    ),
                )
            )
        return count

    def _discover_chrome_root_store_enabled(
        self,
        spec: DeploymentSpec,
        diagnostics: list[PreflightDiagnostic],
    ) -> bool | None:
        """Return an explicit Root Store policy value; None means Chrome default."""

        try:
            value, source = self._resolve_chrome_user_policy(
                spec,
                schema="chrome.users.ChromeRootStoreEnabled",
            )
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("chrome-root-store-policy", error))
            return None
        selection = value.get("chromeRootStoreEnabled") if value else None
        if selection == "TRUE":
            return True
        if selection == "FALSE":
            diagnostics.append(
                PreflightDiagnostic(
                    code="chrome-root-store-disabled",
                    severity="warning",
                    message=(
                        "Chrome Root Store is explicitly disabled for the selected OU "
                        f"by {source or 'an unresolved policy source'}."
                    ),
                    remediation=(
                        "Set Chrome Root Store and certificate verifier to Use the Chrome "
                        "Root Store for the test OU, or restore the Chrome default."
                    ),
                )
            )
            return False
        return None

    def _resource_probes(self, spec: DeploymentSpec) -> Iterable[ResourceProbe]:
        project = spec.project_id
        prefix = spec.name
        region = spec.region
        zone = spec.zone
        network_name = (
            f"{prefix}-vpc"
            if spec.network_strategy is NetworkStrategy.DEDICATED
            else spec.vpc_name or "unresolved"
        )
        network_shared = spec.network_strategy is NetworkStrategy.EXISTING
        if spec.managed_chrome_access_level:
            yield ResourceProbe(
                (f"accesscontextmanager:access_level:{spec.managed_chrome_access_level}"),
                (
                    "https://accesscontextmanager.googleapis.com/v1/"
                    f"{spec.managed_chrome_access_level}"
                ),
            )
        if spec.source_image:
            yield ResourceProbe(
                f"compute:source_image:{spec.source_image}",
                f"https://compute.googleapis.com/compute/v1/{spec.source_image}",
            )
        yield ResourceProbe(
            f"compute:network:{network_name}",
            f"https://compute.googleapis.com/compute/v1/projects/{project}/global/networks/"
            f"{network_name}",
        )
        if spec.backend_kind is BackendKind.DIRECT_HTTPS:
            gateway_parent = (
                f"https://beyondcorp.googleapis.com/v1/projects/{project}/locations/global/"
                f"securityGateways/{spec.gateway_id}"
            )
            yield ResourceProbe(
                f"beyondcorp:security_gateway:{spec.gateway_id}",
                gateway_parent,
            )
            yield ResourceProbe(
                f"beyondcorp:application:{prefix}-app",
                f"{gateway_parent}/applications/{prefix}-app",
            )
            return
        if not network_shared:
            yield ResourceProbe(
                f"compute:subnetwork:{prefix}-subnet",
                f"https://compute.googleapis.com/compute/v1/projects/{project}/regions/{region}/"
                f"subnetworks/{prefix}-subnet",
            )
            yield ResourceProbe(
                f"compute:router:{prefix}-router",
                f"https://compute.googleapis.com/compute/v1/projects/{project}/regions/{region}/"
                f"routers/{prefix}-router",
            )
        else:
            yield ResourceProbe(
                f"compute:subnetwork:{spec.subnet_name}",
                (
                    f"https://compute.googleapis.com/compute/v1/projects/{project}/"
                    f"regions/{region}/subnetworks/{spec.subnet_name}"
                ),
            )

        if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
            yield ResourceProbe(
                f"compute:subnetwork:{prefix}-proxy-subnet",
                (
                    f"https://compute.googleapis.com/compute/v1/projects/{project}/"
                    f"regions/{region}/subnetworks/{prefix}-proxy-subnet"
                ),
            )

        service_account_suffixes = (
            ("backend",)
            if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB
            else ("offload", "backend")
        )
        for suffix in service_account_suffixes:
            if suffix == "backend" and spec.backend_kind not in {
                BackendKind.MANAGED_SAMPLE,
                BackendKind.INTERNAL_HTTPS_LB,
            }:
                continue
            account_id = service_account_id(prefix, suffix)
            email = quote(f"{account_id}@{project}.iam.gserviceaccount.com", safe="")
            yield ResourceProbe(
                f"iam:service_account:{account_id}",
                f"https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/{email}",
            )

        secret_name = (
            spec.public_certificate_secret.rsplit("/", maxsplit=1)[-1]
            if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            and spec.public_certificate_secret
            else f"{prefix}-tls"
        )
        yield ResourceProbe(
            f"secretmanager:secret:{secret_name}",
            (f"https://secretmanager.googleapis.com/v1/projects/{project}/secrets/{secret_name}"),
        )
        for suffix in ("offload", "backend"):
            if suffix == "backend" and spec.backend_kind not in {
                BackendKind.MANAGED_SAMPLE,
                BackendKind.INTERNAL_HTTPS_LB,
            }:
                continue
            yield ResourceProbe(
                f"compute:internal_address:{prefix}-{suffix}-ip",
                f"https://compute.googleapis.com/compute/v1/projects/{project}/regions/{region}/"
                f"addresses/{prefix}-{suffix}-ip",
            )
        if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
            for resource_type, collection, name in (
                (
                    "instance_group",
                    f"zones/{zone}/instanceGroups",
                    f"{prefix}-backend-ig",
                ),
                (
                    "health_check",
                    f"regions/{region}/healthChecks",
                    f"{prefix}-ilb-hc",
                ),
                (
                    "backend_service",
                    f"regions/{region}/backendServices",
                    f"{prefix}-ilb-bs",
                ),
                (
                    "ssl_certificate",
                    f"regions/{region}/sslCertificates",
                    f"{prefix}-ilb-cert",
                ),
                ("url_map", f"regions/{region}/urlMaps", f"{prefix}-ilb-map"),
                (
                    "target_https_proxy",
                    f"regions/{region}/targetHttpsProxies",
                    f"{prefix}-ilb-proxy",
                ),
                (
                    "forwarding_rule",
                    f"regions/{region}/forwardingRules",
                    f"{prefix}-ilb-fr",
                ),
            ):
                yield ResourceProbe(
                    f"compute:{resource_type}:{name}",
                    (
                        f"https://compute.googleapis.com/compute/v1/projects/{project}/"
                        f"{collection}/{name}"
                    ),
                )
        elif spec.mode.value == "production":
            for resource_type, collection, name in (
                (
                    "instance_template",
                    "global/instanceTemplates",
                    f"{prefix}-offload-template",
                ),
                (
                    "health_check",
                    f"regions/{region}/healthChecks",
                    f"{prefix}-offload-hc",
                ),
                (
                    "instance_group_manager",
                    f"regions/{region}/instanceGroupManagers",
                    f"{prefix}-offload-mig",
                ),
                (
                    "backend_service",
                    f"regions/{region}/backendServices",
                    f"{prefix}-offload-bs",
                ),
                (
                    "forwarding_rule",
                    f"regions/{region}/forwardingRules",
                    f"{prefix}-offload-fr",
                ),
            ):
                yield ResourceProbe(
                    f"compute:{resource_type}:{name}",
                    (
                        f"https://compute.googleapis.com/compute/v1/projects/{project}/"
                        f"{collection}/{name}"
                    ),
                )
            yield ResourceProbe(
                f"compute:autoscaler:{prefix}-offload-autoscaler",
                (
                    f"https://compute.googleapis.com/compute/v1/projects/{project}/"
                    f"regions/{region}/autoscalers/{prefix}-offload-autoscaler"
                ),
            )
        else:
            yield ResourceProbe(
                f"compute:instance:{prefix}-offload",
                (
                    f"https://compute.googleapis.com/compute/v1/projects/{project}/"
                    f"zones/{zone}/instances/{prefix}-offload"
                ),
            )
        if spec.backend_kind in {
            BackendKind.MANAGED_SAMPLE,
            BackendKind.INTERNAL_HTTPS_LB,
        }:
            yield ResourceProbe(
                f"compute:instance:{prefix}-backend",
                f"https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/"
                f"instances/{prefix}-backend",
            )
        if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
            firewall_suffixes = ["ilb-proxy-ingress", "ilb-health-ingress"]
        else:
            firewall_suffixes = ["gateway-ingress"]
            if spec.mode.value == "production":
                firewall_suffixes.append("health-check-ingress")
            if spec.backend_kind is BackendKind.MANAGED_SAMPLE:
                firewall_suffixes.append("backend-ingress")
        for suffix in firewall_suffixes:
            yield ResourceProbe(
                f"compute:firewall_rule:{prefix}-{suffix}",
                f"https://compute.googleapis.com/compute/v1/projects/{project}/global/"
                f"firewalls/{prefix}-{suffix}",
            )
        yield ResourceProbe(
            f"dns:private_zone:{prefix}-zone",
            f"https://dns.googleapis.com/dns/v1/projects/{project}/managedZones/{prefix}-zone",
        )
        gateway_parent = (
            f"https://beyondcorp.googleapis.com/v1/projects/{project}/locations/global/"
            f"securityGateways/{spec.gateway_id}"
        )
        yield ResourceProbe(
            f"beyondcorp:security_gateway:{spec.gateway_id}",
            gateway_parent,
        )
        yield ResourceProbe(
            f"beyondcorp:application:{prefix}-app",
            f"{gateway_parent}/applications/{prefix}-app",
        )

    def _cloud_nat_exists(self, spec: DeploymentSpec) -> bool:
        if spec.network_strategy is NetworkStrategy.EXISTING:
            return False
        router_url = (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/regions/"
            f"{spec.region}/routers/{spec.name}-router"
        )
        status_code, payload = self._transport.request_json(
            "GET",
            router_url,
            accepted_statuses=(200, 404),
        )
        if status_code == 404:
            return False
        nats = payload.get("nats", [])
        return isinstance(nats, list) and any(
            isinstance(nat, dict) and nat.get("name") == f"{spec.name}-nat" for nat in nats
        )

    def _existing_private_egress_available(self, spec: DeploymentSpec) -> bool:
        _, payload = self._transport.request_json(
            "GET",
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            "aggregated/routers",
            params={"maxResults": 500},
        )
        expected_network_suffix = f"/global/networks/{spec.vpc_name}"
        scoped_items = payload.get("items", {})
        if not isinstance(scoped_items, dict):
            return False
        for scoped in scoped_items.values():
            if not isinstance(scoped, dict):
                continue
            routers = scoped.get("routers", [])
            if not isinstance(routers, list):
                continue
            for router in routers:
                if not isinstance(router, dict):
                    continue
                network = router.get("network")
                nats = router.get("nats")
                if (
                    isinstance(network, str)
                    and network.endswith(expected_network_suffix)
                    and isinstance(nats, list)
                    and len(nats) > 0
                ):
                    return True
        return False

    def _compatible(
        self,
        key: str,
        payload: dict[str, object],
        spec: DeploymentSpec,
    ) -> bool:
        """Fail closed when a same-name resource is not semantically reusable."""
        _, resource_type, resource_name = key.split(":", maxsplit=2)
        network_suffix = f"/global/networks/{self._network_name(spec)}"
        subnet_suffix = f"/regions/{spec.region}/subnetworks/{self._subnet_name(spec)}"

        if resource_type == "network":
            if spec.network_strategy is NetworkStrategy.EXISTING:
                return payload.get("name") == spec.vpc_name
            return (
                payload.get("autoCreateSubnetworks") is False
                and payload.get("description") == "Managed by Secure Gateway Studio"
            )
        if resource_type == "source_image":
            deprecated = payload.get("deprecated")
            state = deprecated.get("state") if isinstance(deprecated, dict) else None
            return payload.get("name") == resource_name.rsplit("/", 1)[-1] and state not in {
                "OBSOLETE",
                "DELETED",
            }
        if resource_type == "subnetwork":
            network = payload.get("network")
            if not isinstance(network, str) or not network.endswith(network_suffix):
                return False
            if resource_name.endswith("-proxy-subnet"):
                return (
                    payload.get("ipCidrRange") == spec.proxy_subnet_cidr
                    and payload.get("purpose") == "REGIONAL_MANAGED_PROXY"
                    and payload.get("role") == "ACTIVE"
                )
            return (
                spec.network_strategy is NetworkStrategy.EXISTING
                or payload.get("ipCidrRange") == spec.subnet_cidr
            )
        if resource_type == "router":
            network = payload.get("network")
            return isinstance(network, str) and network.endswith(network_suffix)
        if resource_type == "service_account":
            return payload.get("email") == (
                f"{resource_name}@{spec.project_id}.iam.gserviceaccount.com"
            )
        if resource_type == "secret":
            if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED:
                return True
            labels = payload.get("labels")
            return isinstance(labels, dict) and labels.get("managed-by") == (
                "secure-gateway-studio"
            )
        if resource_type == "internal_address":
            subnetwork = payload.get("subnetwork")
            return (
                payload.get("addressType") == "INTERNAL"
                and isinstance(subnetwork, str)
                and subnetwork.endswith(subnet_suffix)
            )
        if resource_type == "instance":
            return self._private_managed_vm(payload, spec)
        if resource_type == "instance_group":
            named_ports = payload.get("namedPorts")
            network = payload.get("network")
            subnetwork = payload.get("subnetwork")
            return (
                isinstance(network, str)
                and network.endswith(f"/networks/{self._network_name(spec)}")
                and isinstance(subnetwork, str)
                and subnetwork.endswith(f"/subnetworks/{self._subnet_name(spec)}")
                and isinstance(named_ports, list)
                and any(
                isinstance(port, dict)
                and port.get("name") == "http"
                and port.get("port") == 80
                for port in named_ports
                )
            )
        if resource_type == "instance_template":
            properties = payload.get("properties")
            return isinstance(properties, dict) and self._private_managed_vm(properties, spec)
        if resource_type == "health_check":
            if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
                http = payload.get("httpHealthCheck")
                return payload.get("type") == "HTTP" and isinstance(http, dict)
            ssl = payload.get("sslHealthCheck")
            return payload.get("type") == "SSL" and isinstance(ssl, dict) and ssl.get("port") == 443
        if resource_type == "instance_group_manager":
            policy = payload.get("distributionPolicy")
            zones = policy.get("zones", []) if isinstance(policy, dict) else []
            zone_names = {
                zone.get("zone", "").rsplit("/", maxsplit=1)[-1]
                for zone in zones
                if isinstance(zone, dict)
            }
            return (
                isinstance(payload.get("targetSize"), int)
                and payload["targetSize"] >= spec.offload_min_replicas
                and {spec.zone, spec.secondary_zone} <= zone_names
            )
        if resource_type == "autoscaler":
            policy = payload.get("autoscalingPolicy")
            cpu = policy.get("cpuUtilization") if isinstance(policy, dict) else None
            return (
                isinstance(policy, dict)
                and policy.get("minNumReplicas") == spec.offload_min_replicas
                and policy.get("maxNumReplicas") == spec.offload_max_replicas
                and isinstance(cpu, dict)
                and cpu.get("utilizationTarget") == spec.offload_cpu_target
            )
        if resource_type == "backend_service":
            if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
                health_checks = payload.get("healthChecks")
                backends = payload.get("backends")
                return (
                    payload.get("protocol") == "HTTP"
                    and payload.get("loadBalancingScheme") == "INTERNAL_MANAGED"
                    and payload.get("portName") == "http"
                    and isinstance(health_checks, list)
                    and any(
                        isinstance(health_check, str)
                        and health_check.endswith(
                            f"/regions/{spec.region}/healthChecks/{spec.name}-ilb-hc"
                        )
                        for health_check in health_checks
                    )
                    and isinstance(backends, list)
                    and any(
                        isinstance(backend, dict)
                        and isinstance(backend.get("group"), str)
                        and backend["group"].endswith(
                            f"/zones/{spec.zone}/instanceGroups/{spec.name}-backend-ig"
                        )
                        for backend in backends
                    )
                )
            return (
                payload.get("protocol") == "TCP"
                and payload.get("loadBalancingScheme") == "INTERNAL"
            )
        if resource_type == "forwarding_rule":
            compatible = (
                payload.get("IPProtocol") == "TCP"
                and payload.get("loadBalancingScheme")
                == (
                    "INTERNAL_MANAGED"
                    if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB
                    else "INTERNAL"
                )
                and "443" in {str(port) for port in payload.get("ports", [])}
            )
            if spec.backend_kind is not BackendKind.INTERNAL_HTTPS_LB:
                return compatible
            target = payload.get("target")
            return (
                compatible
                and isinstance(target, str)
                and target.endswith(
                    f"/regions/{spec.region}/targetHttpsProxies/{spec.name}-ilb-proxy"
                )
            )
        if resource_type == "ssl_certificate":
            return payload.get("description") == (
                "Managed by Secure Gateway Studio; certificate configuration "
                f"{certificate_configuration_hash(spec)}"
            )
        if resource_type == "url_map":
            default_service = payload.get("defaultService")
            return isinstance(default_service, str) and default_service.endswith(
                f"/regions/{spec.region}/backendServices/{spec.name}-ilb-bs"
            )
        if resource_type == "target_https_proxy":
            url_map = payload.get("urlMap")
            certificates = payload.get("sslCertificates")
            return (
                isinstance(url_map, str)
                and url_map.endswith(f"/regions/{spec.region}/urlMaps/{spec.name}-ilb-map")
                and isinstance(certificates, list)
                and any(
                    isinstance(certificate, str)
                    and certificate.endswith(
                        f"/regions/{spec.region}/sslCertificates/{spec.name}-ilb-cert"
                    )
                    for certificate in certificates
                )
            )
        if resource_type == "firewall_rule":
            return self._compatible_firewall(resource_name, payload, spec)
        if resource_type == "private_zone":
            return payload.get("visibility") == "private"
        if resource_type == "security_gateway":
            return "serviceDiscovery" in payload or "service_discovery" in payload
        if resource_type == "application":
            matchers = payload.get("endpointMatchers")
            if not isinstance(matchers, list):
                matchers = payload.get("endpoint_matchers")
            matcher_ok = isinstance(matchers, list) and any(
                isinstance(matcher, dict)
                and matcher.get("hostname") == spec.application_hostname
                and spec.application_port in matcher.get("ports", [])
                for matcher in matchers
            )
            upstreams = payload.get("upstreams")
            expected_network = (
                f"projects/{spec.project_id}/global/networks/{self._network_name(spec)}"
            )
            upstream_ok = False
            if isinstance(upstreams, list):
                for upstream in upstreams:
                    if not isinstance(upstream, dict):
                        continue
                    network = upstream.get("network")
                    if not isinstance(network, dict) or network.get("name") != expected_network:
                        continue
                    if not spec.application_egress_region:
                        upstream_ok = True
                        break
                    policy = upstream.get("egressPolicy", upstream.get("egress_policy"))
                    if (
                        isinstance(policy, dict)
                        and spec.application_egress_region in policy.get("regions", [])
                    ):
                        upstream_ok = True
                        break
            return matcher_ok and upstream_ok
        if resource_type == "access_level":
            custom = payload.get("custom")
            expressions: set[object] = set()
            if isinstance(custom, dict):
                direct_expr = custom.get("expr")
                if isinstance(direct_expr, dict):
                    expressions.add(direct_expr.get("expression"))
                conditions = custom.get("conditions", [])
                if isinstance(conditions, list):
                    expressions.update(
                        condition.get("expr", {}).get("expression")
                        for condition in conditions
                        if isinstance(condition, dict)
                    )
            expression = "\n".join(item for item in expressions if isinstance(item, str))
            # An administrator-owned access level may intentionally target
            # profile-managed Chrome, browser-managed Chrome, or both. Requiring
            # both states rejects valid profile-managed-device PoCs as a name
            # collision even though the selected level is reusable as-is.
            return any(
                state in expression
                for state in (
                    "CHROME_MANAGEMENT_STATE_PROFILE_MANAGED",
                    "CHROME_MANAGEMENT_STATE_BROWSER_MANAGED",
                )
            )
        return True

    @staticmethod
    def _network_name(spec: DeploymentSpec) -> str:
        return (
            f"{spec.name}-vpc"
            if spec.network_strategy is NetworkStrategy.DEDICATED
            else str(spec.vpc_name)
        )

    @staticmethod
    def _subnet_name(spec: DeploymentSpec) -> str:
        return (
            f"{spec.name}-subnet"
            if spec.network_strategy is NetworkStrategy.DEDICATED
            else str(spec.subnet_name)
        )

    @staticmethod
    def _private_managed_vm(payload: dict[str, object], spec: DeploymentSpec) -> bool:
        labels = payload.get("labels")
        interfaces = payload.get("networkInterfaces")
        accounts = payload.get("serviceAccounts")
        if not isinstance(labels, dict) or labels.get("managed-by") != ("secure-gateway-studio"):
            return False
        if not isinstance(interfaces, list) or any(
            not isinstance(interface, dict) or interface.get("accessConfigs")
            for interface in interfaces
        ):
            return False
        expected_suffix = f"@{spec.project_id}.iam.gserviceaccount.com"
        return isinstance(accounts, list) and any(
            isinstance(account, dict)
            and isinstance(account.get("email"), str)
            and account["email"].endswith(expected_suffix)
            for account in accounts
        )

    @staticmethod
    def _compatible_firewall(
        resource_name: str,
        payload: dict[str, object],
        spec: DeploymentSpec,
    ) -> bool:
        allowed = payload.get("allowed")
        ports = (
            {
                str(port)
                for entry in allowed
                if isinstance(entry, dict)
                for port in entry.get("ports", [])
            }
            if isinstance(allowed, list)
            else set()
        )
        sources = set(payload.get("sourceRanges", []))
        if resource_name.endswith("gateway-ingress"):
            return ports == {"443"} and sources == {SECURE_GATEWAY_SOURCE_CIDR}
        if resource_name.endswith("health-check-ingress"):
            return ports == {"443"} and sources == {
                "35.191.0.0/16",
                "130.211.0.0/22",
            }
        if resource_name.endswith("ilb-proxy-ingress"):
            return ports == {"80"} and sources == {spec.proxy_subnet_cidr}
        if resource_name.endswith("ilb-health-ingress"):
            return ports == {"80"} and sources == {
                "35.191.0.0/16",
                "130.211.0.0/22",
            }
        source_accounts = set(payload.get("sourceServiceAccounts", []))
        return ports == {"80"} and source_accounts == {
            service_account_email(spec.name, spec.project_id, "offload")
        }

    @staticmethod
    def _api_diagnostic(resource: str, error: GoogleApiError) -> PreflightDiagnostic:
        severity = "warning" if error.status_code in {403, 404} else "error"
        return PreflightDiagnostic(
            code=f"google-api-{error.status_code}",
            severity=severity,
            message=f"Could not discover {resource} through {error.host}.",
            remediation=(
                "Verify that ADC has read permissions and that the required API is enabled."
            ),
        )


def create_google_discovery_provider() -> GoogleDiscoveryProvider:
    try:
        transport = GoogleAuthorizedTransport.from_adc()
    except (DefaultCredentialsError, RefreshError) as error:
        raise RuntimeError(
            "Application Default Credentials are unavailable. Run "
            "`gcloud auth application-default login "
            "--impersonate-service-account=SERVICE_ACCOUNT_EMAIL`."
        ) from error
    return GoogleDiscoveryProvider(
        transport,
        cloud_identity=transport.metadata.principal_hint,
        credential_kind=transport.metadata.kind,
        quota_project_id=transport.metadata.quota_project_id,
        artifact_store=CertificateArtifactStore(Path.cwd() / ".local" / "artifacts"),
    )
