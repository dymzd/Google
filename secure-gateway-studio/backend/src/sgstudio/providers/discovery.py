from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Protocol
from urllib.parse import quote, unquote, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from google.auth.exceptions import DefaultCredentialsError, RefreshError

from sgstudio.domain.iam_policy import validate_iam_policy_v3
from sgstudio.domain.models import (
    BackendKind,
    CertificateStrategy,
    DeploymentSpec,
    DiscoverySnapshot,
    NetworkStrategy,
    PreflightDiagnostic,
    PreflightResult,
    PublicCertificateBinding,
    SourceImageBinding,
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
OWNERSHIP_DESCRIPTION_PATTERN = re.compile(
    r"^Secure Gateway Studio ownership-token="
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"(?:; (?P<suffix>.*))?$",
    re.IGNORECASE,
)


def _owned_description(payload: dict[str, object], suffix: str | None = None) -> bool:
    description = payload.get("description")
    match = (
        OWNERSHIP_DESCRIPTION_PATTERN.fullmatch(description)
        if isinstance(description, str)
        else None
    )
    if match is None:
        return False
    return match.group("suffix") == suffix


def _compute_reference(value: object, expected_path: str) -> bool:
    if not isinstance(value, str):
        return False
    if value == expected_path or value == expected_path.removeprefix("/"):
        return True
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and parsed.netloc in {"compute.googleapis.com", "www.googleapis.com"}
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
        and parsed.path == f"/compute/v1{expected_path}"
    )


def _valid_external_ip_list(value: object) -> bool:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        return False
    for item in value:
        try:
            ip_address(item)
        except ValueError:
            return False
    return True


def _compatible_health_check_detail(value: object, *, protocol: str) -> bool:
    if not isinstance(value, dict):
        return False
    if protocol == "SSL":
        allowed = {"port", "portName", "portSpecification", "proxyHeader", "request", "response"}
        return (
            set(value) <= allowed
            and value.get("port") in {None, 443}
            and value.get("portName") in {None, ""}
            and value.get("portSpecification") in {None, "USE_FIXED_PORT"}
            and value.get("proxyHeader") in {None, "NONE"}
            and value.get("request") in {None, ""}
            and value.get("response") in {None, ""}
        )
    allowed = {
        "host",
        "port",
        "portName",
        "portSpecification",
        "proxyHeader",
        "requestPath",
        "response",
    }
    return (
        set(value) <= allowed
        and value.get("host") in {None, ""}
        and value.get("port") in {None, 80}
        and value.get("portName") in {None, ""}
        and value.get("portSpecification") in {None, "USE_SERVING_PORT"}
        and value.get("proxyHeader") in {None, "NONE"}
        and value.get("requestPath") in {None, "/"}
        and value.get("response") in {None, ""}
    )


def _compatible_routing_config(value: object) -> bool:
    if not isinstance(value, dict) or not set(value) <= {
        "routingMode",
        "bgpBestPathSelectionMode",
        "bgpInterRegionCost",
        "bgpAlwaysCompareMed",
        "effectiveBgpInterRegionCost",
        "effectiveBgpAlwaysCompareMed",
    }:
        return False
    return (
        value.get("routingMode") == "REGIONAL"
        and value.get("bgpBestPathSelectionMode", "LEGACY") == "LEGACY"
        and value.get("bgpInterRegionCost", "DEFAULT") == "DEFAULT"
        and value.get("effectiveBgpInterRegionCost", "DEFAULT") == "DEFAULT"
        and value.get("bgpAlwaysCompareMed", False) is False
        and value.get("effectiveBgpAlwaysCompareMed", False) is False
    )


def _compatible_fixed_or_percent(value: object, expected_fixed: int) -> bool:
    return (
        isinstance(value, dict)
        and set(value) <= {"fixed", "calculated"}
        and value.get("fixed") == expected_fixed
        and value.get("calculated", expected_fixed) == expected_fixed
    )


def _compatible_mig_update_policy(value: object) -> bool:
    if not isinstance(value, dict) or not set(value) <= {
        "type",
        "minimalAction",
        "maxSurge",
        "maxUnavailable",
        "replacementMethod",
        "mostDisruptiveAllowedAction",
        "instanceRedistributionType",
        "minReadySec",
    }:
        return False
    return (
        value.get("type") == "PROACTIVE"
        and value.get("minimalAction") == "REPLACE"
        and _compatible_fixed_or_percent(value.get("maxSurge"), 2)
        and _compatible_fixed_or_percent(value.get("maxUnavailable"), 0)
        and value.get("replacementMethod", "SUBSTITUTE") == "SUBSTITUTE"
        and value.get("mostDisruptiveAllowedAction", "REPLACE") == "REPLACE"
        and value.get("instanceRedistributionType", "PROACTIVE") == "PROACTIVE"
        and value.get("minReadySec", 0) == 0
    )


def _license_assignment_user(
    payload: dict[str, object],
    *,
    product_id: str = "101040",
    sku_id: str = "1010400001",
) -> str:
    user_id = payload.get("userId")
    self_link = payload.get("selfLink")
    if (
        payload.get("kind") != "licensing#licenseAssignment"
        or payload.get("productId") != product_id
        or payload.get("skuId") != sku_id
        or not isinstance(user_id, str)
        or not user_id.strip()
        or not isinstance(self_link, str)
    ):
        raise ValueError("License assignment identity is invalid")
    parsed = urlparse(self_link)
    if (
        parsed.scheme != "https"
        or parsed.netloc not in {"licensing.googleapis.com", "www.googleapis.com"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("License assignment selfLink is invalid")
    segments = parsed.path.split("/")
    if len(segments) != 10 or segments[1:5] != ["apps", "licensing", "v1", "product"]:
        raise ValueError("License assignment selfLink path is invalid")
    if segments[6] != "sku" or segments[8] != "user":
        raise ValueError("License assignment selfLink path is invalid")
    try:
        link_product = unquote(segments[5])
        link_sku = unquote(segments[7])
        link_user = unquote(segments[9])
    except (UnicodeError, ValueError) as error:
        raise ValueError("License assignment selfLink encoding is invalid") from error
    if (
        link_product != product_id
        or link_sku != sku_id
        or link_user.casefold() != user_id.strip().casefold()
    ):
        raise ValueError("License assignment selfLink identity does not match")
    return user_id.strip()


UPSTREAM_PROJECT_PERMISSIONS = {
    "compute.networks.get",
    "compute.networks.use",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "resourcemanager.projects.setIamPolicy",
}

MANAGED_CHROME_ACCESS_LEVEL_EXPRESSIONS = {
    "device.chrome.management_state == "
    "ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED",
    "device.chrome.management_state == "
    "ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED",
    "device.chrome.management_state in ["
    "ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED, "
    "ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]",
}


class DiscoveryProvider(Protocol):
    def preflight(
        self,
        spec: DeploymentSpec,
        *,
        ownership_proofs: DiscoveryOwnershipProofs | None = None,
    ) -> PreflightResult: ...


@dataclass(frozen=True)
class ResourceProbe:
    key: str
    url: str


@dataclass(frozen=True)
class DiscoveryOwnershipProof:
    """Minimal durable proof needed to reuse one app-managed provider resource."""

    marker: str | None
    provider_identity_field: str | None = None
    provider_identity: str | None = None


DiscoveryOwnershipProofs = Mapping[str, DiscoveryOwnershipProof]


def discovery_ownership_proofs(
    metadata: Mapping[str, Mapping[str, object]],
) -> dict[str, DiscoveryOwnershipProof]:
    """Reduce active run checkpoints to fail-closed discovery proofs.

    The resource payload is never ownership authority by itself. Only an
    applied checkpoint for the exact inventory key can supply a marker and,
    where the provider exposes one, an immutable provider identity.
    """

    proofs: dict[str, DiscoveryOwnershipProof] = {}
    for resource_key, checkpoint in metadata.items():
        if checkpoint.get("resource_key") != resource_key:
            continue
        kind = checkpoint.get("kind")
        phase = checkpoint.get("phase")
        if kind == "generic_created_resource" and phase == "applied":
            marker = checkpoint.get("ownership_marker")
            identity_field = checkpoint.get("provider_identity_field")
            identity = checkpoint.get("provider_identity")
            expected_identity_field = (
                "id"
                if resource_key.startswith("compute:")
                else "createTime"
                if resource_key.startswith("beyondcorp:")
                else None
            )
            if (
                (marker is None or isinstance(marker, str))
                and identity_field == expected_identity_field
                and isinstance(identity, str)
                and bool(identity)
            ):
                proofs[resource_key] = DiscoveryOwnershipProof(
                    marker=marker,
                    provider_identity_field=identity_field,
                    provider_identity=identity,
                )
            continue
        if kind == "named_resource_ownership" and phase == "applied":
            marker = checkpoint.get("marker")
            if not isinstance(marker, str) or not marker:
                continue
            resource_kind = checkpoint.get("resource_kind")
            provider_identity = checkpoint.get("provider_identity")
            identity_field = {
                "iam_service_account": "uniqueId",
                "dns_private_zone": "id",
            }.get(resource_kind)
            if identity_field is not None:
                if not isinstance(provider_identity, str) or not provider_identity:
                    continue
                proofs[resource_key] = DiscoveryOwnershipProof(
                    marker=marker,
                    provider_identity_field=identity_field,
                    provider_identity=provider_identity,
                )
            elif resource_kind in {"secretmanager_secret", "dns_record_set"}:
                proofs[resource_key] = DiscoveryOwnershipProof(marker=marker)
            continue
        if kind == "cloud_nat_delta" and phase == "applied":
            identity_field = checkpoint.get("router_identity_field")
            identity = checkpoint.get("router_identity")
            if (
                resource_key.startswith("compute:cloud_nat:")
                and identity_field == "id"
                and isinstance(identity, str)
                and bool(identity)
            ):
                proofs[resource_key] = DiscoveryOwnershipProof(
                    marker=None,
                    provider_identity_field=identity_field,
                    provider_identity=identity,
                )
            continue
        if kind == "secret_version" and phase == "applied":
            marker = checkpoint.get("ownership_token")
            version_name = checkpoint.get("version_name")
            if (
                isinstance(marker, str)
                and bool(marker)
                and isinstance(version_name, str)
                and bool(version_name)
            ):
                proofs[resource_key] = DiscoveryOwnershipProof(
                    marker=marker,
                    provider_identity_field="name",
                    provider_identity=version_name,
                )
    return proofs


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
        ownership_proofs: DiscoveryOwnershipProofs | None = None,
    ) -> None:
        self._transport = transport
        self._cloud_identity = cloud_identity
        self._credential_kind = credential_kind
        self._quota_project_id = quota_project_id
        self._artifact_store = artifact_store
        self._configured_ownership_proofs: DiscoveryOwnershipProofs = ownership_proofs or {}
        self._ownership_proofs: DiscoveryOwnershipProofs = self._configured_ownership_proofs
        self._public_certificate_binding: PublicCertificateBinding | None = None
        self._validated_tls_payload: bytes | None = None
        self._validated_tls_secret_name: str | None = None
        self._validated_tls_version_name: str | None = None
        self._source_image_binding: SourceImageBinding | None = None
        self._discovered_addresses: dict[str, str] = {}

    def preflight(
        self,
        spec: DeploymentSpec,
        *,
        ownership_proofs: DiscoveryOwnershipProofs | None = None,
    ) -> PreflightResult:
        # API calls pass a fresh, repository-derived mapping for every request.
        # Reset to the constructor mapping when a caller supplies no context,
        # so a reused provider cannot inherit a previous request's ledger.
        self._ownership_proofs = (
            ownership_proofs
            if ownership_proofs is not None
            else self._configured_ownership_proofs
        )
        self._public_certificate_binding = None
        self._validated_tls_payload = None
        self._validated_tls_secret_name = None
        self._validated_tls_version_name = None
        self._source_image_binding = None
        self._discovered_addresses.clear()
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
            self._assert_target_ou_is_non_root(spec)
        except (GoogleApiError, ValueError) as error:
            conflicting_keys.update(
                {
                    "chromepolicy:extension_install:ekajlcmdfcigmdbphhifahdfjbkciflj",
                    "chromepolicy:extension_install:callobklhcbilhphinckomhgkigmfocg",
                    "chromepolicy:extension_configuration:ekajlcmdfcigmdbphhifahdfjbkciflj",
                    f"chromepolicy:service_discovery_proxy:{spec.target_ou_id}",
                }
            )
            diagnostics.append(
                PreflightDiagnostic(
                    code="target-ou-invalid",
                    severity="error",
                    message=(
                        "The selected Workspace organizational unit is not a valid non-root OU."
                    ),
                    remediation=str(error),
                )
            )

        try:
            enabled_apis = self._enabled_apis(spec.project_id)
            if enabled_apis >= required_apis(spec):
                existing_keys.add("serviceusage:project_services:required-apis")
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("service-usage", error))
        except ValueError as error:
            diagnostics.append(
                PreflightDiagnostic(
                    code="service-usage-pagination-invalid",
                    severity="error",
                    message="Enabled-API discovery did not complete safely.",
                    remediation=str(error),
                )
            )
        required = required_permissions(spec)
        try:
            granted_permissions = self._granted_permissions(spec.project_id, required)
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("project-permissions", error))
        if spec.upstream_project_id != spec.project_id:
            upstream_required = required & UPSTREAM_PROJECT_PERMISSIONS
            try:
                upstream_granted = self._granted_permissions(
                    spec.upstream_project_id, upstream_required
                )
                granted_permissions -= upstream_required - upstream_granted
            except GoogleApiError as error:
                # A flat snapshot cannot carry project scope, so retain a
                # permission only if every project where it is used confirms
                # it.  An unreadable upstream project therefore fails closed.
                granted_permissions -= upstream_required
                diagnostics.append(self._api_diagnostic("upstream-project-permissions", error))
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

        public_secret_key = (
            f"secretmanager:secret:{secret_name}"
            if spec.backend_kind is not BackendKind.DIRECT_HTTPS
            and spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            and spec.public_certificate_secret
            else None
        )
        probes = list(self._resource_probes(spec))
        if public_secret_key is not None:
            secret_probe = next(
                (probe for probe in probes if probe.key == public_secret_key),
                None,
            )
            try:
                if secret_probe is None:
                    raise ValueError("The referenced Secret Manager secret was not probed")
                status_code, payload = self._transport.request_json(
                    "GET",
                    secret_probe.url,
                    accepted_statuses=(200, 404),
                )
                if status_code != 200 or not self._compatible(
                    secret_probe.key,
                    payload,
                    spec,
                ):
                    raise ValueError("The referenced Secret Manager secret does not exist")
                binding = self._validate_certificate_secret(
                    spec,
                    secret_name,
                    require_crc32c=True,
                    require_numeric_version_name=True,
                )
                if binding is None:
                    raise ValueError("The referenced TLS secret has no immutable binding")
                self._public_certificate_binding = binding
                existing_keys.add(public_secret_key)
            except GoogleApiError as error:
                conflicting_keys.add(public_secret_key)
                diagnostics.append(self._api_diagnostic(public_secret_key, error))
            except ValueError as error:
                conflicting_keys.add(public_secret_key)
                diagnostics.append(
                    PreflightDiagnostic(
                        code="invalid-public-certificate-secret",
                        severity="error",
                        message="The referenced TLS secret failed certificate validation.",
                        remediation=str(error),
                    )
                )

        if (
            spec.backend_kind is not BackendKind.DIRECT_HTTPS
            and spec.certificate_strategy is not CertificateStrategy.PUBLIC_TRUSTED
        ):
            self._discover_managed_certificate_version(
                spec,
                secret_name,
                existing_keys,
                conflicting_keys,
                diagnostics,
            )

        for probe in probes:
            if probe.key == public_secret_key:
                continue
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
                            granted_permissions.add("accesscontextmanager.accessLevels.get")
                    else:
                        conflicting_keys.add(probe.key)
            except GoogleApiError as error:
                # Only an explicit 404 response from the exact probe URL is
                # absence. Permission, quota, transport, and server failures
                # must not be converted into a CREATE of a reserved name.
                conflicting_keys.add(probe.key)
                diagnostics.append(self._api_diagnostic(probe.key, error))
            except (TypeError, ValueError) as error:
                conflicting_keys.add(probe.key)
                diagnostics.append(
                    PreflightDiagnostic(
                        code="resource-probe-response-invalid",
                        severity="error",
                        message=f"Discovery returned an invalid shape for {probe.key}.",
                        remediation=str(error),
                    )
                )

        if spec.backend_kind is not BackendKind.DIRECT_HTTPS:
            self._discover_local_poc_certificate(
                spec,
                secret_name,
                existing_keys,
                conflicting_keys,
                diagnostics,
            )
            self._discover_dns_record(
                spec,
                existing_keys,
                conflicting_keys,
                diagnostics,
            )
        self._discover_iam_bindings(
            spec,
            existing_keys,
            conflicting_keys,
            diagnostics,
        )
        self._discover_chrome_policies(
            spec,
            existing_keys,
            conflicting_keys,
            diagnostics,
        )
        (
            chrome_extension_group_conflicts,
            chrome_group_policy_discovery_complete,
        ) = self._discover_chrome_group_policy_conflicts(
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
        chrome_enterprise_premium_license_count = self._discover_chrome_enterprise_premium_licenses(
            spec, diagnostics
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
            and spec.certificate_strategy is CertificateStrategy.ENTERPRISE_CA
            and f"secretmanager:secret:{secret_name}" in existing_keys
            and f"secretmanager:secret_version:{secret_name}" in existing_keys
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
                conflicting_keys.add(f"compute:cloud_nat:{spec.name}-nat")
                diagnostics.append(self._api_diagnostic("compute:cloud_nat", error))
            except ValueError as error:
                conflicting_keys.add(f"compute:cloud_nat:{spec.name}-nat")
                diagnostics.append(
                    PreflightDiagnostic(
                        code="compute-cloud-nat-discovery-invalid",
                        severity="error",
                        message="Cloud NAT discovery returned an invalid response.",
                        remediation=str(error),
                    )
                )
        private_egress_available: bool | None = None
        if (
            spec.network_strategy is NetworkStrategy.EXISTING
            and spec.backend_kind is not BackendKind.DIRECT_HTTPS
        ):
            try:
                private_egress_available = self._existing_private_egress_available(spec)
            except GoogleApiError as error:
                diagnostics.append(self._api_diagnostic("compute:private-egress", error))
            except ValueError as error:
                diagnostics.append(
                    PreflightDiagnostic(
                        code="compute-private-egress-discovery-invalid",
                        severity="error",
                        message="Private-egress discovery did not complete safely.",
                        remediation=str(error),
                    )
                )

        application_global_access: bool | None = None
        application_forwarding_rule: str | None = None
        application_global_access_discovery_complete = True
        if spec.backend_kind is BackendKind.DIRECT_HTTPS:
            try:
                (
                    application_global_access,
                    application_forwarding_rule,
                ) = self._application_global_access(spec)
            except GoogleApiError as error:
                application_global_access_discovery_complete = False
                diagnostics.append(self._api_diagnostic("compute:forwarding-rule", error))
            except ValueError as error:
                application_global_access_discovery_complete = False
                diagnostics.append(
                    PreflightDiagnostic(
                        code="compute-forwarding-rule-pagination-invalid",
                        severity="error",
                        message=("Forwarding-rule discovery pagination did not complete safely."),
                        remediation=str(error),
                    )
                )

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
                chrome_group_policy_discovery_complete=(chrome_group_policy_discovery_complete),
                chrome_enterprise_premium_license_count=(chrome_enterprise_premium_license_count),
                chrome_root_store_config_count=chrome_root_store_config_count,
                chrome_root_store_config_names=chrome_root_store_config_names,
                chrome_root_store_enabled=chrome_root_store_enabled,
                application_global_access=application_global_access,
                application_forwarding_rule=application_forwarding_rule,
                application_global_access_discovery_complete=(
                    application_global_access_discovery_complete
                ),
                public_certificate_binding=self._public_certificate_binding,
                source_image_binding=self._source_image_binding,
            ),
            diagnostics=diagnostics,
            credential_kind=self._credential_kind,
            quota_project_id=self._quota_project_id,
        )

    def _assert_target_ou_is_non_root(self, spec: DeploymentSpec) -> None:
        _, payload = self._transport.request_json(
            "GET",
            (
                "https://admin.googleapis.com/admin/directory/v1/customer/"
                f"{spec.customer_id}/orgunits/{quote(f'id:{spec.target_ou_id}', safe='')}"
            ),
        )
        raw_id = payload.get("orgUnitId")
        path = payload.get("orgUnitPath")
        if (
            not isinstance(raw_id, str)
            or raw_id.removeprefix("id:") != spec.target_ou_id
            or not isinstance(path, str)
            or not path.startswith("/")
            or path == "/"
        ):
            raise ValueError(
                "The selected organizational unit is missing, stale, or is the Root OU"
            )

    def _enabled_apis(self, project_id: str) -> set[str]:
        enabled: set[str] = set()
        page_token: str | None = None
        seen_tokens: set[str] = set()
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
            services = payload.get("services")
            if services is not None and not isinstance(services, list):
                raise ValueError("Enabled-API response services is not a list")
            for service in services or []:
                if not isinstance(service, dict):
                    raise ValueError("Enabled-API response contains a malformed service")
                config = service.get("config")
                name = config.get("name") if isinstance(config, dict) else None
                if not isinstance(name, str) or not name:
                    raise ValueError("Enabled-API response contains an invalid service name")
                if name in enabled:
                    raise ValueError("Enabled-API response contains a duplicate service")
                enabled.add(name)
            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                return enabled
            next_page = payload["nextPageToken"]
            if not isinstance(next_page, str) or next_page in seen_tokens:
                raise ValueError("Enabled-API pagination returned an invalid/repeated token")
            seen_tokens.add(next_page)
            page_token = next_page
        raise ValueError("Enabled-API pagination exceeded the 10-page safety limit")

    def _application_global_access(self, spec: DeploymentSpec) -> tuple[bool | None, str | None]:
        """Resolve the Path B matcher address to a forwarding rule.

        The guide flags Global Access as a common Path B failure: a regional
        internal load balancer only accepts traffic from other regions when a
        frontend has Global Access enabled, or when the application pins an
        egress region. Nothing verified it, so the symptom first appeared at
        T07 as an unexplained timeout.

        Returns ``(allow_global_access, forwarding_rule_name)``. Both are None
        when the matcher is not a discoverable forwarding rule -- an FQDN, a
        GKE ingress, or a non-GCP backend -- which is a supported Path B target
        and must not be treated as a failure.
        """
        host = spec.application_hostname
        try:
            address = ip_address(host)
        except ValueError:
            # An FQDN cannot be matched to a forwarding rule without private
            # DNS resolution, which this application deliberately does not do.
            return None, None

        page_token: str | None = None
        seen_tokens: set[str] = set()
        matches: list[tuple[bool, str]] = []
        for _ in range(10):
            params: dict[str, str | int] = {
                "maxResults": 500,
                "returnPartialSuccess": "true",
            }
            if page_token:
                params["pageToken"] = page_token
            _, payload = self._transport.request_json(
                "GET",
                (
                    # The rule lives in the project owning the VPC, which for a
                    # cross-project upstream is not the deployment project.
                    f"https://compute.googleapis.com/compute/v1/projects/"
                    f"{spec.upstream_project_id}/aggregated/forwardingRules"
                ),
                params=params,
            )
            unreachables = payload.get("unreachables")
            if unreachables is not None and (
                not isinstance(unreachables, list)
                or not all(isinstance(item, str) and item for item in unreachables)
            ):
                raise ValueError("Forwarding-rule response unreachables is malformed")
            if unreachables:
                raise ValueError("Forwarding-rule discovery returned unreachable scopes")
            items = payload.get("items")
            if items is not None and not isinstance(items, dict):
                raise ValueError("Forwarding-rule response items is not an object")
            for scope_name, scope in (items or {}).items():
                if (
                    not isinstance(scope_name, str)
                    or not (scope_name == "global" or scope_name.startswith("regions/"))
                    or not isinstance(scope, dict)
                ):
                    raise ValueError("Forwarding-rule response contains an invalid scope")
                rules = scope.get("forwardingRules")
                if rules is None:
                    continue
                if not isinstance(rules, list):
                    raise ValueError("Forwarding-rule scope contains an invalid collection")
                for rule in rules:
                    if not isinstance(rule, dict):
                        raise ValueError("Forwarding-rule response contains a malformed item")
                    rule_address = rule.get("IPAddress")
                    name = rule.get("name")
                    if not isinstance(rule_address, str) or not isinstance(name, str) or not name:
                        raise ValueError("Forwarding-rule response contains an invalid identity")
                    try:
                        parsed_rule_address = ip_address(rule_address)
                    except ValueError as error:
                        raise ValueError(
                            "Forwarding-rule response contains an invalid IP"
                        ) from error
                    if parsed_rule_address != address:
                        continue
                    allow_global_raw = rule.get("allowGlobalAccess", False)
                    scheme = rule.get("loadBalancingScheme")
                    protocol = rule.get("IPProtocol")
                    ports = rule.get("ports")
                    port_range = rule.get("portRange")
                    expected_port = str(spec.application_port)
                    port_matches = (
                        isinstance(ports, list) and len(ports) == 1 and ports[0] == expected_port
                    ) or port_range in {expected_port, f"{expected_port}-{expected_port}"}
                    if (
                        not scope_name.startswith("regions/")
                        or scheme not in {"INTERNAL", "INTERNAL_MANAGED"}
                        or protocol != "TCP"
                        or not port_matches
                        or not isinstance(allow_global_raw, bool)
                    ):
                        raise ValueError(
                            "The application forwarding rule does not have exact "
                            "internal TCP semantics"
                        )
                    matches.append((allow_global_raw, name))
            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                if not matches:
                    return None, None
                if len(matches) != 1:
                    raise ValueError("Multiple forwarding rules use the application address")
                return matches[0]
            next_page = payload["nextPageToken"]
            if not isinstance(next_page, str) or next_page in seen_tokens:
                raise ValueError("Forwarding-rule pagination repeated an invalid page token")
            seen_tokens.add(next_page)
            page_token = next_page
        raise ValueError("Forwarding-rule pagination exceeded the 10-page safety limit")

    def _billing_enabled(self, project_id: str) -> bool:
        _, payload = self._transport.request_json(
            "GET",
            (f"https://cloudbilling.googleapis.com/v1/projects/{project_id}/billingInfo"),
        )
        return payload.get("billingEnabled") is True

    def _validate_certificate_secret(
        self,
        spec: DeploymentSpec,
        secret_name: str,
        *,
        version: str = "latest",
        require_crc32c: bool = False,
        require_numeric_version_name: bool = False,
        minimum_validity_days: int | None = None,
    ) -> PublicCertificateBinding | None:
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
        expected_crc32c = (
            secret_payload.get("dataCrc32c") if isinstance(secret_payload, dict) else None
        )
        if expected_crc32c is None and require_crc32c:
            raise ValueError("Secret Manager response is missing payload.dataCrc32c")
        if expected_crc32c is not None:
            try:
                expected_crc = int(expected_crc32c)
            except (TypeError, ValueError) as error:
                raise ValueError("Secret Manager payload.dataCrc32c is invalid") from error
            if expected_crc < 0 or expected_crc > 0xFFFFFFFF:
                raise ValueError("Secret Manager payload.dataCrc32c is invalid")
            if self._crc32c(decoded) != expected_crc:
                raise ValueError("Secret Manager payload CRC32C does not match")
        CertificateIssuer.validate_secret_payload(
            decoded,
            hostname=spec.private_hostname,
            minimum_validity_days=(
                minimum_validity_days
                if minimum_validity_days is not None
                else 30 if spec.mode.value == "production" else 1
            ),
        )
        if not require_numeric_version_name:
            return None
        version_name = payload.get("name")
        if not isinstance(version_name, str):
            raise ValueError("Secret Manager response is missing its numeric version name")
        binding = PublicCertificateBinding(
            secret_version_name=version_name,
            payload_sha256=hashlib.sha256(decoded).hexdigest(),
        )
        expected_prefix = f"projects/{spec.project_id}/secrets/{secret_name}/versions/"
        if not binding.secret_version_name.startswith(expected_prefix):
            raise ValueError(
                "Secret Manager response version does not belong to the referenced secret"
            )
        if version != "latest" and binding.secret_version_name != f"{expected_prefix}{version}":
            raise ValueError("Secret Manager response version identity changed")
        self._validated_tls_payload = decoded
        self._validated_tls_secret_name = secret_name
        self._validated_tls_version_name = binding.secret_version_name
        return binding

    @staticmethod
    def _certificate_chain_der(payload: bytes) -> tuple[bytes, ...]:
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("TLS secret payload is not valid JSON") from error
        if not isinstance(document, dict):
            raise ValueError("TLS secret payload must be an object")
        leaf = document.get("certificate_pem")
        chain = document.get("certificate_chain_pem")
        if (
            not isinstance(leaf, str)
            or not isinstance(chain, list)
            or not all(isinstance(item, str) for item in chain)
        ):
            raise ValueError("TLS secret certificate chain is malformed")
        try:
            certificates = [
                x509.load_pem_x509_certificate(item.encode("ascii"))
                for item in [leaf, *chain]
            ]
        except (UnicodeEncodeError, ValueError) as error:
            raise ValueError("TLS secret certificate chain is malformed") from error
        return tuple(
            certificate.public_bytes(serialization.Encoding.DER)
            for certificate in certificates
        )

    def _compatible_ssl_certificate(
        self,
        payload: dict[str, object],
        spec: DeploymentSpec,
        resource_name: str,
    ) -> bool:
        if self._validated_tls_payload is None:
            return False
        certificate_pem = payload.get("certificate")
        sans = payload.get("subjectAlternativeNames")
        expire_time = payload.get("expireTime")
        identifier = payload.get("id")
        self_link = payload.get("selfLink")
        region = payload.get("region")
        if (
            payload.get("name") != resource_name
            or payload.get("type") != "SELF_MANAGED"
            or not (
                (isinstance(identifier, int)
                and not isinstance(identifier, bool)
                and identifier > 0)
                or (isinstance(identifier, str)
                and identifier.isdigit()
                and int(identifier) > 0)
            )
            or not _compute_reference(
                self_link,
                f"/projects/{spec.project_id}/regions/{spec.region}/"
                f"sslCertificates/{resource_name}",
            )
            or not _compute_reference(
                region,
                f"/projects/{spec.project_id}/regions/{spec.region}",
            )
            or not isinstance(certificate_pem, str)
            or not isinstance(sans, list)
            or not all(isinstance(item, str) and item for item in sans)
            or len(set(sans)) != len(sans)
            or not isinstance(expire_time, str)
        ):
            return False
        try:
            returned = x509.load_pem_x509_certificates(certificate_pem.encode("ascii"))
            expected_der = self._certificate_chain_der(self._validated_tls_payload)
            returned_der = tuple(
                certificate.public_bytes(serialization.Encoding.DER)
                for certificate in returned
            )
            leaf_sans = returned[0].extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
            returned_expiry = datetime.fromisoformat(expire_time.replace("Z", "+00:00"))
        except (IndexError, UnicodeEncodeError, ValueError, x509.ExtensionNotFound):
            return False
        return (
            returned_der == expected_der
            and sans == leaf_sans
            and returned_expiry.tzinfo is not None
            and returned_expiry.astimezone(UTC)
            == returned[0].not_valid_after_utc.replace(microsecond=0)
        )

    @staticmethod
    def _crc32c(payload: bytes) -> int:
        """Return the unsigned Castagnoli CRC used by Secret Manager."""
        crc = 0xFFFFFFFF
        for byte in payload:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
        return (~crc) & 0xFFFFFFFF

    def _granted_permissions(self, project_id: str, permissions: set[str]) -> set[str]:
        project_permissions = sorted(permissions - {"accesscontextmanager.accessLevels.get"})
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

    def _discover_managed_certificate_version(
        self,
        spec: DeploymentSpec,
        secret_name: str,
        existing_keys: set[str],
        conflicting_keys: set[str],
        diagnostics: list[PreflightDiagnostic],
    ) -> None:
        secret_key = f"secretmanager:secret:{secret_name}"
        version_key = f"secretmanager:secret_version:{secret_name}"
        artifact_key = f"local:root_certificate_artifact:{spec.name}-poc-root"
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
            if not isinstance(metadata, dict):
                raise ValueError("Managed TLS secret metadata is malformed")
            labels = metadata.get("labels")
            replication = metadata.get("replication")
            if (
                metadata.get("name")
                != f"projects/{spec.project_id}/secrets/{secret_name}"
                or not isinstance(labels, dict)
                or set(labels)
                != {
                    "managed-by",
                    "configuration-hash",
                    "certificate-spec-hash",
                    "sgs-owner-token",
                }
                or labels.get("managed-by") != "secure-gateway-studio"
                or not isinstance(labels.get("configuration-hash"), str)
                or re.fullmatch(r"[0-9a-f]{32}", str(labels["configuration-hash"])) is None
                or not isinstance(labels.get("sgs-owner-token"), str)
                or re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
                    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                    str(labels["sgs-owner-token"]),
                    re.IGNORECASE,
                )
                is None
                or replication != {"automatic": {}}
            ):
                raise ValueError("Managed TLS secret metadata identity is malformed")
            if not self._owns_managed_resource(secret_key, metadata):
                raise ValueError("Managed TLS secret has no matching active ownership proof")
            if labels.get("certificate-spec-hash") != certificate_configuration_hash(spec)[:32]:
                diagnostics.append(
                    PreflightDiagnostic(
                        code="managed-certificate-rotation-required",
                        severity="warning",
                        message="The managed TLS certificate no longer matches the specification.",
                        remediation="Approve Apply to rotate the managed certificate.",
                    )
                )
                return
            aliases = metadata.get("versionAliases")
            if not isinstance(aliases, dict):
                raise ValueError("Managed TLS secret aliases are malformed")
            active = aliases.get("active")
            if active is None:
                diagnostics.append(
                    PreflightDiagnostic(
                        code="managed-certificate-alias-migration-required",
                        severity="warning",
                        message="The managed TLS secret has no active numeric version alias.",
                        remediation=(
                            "Approve Apply to create and bind a managed certificate version."
                        ),
                    )
                )
                return
            if not isinstance(active, str) or re.fullmatch(r"[1-9][0-9]*", active) is None:
                raise ValueError("Managed TLS secret active alias is invalid")
            binding = self._validate_certificate_secret(
                spec,
                secret_name,
                version=active,
                require_crc32c=True,
                require_numeric_version_name=True,
                minimum_validity_days=0,
            )
            if binding is None:
                raise ValueError("Managed TLS secret version binding is missing")
            if self._validated_tls_payload is None:
                raise ValueError("Managed TLS secret payload binding is missing")
            try:
                document = json.loads(self._validated_tls_payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("Managed TLS secret payload is not valid JSON") from error
            token = document.get("sgs_ownership_token") if isinstance(document, dict) else None
            proof = self._ownership_proofs.get(version_key)
            if (
                not isinstance(token, str)
                or proof is None
                or proof.marker != token
                or proof.provider_identity_field != "name"
                or proof.provider_identity != binding.secret_version_name
            ):
                raise ValueError(
                    "Managed TLS secret version has no matching active ownership proof"
                )
            try:
                CertificateIssuer.validate_secret_payload(
                    self._validated_tls_payload,
                    hostname=spec.private_hostname,
                    minimum_validity_days=(30 if spec.mode.value == "production" else 1),
                )
            except ValueError:
                self._validated_tls_payload = None
                self._validated_tls_secret_name = None
                self._validated_tls_version_name = None
                raise
            self._public_certificate_binding = binding
            existing_keys.add(version_key)
        except GoogleApiError as error:
            conflicting_keys.add(version_key)
            if spec.certificate_strategy is CertificateStrategy.LOCAL_POC:
                conflicting_keys.add(artifact_key)
            diagnostics.append(self._api_diagnostic(version_key, error))
        except ValueError as error:
            if "expires too soon" in str(error):
                diagnostics.append(
                    PreflightDiagnostic(
                        code="managed-certificate-rotation-required",
                        severity="warning",
                        message="The managed TLS certificate is nearing expiry.",
                        remediation="Approve Apply to rotate the managed certificate.",
                    )
                )
                return
            conflicting_keys.add(version_key)
            if spec.certificate_strategy is CertificateStrategy.LOCAL_POC:
                conflicting_keys.add(artifact_key)
            diagnostics.append(
                PreflightDiagnostic(
                    code="invalid-managed-certificate-secret",
                    severity="error",
                    message="The active managed TLS certificate is invalid.",
                    remediation=str(error),
                )
            )

    def _discover_local_poc_certificate(
        self,
        spec: DeploymentSpec,
        secret_name: str,
        existing_keys: set[str],
        conflicting_keys: set[str],
        diagnostics: list[PreflightDiagnostic],
    ) -> None:
        if spec.certificate_strategy is not CertificateStrategy.LOCAL_POC:
            return
        version_key = f"secretmanager:secret_version:{secret_name}"
        artifact_key = f"local:root_certificate_artifact:{spec.name}-poc-root"
        if (
            version_key not in existing_keys
            or self._validated_tls_payload is None
            or self._validated_tls_secret_name != secret_name
        ):
            return
        try:
            if self._artifact_store is None:
                return
            chain = self._certificate_chain_der(self._validated_tls_payload)
            if len(chain) != 2:
                raise ValueError("PoC TLS secret does not contain exactly one root certificate")
            artifact = self._artifact_store.read_root_certificate(spec.name)
            try:
                artifact_certificates = x509.load_pem_x509_certificates(artifact)
            except ValueError as error:
                raise ValueError("PoC root artifact is not valid PEM") from error
            if (
                len(artifact_certificates) != 1
                or artifact_certificates[0].public_bytes(serialization.Encoding.DER) != chain[-1]
            ):
                raise ValueError("PoC root artifact does not match the active TLS certificate")
            existing_keys.add(artifact_key)
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
        except ValueError as error:
            existing_keys.discard(version_key)
            existing_keys.discard(artifact_key)
            conflicting_keys.add(version_key)
            conflicting_keys.add(artifact_key)
            diagnostics.append(
                PreflightDiagnostic(
                    code="invalid-poc-root-artifact",
                    severity="error",
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
            marker_fqdn = f"_sgs-owner.{spec.private_hostname}."
            marker_name = quote(marker_fqdn, safe="")
            marker_status, marker = self._transport.request_json(
                "GET",
                (
                    f"https://dns.googleapis.com/dns/v1/projects/{spec.project_id}/"
                    f"managedZones/{spec.name}-zone/rrsets/{marker_name}/TXT"
                ),
                accepted_statuses=(200, 404),
            )

            # Only an exact absence of both SGS-managed record sets proves that
            # this reserved DNS name is available.  A partial response or an
            # address lookup failure must never be converted into a blind
            # changes.create call.
            if record_status == 404 and marker_status == 404:
                return
            if (
                address_status != 200
                or record_status != 200
                or marker_status != 200
                or not isinstance(address, dict)
                or not isinstance(record, dict)
                or not isinstance(marker, dict)
            ):
                conflicting_keys.add(record_key)
                return

            expected_address = address.get("address")
            marker_values = marker.get("rrdatas")
            marker_value = (
                marker_values[0]
                if isinstance(marker_values, list)
                and len(marker_values) == 1
                and isinstance(marker_values[0], str)
                else None
            )
            ownership_proof = self._ownership_proofs.get(record_key)
            if (
                isinstance(expected_address, str)
                and bool(expected_address)
                and record.get("name") == f"{spec.private_hostname}."
                and record.get("type") == "A"
                and record.get("ttl") == 60
                and record.get("rrdatas") == [expected_address]
                and marker.get("name") == marker_fqdn
                and marker.get("type") == "TXT"
                and marker.get("ttl") == 60
                and isinstance(marker_value, str)
                and ownership_proof is not None
                and ownership_proof.marker == marker_value
                and ownership_proof.provider_identity_field is None
                and ownership_proof.provider_identity is None
                and re.fullmatch(
                    r'"sgs-owner=[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-'
                    r'[89ab][0-9a-f]{3}-[0-9a-f]{12}"',
                    marker_value,
                    re.IGNORECASE,
                )
            ):
                existing_keys.add(record_key)
            else:
                conflicting_keys.add(record_key)
        except GoogleApiError as error:
            existing_keys.discard(record_key)
            conflicting_keys.add(record_key)
            diagnostics.append(self._api_diagnostic(record_key, error))
        except (TypeError, ValueError) as error:
            existing_keys.discard(record_key)
            conflicting_keys.add(record_key)
            diagnostics.append(
                PreflightDiagnostic(
                    code="dns-record-response-invalid",
                    severity="error",
                    message="DNS record discovery returned an invalid response.",
                    remediation=str(error),
                )
            )

    @staticmethod
    def _policy_has_binding(
        policy: object,
        *,
        role: str,
        members: set[str],
        condition: dict[str, str] | None = None,
    ) -> bool:
        validated = validate_iam_policy_v3(policy, require_etag=True)
        bindings = validated.get("bindings", [])
        return any(
            binding.get("role") == role
            and binding.get("condition") == condition
            and members <= set(binding.get("members", []))
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
        conflicting_keys: set[str],
        diagnostics: list[PreflightDiagnostic],
        condition: dict[str, str] | None = None,
        body: dict[str, object] | None = None,
    ) -> None:
        try:
            request_body = body
            request_params: dict[str, str | int] | None = None
            if method == "POST":
                request_body = {
                    **(body or {}),
                    "options": {"requestedPolicyVersion": 3},
                }
            else:
                request_params = {"options.requestedPolicyVersion": 3}
            status_code, policy = self._transport.request_json(
                method,
                url,
                params=request_params,
                json_body=request_body,
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
            conflicting_keys.add(key)
            diagnostics.append(self._api_diagnostic(key, error))
        except ValueError as error:
            conflicting_keys.add(key)
            diagnostics.append(
                PreflightDiagnostic(
                    code="iam-policy-discovery-invalid",
                    severity="error",
                    message=f"IAM discovery returned an invalid policy for {key}.",
                    remediation=str(error),
                )
            )

    def _discover_iam_bindings(
        self,
        spec: DeploymentSpec,
        existing_keys: set[str],
        conflicting_keys: set[str],
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
                    "serviceAccount:" + service_account_email(spec.name, spec.project_id, "offload")
                },
                existing_keys=existing_keys,
                conflicting_keys=conflicting_keys,
                diagnostics=diagnostics,
            )
        self._discover_iam_binding(
            key=f"beyondcorp:gateway_iam:{spec.gateway_id}-service-discovery-users",
            method="GET",
            url=f"{gateway}:getIamPolicy",
            role="roles/beyondcorp.serviceDiscoveryUser",
            members=members,
            existing_keys=existing_keys,
            conflicting_keys=conflicting_keys,
            diagnostics=diagnostics,
        )
        gateway_account: str | None = None
        try:
            status_code, payload = self._transport.request_json(
                "GET", gateway, accepted_statuses=(200, 404)
            )
            account = payload.get("delegatingServiceAccount")
            if status_code == 200:
                if not isinstance(account, str) or not account:
                    raise ValueError(
                        "Gateway response omitted its delegating service-account identity"
                    )
                gateway_account = account
        except GoogleApiError as error:
            conflicting_keys.add(f"beyondcorp:security_gateway:{spec.gateway_id}")
            conflicting_keys.add(f"cloudresourcemanager:project_iam:{spec.name}-upstream-access")
            diagnostics.append(self._api_diagnostic("beyondcorp:security_gateway", error))
        except ValueError as error:
            conflicting_keys.add(f"beyondcorp:security_gateway:{spec.gateway_id}")
            conflicting_keys.add(f"cloudresourcemanager:project_iam:{spec.name}-upstream-access")
            diagnostics.append(
                PreflightDiagnostic(
                    code="gateway-delegating-service-account-invalid",
                    severity="error",
                    message="Gateway discovery returned an invalid service-account identity.",
                    remediation=str(error),
                )
            )
        if gateway_account:
            self._discover_iam_binding(
                key=f"cloudresourcemanager:project_iam:{spec.name}-upstream-access",
                method="POST",
                url=(
                    f"https://cloudresourcemanager.googleapis.com/v1/projects/"
                    f"{spec.upstream_project_id}:getIamPolicy"
                ),
                body={},
                role="roles/beyondcorp.upstreamAccess",
                members={f"serviceAccount:{gateway_account}"},
                existing_keys=existing_keys,
                conflicting_keys=conflicting_keys,
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
            conflicting_keys=conflicting_keys,
            diagnostics=diagnostics,
        )

    @staticmethod
    def _parse_resolved_chrome_policy(
        payload: dict[str, object],
        *,
        schema: str,
        app_id: str | None,
        target_resource: str,
    ) -> tuple[dict[str, object] | None, str | None]:
        if "resolvedPolicies" not in payload:
            raise ValueError("Chrome Policy resolve response omitted resolvedPolicies")
        policies = payload["resolvedPolicies"]
        if not isinstance(policies, list):
            raise ValueError("Chrome Policy resolve response is malformed")
        if len(policies) == 0:
            return None, None
        if len(policies) != 1:
            raise ValueError("Chrome Policy resolve response contains duplicates")
        policy = policies[0]
        if not isinstance(policy, dict):
            raise ValueError("Chrome Policy resolve response contains a malformed policy")
        expected_target: dict[str, object] = {"targetResource": target_resource}
        if app_id is not None:
            expected_target["additionalTargetKeys"] = {"app_id": f"chrome:{app_id}"}
        if policy.get("targetKey") != expected_target:
            raise ValueError("Chrome Policy resolve response has an unexpected target")
        source = (
            GoogleDiscoveryProvider._chrome_policy_source_resource(
                policy["sourceKey"],
                label="sourceKey",
            )
            if "sourceKey" in policy
            else None
        )
        added_source = None
        if "addedSourceKey" in policy:
            added_source = GoogleDiscoveryProvider._chrome_policy_source_resource(
                policy["addedSourceKey"],
                label="addedSourceKey",
            )
        expected_source_kind = target_resource.partition("/")[0] + "/"
        if (source is not None and not source.startswith(expected_source_kind)) or (
            added_source is not None and not added_source.startswith(expected_source_kind)
        ):
            raise ValueError("Chrome Policy resolve response has an invalid source kind")
        policy_value = policy.get("value")
        if not isinstance(policy_value, dict) or policy_value.get("policySchema") != schema:
            raise ValueError("Chrome Policy resolve response has the wrong schema")
        value = policy_value.get("value")
        if not isinstance(value, dict):
            raise ValueError("Chrome Policy resolve response has a malformed value")
        return value, source

    def _list_resolved_chrome_policies(
        self,
        spec: DeploymentSpec,
        *,
        schema: str,
        target: dict[str, object],
    ) -> dict[str, object]:
        policies: list[object] = []
        seen_tokens: set[str] = set()
        page_token: str | None = None
        for page in range(20):
            body: dict[str, object] = {
                "policyTargetKey": target,
                "policySchemaFilter": schema,
                "pageSize": 1_000,
            }
            if page_token is not None:
                body["pageToken"] = page_token
            _, payload = self._transport.request_json(
                "POST",
                (
                    "https://chromepolicy.googleapis.com/v1/customers/"
                    f"{spec.customer_id}/policies:resolve"
                ),
                json_body=body,
            )
            page_policies = payload.get("resolvedPolicies")
            if not isinstance(page_policies, list) or any(
                not isinstance(item, dict) for item in page_policies
            ):
                raise ValueError("Chrome Policy resolve response is malformed")
            policies.extend(page_policies)
            if len(policies) > 2_000:
                raise ValueError("Chrome Policy resolve exceeded the item safety limit")
            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                return {"resolvedPolicies": policies}
            next_token = payload["nextPageToken"]
            if not isinstance(next_token, str) or next_token in seen_tokens:
                raise ValueError("Chrome Policy resolve returned an invalid page token")
            seen_tokens.add(next_token)
            if page + 1 >= 20:
                raise ValueError("Chrome Policy resolve pagination did not complete")
            page_token = next_token
        raise ValueError("Chrome Policy resolve pagination did not complete")

    @staticmethod
    def _chrome_policy_source_resource(value: object, *, label: str) -> str:
        if not isinstance(value, dict) or not set(value) <= {
            "targetResource",
            "additionalTargetKeys",
        }:
            raise ValueError(f"Chrome Policy resolve response has a malformed {label}")
        source = value.get("targetResource")
        if (
            not isinstance(source, str)
            or re.fullmatch(r"(?:orgunits|groups)/[A-Za-z0-9_-]+", source) is None
        ):
            raise ValueError(f"Chrome Policy resolve response has an invalid {label} target")
        if "additionalTargetKeys" in value:
            additional = value["additionalTargetKeys"]
            if not isinstance(additional, dict) or additional:
                raise ValueError(
                    f"Chrome Policy resolve response has unexpected {label} target keys"
                )
        return source

    def _resolve_chrome_policy(
        self,
        spec: DeploymentSpec,
        *,
        schema: str,
        app_id: str,
    ) -> dict[str, object] | None:
        payload = self._list_resolved_chrome_policies(
            spec,
            schema=schema,
            target={
                "targetResource": f"orgunits/{spec.target_ou_id}",
                "additionalTargetKeys": {"app_id": f"chrome:{app_id}"},
            },
        )
        value, source = self._parse_resolved_chrome_policy(
            payload,
            schema=schema,
            app_id=app_id,
            target_resource=f"orgunits/{spec.target_ou_id}",
        )
        return value if source == f"orgunits/{spec.target_ou_id}" else None

    def _resolve_chrome_user_policy(
        self,
        spec: DeploymentSpec,
        *,
        schema: str,
    ) -> tuple[dict[str, object] | None, str | None]:
        payload = self._list_resolved_chrome_policies(
            spec,
            schema=schema,
            target={"targetResource": f"orgunits/{spec.target_ou_id}"},
        )
        return self._parse_resolved_chrome_policy(
            payload,
            schema=schema,
            app_id=None,
            target_resource=f"orgunits/{spec.target_ou_id}",
        )

    def _discover_chrome_policies(
        self,
        spec: DeploymentSpec,
        existing_keys: set[str],
        conflicting_keys: set[str],
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
                conflicting_keys.add(key)
                diagnostics.append(self._api_diagnostic(key, error))
            except ValueError as error:
                conflicting_keys.add(key)
                diagnostics.append(
                    PreflightDiagnostic(
                        code="chrome-policy-discovery-invalid",
                        severity="error",
                        message=f"Chrome Policy discovery failed closed for {key}.",
                        remediation=str(error),
                    )
                )

        proxy_key = f"chromepolicy:service_discovery_proxy:{spec.target_ou_id}"
        try:
            value, source = self._resolve_chrome_user_policy(
                spec,
                schema="chrome.users.SimpleProxySettings",
            )
            mode = value.get("simpleProxyMode") if value else None
            if value is not None and not isinstance(mode, str):
                raise ValueError("Chrome proxy policy omitted simpleProxyMode")
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
            conflicting_keys.add(proxy_key)
            diagnostics.append(self._api_diagnostic(proxy_key, error))
        except ValueError as error:
            conflicting_keys.add(proxy_key)
            diagnostics.append(
                PreflightDiagnostic(
                    code="chrome-policy-discovery-invalid",
                    severity="error",
                    message="Chrome proxy policy discovery failed closed.",
                    remediation=str(error),
                )
            )

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
                f"projects/{spec.project_id}/locations/global/securityGateways/{spec.gateway_id}"
            )
            if resource == expected:
                existing_keys.add(configuration_key)
        except (GoogleApiError, json.JSONDecodeError, ValueError) as error:
            conflicting_keys.add(configuration_key)
            if isinstance(error, GoogleApiError):
                diagnostics.append(self._api_diagnostic(configuration_key, error))
            else:
                diagnostics.append(
                    PreflightDiagnostic(
                        code="invalid-chrome-managed-configuration",
                        severity="error",
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
    ) -> tuple[list[str], bool]:
        """Find group app policies that take precedence over the selected OU."""

        group_principals = {
            principal.value for principal in spec.principals if principal.type.value == "group"
        }
        user_principals = {
            principal.value for principal in spec.principals if principal.type.value == "user"
        }
        if not group_principals and not user_principals:
            return [], True

        groups: list[dict[str, object]] = []
        page_token: str | None = None
        seen_tokens: set[str] = set()
        try:
            for _ in range(10):
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
                items = payload.get("groups", [])
                if not isinstance(items, list):
                    raise ValueError("Group listing returned an invalid groups collection")
                for item in items:
                    if not isinstance(item, dict):
                        raise ValueError("Group listing returned a malformed group item")
                    email = item.get("email")
                    group_id = item.get("id")
                    if (
                        not isinstance(email, str)
                        or not email
                        or email != email.strip()
                        or email.count("@") != 1
                        or email.startswith("@")
                        or email.endswith("@")
                        or any(character.isspace() for character in email)
                        or not isinstance(group_id, str)
                        or not group_id
                        or group_id != group_id.strip()
                        or any(character.isspace() for character in group_id)
                    ):
                        raise ValueError(
                            "Group listing returned a group with an invalid email or id"
                        )
                    groups.append(item)
                if len(groups) > 2000:
                    raise ValueError("Group listing exceeded the 2,000-group safety limit")
                if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                    page_token = None
                    break
                next_token = payload["nextPageToken"]
                if not isinstance(next_token, str) or next_token in seen_tokens:
                    raise ValueError("Group listing repeated an invalid page token")
                seen_tokens.add(next_token)
                page_token = next_token
            else:
                if page_token is not None:
                    raise ValueError("Group listing exceeded the 10-page safety limit")
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("chrome-group-policy-membership", error))
            return [], False
        except ValueError as error:
            diagnostics.append(
                PreflightDiagnostic(
                    code="chrome-group-policy-discovery-truncated",
                    severity="error",
                    message="Group policy discovery did not complete safely.",
                    remediation=(
                        "Narrow the approved principals or review group-scoped Chrome "
                        f"policies manually before Apply. Detail: {error}"
                    ),
                )
            )
            return [], False

        candidate_groups: dict[str, str] = {}
        discovery_complete = True
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
                    discovery_complete = False
                    continue
                is_member = membership.get("isMember")
                if not isinstance(is_member, bool):
                    diagnostics.append(
                        PreflightDiagnostic(
                            code="chrome-group-policy-membership-invalid",
                            severity="error",
                            message=(
                                "Directory membership discovery returned an invalid "
                                f"result for {user_email} in {normalized_email}."
                            ),
                            remediation=(
                                "Retry preflight and review group-scoped Chrome policies "
                                "manually if Directory continues returning malformed data."
                            ),
                        )
                    )
                    discovery_complete = False
                    continue
                if is_member:
                    candidate_groups[normalized_email] = group_id
                    break

        expected_resource = (
            f"projects/{spec.project_id}/locations/global/securityGateways/{spec.gateway_id}"
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
                discovery_complete = False
                continue
            except ValueError as error:
                diagnostics.append(
                    PreflightDiagnostic(
                        code="chrome-group-policy-response-invalid",
                        severity="error",
                        message=(f"Group {email} Chrome policy discovery returned malformed data."),
                        remediation=str(error),
                    )
                )
                discovery_complete = False
                continue
            if value is None:
                continue
            encoded = value.get("managedConfiguration")
            try:
                if not isinstance(encoded, str):
                    raise ValueError("Resolved group policy is missing managedConfiguration")
                decoded = json.loads(encoded)
                if not isinstance(decoded, dict):
                    raise ValueError("Resolved group managedConfiguration is not a JSON object")
            except (json.JSONDecodeError, ValueError) as error:
                diagnostics.append(
                    PreflightDiagnostic(
                        code="chrome-group-policy-response-invalid",
                        severity="error",
                        message=(f"Group {email} Chrome managed configuration is malformed."),
                        remediation=str(error),
                    )
                )
                discovery_complete = False
                continue
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
            conflicting_keys.add(f"chromepolicy:group_extension_configuration:{email}")
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
        return conflicts, discovery_complete

    def _resolve_chrome_policy_target(
        self,
        spec: DeploymentSpec,
        *,
        schema: str,
        app_id: str,
        target_resource: str,
    ) -> dict[str, object] | None:
        target = {
            "targetResource": target_resource,
            "additionalTargetKeys": {"app_id": f"chrome:{app_id}"},
        }
        payload = self._list_resolved_chrome_policies(
            spec,
            schema=schema,
            target=target,
        )
        value, source = self._parse_resolved_chrome_policy(
            payload,
            schema=schema,
            app_id=app_id,
            target_resource=target_resource,
        )
        if source != target_resource:
            return None
        if value is None or not isinstance(value.get("managedConfiguration"), str):
            raise ValueError("Chrome Policy resolve returned a malformed managedConfiguration")
        return value

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
        profiles: list[dict[str, object]] = []
        page_token: str | None = None
        seen_tokens: set[str] = set()
        try:
            for _ in range(20):
                params: dict[str, str | int] = {
                    "pageSize": 200,
                    "filter": f"ouId = {spec.target_ou_id}",
                    "orderBy": "lastPolicySyncTime desc",
                }
                if page_token:
                    params["pageToken"] = page_token
                _, payload = self._transport.request_json(
                    "GET",
                    (
                        f"https://chromemanagement.googleapis.com/v1/customers/"
                        f"{spec.customer_id}/profiles"
                    ),
                    params=params,
                )
                page_profiles = payload.get("chromeBrowserProfiles")
                if page_profiles is not None and not isinstance(page_profiles, list):
                    raise ValueError("Chrome profile response is not a list")
                for profile in page_profiles or []:
                    if not isinstance(profile, dict):
                        raise ValueError("Chrome profile response contains a malformed item")
                    affiliation = profile.get("affiliationState")
                    if not isinstance(affiliation, str) or not affiliation:
                        raise ValueError("Chrome profile affiliationState is invalid")
                    sync_time = profile.get("lastPolicySyncTime")
                    if sync_time is not None and (not isinstance(sync_time, str) or not sync_time):
                        raise ValueError("Chrome profile lastPolicySyncTime is invalid")
                    reporting = profile.get("reportingData")
                    if reporting is not None and not isinstance(reporting, dict):
                        raise ValueError("Chrome profile reportingData is invalid")
                    extension_data = (
                        reporting.get("extensionData") if isinstance(reporting, dict) else None
                    )
                    if extension_data is not None and not isinstance(extension_data, list):
                        raise ValueError("Chrome profile extensionData is invalid")
                    for extension in extension_data or []:
                        if not isinstance(extension, dict):
                            raise ValueError("Chrome profile extensionData item is invalid")
                        extension_id = extension.get("extensionId")
                        disabled = extension.get("isDisabled")
                        version = extension.get("version")
                        if (
                            not isinstance(extension_id, str)
                            or not extension_id
                            or (disabled is not None and not isinstance(disabled, bool))
                            or (
                                version is not None
                                and (not isinstance(version, str) or not version)
                            )
                        ):
                            raise ValueError("Chrome profile extension identity is invalid")
                    profiles.append(profile)
                if len(profiles) > 4_000:
                    page_token = "profile-limit-exceeded"
                    break
                if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                    page_token = None
                    break
                next_token = payload["nextPageToken"]
                if not isinstance(next_token, str) or next_token in seen_tokens:
                    raise ValueError("Chrome profile pagination returned an invalid/repeated token")
                seen_tokens.add(next_token)
                page_token = next_token
            if page_token:
                diagnostics.append(
                    PreflightDiagnostic(
                        code="chrome-profile-readiness-truncated",
                        severity="error",
                        message=(
                            "Chrome profile discovery exceeded the 4,000-profile safety limit."
                        ),
                        remediation=(
                            "Narrow the target OU or review its profile readiness "
                            "manually before Apply."
                        ),
                    )
                )
                return None, None, None, None, None, None, None
        except GoogleApiError as error:
            diagnostics.append(self._api_diagnostic("chrome-profile-readiness", error))
            return None, None, None, None, None, None, None
        except ValueError as error:
            diagnostics.append(
                PreflightDiagnostic(
                    code="chrome-profile-readiness-pagination-invalid",
                    severity="error",
                    message="Chrome profile pagination could not be completed safely.",
                    remediation=str(error),
                )
            )
            return None, None, None, None, None, None, None

        managed_profiles = profiles
        profile_only_count = sum(
            profile.get("affiliationState") == "PROFILE_ONLY" for profile in managed_profiles
        )
        sync_times = [
            value
            for profile in managed_profiles
            if isinstance((value := profile.get("lastPolicySyncTime")), str) and value
        ]
        latest_sync = max(sync_times) if sync_times else None

        extension_versions: dict[str, str] = {}
        for profile in managed_profiles:
            reporting = profile.get("reportingData")
            extensions = reporting.get("extensionData") if isinstance(reporting, dict) else None
            if extensions is None:
                continue
            for extension in extensions:
                if extension.get("isDisabled") is True:
                    continue
                extension_id = extension.get("extensionId")
                version = extension.get("version")
                candidate = version if isinstance(version, str) else "installed"
                current = extension_versions.get(extension_id)
                if current is None or self._version_key(candidate) > self._version_key(current):
                    extension_versions[extension_id] = candidate

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
        seen_page_tokens: set[str] = set()
        seen_users: set[str] = set()
        try:
            for _ in range(20):
                params: dict[str, str | int] = {
                    "customerId": spec.customer_id,
                    "maxResults": 1000,
                }
                if page_token:
                    params["pageToken"] = page_token
                status_code, payload = self._transport.request_json(
                    "GET",
                    (
                        "https://licensing.googleapis.com/apps/licensing/v1/"
                        "product/101040/sku/1010400001/users"
                    ),
                    params=params,
                    accepted_statuses=(200, 404),
                )
                if status_code == 404:
                    page_token = None
                    break
                items = payload.get("items")
                if items is not None and not isinstance(items, list):
                    raise ValueError("License response items is not a list")
                for item in items or []:
                    if not isinstance(item, dict):
                        raise ValueError("License response contains a malformed item")
                    user_id = _license_assignment_user(item)
                    canonical_user = user_id.casefold()
                    if canonical_user in seen_users:
                        raise ValueError("License response contains a duplicate user")
                    seen_users.add(canonical_user)
                    count += 1
                if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                    page_token = None
                    break
                next_token = payload["nextPageToken"]
                if not isinstance(next_token, str) or next_token in seen_page_tokens:
                    raise ValueError("License pagination returned an invalid/repeated page token")
                seen_page_tokens.add(next_token)
                page_token = next_token
            if page_token:
                raise ValueError("License pagination exceeded the 20-page safety limit")
        except (GoogleApiError, ValueError) as error:
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

    @staticmethod
    def _version_key(version: str) -> tuple[tuple[int, int | str], ...]:
        return tuple(
            (0, int(part)) if part.isdigit() else (1, part)
            for part in version.replace("-", ".").split(".")
        )

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
        except ValueError as error:
            diagnostics.append(
                PreflightDiagnostic(
                    code="chrome-root-store-policy-invalid",
                    severity="error",
                    message="Chrome Root Store policy discovery failed closed.",
                    remediation=str(error),
                )
            )
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
            # For a cross-project Path B upstream the VPC is not in the
            # deployment project; probe where it actually lives.
            "https://compute.googleapis.com/compute/v1/projects/"
            f"{spec.upstream_project_id}/global/networks/{network_name}",
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
        router_key = f"compute:router:{spec.name}-router"
        nat_key = f"compute:cloud_nat:{spec.name}-nat"
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
        if not isinstance(nats, list) or not all(isinstance(nat, dict) for nat in nats):
            raise ValueError("Cloud Router returned malformed NAT state")
        named = [nat for nat in nats if nat.get("name") == f"{spec.name}-nat"]
        if len(named) > 1:
            raise ValueError("Cloud Router returned duplicate reserved NAT names")
        if not named:
            return False
        expected_subnet = (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"regions/{spec.region}/subnetworks/{self._subnet_name(spec)}"
        )
        nat = named[0]
        if (
            not _owned_description(payload)
            or not self._owns_managed_resource(router_key, payload)
            or not self._owns_managed_resource(nat_key, payload)
            or nat.get("natIpAllocateOption") != "AUTO_ONLY"
            or nat.get("sourceSubnetworkIpRangesToNat") != "LIST_OF_SUBNETWORKS"
            or nat.get("subnetworks")
            != [
                {
                    "name": expected_subnet,
                    "sourceIpRangesToNat": ["ALL_IP_RANGES"],
                }
            ]
            or nat.get("logConfig") != {"enable": True, "filter": "ERRORS_ONLY"}
        ):
            raise ValueError("Cloud NAT ownership or managed state is not exact")
        return True

    def _existing_private_egress_available(self, spec: DeploymentSpec) -> bool:
        expected_network_suffix = f"/global/networks/{spec.vpc_name}"
        expected_subnet_suffix = f"/regions/{spec.region}/subnetworks/{spec.subnet_name}"
        page_token: str | None = None
        seen_tokens: set[str] = set()
        found = False
        for _ in range(10):
            params: dict[str, str | int] = {
                "maxResults": 500,
                "returnPartialSuccess": "true",
            }
            if page_token is not None:
                params["pageToken"] = page_token
            _, payload = self._transport.request_json(
                "GET",
                f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
                "aggregated/routers",
                params=params,
            )
            unreachables = payload.get("unreachables")
            if unreachables is not None and (
                not isinstance(unreachables, list)
                or not all(isinstance(item, str) and item for item in unreachables)
            ):
                raise ValueError("Router response unreachables is malformed")
            if unreachables:
                raise ValueError("Router discovery returned unreachable scopes")
            scoped_items = payload.get("items")
            if scoped_items is not None and not isinstance(scoped_items, dict):
                raise ValueError("Router response items is not an object")
            for scope_name, scoped in (scoped_items or {}).items():
                if (
                    not isinstance(scope_name, str)
                    or not scope_name.startswith("regions/")
                    or not isinstance(scoped, dict)
                ):
                    raise ValueError("Router response contains an invalid scope")
                if scope_name != f"regions/{spec.region}":
                    continue
                routers = scoped.get("routers")
                if routers is None:
                    warning = scoped.get("warning")
                    if not isinstance(warning, dict) or not isinstance(warning.get("code"), str):
                        raise ValueError("Router scope has neither routers nor a warning")
                    raise ValueError("Target-region router discovery returned a warning")
                if not isinstance(routers, list):
                    raise ValueError("Router scope contains an invalid routers collection")
                for router in routers:
                    if not isinstance(router, dict):
                        raise ValueError("Router response contains a malformed router")
                    network = router.get("network")
                    # Empty repeated fields are legally omitted from REST JSON.
                    nats = router.get("nats", [])
                    if not isinstance(network, str) or not isinstance(nats, list):
                        raise ValueError("Router response contains invalid network/NAT state")
                    if not _compute_reference(
                        network,
                        f"/projects/{spec.project_id}{expected_network_suffix}",
                    ):
                        continue
                    for nat in nats:
                        if not isinstance(nat, dict):
                            raise ValueError("Router response contains a malformed NAT")
                        nat_type = nat.get("type")
                        endpoint_types = nat.get("endpointTypes")
                        allocation = nat.get("natIpAllocateOption")
                        if nat_type not in {None, "PUBLIC"}:
                            continue
                        if endpoint_types is not None and (
                            not isinstance(endpoint_types, list)
                            or not all(isinstance(item, str) for item in endpoint_types)
                            or len(set(endpoint_types)) != len(endpoint_types)
                            or set(endpoint_types) not in (set(), {"ENDPOINT_TYPE_VM"})
                        ):
                            raise ValueError("Router response contains invalid NAT endpoint types")
                        if allocation == "MANUAL_ONLY":
                            nat_ips = nat.get("natIps")
                            if (
                                not isinstance(nat_ips, list)
                                or not nat_ips
                                or not all(
                                    _compute_reference(
                                        item,
                                        f"/projects/{spec.project_id}/regions/{spec.region}/"
                                        f"addresses/{str(item).rsplit('/', maxsplit=1)[-1]}",
                                    )
                                    for item in nat_ips
                                )
                            ):
                                raise ValueError("Manual Public NAT has invalid address bindings")
                        elif allocation != "AUTO_ONLY":
                            raise ValueError("Router response contains an invalid NAT allocation")
                        mode = nat.get("sourceSubnetworkIpRangesToNat")
                        if mode in {
                            "ALL_SUBNETWORKS_ALL_IP_RANGES",
                            "ALL_SUBNETWORKS_ALL_PRIMARY_IP_RANGES",
                        }:
                            found = True
                            continue
                        if mode != "LIST_OF_SUBNETWORKS":
                            continue
                        subnetworks = nat.get("subnetworks")
                        if not isinstance(subnetworks, list):
                            raise ValueError("NAT subnet coverage is malformed")
                        for subnetwork in subnetworks:
                            if not isinstance(subnetwork, dict):
                                raise ValueError("NAT subnetwork coverage is malformed")
                            name = subnetwork.get("name")
                            ranges = subnetwork.get("sourceIpRangesToNat")
                            if (
                                isinstance(name, str)
                                and _compute_reference(
                                    name,
                                    f"/projects/{spec.project_id}{expected_subnet_suffix}",
                                )
                                and isinstance(ranges, list)
                                and all(isinstance(item, str) for item in ranges)
                                and set(ranges)
                                in (
                                    {"ALL_IP_RANGES"},
                                    {"PRIMARY_IP_RANGE"},
                                )
                            ):
                                found = True
            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                return found and self._default_internet_route_available(spec)
            next_token = payload["nextPageToken"]
            if not isinstance(next_token, str) or next_token in seen_tokens:
                raise ValueError("Router pagination returned an invalid/repeated token")
            seen_tokens.add(next_token)
            page_token = next_token
        raise ValueError("Router pagination exceeded the 10-page safety limit")

    def _default_internet_route_available(self, spec: DeploymentSpec) -> bool:
        expected_network = f"/projects/{spec.project_id}/global/networks/{spec.vpc_name}"
        expected_gateway = (
            f"/projects/{spec.project_id}/global/gateways/default-internet-gateway"
        )
        page_token: str | None = None
        seen_tokens: set[str] = set()
        candidates: list[tuple[int, bool]] = []
        for _ in range(10):
            params: dict[str, str | int] = {"maxResults": 500}
            if page_token is not None:
                params["pageToken"] = page_token
            _, payload = self._transport.request_json(
                "GET",
                f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
                "global/routes",
                params=params,
            )
            items = payload.get("items")
            if items is not None and not isinstance(items, list):
                raise ValueError("Route response items is not a list")
            if items is None and "warning" in payload:
                warning = payload["warning"]
                if not isinstance(warning, dict) or not isinstance(warning.get("code"), str):
                    raise ValueError("Route response warning is malformed")
            for route in items or []:
                if not isinstance(route, dict):
                    raise ValueError("Route response contains a malformed item")
                name = route.get("name")
                network = route.get("network")
                destination = route.get("destRange")
                if (
                    not isinstance(name, str)
                    or not name
                    or not isinstance(network, str)
                    or not isinstance(destination, str)
                ):
                    raise ValueError("Route response contains an invalid identity")
                if not _compute_reference(network, expected_network) or destination != "0.0.0.0/0":
                    continue
                tags = route.get("tags")
                if tags is not None and (
                    not isinstance(tags, list)
                    or not all(isinstance(item, str) and item for item in tags)
                ):
                    raise ValueError("Route response contains invalid tags")
                if tags and not set(tags).intersection(
                    {f"{spec.name}-backend", f"{spec.name}-offload"}
                ):
                    continue
                priority = route.get("priority")
                if (
                    not isinstance(priority, int)
                    or isinstance(priority, bool)
                    or priority < 0
                ):
                    raise ValueError("Route response contains an invalid priority")
                if route.get("status") not in {None, "ACTIVE"}:
                    raise ValueError("Applicable default route is not active")
                is_default_gateway = (
                    route.get("routeType") in {None, "STATIC"}
                    and _compute_reference(route.get("nextHopGateway"), expected_gateway)
                )
                candidates.append((priority, is_default_gateway))
            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                if not candidates:
                    return False
                winning_priority = min(priority for priority, _ in candidates)
                winners = [
                    is_default
                    for priority, is_default in candidates
                    if priority == winning_priority
                ]
                return len(winners) == 1 and winners[0]
            token = payload["nextPageToken"]
            if not isinstance(token, str) or not token or token in seen_tokens:
                raise ValueError("Route pagination returned an invalid/repeated token")
            seen_tokens.add(token)
            page_token = token
        raise ValueError("Route pagination exceeded the 10-page safety limit")

    def _owns_managed_resource(
        self,
        key: str,
        payload: Mapping[str, object],
    ) -> bool:
        proof = self._ownership_proofs.get(key)
        if proof is None:
            return False
        if (
            proof.provider_identity_field is not None
            or proof.provider_identity is not None
        ):
            if (
                not isinstance(proof.provider_identity_field, str)
                or not isinstance(proof.provider_identity, str)
            ):
                return False
            live_identity = payload.get(proof.provider_identity_field)
            if (
                not isinstance(live_identity, (str, int))
                or isinstance(live_identity, bool)
                or str(live_identity) != proof.provider_identity
            ):
                return False
        if proof.marker is None:
            return True
        if payload.get("description") == proof.marker:
            return True
        labels = payload.get("labels")
        return (
            isinstance(labels, dict)
            and labels.get("sgs-owner-token") == proof.marker
        )

    def _compatible(
        self,
        key: str,
        payload: dict[str, object],
        spec: DeploymentSpec,
    ) -> bool:
        """Fail closed when a same-name resource is not semantically reusable."""
        _, resource_type, resource_name = key.split(":", maxsplit=2)
        network_suffix = f"/projects/{spec.project_id}/global/networks/{self._network_name(spec)}"
        subnet_suffix = f"/regions/{spec.region}/subnetworks/{self._subnet_name(spec)}"

        if resource_type == "network":
            if spec.network_strategy is NetworkStrategy.EXISTING:
                return payload.get("name") == spec.vpc_name
            return (
                payload.get("name") == resource_name
                and payload.get("autoCreateSubnetworks") is False
                and _compatible_routing_config(payload.get("routingConfig"))
                and _owned_description(payload, "Managed by Secure Gateway Studio")
                and self._owns_managed_resource(key, payload)
            )
        if resource_type == "source_image":
            deprecated = payload.get("deprecated")
            state = deprecated.get("state") if isinstance(deprecated, dict) else None
            self_link = payload.get("selfLink")
            identifier = payload.get("id")
            expected_path = f"/{resource_name}"
            compatible = (
                payload.get("name") == resource_name.rsplit("/", 1)[-1]
                and _compute_reference(self_link, expected_path)
                and (
                    (isinstance(identifier, str)
                    and identifier.isdigit()
                    and int(identifier) > 0)
                    or (isinstance(identifier, int)
                    and not isinstance(identifier, bool)
                    and identifier > 0)
                )
                and state not in {"OBSOLETE", "DELETED"}
            )
            if compatible:
                self._source_image_binding = SourceImageBinding(
                    name=resource_name,
                    id=str(identifier),
                    self_link=(
                        "https://www.googleapis.com/compute/v1/"
                        f"{resource_name}"
                    ),
                )
            return compatible
        if resource_type == "subnetwork":
            network = payload.get("network")
            if not isinstance(network, str) or not network.endswith(network_suffix):
                return False
            self_link = payload.get("selfLink")
            expected_self_link = (
                f"/compute/v1/projects/{spec.project_id}/regions/{spec.region}/"
                f"subnetworks/{resource_name}"
            )
            identity_matches = (
                payload.get("name") == resource_name
                and (
                    self_link is None
                    or (isinstance(self_link, str)
                    and self_link.endswith(expected_self_link))
                )
            )
            if not identity_matches:
                return False
            if resource_name.endswith("-proxy-subnet"):
                return (
                    _owned_description(payload)
                    and self._owns_managed_resource(key, payload)
                    and payload.get("ipCidrRange") == spec.proxy_subnet_cidr
                    and payload.get("purpose") == "REGIONAL_MANAGED_PROXY"
                    and payload.get("role") == "ACTIVE"
                    and payload.get("privateIpGoogleAccess") is False
                    and payload.get("stackType") == "IPV4_ONLY"
                )
            managed = spec.network_strategy is NetworkStrategy.DEDICATED
            return (
                (
                    not managed
                    or (_owned_description(payload)
                    and self._owns_managed_resource(key, payload))
                )
                # subnet_cidr is a creation input for a run-owned dedicated
                # subnet. The UI deliberately does not ask an operator to
                # re-enter the CIDR of an administrator-managed existing
                # subnet, so comparing that resource with the hidden creation
                # default would reject every otherwise-valid non-default VPC.
                and (not managed or payload.get("ipCidrRange") == spec.subnet_cidr)
                and payload.get("privateIpGoogleAccess") is True
                and payload.get("stackType") == "IPV4_ONLY"
            )
        if resource_type == "router":
            network = payload.get("network")
            return (
                _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and isinstance(network, str)
                and network.endswith(network_suffix)
            )
        if resource_type == "service_account":
            expected_email = f"{resource_name}@{spec.project_id}.iam.gserviceaccount.com"
            return (
                payload.get("email") == expected_email
                and payload.get("displayName") == f"Secure Gateway Studio {resource_name}"
                and _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and isinstance(payload.get("uniqueId"), str)
                and bool(payload.get("uniqueId"))
            )
        if resource_type == "secret":
            if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED:
                return payload.get("name") == (
                    f"projects/{spec.project_id}/secrets/{resource_name}"
                )
            labels = payload.get("labels")
            replication = payload.get("replication")
            return (
                isinstance(labels, dict)
                and set(labels)
                == {
                    "managed-by",
                    "configuration-hash",
                    "certificate-spec-hash",
                    "sgs-owner-token",
                }
                and labels.get("managed-by") == "secure-gateway-studio"
                and labels.get("certificate-spec-hash") == certificate_configuration_hash(spec)[:32]
                and isinstance(labels.get("configuration-hash"), str)
                and re.fullmatch(r"[0-9a-f]{32}", str(labels["configuration-hash"])) is not None
                and isinstance(labels.get("sgs-owner-token"), str)
                and re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
                    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                    str(labels["sgs-owner-token"]),
                    re.IGNORECASE,
                )
                is not None
                and self._owns_managed_resource(key, payload)
                and isinstance(replication, dict)
                and replication == {"automatic": {}}
            )
        if resource_type == "internal_address":
            subnetwork = payload.get("subnetwork")
            compatible = (
                _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and payload.get("name") == resource_name
                and payload.get("addressType") == "INTERNAL"
                and isinstance(subnetwork, str)
                and subnetwork.endswith(subnet_suffix)
                and isinstance(payload.get("address"), str)
                and bool(payload.get("address"))
            )
            if compatible:
                self._discovered_addresses[key] = str(payload["address"])
            return compatible
        if resource_type == "instance":
            return (
                _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and self._private_managed_vm(
                payload, spec, resource_name, template=False
            )
            )
        if resource_type == "instance_group":
            named_ports = payload.get("namedPorts")
            network = payload.get("network")
            subnetwork = payload.get("subnetwork")
            shape_matches = (
                _owned_description(payload, "Managed by Secure Gateway Studio")
                and self._owns_managed_resource(key, payload)
                and isinstance(network, str)
                and network.endswith(f"/networks/{self._network_name(spec)}")
                and isinstance(subnetwork, str)
                and subnetwork.endswith(f"/subnetworks/{self._subnet_name(spec)}")
                and named_ports == [{"name": "http", "port": 80}]
            )
            return shape_matches and self._instance_group_members_exact(
                spec,
                resource_name,
            )
        if resource_type == "instance_template":
            properties = payload.get("properties")
            return (
                _owned_description(payload, "Managed by Secure Gateway Studio")
                and self._owns_managed_resource(key, payload)
                and isinstance(properties, dict)
                and self._private_managed_vm(properties, spec, resource_name, template=True)
            )
        if resource_type == "health_check":
            common = (
                _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and payload.get("name") == resource_name
                and payload.get("checkIntervalSec") == 10
                and payload.get("timeoutSec") == 5
                and payload.get("healthyThreshold") == 2
                and payload.get("unhealthyThreshold") == 3
            )
            if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
                http = payload.get("httpHealthCheck")
                return (
                    common
                    and payload.get("type") == "HTTP"
                    and _compatible_health_check_detail(http, protocol="HTTP")
                )
            ssl = payload.get("sslHealthCheck")
            return (
                common
                and payload.get("type") == "SSL"
                and _compatible_health_check_detail(ssl, protocol="SSL")
            )
        if resource_type == "instance_group_manager":
            policy = payload.get("distributionPolicy")
            zones = policy.get("zones", []) if isinstance(policy, dict) else []
            zone_names = [
                zone.get("zone", "").rsplit("/", maxsplit=1)[-1]
                for zone in zones
                if isinstance(zone, dict)
            ]
            versions = payload.get("versions")
            named_ports = payload.get("namedPorts")
            update = payload.get("updatePolicy")
            return (
                _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and payload.get("name") == resource_name
                and payload.get("baseInstanceName") == f"{spec.name}-offload"
                and payload.get("targetSize") == spec.offload_min_replicas
                and isinstance(policy, dict)
                and policy.get("targetShape") == "EVEN"
                and zone_names == [spec.zone, spec.secondary_zone]
                and isinstance(versions, list)
                and len(versions) == 1
                and isinstance(versions[0], dict)
                and versions[0].get("name") == "primary"
                and isinstance(versions[0].get("instanceTemplate"), str)
                and str(versions[0]["instanceTemplate"]).endswith(
                    f"/global/instanceTemplates/{spec.name}-offload-template"
                )
                and named_ports == [{"name": "https", "port": 443}]
                and _compatible_mig_update_policy(update)
            )
        if resource_type == "autoscaler":
            policy = payload.get("autoscalingPolicy")
            cpu = policy.get("cpuUtilization") if isinstance(policy, dict) else None
            return (
                _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and payload.get("name") == resource_name
                and isinstance(payload.get("target"), str)
                and str(payload["target"]).endswith(
                    f"/regions/{spec.region}/instanceGroupManagers/{spec.name}-offload-mig"
                )
                and isinstance(policy, dict)
                and policy.get("minNumReplicas") == spec.offload_min_replicas
                and policy.get("maxNumReplicas") == spec.offload_max_replicas
                and policy.get("coolDownPeriodSec") == 90
                and policy.get("mode") == "ON"
                and isinstance(cpu, dict)
                and cpu.get("utilizationTarget") == spec.offload_cpu_target
            )
        if resource_type == "backend_service":
            health_checks = payload.get("healthChecks")
            backends = payload.get("backends")
            common = (
                _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and payload.get("name") == resource_name
                and payload.get("timeoutSec") == 10
                and isinstance(health_checks, list)
                and len(health_checks) == 1
                and isinstance(health_checks[0], str)
                and isinstance(backends, list)
                and len(backends) == 1
                and isinstance(backends[0], dict)
            )
            if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
                return (
                    common
                    and payload.get("protocol") == "HTTP"
                    and payload.get("loadBalancingScheme") == "INTERNAL_MANAGED"
                    and payload.get("portName") == "http"
                    and str(health_checks[0]).endswith(
                        f"/regions/{spec.region}/healthChecks/{spec.name}-ilb-hc"
                    )
                    and isinstance(backends[0].get("group"), str)
                    and str(backends[0]["group"]).endswith(
                        f"/zones/{spec.zone}/instanceGroups/{spec.name}-backend-ig"
                    )
                    and backends[0].get("balancingMode") == "UTILIZATION"
                )
            return (
                common
                and payload.get("protocol") == "TCP"
                and payload.get("loadBalancingScheme") == "INTERNAL"
                and payload.get("portName") in {None, ""}
                and str(health_checks[0]).endswith(
                    f"/regions/{spec.region}/healthChecks/{spec.name}-offload-hc"
                )
                and isinstance(backends[0].get("group"), str)
                and str(backends[0]["group"]).endswith(
                    f"/regions/{spec.region}/instanceGroups/{spec.name}-offload-mig"
                )
            )
        if resource_type == "forwarding_rule":
            ports = payload.get("ports")
            expected_address = self._discovered_addresses.get(
                f"compute:internal_address:{spec.name}-offload-ip"
            )
            compatible = (
                _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and payload.get("name") == resource_name
                and payload.get("IPProtocol") == "TCP"
                and payload.get("loadBalancingScheme")
                == (
                    "INTERNAL_MANAGED"
                    if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB
                    else "INTERNAL"
                )
                and ports == ["443"]
                and payload.get("allowGlobalAccess") is True
                and isinstance(expected_address, str)
                and payload.get("IPAddress") == expected_address
                and isinstance(payload.get("network"), str)
                and str(payload["network"]).endswith(network_suffix)
                and isinstance(payload.get("subnetwork"), str)
                and str(payload["subnetwork"]).endswith(subnet_suffix)
            )
            if spec.backend_kind is not BackendKind.INTERNAL_HTTPS_LB:
                backend = payload.get("backendService")
                return (
                    compatible
                    and isinstance(backend, str)
                    and backend.endswith(
                        f"/regions/{spec.region}/backendServices/{spec.name}-offload-bs"
                    )
                )
            target = payload.get("target")
            return (
                compatible
                and payload.get("networkTier") == "PREMIUM"
                and isinstance(target, str)
                and target.endswith(
                    f"/regions/{spec.region}/targetHttpsProxies/{spec.name}-ilb-proxy"
                )
            )
        if resource_type == "ssl_certificate":
            return (
                _owned_description(
                    payload,
                    "Managed by Secure Gateway Studio; certificate configuration "
                    f"{certificate_configuration_hash(spec)}",
                )
                and self._owns_managed_resource(key, payload)
                and self._compatible_ssl_certificate(payload, spec, resource_name)
            )
        if resource_type == "url_map":
            default_service = payload.get("defaultService")
            return (
                _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and payload.get("name") == resource_name
                and isinstance(default_service, str)
                and default_service.endswith(
                    f"/regions/{spec.region}/backendServices/{spec.name}-ilb-bs"
                )
            )
        if resource_type == "target_https_proxy":
            url_map = payload.get("urlMap")
            certificates = payload.get("sslCertificates")
            return (
                _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and payload.get("name") == resource_name
                and isinstance(url_map, str)
                and url_map.endswith(f"/regions/{spec.region}/urlMaps/{spec.name}-ilb-map")
                and isinstance(certificates, list)
                and len(certificates) == 1
                and isinstance(certificates[0], str)
                and certificates[0].endswith(
                    f"/regions/{spec.region}/sslCertificates/{spec.name}-ilb-cert"
                )
            )
        if resource_type == "firewall_rule":
            return (
                _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and self._compatible_firewall(resource_name, payload, spec)
            )
        if resource_type == "private_zone":
            visibility = payload.get("privateVisibilityConfig")
            networks = visibility.get("networks") if isinstance(visibility, dict) else None
            expected_network = (
                f"https://www.googleapis.com/compute/v1/projects/{spec.project_id}/"
                f"global/networks/{self._network_name(spec)}"
            )
            return (
                payload.get("name") == resource_name
                and _owned_description(payload)
                and self._owns_managed_resource(key, payload)
                and payload.get("visibility") == "private"
                and payload.get("dnsName") == f"{spec.private_hostname}."
                and isinstance(networks, list)
                and len(networks) == 1
                and isinstance(networks[0], dict)
                and networks[0].get("networkUrl") == expected_network
            )
        if resource_type == "security_gateway":
            expected_name = (
                f"projects/{spec.project_id}/locations/global/securityGateways/"
                f"{resource_name}"
            )
            allowed_fields = {
                "name",
                "displayName",
                "serviceDiscovery",
                "service_discovery",
                "logging",
                "state",
                "delegatingServiceAccount",
                "externalIps",
                "createTime",
                "updateTime",
            }
            has_camel = "serviceDiscovery" in payload
            has_snake = "service_discovery" in payload
            service_discovery = (
                payload.get("serviceDiscovery")
                if has_camel
                else payload.get("service_discovery")
            )
            return (
                self._owns_managed_resource(key, payload)
                and set(payload) <= allowed_fields
                and payload.get("name") == expected_name
                and payload.get("displayName") == resource_name
                and payload.get("state") == "RUNNING"
                and has_camel != has_snake
                and service_discovery == {}
                and payload.get("logging") == {}
                and isinstance(payload.get("delegatingServiceAccount"), str)
                and bool(str(payload["delegatingServiceAccount"]).strip())
                and (
                    "externalIps" not in payload
                    or _valid_external_ip_list(payload["externalIps"])
                )
            )
        if resource_type == "application":
            expected_name = (
                f"projects/{spec.project_id}/locations/global/securityGateways/"
                f"{spec.gateway_id}/applications/{resource_name}"
            )
            allowed_fields = {
                "name",
                "displayName",
                "endpointMatchers",
                "endpoint_matchers",
                "upstreams",
                "schema",
                "createTime",
                "updateTime",
            }
            has_camel_matchers = "endpointMatchers" in payload
            has_snake_matchers = "endpoint_matchers" in payload
            if (
                not set(payload) <= allowed_fields
                or payload.get("name") != expected_name
                or payload.get("displayName") != resource_name
                or has_camel_matchers == has_snake_matchers
                or (
                    "schema" in payload
                    and payload.get("schema") != "SCHEMA_UNSPECIFIED"
                )
            ):
                return False
            matchers = (
                payload.get("endpointMatchers")
                if has_camel_matchers
                else payload.get("endpoint_matchers")
            )
            matcher_ok = (
                isinstance(matchers, list)
                and len(matchers) == 1
                and isinstance(matchers[0], dict)
                and set(matchers[0]) == {"hostname", "ports"}
                and matchers[0].get("hostname") == spec.application_hostname
                and matchers[0].get("ports") == [spec.application_port]
            )
            upstreams = payload.get("upstreams")
            expected_network = (
                f"projects/{spec.upstream_project_id}/global/networks/{self._network_name(spec)}"
            )
            upstream_ok = False
            if isinstance(upstreams, list) and len(upstreams) == 1:
                for upstream in upstreams:
                    if not isinstance(upstream, dict):
                        continue
                    has_camel_policy = "egressPolicy" in upstream
                    has_snake_policy = "egress_policy" in upstream
                    allowed_upstream_fields = {"network"}
                    if has_camel_policy:
                        allowed_upstream_fields.add("egressPolicy")
                    if has_snake_policy:
                        allowed_upstream_fields.add("egress_policy")
                    if (
                        set(upstream) != allowed_upstream_fields
                        or (has_camel_policy and has_snake_policy)
                    ):
                        continue
                    network = upstream.get("network")
                    if (
                        not isinstance(network, dict)
                        or set(network) != {"name"}
                        or network.get("name") != expected_network
                    ):
                        continue
                    policy = (
                        upstream.get("egressPolicy")
                        if has_camel_policy
                        else upstream.get("egress_policy")
                    )
                    if (
                        not spec.application_egress_region
                        and not has_camel_policy
                        and not has_snake_policy
                    ):
                        upstream_ok = True
                        break
                    if (
                        spec.application_egress_region
                        and isinstance(policy, dict)
                        and set(policy) == {"regions"}
                        and policy.get("regions") == [spec.application_egress_region]
                    ):
                        upstream_ok = True
                        break
            return self._owns_managed_resource(key, payload) and matcher_ok and upstream_ok
        if resource_type == "access_level":
            if (
                not set(payload) <= {"name", "title", "description", "custom"}
                or payload.get("name") != resource_name
                or "custom" not in payload
                or any(
                    field in payload and not isinstance(payload[field], str)
                    for field in ("title", "description")
                )
            ):
                return False
            custom = payload.get("custom")
            if not isinstance(custom, dict) or set(custom) != {"expr"}:
                return False
            expr = custom.get("expr")
            return (
                isinstance(expr, dict)
                and "expression" in expr
                and set(expr) <= {"expression", "title", "description", "location"}
                and isinstance(expr.get("expression"), str)
                and all(
                    field not in expr or isinstance(expr[field], str)
                    for field in ("title", "description", "location")
                )
                and expr["expression"] in MANAGED_CHROME_ACCESS_LEVEL_EXPRESSIONS
            )
        return True

    def _instance_group_members_exact(
        self,
        spec: DeploymentSpec,
        group_name: str,
    ) -> bool:
        group_url = (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"zones/{spec.zone}/instanceGroups/{group_name}"
        )
        expected_instance = (
            f"/projects/{spec.project_id}/zones/{spec.zone}/instances/{spec.name}-backend"
        )
        members: list[str] = []
        page_token: str | None = None
        seen_tokens: set[str] = set()
        for _ in range(100):
            params: dict[str, str | int] = {"maxResults": 500}
            if page_token is not None:
                params["pageToken"] = page_token
            _, payload = self._transport.request_json(
                "POST",
                f"{group_url}/listInstances",
                params=params,
                json_body={"instanceState": "ALL"},
            )
            items = payload.get("items", [])
            if not isinstance(items, list):
                raise ValueError("Instance-group membership response is malformed")
            for item in items:
                instance = item.get("instance") if isinstance(item, dict) else None
                if not isinstance(instance, str):
                    raise ValueError("Instance-group membership response is malformed")
                members.append(instance)
                if len(members) > 1:
                    return False
            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                return len(members) == 1 and _compute_reference(
                    members[0],
                    expected_instance,
                )
            next_token = payload["nextPageToken"]
            if not isinstance(next_token, str) or next_token in seen_tokens:
                raise ValueError("Instance-group membership pagination is invalid")
            seen_tokens.add(next_token)
            page_token = next_token
        raise ValueError("Instance-group membership pagination exceeded its safety limit")

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

    def _private_managed_vm(
        self,
        payload: dict[str, object],
        spec: DeploymentSpec,
        resource_name: str,
        *,
        template: bool,
    ) -> bool:
        role = "backend" if resource_name.endswith("-backend") else "offload"
        labels = payload.get("labels")
        interfaces = payload.get("networkInterfaces")
        accounts = payload.get("serviceAccounts")
        machine_type = payload.get("machineType")
        if not isinstance(machine_type, str) or machine_type.rsplit("/", 1)[-1] != "e2-small":
            return False
        if labels != {"managed-by": "secure-gateway-studio", "role": role}:
            return False
        tags = payload.get("tags")
        if not isinstance(tags, dict) or tags.get("items") != [f"{spec.name}-{role}"]:
            return False
        if not isinstance(interfaces, list) or len(interfaces) != 1:
            return False
        interface = interfaces[0]
        if not isinstance(interface, dict) or interface.get("accessConfigs"):
            return False
        if not (
            isinstance(interface.get("network"), str)
            and interface["network"].endswith(
                f"/global/networks/{GoogleDiscoveryProvider._network_name(spec)}"
            )
            and isinstance(interface.get("subnetwork"), str)
            and interface["subnetwork"].endswith(
                f"/regions/{spec.region}/subnetworks/{GoogleDiscoveryProvider._subnet_name(spec)}"
            )
            and interface.get("stackType") == "IPV4_ONLY"
        ):
            return False
        if template:
            if "networkIP" in interface:
                return False
        else:
            network_ip = interface.get("networkIP")
            try:
                if not isinstance(network_ip, str) or not ip_address(network_ip).is_private:
                    return False
            except ValueError:
                return False
        expected_account = service_account_email(spec.name, spec.project_id, role)
        if not (
            isinstance(accounts, list)
            and len(accounts) == 1
            and isinstance(accounts[0], dict)
            and accounts[0].get("email") == expected_account
            and accounts[0].get("scopes") == ["https://www.googleapis.com/auth/cloud-platform"]
        ):
            return False
        disks = payload.get("disks")
        if not isinstance(disks, list) or len(disks) != 1 or not isinstance(disks[0], dict):
            return False
        disk = disks[0]
        if (
            spec.source_image is None
            or self._source_image_binding is None
            or self._source_image_binding.name != spec.source_image
            or disk.get("boot") is not True
            or disk.get("autoDelete") is not True
        ):
            return False
        if template:
            initialize = disk.get("initializeParams")
            if not (
                isinstance(initialize, dict)
                and initialize.get("sourceImage") == spec.source_image
                and str(initialize.get("diskSizeGb")) == "20"
                and isinstance(initialize.get("diskType"), str)
                and str(initialize["diskType"]).rsplit("/", 1)[-1] == "pd-balanced"
            ):
                return False
        else:
            disk_source = disk.get("source")
            expected_disk_path = (
                f"/projects/{spec.project_id}/zones/{spec.zone}/disks/{resource_name}"
            )
            if (
                disk.get("type") not in {None, "PERSISTENT"}
                or disk.get("mode") not in {None, "READ_WRITE"}
                or not _compute_reference(disk_source, expected_disk_path)
            ):
                return False
            disk_url = (
                f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
                f"zones/{spec.zone}/disks/{resource_name}"
            )
            _, disk_payload = self._transport.request_json("GET", disk_url)
            if not (
                disk_payload.get("name") == resource_name
                and _compute_reference(disk_payload.get("selfLink"), expected_disk_path)
                and _compute_reference(
                    disk_payload.get("zone"),
                    f"/projects/{spec.project_id}/zones/{spec.zone}",
                )
                and disk_payload.get("status") == "READY"
                and str(disk_payload.get("sizeGb")) == "20"
                and _compute_reference(
                    disk_payload.get("type"),
                    f"/projects/{spec.project_id}/zones/{spec.zone}/diskTypes/pd-balanced",
                )
                and _compute_reference(
                    disk_payload.get("sourceImage"),
                    f"/{spec.source_image}",
                )
                and str(disk_payload.get("sourceImageId"))
                == self._source_image_binding.id
            ):
                return False
        metadata = payload.get("metadata")
        items = metadata.get("items") if isinstance(metadata, dict) else None
        if not isinstance(items, list) or len(items) != 2:
            return False
        values: dict[str, object] = {}
        for item in items:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("key"), str)
                or item["key"] in values
            ):
                return False
            values[str(item["key"])] = item.get("value")
        startup = values.get("startup-script")
        if values.get("enable-guest-attributes") != "TRUE" or not isinstance(startup, str):
            return False
        # The startup script executes with cloud-platform scope. A retained
        # configuration hash is not sufficient evidence: an administrator
        # could append arbitrary commands while preserving that substring.
        # Re-render the exact canonical script (including the approved numeric
        # public SecretVersion) and compare every byte.
        from sgstudio.providers.google_executor import render_startup_script_for_discovery

        expected_startup = render_startup_script_for_discovery(
            self._transport,
            spec,
            role=role,
            public_certificate_binding=self._public_certificate_binding,
        )
        if startup != expected_startup:
            return False
        if payload.get("shieldedInstanceConfig") != {
            "enableSecureBoot": True,
            "enableVtpm": True,
            "enableIntegrityMonitoring": True,
        }:
            return False
        return template or payload.get("deletionProtection") is False

    @staticmethod
    def _compatible_firewall(
        resource_name: str,
        payload: dict[str, object],
        spec: DeploymentSpec,
    ) -> bool:
        network = payload.get("network")
        if not (
            payload.get("name") == resource_name
            and isinstance(network, str)
            and network.endswith(
                f"/projects/{spec.project_id}/global/networks/"
                f"{GoogleDiscoveryProvider._network_name(spec)}"
            )
            and payload.get("direction") == "INGRESS"
            and payload.get("priority") == 1000
            and payload.get("disabled") in {None, False}
            and payload.get("logConfig") == {"enable": True, "metadata": "INCLUDE_ALL_METADATA"}
            and payload.get("denied") in {None, ()}
        ):
            return False
        expected_port = "443"
        target_role = "offload"
        source_ranges: list[str] | None = None
        source_accounts: list[str] | None = None
        if resource_name.endswith("gateway-ingress"):
            source_ranges = [SECURE_GATEWAY_SOURCE_CIDR]
        elif resource_name.endswith("health-check-ingress"):
            source_ranges = [
                "35.191.0.0/16",
                "130.211.0.0/22",
            ]
        elif resource_name.endswith("ilb-proxy-ingress"):
            expected_port = "80"
            target_role = "backend"
            source_ranges = [str(spec.proxy_subnet_cidr)]
        elif resource_name.endswith("ilb-health-ingress"):
            expected_port = "80"
            target_role = "backend"
            source_ranges = [
                "35.191.0.0/16",
                "130.211.0.0/22",
            ]
        elif resource_name.endswith("backend-ingress"):
            expected_port = "80"
            target_role = "backend"
            source_accounts = [service_account_email(spec.name, spec.project_id, "offload")]
        else:
            return False
        expected_target = [service_account_email(spec.name, spec.project_id, target_role)]
        return (
            payload.get("allowed") == [{"IPProtocol": "tcp", "ports": [expected_port]}]
            and payload.get("targetServiceAccounts") == expected_target
            and (
                payload.get("sourceRanges") == source_ranges
                if source_ranges is not None
                else payload.get("sourceRanges") in {None, ()}
            )
            and (
                payload.get("sourceServiceAccounts") == source_accounts
                if source_accounts is not None
                else payload.get("sourceServiceAccounts") in {None, ()}
            )
        )

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


def create_google_discovery_provider(
    *, require_impersonation: bool = False
) -> GoogleDiscoveryProvider:
    try:
        transport = GoogleAuthorizedTransport.from_adc(require_impersonation=require_impersonation)
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
