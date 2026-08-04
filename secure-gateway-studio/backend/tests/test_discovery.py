import base64
from typing import Any

import pytest
from fastapi.testclient import TestClient
from google.auth.credentials import AnonymousCredentials

from sgstudio.api.main import (
    SESSION_NONCE,
    app,
    connection_validator,
    discovery_provider,
)
from sgstudio.domain.models import (
    AccessPrincipal,
    CertificateStrategy,
    ConnectionValidation,
    DeploymentMode,
    DeploymentSpec,
    DiscoverySnapshot,
    PreflightResult,
    PrincipalType,
)
from sgstudio.domain.planner import (
    REQUIRED_APIS,
    canonical_configuration_hash,
    certificate_configuration_hash,
)
from sgstudio.providers.certificates import CertificateIssuer
from sgstudio.providers.discovery import GoogleDiscoveryProvider
from sgstudio.providers.google_rest import GoogleApiError, GoogleAuthorizedTransport
from sgstudio.providers.local_artifacts import CertificateArtifactStore


def deployment_spec() -> DeploymentSpec:
    return DeploymentSpec(
        project_id="enterprise-secgw-01",
        ca_pool="projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise",
        ca_name=(
            "projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise/"
            "certificateAuthorities/issuing"
        ),
        target_ou_id="03-test-ou",
        managed_chrome_access_level="accessPolicies/123456789/accessLevels/managed_chrome",
        source_image="projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
        chrome_enterprise_premium_license_confirmed=True,
        workspace_services_confirmed=True,
        endpoint_verification_confirmed=True,
        test_ou_confirmed=True,
        principals=[AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")],
    )


class FakeTransport:
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        del method, json_body, accepted_statuses
        if "serviceusage.googleapis.com" in url:
            assert params == {"filter": "state:ENABLED", "pageSize": 200}
            return 200, {
                "services": [
                    {"config": {"name": "compute.googleapis.com"}},
                    {"config": {"name": "beyondcorp.googleapis.com"}},
                ]
            }
        if "cloudbilling.googleapis.com" in url:
            return 200, {"billingEnabled": True}
        if "licensing.googleapis.com" in url:
            assert params == {
                "customerId": "my_customer",
                "maxResults": 1000,
            }
            return 200, {
                "items": [
                    {
                        "productId": "101040",
                        "skuId": "1010400001",
                        "userId": "operator@example.com",
                    }
                ]
            }
        if "accesscontextmanager.googleapis.com" in url:
            return 200, {
                "custom": {
                    "conditions": [
                        {
                            "expr": {
                                "expression": (
                                    "device.chrome.management_state in ["
                                    "ChromeManagementState."
                                    "CHROME_MANAGEMENT_STATE_BROWSER_MANAGED,"
                                    "ChromeManagementState."
                                    "CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]"
                                )
                            }
                        }
                    ]
                }
            }
        if url.endswith("/global/images/sgs-nginx-20260730"):
            return 200, {"name": "sgs-nginx-20260730"}
        if url.endswith("/global/networks/secure-gateway-http-offload-vpc"):
            return 200, {
                "name": "secure-gateway-http-offload-vpc",
                "autoCreateSubnetworks": False,
                "description": "Managed by Secure Gateway Studio",
            }
        if url.endswith("/routers/secure-gateway-http-offload-router"):
            return 200, {"nats": [{"name": "secure-gateway-http-offload-nat"}]}
        return 404, {}


def test_read_only_discovery_builds_snapshot_without_workspace_claim() -> None:
    provider = GoogleDiscoveryProvider(
        FakeTransport(),
        cloud_identity="operator@example.com",
        credential_kind="AuthorizedUserCredentials",
        quota_project_id="quota-project",
    )

    result = provider.preflight(deployment_spec())

    assert result.read_only is True
    assert result.snapshot.cloud_identity == "operator@example.com"
    assert result.snapshot.workspace_identity is None
    assert result.snapshot.billing_enabled is True
    assert result.snapshot.enabled_apis == {
        "compute.googleapis.com",
        "beyondcorp.googleapis.com",
    }
    assert "compute:network:secure-gateway-http-offload-vpc" in (
        result.snapshot.existing_resource_keys
    )
    assert "compute:cloud_nat:secure-gateway-http-offload-nat" in (
        result.snapshot.existing_resource_keys
    )
    assert result.diagnostics[0].code == "workspace-oauth-required"


class ReportingProfileTransport(FakeTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if "chromemanagement.googleapis.com" in url:
            assert params == {
                "pageSize": 200,
                "filter": "ouId = 03-test-ou",
                "orderBy": "lastPolicySyncTime desc",
            }
            return 200, {
                "chromeBrowserProfiles": [
                    {
                        "userEmail": "operator@example.com",
                        "affiliationState": "PROFILE_ONLY",
                        "lastPolicySyncTime": "2026-08-03T07:15:16Z",
                        "reportingData": {
                            "extensionData": [
                                {
                                    "extensionId": "callobklhcbilhphinckomhgkigmfocg",
                                    "version": "1.140.0",
                                    "installationType": "ADMIN",
                                    "isDisabled": False,
                                },
                                {
                                    "extensionId": "ekajlcmdfcigmdbphhifahdfjbkciflj",
                                    "version": "1.26.129",
                                    "installationType": "ADMIN",
                                    "isDisabled": False,
                                },
                            ]
                        },
                    }
                ]
            }
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_profile_readiness_detects_profile_only_byod_and_required_extensions() -> None:
    provider = GoogleDiscoveryProvider(
        ReportingProfileTransport(),
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(deployment_spec())

    assert result.snapshot.managed_chrome_profile_count == 1
    assert result.snapshot.profile_only_count == 1
    assert result.snapshot.latest_chrome_policy_sync == "2026-08-03T07:15:16Z"
    assert result.snapshot.endpoint_verification_installed is True
    assert result.snapshot.endpoint_verification_version == "1.140.0"
    assert result.snapshot.secure_enterprise_browser_installed is True
    assert result.snapshot.secure_enterprise_browser_version == "1.26.129"


class EnterpriseReadinessTransport(ReportingProfileTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if url.endswith("/policies:resolve") and (
            (json_body or {}).get("policySchemaFilter")
            == "chrome.users.ChromeRootStoreEnabled"
        ):
            return 200, {
                "resolvedPolicies": [
                    {
                        "sourceKey": {"targetResource": "orgunits/03-test-ou"},
                        "value": {
                            "value": {"chromeRootStoreEnabled": "TRUE"},
                        },
                    }
                ]
            }
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_enterprise_readiness_detects_license_and_root_store_policy_only() -> None:
    provider = GoogleDiscoveryProvider(
        EnterpriseReadinessTransport(),
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(deployment_spec())

    assert result.snapshot.chrome_enterprise_premium_license_count == 1
    assert result.snapshot.chrome_root_store_config_count is None
    assert result.snapshot.chrome_root_store_config_names == []
    assert result.snapshot.chrome_root_store_enabled is True
    assert not any(
        diagnostic.code == "chrome-root-store-configuration-required"
        for diagnostic in result.diagnostics
    )


class LicenseApiUnavailableTransport(ReportingProfileTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if "licensing.googleapis.com" in url:
            raise GoogleApiError(
                status_code=403,
                method="GET",
                host="licensing.googleapis.com",
                detail="Forbidden",
            )
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_license_api_unavailability_routes_to_manual_confirmation() -> None:
    provider = GoogleDiscoveryProvider(
        LicenseApiUnavailableTransport(),
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(deployment_spec())

    assert result.snapshot.chrome_enterprise_premium_license_count is None
    diagnostic = next(
        item
        for item in result.diagnostics
        if item.code == "chrome-enterprise-premium-manual-confirmation"
    )
    assert diagnostic.severity == "info"
    assert "Admin console" in (diagnostic.remediation or "")


class GroupPolicyConflictTransport(ReportingProfileTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if url == "https://admin.googleapis.com/admin/directory/v1/groups":
            return 200, {
                "groups": [
                    {
                        "id": "group-123",
                        "email": "secure-access@example.com",
                    }
                ]
            }
        if "chromepolicy.googleapis.com" in url and json_body:
            target = json_body.get("policyTargetKey", {}).get("targetResource")
            if target == "groups/group-123":
                return 200, {
                    "resolvedPolicies": [
                        {
                            "value": {
                                "value": {"managedConfiguration": "{}"},
                            },
                            "sourceKey": {"targetResource": target},
                        }
                    ]
                }
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_preflight_blocks_incompatible_group_extension_policy() -> None:
    provider = GoogleDiscoveryProvider(
        GroupPolicyConflictTransport(),
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(deployment_spec())

    assert result.snapshot.chrome_extension_group_conflicts == [
        "secure-access@example.com"
    ]
    assert (
        "chromepolicy:group_extension_configuration:secure-access@example.com"
        in result.snapshot.conflicting_resource_keys
    )
    assert any(
        diagnostic.code == "chrome-extension-group-policy-conflict"
        for diagnostic in result.diagnostics
    )


def test_access_level_direct_custom_expression_is_compatible() -> None:
    provider = GoogleDiscoveryProvider(FakeTransport(), cloud_identity=None)
    payload = {
        "custom": {
            "expr": {
                "expression": (
                    "device.chrome.management_state in ["
                    "ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED,"
                    "ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]"
                )
            }
        }
    }

    assert provider._compatible(
        "accesscontextmanager:access_level:managed_chrome",
        payload,
        deployment_spec(),
    )


def test_profile_managed_only_access_level_is_compatible() -> None:
    provider = GoogleDiscoveryProvider(FakeTransport(), cloud_identity=None)
    payload = {
        "custom": {
            "expr": {
                "expression": (
                    "device.chrome.management_state == "
                    "ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED"
                )
            }
        }
    }

    assert provider._compatible(
        "accesscontextmanager:access_level:profile_managed",
        payload,
        deployment_spec(),
    )


class InheritedPacDiscoveryTransport(FakeTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if url.endswith("/policies:resolve"):
            schema = (json_body or {}).get("policySchemaFilter")
            if schema == "chrome.users.SimpleProxySettings":
                return 200, {
                    "resolvedPolicies": [
                        {
                            "sourceKey": {"targetResource": "orgunits/parent-ou"},
                            "value": {
                                "policySchema": schema,
                                "value": {
                                    "simpleProxyMode": "PROXY_MODE_ENUM_PAC_SCRIPT",
                                    "simpleProxyPacUrl": "https://example.test/legacy.pac",
                                },
                            },
                        }
                    ]
                }
            return 200, {"resolvedPolicies": []}
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_discovery_flags_inherited_legacy_pac_for_service_discovery_override() -> None:
    provider = GoogleDiscoveryProvider(
        InheritedPacDiscoveryTransport(),
        cloud_identity=None,
    )
    existing_keys: set[str] = set()
    diagnostics = []

    provider._discover_chrome_policies(
        deployment_spec(),
        existing_keys,
        diagnostics,
    )

    proxy_key = "chromepolicy:service_discovery_proxy:03-test-ou"
    assert proxy_key not in existing_keys
    diagnostic = next(item for item in diagnostics if item.code == "legacy-pac-policy-detected")
    assert "parent-ou" in diagnostic.message
    assert "legacy.pac" in diagnostic.message


class ExistingManagedCertificateTransport(FakeTransport):
    def __init__(self, *, lifetime_days: int = 90) -> None:
        self.payload = (
            CertificateIssuer()
            .issue_local_poc(
                hostname="demo-server-http.internal",
                lifetime_days=lifetime_days,
            )
            .secret_payload()
        )

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if url.endswith("/secrets/secure-gateway-http-offload-tls"):
            return 200, {
                "name": ("projects/enterprise-secgw-01/secrets/secure-gateway-http-offload-tls"),
                "labels": {"managed-by": "secure-gateway-studio"},
                "versionAliases": {"active": "1"},
            }
        if "/secrets/secure-gateway-http-offload-tls/versions/" in url and (
            url.endswith(":access")
        ):
            return 200, {"payload": {"data": base64.b64encode(self.payload).decode("ascii")}}
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_existing_valid_managed_certificate_version_is_reused() -> None:
    provider = GoogleDiscoveryProvider(
        ExistingManagedCertificateTransport(),
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(deployment_spec())

    assert (
        "secretmanager:secret_version:secure-gateway-http-offload-tls"
        in result.snapshot.existing_resource_keys
    )


def test_expiring_managed_certificate_plans_rotation_instead_of_conflict() -> None:
    provider = GoogleDiscoveryProvider(
        ExistingManagedCertificateTransport(lifetime_days=1),
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(deployment_spec())

    version_key = "secretmanager:secret_version:secure-gateway-http-offload-tls"
    assert version_key not in result.snapshot.existing_resource_keys
    assert version_key not in result.snapshot.conflicting_resource_keys
    assert any(
        diagnostic.code == "managed-certificate-rotation-required"
        for diagnostic in result.diagnostics
    )


class MissingActiveAliasTransport(ExistingManagedCertificateTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        status_code, payload = super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )
        if url.endswith("/secrets/secure-gateway-http-offload-tls"):
            payload.pop("versionAliases", None)
        return status_code, payload


def test_existing_managed_secret_without_active_alias_plans_safe_migration() -> None:
    provider = GoogleDiscoveryProvider(
        MissingActiveAliasTransport(),
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(deployment_spec())

    version_key = "secretmanager:secret_version:secure-gateway-http-offload-tls"
    assert version_key not in result.snapshot.existing_resource_keys
    assert any(
        diagnostic.code == "managed-certificate-alias-migration-required"
        for diagnostic in result.diagnostics
    )


class ConvergedPocTransport(FakeTransport):
    def __init__(self, poc_spec: DeploymentSpec) -> None:
        self.spec = poc_spec

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if "serviceusage.googleapis.com" in url:
            return 200, {
                "services": [{"config": {"name": name}} for name in sorted(REQUIRED_APIS)]
            }
        if url.endswith("/secrets/secure-gateway-http-offload-tls"):
            return 200, {
                "name": (
                    "projects/enterprise-secgw-01/secrets/"
                    "secure-gateway-http-offload-tls"
                ),
                "labels": {
                    "managed-by": "secure-gateway-studio",
                    "configuration-hash": canonical_configuration_hash(self.spec)[:32],
                    "certificate-spec-hash": certificate_configuration_hash(self.spec)[:32],
                },
                "versionAliases": {"active": "1"},
            }
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_converged_local_poc_reuses_apis_certificate_and_root_artifact(tmp_path) -> None:
    poc_spec = deployment_spec().model_copy(
        update={
            "mode": DeploymentMode.POC,
            "certificate_strategy": CertificateStrategy.LOCAL_POC,
        }
    )
    artifact_store = CertificateArtifactStore(tmp_path)
    bundle = CertificateIssuer().issue_local_poc(
        hostname=poc_spec.private_hostname,
        lifetime_days=30,
    )
    artifact_store.write_root_certificate(poc_spec.name, bundle.certificate_chain_pem[0])
    provider = GoogleDiscoveryProvider(
        ConvergedPocTransport(poc_spec),
        cloud_identity="operator@example.com",
        artifact_store=artifact_store,
    )

    result = provider.preflight(poc_spec)

    assert "serviceusage:project_services:required-apis" in (
        result.snapshot.existing_resource_keys
    )
    assert "secretmanager:secret_version:secure-gateway-http-offload-tls" in (
        result.snapshot.existing_resource_keys
    )
    assert "local:root_certificate_artifact:secure-gateway-http-offload-poc-root" in (
        result.snapshot.existing_resource_keys
    )


def test_local_poc_certificate_is_reused_after_unrelated_access_changes(tmp_path) -> None:
    original_spec = deployment_spec().model_copy(
        update={
            "mode": DeploymentMode.POC,
            "certificate_strategy": CertificateStrategy.LOCAL_POC,
        }
    )
    changed_access_spec = original_spec.model_copy(
        update={
            "managed_chrome_access_level": "accessPolicies/123/accessLevels/new-level",
            "principals": [
                AccessPrincipal(type=PrincipalType.USER, value="operator@example.com")
            ],
        }
    )
    artifact_store = CertificateArtifactStore(tmp_path)
    transport = ConvergedPocTransport(original_spec)
    bundle = CertificateIssuer().issue_local_poc(
        hostname=original_spec.private_hostname,
        lifetime_days=30,
    )
    artifact_store.write_root_certificate(
        original_spec.name,
        bundle.certificate_chain_pem[0],
    )
    provider = GoogleDiscoveryProvider(
        transport,
        cloud_identity="operator@example.com",
        artifact_store=artifact_store,
    )

    result = provider.preflight(changed_access_spec)

    assert "secretmanager:secret_version:secure-gateway-http-offload-tls" in (
        result.snapshot.existing_resource_keys
    )
    assert "local:root_certificate_artifact:secure-gateway-http-offload-poc-root" in (
        result.snapshot.existing_resource_keys
    )


def test_local_poc_certificate_rotates_when_hostname_changes(tmp_path) -> None:
    original_spec = deployment_spec().model_copy(
        update={
            "mode": DeploymentMode.POC,
            "certificate_strategy": CertificateStrategy.LOCAL_POC,
        }
    )
    changed_hostname_spec = original_spec.model_copy(
        update={"private_hostname": "new-demo.internal"}
    )
    artifact_store = CertificateArtifactStore(tmp_path)
    bundle = CertificateIssuer().issue_local_poc(
        hostname=original_spec.private_hostname,
        lifetime_days=30,
    )
    artifact_store.write_root_certificate(
        original_spec.name,
        bundle.certificate_chain_pem[0],
    )
    provider = GoogleDiscoveryProvider(
        ConvergedPocTransport(original_spec),
        cloud_identity="operator@example.com",
        artifact_store=artifact_store,
    )

    result = provider.preflight(changed_hostname_spec)

    assert "secretmanager:secret_version:secure-gateway-http-offload-tls" not in (
        result.snapshot.existing_resource_keys
    )


def test_policy_binding_match_requires_members_and_exact_condition() -> None:
    condition = {
        "title": "Managed Chrome required",
        "description": "Allow only profiles or browsers managed by this enterprise",
        "expression": "'level' in request.auth.access_levels",
    }
    policy = {
        "bindings": [
            {
                "role": "roles/beyondcorp.sgApplicationUser",
                "members": ["group:secure-access@example.com"],
                "condition": condition,
            }
        ]
    }

    assert GoogleDiscoveryProvider._policy_has_binding(
        policy,
        role="roles/beyondcorp.sgApplicationUser",
        members={"group:secure-access@example.com"},
        condition=condition,
    )
    assert not GoogleDiscoveryProvider._policy_has_binding(
        policy,
        role="roles/beyondcorp.sgApplicationUser",
        members={"user:missing@example.com"},
        condition=condition,
    )


def test_google_transport_rejects_non_google_hosts_before_network() -> None:
    transport = GoogleAuthorizedTransport(AnonymousCredentials())

    with pytest.raises(ValueError, match="non-allowlisted"):
        transport.request_json("GET", "https://evil.example/resource")


class ExternalIpCollisionTransport(FakeTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if url.endswith("/instances/secure-gateway-http-offload-offload"):
            return 200, {
                "labels": {
                    "managed-by": "secure-gateway-studio",
                    "role": "offload",
                },
                "networkInterfaces": [{"accessConfigs": [{"natIP": "203.0.113.10"}]}],
                "serviceAccounts": [
                    {
                        "email": (
                            "secure-gateway-http-offload-offload@"
                            "enterprise-secgw-01.iam.gserviceaccount.com"
                        )
                    }
                ],
            }
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_discovery_marks_external_ip_name_collision_as_blocking_conflict() -> None:
    provider = GoogleDiscoveryProvider(
        ExternalIpCollisionTransport(),
        cloud_identity="operator@example.com",
    )
    poc_spec = deployment_spec().model_copy(
        update={
            "mode": DeploymentMode.POC,
            "certificate_strategy": CertificateStrategy.LOCAL_POC,
        }
    )

    result = provider.preflight(poc_spec)

    assert (
        "compute:instance:secure-gateway-http-offload-offload"
        in result.snapshot.conflicting_resource_keys
    )


class FakeDiscoveryProvider:
    def preflight(self, spec: DeploymentSpec) -> PreflightResult:
        return PreflightResult(
            snapshot=DiscoverySnapshot(
                enabled_apis={"compute.googleapis.com"},
                cloud_identity=f"adc:{spec.project_id}",
            )
        )


class FakeConnectionValidator:
    def validate_cloud(self, project_id: str) -> ConnectionValidation:
        return ConnectionValidation(
            provider="google_cloud",
            status="connected",
            principal_hint=f"adc:{project_id}",
            resource_id=project_id,
            credential_kind="test",
        )

    def validate_workspace(
        self,
        customer_id: str,
        target_ou_id: str | None = None,
    ) -> ConnectionValidation:
        assert target_ou_id == "03-test-ou"
        return ConnectionValidation(
            provider="workspace",
            status="connected",
            principal_hint="admin@example.com",
            resource_id=customer_id,
            credential_kind="test",
        )


def test_preflight_endpoint_supports_provider_injection() -> None:
    app.dependency_overrides[discovery_provider] = lambda: FakeDiscoveryProvider()
    app.dependency_overrides[connection_validator] = lambda: FakeConnectionValidator()
    try:
        response = TestClient(app).post(
            "/api/v1/preflight",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "X-SGS-Session": SESSION_NONCE,
            },
            json=deployment_spec().model_dump(mode="json"),
        )
    finally:
        app.dependency_overrides.pop(discovery_provider, None)
        app.dependency_overrides.pop(connection_validator, None)

    assert response.status_code == 200
    assert response.json()["read_only"] is True
    assert response.json()["snapshot"]["cloud_identity"] == "adc:enterprise-secgw-01"
