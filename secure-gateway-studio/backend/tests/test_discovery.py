import base64
import hashlib
import json
from copy import deepcopy
from typing import Any

import pytest
from fastapi.testclient import TestClient
from google.auth.credentials import AnonymousCredentials

from sgstudio.api.main import (
    SESSION_NONCE,
    PlanRequest,
    app,
    create_plan,
    discovery_provider,
    repository,
    trusted_connection_validator,
)
from sgstudio.domain.models import (
    AccessPrincipal,
    BackendKind,
    BackendLocation,
    CertificateStrategy,
    ConnectionValidation,
    DeploymentMode,
    DeploymentSpec,
    DiscoverySnapshot,
    NetworkStrategy,
    PreflightResult,
    PrincipalType,
)
from sgstudio.domain.naming import service_account_email
from sgstudio.domain.planner import (
    REQUIRED_APIS,
    DesiredStatePlanner,
    canonical_configuration_hash,
    certificate_configuration_hash,
)
from sgstudio.providers.certificates import CertificateIssuer
from sgstudio.providers.discovery import (
    MANAGED_CHROME_ACCESS_LEVEL_EXPRESSIONS,
    DiscoveryOwnershipProof,
    GoogleDiscoveryProvider,
    discovery_ownership_proofs,
)
from sgstudio.providers.google_executor import render_startup_script_for_discovery
from sgstudio.providers.google_rest import GoogleApiError, GoogleAuthorizedTransport
from sgstudio.providers.local_artifacts import CertificateArtifactStore

TEST_OWNER = "d36ac6fb-431c-441a-ae78-3736e425ee25"
_DEFAULT_MARKER = object()


def owned_description(suffix: str | None = None) -> str:
    prefix = f"Secure Gateway Studio ownership-token={TEST_OWNER}"
    return prefix if suffix is None else f"{prefix}; {suffix}"


def ownership_proof(
    marker: object | None = _DEFAULT_MARKER,
    *,
    identity_field: str | None = None,
    identity: str | None = None,
) -> DiscoveryOwnershipProof:
    if marker is _DEFAULT_MARKER:
        resolved_marker: str | None = owned_description()
    elif marker is None or isinstance(marker, str):
        resolved_marker = marker
    else:
        raise TypeError("ownership proof marker must be a string or None")
    return DiscoveryOwnershipProof(
        marker=resolved_marker,
        provider_identity_field=identity_field,
        provider_identity=identity,
    )


def managed_secret_payload(payload: bytes, token: str = TEST_OWNER) -> bytes:
    document = json.loads(payload)
    assert isinstance(document, dict)
    document["sgs_ownership_token"] = token
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def managed_certificate_ownership_proofs() -> dict[str, DiscoveryOwnershipProof]:
    secret_name = "secure-gateway-http-offload-tls"
    return {
        f"secretmanager:secret:{secret_name}": ownership_proof(TEST_OWNER),
        f"secretmanager:secret_version:{secret_name}": ownership_proof(
            TEST_OWNER,
            identity_field="name",
            identity=(
                "projects/enterprise-secgw-01/secrets/"
                f"{secret_name}/versions/1"
            ),
        ),
    }


def license_assignment(user_id: str, *, host: str = "licensing.googleapis.com") -> dict[str, str]:
    return {
        "kind": "licensing#licenseAssignment",
        "productId": "101040",
        "skuId": "1010400001",
        "userId": user_id,
        "selfLink": (
            f"https://{host}/apps/licensing/v1/product/101040/sku/1010400001/user/{user_id}"
        ),
    }


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
        if "admin.googleapis.com" in url and "/orgunits/id%3A" in url:
            return 200, {
                "orgUnitId": "id:03-test-ou",
                "orgUnitPath": "/Secure Gateway Test",
            }
        if "licensing.googleapis.com" in url:
            assert params == {
                "customerId": "my_customer",
                "maxResults": 1000,
            }
            return 200, {"items": [license_assignment("operator@example.com")]}
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
        if "chromepolicy.googleapis.com" in url:
            return 200, {"resolvedPolicies": []}
        if url.endswith("/global/images/sgs-nginx-20260730"):
            return 200, {
                "id": "987654321",
                "name": "sgs-nginx-20260730",
                "selfLink": (
                    "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/"
                    "global/images/sgs-nginx-20260730"
                ),
            }
        if url.endswith("/global/networks/secure-gateway-http-offload-vpc"):
            return 200, {
                "id": "network-123",
                "name": "secure-gateway-http-offload-vpc",
                "autoCreateSubnetworks": False,
                "routingConfig": {"routingMode": "REGIONAL"},
                "description": owned_description("Managed by Secure Gateway Studio"),
            }
        if url.endswith("/routers/secure-gateway-http-offload-router"):
            return 200, {
                "id": "router-123",
                "name": "secure-gateway-http-offload-router",
                "network": (
                    "https://compute.googleapis.com/compute/v1/projects/"
                    "enterprise-secgw-01/global/networks/"
                    "secure-gateway-http-offload-vpc"
                ),
                "description": owned_description(),
                "nats": [
                    {
                        "name": "secure-gateway-http-offload-nat",
                        "natIpAllocateOption": "AUTO_ONLY",
                        "sourceSubnetworkIpRangesToNat": "LIST_OF_SUBNETWORKS",
                        "subnetworks": [
                            {
                                "name": (
                                    "https://compute.googleapis.com/compute/v1/projects/"
                                    "enterprise-secgw-01/regions/asia-east1/subnetworks/"
                                    "secure-gateway-http-offload-subnet"
                                ),
                                "sourceIpRangesToNat": ["ALL_IP_RANGES"],
                            }
                        ],
                        "logConfig": {"enable": True, "filter": "ERRORS_ONLY"},
                    }
                ],
            }
        return 404, {}


def test_read_only_discovery_builds_snapshot_without_workspace_claim() -> None:
    provider = GoogleDiscoveryProvider(
        FakeTransport(),
        cloud_identity="operator@example.com",
        credential_kind="AuthorizedUserCredentials",
        quota_project_id="quota-project",
        ownership_proofs={
            "compute:network:secure-gateway-http-offload-vpc": ownership_proof(
                owned_description("Managed by Secure Gateway Studio"),
                identity_field="id",
                identity="network-123",
            ),
            "compute:router:secure-gateway-http-offload-router": ownership_proof(
                identity_field="id",
                identity="router-123",
            ),
            "compute:cloud_nat:secure-gateway-http-offload-nat": ownership_proof(
                marker=None,
                identity_field="id",
                identity="router-123",
            ),
        },
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


def test_root_ou_fails_preflight_and_conflicts_every_main_chrome_mutation() -> None:
    class RootOuTransport(FakeTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if "admin.googleapis.com" in url and "/orgunits/id%3A" in url:
                return 200, {"orgUnitId": "id:03-test-ou", "orgUnitPath": "/"}
            return super().request_json(method, url, **kwargs)

    deployment = deployment_spec()
    result = GoogleDiscoveryProvider(
        RootOuTransport(),
        cloud_identity="operator@example.com",
    ).preflight(deployment)
    plan = DesiredStatePlanner().build_plan(deployment, result.snapshot)

    assert plan.can_apply is False
    assert {
        "chromepolicy:extension_install:ekajlcmdfcigmdbphhifahdfjbkciflj",
        "chromepolicy:extension_install:callobklhcbilhphinckomhgkigmfocg",
        "chromepolicy:extension_configuration:ekajlcmdfcigmdbphhifahdfjbkciflj",
        "chromepolicy:service_discovery_proxy:03-test-ou",
    } <= result.snapshot.conflicting_resource_keys
    assert any(item.code == "target-ou-invalid" for item in result.diagnostics)


class DnsRecordDiscoveryTransport(FakeTransport):
    def __init__(
        self,
        *,
        address_status: int = 200,
        record_status: int = 200,
        marker_status: int = 200,
        error_status: int | None = None,
    ) -> None:
        self.address_status = address_status
        self.record_status = record_status
        self.marker_status = marker_status
        self.error_status = error_status

    def request_json(self, method: str, url: str, **kwargs):
        del kwargs
        spec = deployment_spec()
        fqdn = f"{spec.private_hostname}."
        if "/addresses/" in url:
            if self.error_status is not None:
                raise GoogleApiError(
                    status_code=self.error_status,
                    method=method,
                    host="compute.googleapis.com",
                    detail="failed",
                )
            return self.address_status, (
                {"address": "10.42.0.10"} if self.address_status == 200 else {}
            )
        if url.endswith("/A"):
            return self.record_status, (
                {
                    "name": fqdn,
                    "type": "A",
                    "ttl": 60,
                    "rrdatas": ["10.42.0.10"],
                }
                if self.record_status == 200
                else {}
            )
        if url.endswith("/TXT"):
            return self.marker_status, (
                {
                    "name": f"_sgs-owner.{fqdn}",
                    "type": "TXT",
                    "ttl": 60,
                    "rrdatas": [f'"sgs-owner={TEST_OWNER}"'],
                }
                if self.marker_status == 200
                else {}
            )
        raise AssertionError(url)


def _run_dns_record_discovery(
    transport: DnsRecordDiscoveryTransport,
) -> tuple[set[str], set[str], list[object]]:
    spec = deployment_spec()
    existing = {f"dns:private_zone:{spec.name}-zone"}
    conflicts: set[str] = set()
    diagnostics: list[object] = []
    record_key = f"dns:record_set:{spec.private_hostname}"
    GoogleDiscoveryProvider(
        transport,
        cloud_identity=None,
        ownership_proofs={
            record_key: ownership_proof(f'"sgs-owner={TEST_OWNER}"'),
        },
    )._discover_dns_record(
        spec, existing, conflicts, diagnostics  # type: ignore[arg-type]
    )
    return existing, conflicts, diagnostics


def test_dns_record_discovery_requires_exact_a_txt_and_reserved_address() -> None:
    spec = deployment_spec()
    key = f"dns:record_set:{spec.private_hostname}"
    existing, conflicts, diagnostics = _run_dns_record_discovery(
        DnsRecordDiscoveryTransport()
    )

    assert key in existing
    assert key not in conflicts
    assert diagnostics == []


@pytest.mark.parametrize(
    ("address_status", "record_status", "marker_status"),
    [(200, 404, 200), (200, 200, 404), (404, 200, 200)],
)
def test_dns_record_discovery_rejects_partial_existence(
    address_status: int,
    record_status: int,
    marker_status: int,
) -> None:
    spec = deployment_spec()
    key = f"dns:record_set:{spec.private_hostname}"
    existing, conflicts, _ = _run_dns_record_discovery(
        DnsRecordDiscoveryTransport(
            address_status=address_status,
            record_status=record_status,
            marker_status=marker_status,
        )
    )

    assert key not in existing
    assert key in conflicts


@pytest.mark.parametrize("status_code", [403, 429, 500])
def test_dns_record_discovery_api_failure_is_conflicting(status_code: int) -> None:
    spec = deployment_spec()
    key = f"dns:record_set:{spec.private_hostname}"
    existing, conflicts, diagnostics = _run_dns_record_discovery(
        DnsRecordDiscoveryTransport(error_status=status_code)
    )

    assert key not in existing
    assert key in conflicts
    assert diagnostics


def test_dns_record_discovery_only_both_dns_404_is_absent() -> None:
    spec = deployment_spec()
    key = f"dns:record_set:{spec.private_hostname}"
    existing, conflicts, _ = _run_dns_record_discovery(
        DnsRecordDiscoveryTransport(record_status=404, marker_status=404)
    )

    assert key not in existing
    assert key not in conflicts


def test_non_404_reserved_name_probe_failure_blocks_create() -> None:
    class ForbiddenNetworkProbe(FakeTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if url.endswith("/global/networks/secure-gateway-http-offload-vpc"):
                raise GoogleApiError(
                    status_code=403,
                    method="GET",
                    host="compute.googleapis.com",
                    detail="forbidden",
                )
            return super().request_json(method, url, **kwargs)

    spec = deployment_spec()
    result = GoogleDiscoveryProvider(
        ForbiddenNetworkProbe(), cloud_identity="operator@example.com"
    ).preflight(spec)
    key = "compute:network:secure-gateway-http-offload-vpc"
    plan = DesiredStatePlanner().build_plan(spec, result.snapshot)

    assert key in result.snapshot.conflicting_resource_keys
    assert not any(
        change.provider == "compute"
        and change.resource_type == "network"
        and change.action.value == "create"
        for change in plan.changes
    )


class CrossProjectApplicationTransport(FakeTransport):
    def request_json(self, method: str, url: str, **kwargs):
        if url.endswith("/applications/secure-gateway-http-offload-app"):
            return 200, {
                "name": (
                    "projects/enterprise-secgw-01/locations/global/securityGateways/"
                    "default/applications/secure-gateway-http-offload-app"
                ),
                "displayName": "secure-gateway-http-offload-app",
                "createTime": "2026-08-24T00:00:01Z",
                "endpointMatchers": [{"hostname": "demo-server-http.internal", "ports": [443]}],
                "upstreams": [
                    {
                        "network": {
                            "name": (
                                "projects/shared-network-prj/global/networks/"
                                "secure-gateway-http-offload-vpc"
                            )
                        }
                    }
                ],
            }
        return super().request_json(method, url, **kwargs)


def test_cross_project_application_is_rediscovered_in_its_upstream_vpc() -> None:
    direct = DeploymentSpec(
        **{
            **deployment_spec().model_dump(),
            "mode": "poc",
            "backend_kind": BackendKind.DIRECT_HTTPS,
            "network_strategy": NetworkStrategy.EXISTING,
            "vpc_name": "secure-gateway-http-offload-vpc",
            "upstream_vpc_project_id": "shared-network-prj",
            "subnet_name": None,
            "source_image": None,
            "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
            "ca_pool": None,
            "ca_name": None,
            "existing_backend_url": "https://demo-server-http.internal",
            "existing_backend_location": BackendLocation.GCP,
            "existing_backend_connectivity_confirmed": True,
        }
    )
    provider = GoogleDiscoveryProvider(
        CrossProjectApplicationTransport(),
        cloud_identity="operator@example.com",
        ownership_proofs={
            "beyondcorp:application:secure-gateway-http-offload-app": (
                ownership_proof(
                    marker=None,
                    identity_field="createTime",
                    identity="2026-08-24T00:00:01Z",
                )
            ),
        },
    )

    result = provider.preflight(direct)

    application_key = "beyondcorp:application:secure-gateway-http-offload-app"
    assert application_key in result.snapshot.existing_resource_keys
    assert application_key not in result.snapshot.conflicting_resource_keys


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


class PaginatedWorkspaceSignalsTransport(FakeTransport):
    def __init__(self, *, license_404: bool = False) -> None:
        self.profile_params: list[dict[str, str | int]] = []
        self.license_params: list[dict[str, str | int]] = []
        self.license_404 = license_404

    def request_json(
        self,
        method: str,
        url: str,
        *args,
        params: dict[str, str | int] | None = None,
        **kwargs,
    ) -> tuple[int, dict[str, Any]]:
        if "chromemanagement.googleapis.com" in url:
            assert params is not None
            self.profile_params.append(params)
            if params.get("pageToken") == "profiles-2":
                return 200, {
                    "chromeBrowserProfiles": [
                        {
                            "affiliationState": "BROWSER_MANAGED",
                            "lastPolicySyncTime": "2026-08-03T07:15:16Z",
                            "reportingData": {
                                "extensionData": [
                                    {
                                        "extensionId": "ekajlcmdfcigmdbphhifahdfjbkciflj",
                                        "version": "1.26.129",
                                        "isDisabled": False,
                                    }
                                ]
                            },
                        }
                    ]
                }
            return 200, {
                "chromeBrowserProfiles": [
                    {
                        "affiliationState": "PROFILE_ONLY",
                        "lastPolicySyncTime": "2026-08-04T08:00:00Z",
                        "reportingData": {
                            "extensionData": [
                                {
                                    "extensionId": "callobklhcbilhphinckomhgkigmfocg",
                                    "version": "1.140.0",
                                    "isDisabled": False,
                                }
                            ]
                        },
                    }
                ],
                "nextPageToken": "profiles-2",
            }
        if "licensing.googleapis.com" in url:
            assert params is not None
            self.license_params.append(params)
            if self.license_404:
                return 404, {}
            if params.get("pageToken") == "licenses-2":
                return 200, {"items": [license_assignment("three@example.com")]}
            return 200, {
                "items": [
                    license_assignment("one@example.com"),
                    license_assignment("two@example.com"),
                ],
                "nextPageToken": "licenses-2",
            }
        return super().request_json(method, url, *args, params=params, **kwargs)


def test_workspace_signals_follow_all_pages_and_use_actual_profile_fields() -> None:
    transport = PaginatedWorkspaceSignalsTransport()
    result = GoogleDiscoveryProvider(
        transport,
        cloud_identity="operator@example.com",
    ).preflight(deployment_spec())

    assert result.snapshot.managed_chrome_profile_count == 2
    assert result.snapshot.profile_only_count == 1
    assert result.snapshot.latest_chrome_policy_sync == "2026-08-04T08:00:00Z"
    assert result.snapshot.endpoint_verification_version == "1.140.0"
    assert result.snapshot.secure_enterprise_browser_version == "1.26.129"
    assert result.snapshot.chrome_enterprise_premium_license_count == 3
    assert transport.profile_params[1]["pageToken"] == "profiles-2"
    assert transport.license_params[1]["pageToken"] == "licenses-2"


def test_license_list_404_is_an_empty_assignment_contract_not_api_failure() -> None:
    result = GoogleDiscoveryProvider(
        PaginatedWorkspaceSignalsTransport(license_404=True),
        cloud_identity="operator@example.com",
    ).preflight(deployment_spec())

    assert result.snapshot.chrome_enterprise_premium_license_count == 0
    assert any(
        item.code == "chrome-enterprise-premium-license-not-detected" for item in result.diagnostics
    )
    assert not any(
        item.code == "chrome-enterprise-premium-manual-confirmation" for item in result.diagnostics
    )


@pytest.mark.parametrize(
    "items",
    [
        [{}],
        [{**license_assignment("user@example.com"), "skuId": "wrong"}],
        [
            license_assignment("User@example.com"),
            license_assignment("user@EXAMPLE.com"),
        ],
    ],
)
def test_license_list_rejects_malformed_wrong_sku_and_duplicate_users(
    items: list[dict[str, object]],
) -> None:
    class InvalidLicenseTransport(PaginatedWorkspaceSignalsTransport):
        def request_json(self, method: str, url: str, *args, params=None, **kwargs):
            if "licensing.googleapis.com" in url:
                return 200, {"items": deepcopy(items)}
            return super().request_json(method, url, *args, params=params, **kwargs)

    result = GoogleDiscoveryProvider(
        InvalidLicenseTransport(),
        cloud_identity="operator@example.com",
    ).preflight(deployment_spec())

    assert result.snapshot.chrome_enterprise_premium_license_count is None
    assert any(
        item.code == "chrome-enterprise-premium-manual-confirmation" for item in result.diagnostics
    )


@pytest.mark.parametrize("self_link_host", ["licensing.googleapis.com", "www.googleapis.com"])
def test_license_list_accepts_only_the_two_official_self_link_hosts(
    self_link_host: str,
) -> None:
    class OfficialHostTransport(PaginatedWorkspaceSignalsTransport):
        def request_json(self, method: str, url: str, *args, params=None, **kwargs):
            if "licensing.googleapis.com" in url:
                return 200, {"items": [license_assignment("user@example.com", host=self_link_host)]}
            return super().request_json(method, url, *args, params=params, **kwargs)

    result = GoogleDiscoveryProvider(
        OfficialHostTransport(), cloud_identity="operator@example.com"
    ).preflight(deployment_spec())

    assert result.snapshot.chrome_enterprise_premium_license_count == 1


def test_license_list_rejects_an_untrusted_self_link_host() -> None:
    class UntrustedHostTransport(PaginatedWorkspaceSignalsTransport):
        def request_json(self, method: str, url: str, *args, params=None, **kwargs):
            if "licensing.googleapis.com" in url:
                return 200, {"items": [license_assignment("user@example.com", host="example.com")]}
            return super().request_json(method, url, *args, params=params, **kwargs)

    result = GoogleDiscoveryProvider(
        UntrustedHostTransport(), cloud_identity="operator@example.com"
    ).preflight(deployment_spec())

    assert result.snapshot.chrome_enterprise_premium_license_count is None


class RepeatedProfilePageTokenTransport(PaginatedWorkspaceSignalsTransport):
    def request_json(self, method: str, url: str, *args, params=None, **kwargs):
        if "chromemanagement.googleapis.com" in url:
            assert params is not None
            token = str(params.get("pageToken", "profiles-loop"))
            return 200, {
                "chromeBrowserProfiles": [{}],
                "nextPageToken": token,
            }
        return super().request_json(method, url, *args, params=params, **kwargs)


def test_repeated_profile_page_token_fails_closed_instead_of_returning_partial_counts() -> None:
    result = GoogleDiscoveryProvider(
        RepeatedProfilePageTokenTransport(),
        cloud_identity="operator@example.com",
    ).preflight(deployment_spec())

    assert result.snapshot.managed_chrome_profile_count is None
    assert result.snapshot.endpoint_verification_installed is None
    assert any(
        item.code == "chrome-profile-readiness-pagination-invalid" for item in result.diagnostics
    )


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
            (json_body or {}).get("policySchemaFilter") == "chrome.users.ChromeRootStoreEnabled"
        ):
            return 200, {
                "resolvedPolicies": [
                    {
                        "targetKey": deepcopy((json_body or {})["policyTargetKey"]),
                        "sourceKey": {"targetResource": "orgunits/03-test-ou"},
                        "value": {
                            "policySchema": "chrome.users.ChromeRootStoreEnabled",
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
                            "targetKey": deepcopy(json_body.get("policyTargetKey", {})),
                            "value": {
                                "policySchema": ("chrome.users.apps.ManagedConfiguration"),
                                "value": {"managedConfiguration": "{}"},
                            },
                            "sourceKey": {"targetResource": "groups/group-123"},
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


class PagedChromeResolveTransport(GroupPolicyConflictTransport):
    def __init__(self) -> None:
        super().__init__()
        self.resolve_bodies: list[dict[str, Any]] = []

    def request_json(self, method: str, url: str, **kwargs):
        body = kwargs.get("json_body") or {}
        if method == "POST" and url.endswith("/policies:resolve"):
            self.resolve_bodies.append(deepcopy(body))
            if "pageToken" not in body:
                return 200, {
                    "resolvedPolicies": [],
                    "nextPageToken": "resolve-page-2",
                }
            target = body["policyTargetKey"]
            schema = body["policySchemaFilter"]
            target_resource = target["targetResource"]
            if target_resource == "groups/group-123":
                return super().request_json(method, url, **kwargs)
            return 200, {
                "resolvedPolicies": [
                    {
                        "targetKey": deepcopy(target),
                        "sourceKey": {"targetResource": target_resource},
                        "value": {
                            "policySchema": schema,
                            "value": {"appInstallType": "FORCED"},
                        },
                    }
                ]
            }
        return super().request_json(method, url, **kwargs)


def test_chrome_policy_discovery_follows_empty_first_page_for_ou_and_group() -> None:
    deployment = deployment_spec()
    direct_transport = PagedChromeResolveTransport()
    direct = GoogleDiscoveryProvider(
        direct_transport,
        cloud_identity="operator@example.com",
    )._resolve_chrome_policy(
        deployment,
        schema="chrome.users.apps.InstallType",
        app_id="ekajlcmdfcigmdbphhifahdfjbkciflj",
    )
    assert direct == {"appInstallType": "FORCED"}
    assert direct_transport.resolve_bodies[0]["pageSize"] == 1_000
    assert direct_transport.resolve_bodies[1]["pageToken"] == "resolve-page-2"

    group_result = GoogleDiscoveryProvider(
        PagedChromeResolveTransport(),
        cloud_identity="operator@example.com",
    ).preflight(deployment)
    assert group_result.snapshot.chrome_group_policy_discovery_complete is True
    assert group_result.snapshot.chrome_extension_group_conflicts == [
        "secure-access@example.com"
    ]


@pytest.mark.parametrize("token", [None, 7, "repeat"])
def test_chrome_policy_discovery_rejects_invalid_or_repeated_page_token(
    token: object,
) -> None:
    class InvalidTokenTransport(ReportingProfileTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if method == "POST" and url.endswith("/policies:resolve"):
                return 200, {"resolvedPolicies": [], "nextPageToken": token}
            return super().request_json(method, url, **kwargs)

    with pytest.raises(ValueError, match="invalid page token"):
        GoogleDiscoveryProvider(
            InvalidTokenTransport(),
            cloud_identity="operator@example.com",
        )._resolve_chrome_policy(
            deployment_spec(),
            schema="chrome.users.apps.InstallType",
            app_id="ekajlcmdfcigmdbphhifahdfjbkciflj",
        )


def test_preflight_blocks_incompatible_group_extension_policy() -> None:
    provider = GoogleDiscoveryProvider(
        GroupPolicyConflictTransport(),
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(deployment_spec())

    assert result.snapshot.chrome_extension_group_conflicts == ["secure-access@example.com"]
    assert (
        "chromepolicy:group_extension_configuration:secure-access@example.com"
        in result.snapshot.conflicting_resource_keys
    )
    assert any(
        diagnostic.code == "chrome-extension-group-policy-conflict"
        for diagnostic in result.diagnostics
    )


@pytest.mark.parametrize(
    "group_item",
    [
        None,
        {},
        {"id": "group-123"},
        {"email": "secure-access@example.com"},
        {"id": 123, "email": "secure-access@example.com"},
        {"id": "group-123", "email": "invalid-email"},
    ],
)
def test_group_policy_discovery_rejects_malformed_directory_groups(
    group_item: object,
) -> None:
    class MalformedGroupTransport(ReportingProfileTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if url == "https://admin.googleapis.com/admin/directory/v1/groups":
                return 200, {"groups": [group_item]}
            return super().request_json(method, url, **kwargs)

    deployment = deployment_spec()
    result = GoogleDiscoveryProvider(
        MalformedGroupTransport(),
        cloud_identity="operator@example.com",
    ).preflight(deployment)
    plan = DesiredStatePlanner().build_plan(deployment, result.snapshot)

    assert result.snapshot.chrome_group_policy_discovery_complete is False
    assert any(
        diagnostic.code == "chrome-group-policy-discovery-truncated"
        for diagnostic in result.diagnostics
    )
    assert (
        next(gate for gate in plan.gates if gate.gate_id == "group-policy-discovery").blocking
        is True
    )


def test_group_policy_discovery_rejects_non_boolean_membership() -> None:
    class InvalidMembershipTransport(ReportingProfileTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if url == "https://admin.googleapis.com/admin/directory/v1/groups":
                return 200, {"groups": [{"id": "group-123", "email": "indirect@example.com"}]}
            if "/hasMember/" in url:
                return 200, {"isMember": "false"}
            return super().request_json(method, url, **kwargs)

    deployment = deployment_spec().model_copy(
        update={
            "principals": [
                AccessPrincipal(
                    type=PrincipalType.USER,
                    value="approved-user@example.com",
                )
            ]
        }
    )
    result = GoogleDiscoveryProvider(
        InvalidMembershipTransport(),
        cloud_identity="operator@example.com",
    ).preflight(deployment)

    assert result.snapshot.chrome_group_policy_discovery_complete is False
    assert any(
        diagnostic.code == "chrome-group-policy-membership-invalid"
        for diagnostic in result.diagnostics
    )


@pytest.mark.parametrize(
    "resolved_payload",
    [
        {},
        {"resolvedPolicies": {}},
        {"resolvedPolicies": [None]},
        {
            "resolvedPolicies": [
                {
                    "sourceKey": {"targetResource": "groups/other"},
                    "value": {"value": {"managedConfiguration": "{}"}},
                }
            ]
        },
        {
            "resolvedPolicies": [
                {
                    "sourceKey": {"targetResource": "groups/group-123"},
                    "value": {"value": {}},
                }
            ]
        },
        {
            "resolvedPolicies": [
                {
                    "sourceKey": {"targetResource": "groups/group-123"},
                    "value": {"value": {"managedConfiguration": "{"}},
                }
            ]
        },
        {
            "resolvedPolicies": [
                {
                    "sourceKey": {"targetResource": "groups/group-123"},
                    "value": {"value": {"managedConfiguration": "{}"}},
                },
                {
                    "sourceKey": {"targetResource": "groups/group-123"},
                    "value": {"value": {"managedConfiguration": "{}"}},
                },
            ]
        },
    ],
)
def test_group_policy_discovery_rejects_malformed_resolve_payloads(
    resolved_payload: dict[str, object],
) -> None:
    class MalformedResolveTransport(GroupPolicyConflictTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if "chromepolicy.googleapis.com" in url and kwargs.get("json_body"):
                target = kwargs["json_body"].get("policyTargetKey", {}).get("targetResource")
                if target == "groups/group-123":
                    return 200, resolved_payload
            return super().request_json(method, url, **kwargs)

    deployment = deployment_spec()
    result = GoogleDiscoveryProvider(
        MalformedResolveTransport(),
        cloud_identity="operator@example.com",
    ).preflight(deployment)
    plan = DesiredStatePlanner().build_plan(deployment, result.snapshot)

    assert result.snapshot.chrome_group_policy_discovery_complete is False
    assert any(
        diagnostic.code == "chrome-group-policy-response-invalid"
        for diagnostic in result.diagnostics
    )
    assert (
        next(gate for gate in plan.gates if gate.gate_id == "group-policy-discovery").blocking
        is True
    )


def test_group_policy_discovery_accepts_only_a_valid_empty_policy_array_as_absent() -> None:
    class EmptyResolveTransport(GroupPolicyConflictTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if "chromepolicy.googleapis.com" in url and kwargs.get("json_body"):
                target = kwargs["json_body"].get("policyTargetKey", {}).get("targetResource")
                if target == "groups/group-123":
                    return 200, {"resolvedPolicies": []}
            return super().request_json(method, url, **kwargs)

    result = GoogleDiscoveryProvider(
        EmptyResolveTransport(),
        cloud_identity="operator@example.com",
    ).preflight(deployment_spec())

    assert result.snapshot.chrome_group_policy_discovery_complete is True
    assert result.snapshot.chrome_extension_group_conflicts == []


class GroupPolicyDiscoveryDeniedTransport(FakeTransport):
    def request_json(self, method: str, url: str, **kwargs):
        if url == "https://admin.googleapis.com/admin/directory/v1/groups":
            raise GoogleApiError(
                status_code=403,
                method=method,
                host="admin.googleapis.com",
                detail="Forbidden",
            )
        return super().request_json(method, url, **kwargs)


def test_preflight_fails_closed_when_group_policy_discovery_is_denied() -> None:
    spec = deployment_spec()
    provider = GoogleDiscoveryProvider(
        GroupPolicyDiscoveryDeniedTransport(),
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(spec)
    plan = DesiredStatePlanner().build_plan(spec, result.snapshot)
    gate = next(item for item in plan.gates if item.gate_id == "group-policy-discovery")

    assert result.snapshot.chrome_group_policy_discovery_complete is False
    assert gate.status == "blocked"
    assert gate.blocking is True
    assert plan.can_apply is False


class GroupPolicyDiscoveryTruncatedTransport(FakeTransport):
    def request_json(self, method: str, url: str, **kwargs):
        if url == "https://admin.googleapis.com/admin/directory/v1/groups":
            page = int((kwargs.get("params") or {}).get("pageToken", "0"))
            return 200, {
                "groups": [
                    {
                        "id": f"group-{page}-{index}",
                        "email": f"group-{page}-{index}@example.com",
                    }
                    for index in range(200)
                ],
                "nextPageToken": str(page + 1),
            }
        return super().request_json(method, url, **kwargs)


def test_preflight_fails_closed_when_group_policy_discovery_is_truncated() -> None:
    spec = deployment_spec()
    provider = GoogleDiscoveryProvider(
        GroupPolicyDiscoveryTruncatedTransport(),
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(spec)
    plan = DesiredStatePlanner().build_plan(spec, result.snapshot)
    gate = next(item for item in plan.gates if item.gate_id == "group-policy-discovery")

    assert result.snapshot.chrome_group_policy_discovery_complete is False
    assert any(
        item.code == "chrome-group-policy-discovery-truncated" for item in result.diagnostics
    )
    assert gate.status == "blocked"
    assert plan.can_apply is False


@pytest.mark.parametrize("token_mode", ["repeated", "rotating"])
def test_group_policy_empty_page_token_loops_are_bounded_and_fail_closed(
    token_mode: str,
) -> None:
    class EmptyLoopTransport(FakeTransport):
        def __init__(self) -> None:
            self.group_pages = 0

        def request_json(self, method: str, url: str, **kwargs):
            if url == "https://admin.googleapis.com/admin/directory/v1/groups":
                self.group_pages += 1
                token = "loop" if token_mode == "repeated" else f"page-{self.group_pages}"
                return 200, {"groups": [], "nextPageToken": token}
            return super().request_json(method, url, **kwargs)

    transport = EmptyLoopTransport()
    result = GoogleDiscoveryProvider(
        transport,
        cloud_identity="operator@example.com",
    ).preflight(deployment_spec())

    assert result.snapshot.chrome_group_policy_discovery_complete is False
    assert transport.group_pages <= 10
    assert any(
        item.code == "chrome-group-policy-discovery-truncated" for item in result.diagnostics
    )


def _direct_ip_spec() -> DeploymentSpec:
    return DeploymentSpec(
        **{
            **deployment_spec().model_dump(),
            "mode": "poc",
            "backend_kind": BackendKind.DIRECT_HTTPS,
            "network_strategy": NetworkStrategy.EXISTING,
            "vpc_name": "private-app-vpc",
            "subnet_name": None,
            "source_image": None,
            "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
            "ca_pool": None,
            "ca_name": None,
            "existing_backend_url": "https://10.20.0.10:8443",
            "existing_backend_location": BackendLocation.GCP,
            "existing_backend_connectivity_confirmed": True,
        }
    )


@pytest.mark.parametrize("token_mode", ["repeated", "rotating"])
def test_forwarding_rule_pagination_loops_block_global_access_gate(
    token_mode: str,
) -> None:
    class ForwardingLoopTransport(FakeTransport):
        def __init__(self) -> None:
            self.forwarding_pages = 0

        def request_json(self, method: str, url: str, **kwargs):
            if url.endswith("/aggregated/forwardingRules"):
                self.forwarding_pages += 1
                token = "loop" if token_mode == "repeated" else f"page-{self.forwarding_pages}"
                return 200, {"items": {}, "nextPageToken": token}
            return super().request_json(method, url, **kwargs)

    transport = ForwardingLoopTransport()
    result = GoogleDiscoveryProvider(
        transport,
        cloud_identity="operator@example.com",
    ).preflight(_direct_ip_spec())
    plan = DesiredStatePlanner().build_plan(_direct_ip_spec(), result.snapshot)
    gate = next(item for item in plan.gates if item.gate_id == "global-access")

    assert result.snapshot.application_global_access_discovery_complete is False
    assert transport.forwarding_pages <= 10
    assert gate.status == "blocked"
    assert gate.blocking is True
    assert any(
        item.code == "compute-forwarding-rule-pagination-invalid" for item in result.diagnostics
    )


def test_forwarding_rule_ignores_unrelated_optional_fields_but_validates_the_match() -> None:
    class MixedForwardingTransport(FakeTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if url.endswith("/aggregated/forwardingRules"):
                return 200, {
                    "items": {
                        "regions/asia-east1": {
                            "forwardingRules": [
                                {"name": "unrelated-vpn-rule", "IPAddress": "10.20.0.99"},
                                {
                                    "name": "target-ilb-rule",
                                    "IPAddress": "10.20.0.10",
                                    "loadBalancingScheme": "INTERNAL_MANAGED",
                                    "IPProtocol": "TCP",
                                    "ports": ["8443"],
                                    "allowGlobalAccess": True,
                                },
                            ]
                        }
                    }
                }
            return super().request_json(method, url, **kwargs)

    assert GoogleDiscoveryProvider(
        MixedForwardingTransport(), cloud_identity=None
    )._application_global_access(_direct_ip_spec()) == (True, "target-ilb-rule")


def test_existing_private_egress_follows_pages_and_requires_selected_subnet() -> None:
    class RouterPages(FakeTransport):
        def __init__(self, subnet_name: str) -> None:
            self.subnet_name = subnet_name

        def request_json(self, method: str, url: str, *, params=None, **kwargs):
            if url.endswith("/global/routes"):
                return 200, {
                    "items": [
                        {
                            "name": "default-internet-route",
                            "network": (
                                "https://www.googleapis.com/compute/v1/projects/"
                                "enterprise-secgw-01/global/networks/admin-vpc"
                            ),
                            "destRange": "0.0.0.0/0",
                            "nextHopGateway": (
                                "https://www.googleapis.com/compute/v1/projects/"
                                "enterprise-secgw-01/global/gateways/default-internet-gateway"
                            ),
                            "priority": 1000,
                            "routeType": "STATIC",
                            "status": "ACTIVE",
                        }
                    ]
                }
            if url.endswith("/aggregated/routers"):
                if params and params.get("pageToken") == "page-2":
                    return 200, {
                        "items": {
                            "regions/asia-east1": {
                                "routers": [
                                    {
                                        "network": (
                                            "projects/enterprise-secgw-01/global/networks/"
                                            "admin-vpc"
                                        )
                                        # A legal empty repeated field is omitted.
                                    },
                                    {
                                        "network": (
                                            "projects/enterprise-secgw-01/global/networks/admin-vpc"
                                        ),
                                        "nats": [
                                            {
                                                "name": "admin-nat",
                                                "natIpAllocateOption": "AUTO_ONLY",
                                                "sourceSubnetworkIpRangesToNat": (
                                                    "LIST_OF_SUBNETWORKS"
                                                ),
                                                "subnetworks": [
                                                    {
                                                        "name": (
                                                            "projects/enterprise-secgw-01/regions/"
                                                            f"asia-east1/subnetworks/{self.subnet_name}"
                                                        ),
                                                        "sourceIpRangesToNat": ["ALL_IP_RANGES"],
                                                    }
                                                ],
                                            }
                                        ],
                                    }
                                ]
                            }
                        }
                    }
                return 200, {"items": {}, "nextPageToken": "page-2"}
            return super().request_json(method, url, params=params, **kwargs)

    spec = deployment_spec().model_copy(
        update={
            "network_strategy": NetworkStrategy.EXISTING,
            "vpc_name": "admin-vpc",
            "subnet_name": "admin-subnet",
        }
    )
    assert GoogleDiscoveryProvider(
        RouterPages("admin-subnet"), cloud_identity=None
    )._existing_private_egress_available(spec)
    assert not GoogleDiscoveryProvider(
        RouterPages("different-subnet"), cloud_identity=None
    )._existing_private_egress_available(spec)

    class MalformedNats(RouterPages):
        def request_json(self, method: str, url: str, *, params=None, **kwargs):
            status, payload = super().request_json(
                method,
                url,
                params=params,
                **kwargs,
            )
            if url.endswith("/aggregated/routers") and params.get("pageToken") == "page-2":
                payload["items"]["regions/asia-east1"]["routers"][0]["nats"] = {}
            return status, payload

    with pytest.raises(ValueError, match="network/NAT"):
        GoogleDiscoveryProvider(
            MalformedNats("admin-subnet"), cloud_identity=None
        )._existing_private_egress_available(spec)


def test_existing_private_egress_rejects_other_region_and_unreachable_scopes() -> None:
    class RouterScope(FakeTransport):
        def __init__(
            self,
            *,
            scope: str,
            unreachables: object = None,
            nat_type: str | None = None,
            endpoint_types: object = None,
            route_available: bool = True,
            competing_route: bool = False,
        ) -> None:
            self.scope = scope
            self.unreachables = unreachables
            self.nat_type = nat_type
            self.endpoint_types = endpoint_types
            self.route_available = route_available
            self.competing_route = competing_route

        def request_json(self, method: str, url: str, *, params=None, **kwargs):
            if url.endswith("/global/routes"):
                if not self.route_available:
                    return 200, {"items": []}
                return 200, {
                    "items": [
                        {
                            "name": "default-internet-route",
                            "network": (
                                "https://www.googleapis.com/compute/v1/projects/"
                                "enterprise-secgw-01/global/networks/admin-vpc"
                            ),
                            "destRange": "0.0.0.0/0",
                            "nextHopGateway": (
                                "https://www.googleapis.com/compute/v1/projects/"
                                "enterprise-secgw-01/global/gateways/default-internet-gateway"
                            ),
                            "priority": 1000,
                            "routeType": "STATIC",
                            "status": "ACTIVE",
                        },
                        *(
                            [
                                {
                                    "name": "higher-priority-vpn-default",
                                    "network": (
                                        "https://www.googleapis.com/compute/v1/projects/"
                                        "enterprise-secgw-01/global/networks/admin-vpc"
                                    ),
                                    "destRange": "0.0.0.0/0",
                                    "nextHopIp": "10.42.0.5",
                                    "priority": 100,
                                    "routeType": "STATIC",
                                    "status": "ACTIVE",
                                }
                            ]
                            if self.competing_route
                            else []
                        ),
                    ]
                }
            if url.endswith("/aggregated/routers"):
                assert params == {"maxResults": 500, "returnPartialSuccess": "true"}
                payload: dict[str, object] = {
                    "items": {
                        self.scope: {
                            "routers": [
                                {
                                    "network": (
                                        "https://www.googleapis.com/compute/v1/projects/"
                                        "enterprise-secgw-01/global/networks/admin-vpc"
                                    ),
                                    "nats": [
                                        {
                                            "name": "admin-nat",
                                            "natIpAllocateOption": "AUTO_ONLY",
                                            "sourceSubnetworkIpRangesToNat": (
                                                "ALL_SUBNETWORKS_ALL_IP_RANGES"
                                            ),
                                            **(
                                                {}
                                                if self.nat_type is None
                                                else {"type": self.nat_type}
                                            ),
                                            **(
                                                {}
                                                if self.endpoint_types is None
                                                else {"endpointTypes": self.endpoint_types}
                                            ),
                                        }
                                    ],
                                }
                            ]
                        }
                    }
                }
                if self.unreachables is not None:
                    payload["unreachables"] = self.unreachables
                return 200, payload
            return super().request_json(method, url, params=params, **kwargs)

    deployment = deployment_spec().model_copy(
        update={
            "network_strategy": NetworkStrategy.EXISTING,
            "vpc_name": "admin-vpc",
            "subnet_name": "admin-subnet",
        }
    )
    assert GoogleDiscoveryProvider(
        RouterScope(scope="regions/asia-east1"), cloud_identity=None
    )._existing_private_egress_available(deployment)
    assert not GoogleDiscoveryProvider(
        RouterScope(scope="regions/us-central1"), cloud_identity=None
    )._existing_private_egress_available(deployment)
    assert not GoogleDiscoveryProvider(
        RouterScope(scope="regions/asia-east1", nat_type="PRIVATE"), cloud_identity=None
    )._existing_private_egress_available(deployment)
    assert not GoogleDiscoveryProvider(
        RouterScope(scope="regions/asia-east1", route_available=False), cloud_identity=None
    )._existing_private_egress_available(deployment)
    assert not GoogleDiscoveryProvider(
        RouterScope(scope="regions/asia-east1", competing_route=True), cloud_identity=None
    )._existing_private_egress_available(deployment)
    with pytest.raises(ValueError, match="endpoint"):
        GoogleDiscoveryProvider(
            RouterScope(
                scope="regions/asia-east1",
                endpoint_types=["ENDPOINT_TYPE_SWG"],
            ),
            cloud_identity=None,
        )._existing_private_egress_available(deployment)
    with pytest.raises(ValueError, match="unreachable"):
        GoogleDiscoveryProvider(
            RouterScope(
                scope="regions/asia-east1",
                unreachables=["regions/asia-east1"],
            ),
            cloud_identity=None,
        )._existing_private_egress_available(deployment)


def test_group_listing_present_null_page_token_fails_closed() -> None:
    class NullGroupToken(FakeTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if url.endswith("/admin/directory/v1/groups"):
                return 200, {"groups": [], "nextPageToken": None}
            return super().request_json(method, url, **kwargs)

    diagnostics = []
    conflicts: set[str] = set()
    groups, complete = GoogleDiscoveryProvider(
        NullGroupToken(), cloud_identity=None
    )._discover_chrome_group_policy_conflicts(deployment_spec(), conflicts, diagnostics)

    assert groups == []
    assert complete is False
    assert any(item.code == "chrome-group-policy-discovery-truncated" for item in diagnostics)


def test_access_level_direct_custom_expression_is_compatible() -> None:
    provider = GoogleDiscoveryProvider(FakeTransport(), cloud_identity=None)
    payload = {
        "name": "accessPolicies/123456789/accessLevels/managed_chrome",
        "custom": {
            "expr": {
                "expression": (
                        "device.chrome.management_state in ["
                        "ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED,"
                        " "
                        "ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]"
                )
            }
        }
    }

    assert provider._compatible(
        "accesscontextmanager:access_level:accessPolicies/123456789/accessLevels/managed_chrome",
        payload,
        deployment_spec(),
    )


@pytest.mark.parametrize(
    "expression",
    [
        "true || device.chrome.management_state == "
        "ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED",
        "(device.chrome.management_state == "
        "ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED)",
        "device.chrome.management_state == "
        "ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED ",
    ],
)
def test_access_level_rejects_noncanonical_managed_chrome_expressions(
    expression: str,
) -> None:
    provider = GoogleDiscoveryProvider(FakeTransport(), cloud_identity=None)

    assert not provider._compatible(
        (
            "accesscontextmanager:access_level:"
            "accessPolicies/123456789/accessLevels/managed_chrome"
        ),
        {
            "name": "accessPolicies/123456789/accessLevels/managed_chrome",
            "custom": {"expr": {"expression": expression}},
        },
        deployment_spec(),
    )


def test_access_level_accepts_canonical_expression_with_documented_metadata() -> None:
    spec = deployment_spec()
    key = f"accesscontextmanager:access_level:{spec.managed_chrome_access_level}"
    provider = GoogleDiscoveryProvider(FakeTransport(), cloud_identity=None)

    assert provider._compatible(
        key,
        {
            "name": spec.managed_chrome_access_level,
            "title": "Managed Chrome",
            "description": "Require an enterprise-managed Chrome profile or browser.",
            "custom": {
                "expr": {
                    "expression": next(iter(MANAGED_CHROME_ACCESS_LEVEL_EXPRESSIONS)),
                    "title": "Chrome management state",
                    "description": "Canonical managed-Chrome expression.",
                    "location": "access-level.yaml:8",
                }
            },
        },
        spec,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        {"name": "accessPolicies/123456789/accessLevels/wrong"},
        {"unknown": True},
        {"basic": {"conditions": []}},
        {"custom": {"expr": {"expression": "placeholder", "unknown": True}}},
    ],
    ids=["wrong-name", "unknown-top-level", "basic-custom-union", "unknown-expr-field"],
)
def test_access_level_wrong_identity_or_extra_shape_conflicts(
    mutation: dict[str, object],
) -> None:
    spec = deployment_spec()
    key = f"accesscontextmanager:access_level:{spec.managed_chrome_access_level}"
    payload: dict[str, object] = {
        "name": spec.managed_chrome_access_level,
        "custom": {
            "expr": {
                "expression": next(iter(MANAGED_CHROME_ACCESS_LEVEL_EXPRESSIONS)),
            }
        },
    }
    if "custom" in mutation and isinstance(mutation["custom"], dict):
        custom = mutation["custom"]
        expr = custom.get("expr")
        if isinstance(expr, dict) and expr.get("expression") == "placeholder":
            custom = {
                "expr": {
                    **expr,
                    "expression": next(iter(MANAGED_CHROME_ACCESS_LEVEL_EXPRESSIONS)),
                }
            }
        payload["custom"] = custom
        payload.update({field: value for field, value in mutation.items() if field != "custom"})
    else:
        payload.update(mutation)

    assert not GoogleDiscoveryProvider(FakeTransport(), cloud_identity=None)._compatible(
        key,
        payload,
        spec,
    )


@pytest.mark.parametrize(
    ("mutation", "existing"),
    [
        ({}, True),
        ({"name": "accessPolicies/123456789/accessLevels/wrong"}, False),
        ({"unknown": True}, False),
    ],
    ids=["canonical-metadata", "wrong-name", "unknown-field"],
)
def test_access_level_preflight_classifies_exact_identity_and_shape(
    mutation: dict[str, object],
    existing: bool,
) -> None:
    spec = deployment_spec()
    key = f"accesscontextmanager:access_level:{spec.managed_chrome_access_level}"
    payload: dict[str, object] = {
        "name": spec.managed_chrome_access_level,
        "title": "Managed Chrome",
        "custom": {
            "expr": {
                "expression": next(iter(MANAGED_CHROME_ACCESS_LEVEL_EXPRESSIONS)),
                "location": "access-level.yaml:8",
            }
        },
        **mutation,
    }

    class AccessLevelTransport(FakeTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if url == (
                "https://accesscontextmanager.googleapis.com/v1/"
                f"{spec.managed_chrome_access_level}"
            ):
                return 200, payload
            return super().request_json(method, url, **kwargs)

    result = GoogleDiscoveryProvider(
        AccessLevelTransport(),
        cloud_identity="operator@example.com",
    ).preflight(spec)

    assert (key in result.snapshot.existing_resource_keys) is existing
    assert (key in result.snapshot.conflicting_resource_keys) is (not existing)


@pytest.mark.parametrize(
    "resolved",
    [
        {},
        {"resolvedPolicies": {}},
        {"resolvedPolicies": [None]},
        {
            "resolvedPolicies": [
                {
                    "sourceKey": {"targetResource": "orgunits/03-test-ou"},
                    "value": {"value": {}},
                }
            ]
        },
        {
            "resolvedPolicies": [
                {
                    "sourceKey": {
                        "targetResource": "orgunits/03-test-ou",
                        "additionalTargetKeys": {"app_id": "chrome:wrong"},
                    },
                    "value": {
                        "policySchema": "chrome.users.apps.InstallType",
                        "value": {"appInstallType": "FORCED"},
                    },
                }
            ]
        },
    ],
)
def test_main_chrome_policy_discovery_malformed_response_blocks_create(
    resolved: dict[str, object],
) -> None:
    companion = "ekajlcmdfcigmdbphhifahdfjbkciflj"

    class MalformedChromeTransport(FakeTransport):
        def request_json(self, method: str, url: str, *args, json_body=None, **kwargs):
            if (
                url.endswith("/policies:resolve")
                and (json_body or {}).get("policySchemaFilter")
                == "chrome.users.apps.InstallType"
                and (json_body or {}).get("policyTargetKey", {})
                .get("additionalTargetKeys", {})
                .get("app_id")
                == f"chrome:{companion}"
            ):
                return 200, deepcopy(resolved)
            return super().request_json(
                method,
                url,
                *args,
                json_body=json_body,
                **kwargs,
            )

    result = GoogleDiscoveryProvider(
        MalformedChromeTransport(),
        cloud_identity="operator@example.com",
    ).preflight(deployment_spec())

    key = f"chromepolicy:extension_install:{companion}"
    assert key in result.snapshot.conflicting_resource_keys
    assert key not in result.snapshot.existing_resource_keys


@pytest.mark.parametrize(
    "failure",
    [
        "missing-etag",
        "duplicate-member",
        "malformed-condition",
        "unknown-binding-field",
        "forbidden",
    ],
)
def test_iam_discovery_failure_blocks_mutation_planning(failure: str) -> None:
    class InvalidIamTransport(FakeTransport):
        def request_json(self, method: str, url: str, *args, **kwargs):
            if url.endswith("secure-gateway-http-offload-tls:getIamPolicy"):
                if failure == "forbidden":
                    raise GoogleApiError(
                        status_code=403,
                        method=method,
                        host="secretmanager.googleapis.com",
                        detail="forbidden",
                    )
                if failure == "missing-etag":
                    return 200, {"version": 1, "bindings": []}
                malformed_binding: dict[str, object] = {
                    "role": "roles/viewer",
                    "members": ["user:owner@example.com"],
                }
                if failure == "duplicate-member":
                    malformed_binding["members"] = [
                        "user:owner@example.com",
                        "user:owner@example.com",
                    ]
                elif failure == "malformed-condition":
                    malformed_binding["condition"] = {
                        "title": "Unrelated",
                        "expression": "true",
                        "unknown": "must-not-round-trip",
                    }
                else:
                    malformed_binding["unknown"] = True
                return 200, {
                    "version": 3,
                    "etag": "fresh",
                    "bindings": [malformed_binding],
                }
            return super().request_json(method, url, *args, **kwargs)

    result = GoogleDiscoveryProvider(
        InvalidIamTransport(),
        cloud_identity="operator@example.com",
    ).preflight(deployment_spec())

    key = "secretmanager:secret_iam:secure-gateway-http-offload-tls-accessor"
    assert key in result.snapshot.conflicting_resource_keys
    assert key not in result.snapshot.existing_resource_keys


def test_profile_managed_only_access_level_is_compatible() -> None:
    provider = GoogleDiscoveryProvider(FakeTransport(), cloud_identity=None)
    payload = {
        "name": "accessPolicies/123456789/accessLevels/profile_managed",
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
        (
            "accesscontextmanager:access_level:"
            "accessPolicies/123456789/accessLevels/profile_managed"
        ),
        payload,
        deployment_spec(),
    )


def test_existing_subnet_requires_exact_identity_but_accepts_its_actual_cidr() -> None:
    provider = GoogleDiscoveryProvider(FakeTransport(), cloud_identity=None)
    spec = deployment_spec().model_copy(
        update={
            "network_strategy": NetworkStrategy.EXISTING,
            "vpc_name": "admin-vpc",
            "subnet_name": "admin-subnet",
            "subnet_cidr": "10.99.0.0/24",
        }
    )
    key = "compute:subnetwork:admin-subnet"
    exact = {
        "name": "admin-subnet",
        "network": (
            "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/"
            "global/networks/admin-vpc"
        ),
        # Existing-subnet CIDR is discovered, not supplied by the UI. It may
        # legitimately differ from the creation-only subnet_cidr default.
        "ipCidrRange": "10.98.0.0/24",
        "privateIpGoogleAccess": True,
        "stackType": "IPV4_ONLY",
        "selfLink": (
            "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/"
            "regions/asia-east1/subnetworks/admin-subnet"
        ),
    }

    assert provider._compatible(key, exact, spec)
    assert provider._compatible(key, {**exact, "ipCidrRange": "10.97.0.0/24"}, spec)
    second_plan = DesiredStatePlanner().build_plan(
        spec,
        DiscoverySnapshot(existing_resource_keys={key}),
    )
    subnet_change = next(
        change
        for change in second_plan.changes
        if f"{change.provider}:{change.resource_type}:{change.resource_name}" == key
    )
    assert subnet_change.action.value == "reuse"
    assert subnet_change.owned_after_apply is False
    assert not provider._compatible(key, {**exact, "name": "other-subnet"}, spec)
    assert not provider._compatible(
        key,
        {
            **exact,
            "selfLink": (
                "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/"
                "regions/other-region/subnetworks/admin-subnet"
            ),
        },
        spec,
    )
    assert not provider._compatible(
        key,
        {
            **exact,
            "network": (
                "https://compute.googleapis.com/compute/v1/projects/other/global/networks/admin-vpc"
            ),
        },
        spec,
    )


def test_dedicated_subnet_still_requires_the_approved_creation_cidr() -> None:
    spec = deployment_spec()
    key = "compute:subnetwork:secure-gateway-http-offload-subnet"
    exact = {
        "name": "secure-gateway-http-offload-subnet",
        "description": "Secure Gateway Studio ownership-token=d36ac6fb-91a8-4c82-8fb4-9dc576d4480d",
        "network": (
            "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/"
            "global/networks/secure-gateway-http-offload-vpc"
        ),
        "ipCidrRange": spec.subnet_cidr,
        "privateIpGoogleAccess": True,
        "stackType": "IPV4_ONLY",
        "selfLink": (
            "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/"
            "regions/asia-east1/subnetworks/secure-gateway-http-offload-subnet"
        ),
    }
    provider = GoogleDiscoveryProvider(
        FakeTransport(),
        cloud_identity=None,
        ownership_proofs={key: ownership_proof(str(exact["description"]))},
    )

    assert provider._compatible(key, exact, spec)
    assert not provider._compatible(key, {**exact, "ipCidrRange": "10.98.0.0/24"}, spec)


def test_managed_same_name_resource_requires_exact_active_marker_and_provider_identity() -> None:
    spec = deployment_spec()
    key = f"compute:network:{spec.name}-vpc"
    marker = owned_description("Managed by Secure Gateway Studio")
    payload = {
        "id": "network-immutable-123",
        "name": f"{spec.name}-vpc",
        "description": marker,
        "autoCreateSubnetworks": False,
        "routingConfig": {"routingMode": "REGIONAL"},
    }

    assert not GoogleDiscoveryProvider(
        FakeTransport(), cloud_identity=None
    )._compatible(key, payload, spec)
    assert GoogleDiscoveryProvider(
        FakeTransport(),
        cloud_identity=None,
        ownership_proofs={
            key: ownership_proof(
                marker,
                identity_field="id",
                identity="network-immutable-123",
            )
        },
    )._compatible(key, payload, spec)
    assert not GoogleDiscoveryProvider(
        FakeTransport(),
        cloud_identity=None,
        ownership_proofs={
            key: ownership_proof(
                owned_description("different-marker"),
                identity_field="id",
                identity="network-immutable-123",
            )
        },
    )._compatible(key, payload, spec)
    assert not GoogleDiscoveryProvider(
        FakeTransport(),
        cloud_identity=None,
        ownership_proofs={
            key: ownership_proof(
                marker,
                identity_field="id",
                identity="network-replacement-456",
            )
        },
    )._compatible(key, payload, spec)

    plan = DesiredStatePlanner().build_plan(
        spec,
        DiscoverySnapshot(existing_resource_keys={key}),
    )
    change = next(
        item
        for item in plan.changes
        if f"{item.provider}:{item.resource_type}:{item.resource_name}" == key
    )
    assert change.action.value == "no_change"
    assert change.owned_after_apply is False


def test_checkpoint_reducer_requires_provider_ids_when_available_but_keeps_no_id_types() -> None:
    service_account_key = "iam:service_account:secure-gateway-http-offload-offload"
    secret_key = "secretmanager:secret:secure-gateway-http-offload-tls"
    dns_record_key = "dns:record_set:demo-server-http.internal"
    generic_key = "compute:network:secure-gateway-http-offload-vpc"
    marker = owned_description()
    metadata = {
        service_account_key: {
            "kind": "named_resource_ownership",
            "phase": "applied",
            "resource_key": service_account_key,
            "resource_kind": "iam_service_account",
            "marker": marker,
        },
        secret_key: {
            "kind": "named_resource_ownership",
            "phase": "applied",
            "resource_key": secret_key,
            "resource_kind": "secretmanager_secret",
            "marker": TEST_OWNER,
        },
        dns_record_key: {
            "kind": "named_resource_ownership",
            "phase": "applied",
            "resource_key": dns_record_key,
            "resource_kind": "dns_record_set",
            "marker": f'"sgs-owner={TEST_OWNER}"',
        },
        generic_key: {
            "kind": "generic_created_resource",
            "phase": "applied",
            "resource_key": generic_key,
            "ownership_marker": marker,
        },
    }

    proofs = discovery_ownership_proofs(metadata)

    assert service_account_key not in proofs
    assert generic_key not in proofs
    assert proofs[secret_key].marker == TEST_OWNER
    assert proofs[dns_record_key].marker == f'"sgs-owner={TEST_OWNER}"'

    metadata[generic_key]["provider_identity_field"] = "selfLink"
    metadata[generic_key]["provider_identity"] = (
        "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/"
        "global/networks/secure-gateway-http-offload-vpc"
    )
    metadata["compute:network:unknown"] = {
        "kind": "named_resource_ownership",
        "phase": "applied",
        "resource_key": "compute:network:unknown",
        "resource_kind": "unrecognized_no_id_resource",
        "marker": marker,
    }
    proofs = discovery_ownership_proofs(metadata)
    assert generic_key not in proofs
    assert "compute:network:unknown" not in proofs

    metadata[service_account_key]["provider_identity"] = "123456789012345678901"
    metadata[generic_key]["provider_identity_field"] = "id"
    metadata[generic_key]["provider_identity"] = "network-immutable-123"
    proofs = discovery_ownership_proofs(metadata)
    assert proofs[service_account_key].provider_identity_field == "uniqueId"
    assert proofs[service_account_key].provider_identity == "123456789012345678901"
    assert proofs[generic_key].provider_identity_field == "id"


def test_beyondcorp_create_time_checkpoint_is_exact_second_preflight_proof() -> None:
    spec = deployment_spec()
    key = "beyondcorp:security_gateway:default"
    create_time = "2026-08-24T00:00:42Z"
    checkpoint = {
        key: {
            "kind": "generic_created_resource",
            "phase": "applied",
            "resource_key": key,
            "ownership_marker": None,
            "provider_identity_field": "createTime",
            "provider_identity": create_time,
        }
    }
    proofs = discovery_ownership_proofs(checkpoint)
    payload = {
        "name": (
            f"projects/{spec.project_id}/locations/global/"
            "securityGateways/default"
        ),
        "displayName": "default",
        "state": "RUNNING",
        "delegatingServiceAccount": "gateway@example.iam.gserviceaccount.com",
        "createTime": create_time,
        "serviceDiscovery": {},
        "logging": {},
    }

    assert proofs[key].provider_identity_field == "createTime"
    assert GoogleDiscoveryProvider(
        FakeTransport(),
        cloud_identity=None,
        ownership_proofs=proofs,
    )._compatible(key, payload, spec)
    assert not GoogleDiscoveryProvider(
        FakeTransport(),
        cloud_identity=None,
        ownership_proofs=proofs,
    )._compatible(
        key,
        {**payload, "createTime": "2026-08-25T00:00:42Z"},
        spec,
    )

    second_plan = DesiredStatePlanner().build_plan(
        spec,
        DiscoverySnapshot(existing_resource_keys={key}),
    )
    change = next(
        item
        for item in second_plan.changes
        if f"{item.provider}:{item.resource_type}:{item.resource_name}" == key
    )
    assert change.action.value == "reuse"
    assert change.owned_after_apply is False


def test_source_image_probe_rejects_wrong_project_self_link_and_obsolete_image() -> None:
    provider = GoogleDiscoveryProvider(FakeTransport(), cloud_identity=None)
    spec = deployment_spec()
    key = f"compute:source_image:{spec.source_image}"
    exact = {
        "id": "987654321",
        "name": "sgs-nginx-20260730",
        "selfLink": (
            "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/"
            "global/images/sgs-nginx-20260730"
        ),
    }

    assert provider._compatible(key, exact, spec)
    assert not provider._compatible(
        key,
        {
            **exact,
            "selfLink": (
                "https://compute.googleapis.com/compute/v1/projects/other-project/"
                "global/images/sgs-nginx-20260730"
            ),
        },
        spec,
    )
    assert not provider._compatible(
        key,
        {**exact, "deprecated": {"state": "OBSOLETE"}},
        spec,
    )


def test_live_instance_uses_output_disk_source_and_exact_immutable_image_id() -> None:
    spec = deployment_spec()
    resource_name = f"{spec.name}-offload"
    disk_path = f"projects/{spec.project_id}/zones/{spec.zone}/disks/{resource_name}"
    image_path = str(spec.source_image)

    class DiskTransport(FakeTransport):
        def __init__(self) -> None:
            self.source_image_id = "987654321"

        def request_json(self, method: str, url: str, **kwargs):
            if method == "GET" and url.endswith(f"/{disk_path}"):
                return 200, {
                    "name": resource_name,
                    "selfLink": f"https://www.googleapis.com/compute/v1/{disk_path}",
                    "zone": (
                        "https://www.googleapis.com/compute/v1/projects/"
                        f"{spec.project_id}/zones/{spec.zone}"
                    ),
                    "status": "READY",
                    "sizeGb": "20",
                    "type": (
                        "https://www.googleapis.com/compute/v1/projects/"
                        f"{spec.project_id}/zones/{spec.zone}/diskTypes/pd-balanced"
                    ),
                    "sourceImage": f"https://www.googleapis.com/compute/v1/{image_path}",
                    "sourceImageId": self.source_image_id,
                }
            if method == "GET" and url.endswith(f"/{spec.name}-backend-ip"):
                return 200, {"address": "10.42.0.20"}
            return super().request_json(method, url, **kwargs)

    transport = DiskTransport()
    instance_key = f"compute:instance:{resource_name}"
    provider = GoogleDiscoveryProvider(
        transport,
        cloud_identity=None,
        ownership_proofs={
            instance_key: ownership_proof(
                identity_field="id",
                identity="instance-123",
            )
        },
    )
    image_key = f"compute:source_image:{image_path}"
    assert provider._compatible(
        image_key,
        {
            "id": "987654321",
            "name": "sgs-nginx-20260730",
            "selfLink": f"https://www.googleapis.com/compute/v1/{image_path}",
        },
        spec,
    )
    startup = render_startup_script_for_discovery(
        transport,
        spec,
        role="offload",
    )
    instance = {
        "id": "instance-123",
        "name": resource_name,
        "description": owned_description(),
        "machineType": (
            "https://www.googleapis.com/compute/v1/projects/"
            f"{spec.project_id}/zones/{spec.zone}/machineTypes/e2-small"
        ),
        "labels": {"managed-by": "secure-gateway-studio", "role": "offload"},
        "tags": {"items": [f"{spec.name}-offload"], "fingerprint": "output-only"},
        "networkInterfaces": [
            {
                "network": (
                    "https://www.googleapis.com/compute/v1/projects/"
                    f"{spec.project_id}/global/networks/{spec.name}-vpc"
                ),
                "subnetwork": (
                    "https://www.googleapis.com/compute/v1/projects/"
                    f"{spec.project_id}/regions/{spec.region}/subnetworks/{spec.name}-subnet"
                ),
                "networkIP": "10.42.0.10",
                "stackType": "IPV4_ONLY",
            }
        ],
        "serviceAccounts": [
            {
                "email": (
                    service_account_email(spec.name, spec.project_id, "offload")
                ),
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            }
        ],
        # initializeParams is input-only and intentionally absent from instances.get.
        "disks": [
            {
                "boot": True,
                "autoDelete": True,
                "type": "PERSISTENT",
                "mode": "READ_WRITE",
                "source": f"https://www.googleapis.com/compute/v1/{disk_path}",
            }
        ],
        "metadata": {
            "items": [
                {"key": "enable-guest-attributes", "value": "TRUE"},
                {"key": "startup-script", "value": startup},
            ]
        },
        "shieldedInstanceConfig": {
            "enableSecureBoot": True,
            "enableVtpm": True,
            "enableIntegrityMonitoring": True,
        },
        "deletionProtection": False,
    }

    assert provider._compatible(instance_key, instance, spec)
    transport.source_image_id = "123456789"
    assert not provider._compatible(instance_key, instance, spec)


def test_beyondcorp_same_name_resources_require_exact_semantics_in_both_field_styles() -> None:
    spec = DeploymentSpec(
        **{
            **deployment_spec().model_dump(),
            "mode": "poc",
            "backend_kind": BackendKind.DIRECT_HTTPS,
            "network_strategy": NetworkStrategy.EXISTING,
            "vpc_name": "private-app-vpc",
            "subnet_name": None,
            "source_image": None,
            "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
            "ca_pool": None,
            "ca_name": None,
            "existing_backend_url": "https://app.corp.internal:8443",
            "existing_backend_location": BackendLocation.GCP,
            "existing_backend_connectivity_confirmed": True,
            "application_egress_region": "asia-east1",
        }
    )
    gateway_key = f"beyondcorp:security_gateway:{spec.gateway_id}"
    application_key = f"beyondcorp:application:{spec.name}-app"
    provider = GoogleDiscoveryProvider(
        FakeTransport(),
        cloud_identity=None,
        ownership_proofs={
            gateway_key: ownership_proof(
                marker=None,
                identity_field="createTime",
                identity="2026-08-24T00:00:01Z",
            ),
            application_key: ownership_proof(
                marker=None,
                identity_field="createTime",
                identity="2026-08-24T00:00:02Z",
            ),
        },
    )
    expected_network = f"projects/{spec.project_id}/global/networks/{spec.vpc_name}"
    gateway_base = {
        "name": (
            f"projects/{spec.project_id}/locations/global/securityGateways/"
            f"{spec.gateway_id}"
        ),
        "displayName": spec.gateway_id,
        "state": "RUNNING",
        "delegatingServiceAccount": "gateway@example.iam.gserviceaccount.com",
        "createTime": "2026-08-24T00:00:01Z",
        "externalIps": ["203.0.113.10"],
        "logging": {},
    }

    assert provider._compatible(
        gateway_key,
        {**gateway_base, "service_discovery": {}},
        spec,
    )
    assert provider._compatible(
        gateway_key,
        {**gateway_base, "serviceDiscovery": {}},
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {key: value for key, value in gateway_base.items() if key != "logging"}
        | {"serviceDiscovery": {}},
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {
            **gateway_base,
            "serviceDiscovery": {},
            "service_discovery": {},
        },
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {
            **gateway_base,
            "serviceDiscovery": {"apiGateway": {}},
        },
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {**gateway_base, "serviceDiscovery": "enabled"},
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {**gateway_base, "serviceDiscovery": {}, "logging": {"enabled": True}},
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {**gateway_base, "serviceDiscovery": {}, "proxyProtocolConfig": {}},
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {**gateway_base, "serviceDiscovery": {}, "hubs": ["projects/p/hubs/h"]},
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {**gateway_base, "serviceDiscovery": {}, "state": "ERROR"},
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {**gateway_base, "serviceDiscovery": {}, "name": "projects/wrong"},
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {**gateway_base, "serviceDiscovery": {}, "uid": "gateway-123"},
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {**gateway_base, "serviceDiscovery": {}, "externalIps": "203.0.113.10"},
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {**gateway_base, "serviceDiscovery": {}, "externalIps": ["not-an-ip"]},
        spec,
    )
    assert not provider._compatible(
        gateway_key,
        {
            **gateway_base,
            "serviceDiscovery": {},
            "externalIps": ["203.0.113.10", "203.0.113.10"],
        },
        spec,
    )
    snake_application = {
        "name": (
            f"projects/{spec.project_id}/locations/global/securityGateways/"
            f"{spec.gateway_id}/applications/{spec.name}-app"
        ),
        "displayName": f"{spec.name}-app",
        "createTime": "2026-08-24T00:00:02Z",
        "endpoint_matchers": [{"hostname": "app.corp.internal", "ports": [8443]}],
        "upstreams": [
            {
                "network": {"name": expected_network},
                "egress_policy": {"regions": ["asia-east1"]},
            }
        ],
    }
    assert provider._compatible(application_key, snake_application, spec)
    assert not provider._compatible(
        application_key,
        {
            **snake_application,
            "endpoint_matchers": [{"hostname": "other.corp.internal", "ports": [8443]}],
        },
        spec,
    )
    assert not provider._compatible(
        application_key,
        {
            **snake_application,
            "endpointMatchers": snake_application["endpoint_matchers"],
        },
        spec,
    )
    assert not provider._compatible(
        application_key,
        {
            **snake_application,
            "upstreams": [
                {
                    "network": {"name": expected_network},
                    "egress_policy": {"regions": ["asia-east1"]},
                    "proxyProtocol": "PROXY_PROTOCOL_V1",
                }
            ],
        },
        spec,
    )
    assert not provider._compatible(
        application_key,
        {
            **snake_application,
            "upstreams": [
                {
                    "network": {"name": expected_network},
                    "external": {"uri": "https://example.invalid"},
                    "egress_policy": {"regions": ["asia-east1"]},
                }
            ],
        },
        spec,
    )
    assert not provider._compatible(
        application_key,
        {
            **snake_application,
            "upstreams": [
                {
                    "network": {"name": expected_network, "unknown": True},
                    "egress_policy": {"regions": ["asia-east1"]},
                }
            ],
        },
        spec,
    )
    assert not provider._compatible(
        application_key,
        {**snake_application, "schema": "HTTP"},
        spec,
    )
    assert not provider._compatible(
        application_key,
        {**snake_application, "name": "projects/wrong/applications/wrong"},
        spec,
    )
    assert not provider._compatible(
        application_key,
        {**snake_application, "unknown": True},
        spec,
    )
    assert not provider._compatible(
        application_key,
        {
            **snake_application,
            "upstreams": [
                {
                    "network": {"name": expected_network},
                    "egressPolicy": {"regions": ["us-central1"]},
                }
            ],
        },
        spec,
    )


def test_application_same_createtime_with_proxy_protocol_drift_conflicts() -> None:
    spec = deployment_spec()
    application_key = f"beyondcorp:application:{spec.name}-app"
    create_time = "2026-08-24T00:00:00Z"

    class ProxyProtocolDriftTransport(FakeTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if url.endswith(f"/applications/{spec.name}-app"):
                return 200, {
                    "name": (
                        f"projects/{spec.project_id}/locations/global/securityGateways/"
                        f"{spec.gateway_id}/applications/{spec.name}-app"
                    ),
                    "displayName": f"{spec.name}-app",
                    "createTime": create_time,
                    "endpointMatchers": [
                        {
                            "hostname": spec.application_hostname,
                            "ports": [spec.application_port],
                        }
                    ],
                    "upstreams": [
                        {
                            "network": {
                                "name": (
                                    f"projects/{spec.upstream_project_id}/global/networks/"
                                    f"{spec.name}-vpc"
                                )
                            },
                            "proxyProtocol": "PROXY_PROTOCOL_V1",
                        }
                    ],
                }
            return super().request_json(method, url, **kwargs)

    result = GoogleDiscoveryProvider(
        ProxyProtocolDriftTransport(),
        cloud_identity="operator@example.com",
        ownership_proofs={
            application_key: ownership_proof(
                marker=None,
                identity_field="createTime",
                identity=create_time,
            )
        },
    ).preflight(spec)

    assert application_key in result.snapshot.conflicting_resource_keys
    assert application_key not in result.snapshot.existing_resource_keys


@pytest.mark.parametrize(
    "mutation",
    [
        {"proxyProtocolConfig": {}},
        {"hubs": ["projects/example/locations/global/hubs/admin"]},
        {"name": "projects/wrong/locations/global/securityGateways/default"},
        {"state": "ERROR"},
        {"uid": "gateway-123"},
        {"externalIps": "203.0.113.10"},
        {"externalIps": ["not-an-ip"]},
    ],
    ids=[
        "proxy-protocol",
        "hubs",
        "wrong-name",
        "error-state",
        "non-schema-uid",
        "external-ips-not-list",
        "external-ips-invalid-address",
    ],
)
def test_gateway_same_createtime_behavior_drift_conflicts(
    mutation: dict[str, object],
) -> None:
    spec = deployment_spec()
    gateway_key = f"beyondcorp:security_gateway:{spec.gateway_id}"
    create_time = "2026-08-24T00:00:00Z"
    payload: dict[str, object] = {
        "name": (
            f"projects/{spec.project_id}/locations/global/securityGateways/"
            f"{spec.gateway_id}"
        ),
        "displayName": spec.gateway_id,
        "state": "RUNNING",
        "delegatingServiceAccount": "gateway@example.iam.gserviceaccount.com",
        "createTime": create_time,
        "externalIps": ["203.0.113.10"],
        "serviceDiscovery": {},
        "logging": {},
        **mutation,
    }

    class GatewayDriftTransport(FakeTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if url.endswith(f"/securityGateways/{spec.gateway_id}"):
                return 200, payload
            return super().request_json(method, url, **kwargs)

    result = GoogleDiscoveryProvider(
        GatewayDriftTransport(),
        cloud_identity="operator@example.com",
        ownership_proofs={
            gateway_key: ownership_proof(
                marker=None,
                identity_field="createTime",
                identity=create_time,
            )
        },
    ).preflight(spec)

    assert gateway_key in result.snapshot.conflicting_resource_keys
    assert gateway_key not in result.snapshot.existing_resource_keys


def test_internal_https_lb_discovery_checks_certificate_and_routing_references() -> None:
    spec = deployment_spec().model_copy(update={"backend_kind": BackendKind.INTERNAL_HTTPS_LB})
    address_key = f"compute:internal_address:{spec.name}-offload-ip"
    certificate_key = f"compute:ssl_certificate:{spec.name}-ilb-cert"
    forwarding_key = f"compute:forwarding_rule:{spec.name}-ilb-fr"
    provider = GoogleDiscoveryProvider(
        FakeTransport(),
        cloud_identity=None,
        ownership_proofs={
            address_key: ownership_proof(identity_field="id", identity="address-123"),
            certificate_key: ownership_proof(
                owned_description(
                    "Managed by Secure Gateway Studio; certificate configuration "
                    f"{certificate_configuration_hash(spec)}"
                ),
                identity_field="id",
                identity="123456789",
            ),
            forwarding_key: ownership_proof(
                identity_field="id", identity="forwarding-123"
            ),
        },
    )
    bundle = CertificateIssuer().issue_local_poc(
        hostname=spec.private_hostname,
        lifetime_days=90,
    )
    provider._validated_tls_payload = bundle.secret_payload()
    certificate_description = (
        "Managed by Secure Gateway Studio; certificate configuration "
        f"{certificate_configuration_hash(spec)}"
    )
    certificate = {
        "id": "123456789",
        "name": f"{spec.name}-ilb-cert",
        "description": owned_description(certificate_description),
        "type": "SELF_MANAGED",
        "selfLink": (
            f"https://www.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"regions/{spec.region}/sslCertificates/{spec.name}-ilb-cert"
        ),
        "region": (
            f"https://www.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"regions/{spec.region}"
        ),
        "certificate": (
            bundle.certificate_pem + b"".join(bundle.certificate_chain_pem)
        ).decode("ascii"),
        "subjectAlternativeNames": [spec.private_hostname],
        "expireTime": bundle.not_after.replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
    }

    forwarding_rule = {
        "id": "forwarding-123",
        "name": f"{spec.name}-ilb-fr",
        "description": owned_description(),
        "IPAddress": "10.42.0.10",
        "IPProtocol": "TCP",
        "loadBalancingScheme": "INTERNAL_MANAGED",
        "allowGlobalAccess": True,
        "ports": ["443"],
        "network": (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"global/networks/{spec.name}-vpc"
        ),
        "subnetwork": (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"regions/{spec.region}/subnetworks/{spec.name}-subnet"
        ),
        "networkTier": "PREMIUM",
        "target": (
            f"projects/{spec.project_id}/regions/{spec.region}/"
            f"targetHttpsProxies/{spec.name}-ilb-proxy"
        ),
    }

    assert provider._compatible(
        address_key,
        {
            "id": "address-123",
            "name": f"{spec.name}-offload-ip",
            "description": owned_description(),
            "addressType": "INTERNAL",
            "address": "10.42.0.10",
            "subnetwork": (
                f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
                f"regions/{spec.region}/subnetworks/{spec.name}-subnet"
            ),
        },
        spec,
    )

    assert provider._compatible(
        certificate_key,
        certificate,
        spec,
    )
    assert not provider._compatible(
        certificate_key,
        {**certificate, "description": "Managed by another certificate configuration"},
        spec,
    )
    other_bundle = CertificateIssuer().issue_local_poc(
        hostname=spec.private_hostname,
        lifetime_days=90,
    )
    assert not provider._compatible(
        certificate_key,
        {
            **certificate,
            "certificate": (
                other_bundle.certificate_pem + b"".join(other_bundle.certificate_chain_pem)
            ).decode("ascii"),
        },
        spec,
    )
    assert provider._compatible(
        forwarding_key,
        forwarding_rule,
        spec,
    )
    assert not provider._compatible(
        forwarding_key,
        {
            **forwarding_rule,
            "target": "projects/example/regions/asia-east1/targetHttpsProxies/wrong",
        },
        spec,
    )
    assert not provider._compatible(
        forwarding_key,
        {**forwarding_rule, "IPAddress": "10.42.0.99"},
        spec,
    )


@pytest.mark.parametrize("membership", [[], ["wrong"], ["exact", "extra"], ["exact"]])
def test_internal_https_lb_instance_group_requires_exact_single_backend_member(
    membership: list[str],
) -> None:
    spec = deployment_spec().model_copy(update={"backend_kind": BackendKind.INTERNAL_HTTPS_LB})
    expected = (
        f"https://www.googleapis.com/compute/v1/projects/{spec.project_id}/"
        f"zones/{spec.zone}/instances/{spec.name}-backend"
    )

    class MembershipTransport(FakeTransport):
        def request_json(self, method: str, url: str, *args, **kwargs):
            if url.endswith("/listInstances"):
                values = [
                    expected if value == "exact" else expected.replace("-backend", "-wrong")
                    for value in membership
                ]
                return 200, {"items": [{"instance": value} for value in values]}
            return super().request_json(method, url, *args, **kwargs)

    key = f"compute:instance_group:{spec.name}-backend-ig"
    provider = GoogleDiscoveryProvider(
        MembershipTransport(),
        cloud_identity=None,
        ownership_proofs={
            key: ownership_proof(
                owned_description("Managed by Secure Gateway Studio"),
                identity_field="id",
                identity="group-123",
            )
        },
    )
    payload = {
        "id": "group-123",
        "description": owned_description("Managed by Secure Gateway Studio"),
        "network": (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"global/networks/{spec.name}-vpc"
        ),
        "subnetwork": (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"regions/{spec.region}/subnetworks/{spec.name}-subnet"
        ),
        "namedPorts": [{"name": "http", "port": 80}],
    }

    assert provider._compatible(
        key,
        payload,
        spec,
    ) is (membership == ["exact"])


@pytest.mark.parametrize("kind", ["ssl", "http"])
def test_health_check_discovery_accepts_only_documented_default_expansion(kind: str) -> None:
    spec = deployment_spec().model_copy(
        update={
            "backend_kind": (
                BackendKind.INTERNAL_HTTPS_LB
                if kind == "http"
                else BackendKind.EXISTING_HTTP
            )
        }
    )
    name = f"{spec.name}-{'ilb' if kind == 'http' else 'offload'}-hc"
    detail = (
        {
            "host": "",
            "port": 80,
            "portName": "",
            "portSpecification": "USE_SERVING_PORT",
            "proxyHeader": "NONE",
            "requestPath": "/",
            "response": "",
        }
        if kind == "http"
        else {
            "port": 443,
            "portName": "",
            "portSpecification": "USE_FIXED_PORT",
            "proxyHeader": "NONE",
            "request": "",
            "response": "",
        }
    )
    payload = {
        "id": "health-check-123",
        "name": name,
        "description": owned_description(),
        "type": kind.upper(),
        "checkIntervalSec": 10,
        "timeoutSec": 5,
        "healthyThreshold": 2,
        "unhealthyThreshold": 3,
        f"{kind}HealthCheck": detail,
    }
    key = f"compute:health_check:{name}"
    provider = GoogleDiscoveryProvider(
        FakeTransport(),
        cloud_identity=None,
        ownership_proofs={
            key: ownership_proof(
                identity_field="id",
                identity="health-check-123",
            )
        },
    )

    assert provider._compatible(key, payload, spec)
    assert not provider._compatible(
        key,
        {
            **payload,
            f"{kind}HealthCheck": {**detail, "proxyHeader": "PROXY_V1"},
        },
        spec,
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
                            "targetKey": deepcopy((json_body or {})["policyTargetKey"]),
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
        set(),
        diagnostics,
    )

    proxy_key = "chromepolicy:service_discovery_proxy:03-test-ou"
    assert proxy_key not in existing_keys
    diagnostic = next(item for item in diagnostics if item.code == "legacy-pac-policy-detected")
    assert "parent-ou" in diagnostic.message
    assert "legacy.pac" in diagnostic.message


class ExistingManagedCertificateTransport(FakeTransport):
    def __init__(self, *, lifetime_days: int = 90) -> None:
        self.payload = managed_secret_payload(
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
            spec = deployment_spec()
            return 200, {
                "name": ("projects/enterprise-secgw-01/secrets/secure-gateway-http-offload-tls"),
                "labels": {
                    "managed-by": "secure-gateway-studio",
                    "configuration-hash": canonical_configuration_hash(spec)[:32],
                    "certificate-spec-hash": certificate_configuration_hash(spec)[:32],
                    "sgs-owner-token": TEST_OWNER,
                },
                "replication": {"automatic": {}},
                "versionAliases": {"active": "1"},
            }
        if "/secrets/secure-gateway-http-offload-tls/versions/" in url and (
            url.endswith(":access")
        ):
            return 200, {
                "name": (
                    "projects/enterprise-secgw-01/secrets/"
                    "secure-gateway-http-offload-tls/versions/1"
                ),
                "payload": {
                    "data": base64.b64encode(self.payload).decode("ascii"),
                    "dataCrc32c": str(GoogleDiscoveryProvider._crc32c(self.payload)),
                },
            }
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


class PublicCertificateTransport(FakeTransport):
    def __init__(
        self,
        *,
        corrupt_crc: bool = False,
        include_crc: bool = True,
        version_name: str | None = (
            "projects/enterprise-secgw-01/secrets/operator-public-tls/versions/7"
        ),
    ) -> None:
        self.payload = (
            CertificateIssuer()
            .issue_local_poc(
                hostname="demo-server-http.internal",
                lifetime_days=90,
            )
            .secret_payload()
        )
        self.corrupt_crc = corrupt_crc
        self.include_crc = include_crc
        self.version_name = version_name

    def request_json(
        self,
        method: str,
        url: str,
        *args,
        **kwargs,
    ) -> tuple[int, dict[str, Any]]:
        if url.endswith("/secrets/operator-public-tls"):
            return 200, {"name": "projects/enterprise-secgw-01/secrets/operator-public-tls"}
        if url.endswith("/secrets/operator-public-tls/versions/latest:access"):
            crc = GoogleDiscoveryProvider._crc32c(self.payload)
            payload: dict[str, Any] = {"data": base64.b64encode(self.payload).decode("ascii")}
            if self.include_crc:
                payload["dataCrc32c"] = str(crc + 1 if self.corrupt_crc else crc)
            envelope: dict[str, Any] = {"payload": payload}
            if self.version_name is not None:
                envelope["name"] = self.version_name
            return 200, envelope
        return super().request_json(method, url, *args, **kwargs)


def public_certificate_spec() -> DeploymentSpec:
    return deployment_spec().model_copy(
        update={
            "mode": DeploymentMode.POC,
            "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
            "public_certificate_secret": (
                "projects/enterprise-secgw-01/secrets/operator-public-tls"
            ),
            "ca_pool": None,
            "ca_name": None,
        }
    )


def test_public_certificate_secret_is_existing_only_after_crc_and_pki_validation() -> None:
    transport = PublicCertificateTransport()
    provider = GoogleDiscoveryProvider(
        transport,
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(public_certificate_spec())

    key = "secretmanager:secret:operator-public-tls"
    assert key in result.snapshot.existing_resource_keys
    assert key not in result.snapshot.conflicting_resource_keys
    assert result.snapshot.public_certificate_binding is not None
    assert result.snapshot.public_certificate_binding.secret_version_name.endswith("/versions/7")
    assert (
        result.snapshot.public_certificate_binding.payload_sha256
        == hashlib.sha256(transport.payload).hexdigest()
    )


@pytest.mark.parametrize(
    ("transport", "remediation"),
    [
        (PublicCertificateTransport(corrupt_crc=True), "CRC32C"),
        (PublicCertificateTransport(include_crc=False), "dataCrc32c"),
    ],
)
def test_public_certificate_secret_fails_closed_on_missing_or_bad_crc(
    transport: PublicCertificateTransport,
    remediation: str,
) -> None:
    provider = GoogleDiscoveryProvider(
        transport,
        cloud_identity="operator@example.com",
    )

    result = provider.preflight(public_certificate_spec())

    key = "secretmanager:secret:operator-public-tls"
    assert key not in result.snapshot.existing_resource_keys
    assert key in result.snapshot.conflicting_resource_keys
    diagnostic = next(
        item for item in result.diagnostics if item.code == "invalid-public-certificate-secret"
    )
    assert remediation in (diagnostic.remediation or "")


@pytest.mark.parametrize(
    "version_name",
    [
        None,
        "projects/enterprise-secgw-01/secrets/operator-public-tls/versions/latest",
        "projects/enterprise-secgw-01/secrets/other-public-tls/versions/7",
    ],
    ids=["missing", "alias", "wrong-secret"],
)
def test_public_certificate_discovery_requires_exact_numeric_version_name(
    version_name: str | None,
) -> None:
    result = GoogleDiscoveryProvider(
        PublicCertificateTransport(version_name=version_name),
        cloud_identity="operator@example.com",
    ).preflight(public_certificate_spec())

    key = "secretmanager:secret:operator-public-tls"
    assert key in result.snapshot.conflicting_resource_keys
    assert result.snapshot.public_certificate_binding is None


def test_existing_valid_managed_certificate_version_is_reused() -> None:
    provider = GoogleDiscoveryProvider(
        ExistingManagedCertificateTransport(),
        cloud_identity="operator@example.com",
        ownership_proofs=managed_certificate_ownership_proofs(),
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
        ownership_proofs=managed_certificate_ownership_proofs(),
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
            payload["versionAliases"] = {}
        return status_code, payload


def test_existing_managed_secret_without_active_alias_plans_safe_migration() -> None:
    provider = GoogleDiscoveryProvider(
        MissingActiveAliasTransport(),
        cloud_identity="operator@example.com",
        ownership_proofs=managed_certificate_ownership_proofs(),
    )

    result = provider.preflight(deployment_spec())

    version_key = "secretmanager:secret_version:secure-gateway-http-offload-tls"
    assert version_key not in result.snapshot.existing_resource_keys
    assert any(
        diagnostic.code == "managed-certificate-alias-migration-required"
        for diagnostic in result.diagnostics
    )


class ConvergedPocTransport(FakeTransport):
    def __init__(self, poc_spec: DeploymentSpec, payload: bytes) -> None:
        self.spec = poc_spec
        self.payload = managed_secret_payload(payload)

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
            return 200, {"services": [{"config": {"name": name}} for name in sorted(REQUIRED_APIS)]}
        if url.endswith("/secrets/secure-gateway-http-offload-tls"):
            return 200, {
                "name": ("projects/enterprise-secgw-01/secrets/secure-gateway-http-offload-tls"),
                "labels": {
                    "managed-by": "secure-gateway-studio",
                    "configuration-hash": canonical_configuration_hash(self.spec)[:32],
                    "certificate-spec-hash": certificate_configuration_hash(self.spec)[:32],
                    "sgs-owner-token": TEST_OWNER,
                },
                "replication": {"automatic": {}},
                "versionAliases": {"active": "1"},
            }
        if url.endswith("/secrets/secure-gateway-http-offload-tls/versions/1:access"):
            return 200, {
                "name": (
                    "projects/enterprise-secgw-01/secrets/"
                    "secure-gateway-http-offload-tls/versions/1"
                ),
                "payload": {
                    "data": base64.b64encode(self.payload).decode("ascii"),
                    "dataCrc32c": str(GoogleDiscoveryProvider._crc32c(self.payload)),
                },
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
        ConvergedPocTransport(poc_spec, bundle.secret_payload()),
        cloud_identity="operator@example.com",
        artifact_store=artifact_store,
        ownership_proofs=managed_certificate_ownership_proofs(),
    )

    result = provider.preflight(poc_spec)

    assert "serviceusage:project_services:required-apis" in (result.snapshot.existing_resource_keys)
    assert "secretmanager:secret_version:secure-gateway-http-offload-tls" in (
        result.snapshot.existing_resource_keys
    )
    assert "local:root_certificate_artifact:secure-gateway-http-offload-poc-root" in (
        result.snapshot.existing_resource_keys
    )


def test_local_poc_root_artifact_must_match_the_active_numeric_version(tmp_path) -> None:
    poc_spec = deployment_spec().model_copy(
        update={
            "mode": DeploymentMode.POC,
            "certificate_strategy": CertificateStrategy.LOCAL_POC,
        }
    )
    active = CertificateIssuer().issue_local_poc(
        hostname=poc_spec.private_hostname,
        lifetime_days=30,
    )
    unrelated = CertificateIssuer().issue_local_poc(
        hostname=poc_spec.private_hostname,
        lifetime_days=30,
    )
    artifact_store = CertificateArtifactStore(tmp_path)
    artifact_store.write_root_certificate(
        poc_spec.name,
        unrelated.certificate_chain_pem[0],
    )
    result = GoogleDiscoveryProvider(
        ConvergedPocTransport(poc_spec, active.secret_payload()),
        cloud_identity="operator@example.com",
        artifact_store=artifact_store,
        ownership_proofs=managed_certificate_ownership_proofs(),
    ).preflight(poc_spec)

    version_key = "secretmanager:secret_version:secure-gateway-http-offload-tls"
    artifact_key = "local:root_certificate_artifact:secure-gateway-http-offload-poc-root"
    assert version_key not in result.snapshot.existing_resource_keys
    assert artifact_key not in result.snapshot.existing_resource_keys
    assert {version_key, artifact_key} <= result.snapshot.conflicting_resource_keys


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
            "principals": [AccessPrincipal(type=PrincipalType.USER, value="operator@example.com")],
        }
    )
    artifact_store = CertificateArtifactStore(tmp_path)
    bundle = CertificateIssuer().issue_local_poc(
        hostname=original_spec.private_hostname,
        lifetime_days=30,
    )
    transport = ConvergedPocTransport(original_spec, bundle.secret_payload())
    artifact_store.write_root_certificate(
        original_spec.name,
        bundle.certificate_chain_pem[0],
    )
    provider = GoogleDiscoveryProvider(
        transport,
        cloud_identity="operator@example.com",
        artifact_store=artifact_store,
        ownership_proofs=managed_certificate_ownership_proofs(),
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
        ConvergedPocTransport(original_spec, bundle.secret_payload()),
        cloud_identity="operator@example.com",
        artifact_store=artifact_store,
        ownership_proofs=managed_certificate_ownership_proofs(),
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
        "version": 3,
        "etag": "fresh",
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
    def preflight(
        self,
        spec: DeploymentSpec,
        *,
        ownership_proofs=None,
    ) -> PreflightResult:
        assert ownership_proofs == {}
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
    app.dependency_overrides[trusted_connection_validator] = lambda: FakeConnectionValidator()
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
        app.dependency_overrides.pop(trusted_connection_validator, None)

    assert response.status_code == 200
    assert response.json()["read_only"] is True
    assert response.json()["snapshot"]["cloud_identity"] == "adc:enterprise-secgw-01"


def test_preflight_api_passes_repository_active_checkpoint_proof_to_discovery() -> None:
    key = "compute:network:secure-gateway-http-offload-vpc"
    marker = owned_description("Managed by Secure Gateway Studio")
    captured: list[dict[str, DiscoveryOwnershipProof]] = []

    class OwnershipRepository:
        @staticmethod
        def active_discovery_ownership_metadata(_specification: DeploymentSpec):
            return {
                key: {
                    "kind": "generic_created_resource",
                    "phase": "applied",
                    "resource_key": key,
                    "ownership_marker": marker,
                    "provider_identity_field": "id",
                    "provider_identity": "network-immutable-123",
                }
            }

    class CapturingDiscoveryProvider:
        @staticmethod
        def preflight(
            spec: DeploymentSpec,
            *,
            ownership_proofs=None,
        ) -> PreflightResult:
            captured.append(dict(ownership_proofs or {}))
            return PreflightResult(
                snapshot=DiscoverySnapshot(cloud_identity=f"adc:{spec.project_id}")
            )

    app.dependency_overrides[repository] = OwnershipRepository
    app.dependency_overrides[discovery_provider] = CapturingDiscoveryProvider
    app.dependency_overrides[trusted_connection_validator] = FakeConnectionValidator
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
        app.dependency_overrides.pop(repository, None)
        app.dependency_overrides.pop(discovery_provider, None)
        app.dependency_overrides.pop(trusted_connection_validator, None)

    assert response.status_code == 200
    assert captured == [
        {
            key: DiscoveryOwnershipProof(
                marker=marker,
                provider_identity_field="id",
                provider_identity="network-immutable-123",
            )
        }
    ]


def test_create_plan_api_passes_same_repository_ownership_context() -> None:
    key = "compute:network:secure-gateway-http-offload-vpc"
    marker = owned_description("Managed by Secure Gateway Studio")
    captured: list[dict[str, DiscoveryOwnershipProof]] = []
    stored: list[object] = []

    class PlanRepository:
        @staticmethod
        def active_discovery_ownership_metadata(_specification: DeploymentSpec):
            return {
                key: {
                    "kind": "generic_created_resource",
                    "phase": "applied",
                    "resource_key": key,
                    "ownership_marker": marker,
                    "provider_identity_field": "id",
                    "provider_identity": "network-immutable-123",
                }
            }

        @staticmethod
        def store_prepared_plan(specification, preflight, plan):
            stored.extend([specification, preflight, plan])
            return plan

    class CapturingDiscoveryProvider:
        @staticmethod
        def preflight(
            spec: DeploymentSpec,
            *,
            ownership_proofs=None,
        ) -> PreflightResult:
            captured.append(dict(ownership_proofs or {}))
            return PreflightResult(
                snapshot=DiscoverySnapshot(cloud_identity=f"adc:{spec.project_id}")
            )

    result = create_plan(
        PlanRequest(specification=deployment_spec()),
        CapturingDiscoveryProvider(),
        FakeConnectionValidator(),
        PlanRepository(),
    )

    assert result is stored[-1]
    assert captured[0][key] == DiscoveryOwnershipProof(
        marker=marker,
        provider_identity_field="id",
        provider_identity="network-immutable-123",
    )
