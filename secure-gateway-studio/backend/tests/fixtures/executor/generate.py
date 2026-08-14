"""Regenerate the cross-language executor golden set.

Run from the repository root:

    python secure-gateway-studio/backend/tests/fixtures/executor/generate.py

`google_executor.py` is the largest module being ported, and what it produces
is a sequence of HTTP requests. Correctness therefore means: for a given change
and specification, the extension issues the same requests, in the same order,
with the same bodies. That is what this file pins.

The recorded requests are the whole contract. A reordered IAM read/write, a
missing egress policy, or a wrong project in the upstream network path is a
deployment that behaves differently, and none of those would be caught by
comparing plans alone.

Only the Path B resource types are recorded. Path A is Phase 4.
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_BACKEND = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_BACKEND / "src"))

from sgstudio.domain.models import (  # noqa: E402
    AccessPrincipal,
    BackendKind,
    BackendLocation,
    CertificateStrategy,
    ChangeAction,
    DeploymentSpec,
    NetworkStrategy,
    PrincipalType,
    ResourceChange,
    RiskLevel,
)
from sgstudio.domain.planner import canonical_configuration_hash  # noqa: E402
from sgstudio.providers.certificates import CertificateBundle  # noqa: E402
from sgstudio.providers.google_executor import GoogleResourceExecutor  # noqa: E402


class RecordingTransport:
    """Records every request and returns the minimum the executor needs.

    Deliberately not a network client: the golden set describes what the
    executor *asks for*, which is exactly the part the port must reproduce.
    """

    def __init__(self, configuration_hash: str = "") -> None:
        self.calls: list[dict[str, Any]] = []
        self._configuration_hash = configuration_hash

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        del accepted_statuses
        self.calls.append(
            {"method": method, "url": url, "params": params, "body": json_body}
        )

        if method == "GET" and url.endswith("/getGuestAttributes"):
            # The offload VM writes its own T01-T03 self-test results into guest
            # attributes; Apply reads them back rather than trusting the boot.
            evidence = self._configuration_hash
            return 200, {
                "queryValue": {
                    "items": [
                        {
                            "namespace": "sgstudio",
                            "key": "T01",
                            "value": f'{{"status":200,"configuration_hash":"{evidence}"}}',
                        },
                        {
                            "namespace": "sgstudio",
                            "key": "T02",
                            "value": f'{{"status":200,"configuration_hash":"{evidence}"}}',
                        },
                        {
                            "namespace": "sgstudio",
                            "key": "T03",
                            "value": (
                                '{"http_status":200,"tls_version":"TLSv1.3",'
                                '"hostname":"demo-server-http.internal",'
                                '"subject_alt_names":["demo-server-http.internal"],'
                                f'"configuration_hash":"{evidence}"}}'
                            ),
                        },
                    ]
                }
            }
        if method == "POST" and url.endswith(":addVersion"):
            return 200, {
                "name": (
                    "projects/enterprise-secgw-01/secrets/"
                    "secure-gateway-http-offload-tls/versions/1"
                )
            }
        if method == "GET" and "/instanceGroupManagers/" in url:
            # Stable, with the configured baseline of replicas running, so the
            # create path completes rather than polling to its deadline.
            return 200, {
                "status": {"isStable": True, "currentInstanceStatuses": {"running": 2}},
                "targetSize": 2,
            }
        if url.endswith("/getHealth"):
            return 200, {
                "healthStatus": [
                    {"healthState": "HEALTHY"},
                    {"healthState": "HEALTHY"},
                ]
            }
        if "/addresses/" in url and method == "GET":
            # The offload VM and the DNS record both need the reserved internal
            # address that was allocated earlier in the run.
            suffix = "20" if "-backend-ip" in url else "10"
            return 200, {"address": f"10.42.0.{suffix}"}
        if method == "GET" and "/secrets/" in url and not url.endswith(":getIamPolicy"):
            # A freshly created secret has no aliases or labels yet.
            return 200, {"etag": "secret-etag", "versionAliases": {}, "labels": {}}
        if url.endswith(":getIamPolicy"):
            return 200, {
                "version": 1,
                "etag": "before-etag",
                "bindings": [
                    {"role": "roles/viewer", "members": ["user:owner@example.com"]}
                ],
            }
        if method == "GET" and "/securityGateways/" in url and "/applications" not in url:
            return 200, {
                "name": (
                    "projects/enterprise-secgw-01/locations/global/securityGateways/default"
                ),
                "delegatingServiceAccount": (
                    "sg-delegate@enterprise-secgw-01.iam.gserviceaccount.com"
                ),
            }
        if "/policySchemas/" in url:
            # The executor discovers the Chrome Policy schema at runtime rather
            # than assuming it, so each policy needs its own field advertised.
            schema_name = url.rsplit("/", maxsplit=1)[-1]
            if schema_name.endswith("SimpleProxySettings"):
                field_name = "simpleProxyMode"
                target_keys: list[dict[str, str]] = []
            elif schema_name.endswith("ManagedConfiguration"):
                field_name = "managedConfiguration"
                target_keys = [{"key": "app_id"}]
            else:
                field_name = "appInstallType"
                target_keys = [{"key": "app_id"}]
            return 200, {
                "schemaName": schema_name,
                "additionalTargetKeyNames": target_keys,
                "definition": {
                    "messageType": [{"name": "Policy", "field": [{"name": field_name}]}]
                },
            }
        if url.endswith("/policies:resolve"):
            return 200, {"resolvedPolicies": []}
        if method in {"POST", "PATCH", "DELETE"}:
            if "compute.googleapis.com" in url:
                return 200, {"status": "DONE"}
            return 200, {"done": True}
        if "/operations/" in url:
            # Long-running operations are polled until done. Without a terminal
            # status the executor spins until its deadline.
            return 200, {"status": "DONE", "done": True}
        return 200, {}


def _spec(**overrides: Any) -> DeploymentSpec:
    values: dict[str, Any] = {
        "project_id": "enterprise-secgw-01",
        "mode": "poc",
        "target_ou_id": "03-test-ou",
        "managed_chrome_access_level": (
            "accessPolicies/123456789/accessLevels/managed_chrome"
        ),
        "test_ou_confirmed": True,
        "principals": [
            AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")
        ],
        "backend_kind": BackendKind.DIRECT_HTTPS,
        "network_strategy": NetworkStrategy.EXISTING,
        "vpc_name": "private-app-vpc",
        "subnet_name": None,
        "source_image": None,
        "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
        "existing_backend_url": "https://10.20.0.10:8443",
        "existing_backend_location": BackendLocation.GCP,
        "existing_backend_connectivity_confirmed": True,
    }
    values.update(overrides)
    return DeploymentSpec(**values)


def _change(provider: str, resource_type: str, name: str) -> ResourceChange:
    return ResourceChange(
        provider=provider,
        resource_type=resource_type,
        resource_name=name,
        action=ChangeAction.CREATE,
        risk=RiskLevel.HIGH,
        summary="fixture",
        owned_after_apply=True,
        dependencies=[],
    )


def _path_a_spec(**overrides: Any) -> DeploymentSpec:
    values: dict[str, Any] = {
        "project_id": "enterprise-secgw-01",
        "mode": "poc",
        "target_ou_id": "03-test-ou",
        "managed_chrome_access_level": (
            "accessPolicies/123456789/accessLevels/managed_chrome"
        ),
        "test_ou_confirmed": True,
        "principals": [
            AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")
        ],
        "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
        "public_certificate_secret": (
            "projects/enterprise-secgw-01/secrets/enterprise-tls"
        ),
        "source_image": None,
    }
    values.update(overrides)
    return DeploymentSpec(**values)


_FIXED_EXECUTION_ID = uuid.UUID("00000000-0000-4000-8000-000000000000")

PREFIX = "secure-gateway-http-offload"

# Every Path B resource type that performs a mutation, in plan order.
CHANGES: list[tuple[str, str, str]] = [
    ("serviceusage", "project_services", "required-apis"),
    ("beyondcorp", "security_gateway", "default"),
    ("beyondcorp", "gateway_iam", "default-service-discovery-users"),
    ("cloudresourcemanager", "project_iam", f"{PREFIX}-upstream-access"),
    ("beyondcorp", "application", f"{PREFIX}-app"),
    ("beyondcorp", "application_iam", f"{PREFIX}-app-access"),
    ("chromepolicy", "extension_install", "ekajlcmdfcigmdbphhifahdfjbkciflj"),
    ("chromepolicy", "extension_install", "callobklhcbilhphinckomhgkigmfocg"),
    ("chromepolicy", "extension_configuration", "ekajlcmdfcigmdbphhifahdfjbkciflj"),
    ("chromepolicy", "service_discovery_proxy", "03-test-ou"),
]

# Path A resource types that perform a mutation, in plan order. The
# certificate-issuing types are excluded: they depend on WebCrypto in the
# extension and are captured separately once that lands.
PATH_A_CHANGES: list[tuple[str, str, str]] = [
    ("serviceusage", "project_services", "required-apis"),
    ("compute", "network", f"{PREFIX}-vpc"),
    ("compute", "subnetwork", f"{PREFIX}-subnet"),
    ("compute", "router", f"{PREFIX}-router"),
    ("compute", "cloud_nat", f"{PREFIX}-nat"),
    ("iam", "service_account", "secure-gateway-http-offload-offload"),
    ("compute", "internal_address", f"{PREFIX}-offload-ip"),
    ("secretmanager", "secret_iam", f"{PREFIX}-tls-accessor"),
    ("compute", "instance", f"{PREFIX}-offload"),
    ("compute", "firewall_rule", f"{PREFIX}-gateway-ingress"),
    ("dns", "private_zone", f"{PREFIX}-zone"),
    ("dns", "record_set", "demo-server-http.internal"),
]

# A fixed certificate bundle. Issuance generates a fresh RSA key each run, so
# recording a real one would make this file differ on every regeneration.
_PINNED_CERTIFICATE = CertificateBundle(
    certificate_pem=b"-----BEGIN CERTIFICATE-----\nUElOTkVE\n-----END CERTIFICATE-----\n",
    certificate_chain_pem=(
        b"-----BEGIN CERTIFICATE-----\nQ0hBSU4=\n-----END CERTIFICATE-----\n",
    ),
    private_key_pem=b"-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n",
    fingerprint_sha256="ab" * 32,
    not_after=datetime(2026, 4, 1, tzinfo=UTC),
    hostname="demo-server-http.internal",
    issuer_resource_name=(
        "projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise"
        "/certificates/pinned"
    ),
)


def _production_spec(**overrides):
    values = {
        "project_id": "enterprise-secgw-01",
        "mode": "production",
        "target_ou_id": "03-test-ou",
        "managed_chrome_access_level": (
            "accessPolicies/123456789/accessLevels/managed_chrome"
        ),
        "test_ou_confirmed": True,
        "chrome_enterprise_premium_license_confirmed": True,
        "workspace_services_confirmed": True,
        "endpoint_verification_confirmed": True,
        "principals": [
            AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")
        ],
        "certificate_strategy": CertificateStrategy.ENTERPRISE_CA,
        "ca_pool": (
            "projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise"
        ),
        "ca_name": (
            "projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise"
            "/certificateAuthorities/issuing"
        ),
        "source_image": (
            "projects/enterprise-secgw-01/global/images/sgs-nginx-20260730"
        ),
    }
    values.update(overrides)
    return DeploymentSpec(**values)


# The Production offload tier plus the certificate-issuing resources.
PRODUCTION_CHANGES: list[tuple[str, str, str]] = [
    ("secretmanager", "secret", f"{PREFIX}-tls"),
    ("secretmanager", "secret_version", f"{PREFIX}-tls"),
    ("compute", "instance_template", f"{PREFIX}-offload-template"),
    ("compute", "health_check", f"{PREFIX}-offload-hc"),
    ("compute", "instance_group_manager", f"{PREFIX}-offload-mig"),
    ("compute", "autoscaler", f"{PREFIX}-offload-autoscaler"),
    ("compute", "backend_service", f"{PREFIX}-offload-bs"),
    ("compute", "forwarding_rule", f"{PREFIX}-offload-fr"),
]


SCENARIOS: list[tuple[str, DeploymentSpec]] = [
    ("path-b-single-project", _spec()),
    ("path-b-egress-region", _spec(application_egress_region="asia-east1")),
    (
        "path-b-cross-project-upstream",
        _spec(upstream_vpc_project_id="shared-network-prj"),
    ),
    (
        "path-b-fqdn-matcher",
        _spec(existing_backend_url="https://app.corp.internal:8443"),
    ),
]


PATH_A_SCENARIOS: list[tuple[str, DeploymentSpec]] = [
    ("path-a-poc-dedicated-vpc", _path_a_spec()),
]

PRODUCTION_SCENARIOS: list[tuple[str, DeploymentSpec]] = [
    ("path-a-production-managed-group", _production_spec()),
]


def build() -> dict[str, Any]:
    scenarios = []
    for name, spec in [*SCENARIOS, *PATH_A_SCENARIOS, *PRODUCTION_SCENARIOS]:
        if spec.backend_kind is BackendKind.DIRECT_HTTPS:
            changes = CHANGES
        elif spec.mode.value == "production":
            changes = PRODUCTION_CHANGES
        else:
            changes = PATH_A_CHANGES
        recorded = []
        for provider, resource_type, resource_name in changes:
            transport = RecordingTransport(canonical_configuration_hash(spec))
            # A short deadline: with no sleep between polls, a long one would
            # busy-spin for minutes if a fixture ever stopped reaching DONE.
            executor = GoogleResourceExecutor(
                transport, poll_interval_seconds=0, operation_timeout_seconds=5
            )
            # `requestId` is uuid5(execution_id, change_key) and execution_id is
            # a fresh uuid4 per executor. Pinning it here keeps this file stable
            # across regenerations; the parity check treats the value as opaque
            # because the two implementations derive it differently by design.
            executor._execution_id = _FIXED_EXECUTION_ID
            # Issuance generates a fresh key per run; pin the bundle so
            # the recorded secret payload is stable.
            executor._certificate = _PINNED_CERTIFICATE
            change = _change(provider, resource_type, resource_name)
            executor.apply(change, spec)
            recorded.append(
                {
                    "change": {
                        "provider": provider,
                        "resource_type": resource_type,
                        "resource_name": resource_name,
                    },
                    "requests": transport.calls,
                }
            )
        scenarios.append(
            {
                "name": name,
                "spec": {
                    **spec.model_dump(mode="json", exclude_none=True),
                    "platforms": sorted(spec.model_dump(mode="json")["platforms"]),
                },
                "operations": recorded,
            }
        )
    return {
        "note": (
            "Generated by generate.py from GoogleResourceExecutor against a recording "
            "transport. Verified by backend/tests/test_executor_golden.py and the "
            "extension executor test. Do not hand-edit."
        ),
        "scenarios": scenarios,
    }


def main() -> None:
    target = Path(__file__).with_name("golden.json")
    document = build()
    target.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    total = sum(
        len(operation["requests"])
        for scenario in document["scenarios"]  # type: ignore[union-attr]
        for operation in scenario["operations"]
    )
    print(
        f"wrote {len(document['scenarios'])} scenarios "  # type: ignore[arg-type]
        f"and {total} recorded requests to {target.name}"
    )


if __name__ == "__main__":
    main()
