from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import uuid
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sgstudio.domain.execution import ProviderExecutionError
from sgstudio.domain.models import (
    AccessPrincipal,
    BackendKind,
    BackendLocation,
    CertificateStrategy,
    ChangeAction,
    ChromePlatform,
    DeploymentMode,
    DeploymentSpec,
    DiscoverySnapshot,
    NetworkStrategy,
    OperationStatus,
    PrincipalType,
    PublicCertificateBinding,
    ResourceChange,
    RiskLevel,
    RunOperation,
    SourceImageBinding,
)
from sgstudio.domain.planner import (
    DesiredStatePlanner,
    canonical_configuration_hash,
    certificate_configuration_hash,
)
from sgstudio.providers.certificates import CertificateBundle, CertificateIssuer
from sgstudio.providers.google_executor import GoogleResourceExecutor
from sgstudio.providers.google_rest import GoogleApiError
from sgstudio.providers.local_artifacts import CertificateArtifactStore


def spec() -> DeploymentSpec:
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


def local_poc_spec() -> DeploymentSpec:
    return DeploymentSpec(
        project_id="enterprise-secgw-01",
        mode=DeploymentMode.POC,
        platforms=set(ChromePlatform),
        certificate_strategy=CertificateStrategy.LOCAL_POC,
        source_image="projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
        target_ou_id="03-test-ou",
        test_ou_confirmed=True,
        principals=[AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")],
    )


def internal_https_lb_spec() -> DeploymentSpec:
    return DeploymentSpec(
        project_id="enterprise-secgw-01",
        mode=DeploymentMode.POC,
        platforms=set(ChromePlatform),
        backend_kind=BackendKind.INTERNAL_HTTPS_LB,
        certificate_strategy=CertificateStrategy.LOCAL_POC,
        source_image="projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
        proxy_subnet_cidr="10.42.1.0/24",
        target_ou_id="03-test-ou",
        test_ou_confirmed=True,
        principals=[
            AccessPrincipal(
                type=PrincipalType.GROUP,
                value="secure-access@example.com",
            )
        ],
    )


def change(provider: str, resource_type: str, name: str) -> ResourceChange:
    return ResourceChange(
        provider=provider,
        resource_type=resource_type,
        resource_name=name,
        action=ChangeAction.CREATE,
        risk=RiskLevel.MEDIUM,
        summary="test",
        owned_after_apply=True,
    )


def test_destroy_deletes_recorded_application_and_skips_nonempty_gateway() -> None:
    class NonEmptyGatewayTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/applications"):
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                return 200, {
                    "applications": [
                        {
                            "name": (
                                "projects/enterprise-secgw-01/locations/global/"
                                "securityGateways/default/applications/remaining"
                            )
                        }
                    ]
                }
            return super().request_json(method, url, **kwargs)

    transport = NonEmptyGatewayTransport()
    executor = GoogleResourceExecutor(transport)
    gateway_change = change("beyondcorp", "security_gateway", "default")
    application_change = change("beyondcorp", "application", "secure-gateway-http-offload-app")
    executor.apply(gateway_change, spec())
    executor.apply(application_change, spec())

    assert executor.destroy(application_change, spec()) == "deleted"
    assert executor.destroy(gateway_change, spec()) == "skipped"
    assert any(
        call["method"] == "DELETE" and call["url"].endswith("-app") for call in transport.calls
    )


def test_gateway_teardown_paginates_until_it_finds_an_application() -> None:
    class PaginatedGatewayTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/applications"):
                params = kwargs.get("params") or {}
                self.calls.append(
                    {"method": method, "url": url, "params": params, "body": None}
                )
                if params.get("pageToken") is None:
                    return 200, {"applications": [], "nextPageToken": "page-2"}
                assert params.get("pageToken") == "page-2"
                return 200, {
                    "applications": [
                        {
                            "name": (
                                "projects/enterprise-secgw-01/locations/global/"
                                "securityGateways/default/applications/remaining"
                            )
                        }
                    ]
                }
            return super().request_json(method, url, **kwargs)

    transport = PaginatedGatewayTransport()
    executor = GoogleResourceExecutor(transport)
    gateway_change = change("beyondcorp", "security_gateway", "default")
    executor.apply(gateway_change, spec())

    assert executor.destroy(gateway_change, spec()) == "skipped"
    list_calls = [
        call
        for call in transport.calls
        if call["method"] == "GET" and call["url"].endswith("/applications")
    ]
    assert [call["params"].get("pageToken") for call in list_calls] == [None, "page-2"]
    assert not any(
        call["method"] == "DELETE" and call["url"].endswith("securityGateways/default")
        for call in transport.calls
    )


def test_gateway_teardown_deletes_only_after_all_pages_are_empty() -> None:
    class EmptyPaginatedGatewayTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/applications"):
                params = kwargs.get("params") or {}
                self.calls.append(
                    {"method": method, "url": url, "params": params, "body": None}
                )
                if params.get("pageToken") is None:
                    return 200, {"applications": [], "nextPageToken": "page-2"}
                return 200, {}
            return super().request_json(method, url, **kwargs)

    transport = EmptyPaginatedGatewayTransport()
    executor = GoogleResourceExecutor(transport)
    gateway_change = change("beyondcorp", "security_gateway", "default")
    executor.apply(gateway_change, spec())

    assert executor.destroy(gateway_change, spec()) == "deleted"
    assert sum(
        call["method"] == "DELETE" and call["url"].endswith("securityGateways/default")
        for call in transport.calls
    ) == 1


@pytest.mark.parametrize(
    ("mode", "expected_code"),
    [
        ("malformed", "teardown-gateway-applications-invalid"),
        ("unreachable", "teardown-gateway-applications-unreachable"),
        ("repeated", "teardown-gateway-applications-pagination-invalid"),
        ("limit", "teardown-gateway-applications-pagination-limit-exceeded"),
    ],
)
def test_gateway_teardown_retains_on_unprovable_pagination(
    mode: str,
    expected_code: str,
) -> None:
    class UnsafePaginationTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/applications"):
                params = kwargs.get("params") or {}
                self.calls.append(
                    {"method": method, "url": url, "params": params, "body": None}
                )
                if mode == "malformed":
                    return 200, {"applications": [{"name": "not-a-resource-name"}]}
                if mode == "unreachable":
                    return 200, {"applications": [], "unreachable": ["global"]}
                if mode == "repeated":
                    return 200, {"applications": [], "nextPageToken": "same-token"}
                page = int(str(params.get("pageToken", "page-0")).removeprefix("page-"))
                return 200, {"applications": [], "nextPageToken": f"page-{page + 1}"}
            return super().request_json(method, url, **kwargs)

    transport = UnsafePaginationTransport()
    executor = GoogleResourceExecutor(transport)
    gateway_change = change("beyondcorp", "security_gateway", "default")
    executor.apply(gateway_change, spec())

    with pytest.raises(ProviderExecutionError) as captured:
        executor.destroy(gateway_change, spec())
    assert captured.value.error_code == expected_code
    assert not any(
        call["method"] == "DELETE" and call["url"].endswith("securityGateways/default")
        for call in transport.calls
    )


def public_tls_spec(**overrides: Any) -> DeploymentSpec:
    values = {
        **spec().model_dump(),
        "mode": DeploymentMode.POC,
        "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
        "private_hostname": "gw.example-company.com",
        "public_certificate_secret": ("projects/enterprise-secgw-01/secrets/operator-public-tls"),
        "ca_pool": None,
        "ca_name": None,
    }
    values.update(overrides)
    return DeploymentSpec(**values)


def public_certificate_binding(
    payload: bytes,
    *,
    version: int = 7,
) -> PublicCertificateBinding:
    return PublicCertificateBinding(
        secret_version_name=(
            f"projects/enterprise-secgw-01/secrets/operator-public-tls/versions/{version}"
        ),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )


def source_image_binding(deployment: DeploymentSpec | None = None) -> SourceImageBinding:
    image_name = (deployment or spec()).source_image
    assert image_name is not None
    return SourceImageBinding(
        name=image_name,
        id="987654321",
        self_link=f"https://www.googleapis.com/compute/v1/{image_name}",
    )


def bind_source_image_plan(
    executor: GoogleResourceExecutor,
    deployment: DeploymentSpec,
) -> None:
    executor.bind_plan(
        DesiredStatePlanner().build_plan(
            deployment,
            DiscoverySnapshot(source_image_binding=source_image_binding(deployment)),
        )
    )


def bind_public_certificate_plan(
    executor: GoogleResourceExecutor,
    deployment: DeploymentSpec,
    payload: bytes,
) -> None:
    plan = DesiredStatePlanner().build_plan(
        deployment,
        DiscoverySnapshot(
            public_certificate_binding=public_certificate_binding(payload),
            source_image_binding=source_image_binding(deployment),
        ),
    )
    executor.bind_plan(plan)


def test_source_image_numeric_identity_is_revalidated_before_any_mutation() -> None:
    deployment = spec()

    class RecreatedImageTransport(FakeTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if method == "GET" and url.endswith("/global/images/sgs-nginx-20260730"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                return 200, {
                    "name": "sgs-nginx-20260730",
                    "id": "123456789",
                    "selfLink": (
                        "https://www.googleapis.com/compute/v1/projects/"
                        "enterprise-secgw-01/global/images/sgs-nginx-20260730"
                    ),
                }
            return super().request_json(method, url, **kwargs)

    transport = RecreatedImageTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    plan = DesiredStatePlanner().build_plan(
        deployment,
        DiscoverySnapshot(source_image_binding=source_image_binding(deployment)),
    )
    executor.bind_plan(plan)

    with pytest.raises(ProviderExecutionError) as captured:
        executor.prepare_apply(deployment)

    assert captured.value.error_code == "source-image-binding-invalid"
    assert [call["method"] for call in transport.calls] == ["GET"]


def test_destroy_removes_only_the_owned_cloud_nat_from_its_router() -> None:
    class RouterTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.router = {
                "id": "router-immutable-123",
                "fingerprint": "router-fingerprint-1",
                "name": "secure-gateway-http-offload-router",
                "description": "administrator edit retained",
                "nats": [
                    {"name": "shared-nat", "natIpAllocateOption": "AUTO_ONLY"},
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
                    },
                ],
            }

        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/routers/secure-gateway-http-offload-router"):
                self.calls.append({"method": method, "url": url, "params": None, "body": None})
                return 200, deepcopy(self.router)
            if method == "PATCH" and url.endswith("/routers/secure-gateway-http-offload-router"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body")),
                    }
                )
                self.router = deepcopy(kwargs["json_body"])
                return 200, {"status": "DONE"}
            return super().request_json(method, url, **kwargs)

    transport = RouterTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    managed_nat = deepcopy(transport.router["nats"][1])
    executor.bind_ownership_metadata(
        {
            "compute:cloud_nat:secure-gateway-http-offload-nat": {
                "kind": "cloud_nat_delta",
                "protocol_version": 2,
                "phase": "applied",
                "resource_key": "compute:cloud_nat:secure-gateway-http-offload-nat",
                "router_url": (
                    "https://compute.googleapis.com/compute/v1/projects/"
                    "enterprise-secgw-01/regions/asia-east1/routers/"
                    "secure-gateway-http-offload-router"
                ),
                "router_identity_field": "id",
                "router_identity": "router-immutable-123",
                "nat_name": "secure-gateway-http-offload-nat",
                "managed_before_nat": None,
                "managed_after_nat": managed_nat,
            }
        }
    )

    outcome = executor.destroy(
        change("compute", "cloud_nat", "secure-gateway-http-offload-nat"),
        spec(),
    )

    assert outcome == "deleted"
    patch_call = next(
        call for call in transport.calls if call["method"] == "PATCH" and "/routers/" in call["url"]
    )
    assert patch_call["body"]["nats"] == [
        {"name": "shared-nat", "natIpAllocateOption": "AUTO_ONLY"}
    ]
    assert patch_call["body"]["fingerprint"] == "router-fingerprint-1"
    assert "description" not in patch_call["body"]
    assert uuid.UUID(str(patch_call["params"]["requestId"])).version == 5


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.generic_resources: dict[str, dict[str, Any]] = {}
        self.generic_identity = 1000
        self.private_ca_certificates: dict[str, dict[str, Any]] = {}
        self.chrome_policies: dict[str, dict[str, Any]] = {}
        self.secret: dict[str, Any] = {
            "name": ("projects/enterprise-secgw-01/secrets/secure-gateway-http-offload-tls"),
            "etag": "secret-etag",
            "versionAliases": {"active": "7"},
            "labels": {},
            "replication": {"automatic": {}},
        }
        self.original_policy = {
            "version": 1,
            "etag": "before-etag",
            "bindings": [{"role": "roles/viewer", "members": ["user:owner@example.com"]}],
        }

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
        self.calls.append({"method": method, "url": url, "params": params, "body": json_body})
        if method == "GET" and "admin.googleapis.com" in url and "/orgunits/id%3A" in url:
            return 200, {
                "orgUnitId": "id:03-test-ou",
                "orgUnitPath": "/Secure Gateway Test",
            }
        if method == "GET" and url.endswith(
            "/global/images/sgs-nginx-20260730"
        ):
            return 200, {
                "name": "sgs-nginx-20260730",
                "id": "987654321",
                "selfLink": (
                    "https://www.googleapis.com/compute/v1/projects/"
                    "enterprise-secgw-01/global/images/sgs-nginx-20260730"
                ),
            }
        if method == "POST" and url.endswith("/listManagedInstances"):
            return 200, {
                "managedInstances": [
                    {
                        "instance": (
                            "https://www.googleapis.com/compute/v1/projects/"
                            "enterprise-secgw-01/zones/asia-east1-c/instances/"
                            "secure-gateway-http-offload-offload-a1"
                        ),
                        "instanceStatus": "RUNNING",
                    },
                    {
                        "instance": (
                            "https://www.googleapis.com/compute/v1/projects/"
                            "enterprise-secgw-01/zones/asia-east1-a/instances/"
                            "secure-gateway-http-offload-offload-a2"
                        ),
                        "instanceStatus": "RUNNING",
                    },
                ]
            }
        if (
            method == "GET"
            and "/zones/" in url
            and "/instances/secure-gateway-http-offload-offload-" in url
        ):
            zone = url.split("/zones/", maxsplit=1)[1].split("/", maxsplit=1)[0]
            instance_name = url.rsplit("/", maxsplit=1)[-1]
            return 200, {
                "name": instance_name,
                "disks": [
                    {
                        "boot": True,
                        "source": (
                            "https://www.googleapis.com/compute/v1/projects/"
                            f"enterprise-secgw-01/zones/{zone}/disks/{instance_name}"
                        ),
                    }
                ],
            }
        if method == "GET" and url in self.generic_resources:
            current = deepcopy(self.generic_resources[url])
            if "/instances/" in url:
                instance_name = url.rsplit("/", maxsplit=1)[-1]
                current["disks"] = [
                    {
                        "boot": True,
                        "source": (
                            "https://www.googleapis.com/compute/v1/projects/"
                            "enterprise-secgw-01/zones/asia-east1-c/disks/"
                            f"{instance_name}"
                        ),
                    }
                ]
            if "/addresses/" in url:
                suffix = "20" if "-backend-ip" in url else "10"
                current["address"] = f"10.42.0.{suffix}"
            if "/instanceGroupManagers/" in url:
                current.update(
                    {
                        "status": {
                            "isStable": True,
                            "currentInstanceStatuses": {"running": 2},
                        },
                        "targetSize": 2,
                    }
                )
            if "/securityGateways/" in url and "/applications/" not in url:
                current["delegatingServiceAccount"] = (
                    "sg-delegate@enterprise-secgw-01.iam.gserviceaccount.com"
                )
            return 200, current
        if method == "GET" and "/zones/" in url and "/disks/" in url:
            disk_name = url.rsplit("/", maxsplit=1)[-1]
            return 200, {
                "name": disk_name,
                "status": "READY",
                "sourceImage": (
                    "https://www.googleapis.com/compute/v1/projects/"
                    "enterprise-secgw-01/global/images/sgs-nginx-20260730"
                ),
                "sourceImageId": "987654321",
            }
        if method == "GET" and "privateca.googleapis.com/v1/" in url:
            certificate = self.private_ca_certificates.get(url)
            return (200, deepcopy(certificate)) if certificate is not None else (404, {})
        if method == "POST" and url.endswith(":revoke"):
            certificate_url = url.removesuffix(":revoke")
            certificate = self.private_ca_certificates.get(certificate_url)
            if certificate is not None:
                certificate["revocationDetails"] = {}
            return 200, {}
        if "/addresses/" in url and method == "GET":
            suffix = "20" if "-backend-ip" in url else "10"
            return 200, {"address": f"10.42.0.{suffix}"}
        if method == "GET" and url.endswith("/getGuestAttributes"):
            configuration_hash = canonical_configuration_hash(spec())
            return 200, {
                "queryValue": {
                    "items": [
                        {
                            "namespace": "sgstudio",
                            "key": "T01",
                            "value": (
                                '{"status":200,"configuration_hash":"' + configuration_hash + '"}'
                            ),
                        },
                        {
                            "namespace": "sgstudio",
                            "key": "T02",
                            "value": (
                                '{"status":200,"configuration_hash":"' + configuration_hash + '"}'
                            ),
                        },
                        {
                            "namespace": "sgstudio",
                            "key": "T03",
                            "value": (
                                '{"http_status":200,"tls_version":"TLSv1.3",'
                                '"hostname":"demo-server-http.internal",'
                                '"subject_alt_names":["demo-server-http.internal"],'
                                '"configuration_hash":"' + configuration_hash + '"}'
                            ),
                        },
                    ]
                }
            }
        if url.endswith(":getIamPolicy"):
            return 200, self.original_policy
        if "/policySchemas/" in url:
            schema_name = url.rsplit("/", maxsplit=1)[-1]
            field_name = (
                "managedConfiguration"
                if schema_name.endswith("ManagedConfiguration")
                else "appInstallType"
            )
            return 200, {
                "schemaName": schema_name,
                "additionalTargetKeyNames": [{"key": "app_id"}],
                "definition": {
                    "messageType": [{"name": "Policy", "field": [{"name": field_name}]}]
                },
            }
        if method == "POST" and url.endswith("/policies:resolve"):
            body = json_body or {}
            target = body.get("policyTargetKey", {})
            schema = body.get("policySchemaFilter")
            policy_key = json.dumps({"schema": schema, "target": target}, sort_keys=True)
            current = self.chrome_policies.get(policy_key)
            return 200, {
                "resolvedPolicies": (
                    [
                        {
                            "targetKey": deepcopy(target),
                            "sourceKey": {
                                "targetResource": target["targetResource"],
                            },
                            "value": deepcopy(current),
                        }
                    ]
                    if current is not None
                    else []
                )
            }
        if method == "POST" and url.endswith("policies/orgunits:batchModify"):
            for request in (json_body or {}).get("requests", []):
                target = request["policyTargetKey"]
                policy_value = request["policyValue"]
                schema = policy_value["policySchema"]
                policy_key = json.dumps({"schema": schema, "target": target}, sort_keys=True)
                current = deepcopy(
                    self.chrome_policies.get(
                        policy_key,
                        {"policySchema": schema, "value": {}},
                    )
                )
                for field in request["updateMask"].split(","):
                    current["value"][field] = deepcopy(policy_value["value"][field])
                self.chrome_policies[policy_key] = current
            return 200, {}
        if method == "POST" and url.endswith("policies/orgunits:batchInherit"):
            for request in (json_body or {}).get("requests", []):
                policy_key = json.dumps(
                    {
                        "schema": request["policySchema"],
                        "target": request["policyTargetKey"],
                    },
                    sort_keys=True,
                )
                self.chrome_policies.pop(policy_key, None)
            return 200, {}
        if url.endswith("networks:defineCertificate"):
            return 200, {"networkId": "{test-root-guid}"}
        if method == "GET" and url.endswith("/secrets/secure-gateway-http-offload-tls"):
            return 200, deepcopy(self.secret)
        if method == "POST" and (
            "compute.googleapis.com" in url or "beyondcorp.googleapis.com" in url
        ):
            resource_name = (
                (json_body or {}).get("name")
                or (params or {}).get("securityGatewayId")
                or (params or {}).get("applicationId")
            )
            if isinstance(resource_name, str) and not url.endswith(":setIamPolicy"):
                resource_url = f"{url.rstrip('/')}/{resource_name}"
                self.generic_identity += 1
                current = deepcopy(json_body or {})
                if "compute.googleapis.com" in url:
                    current.update(
                        {
                            "id": str(self.generic_identity),
                            "selfLink": resource_url,
                            "creationTimestamp": "2026-08-24T00:00:00.000Z",
                        }
                    )
                else:
                    current.update(
                        {
                            "name": resource_url.removeprefix(
                                "https://beyondcorp.googleapis.com/v1/"
                            ),
                            "createTime": (f"2026-08-24T00:00:{self.generic_identity % 60:02d}Z"),
                        }
                    )
                    if "serviceDiscovery" in current:
                        current.update(
                            {
                                "externalIps": ["203.0.113.10"],
                                "state": "RUNNING",
                                "delegatingServiceAccount": (
                                    "gateway@example.iam.gserviceaccount.com"
                                ),
                            }
                        )
                self.generic_resources[resource_url] = current
        if method == "DELETE" and url in self.generic_resources:
            self.generic_resources.pop(url)
            return 200, {"status": "DONE"}
        if (
            method == "POST"
            and url.endswith("/secrets")
            and params is not None
            and params.get("secretId") == "secure-gateway-http-offload-tls"
        ):
            self.secret = {
                **deepcopy(json_body or {}),
                "name": ("projects/enterprise-secgw-01/secrets/secure-gateway-http-offload-tls"),
                "etag": "secret-created-etag",
                "versionAliases": deepcopy((json_body or {}).get("versionAliases", {})),
            }
            return 200, deepcopy(self.secret)
        if method == "PATCH" and url.endswith("/secrets/secure-gateway-http-offload-tls"):
            assert json_body is not None
            self.secret.update(deepcopy(json_body))
            self.secret["etag"] = "secret-patched-etag"
            return 200, deepcopy(self.secret)
        if method == "POST" and url.endswith("/secrets/secure-gateway-http-offload-tls:addVersion"):
            return 200, {
                "name": (
                    "projects/enterprise-secgw-01/secrets/"
                    "secure-gateway-http-offload-tls/versions/8"
                )
            }
        if method == "POST" and url.endswith("/changes"):
            return 200, {"kind": "dns#change", "id": "42", "status": "done"}
        if method == "GET" and "/instanceGroupManagers/" in url:
            return 404, {}
        if method in {"POST", "PATCH", "DELETE"}:
            if "compute.googleapis.com" in url:
                return 200, {"status": "DONE"}
            return 200, {}
        return 200, {}


class PublicCertificateTransport(FakeTransport):
    def __init__(
        self,
        payload: bytes,
        *,
        version: int = 7,
        corrupt_crc: bool = False,
    ) -> None:
        super().__init__()
        self.payload = payload
        self.version = version
        self.corrupt_crc = corrupt_crc

    def request_json(self, method: str, url: str, **kwargs):
        if method == "GET" and url.endswith("/secrets/operator-public-tls/versions/latest:access"):
            self.calls.append(
                {
                    "method": method,
                    "url": url,
                    "params": kwargs.get("params"),
                    "body": kwargs.get("json_body"),
                }
            )
            crc = GoogleResourceExecutor._crc32c(self.payload)
            return 200, {
                "name": (
                    "projects/enterprise-secgw-01/secrets/operator-public-tls/"
                    f"versions/{self.version}"
                ),
                "payload": {
                    "data": base64.b64encode(self.payload).decode("ascii"),
                    "dataCrc32c": str(crc + 1 if self.corrupt_crc else crc),
                },
            }
        return super().request_json(method, url, **kwargs)


class StatefulIamTransport(FakeTransport):
    def __init__(self) -> None:
        super().__init__()
        self.current_policy = deepcopy(self.original_policy)
        self.set_count = 0

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if url.endswith(":getIamPolicy"):
            self.calls.append({"method": method, "url": url, "params": params, "body": json_body})
            return 200, deepcopy(self.current_policy)
        if url.endswith(":setIamPolicy"):
            self.calls.append({"method": method, "url": url, "params": params, "body": json_body})
            assert json_body is not None
            policy = deepcopy(json_body["policy"])
            assert policy.get("etag") == self.current_policy.get("etag")
            self.set_count += 1
            policy["etag"] = f"current-etag-{self.set_count}"
            self.current_policy = policy
            return 200, deepcopy(policy)
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


@pytest.mark.parametrize(
    "malformed_sans",
    [
        "demo-server-http.internal",
        ["demo-server-http.internal", 7],
        {"demo-server-http.internal": True},
    ],
)
def test_instance_readiness_rejects_malformed_subject_alt_name_evidence(
    malformed_sans: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deployment = local_poc_spec()
    configuration_hash = canonical_configuration_hash(deployment)
    monkeypatch.setattr("sgstudio.providers.google_executor.time.sleep", lambda _seconds: None)

    class ReadinessTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.reads = 0

        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/getGuestAttributes"):
                self.reads += 1
                sans = malformed_sans if self.reads == 1 else [deployment.private_hostname]
                return 200, {
                    "queryValue": {
                        "items": [
                            {
                                "namespace": "sgstudio",
                                "key": "T02",
                                "value": json.dumps(
                                    {
                                        "status": 200,
                                        "configuration_hash": configuration_hash,
                                    }
                                ),
                            },
                            {
                                "namespace": "sgstudio",
                                "key": "T03",
                                "value": json.dumps(
                                    {
                                        "http_status": 200,
                                        "configuration_hash": configuration_hash,
                                        "hostname": deployment.private_hostname,
                                        "tls_version": "TLSv1.3",
                                        "subject_alt_names": sans,
                                    }
                                ),
                            },
                        ]
                    }
                }
            return super().request_json(method, url, **kwargs)

    transport = ReadinessTransport()
    executor = GoogleResourceExecutor(
        transport,
        poll_interval_seconds=0,
        operation_timeout_seconds=1,
    )
    target = change("compute", "instance", f"{deployment.name}-offload")

    executor._wait_for_instance_readiness(target, deployment, suffix="offload")

    assert transport.reads == 2


def test_destroy_reverts_only_gateway_iam_members_added_by_apply() -> None:
    deployment = spec().model_copy(
        update={
            "principals": [
                AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com"),
                AccessPrincipal(type=PrincipalType.GROUP, value="new-access@example.com"),
            ]
        }
    )
    transport = StatefulIamTransport()
    transport.current_policy = {
        "version": 1,
        "etag": "gateway-etag",
        "bindings": [
            {
                "role": "roles/beyondcorp.serviceDiscoveryUser",
                "members": [
                    "group:secure-access@example.com",
                    "group:shared-access@example.com",
                ],
            },
            {"role": "roles/viewer", "members": ["user:owner@example.com"]},
        ],
    }
    iam_change = change("beyondcorp", "gateway_iam", "default-service-discovery-users")
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    executor.apply(iam_change, deployment)
    metadata = executor.ownership_metadata(iam_change, deployment)
    assert metadata is not None
    gateway_binding = next(
        binding
        for binding in transport.current_policy["bindings"]
        if binding["role"] == "roles/beyondcorp.serviceDiscoveryUser"
    )
    gateway_binding["members"].append("group:concurrent@example.com")
    transport.current_policy["etag"] = "gateway-third-party-etag"

    resumed = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    resumed.bind_ownership_metadata(
        {"beyondcorp:gateway_iam:default-service-discovery-users": metadata}
    )
    outcome = resumed.destroy(iam_change, deployment)

    assert outcome == "deleted"
    assert transport.current_policy["bindings"] == [
        {
            "role": "roles/beyondcorp.serviceDiscoveryUser",
            "members": [
                "group:secure-access@example.com",
                "group:shared-access@example.com",
                "group:concurrent@example.com",
            ],
        },
        {"role": "roles/viewer", "members": ["user:owner@example.com"]},
    ]


def test_destroy_treats_owned_but_already_missing_iam_resource_as_deleted() -> None:
    class MissingIamTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if url.endswith(":getIamPolicy"):
                if 404 not in kwargs.get("accepted_statuses", (200,)):
                    raise GoogleApiError(
                        status_code=404,
                        method=method,
                        host="beyondcorp.googleapis.com",
                        detail="Not found",
                    )
                return 404, {}
            return super().request_json(method, url, **kwargs)

    iam_change = change("beyondcorp", "gateway_iam", "default-service-discovery-users")
    source = GoogleResourceExecutor(StatefulIamTransport(), poll_interval_seconds=0)
    source.apply(iam_change, spec())
    metadata = source.ownership_metadata(iam_change, spec())
    assert metadata is not None
    executor = GoogleResourceExecutor(MissingIamTransport(), poll_interval_seconds=0)
    executor.bind_ownership_metadata(
        {"beyondcorp:gateway_iam:default-service-discovery-users": metadata}
    )

    outcome = executor.destroy(iam_change, spec())

    assert outcome == "deleted"


def test_destroy_reverts_only_application_iam_members_added_by_apply() -> None:
    managed_condition = {
        "title": "Managed Chrome required",
        "description": "Allow only profiles or browsers managed by this enterprise",
        "expression": (
            "'accessPolicies/123456789/accessLevels/managed_chrome' in request.auth.access_levels"
        ),
    }
    deployment = spec().model_copy(
        update={
            "principals": [
                AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com"),
                AccessPrincipal(type=PrincipalType.GROUP, value="new-access@example.com"),
            ]
        }
    )
    transport = StatefulIamTransport()
    transport.current_policy = {
        "version": 3,
        "etag": "application-etag",
        "bindings": [
            {
                "role": "roles/beyondcorp.sgApplicationUser",
                "members": ["group:secure-access@example.com"],
                "condition": managed_condition,
            },
            {
                "role": "roles/beyondcorp.sgApplicationUser",
                "members": ["group:break-glass@example.com"],
                "condition": {"title": "Break glass", "expression": "false"},
            },
        ],
    }
    iam_change = change(
        "beyondcorp",
        "application_iam",
        "secure-gateway-http-offload-app-access",
    )
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    executor.apply(iam_change, deployment)
    metadata = executor.ownership_metadata(iam_change, deployment)
    assert metadata is not None
    managed_binding = next(
        binding
        for binding in transport.current_policy["bindings"]
        if binding.get("condition") == managed_condition
    )
    managed_binding["members"].append("group:concurrent@example.com")
    transport.current_policy["etag"] = "application-third-party-etag"
    resumed = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    resumed.bind_ownership_metadata(
        {"beyondcorp:application_iam:secure-gateway-http-offload-app-access": (metadata)}
    )

    outcome = resumed.destroy(iam_change, deployment)

    assert outcome == "deleted"
    assert transport.current_policy["bindings"] == [
        {
            "role": "roles/beyondcorp.sgApplicationUser",
            "members": [
                "group:secure-access@example.com",
                "group:concurrent@example.com",
            ],
            "condition": managed_condition,
        },
        {
            "role": "roles/beyondcorp.sgApplicationUser",
            "members": ["group:break-glass@example.com"],
            "condition": {"title": "Break glass", "expression": "false"},
        },
    ]


def test_destroy_iam_without_durable_delta_fails_closed() -> None:
    executor = GoogleResourceExecutor(StatefulIamTransport(), poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError) as captured:
        executor.destroy(
            change("beyondcorp", "gateway_iam", "default-service-discovery-users"),
            spec(),
        )

    assert captured.value.error_code == "iam-teardown-ownership-metadata-missing"


@pytest.mark.parametrize(
    "iam_change",
    [
        change("beyondcorp", "gateway_iam", "default-service-discovery-users"),
        change(
            "beyondcorp",
            "application_iam",
            "secure-gateway-http-offload-app-access",
        ),
        change(
            "cloudresourcemanager",
            "project_iam",
            "enterprise-secgw-01-secure-gateway-delegation",
        ),
        change(
            "secretmanager",
            "secret_iam",
            "secure-gateway-http-offload-tls-accessor",
        ),
    ],
)
def test_iam_response_loss_never_claims_a_coincident_live_binding(
    iam_change: ResourceChange,
) -> None:
    class LostResponseTransport(StatefulIamTransport):
        def __init__(self) -> None:
            super().__init__()
            self.lose_response = True

        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/securityGateways/default"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                return 200, {"delegatingServiceAccount": "gateway@example.iam.gserviceaccount.com"}
            result = super().request_json(method, url, **kwargs)
            if self.lose_response and url.endswith(":setIamPolicy"):
                self.lose_response = False
                raise ConnectionError("provider response lost")
            return result

    transport = LostResponseTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError) as lost:
        executor.apply(iam_change, spec())

    assert lost.value.error_code == f"invalid-provider-response-{iam_change.resource_type}"

    set_count = transport.set_count
    with pytest.raises(ProviderExecutionError) as captured:
        executor.apply(iam_change, spec())

    assert captured.value.error_code == "iam-provider-response-ambiguous"
    assert transport.set_count == set_count


def test_iam_confirmed_aborted_retry_refreshes_etag_and_preserves_concurrent_edits() -> None:
    class OneConflictTransport(StatefulIamTransport):
        def __init__(self) -> None:
            super().__init__()
            self.conflicts = 1

        def request_json(self, method: str, url: str, **kwargs):
            if method == "POST" and url.endswith(":setIamPolicy") and self.conflicts:
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body")),
                    }
                )
                self.conflicts -= 1
                self.current_policy["bindings"].append(
                    {
                        "role": "roles/editor",
                        "members": ["user:concurrent@example.com"],
                    }
                )
                self.current_policy["etag"] = "concurrent-etag"
                raise GoogleApiError(
                    status_code=409,
                    method="POST",
                    host="secretmanager.googleapis.com",
                    detail='{"error":{"status":"ABORTED"}}',
                )
            return super().request_json(method, url, **kwargs)

    transport = OneConflictTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "secretmanager",
        "secret_iam",
        "secure-gateway-http-offload-tls-accessor",
    )
    checkpoints: list[dict[str, object]] = []
    _bind_durable_operation(executor, target, spec(), checkpoints)

    executor.apply(target, spec())

    set_calls = [call for call in transport.calls if call["url"].endswith(":setIamPolicy")]
    prepared = [item for item in checkpoints if item.get("phase") == "prepared"]
    assert len(set_calls) == 2
    assert [item["attempt"] for item in prepared] == [1, 2]
    assert prepared[0]["body"]["policy"]["etag"] == "before-etag"
    assert prepared[1]["body"]["policy"]["etag"] == "concurrent-etag"
    assert any(
        binding["role"] == "roles/editor" for binding in transport.current_policy["bindings"]
    )
    assert checkpoints[-1]["phase"] == "applied"


def test_iam_aborted_retries_are_bounded() -> None:
    class AlwaysConflictTransport(StatefulIamTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if method == "POST" and url.endswith(":setIamPolicy"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body")),
                    }
                )
                self.current_policy["etag"] = f"conflict-{len(self.calls)}"
                raise GoogleApiError(
                    status_code=409,
                    method="POST",
                    host="secretmanager.googleapis.com",
                    detail='{"error":{"status":"ABORTED"}}',
                )
            return super().request_json(method, url, **kwargs)

    transport = AlwaysConflictTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "secretmanager",
        "secret_iam",
        "secure-gateway-http-offload-tls-accessor",
    )
    checkpoints: list[dict[str, object]] = []
    _bind_durable_operation(executor, target, spec(), checkpoints)

    with pytest.raises(ProviderExecutionError):
        executor.apply(target, spec())

    assert len([call for call in transport.calls if call["url"].endswith(":setIamPolicy")]) == 5
    assert checkpoints[-1]["phase"] == "rejected"


def test_iam_non_aborted_409_is_not_retried() -> None:
    class NonAbortedConflictTransport(StatefulIamTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if method == "POST" and url.endswith(":setIamPolicy"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body")),
                    }
                )
                raise GoogleApiError(
                    status_code=409,
                    method="POST",
                    host="secretmanager.googleapis.com",
                    detail='{"error":{"status":"ALREADY_EXISTS"}}',
                )
            return super().request_json(method, url, **kwargs)

    transport = NonAbortedConflictTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "secretmanager",
        "secret_iam",
        "secure-gateway-http-offload-tls-accessor",
    )

    with pytest.raises(ProviderExecutionError):
        executor.apply(target, spec())

    assert len([call for call in transport.calls if call["url"].endswith(":setIamPolicy")]) == 1


@pytest.mark.parametrize("etag", [None, ""])
def test_iam_apply_requires_nonempty_fresh_etag_before_send(etag: str | None) -> None:
    transport = StatefulIamTransport()
    if etag is None:
        transport.current_policy.pop("etag")
    else:
        transport.current_policy["etag"] = etag
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "secretmanager",
        "secret_iam",
        "secure-gateway-http-offload-tls-accessor",
    )

    with pytest.raises(ProviderExecutionError) as captured:
        executor.apply(target, spec())

    assert captured.value.error_code == "iam-policy-etag-missing"
    assert not any(call["url"].endswith(":setIamPolicy") for call in transport.calls)


IAM_MUTATION_CHANGES = [
    change("beyondcorp", "gateway_iam", "default-service-discovery-users"),
    change(
        "beyondcorp",
        "application_iam",
        "secure-gateway-http-offload-app-access",
    ),
    change("cloudresourcemanager", "project_iam", "upstream-access"),
    change(
        "secretmanager",
        "secret_iam",
        "secure-gateway-http-offload-tls-accessor",
    ),
]


@pytest.mark.parametrize(
    "malformed_binding",
    [
        {
            "role": "roles/viewer",
            "members": ["user:duplicate@example.com", "user:duplicate@example.com"],
        },
        {
            "role": "roles/viewer",
            "members": ["user:owner@example.com"],
            "condition": {
                "title": "Unrelated",
                "expression": "true",
                "unknown": "must-not-round-trip",
            },
        },
        {
            "role": "roles/viewer",
            "members": ["user:owner@example.com"],
            "unknown": True,
        },
    ],
    ids=["duplicate-member", "malformed-condition", "unknown-binding-field"],
)
@pytest.mark.parametrize(
    "iam_change",
    IAM_MUTATION_CHANGES,
    ids=["gateway", "application", "project", "secret"],
)
def test_all_iam_apply_paths_reject_malformed_unrelated_binding_before_send(
    malformed_binding: dict[str, object],
    iam_change: ResourceChange,
) -> None:
    transport = StatefulIamTransport()
    transport.current_policy["bindings"].append(deepcopy(malformed_binding))
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    if iam_change.resource_type == "project_iam":
        executor._gateway_service_account = "gateway@example.iam.gserviceaccount.com"

    with pytest.raises(ProviderExecutionError):
        executor.apply(iam_change, spec())

    assert transport.set_count == 0
    assert not any(call["url"].endswith(":setIamPolicy") for call in transport.calls)


@pytest.mark.parametrize(
    "iam_change",
    IAM_MUTATION_CHANGES,
    ids=["gateway", "application", "project", "secret"],
)
def test_all_iam_rollback_paths_reject_malformed_fresh_policy_before_send(
    iam_change: ResourceChange,
) -> None:
    transport = StatefulIamTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    if iam_change.resource_type == "project_iam":
        executor._gateway_service_account = "gateway@example.iam.gserviceaccount.com"
    executor.apply(iam_change, spec())
    transport.current_policy["bindings"].append(
        {
            "role": "roles/viewer",
            "members": ["user:owner@example.com"],
            "condition": {
                "title": "Unrelated",
                "expression": "true",
                "unknown": "must-not-round-trip",
            },
        }
    )
    set_count = transport.set_count

    with pytest.raises(ProviderExecutionError):
        executor.rollback(iam_change, spec())

    assert transport.set_count == set_count


def test_iam_5xx_retains_sending_checkpoint_without_blind_retry() -> None:
    class AmbiguousServerErrorTransport(StatefulIamTransport):
        def request_json(self, method: str, url: str, **kwargs):
            if method == "POST" and url.endswith(":setIamPolicy"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body")),
                    }
                )
                raise GoogleApiError(
                    status_code=503,
                    method="POST",
                    host="secretmanager.googleapis.com",
                    detail='{"error":{"status":"UNAVAILABLE"}}',
                )
            return super().request_json(method, url, **kwargs)

    transport = AmbiguousServerErrorTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "secretmanager",
        "secret_iam",
        "secure-gateway-http-offload-tls-accessor",
    )
    checkpoints: list[dict[str, object]] = []
    _bind_durable_operation(executor, target, spec(), checkpoints)

    with pytest.raises(ProviderExecutionError):
        executor.apply(target, spec())
    with pytest.raises(ProviderExecutionError) as resumed:
        executor.apply(target, spec())

    assert resumed.value.error_code == "iam-provider-response-ambiguous"
    assert checkpoints[-1]["phase"] == "sending"
    assert len([call for call in transport.calls if call["url"].endswith(":setIamPolicy")]) == 1


def test_iam_v3_restart_phase_contract() -> None:
    target = change(
        "secretmanager",
        "secret_iam",
        "secure-gateway-http-offload-tls-accessor",
    )
    seed = GoogleResourceExecutor(StatefulIamTransport(), poll_interval_seconds=0)
    seed_writes: list[dict[str, object]] = []
    _bind_durable_operation(seed, target, spec(), seed_writes)
    seed.apply(target, spec())
    prepared = next(item for item in seed_writes if item.get("phase") == "prepared")

    for phase in ("prepared", "rejected"):
        transport = StatefulIamTransport()
        executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
        writes: list[dict[str, object]] = []
        _bind_durable_operation(
            executor,
            target,
            spec(),
            writes,
            checkpoint={**prepared, "phase": phase},
        )
        executor.apply(target, spec())
        assert transport.set_count == 1
        assert writes[-1]["phase"] == "applied"

    sending_transport = StatefulIamTransport()
    sending = GoogleResourceExecutor(sending_transport, poll_interval_seconds=0)
    _bind_durable_operation(
        sending,
        target,
        spec(),
        [],
        checkpoint={**prepared, "phase": "sending"},
    )
    with pytest.raises(ProviderExecutionError) as ambiguous:
        sending.apply(target, spec())
    assert ambiguous.value.error_code == "iam-provider-response-ambiguous"
    assert sending_transport.set_count == 0

    applied_transport = StatefulIamTransport()
    applied = GoogleResourceExecutor(applied_transport, poll_interval_seconds=0)
    _bind_durable_operation(
        applied,
        target,
        spec(),
        [],
        checkpoint={**prepared, "phase": "applied"},
    )
    applied.apply(target, spec())
    assert applied_transport.set_count == 0


def test_iam_rollback_requires_a_nonempty_fresh_etag_before_send() -> None:
    transport = StatefulIamTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "secretmanager",
        "secret_iam",
        "secure-gateway-http-offload-tls-accessor",
    )
    executor.apply(target, spec())
    transport.current_policy.pop("etag")

    with pytest.raises(ProviderExecutionError) as captured:
        executor.rollback(target, spec())

    assert captured.value.error_code == "iam-policy-etag-missing"
    assert transport.set_count == 1


def test_iam_rollback_aborted_retry_preserves_concurrent_bindings() -> None:
    class RollbackConflictTransport(StatefulIamTransport):
        def __init__(self) -> None:
            super().__init__()
            self.conflict_rollback = False

        def request_json(self, method: str, url: str, **kwargs):
            if self.conflict_rollback and method == "POST" and url.endswith(":setIamPolicy"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body")),
                    }
                )
                self.conflict_rollback = False
                self.current_policy["bindings"].append(
                    {
                        "role": "roles/editor",
                        "members": ["user:concurrent@example.com"],
                    }
                )
                self.current_policy["etag"] = "rollback-concurrent-etag"
                raise GoogleApiError(
                    status_code=409,
                    method="POST",
                    host="secretmanager.googleapis.com",
                    detail='{"error":{"status":"ABORTED"}}',
                )
            return super().request_json(method, url, **kwargs)

    transport = RollbackConflictTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "secretmanager",
        "secret_iam",
        "secure-gateway-http-offload-tls-accessor",
    )
    executor.apply(target, spec())
    transport.conflict_rollback = True

    executor.rollback(target, spec())

    assert any(
        binding["role"] == "roles/editor" for binding in transport.current_policy["bindings"]
    )
    assert not any(
        binding["role"] == "roles/secretmanager.secretAccessor"
        for binding in transport.current_policy["bindings"]
    )
    metadata = executor.ownership_metadata(target, spec())
    assert metadata is not None
    assert metadata["rollback"]["phase"] == "applied"
    assert metadata["rollback"]["attempt"] == 2


def test_iam_rollback_5xx_retains_sending_checkpoint_without_blind_retry() -> None:
    class RollbackServerErrorTransport(StatefulIamTransport):
        def __init__(self) -> None:
            super().__init__()
            self.fail_rollback = False

        def request_json(self, method: str, url: str, **kwargs):
            if self.fail_rollback and method == "POST" and url.endswith(":setIamPolicy"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body")),
                    }
                )
                raise GoogleApiError(
                    status_code=503,
                    method="POST",
                    host="secretmanager.googleapis.com",
                    detail='{"error":{"status":"UNAVAILABLE"}}',
                )
            return super().request_json(method, url, **kwargs)

    transport = RollbackServerErrorTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "secretmanager",
        "secret_iam",
        "secure-gateway-http-offload-tls-accessor",
    )
    executor.apply(target, spec())
    transport.fail_rollback = True

    with pytest.raises(ProviderExecutionError):
        executor.rollback(target, spec())
    sets_after_loss = len(
        [call for call in transport.calls if call["url"].endswith(":setIamPolicy")]
    )
    with pytest.raises(ProviderExecutionError) as resumed:
        executor.rollback(target, spec())

    assert resumed.value.error_code == "iam-rollback-provider-response-ambiguous"
    assert (
        len([call for call in transport.calls if call["url"].endswith(":setIamPolicy")])
        == sets_after_loss
    )


def test_destroy_preserves_preexisting_secret_accessor_member() -> None:
    transport = StatefulIamTransport()
    transport.current_policy = {
        "version": 1,
        "etag": "secret-etag",
        "bindings": [
            {
                "role": "roles/secretmanager.secretAccessor",
                "members": [
                    (
                        "serviceAccount:secure-gateway-cd03d7-offload@"
                        "enterprise-secgw-01.iam.gserviceaccount.com"
                    ),
                    "serviceAccount:shared@example.iam.gserviceaccount.com",
                ],
            }
        ],
    }
    iam_change = change(
        "secretmanager",
        "secret_iam",
        "secure-gateway-http-offload-tls-accessor",
    )
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    executor.apply(iam_change, spec())
    metadata = executor.ownership_metadata(iam_change, spec())
    assert metadata is not None
    accessor = next(
        binding
        for binding in transport.current_policy["bindings"]
        if binding["role"] == "roles/secretmanager.secretAccessor"
    )
    accessor["members"].append("serviceAccount:concurrent@example.iam.gserviceaccount.com")
    transport.current_policy["etag"] = "secret-third-party-etag"
    resumed = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    resumed.bind_ownership_metadata(
        {"secretmanager:secret_iam:secure-gateway-http-offload-tls-accessor": metadata}
    )

    outcome = resumed.destroy(iam_change, spec())

    assert outcome == "deleted"
    assert transport.current_policy["bindings"][0]["members"] == [
        (
            "serviceAccount:secure-gateway-cd03d7-offload@"
            "enterprise-secgw-01.iam.gserviceaccount.com"
        ),
        "serviceAccount:shared@example.iam.gserviceaccount.com",
        "serviceAccount:concurrent@example.iam.gserviceaccount.com",
    ]


def _bind_managed_secret_version(
    executor: GoogleResourceExecutor,
) -> None:
    managed_labels = {
        "managed-by": "secure-gateway-studio",
        "configuration-hash": canonical_configuration_hash(spec())[:32],
        "certificate-spec-hash": certificate_configuration_hash(spec())[:32],
        "sgs-active-version": "8",
        "sgs-previous-active": "7",
    }
    executor.bind_ownership_metadata(
        {
            "secretmanager:secret_version:secure-gateway-http-offload-tls": {
                "kind": "secret_version",
                "phase": "applied",
                "secret_url": (
                    "https://secretmanager.googleapis.com/v1/projects/"
                    "enterprise-secgw-01/secrets/secure-gateway-http-offload-tls"
                ),
                "version_name": (
                    "projects/enterprise-secgw-01/secrets/"
                    "secure-gateway-http-offload-tls/versions/8"
                ),
                "managed_before_aliases": {"active": "7"},
                "managed_after_aliases": {"active": "8"},
                "managed_before_labels": {key: None for key in managed_labels},
                "managed_after_labels": managed_labels,
            }
        }
    )


def test_destroy_secret_version_restores_previous_alias_before_destroy() -> None:
    class ManagedVersionTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.metadata = {
                "etag": "secret-etag",
                "versionAliases": {"active": "8"},
                "labels": {
                    "managed-by": "secure-gateway-studio",
                    "configuration-hash": canonical_configuration_hash(spec())[:32],
                    "certificate-spec-hash": certificate_configuration_hash(spec())[:32],
                    "sgs-active-version": "8",
                    "sgs-previous-active": "7",
                },
            }

        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/secrets/secure-gateway-http-offload-tls"):
                self.calls.append({"method": method, "url": url, "params": None, "body": None})
                return 200, deepcopy(self.metadata)
            if method == "PATCH" and url.endswith("/secrets/secure-gateway-http-offload-tls"):
                self.calls.append(
                    {"method": method, "url": url, "params": None, "body": kwargs["json_body"]}
                )
                self.metadata.update(deepcopy(kwargs["json_body"]))
                self.metadata["etag"] = "secret-restored-etag"
                return 200, deepcopy(self.metadata)
            if method == "GET" and url.endswith("/versions/8"):
                self.calls.append({"method": method, "url": url, "params": None, "body": None})
                return 200, {"name": url, "state": "ENABLED"}
            return super().request_json(method, url, **kwargs)

    transport = ManagedVersionTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _bind_managed_secret_version(executor)

    outcome = executor.destroy(
        change(
            "secretmanager",
            "secret_version",
            "secure-gateway-http-offload-tls",
        ),
        spec(),
    )

    assert outcome == "deleted"
    metadata_update = next(
        call
        for call in transport.calls
        if call["method"] == "PATCH" and call["url"].endswith("-tls")
    )
    assert metadata_update["body"]["versionAliases"] == {"active": "7"}
    assert "sgs-active-version" not in metadata_update["body"]["labels"]
    assert "sgs-previous-active" not in metadata_update["body"]["labels"]
    assert any(
        call["method"] == "POST" and call["url"].endswith("/versions/8:destroy")
        for call in transport.calls
    )
    destroy_index = next(
        index
        for index, call in enumerate(transport.calls)
        if call["method"] == "POST" and call["url"].endswith("/versions/8:destroy")
    )
    metadata_index = next(
        index
        for index, call in enumerate(transport.calls)
        if call["method"] == "PATCH" and call["url"].endswith("-tls")
    )
    assert metadata_index < destroy_index


def test_destroy_secret_version_resumes_after_destroy_before_metadata_restore() -> None:
    class DestroyedVersionTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.metadata = {
                "etag": "secret-etag",
                "versionAliases": {},
                "labels": {
                    "managed-by": "secure-gateway-studio",
                    "configuration-hash": canonical_configuration_hash(spec())[:32],
                    "certificate-spec-hash": certificate_configuration_hash(spec())[:32],
                    "sgs-active-version": "8",
                    "sgs-previous-active": "7",
                },
            }

        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/secrets/secure-gateway-http-offload-tls"):
                self.calls.append({"method": method, "url": url, "params": None, "body": None})
                return 200, deepcopy(self.metadata)
            if method == "PATCH" and url.endswith("/secrets/secure-gateway-http-offload-tls"):
                self.calls.append(
                    {"method": method, "url": url, "params": None, "body": kwargs["json_body"]}
                )
                self.metadata.update(deepcopy(kwargs["json_body"]))
                self.metadata["etag"] = "secret-restored-etag"
                return 200, deepcopy(self.metadata)
            if method == "GET" and url.endswith("/versions/8"):
                self.calls.append({"method": method, "url": url, "params": None, "body": None})
                return 200, {"name": url, "state": "DESTROYED"}
            return super().request_json(method, url, **kwargs)

    transport = DestroyedVersionTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _bind_managed_secret_version(executor)

    outcome = executor.destroy(
        change("secretmanager", "secret_version", "secure-gateway-http-offload-tls"),
        spec(),
    )

    assert outcome == "deleted"
    assert not any(call["url"].endswith(":destroy") for call in transport.calls)
    metadata_update = next(call for call in transport.calls if call["method"] == "PATCH")
    assert metadata_update["body"]["versionAliases"] == {"active": "7"}


class LegacyComputeOperationTransport(FakeTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if method == "POST" and url.endswith("/global/networks"):
            super().request_json(
                method,
                url,
                params=params,
                json_body=json_body,
                accepted_statuses=accepted_statuses,
            )
            return 200, {
                "name": "operation-123",
                "status": "PENDING",
                "selfLink": (
                    "https://www.googleapis.com/compute/v1/projects/"
                    "enterprise-secgw-01/global/operations/operation-123"
                ),
            }
        if method == "GET" and "/global/operations/operation-123" in url:
            self.calls.append({"method": method, "url": url, "params": params, "body": json_body})
            return 200, {"name": "operation-123", "status": "DONE"}
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_compute_legacy_operation_self_link_uses_allowlisted_host() -> None:
    transport = LegacyComputeOperationTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    executor.apply(
        change("compute", "network", "secure-gateway-http-offload-vpc"),
        local_poc_spec(),
    )

    operation_read = next(
        call
        for call in transport.calls
        if call["method"] == "GET" and "/global/operations/" in call["url"]
    )
    assert operation_read["url"].startswith("https://compute.googleapis.com/compute/")


def test_create_request_id_is_stable_within_a_run_and_distinct_between_runs() -> None:
    target = change("compute", "network", "secure-gateway-http-offload-vpc")

    def request_id(execution_id: str) -> str:
        transport = FakeTransport()
        executor = GoogleResourceExecutor(
            transport,
            poll_interval_seconds=0,
            execution_id=execution_id,
        )
        executor.apply(target, local_poc_spec())
        create_call = next(
            call
            for call in transport.calls
            if call["method"] == "POST" and call["url"].endswith("/global/networks")
        )
        return str(create_call["params"]["requestId"])

    run_one = "00000000-0000-4000-8000-000000000111"
    run_two = "00000000-0000-4000-8000-000000000222"
    first_attempt = request_id(run_one)
    process_restart_retry = request_id(run_one)
    later_run = request_id(run_two)

    assert first_attempt == process_restart_retry
    assert first_attempt != later_run
    assert uuid.UUID(first_attempt).version == 5
    assert uuid.UUID(later_run).version == 5


@pytest.mark.parametrize(
    ("target", "deployment"),
    [
        (
            change("compute", "network", "secure-gateway-http-offload-vpc"),
            local_poc_spec(),
        ),
        (
            change(
                "beyondcorp",
                "application",
                "secure-gateway-http-offload-app",
            ),
            spec(),
        ),
    ],
)
def test_generic_teardown_retains_a_same_name_replacement(
    target: ResourceChange,
    deployment: DeploymentSpec,
) -> None:
    transport = FakeTransport()
    source = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    source.apply(target, deployment)
    metadata = source.ownership_metadata(target, deployment)
    assert metadata is not None
    resource_url = metadata["resource_url"]
    assert isinstance(resource_url, str)
    replacement = transport.generic_resources[resource_url]
    if target.provider == "compute":
        replacement["id"] = "999999999999"
    else:
        replacement["createTime"] = "2026-08-25T00:00:00Z"

    resumed = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    resource_key = f"{target.provider}:{target.resource_type}:{target.resource_name}"
    resumed.bind_ownership_metadata({resource_key: metadata})
    outcome = resumed.destroy(target, deployment)

    assert outcome == "skipped"
    assert resource_url in transport.generic_resources
    assert not any(
        call["method"] == "DELETE" and call["url"] == resource_url for call in transport.calls
    )


def test_compute_response_loss_reconciles_once_by_durable_marker_and_identity() -> None:
    class LostCreateResponse(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.lose_response = True

        def request_json(self, method, url, **kwargs):
            result = super().request_json(method, url, **kwargs)
            if self.lose_response and method == "POST" and url.endswith("/global/networks"):
                self.lose_response = False
                raise ConnectionError("provider response lost")
            return result

    target = change("compute", "network", "secure-gateway-http-offload-vpc")
    transport = LostCreateResponse()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError) as lost:
        executor.apply(target, local_poc_spec())
    assert lost.value.error_code == "invalid-provider-response-network"
    executor.apply(target, local_poc_spec())

    assert (
        len(
            [
                call
                for call in transport.calls
                if call["method"] == "POST" and call["url"].endswith("/global/networks")
            ]
        )
        == 1
    )
    metadata = executor.ownership_metadata(target, local_poc_spec())
    assert metadata is not None and metadata["phase"] == "applied"


def test_beyondcorp_provider_identity_is_create_time_only() -> None:
    assert (
        GoogleResourceExecutor._generic_provider_identity(
            {"uid": "nonexistent-schema-id"}, "beyondcorp"
        )
        is None
    )
    assert GoogleResourceExecutor._generic_provider_identity(
        {
            "uid": "nonexistent-schema-id",
            "createTime": "2026-08-24T00:00:01Z",
        },
        "beyondcorp",
    ) == ("createTime", "2026-08-24T00:00:01Z")


def test_gateway_replay_accepts_strict_external_ips_and_rejects_non_schema_uid() -> None:
    expected = {
        "displayName": "default",
        "serviceDiscovery": {},
        "logging": {},
    }
    actual: dict[str, object] = {
        **expected,
        "name": "projects/p/locations/global/securityGateways/default",
        "createTime": "2026-08-24T00:00:01Z",
        "externalIps": ["203.0.113.10", "2001:db8::10"],
        "state": "RUNNING",
        "delegatingServiceAccount": "gateway@example.iam.gserviceaccount.com",
    }

    assert GoogleResourceExecutor._provider_payload_contains_expected(actual, expected)
    assert GoogleResourceExecutor._provider_payload_contains_expected(
        {key: value for key, value in actual.items() if key != "externalIps"},
        expected,
    )
    assert not GoogleResourceExecutor._provider_payload_contains_expected(
        {**actual, "uid": "nonexistent-schema-id"}, expected
    )
    assert not GoogleResourceExecutor._provider_payload_contains_expected(
        {**actual, "externalIps": "203.0.113.10"}, expected
    )
    assert not GoogleResourceExecutor._provider_payload_contains_expected(
        {**actual, "externalIps": ["not-an-ip"]}, expected
    )
    assert not GoogleResourceExecutor._provider_payload_contains_expected(
        {**actual, "externalIps": ["203.0.113.10", "203.0.113.10"]}, expected
    )


@pytest.mark.parametrize(
    ("resource_type", "resource_name", "collection_suffix"),
    [
        ("security_gateway", "default", "/securityGateways"),
        ("application", "secure-gateway-http-offload-app", "/applications"),
    ],
)
def test_beyondcorp_response_loss_replays_exact_request_after_restart(
    resource_type: str,
    resource_name: str,
    collection_suffix: str,
) -> None:
    class LostCreateResponse(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.lose_response = True
            self.first_request: dict[str, object] | None = None

        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith(collection_suffix):
                if self.lose_response:
                    super().request_json(method, url, **kwargs)
                    self.first_request = deepcopy(self.calls[-1])
                    self.lose_response = False
                    raise ConnectionError("provider response lost")
                replay = {
                    "method": method,
                    "url": url,
                    "params": deepcopy(kwargs.get("params")),
                    "body": deepcopy(kwargs.get("json_body")),
                }
                assert replay == self.first_request
                self.calls.append(replay)
                provider_id = (kwargs.get("params") or {}).get(
                    "securityGatewayId"
                    if resource_type == "security_gateway"
                    else "applicationId"
                )
                resource_url = f"{url}/{provider_id}"
                return 200, deepcopy(self.generic_resources[resource_url])
            return super().request_json(method, url, **kwargs)

    target = change("beyondcorp", resource_type, resource_name)
    deployment = spec()
    run_id = f"run-beyondcorp-replay-{resource_type}"
    operation_request_id = "00000000-0000-4000-8000-00000000f0bc"
    transport = LostCreateResponse()
    first_writes: list[dict[str, object]] = []
    first = GoogleResourceExecutor(
        transport,
        poll_interval_seconds=0,
        execution_id=run_id,
    )
    _bind_durable_operation(
        first,
        target,
        deployment,
        first_writes,
        request_id=operation_request_id,
    )

    with pytest.raises(ProviderExecutionError):
        first.apply(target, deployment)
    assert first_writes[-1]["phase"] == "sending"

    resumed_writes: list[dict[str, object]] = []
    resumed = GoogleResourceExecutor(
        transport,
        poll_interval_seconds=0,
        execution_id=run_id,
    )
    _bind_durable_operation(
        resumed,
        target,
        deployment,
        resumed_writes,
        checkpoint=first_writes[-1],
        request_id=operation_request_id,
    )
    resumed.apply(target, deployment)

    creates = [
        call
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith(collection_suffix)
    ]
    metadata = resumed.ownership_metadata(target, deployment)
    assert len(creates) == 2
    assert creates[0] == creates[1]
    assert metadata is not None
    assert metadata["phase"] == "applied"
    assert metadata["create_request_id"] == creates[0]["params"]["requestId"]
    assert metadata["provider_identity_field"] == "createTime"
    resource_url = metadata["resource_url"]
    assert isinstance(resource_url, str)
    applied_resource = deepcopy(transport.generic_resources[resource_url])
    if resource_type == "security_gateway":
        transport.generic_resources[resource_url]["serviceDiscovery"] = {
            "apiGateway": {}
        }
    else:
        transport.generic_resources[resource_url]["upstreams"][0][
            "proxyProtocol"
        ] = {}
    drift_writes: list[dict[str, object]] = []
    drifted = GoogleResourceExecutor(
        transport,
        poll_interval_seconds=0,
        execution_id=run_id,
    )
    _bind_durable_operation(
        drifted,
        target,
        deployment,
        drift_writes,
        checkpoint=metadata,
        request_id=operation_request_id,
    )
    with pytest.raises(ProviderExecutionError) as drift:
        drifted.apply(target, deployment)
    assert drift.value.error_code == "generic-resource-managed-state-changed"
    assert len(
        [
            call
            for call in transport.calls
            if call["method"] == "POST" and call["url"].endswith(collection_suffix)
        ]
    ) == 2
    transport.generic_resources[resource_url] = applied_resource
    assert resumed.destroy(target, deployment) == "deleted"
    assert resource_url not in transport.generic_resources


class UnpollableComputeOperationTransport(FakeTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if method == "POST" and url.endswith("/global/networks"):
            super().request_json(
                method,
                url,
                params=params,
                json_body=json_body,
                accepted_statuses=accepted_statuses,
            )
            return 200, {
                "name": "operation-stuck",
                "status": "PENDING",
                "selfLink": (
                    "https://compute.googleapis.com/compute/v1/projects/"
                    "enterprise-secgw-01/global/operations/operation-stuck"
                ),
            }
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_create_polling_failure_cleans_up_accepted_resource() -> None:
    transport = UnpollableComputeOperationTransport()
    executor = GoogleResourceExecutor(
        transport,
        poll_interval_seconds=0,
        operation_timeout_seconds=0,
    )

    with pytest.raises(ProviderExecutionError) as captured:
        executor.apply(
            change("compute", "network", "secure-gateway-http-offload-vpc"),
            local_poc_spec(),
        )

    assert captured.value.error_code == "provider-operation-timeout"

    assert any(
        call["method"] == "DELETE"
        and call["url"].endswith("/global/networks/secure-gateway-http-offload-vpc")
        for call in transport.calls
    )


class SynchronousIamResourceTransport(FakeTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if method == "POST" and url.endswith("/serviceAccounts"):
            self.calls.append({"method": method, "url": url, "params": params, "body": json_body})
            return 200, {
                "name": (
                    "projects/enterprise-secgw-01/serviceAccounts/"
                    "secure-gateway-cd03d7-offload@enterprise-secgw-01.iam.gserviceaccount.com"
                ),
                "email": (
                    "secure-gateway-cd03d7-offload@enterprise-secgw-01.iam.gserviceaccount.com"
                ),
            }
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_synchronous_named_resource_is_not_polled_as_operation() -> None:
    transport = SynchronousIamResourceTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    executor.apply(
        change("iam", "service_account", "secure-gateway-cd03d7-offload"),
        local_poc_spec(),
    )

    assert not any(call["method"] == "GET" for call in transport.calls)


def test_every_planned_resource_has_an_executor() -> None:
    executor = GoogleResourceExecutor(FakeTransport(), poll_interval_seconds=0)
    planned = DesiredStatePlanner().build_plan(spec()).changes
    missing = {
        (item.provider, item.resource_type)
        for item in planned
        if (item.provider, item.resource_type) not in executor._mutations
    }
    assert missing == set()


def test_every_local_poc_resource_has_an_executor() -> None:
    executor = GoogleResourceExecutor(FakeTransport(), poll_interval_seconds=0)
    planned = DesiredStatePlanner().build_plan(local_poc_spec()).changes
    missing = {
        (item.provider, item.resource_type)
        for item in planned
        if (item.provider, item.resource_type) not in executor._mutations
    }
    assert missing == set()


def test_every_internal_https_lb_resource_has_an_executor() -> None:
    executor = GoogleResourceExecutor(FakeTransport(), poll_interval_seconds=0)
    planned = DesiredStatePlanner().build_plan(internal_https_lb_spec()).changes
    missing = {
        (item.provider, item.resource_type)
        for item in planned
        if (item.provider, item.resource_type) not in executor._mutations
    }
    assert missing == set()


def test_internal_https_lb_uses_regional_managed_https_resources() -> None:
    class HealthyInternalLbTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/listInstances"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                return 200, {
                    "items": [
                        {
                            "instance": (
                                "https://www.googleapis.com/compute/v1/projects/"
                                "enterprise-secgw-01/zones/asia-east1-c/instances/"
                                "secure-gateway-http-offload-backend"
                            )
                        }
                    ]
                }
            if method == "POST" and url.endswith("/getHealth"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                return 200, {"healthStatus": [{"healthState": "HEALTHY"}]}
            return super().request_json(method, url, **kwargs)

    deployment = internal_https_lb_spec()
    transport = HealthyInternalLbTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    executor._certificate = CertificateIssuer().issue_local_poc(
        hostname=deployment.private_hostname,
        lifetime_days=deployment.certificate_lifetime_days,
    )

    for resource_type, name in (
        ("subnetwork", f"{deployment.name}-proxy-subnet"),
        ("instance_group", f"{deployment.name}-backend-ig"),
        ("health_check", f"{deployment.name}-ilb-hc"),
        ("backend_service", f"{deployment.name}-ilb-bs"),
        ("ssl_certificate", f"{deployment.name}-ilb-cert"),
        ("url_map", f"{deployment.name}-ilb-map"),
        ("target_https_proxy", f"{deployment.name}-ilb-proxy"),
        ("forwarding_rule", f"{deployment.name}-ilb-fr"),
    ):
        executor.apply(change("compute", resource_type, name), deployment)

    proxy_subnet = next(
        call
        for call in transport.calls
        if call["method"] == "POST"
        and call["url"].endswith("/subnetworks")
        and call["body"]["name"].endswith("-proxy-subnet")
    )["body"]
    assert proxy_subnet["purpose"] == "REGIONAL_MANAGED_PROXY"
    assert proxy_subnet["role"] == "ACTIVE"
    assert proxy_subnet["ipCidrRange"] == "10.42.1.0/24"

    health_check = next(
        call["body"]
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith("/healthChecks")
    )
    assert health_check["type"] == "HTTP"
    assert health_check["httpHealthCheck"]["portSpecification"] == "USE_SERVING_PORT"

    instance_group = next(
        call["body"]
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith("/instanceGroups")
    )
    assert instance_group["namedPorts"] == [{"name": "http", "port": 80}]
    assert "network" not in instance_group
    assert "subnetwork" not in instance_group

    backend_service = next(
        call["body"]
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith("/backendServices")
    )
    assert backend_service["protocol"] == "HTTP"
    assert backend_service["loadBalancingScheme"] == "INTERNAL_MANAGED"
    assert backend_service["portName"] == "http"
    assert backend_service["backends"][0]["group"] == (
        "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/"
        "zones/asia-east1-c/instanceGroups/secure-gateway-http-offload-backend-ig"
    )

    certificate = next(
        call["body"]
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith("/sslCertificates")
    )
    assert certificate["certificate"].startswith("-----BEGIN CERTIFICATE-----")
    assert certificate["privateKey"].startswith("-----BEGIN PRIVATE KEY-----")
    assert certificate_configuration_hash(deployment) in certificate["description"]

    proxy = next(
        call["body"]
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith("/targetHttpsProxies")
    )
    assert proxy["urlMap"].endswith("-ilb-map")
    assert proxy["sslCertificates"][0].endswith("-ilb-cert")

    forwarding_rule = next(
        call["body"]
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith("/forwardingRules")
    )
    assert forwarding_rule["loadBalancingScheme"] == "INTERNAL_MANAGED"
    assert forwarding_rule["ports"] == ["443"]
    assert forwarding_rule["target"].endswith("-ilb-proxy")
    assert "backendService" not in forwarding_rule
    health_call = next(call for call in transport.calls if call["url"].endswith("/getHealth"))
    assert health_call["url"].startswith("https://compute.googleapis.com/compute/v1/")
    assert health_call["body"]["group"] == (
        "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/"
        "zones/asia-east1-c/instanceGroups/secure-gateway-http-offload-backend-ig"
    )


def test_production_autoscaler_uses_configured_capacity_ceiling() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    scaling_spec = spec().model_copy(
        update={
            "offload_min_replicas": 4,
            "offload_max_replicas": 80,
            "offload_cpu_target": 0.55,
        }
    )

    executor.apply(
        change(
            "compute",
            "autoscaler",
            "secure-gateway-http-offload-offload-autoscaler",
        ),
        scaling_spec,
    )

    insert = next(
        call
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith("/autoscalers")
    )
    assert insert["body"]["autoscalingPolicy"] == {
        "minNumReplicas": 4,
        "maxNumReplicas": 80,
        "coolDownPeriodSec": 90,
        "cpuUtilization": {"utilizationTarget": 0.55},
        "mode": "ON",
    }
    assert insert["body"]["target"].endswith(
        "/instanceGroupManagers/secure-gateway-http-offload-offload-mig"
    )


def test_offload_vm_has_no_external_ip_and_no_private_key_in_metadata() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    bind_source_image_plan(executor, spec())

    executor.apply(
        change("compute", "instance", "secure-gateway-http-offload-offload"),
        spec(),
    )

    insert = next(
        call
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith("/instances")
    )
    body = insert["body"]
    assert "accessConfigs" not in body["networkInterfaces"][0]
    assert body["networkInterfaces"][0]["networkIP"] == "10.42.0.10"
    script = body["metadata"]["items"][0]["value"]
    metadata = {item["key"]: item["value"] for item in body["metadata"]["items"]}
    assert "BEGIN PRIVATE KEY" not in script
    assert "secretmanager.googleapis.com" in script
    assert "configuration_hash" in script
    assert metadata["enable-guest-attributes"] == "TRUE"
    assert "log_format sgstudio_offload escape=json" in script
    assert '"host":"$host"' not in script
    assert '"uri":"$uri"' not in script
    assert "proxy_set_header X-Request-ID $request_id;" in script
    assert "add_header X-Request-ID $request_id always;" in script
    assert '"upstream_status":"$upstream_status"' in script
    assert body["shieldedInstanceConfig"]["enableSecureBoot"] is True
    assert body["disks"][0]["initializeParams"]["sourceImage"] == (
        "projects/enterprise-secgw-01/global/images/sgs-nginx-20260730"
    )
    assert "apt-get" not in script
    assert "command -v nginx" in script
    assert "/versions/active:access" in script


def test_instance_postcondition_rejects_recreated_source_image_before_readiness() -> None:
    class WrongDiskImageTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            status, payload = super().request_json(method, url, **kwargs)
            if method == "GET" and "/zones/asia-east1-c/disks/" in url:
                payload = {**payload, "sourceImageId": "123456789"}
            return status, payload

    deployment = spec()
    transport = WrongDiskImageTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    bind_source_image_plan(executor, deployment)

    with pytest.raises(ProviderExecutionError) as captured:
        executor.apply(
            change("compute", "instance", f"{deployment.name}-offload"),
            deployment,
        )

    assert captured.value.error_code == "instance-boot-disk-identity-invalid"
    assert not any(call["url"].endswith("/getGuestAttributes") for call in transport.calls)


def test_backend_vm_logs_the_propagated_request_id_as_structured_json() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    bind_source_image_plan(executor, spec())

    executor.apply(
        change("compute", "instance", "secure-gateway-http-offload-backend"),
        spec(),
    )

    insert = next(
        call
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith("/instances")
    )
    script = insert["body"]["metadata"]["items"][0]["value"]

    assert "log_format sgstudio_backend escape=json" in script
    assert '"host":"$host"' not in script
    assert '"uri":"$uri"' not in script
    assert '"request_id":"$http_x_request_id"' in script
    assert "access_log /var/log/nginx/sgstudio-access.log" in script


def test_instance_apply_rolls_back_when_runtime_readiness_never_arrives() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(
        transport,
        poll_interval_seconds=0,
        operation_timeout_seconds=0,
    )
    bind_source_image_plan(executor, spec())

    with pytest.raises(ProviderExecutionError) as captured:
        executor.apply(
            change("compute", "instance", "secure-gateway-http-offload-backend"),
            spec(),
        )

    assert captured.value.error_code == "instance-readiness-timeout"
    assert any(
        call["method"] == "DELETE"
        and call["url"].endswith("/instances/secure-gateway-http-offload-backend")
        for call in transport.calls
    )


def test_generated_startup_scripts_are_valid_bash() -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash is not available on this platform")
    executor = GoogleResourceExecutor(FakeTransport(), poll_interval_seconds=0)

    for script in (
        executor._backend_startup_script(spec()),
        executor._offload_startup_script(spec()),
    ):
        result = subprocess.run(
            ["bash", "-n"],
            check=False,
            input=script,
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr


def test_public_tls_startup_uses_only_approved_numeric_secret_version() -> None:
    deployment = public_tls_spec()
    payload = (
        CertificateIssuer()
        .issue_local_poc(
            hostname=deployment.private_hostname,
            lifetime_days=90,
        )
        .secret_payload()
    )
    transport = PublicCertificateTransport(payload)
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    bind_public_certificate_plan(executor, deployment, payload)

    executor.prepare_apply(deployment)
    script = executor._offload_startup_script(deployment)

    assert "/versions/7:access" in script
    assert "/versions/latest:access" not in script
    assert "pin_presented_chain = False" in script
    assert '"public_system_roots"' in script
    assert "if pin_presented_chain:\n        context.load_verify_locations" in script


def test_private_tls_startup_pins_the_presented_certificate_chain() -> None:
    executor = GoogleResourceExecutor(FakeTransport(), poll_interval_seconds=0)

    script = executor._offload_startup_script(spec())

    assert "pin_presented_chain = True" in script
    assert '"presented_chain_pinned"' in script
    assert "if pin_presented_chain:\n        context.load_verify_locations" in script


def test_public_tls_ilb_uses_the_same_apply_validated_payload_bytes() -> None:
    deployment = public_tls_spec(
        backend_kind=BackendKind.INTERNAL_HTTPS_LB,
        proxy_subnet_cidr="10.42.1.0/24",
    )
    bundle = CertificateIssuer().issue_local_poc(
        hostname=deployment.private_hostname,
        lifetime_days=90,
    )
    payload = bundle.secret_payload()
    transport = PublicCertificateTransport(payload)
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    bind_public_certificate_plan(executor, deployment, payload)

    executor.prepare_apply(deployment)
    executor.apply(
        change("compute", "ssl_certificate", f"{deployment.name}-ilb-cert"),
        deployment,
    )

    secret_reads = [
        call for call in transport.calls if call["url"].endswith("/versions/latest:access")
    ]
    certificate_create = next(
        call
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith("/sslCertificates")
    )
    assert len(secret_reads) == 2
    assert certificate_create["body"]["certificate"] == (
        bundle.certificate_pem + b"".join(bundle.certificate_chain_pem)
    ).decode("ascii")


@pytest.mark.parametrize(
    "failure",
    ["alias-drift", "crc", "digest", "pki"],
)
def test_public_tls_apply_revalidation_fails_before_external_mutation(
    failure: str,
) -> None:
    deployment = public_tls_spec()
    approved_payload = (
        CertificateIssuer()
        .issue_local_poc(
            hostname=deployment.private_hostname,
            lifetime_days=90,
        )
        .secret_payload()
    )
    actual_payload = approved_payload
    if failure == "digest":
        actual_payload = (
            CertificateIssuer()
            .issue_local_poc(
                hostname=deployment.private_hostname,
                lifetime_days=90,
            )
            .secret_payload()
        )
    elif failure == "pki":
        actual_payload = (
            CertificateIssuer()
            .issue_local_poc(
                hostname="other.internal",
                lifetime_days=90,
            )
            .secret_payload()
        )
        approved_payload = actual_payload
    transport = PublicCertificateTransport(
        actual_payload,
        version=8 if failure == "alias-drift" else 7,
        corrupt_crc=failure == "crc",
    )
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    bind_public_certificate_plan(executor, deployment, approved_payload)

    with pytest.raises(ProviderExecutionError) as captured:
        executor.prepare_apply(deployment)

    assert captured.value.error_code == "public-certificate-binding-invalid"
    assert {call["method"] for call in transport.calls} == {"GET"}


def test_public_tls_executor_refuses_mutation_until_revalidation_completes() -> None:
    deployment = public_tls_spec()
    payload = (
        CertificateIssuer()
        .issue_local_poc(
            hostname=deployment.private_hostname,
            lifetime_days=90,
        )
        .secret_payload()
    )
    transport = PublicCertificateTransport(payload)
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    bind_public_certificate_plan(executor, deployment, payload)

    with pytest.raises(ProviderExecutionError) as captured:
        executor.apply(
            change("serviceusage", "project_services", "required-apis"),
            deployment,
        )

    assert captured.value.error_code == "public-certificate-not-revalidated"
    assert transport.calls == []


@pytest.mark.parametrize(
    "consumer",
    ["poc-instance", "production-template", "ilb-certificate"],
)
def test_public_tls_alias_flip_blocks_each_consumer_before_its_mutation(
    consumer: str,
) -> None:
    if consumer == "poc-instance":
        deployment = public_tls_spec()
        target = change("compute", "instance", f"{deployment.name}-offload")
        mutation_suffix = "/instances"
    elif consumer == "production-template":
        deployment = public_tls_spec(
            mode=DeploymentMode.PRODUCTION,
            source_image=("projects/enterprise-secgw-01/global/images/sgs-nginx-20260730"),
        )
        target = change(
            "compute",
            "instance_template",
            f"{deployment.name}-offload-template",
        )
        mutation_suffix = "/instanceTemplates"
    else:
        deployment = public_tls_spec(
            backend_kind=BackendKind.INTERNAL_HTTPS_LB,
            proxy_subnet_cidr="10.42.1.0/24",
        )
        target = change(
            "compute",
            "ssl_certificate",
            f"{deployment.name}-ilb-cert",
        )
        mutation_suffix = "/sslCertificates"
    payload = (
        CertificateIssuer()
        .issue_local_poc(
            hostname=deployment.private_hostname,
            lifetime_days=90,
        )
        .secret_payload()
    )
    transport = PublicCertificateTransport(payload)
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    bind_public_certificate_plan(executor, deployment, payload)
    executor.prepare_apply(deployment)
    transport.version = 8
    transport.calls.clear()

    with pytest.raises(ProviderExecutionError) as captured:
        executor.apply(target, deployment)

    assert captured.value.error_code == "public-certificate-binding-invalid"
    assert not any(
        call["method"] == "POST" and call["url"].endswith(mutation_suffix)
        for call in transport.calls
    )
    assert all(call["method"] == "GET" for call in transport.calls)


def test_offload_startup_restarts_nginx_after_writing_tls_configuration() -> None:
    executor = GoogleResourceExecutor(FakeTransport(), poll_interval_seconds=0)
    script = executor._offload_startup_script(spec())

    assert "systemctl enable nginx\nsystemctl restart nginx" in script
    assert script.index("cat >/etc/nginx/sites-available/default") < script.index(
        "systemctl restart nginx"
    )


def test_secret_rotation_uses_active_alias_and_compensates_ca_certificate() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _, rotation_csr = CertificateIssuer.prepare_enterprise_request("demo-server-http.internal")
    rotation_name = (
        "projects/enterprise-secgw-01/locations/asia-east1/caPools/"
        "enterprise/certificates/rotation-test"
    )
    executor._certificate = replace(
        CertificateIssuer().issue_local_poc(
            hostname="demo-server-http.internal",
            lifetime_days=90,
        ),
        issuer_resource_name=rotation_name,
        csr_sha256=hashlib.sha256(rotation_csr).hexdigest(),
        issuer_certificate_authority=spec().ca_name,
    )
    transport.private_ca_certificates[f"https://privateca.googleapis.com/v1/{rotation_name}"] = {
        "name": rotation_name,
        "pemCsr": rotation_csr.decode("ascii"),
        "issuerCertificateAuthority": spec().ca_name,
    }
    version_change = change(
        "secretmanager",
        "secret_version",
        "secure-gateway-http-offload-tls",
    )

    executor.apply(version_change, spec())
    executor.rollback(version_change, spec())

    alias_updates = [
        call
        for call in transport.calls
        if call["method"] == "PATCH"
        and call["url"].endswith("/secrets/secure-gateway-http-offload-tls")
    ]
    assert alias_updates[0]["params"] == {"updateMask": "versionAliases,labels"}
    assert alias_updates[0]["body"]["versionAliases"]["active"] == "8"
    assert (
        alias_updates[0]["body"]["labels"]["configuration-hash"]
        == (canonical_configuration_hash(spec())[:32])
    )
    assert (
        alias_updates[0]["body"]["labels"]["certificate-spec-hash"]
        == (certificate_configuration_hash(spec())[:32])
    )
    assert alias_updates[0]["body"]["labels"]["sgs-active-version"] == "8"
    assert alias_updates[0]["body"]["labels"]["sgs-previous-active"] == "7"
    assert alias_updates[-1]["body"]["versionAliases"]["active"] == "7"
    assert alias_updates[-1]["body"]["labels"] == {}
    assert any(call["url"].endswith("/versions/8:disable") for call in transport.calls)
    revoke = next(call for call in transport.calls if call["url"].endswith(":revoke"))
    assert revoke["body"]["reason"] == "CESSATION_OF_OPERATION"


@pytest.mark.parametrize("etag", [None, ""])
def test_secret_metadata_requires_a_nonempty_etag_before_patch(
    etag: str | None,
) -> None:
    transport = FakeTransport()
    if etag is None:
        transport.secret.pop("etag")
    else:
        transport.secret["etag"] = etag
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    secret_url = (
        "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/"
        "secrets/secure-gateway-http-offload-tls"
    )

    with pytest.raises(ProviderExecutionError) as captured:
        executor._set_secret_metadata(
            secret_url,
            {"active": "8"},
            {"managed-by": "secure-gateway-studio"},
        )

    assert captured.value.error_code == "secret-metadata-etag-missing"
    assert not any(call["method"] == "PATCH" for call in transport.calls)


def test_secret_metadata_conflict_remerges_fresh_unmanaged_keys() -> None:
    class SecretConflictTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.secret["versionAliases"]["administrator"] = "3"
            self.secret["labels"]["administrator"] = "retained"
            self.conflicted = False

        def request_json(self, method, url, **kwargs):
            if method == "PATCH" and url.endswith("/secrets/secure-gateway-http-offload-tls"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body")),
                    }
                )
                if not self.conflicted:
                    self.conflicted = True
                    self.secret["etag"] = "secret-concurrent-etag"
                    self.secret["versionAliases"]["concurrent"] = "4"
                    self.secret["labels"]["concurrent"] = "preserved"
                    raise GoogleApiError(
                        status_code=400,
                        method="PATCH",
                        host="secretmanager.googleapis.com",
                        detail='{"error":{"status":"FAILED_PRECONDITION"}}',
                    )
                self.secret.update(deepcopy(kwargs["json_body"]))
                self.secret["etag"] = "secret-applied-etag"
                return 200, deepcopy(self.secret)
            return super().request_json(method, url, **kwargs)

    transport = SecretConflictTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    secret_url = (
        "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/"
        "secrets/secure-gateway-http-offload-tls"
    )

    executor._set_secret_metadata(
        secret_url,
        {"active": "8", "administrator": "3"},
        {
            "administrator": "retained",
            "managed-by": "secure-gateway-studio",
        },
    )

    patches = [call for call in transport.calls if call["method"] == "PATCH"]
    assert [call["body"]["etag"] for call in patches] == [
        "secret-etag",
        "secret-concurrent-etag",
    ]
    assert transport.secret["versionAliases"] == {
        "active": "8",
        "administrator": "3",
        "concurrent": "4",
    }
    assert transport.secret["labels"] == {
        "administrator": "retained",
        "concurrent": "preserved",
        "managed-by": "secure-gateway-studio",
    }


def test_secret_metadata_conflict_fails_closed_on_a_managed_key_edit() -> None:
    class ManagedSecretConflictTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "PATCH" and url.endswith("/secrets/secure-gateway-http-offload-tls"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body")),
                    }
                )
                self.secret["etag"] = "secret-concurrent-etag"
                self.secret["versionAliases"]["active"] = "9"
                raise GoogleApiError(
                    status_code=400,
                    method="PATCH",
                    host="secretmanager.googleapis.com",
                    detail='{"error":{"status":"FAILED_PRECONDITION"}}',
                )
            return super().request_json(method, url, **kwargs)

    transport = ManagedSecretConflictTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    secret_url = (
        "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/"
        "secrets/secure-gateway-http-offload-tls"
    )

    with pytest.raises(ProviderExecutionError) as captured:
        executor._set_secret_metadata(secret_url, {"active": "8"}, {})

    assert captured.value.error_code == "secret-metadata-concurrent-change"
    assert len([call for call in transport.calls if call["method"] == "PATCH"]) == 1


@pytest.mark.parametrize(
    ("status_code", "canonical_status"),
    [(400, "INVALID_ARGUMENT"), (409, "ABORTED")],
)
def test_secret_metadata_does_not_retry_a_non_etag_error(
    status_code: int,
    canonical_status: str,
) -> None:
    class NonEtagErrorTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "PATCH" and url.endswith("/secrets/secure-gateway-http-offload-tls"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body")),
                    }
                )
                raise GoogleApiError(
                    status_code=status_code,
                    method="PATCH",
                    host="secretmanager.googleapis.com",
                    detail=json.dumps({"error": {"status": canonical_status}}),
                )
            return super().request_json(method, url, **kwargs)

    transport = NonEtagErrorTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    secret_url = (
        "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/"
        "secrets/secure-gateway-http-offload-tls"
    )

    with pytest.raises(GoogleApiError):
        executor._set_secret_metadata(secret_url, {"active": "8"}, {})

    assert len([call for call in transport.calls if call["method"] == "PATCH"]) == 1


def test_add_secret_version_rejects_a_cross_secret_response_name() -> None:
    class CrossSecretVersionTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith(":addVersion"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                return 200, {"name": ("projects/enterprise-secgw-01/secrets/other/versions/8")}
            return super().request_json(method, url, **kwargs)

    transport = CrossSecretVersionTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "secretmanager",
        "secret_version",
        "secure-gateway-http-offload-tls",
    )

    with pytest.raises(ProviderExecutionError) as captured:
        executor.apply(target, local_poc_spec())

    assert captured.value.error_code == "secret-version-name-invalid"
    assert executor.ownership_metadata(target, local_poc_spec())["phase"] == "sending"
    assert not any(call["method"] == "PATCH" for call in transport.calls)


def test_add_secret_version_definitive_400_is_rejected_and_compensated() -> None:
    class RejectedSecretVersionTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith(":addVersion"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                raise GoogleApiError(
                    status_code=400,
                    method="POST",
                    host="secretmanager.googleapis.com",
                    detail='{"error":{"status":"INVALID_ARGUMENT"}}',
                )
            return super().request_json(method, url, **kwargs)

    transport = RejectedSecretVersionTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "secretmanager",
        "secret_version",
        "secure-gateway-http-offload-tls",
    )
    checkpoints: list[dict[str, object]] = []
    _bind_durable_operation(executor, target, local_poc_spec(), checkpoints)

    with pytest.raises(ProviderExecutionError) as captured:
        executor.apply(target, local_poc_spec())

    assert captured.value.error_code == ("google-api-400-secretmanager-invalid-argument")
    assert [checkpoint["phase"] for checkpoint in checkpoints] == [
        "prepared",
        "sending",
        "rejected",
    ]
    assert executor._certificate is None
    assert not any(call["method"] == "PATCH" for call in transport.calls)
    executor.rollback(target, local_poc_spec())


def test_enterprise_certificate_step_owns_and_revokes_the_exact_run_resource() -> None:
    execution_id = "00000000-0000-4000-8000-000000000123"
    deployment = spec()
    expected_name = f"{deployment.ca_pool}/certificates/{deployment.name[:40]}-tls-000000000000"
    transport = FakeTransport()
    executor = GoogleResourceExecutor(
        transport,
        poll_interval_seconds=0,
        execution_id=execution_id,
    )
    executor._certificate = replace(
        CertificateIssuer().issue_local_poc(
            hostname=deployment.private_hostname,
            lifetime_days=deployment.certificate_lifetime_days,
        ),
        issuer_resource_name=expected_name,
    )
    certificate_change = change(
        "privateca",
        "certificate",
        f"{deployment.name}-certificate",
    )

    executor.apply(certificate_change, deployment)
    ownership = deepcopy(executor._ownership_metadata[executor._key(certificate_change)])
    executor._save_checkpoint({**ownership, "phase": "applied"})
    assert executor._enterprise_request is not None
    issued_csr = executor._enterprise_request[1]
    transport.private_ca_certificates[f"https://privateca.googleapis.com/v1/{expected_name}"] = {
        "name": expected_name,
        "pemCsr": issued_csr.decode("ascii"),
        "issuerCertificateAuthority": deployment.ca_name,
    }
    executor.rollback(certificate_change, deployment)

    exact_url = f"https://privateca.googleapis.com/v1/{expected_name}"
    assert any(call["method"] == "GET" and call["url"] == exact_url for call in transport.calls)
    revoke = next(call for call in transport.calls if call["url"] == f"{exact_url}:revoke")
    assert revoke["body"]["reason"] == "CESSATION_OF_OPERATION"
    assert isinstance(revoke["body"]["requestId"], str)


def test_enterprise_certificate_teardown_is_idempotent_and_exact() -> None:
    execution_id = "00000000-0000-4000-8000-000000000123"
    deployment = spec()
    transport = FakeTransport()
    executor = GoogleResourceExecutor(
        transport,
        poll_interval_seconds=0,
        execution_id=execution_id,
    )

    certificate_change = change("privateca", "certificate", f"{deployment.name}-certificate")
    ownership = executor.preclaim_metadata(certificate_change, deployment)
    assert executor._enterprise_request is not None
    teardown_csr = executor._enterprise_request[1]
    expected_name = str(ownership["certificate_name"])
    transport.private_ca_certificates[f"https://privateca.googleapis.com/v1/{expected_name}"] = {
        "name": expected_name,
        "pemCsr": teardown_csr.decode("ascii"),
        "issuerCertificateAuthority": deployment.ca_name,
    }

    outcome = executor.destroy(
        certificate_change,
        deployment,
    )

    assert outcome == "deleted"
    assert any(
        call["method"] == "POST"
        and call["url"] == f"https://privateca.googleapis.com/v1/{expected_name}:revoke"
        for call in transport.calls
    )


def test_enterprise_certificate_name_collision_is_never_revoked() -> None:
    deployment = spec()
    transport = FakeTransport()
    executor = GoogleResourceExecutor(
        transport,
        poll_interval_seconds=0,
        execution_id="00000000-0000-4000-8000-000000000123",
    )
    certificate_change = change("privateca", "certificate", f"{deployment.name}-certificate")
    ownership = executor.preclaim_metadata(certificate_change, deployment)
    certificate_name = str(ownership["certificate_name"])
    transport.private_ca_certificates[f"https://privateca.googleapis.com/v1/{certificate_name}"] = {
        "name": certificate_name,
        "pemCsr": "-----BEGIN CERTIFICATE REQUEST-----\nother\n-----END CERTIFICATE REQUEST-----",
        "issuerCertificateAuthority": deployment.ca_name,
    }

    with pytest.raises(ProviderExecutionError) as captured:
        executor.rollback(certificate_change, deployment)

    assert not any(call["url"].endswith(":revoke") for call in transport.calls)
    assert captured.value.error_code == "privateca-certificate-ownership-mismatch"


def test_enterprise_certificate_pre_send_restart_replaces_only_absent_csr() -> None:
    deployment = spec()
    certificate_change = change("privateca", "certificate", f"{deployment.name}-certificate")
    first = GoogleResourceExecutor(FakeTransport(), poll_interval_seconds=0)
    ownership = first.preclaim_metadata(certificate_change, deployment)
    old_digest = ownership["csr_sha256"]

    restarted = GoogleResourceExecutor(FakeTransport(), poll_interval_seconds=0)
    restarted.bind_ownership_metadata(
        {f"privateca:certificate:{deployment.name}-certificate": ownership}
    )

    replacement = restarted.preclaim_metadata(certificate_change, deployment)

    assert replacement["phase"] == "prepared"
    assert replacement["certificate_name"] == ownership["certificate_name"]
    assert replacement["csr_sha256"] != old_digest
    assert restarted._enterprise_request is not None


def test_enterprise_certificate_response_loss_revokes_exact_lost_key_resource() -> None:
    deployment = spec()
    certificate_change = change("privateca", "certificate", f"{deployment.name}-certificate")
    seed_transport = FakeTransport()
    first = GoogleResourceExecutor(seed_transport, poll_interval_seconds=0)
    ownership = first.preclaim_metadata(certificate_change, deployment)
    assert first._enterprise_request is not None
    csr = first._enterprise_request[1]
    sending = {**ownership, "phase": "sending"}
    certificate_name = str(ownership["certificate_name"])

    transport = FakeTransport()
    transport.private_ca_certificates[f"https://privateca.googleapis.com/v1/{certificate_name}"] = {
        "name": certificate_name,
        "pemCsr": csr.decode("ascii"),
        "issuerCertificateAuthority": deployment.ca_name,
    }
    restarted = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    restarted.bind_ownership_metadata(
        {f"privateca:certificate:{deployment.name}-certificate": sending}
    )

    with pytest.raises(ProviderExecutionError) as captured:
        restarted.apply(certificate_change, deployment)

    assert captured.value.error_code == ("privateca-certificate-private-key-unrecoverable")
    assert any(call["url"].endswith(":revoke") for call in transport.calls)
    assert not any(
        call["method"] == "POST" and call["url"].endswith("/certificates")
        for call in transport.calls
    )
    restarted.rollback(certificate_change, deployment)


def test_enterprise_certificate_ambiguous_absence_retains_claim() -> None:
    deployment = spec()
    certificate_change = change("privateca", "certificate", f"{deployment.name}-certificate")
    first = GoogleResourceExecutor(FakeTransport(), poll_interval_seconds=0)
    ownership = first.preclaim_metadata(certificate_change, deployment)
    sending = {**ownership, "phase": "sending"}
    restarted = GoogleResourceExecutor(FakeTransport(), poll_interval_seconds=0)
    restarted.bind_ownership_metadata(
        {f"privateca:certificate:{deployment.name}-certificate": sending}
    )

    with pytest.raises(ProviderExecutionError):
        restarted.apply(certificate_change, deployment)
    with pytest.raises(ProviderExecutionError) as rollback:
        restarted.rollback(certificate_change, deployment)

    assert rollback.value.error_code == ("privateca-certificate-provider-response-ambiguous")


@pytest.mark.parametrize(
    ("status_code", "expected_phase", "rollback_succeeds"),
    [
        (403, "rejected", True),
        (408, "sending", False),
        (429, "sending", False),
        (503, "sending", False),
    ],
)
def test_enterprise_certificate_http_rejection_phase_is_status_aware(
    status_code: int,
    expected_phase: str,
    rollback_succeeds: bool,
) -> None:
    class RejectingPrivateCaTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/certificates"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body") or {}),
                    }
                )
                raise GoogleApiError(
                    status_code=status_code,
                    method=method,
                    host="privateca.googleapis.com",
                    detail="fixture rejection",
                )
            return super().request_json(method, url, **kwargs)

    deployment = spec()
    target = change("privateca", "certificate", f"{deployment.name}-certificate")
    transport = RejectingPrivateCaTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError):
        executor.apply(target, deployment)

    checkpoint = executor.ownership_metadata(target, deployment)
    assert checkpoint is not None
    assert checkpoint["phase"] == expected_phase
    if rollback_succeeds:
        executor.rollback(target, deployment)
    else:
        with pytest.raises(ProviderExecutionError) as captured:
            executor.rollback(target, deployment)
        assert captured.value.error_code == (
            "privateca-certificate-provider-response-ambiguous"
        )


def test_enterprise_certificate_terminal_lro_error_is_definitely_rejected() -> None:
    class FailedPrivateCaOperationTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/certificates"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body") or {}),
                    }
                )
                return 200, {
                    "name": "projects/enterprise-secgw-01/locations/asia-east1/operations/failed",
                    "done": True,
                    "error": {"code": 7, "message": "denied"},
                }
            return super().request_json(method, url, **kwargs)

    deployment = spec()
    target = change("privateca", "certificate", f"{deployment.name}-certificate")
    executor = GoogleResourceExecutor(
        FailedPrivateCaOperationTransport(),
        poll_interval_seconds=0,
    )

    with pytest.raises(ProviderExecutionError):
        executor.apply(target, deployment)

    checkpoint = executor.ownership_metadata(target, deployment)
    assert checkpoint is not None
    assert checkpoint["phase"] == "rejected"
    executor.rollback(target, deployment)


class RefreshTransport(FakeTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if method == "GET" and "/instanceGroupManagers/" in url:
            self.calls.append({"method": method, "url": url, "params": params, "body": json_body})
            return 200, {
                "status": {
                    "isStable": True,
                    "currentInstanceStatuses": {"running": 2},
                }
            }
        if method == "POST" and url.endswith("/getHealth"):
            self.calls.append({"method": method, "url": url, "params": params, "body": json_body})
            return 200, {
                "healthStatus": [
                    {"healthState": "HEALTHY"},
                    {"healthState": "HEALTHY"},
                ]
            }
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_production_certificate_refresh_restarts_all_mig_instances() -> None:
    transport = RefreshTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    bind_source_image_plan(executor, spec())

    executor.apply(
        change(
            "compute",
            "offload_refresh",
            "secure-gateway-http-offload-certificate-refresh",
        ),
        spec(),
    )

    refresh = next(
        call for call in transport.calls if call["url"].endswith("/applyUpdatesToInstances")
    )
    assert refresh["body"] == {
        "allInstances": True,
        "minimalAction": "RESTART",
        "mostDisruptiveAllowedAction": "RESTART",
    }
    assert refresh["params"] is None


def test_chrome_policy_uses_runtime_schema_target_key_and_can_inherit_on_rollback() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    policy_change = change(
        "chromepolicy",
        "extension_install",
        "ekajlcmdfcigmdbphhifahdfjbkciflj",
    )

    executor.apply(policy_change, spec())
    executor.rollback(policy_change, spec())

    modify = next(call for call in transport.calls if call["url"].endswith(":batchModify"))
    request = modify["body"]["requests"][0]
    assert request["policyTargetKey"]["additionalTargetKeys"] == {
        "app_id": "chrome:ekajlcmdfcigmdbphhifahdfjbkciflj"
    }
    assert request["policyValue"]["value"]["appInstallType"] == "FORCED"
    assert any(call["url"].endswith(":batchInherit") for call in transport.calls)


def test_chrome_policy_apply_and_rollback_follow_all_resolve_pages() -> None:
    class PagedResolveTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/policies:resolve"):
                body = kwargs.get("json_body") or {}
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(body),
                    }
                )
                if "pageToken" not in body:
                    return 200, {"resolvedPolicies": [], "nextPageToken": "page-2"}
                assert body["pageToken"] == "page-2"
                target = body["policyTargetKey"]
                policy_key = json.dumps(
                    {"schema": body["policySchemaFilter"], "target": target},
                    sort_keys=True,
                )
                current = self.chrome_policies.get(policy_key)
                return 200, {
                    "resolvedPolicies": (
                        [
                            {
                                "targetKey": deepcopy(target),
                                "sourceKey": {
                                    "targetResource": target["targetResource"],
                                },
                                "value": deepcopy(current),
                            }
                        ]
                        if current is not None
                        else []
                    )
                }
            return super().request_json(method, url, **kwargs)

    transport = PagedResolveTransport()
    target = {
        "targetResource": "orgunits/03-test-ou",
        "additionalTargetKeys": {
            "app_id": "chrome:ekajlcmdfcigmdbphhifahdfjbkciflj",
        },
    }
    policy_key = json.dumps(
        {"schema": "chrome.users.apps.InstallType", "target": target},
        sort_keys=True,
    )
    transport.chrome_policies[policy_key] = {
        "policySchema": "chrome.users.apps.InstallType",
        "value": {"appInstallType": "BLOCKED"},
    }
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    policy_change = change(
        "chromepolicy",
        "extension_install",
        "ekajlcmdfcigmdbphhifahdfjbkciflj",
    )

    executor.apply(policy_change, spec())
    executor.rollback(policy_change, spec())

    resolve_calls = [
        call for call in transport.calls if call["url"].endswith("/policies:resolve")
    ]
    assert len(resolve_calls) == 4
    assert all(call["body"]["pageSize"] == 1_000 for call in resolve_calls)
    assert [call["body"].get("pageToken") for call in resolve_calls] == [
        None,
        "page-2",
        None,
        "page-2",
    ]
    assert transport.chrome_policies[policy_key]["value"]["appInstallType"] == "BLOCKED"


@pytest.mark.parametrize("token", [None, 17, "repeat"])
def test_chrome_policy_resolve_pagination_failure_prevents_mutation(token: object) -> None:
    class InvalidPaginationTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/policies:resolve"):
                body = kwargs.get("json_body") or {}
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(body),
                    }
                )
                return 200, {"resolvedPolicies": [], "nextPageToken": token}
            return super().request_json(method, url, **kwargs)

    transport = InvalidPaginationTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError):
        executor.apply(
            change(
                "chromepolicy",
                "extension_install",
                "ekajlcmdfcigmdbphhifahdfjbkciflj",
            ),
            spec(),
        )

    assert not any(call["url"].endswith(":batchModify") for call in transport.calls)


def test_chrome_policy_rechecks_non_root_ou_before_any_mutation() -> None:
    class RootOuTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and "admin.googleapis.com" in url and "/orgunits/id%3A" in url:
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                return 200, {"orgUnitId": "id:03-test-ou", "orgUnitPath": "/"}
            return super().request_json(method, url, **kwargs)

    transport = RootOuTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError) as captured:
        executor.apply(
            change(
                "chromepolicy",
                "extension_install",
                "ekajlcmdfcigmdbphhifahdfjbkciflj",
            ),
            spec(),
        )

    assert captured.value.error_code == "chrome-policy-target-ou-invalid"
    assert not any(
        call["url"].endswith((":batchModify", ":batchInherit")) for call in transport.calls
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
                    "sourceKey": {"targetResource": "groups/not-an-ou"},
                    "value": {
                        "policySchema": "chrome.users.apps.InstallType",
                        "value": {"appInstallType": "BLOCKED"},
                    },
                }
            ]
        },
        {
            "resolvedPolicies": [
                {
                    "sourceKey": {"targetResource": "orgunits/03-test-ou"},
                    "value": {
                        "policySchema": "chrome.users.apps.InstallType",
                        "value": {"appInstallType": "BLOCKED"},
                    },
                }
            ]
        },
        {
            "resolvedPolicies": [
                {
                    "sourceKey": {
                        "targetResource": "orgunits/03-test-ou",
                        "additionalTargetKeys": {"app_id": "chrome:different-extension"},
                    },
                    "value": {
                        "policySchema": "chrome.users.apps.InstallType",
                        "value": {"appInstallType": "BLOCKED"},
                    },
                }
            ]
        },
        {
            "resolvedPolicies": [
                {
                    "sourceKey": {
                        "targetResource": "orgunits/03-test-ou",
                        "additionalTargetKeys": {
                            "app_id": ("chrome:ekajlcmdfcigmdbphhifahdfjbkciflj"),
                            "extra": "unexpected",
                        },
                    },
                    "value": {
                        "policySchema": "chrome.users.apps.InstallType",
                        "value": {"appInstallType": "BLOCKED"},
                    },
                }
            ]
        },
        {
            "resolvedPolicies": [
                {
                    "sourceKey": {"targetResource": "orgunits/03-test-ou"},
                    "value": {"value": {"appInstallType": "BLOCKED"}},
                }
            ]
        },
        {
            "resolvedPolicies": [
                {
                    "sourceKey": {"targetResource": "orgunits/03-test-ou"},
                    "value": {
                        "policySchema": "chrome.users.apps.InstallType",
                        "value": {"appInstallType": "BLOCKED"},
                    },
                },
                {
                    "sourceKey": {"targetResource": "orgunits/03-test-ou"},
                    "value": {
                        "policySchema": "chrome.users.apps.InstallType",
                        "value": {"appInstallType": "ALLOWED"},
                    },
                },
            ]
        },
    ],
)
def test_chrome_policy_apply_rejects_malformed_before_image_without_mutation(
    resolved_payload: dict[str, object],
) -> None:
    class MalformedResolveTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/policies:resolve"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                return 200, resolved_payload
            return super().request_json(method, url, **kwargs)

    transport = MalformedResolveTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "chromepolicy",
        "extension_install",
        "ekajlcmdfcigmdbphhifahdfjbkciflj",
    )

    with pytest.raises(ProviderExecutionError):
        executor.apply(target, spec())

    assert not any(call["url"].endswith(":batchModify") for call in transport.calls)


def test_chrome_policy_rollback_rejects_malformed_live_state_without_mutation() -> None:
    class MalformedRollbackResolveTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.malformed = False

        def request_json(self, method, url, **kwargs):
            if self.malformed and method == "POST" and url.endswith("/policies:resolve"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                return 200, {"resolvedPolicies": {"malformed": True}}
            return super().request_json(method, url, **kwargs)

    transport = MalformedRollbackResolveTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    target = change(
        "chromepolicy",
        "extension_install",
        "ekajlcmdfcigmdbphhifahdfjbkciflj",
    )
    executor.apply(target, spec())
    transport.malformed = True
    writes_before = len(
        [
            call
            for call in transport.calls
            if call["url"].endswith((":batchModify", ":batchInherit"))
        ]
    )

    with pytest.raises(ProviderExecutionError):
        executor.rollback(target, spec())

    writes_after = len(
        [
            call
            for call in transport.calls
            if call["url"].endswith((":batchModify", ":batchInherit"))
        ]
    )
    assert writes_after == writes_before


def test_chrome_user_policy_resolver_rejects_duplicate_direct_policies() -> None:
    schema = "chrome.users.SimpleProxySettings"

    class DuplicateUserPolicyTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/policies:resolve"):
                target = kwargs["json_body"]["policyTargetKey"]
                policy = {
                    "targetKey": deepcopy(target),
                    "sourceKey": {"targetResource": "orgunits/03-test-ou"},
                    "value": {
                        "policySchema": schema,
                        "value": {"simpleProxyMode": "PROXY_MODE_ENUM_USER_CONFIGURED"},
                    },
                }
                return 200, {"resolvedPolicies": [policy, deepcopy(policy)]}
            return super().request_json(method, url, **kwargs)

    executor = GoogleResourceExecutor(DuplicateUserPolicyTransport())

    with pytest.raises(ProviderExecutionError) as captured:
        executor._resolve_chrome_user_policy(spec(), schema)

    assert captured.value.error_code == "chrome-policy-direct-policy-duplicate"


def test_endpoint_verification_install_targets_its_own_extension_id() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    policy_change = change(
        "chromepolicy",
        "extension_install",
        "callobklhcbilhphinckomhgkigmfocg",
    )

    executor.apply(policy_change, spec())

    modify = next(call for call in transport.calls if call["url"].endswith(":batchModify"))
    target = modify["body"]["requests"][0]["policyTargetKey"]
    assert target["additionalTargetKeys"] == {"app_id": "chrome:callobklhcbilhphinckomhgkigmfocg"}


class InheritedPacTransport(FakeTransport):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if url.endswith("/policySchemas/chrome.users.SimpleProxySettings"):
            self.calls.append({"method": method, "url": url, "params": params, "body": json_body})
            return 200, {
                "schemaName": "chrome.users.SimpleProxySettings",
                "definition": {
                    "messageType": [
                        {
                            "name": "SimpleProxySettings",
                            "field": [{"name": "simpleProxyMode"}],
                        }
                    ]
                },
            }
        if url.endswith("/policies:resolve"):
            if self.chrome_policies:
                return super().request_json(
                    method,
                    url,
                    params=params,
                    json_body=json_body,
                    accepted_statuses=accepted_statuses,
                )
            self.calls.append({"method": method, "url": url, "params": params, "body": json_body})
            return 200, {
                "resolvedPolicies": [
                    {
                        "targetKey": deepcopy((json_body or {})["policyTargetKey"]),
                        "sourceKey": {"targetResource": "orgunits/parent-ou"},
                        "value": {
                            "policySchema": "chrome.users.SimpleProxySettings",
                            "value": {
                                "simpleProxyMode": "PROXY_MODE_ENUM_PAC_SCRIPT",
                                "simpleProxyPacUrl": "https://example.test/legacy.pac",
                            },
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


def test_service_discovery_proxy_overrides_inherited_pac_and_rolls_back_to_inherit() -> None:
    transport = InheritedPacTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    proxy_change = change(
        "chromepolicy",
        "service_discovery_proxy",
        "03-test-ou",
    )

    executor.apply(proxy_change, spec())
    executor.rollback(proxy_change, spec())

    modify = next(call for call in transport.calls if call["url"].endswith(":batchModify"))
    request = modify["body"]["requests"][0]
    assert request["policyTargetKey"] == {"targetResource": "orgunits/03-test-ou"}
    assert request["policyValue"] == {
        "policySchema": "chrome.users.SimpleProxySettings",
        "value": {"simpleProxyMode": "PROXY_MODE_ENUM_USER_CONFIGURED"},
    }
    assert request["updateMask"] == "simpleProxyMode"
    inherit = next(call for call in transport.calls if call["url"].endswith(":batchInherit"))
    assert inherit["body"]["requests"] == [
        {
            "policyTargetKey": {"targetResource": "orgunits/03-test-ou"},
            "policySchema": "chrome.users.SimpleProxySettings",
        }
    ]


def test_local_poc_root_is_exported_for_admin_console_and_retained_on_rollback(
    tmp_path: Path,
) -> None:
    transport = FakeTransport()
    artifacts = CertificateArtifactStore(tmp_path)
    executor = GoogleResourceExecutor(
        transport,
        artifact_store=artifacts,
        poll_interval_seconds=0,
    )
    bundle = CertificateIssuer().issue_local_poc(
        hostname=local_poc_spec().private_hostname,
        lifetime_days=local_poc_spec().certificate_lifetime_days,
    )
    executor._certificate = bundle
    root_change = change(
        "local",
        "root_certificate_artifact",
        "secure-gateway-http-offload-poc-root",
    )

    executor.apply(root_change, local_poc_spec())
    root = artifacts.read_root_certificate(local_poc_spec().name)

    assert root.startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY" not in root
    assert not any(call["url"].endswith("networks:defineCertificate") for call in transport.calls)

    executor.rollback(root_change, local_poc_spec())
    assert artifacts.read_root_certificate(local_poc_spec().name) == root


def test_stale_local_poc_rollback_cannot_delete_a_newer_runs_root_artifact(
    tmp_path: Path,
) -> None:
    deployment = local_poc_spec()
    root_change = change(
        "local",
        "root_certificate_artifact",
        "secure-gateway-http-offload-poc-root",
    )
    artifacts = CertificateArtifactStore(tmp_path)
    older = GoogleResourceExecutor(
        FakeTransport(),
        artifact_store=artifacts,
        poll_interval_seconds=0,
    )
    newer = GoogleResourceExecutor(
        FakeTransport(),
        artifact_store=artifacts,
        poll_interval_seconds=0,
    )
    older._certificate = CertificateIssuer().issue_local_poc(
        hostname=deployment.private_hostname,
        lifetime_days=deployment.certificate_lifetime_days,
    )
    newer._certificate = CertificateIssuer().issue_local_poc(
        hostname=deployment.private_hostname,
        lifetime_days=deployment.certificate_lifetime_days,
    )

    older.apply(root_change, deployment)
    newer.apply(root_change, deployment)
    newer_root = artifacts.read_root_certificate(deployment.name)
    assert newer_root == newer._certificate.certificate_chain_pem[0]
    assert newer_root != older._certificate.certificate_chain_pem[0]

    older.rollback(root_change, deployment)
    assert artifacts.read_root_certificate(deployment.name) == newer_root

    assert older.destroy(root_change, deployment) == "skipped"
    assert artifacts.read_root_certificate(deployment.name) == newer_root


def test_local_poc_root_export_after_restart_uses_the_owned_numeric_version(
    tmp_path: Path,
) -> None:
    deployment = local_poc_spec()
    token = "00000000-0000-4000-8000-00000000f122"
    version_name = (
        "projects/enterprise-secgw-01/secrets/"
        "secure-gateway-http-offload-tls/versions/8"
    )
    bundle = CertificateIssuer().issue_local_poc(
        hostname=deployment.private_hostname,
        lifetime_days=deployment.certificate_lifetime_days,
    )
    payload = GoogleResourceExecutor._run_owned_secret_payload(bundle, token)

    class ActiveVersionTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/versions/8:access"):
                return 200, {
                    "name": version_name,
                    "payload": {
                        "data": base64.b64encode(payload).decode("ascii"),
                        "dataCrc32c": str(GoogleResourceExecutor._crc32c(payload)),
                    },
                }
            return super().request_json(method, url, **kwargs)

    artifacts = CertificateArtifactStore(tmp_path)
    executor = GoogleResourceExecutor(
        ActiveVersionTransport(),
        artifact_store=artifacts,
        poll_interval_seconds=0,
    )
    executor.bind_ownership_metadata(
        {
            "secretmanager:secret_version:secure-gateway-http-offload-tls": {
                "kind": "secret_version",
                "phase": "applied",
                "version_name": version_name,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "ownership_token": token,
            }
        }
    )

    executor.apply(
        change(
            "local",
            "root_certificate_artifact",
            "secure-gateway-http-offload-poc-root",
        ),
        deployment,
    )

    assert artifacts.read_root_certificate(deployment.name) == bundle.certificate_chain_pem[0]


def test_application_iam_requires_the_verified_managed_chrome_access_level() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    executor.apply(
        change(
            "beyondcorp",
            "application_iam",
            "secure-gateway-http-offload-app-access",
        ),
        spec(),
    )

    set_call = next(call for call in transport.calls if call["url"].endswith(":setIamPolicy"))
    get_call = next(call for call in transport.calls if call["url"].endswith(":getIamPolicy"))
    policy = set_call["body"]["policy"]
    binding = next(
        item for item in policy["bindings"] if item["role"] == "roles/beyondcorp.sgApplicationUser"
    )
    assert policy["version"] == 3
    assert get_call["params"] == {"options.requestedPolicyVersion": 3}
    assert binding["condition"]["expression"] == (
        "'accessPolicies/123456789/accessLevels/managed_chrome' in request.auth.access_levels"
    )


def test_project_iam_round_trips_v3_conditions_and_requests_v3() -> None:
    class ProjectIamTransport(StatefulIamTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/securityGateways/default"):
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                return 200, {"delegatingServiceAccount": "gateway@example.iam.gserviceaccount.com"}
            return super().request_json(method, url, **kwargs)

    transport = ProjectIamTransport()
    transport.current_policy = {
        "version": 3,
        "etag": "project-etag",
        "bindings": [
            {
                "role": "roles/viewer",
                "members": ["user:auditor@example.com"],
                "condition": {
                    "title": "temporary",
                    "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
                },
            }
        ],
    }
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    executor.apply(
        change("cloudresourcemanager", "project_iam", "upstream-access"),
        spec(),
    )

    get_call = next(
        call
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith(":getIamPolicy")
    )
    set_call = next(call for call in transport.calls if call["url"].endswith(":setIamPolicy"))
    assert get_call["body"] == {"options": {"requestedPolicyVersion": 3}}
    assert set_call["body"]["policy"]["version"] == 3
    assert transport.current_policy["bindings"][0]["condition"]["title"] == "temporary"

    transport.current_policy["bindings"].append(
        {
            "role": "roles/logging.viewer",
            "members": ["group:concurrent@example.com"],
        }
    )
    transport.current_policy["etag"] = "concurrent-etag"
    executor.rollback(
        change("cloudresourcemanager", "project_iam", "upstream-access"),
        spec(),
    )

    assert any(
        binding.get("role") == "roles/logging.viewer"
        for binding in transport.current_policy["bindings"]
    )
    assert any(
        binding.get("condition", {}).get("title") == "temporary"
        for binding in transport.current_policy["bindings"]
    )
    assert not any(
        binding.get("role") == "roles/beyondcorp.upstreamAccess"
        for binding in transport.current_policy["bindings"]
    )


def test_direct_https_application_uses_endpoint_port_vpc_and_egress_region() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    direct_spec = DeploymentSpec(
        **{
            **spec().model_dump(),
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
            "existing_backend_location": BackendLocation.ON_PREM,
            "existing_backend_connectivity_confirmed": True,
            "application_egress_region": "asia-east1",
        }
    )

    executor.apply(
        change("beyondcorp", "application", "secure-gateway-http-offload-app"),
        direct_spec,
    )

    create_call = next(
        call
        for call in transport.calls
        if call["method"] == "POST" and "/applications" in call["url"]
    )
    assert create_call["params"]["applicationId"] == "secure-gateway-http-offload-app"
    assert "application_id" not in create_call["params"]
    assert create_call["body"]["endpointMatchers"] == [
        {"hostname": "app.corp.internal", "ports": [8443]}
    ]
    assert create_call["body"]["upstreams"] == [
        {
            "network": {"name": "projects/enterprise-secgw-01/global/networks/private-app-vpc"},
            "egressPolicy": {"regions": ["asia-east1"]},
        }
    ]


def test_iam_rollback_reverses_run_delta_and_preserves_later_iam_edits() -> None:
    transport = StatefulIamTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    iam_change = change("secretmanager", "secret_iam", "secure-gateway-http-offload-tls-accessor")

    executor.apply(iam_change, spec())
    accessor = next(
        binding
        for binding in transport.current_policy["bindings"]
        if binding["role"] == "roles/secretmanager.secretAccessor"
    )
    accessor["members"].append("serviceAccount:concurrent@example.iam.gserviceaccount.com")
    transport.current_policy["bindings"].append(
        {
            "role": "roles/editor",
            "members": ["user:concurrent@example.com"],
            "condition": {
                "title": "Concurrent",
                "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
            },
        }
    )
    transport.current_policy["etag"] = "third-party-etag"
    executor.rollback(iam_change, spec())

    set_calls = [call for call in transport.calls if call["url"].endswith(":setIamPolicy")]
    assert set_calls[0]["body"]["policy"]["etag"] == "before-etag"
    assert set_calls[-1]["body"]["policy"]["etag"] == "third-party-etag"
    accessor = next(
        binding
        for binding in transport.current_policy["bindings"]
        if binding["role"] == "roles/secretmanager.secretAccessor"
    )
    assert accessor["members"] == ["serviceAccount:concurrent@example.iam.gserviceaccount.com"]
    assert any(
        binding["role"] == "roles/editor" and binding["condition"]["title"] == "Concurrent"
        for binding in transport.current_policy["bindings"]
    )
    assert transport.current_policy["bindings"][0] == transport.original_policy["bindings"][0]


def test_new_secret_iam_rollback_is_owned_by_parent_secret_cleanup() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    secret_change = change("secretmanager", "secret", "secure-gateway-http-offload-tls")
    iam_change = change("secretmanager", "secret_iam", "secure-gateway-http-offload-tls-accessor")

    executor.apply(secret_change, spec())
    executor.apply(iam_change, spec())
    executor.rollback(iam_change, spec())
    executor.rollback(secret_change, spec())

    set_calls = [call for call in transport.calls if call["url"].endswith(":setIamPolicy")]
    assert len(set_calls) == 1
    assert any(
        call["method"] == "DELETE"
        and call["url"].endswith("/secrets/secure-gateway-http-offload-tls")
        for call in transport.calls
    )


def test_unknown_provider_operation_fails_closed() -> None:
    executor = GoogleResourceExecutor(FakeTransport(), poll_interval_seconds=0)
    with pytest.raises(ProviderExecutionError, match="Provider operation failed"):
        executor.apply(change("unknown", "resource", "unknown"), spec())


def test_google_error_code_includes_safe_canonical_status() -> None:
    error = GoogleApiError(
        status_code=400,
        method="POST",
        host="beyondcorp.googleapis.com",
        detail='{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"detail"}}',
    )

    assert GoogleResourceExecutor._google_error_code(error, "beyondcorp") == (
        "google-api-400-beyondcorp-invalid-argument"
    )


def _bind_durable_operation(
    executor: GoogleResourceExecutor,
    target: ResourceChange,
    deployment: DeploymentSpec,
    writes: list[dict[str, object]],
    *,
    checkpoint: dict[str, object] | None = None,
    request_id: str = "00000000-0000-4000-8000-00000000f001",
) -> None:
    executor.bind_operation(
        target,
        deployment,
        RunOperation(
            operation_id="operation-durability-test",
            request_id=request_id,
            resource_key=f"{target.provider}:{target.resource_type}:{target.resource_name}",
            action=target.action,
            status=OperationStatus.RUNNING,
            owned_after_apply=target.owned_after_apply,
            intent_digest="durability-test",
            checkpoint=deepcopy(checkpoint),
            started_at=datetime.now(UTC),
        ),
        lambda value: writes.append(deepcopy(value)),
    )


def test_instance_group_membership_response_loss_resumes_from_paginated_exact_state() -> None:
    class MembershipTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.members: list[str] = []
            self.lose_add_response = True

        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/listInstances"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                page_token = (kwargs.get("params") or {}).get("pageToken")
                if page_token is None:
                    return 200, {"items": [], "nextPageToken": "members-page-2"}
                assert page_token == "members-page-2"
                return 200, {"items": [{"instance": member} for member in self.members]}
            if method == "POST" and url.endswith("/addInstances"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                self.members = [kwargs["json_body"]["instances"][0]["instance"]]
                if self.lose_add_response:
                    self.lose_add_response = False
                    raise ConnectionError("addInstances response lost")
                return 200, {"status": "DONE"}
            return super().request_json(method, url, **kwargs)

    deployment = internal_https_lb_spec()
    target = change("compute", "instance_group", f"{deployment.name}-backend-ig")
    run_id = "00000000-0000-4000-8000-00000000f101"
    transport = MembershipTransport()
    first_writes: list[dict[str, object]] = []
    first = GoogleResourceExecutor(transport, poll_interval_seconds=0, execution_id=run_id)
    bind_source_image_plan(first, deployment)
    _bind_durable_operation(first, target, deployment, first_writes)

    with pytest.raises(ProviderExecutionError):
        first.apply(target, deployment)

    sending = first_writes[-1]
    assert sending["phase"] == "applied"
    assert sending["membership"]["phase"] == "sending"
    second_writes: list[dict[str, object]] = []
    resumed = GoogleResourceExecutor(transport, poll_interval_seconds=0, execution_id=run_id)
    bind_source_image_plan(resumed, deployment)
    _bind_durable_operation(
        resumed,
        target,
        deployment,
        second_writes,
        checkpoint=sending,
    )
    resumed.apply(target, deployment)

    add_calls = [call for call in transport.calls if call["url"].endswith("/addInstances")]
    assert len(add_calls) == 1
    assert uuid.UUID(str(add_calls[0]["params"]["requestId"])).version == 5
    assert second_writes[-1]["membership"]["phase"] == "applied"
    list_calls = [call for call in transport.calls if call["url"].endswith("/listInstances")]
    assert [call["params"].get("pageToken") for call in list_calls] == [
        None,
        "members-page-2",
    ]


def test_production_refresh_response_loss_never_reposts_or_commits_old_health() -> None:
    class LostRefreshTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.lose_refresh_response = True

        def request_json(self, method, url, **kwargs):
            if method == "GET" and "/instanceGroupManagers/" in url:
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                return 200, {
                    "status": {
                        "isStable": True,
                        "currentInstanceStatuses": {"running": 2},
                    }
                }
            if method == "POST" and url.endswith("/getHealth"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                return 200, {
                    "healthStatus": [
                        {"healthState": "HEALTHY"},
                        {"healthState": "HEALTHY"},
                    ]
                }
            if method == "POST" and url.endswith("/applyUpdatesToInstances"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                if self.lose_refresh_response:
                    self.lose_refresh_response = False
                    raise ConnectionError("applyUpdatesToInstances response lost")
                return 200, {"status": "DONE"}
            return super().request_json(method, url, **kwargs)

    deployment = spec()
    target = change("compute", "offload_refresh", f"{deployment.name}-certificate-refresh")
    run_id = "00000000-0000-4000-8000-00000000f102"
    transport = LostRefreshTransport()
    first_writes: list[dict[str, object]] = []
    first = GoogleResourceExecutor(transport, poll_interval_seconds=0, execution_id=run_id)
    bind_source_image_plan(first, deployment)
    _bind_durable_operation(first, target, deployment, first_writes)
    with pytest.raises(ProviderExecutionError):
        first.apply(target, deployment)

    assert first_writes[-1]["phase"] == "update_sending"
    second_writes: list[dict[str, object]] = []
    resumed = GoogleResourceExecutor(transport, poll_interval_seconds=0, execution_id=run_id)
    bind_source_image_plan(resumed, deployment)
    _bind_durable_operation(
        resumed,
        target,
        deployment,
        second_writes,
        checkpoint=first_writes[-1],
    )
    with pytest.raises(ProviderExecutionError) as resumed_apply:
        resumed.apply(target, deployment)

    with pytest.raises(ProviderExecutionError) as resumed_rollback:
        resumed.rollback(target, deployment)

    updates = [call for call in transport.calls if call["url"].endswith("/applyUpdatesToInstances")]
    assert len(updates) == 1
    assert updates[0]["params"] is None
    assert resumed_apply.value.error_code == "offload-refresh-provider-response-ambiguous"
    assert resumed_rollback.value.error_code == "offload-refresh-rollback-outcome-ambiguous"
    assert first_writes[-1]["phase"] == "update_sending"
    assert not second_writes
    assert not any(call["url"].endswith("/getHealth") for call in transport.calls)


def test_production_refresh_definite_rejection_rolls_back_without_health_inference() -> None:
    class RejectedRefreshTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/applyUpdatesToInstances"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                raise GoogleApiError(
                    status_code=400,
                    method=method,
                    host="compute.googleapis.com",
                    detail='{"error":{"status":"INVALID_ARGUMENT"}}',
                )
            return super().request_json(method, url, **kwargs)

    deployment = spec()
    target = change("compute", "offload_refresh", f"{deployment.name}-certificate-refresh")
    transport = RejectedRefreshTransport()
    writes: list[dict[str, object]] = []
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    bind_source_image_plan(executor, deployment)
    _bind_durable_operation(executor, target, deployment, writes)

    with pytest.raises(ProviderExecutionError):
        executor.apply(target, deployment)
    executor.rollback(target, deployment)

    updates = [call for call in transport.calls if call["url"].endswith("/applyUpdatesToInstances")]
    assert len(updates) == 1
    assert updates[0]["params"] is None
    assert writes[-1]["phase"] == "update_rejected"
    assert not any(call["url"].endswith("/getHealth") for call in transport.calls)


def test_production_secret_rollback_refresh_response_loss_never_reposts() -> None:
    class LostRollbackRefreshTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/applyUpdatesToInstances"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                raise ConnectionError("rollback refresh response lost")
            return super().request_json(method, url, **kwargs)

    deployment = spec()
    target = change(
        "secretmanager",
        "secret_version",
        f"{deployment.name}-tls",
    )
    checkpoint = {
        "kind": "secret_version",
        "phase": "applied",
        "resource_key": f"{target.provider}:{target.resource_type}:{target.resource_name}",
    }
    transport = LostRollbackRefreshTransport()
    first_writes: list[dict[str, object]] = []
    first = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _bind_durable_operation(
        first,
        target,
        deployment,
        first_writes,
        checkpoint=checkpoint,
    )

    with pytest.raises(ConnectionError, match="response lost"):
        first._perform_existing_offload_refresh(deployment, checkpoint)

    resumed = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _bind_durable_operation(
        resumed,
        target,
        deployment,
        [],
        checkpoint=first_writes[-1],
    )
    with pytest.raises(ProviderExecutionError) as captured:
        resumed._perform_existing_offload_refresh(deployment, first_writes[-1])

    updates = [call for call in transport.calls if call["url"].endswith("/applyUpdatesToInstances")]
    assert len(updates) == 1
    assert updates[0]["params"] is None
    assert captured.value.error_code == (
        "secret-version-rollback-refresh-outcome-ambiguous"
    )
    assert first_writes[-1]["offload_refresh_rollback"]["phase"] == "sending"


@pytest.mark.parametrize("lost_phase", ["stop", "start"])
def test_poc_refresh_recovers_committed_phase_after_response_loss(lost_phase: str) -> None:
    class LostPocRefreshTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.status = "RUNNING"
            self.lost = False

        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("-offload"):
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                return 200, {"status": self.status}
            if method == "POST" and url.endswith("/stop"):
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                self.status = "TERMINATED"
                if lost_phase == "stop" and not self.lost:
                    self.lost = True
                    raise ConnectionError("stop response lost")
                return 200, {"status": "DONE"}
            if method == "POST" and url.endswith("/start"):
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                self.status = "RUNNING"
                if lost_phase == "start" and not self.lost:
                    self.lost = True
                    raise ConnectionError("start response lost")
                return 200, {"status": "DONE"}
            return super().request_json(method, url, **kwargs)

    deployment = local_poc_spec()
    target = change("compute", "offload_refresh", f"{deployment.name}-certificate-refresh")
    run_id = f"00000000-0000-4000-8000-00000000f10{3 if lost_phase == 'stop' else 4}"
    transport = LostPocRefreshTransport()
    first_writes: list[dict[str, object]] = []
    first = GoogleResourceExecutor(transport, poll_interval_seconds=0, execution_id=run_id)
    _bind_durable_operation(first, target, deployment, first_writes)
    with pytest.raises(ProviderExecutionError):
        first.apply(target, deployment)

    second_writes: list[dict[str, object]] = []
    resumed = GoogleResourceExecutor(transport, poll_interval_seconds=0, execution_id=run_id)
    _bind_durable_operation(
        resumed,
        target,
        deployment,
        second_writes,
        checkpoint=first_writes[-1],
    )
    resumed.apply(target, deployment)

    stop_calls = [call for call in transport.calls if call["url"].endswith("/stop")]
    start_calls = [call for call in transport.calls if call["url"].endswith("/start")]
    assert len(stop_calls) == 1
    assert len(start_calls) == 1
    assert stop_calls[0]["params"]["requestId"] != start_calls[0]["params"]["requestId"]
    assert transport.status == "RUNNING"
    assert second_writes[-1]["phase"] == "applied"


def test_poc_refresh_rollback_restarts_a_vm_when_stop_response_was_lost() -> None:
    class LostStopTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.status = "RUNNING"

        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("-offload"):
                return 200, {"status": self.status}
            if method == "POST" and url.endswith("/stop"):
                self.status = "TERMINATED"
                raise ConnectionError("stop response lost")
            if method == "POST" and url.endswith("/start"):
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                self.status = "RUNNING"
                return 200, {"status": "DONE"}
            return super().request_json(method, url, **kwargs)

    deployment = local_poc_spec()
    target = change("compute", "offload_refresh", f"{deployment.name}-certificate-refresh")
    transport = LostStopTransport()
    writes: list[dict[str, object]] = []
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _bind_durable_operation(executor, target, deployment, writes)
    with pytest.raises(ProviderExecutionError):
        executor.apply(target, deployment)

    executor.rollback(target, deployment)

    assert transport.status == "RUNNING"
    restart = next(call for call in transport.calls if call["url"].endswith("/start"))
    assert restart["params"]["requestId"] == writes[-1]["start_request_id"]


def test_poc_refresh_rollback_observes_a_delayed_stop_after_response_loss() -> None:
    class DelayedStopTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.statuses = ["RUNNING", "STOPPING", "TERMINATED"]
            self.status = "RUNNING"

        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("-offload"):
                if self.statuses:
                    self.status = self.statuses.pop(0)
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                return 200, {"status": self.status}
            if method == "POST" and url.endswith("/start"):
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                self.status = "RUNNING"
                return 200, {"status": "DONE"}
            return super().request_json(method, url, **kwargs)

    deployment = local_poc_spec()
    target = change("compute", "offload_refresh", f"{deployment.name}-certificate-refresh")
    checkpoint = {
        "kind": "offload_refresh",
        "protocol_version": 2,
        "resource_key": (f"{target.provider}:{target.resource_type}:{target.resource_name}"),
        "phase": "stop_sending",
        "target_url": (
            "https://compute.googleapis.com/compute/v1/projects/"
            f"{deployment.project_id}/zones/{deployment.zone}/instances/"
            f"{deployment.name}-offload"
        ),
        "update_request_id": "00000000-0000-4000-8000-00000000f111",
        "stop_request_id": "00000000-0000-4000-8000-00000000f112",
        "start_request_id": "00000000-0000-4000-8000-00000000f113",
    }
    transport = DelayedStopTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _bind_durable_operation(
        executor,
        target,
        deployment,
        [],
        checkpoint=checkpoint,
    )

    executor.rollback(target, deployment)

    assert transport.status == "RUNNING"
    assert transport.statuses == []
    restart = next(call for call in transport.calls if call["url"].endswith("/start"))
    assert restart["params"]["requestId"] == checkpoint["start_request_id"]


def test_poc_refresh_rollback_retains_ownership_when_lost_stop_stays_running() -> None:
    class IndeterminateStopTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("-offload"):
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                return 200, {"status": "RUNNING"}
            return super().request_json(method, url, **kwargs)

    deployment = local_poc_spec()
    target = change("compute", "offload_refresh", f"{deployment.name}-certificate-refresh")
    checkpoint = {
        "kind": "offload_refresh",
        "protocol_version": 2,
        "resource_key": (f"{target.provider}:{target.resource_type}:{target.resource_name}"),
        "phase": "stop_sending",
        "target_url": (
            "https://compute.googleapis.com/compute/v1/projects/"
            f"{deployment.project_id}/zones/{deployment.zone}/instances/"
            f"{deployment.name}-offload"
        ),
        "update_request_id": "00000000-0000-4000-8000-00000000f121",
        "stop_request_id": "00000000-0000-4000-8000-00000000f122",
        "start_request_id": "00000000-0000-4000-8000-00000000f123",
    }
    transport = IndeterminateStopTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _bind_durable_operation(
        executor,
        target,
        deployment,
        [],
        checkpoint=checkpoint,
    )

    with pytest.raises(ProviderExecutionError) as captured:
        executor.rollback(target, deployment)

    assert captured.value.error_code == ("offload-refresh-rollback-outcome-ambiguous")
    assert len([call for call in transport.calls if call["method"] == "GET"]) == 5
    assert not any(call["method"] == "POST" for call in transport.calls)


def test_poc_refresh_rollback_reconciles_a_lost_start_response() -> None:
    class LostRollbackStartTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.status = "TERMINATED"
            self.lose_start_response = True

        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("-offload"):
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                return 200, {"status": self.status}
            if method == "POST" and url.endswith("/start"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": None,
                    }
                )
                self.status = "RUNNING"
                if self.lose_start_response:
                    self.lose_start_response = False
                    raise ConnectionError("rollback start response lost")
                return 200, {"status": "DONE"}
            return super().request_json(method, url, **kwargs)

    deployment = local_poc_spec()
    target = change("compute", "offload_refresh", f"{deployment.name}-certificate-refresh")
    checkpoint = {
        "kind": "offload_refresh",
        "protocol_version": 2,
        "resource_key": (f"{target.provider}:{target.resource_type}:{target.resource_name}"),
        "phase": "stop_sending",
        "target_url": (
            "https://compute.googleapis.com/compute/v1/projects/"
            f"{deployment.project_id}/zones/{deployment.zone}/instances/"
            f"{deployment.name}-offload"
        ),
        "update_request_id": "00000000-0000-4000-8000-00000000f131",
        "stop_request_id": "00000000-0000-4000-8000-00000000f132",
        "start_request_id": "00000000-0000-4000-8000-00000000f133",
    }
    first_checkpoints: list[dict[str, object]] = []
    transport = LostRollbackStartTransport()
    first = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _bind_durable_operation(
        first,
        target,
        deployment,
        first_checkpoints,
        checkpoint=checkpoint,
    )

    with pytest.raises(ProviderExecutionError):
        first.rollback(target, deployment)

    assert first_checkpoints[-1]["rollback_phase"] == "start_sending"
    resumed_checkpoints: list[dict[str, object]] = []
    resumed = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _bind_durable_operation(
        resumed,
        target,
        deployment,
        resumed_checkpoints,
        checkpoint=first_checkpoints[-1],
    )
    resumed.rollback(target, deployment)

    assert resumed_checkpoints[-1]["rollback_phase"] == "applied"
    start_calls = [call for call in transport.calls if call["url"].endswith("/start")]
    assert len(start_calls) == 1
    assert start_calls[0]["params"]["requestId"] == checkpoint["start_request_id"]


@pytest.mark.parametrize(
    ("operation_url", "fallback_host", "mutation_url"),
    [
        (
            "https://compute.googleapis.com/compute/v1/projects/other/global/operations/op",
            "compute.googleapis.com",
            "https://compute.googleapis.com/compute/v1/projects/expected/global/networks",
        ),
        (
            "https://compute.googleapis.com/compute/v1/projects/expected/regions/us-east1/operations/op",
            "compute.googleapis.com",
            "https://compute.googleapis.com/compute/v1/projects/expected/regions/asia-east1/routers/r",
        ),
        (
            "https://privateca.googleapis.com/v1/projects/expected/locations/us-east1/operations/op",
            "privateca.googleapis.com",
            "https://privateca.googleapis.com/v1/projects/expected/locations/asia-east1/caPools/p/certificates",
        ),
        (
            "https://compute.googleapis.com/compute/v1/projects/expected/global/operations/op?alt=json",
            "compute.googleapis.com",
            "https://compute.googleapis.com/compute/v1/projects/expected/global/networks",
        ),
        (
            "https://user@compute.googleapis.com/compute/v1/projects/expected/global/operations/op",
            "compute.googleapis.com",
            "https://compute.googleapis.com/compute/v1/projects/expected/global/networks",
        ),
        (
            "https://compute.googleapis.com/compute/v1/projects/expected/global/../global/operations/op",
            "compute.googleapis.com",
            "https://compute.googleapis.com/compute/v1/projects/expected/global/networks",
        ),
    ],
)
def test_operation_poll_url_is_bound_to_exact_mutation_scope(
    operation_url: str,
    fallback_host: str,
    mutation_url: str,
) -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError) as captured:
        executor._wait(
            {"name": "operations/op", "status": "PENDING", "selfLink": operation_url},
            fallback_host=fallback_host,
            mutation_url=mutation_url,
        )

    assert captured.value.error_code == "provider-operation-poll-url-invalid"
    assert transport.calls == []


def test_absolute_operation_name_is_validated_before_polling() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError) as captured:
        executor._wait(
            {
                "name": (
                    "https://compute.googleapis.com/compute/v1/projects/other/global/operations/op"
                ),
                "status": "PENDING",
            },
            fallback_host="compute.googleapis.com",
            mutation_url=(
                "https://compute.googleapis.com/compute/v1/projects/expected/global/networks"
            ),
        )

    assert captured.value.error_code == "provider-operation-poll-url-invalid"
    assert transport.calls == []


def test_unfinished_status_only_operation_fails_before_polling() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError) as captured:
        executor._wait(
            {"status": "PENDING"},
            fallback_host="compute.googleapis.com",
            mutation_url=(
                "https://compute.googleapis.com/compute/v1/projects/expected/global/networks"
            ),
        )

    assert captured.value.error_code == "provider-operation-missing-name"
    assert transport.calls == []


def test_initial_done_operation_with_falsey_error_fails_closed() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError) as captured:
        executor._wait(
            {"status": "DONE", "error": {}},
            fallback_host="compute.googleapis.com",
            mutation_url=(
                "https://compute.googleapis.com/compute/v1/projects/expected/global/networks"
            ),
        )

    assert captured.value.error_code == "provider-operation-failed"
    assert transport.calls == []


def test_polled_done_operation_with_falsey_error_fails_closed() -> None:
    operation_url = (
        "https://compute.googleapis.com/compute/v1/projects/expected/global/operations/op"
    )

    class FalseyErrorTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url == operation_url:
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                return 200, {"status": "DONE", "error": {}}
            return super().request_json(method, url, **kwargs)

    transport = FalseyErrorTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError) as captured:
        executor._wait(
            {"status": "PENDING", "selfLink": operation_url},
            fallback_host="compute.googleapis.com",
            mutation_url=(
                "https://compute.googleapis.com/compute/v1/projects/expected/global/networks"
            ),
        )

    assert captured.value.error_code == "provider-operation-failed"
    assert [call["url"] for call in transport.calls] == [operation_url]


def test_secret_version_listing_rejects_a_repeated_page_token() -> None:
    class RepeatingTokenTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/versions"):
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                return 200, {"versions": [], "nextPageToken": "same-token"}
            return super().request_json(method, url, **kwargs)

    transport = RepeatingTokenTransport()
    executor = GoogleResourceExecutor(transport)

    with pytest.raises(ProviderExecutionError) as captured:
        executor._list_secret_version_names(
            "https://secretmanager.googleapis.com/v1/projects/p/secrets/s"
        )

    assert captured.value.error_code == "secret-version-pagination-invalid"
    assert len(transport.calls) == 2


def test_secret_version_listing_rejects_a_present_null_page_token() -> None:
    class NullTokenTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/versions"):
                return 200, {"versions": [], "nextPageToken": None}
            return super().request_json(method, url, **kwargs)

    executor = GoogleResourceExecutor(NullTokenTransport())

    with pytest.raises(ProviderExecutionError) as captured:
        executor._list_secret_version_names(
            "https://secretmanager.googleapis.com/v1/projects/p/secrets/s"
        )

    assert captured.value.error_code == "secret-version-pagination-invalid"


def test_secret_version_listing_bounds_an_empty_rotating_token_loop() -> None:
    class EmptyLoopTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/versions"):
                self.calls.append(
                    {"method": method, "url": url, "params": kwargs.get("params"), "body": None}
                )
                return 200, {
                    "versions": [],
                    "nextPageToken": f"page-{len(self.calls)}",
                }
            return super().request_json(method, url, **kwargs)

    transport = EmptyLoopTransport()
    executor = GoogleResourceExecutor(transport)

    with pytest.raises(ProviderExecutionError) as captured:
        executor._list_secret_version_names(
            "https://secretmanager.googleapis.com/v1/projects/p/secrets/s"
        )

    assert captured.value.error_code == "secret-version-pagination-limit-exceeded"
    assert len(transport.calls) == 100


def test_secret_version_listing_rejects_a_cross_secret_identity() -> None:
    class CrossSecretListTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/versions"):
                return 200, {
                    "versions": [
                        {"name": ("projects/enterprise-secgw-01/secrets/other/versions/8")}
                    ]
                }
            return super().request_json(method, url, **kwargs)

    executor = GoogleResourceExecutor(CrossSecretListTransport())

    with pytest.raises(ProviderExecutionError) as captured:
        executor._list_secret_version_names(
            "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/"
            "secrets/secure-gateway-http-offload-tls"
        )

    assert captured.value.error_code == "secret-version-name-invalid"


def test_secret_version_recovery_rejects_a_cross_version_access_identity() -> None:
    payload = b"expected secret payload"
    expected_name = (
        "projects/enterprise-secgw-01/secrets/secure-gateway-http-offload-tls/versions/8"
    )

    class CrossAccessIdentityTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/versions"):
                return 200, {"versions": [{"name": expected_name}]}
            if method == "GET" and url.endswith("/versions/8:access"):
                return 200, {
                    "name": (
                        "projects/enterprise-secgw-01/secrets/"
                        "secure-gateway-http-offload-tls/versions/9"
                    ),
                    "payload": {"data": base64.b64encode(payload).decode("ascii")},
                }
            return super().request_json(method, url, **kwargs)

    executor = GoogleResourceExecutor(CrossAccessIdentityTransport())
    checkpoint: dict[str, object] = {
        "secret_url": (
            "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/"
            "secrets/secure-gateway-http-offload-tls"
        ),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "ownership_token": "00000000-0000-4000-8000-00000000f121",
        "baseline_versions": [],
    }

    with pytest.raises(ProviderExecutionError) as captured:
        executor._recover_secret_version(checkpoint)

    assert captured.value.error_code == "secret-version-access-identity-invalid"


def test_secret_version_response_loss_resumes_from_exact_list_and_access_identity() -> None:
    class LostAddVersionTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.created_payload: bytes | None = None
            self.version_list_reads = 0

        def request_json(self, method, url, **kwargs):
            if method == "GET" and url.endswith("/versions"):
                self.version_list_reads += 1
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": None,
                    }
                )
                versions = []
                if self.created_payload is not None and self.version_list_reads >= 3:
                    versions = [
                        {
                            "name": (
                                "projects/enterprise-secgw-01/secrets/"
                                "secure-gateway-http-offload-tls/versions/8"
                            )
                        }
                    ]
                return 200, {"versions": versions}
            if method == "POST" and url.endswith(":addVersion"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                encoded = kwargs["json_body"]["payload"]["data"]
                self.created_payload = base64.b64decode(encoded)
                raise ConnectionError("addVersion response lost")
            if method == "GET" and url.endswith("/versions/8:access"):
                assert self.created_payload is not None
                self.calls.append({"method": method, "url": url, "params": None, "body": None})
                return 200, {
                    "name": (
                        "projects/enterprise-secgw-01/secrets/"
                        "secure-gateway-http-offload-tls/versions/8"
                    ),
                    "payload": {"data": base64.b64encode(self.created_payload).decode("ascii")},
                }
            return super().request_json(method, url, **kwargs)

    deployment = local_poc_spec()
    target = change(
        "secretmanager",
        "secret_version",
        "secure-gateway-http-offload-tls",
    )
    run_id = "00000000-0000-4000-8000-00000000f120"
    transport = LostAddVersionTransport()
    first_checkpoints: list[dict[str, object]] = []
    first = GoogleResourceExecutor(transport, poll_interval_seconds=0, execution_id=run_id)
    _bind_durable_operation(
        first,
        target,
        deployment,
        first_checkpoints,
    )

    with pytest.raises(ProviderExecutionError) as first_error:
        first.apply(target, deployment)

    assert first_error.value.error_code == "secret-version-recovery-not-found"
    assert first_checkpoints[-1]["phase"] == "sending"
    resumed_checkpoints: list[dict[str, object]] = []
    resumed = GoogleResourceExecutor(
        transport,
        poll_interval_seconds=0,
        execution_id=run_id,
    )
    _bind_durable_operation(
        resumed,
        target,
        deployment,
        resumed_checkpoints,
        checkpoint=first_checkpoints[-1],
    )

    resumed.apply(target, deployment)

    assert len([call for call in transport.calls if call["url"].endswith(":addVersion")]) == 1
    assert resumed_checkpoints[-1]["phase"] == "applied"
    assert resumed_checkpoints[-1]["version_name"].endswith("/versions/8")


def _prepared_secret_version_checkpoint(
    deployment: DeploymentSpec,
    bundle: CertificateBundle,
) -> dict[str, object]:
    secret_url = (
        f"https://secretmanager.googleapis.com/v1/projects/{deployment.project_id}/"
        "secrets/secure-gateway-http-offload-tls"
    )
    ownership_token = "00000000-0000-4000-8000-00000000f121"
    owned_payload = GoogleResourceExecutor._run_owned_secret_payload(
        bundle,
        ownership_token,
    )
    return {
        "kind": "secret_version",
        "phase": "prepared",
        "resource_key": "secretmanager:secret_version:secure-gateway-http-offload-tls",
        "secret_url": secret_url,
        "payload_sha256": hashlib.sha256(owned_payload).hexdigest(),
        "ownership_token": ownership_token,
        "baseline_versions": [],
        "version_name": None,
        "issuer_resource_name": bundle.issuer_resource_name,
        "issuer_certificate_authority": bundle.issuer_certificate_authority,
        "csr_sha256": bundle.csr_sha256,
    }


def test_local_secret_version_prepared_restart_reissues_before_add_version() -> None:
    deployment = local_poc_spec()
    abandoned = CertificateIssuer().issue_local_poc(
        hostname=deployment.private_hostname,
        lifetime_days=deployment.certificate_lifetime_days,
    )
    checkpoint = _prepared_secret_version_checkpoint(deployment, abandoned)
    target = change(
        "secretmanager",
        "secret_version",
        "secure-gateway-http-offload-tls",
    )
    transport = FakeTransport()
    writes: list[dict[str, object]] = []
    restarted = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _bind_durable_operation(
        restarted,
        target,
        deployment,
        writes,
        checkpoint=checkpoint,
    )

    restarted.apply(target, deployment)

    assert len([call for call in transport.calls if call["url"].endswith(":addVersion")]) == 1
    assert writes[-1]["phase"] == "applied"
    assert writes[-1]["payload_sha256"] != checkpoint["payload_sha256"]


@pytest.mark.parametrize("resume_action", ["apply", "rollback"])
def test_enterprise_secret_version_prepared_restart_revokes_before_release(
    resume_action: str,
) -> None:
    deployment = spec()
    _, csr = CertificateIssuer.prepare_enterprise_request(deployment.private_hostname)
    certificate_name = (
        f"{deployment.ca_pool}/certificates/{deployment.name}-prepared-secret-test"
    )
    abandoned = replace(
        CertificateIssuer().issue_local_poc(
            hostname=deployment.private_hostname,
            lifetime_days=deployment.certificate_lifetime_days,
        ),
        issuer_resource_name=certificate_name,
        issuer_certificate_authority=deployment.ca_name,
        csr_sha256=hashlib.sha256(csr).hexdigest(),
    )
    checkpoint = _prepared_secret_version_checkpoint(deployment, abandoned)
    target = change(
        "secretmanager",
        "secret_version",
        "secure-gateway-http-offload-tls",
    )
    transport = FakeTransport()
    transport.private_ca_certificates[
        f"https://privateca.googleapis.com/v1/{certificate_name}"
    ] = {
        "name": certificate_name,
        "pemCsr": csr.decode("ascii"),
        "issuerCertificateAuthority": deployment.ca_name,
    }
    writes: list[dict[str, object]] = []
    restarted = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    _bind_durable_operation(
        restarted,
        target,
        deployment,
        writes,
        checkpoint=checkpoint,
    )

    if resume_action == "apply":
        with pytest.raises(ProviderExecutionError) as captured:
            restarted.apply(target, deployment)
        assert captured.value.error_code == (
            "secret-version-prepared-private-key-unrecoverable"
        )
        restarted.rollback(target, deployment)
    else:
        restarted.rollback(target, deployment)

    assert writes[-1]["phase"] == "rejected"
    assert any(call["url"].endswith(":revoke") for call in transport.calls)
    assert not any(call["url"].endswith(":addVersion") for call in transport.calls)


def test_instance_group_listing_bounds_unique_empty_page_tokens() -> None:
    class EmptyMembershipLoopTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/listInstances"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": kwargs.get("json_body"),
                    }
                )
                return 200, {
                    "items": [],
                    "nextPageToken": f"membership-page-{len(self.calls)}",
                }
            return super().request_json(method, url, **kwargs)

    transport = EmptyMembershipLoopTransport()
    executor = GoogleResourceExecutor(transport)

    with pytest.raises(ProviderExecutionError) as captured:
        executor._list_instance_group_members(
            "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instanceGroups/g"
        )

    assert captured.value.error_code == ("instance-group-membership-pagination-limit-exceeded")
    assert len(transport.calls) == 100


def test_instance_group_listing_rejects_a_present_null_page_token() -> None:
    class NullMembershipTokenTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/listInstances"):
                return 200, {"items": [], "nextPageToken": None}
            return super().request_json(method, url, **kwargs)

    executor = GoogleResourceExecutor(NullMembershipTokenTransport())

    with pytest.raises(ProviderExecutionError) as captured:
        executor._list_instance_group_members(
            "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instanceGroups/g"
        )

    assert captured.value.error_code == "instance-group-membership-response-invalid"


def test_dns_record_create_and_delete_poll_the_exact_change_to_done() -> None:
    class DnsChangeTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.records: dict[str, dict[str, Any]] = {}
            self.next_change = 40

        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/changes"):
                body = deepcopy(kwargs.get("json_body") or {})
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": body,
                    }
                )
                for record in body.get("additions", []):
                    self.records[str(record["type"])] = deepcopy(record)
                for record in body.get("deletions", []):
                    self.records.pop(str(record["type"]), None)
                self.next_change += 1
                return 200, {
                    "kind": "dns#change",
                    "id": str(self.next_change),
                    "status": "pending",
                }
            if method == "GET" and "/changes/" in url:
                self.calls.append(
                    {"method": method, "url": url, "params": None, "body": None}
                )
                return 200, {
                    "kind": "dns#change",
                    "id": url.rsplit("/", maxsplit=1)[-1],
                    "status": "done",
                }
            if method == "GET" and "/rrsets/" in url:
                self.calls.append(
                    {"method": method, "url": url, "params": None, "body": None}
                )
                record_type = url.rsplit("/", maxsplit=1)[-1]
                record = self.records.get(record_type)
                if record is None:
                    return 404, {}
                return 200, {"kind": "dns#resourceRecordSet", **deepcopy(record)}
            return super().request_json(method, url, **kwargs)

    deployment = local_poc_spec()
    target = change("dns", "record_set", deployment.private_hostname)
    transport = DnsChangeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    executor.apply(target, deployment)
    assert executor.destroy(target, deployment) == "deleted"

    change_posts = [
        call
        for call in transport.calls
        if call["method"] == "POST" and call["url"].endswith("/changes")
    ]
    change_polls = [
        call
        for call in transport.calls
        if call["method"] == "GET" and "/changes/" in call["url"]
    ]
    assert len(change_posts) == 2
    assert [call["url"].rsplit("/", maxsplit=1)[-1] for call in change_polls] == [
        "41",
        "42",
    ]
    assert transport.records == {}


def test_dns_record_pending_change_with_malformed_poll_never_becomes_applied() -> None:
    class MalformedDnsChangeTransport(FakeTransport):
        def request_json(self, method, url, **kwargs):
            if method == "POST" and url.endswith("/changes"):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "params": kwargs.get("params"),
                        "body": deepcopy(kwargs.get("json_body") or {}),
                    }
                )
                return 200, {"kind": "dns#change", "id": "42", "status": "pending"}
            if method == "GET" and url.endswith("/changes/42"):
                self.calls.append(
                    {"method": method, "url": url, "params": None, "body": None}
                )
                return 200, {"kind": "dns#change", "id": "other", "status": "done"}
            return super().request_json(method, url, **kwargs)

    deployment = local_poc_spec()
    target = change("dns", "record_set", deployment.private_hostname)
    transport = MalformedDnsChangeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

    with pytest.raises(ProviderExecutionError) as captured:
        executor.apply(target, deployment)

    assert captured.value.error_code == "dns-change-identity-mismatch"
