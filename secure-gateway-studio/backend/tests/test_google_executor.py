from __future__ import annotations

import subprocess
from copy import deepcopy
from dataclasses import replace
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
    NetworkStrategy,
    PrincipalType,
    ResourceChange,
    RiskLevel,
)
from sgstudio.domain.planner import (
    DesiredStatePlanner,
    canonical_configuration_hash,
    certificate_configuration_hash,
)
from sgstudio.providers.certificates import CertificateIssuer
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
        target_ou_id="03-test-ou",
        test_ou_confirmed=True,
        principals=[AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")],
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
                return 200, {"applications": [{"name": "remaining"}]}
            return super().request_json(method, url, **kwargs)

    transport = NonEmptyGatewayTransport()
    executor = GoogleResourceExecutor(transport)

    assert executor.destroy(
        change("beyondcorp", "application", "secure-gateway-http-offload-app"), spec()
    ) == "deleted"
    assert executor.destroy(
        change("beyondcorp", "security_gateway", "default"), spec()
    ) == "skipped"
    assert any(
        call["method"] == "DELETE" and call["url"].endswith("-app")
        for call in transport.calls
    )


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
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
                                '{"status":200,"configuration_hash":"'
                                + configuration_hash
                                + '"}'
                            ),
                        },
                        {
                            "namespace": "sgstudio",
                            "key": "T02",
                            "value": (
                                '{"status":200,"configuration_hash":"'
                                + configuration_hash
                                + '"}'
                            ),
                        },
                        {
                            "namespace": "sgstudio",
                            "key": "T03",
                            "value": (
                                '{"http_status":200,"tls_version":"TLSv1.3",'
                                '"hostname":"demo-server-http.internal",'
                                '"subject_alt_names":["demo-server-http.internal"],'
                                '"configuration_hash":"'
                                + configuration_hash
                                + '"}'
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
        if url.endswith("/policies:resolve"):
            return 200, {"resolvedPolicies": []}
        if url.endswith("networks:defineCertificate"):
            return 200, {"networkId": "{test-root-guid}"}
        if method == "GET" and url.endswith("/secrets/secure-gateway-http-offload-tls"):
            return 200, {
                "etag": "secret-etag",
                "versionAliases": {"active": "7"},
            }
        if method == "POST" and url.endswith("/secrets/secure-gateway-http-offload-tls:addVersion"):
            return 200, {
                "name": (
                    "projects/enterprise-secgw-01/secrets/"
                    "secure-gateway-http-offload-tls/versions/8"
                )
            }
        if method == "GET" and "/instanceGroupManagers/" in url:
            return 404, {}
        if method in {"POST", "PATCH", "DELETE"}:
            if "compute.googleapis.com" in url:
                return 200, {"status": "DONE"}
            return 200, {}
        return 200, {}


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
            self.calls.append(
                {"method": method, "url": url, "params": params, "body": json_body}
            )
            return 200, deepcopy(self.current_policy)
        if url.endswith(":setIamPolicy"):
            self.calls.append(
                {"method": method, "url": url, "params": params, "body": json_body}
            )
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
            self.calls.append(
                {"method": method, "url": url, "params": params, "body": json_body}
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
            self.calls.append(
                {"method": method, "url": url, "params": params, "body": json_body}
            )
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
            self.calls.append(
                {"method": method, "url": url, "params": params, "body": json_body}
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
            self.calls.append(
                {"method": method, "url": url, "params": params, "body": json_body}
            )
            return 200, {
                "name": (
                    "projects/enterprise-secgw-01/serviceAccounts/"
                    "secure-gateway-cd03d7-offload@enterprise-secgw-01.iam.gserviceaccount.com"
                ),
                "email": (
                    "secure-gateway-cd03d7-offload@"
                    "enterprise-secgw-01.iam.gserviceaccount.com"
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


def test_backend_vm_logs_the_propagated_request_id_as_structured_json() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)

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
    assert '"request_id":"$http_x_request_id"' in script
    assert "access_log /var/log/nginx/sgstudio-access.log" in script


def test_instance_apply_rolls_back_when_runtime_readiness_never_arrives() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(
        transport,
        poll_interval_seconds=0,
        operation_timeout_seconds=0,
    )

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
    executor._certificate = replace(
        CertificateIssuer().issue_local_poc(
            hostname="demo-server-http.internal",
            lifetime_days=90,
        ),
        issuer_resource_name=(
            "projects/enterprise-secgw-01/locations/asia-east1/caPools/"
            "enterprise/certificates/rotation-test"
        ),
    )
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
    assert alias_updates[0]["params"] == {"updateMask": "version_aliases,labels"}
    assert alias_updates[0]["body"]["versionAliases"]["active"] == "8"
    assert alias_updates[0]["body"]["labels"]["configuration-hash"] == (
        canonical_configuration_hash(spec())[:32]
    )
    assert alias_updates[0]["body"]["labels"]["certificate-spec-hash"] == (
        certificate_configuration_hash(spec())[:32]
    )
    assert alias_updates[-1]["body"]["versionAliases"]["active"] == "7"
    assert alias_updates[-1]["body"]["labels"] == {}
    assert any(call["url"].endswith("/versions/8:disable") for call in transport.calls)
    revoke = next(call for call in transport.calls if call["url"].endswith(":revoke"))
    assert revoke["body"]["reason"] == "CESSATION_OF_OPERATION"


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
            self.calls.append(
                {"method": method, "url": url, "params": params, "body": json_body}
            )
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
            self.calls.append(
                {"method": method, "url": url, "params": params, "body": json_body}
            )
            return 200, {
                "resolvedPolicies": [
                    {
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
    inherit = next(call for call in transport.calls if call["url"].endswith(":batchInherit"))
    assert inherit["body"]["requests"] == [
        {
            "policyTargetKey": {"targetResource": "orgunits/03-test-ou"},
            "policySchema": "chrome.users.SimpleProxySettings",
        }
    ]


def test_local_poc_root_is_exported_for_admin_console_and_removed_on_rollback(
    tmp_path: Path,
) -> None:
    transport = FakeTransport()
    artifacts = CertificateArtifactStore(tmp_path)
    executor = GoogleResourceExecutor(
        transport,
        artifact_store=artifacts,
        poll_interval_seconds=0,
    )
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
    assert not (tmp_path / "secure-gateway-http-offload-poc-root.pem").exists()


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
    policy = set_call["body"]["policy"]
    binding = next(
        item for item in policy["bindings"] if item["role"] == "roles/beyondcorp.sgApplicationUser"
    )
    assert policy["version"] == 3
    assert binding["condition"]["expression"] == (
        "'accessPolicies/123456789/accessLevels/managed_chrome' "
        "in request.auth.access_levels"
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
    assert create_call["body"]["endpoint_matchers"] == [
        {"hostname": "app.corp.internal", "ports": [8443]}
    ]
    assert create_call["body"]["upstreams"] == [
        {
            "network": {
                "name": "projects/enterprise-secgw-01/global/networks/private-app-vpc"
            },
            "egress_policy": {"regions": ["asia-east1"]},
        }
    ]


def test_iam_rollback_restores_before_image_with_latest_etag() -> None:
    transport = StatefulIamTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    iam_change = change("secretmanager", "secret_iam", "secure-gateway-http-offload-tls-accessor")

    executor.apply(iam_change, spec())
    executor.rollback(iam_change, spec())

    set_calls = [call for call in transport.calls if call["url"].endswith(":setIamPolicy")]
    assert set_calls[0]["body"]["policy"]["etag"] == "before-etag"
    assert set_calls[-1]["body"]["policy"]["etag"] == "current-etag-1"
    assert transport.current_policy["bindings"] == transport.original_policy["bindings"]


def test_new_secret_iam_rollback_is_owned_by_parent_secret_cleanup() -> None:
    transport = FakeTransport()
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    secret_change = change("secretmanager", "secret", "secure-gateway-http-offload-tls")
    iam_change = change(
        "secretmanager", "secret_iam", "secure-gateway-http-offload-tls-accessor"
    )

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
