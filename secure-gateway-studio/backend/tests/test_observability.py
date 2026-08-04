from typing import Any

from sgstudio.domain.models import (
    AccessPrincipal,
    DeploymentSpec,
    GatewayLogCategory,
    PrincipalType,
)
from sgstudio.providers.observability import GoogleGatewayObservability


def spec() -> DeploymentSpec:
    return DeploymentSpec(
        project_id="enterprise-secgw-01",
        ca_pool="projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise",
        ca_name=(
            "projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise/"
            "certificateAuthorities/issuing"
        ),
        target_ou_id="03-test-ou",
        managed_chrome_access_level=(
            "accessPolicies/123456789/accessLevels/managed_chrome"
        ),
        source_image="projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
        chrome_enterprise_premium_license_confirmed=True,
        workspace_services_confirmed=True,
        endpoint_verification_confirmed=True,
        test_ou_confirmed=True,
        principals=[
            AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")
        ],
    )


class ObservabilityTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

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
        if "securityGateways" in url:
            return 200, {"logging": {}}
        return 200, {
            "entries": [
                {
                    "insertId": "log-1",
                    "timestamp": "2026-08-04T00:00:00Z",
                    "severity": "NOTICE",
                    "protoPayload": {
                        "methodName": "AuthorizeUser",
                        "authenticationInfo": {
                            "principalEmail": "user@example.com",
                            "accessToken": "must-not-leak",
                        },
                    },
                }
            ]
        }


def test_access_log_query_uses_fixed_filter_and_redacts_credentials() -> None:
    transport = ObservabilityTransport()
    response = GoogleGatewayObservability(transport).list_logs(
        spec(), run_id="run-1", category=GatewayLogCategory.ACCESS
    )

    logging_call = next(call for call in transport.calls if "entries:list" in call["url"])
    assert 'resource.labels.method="AuthorizeUser"' in logging_call["body"]["filter"]
    assert response.logging_enabled is True
    assert response.entries[0].principal == "user@example.com"
    assert (
        response.entries[0].payload["protoPayload"]["authenticationInfo"]["accessToken"]
        == "[redacted]"
    )
