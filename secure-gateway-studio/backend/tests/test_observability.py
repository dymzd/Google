from typing import Any

import pytest

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
        if method == "GET" and "/securityGateways/" in url:
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


def test_access_log_query_requests_and_returns_only_operational_fields() -> None:
    transport = ObservabilityTransport()
    response = GoogleGatewayObservability(transport).list_logs(
        spec(), run_id="run-1", category=GatewayLogCategory.ACCESS
    )

    logging_call = next(call for call in transport.calls if "entries:list" in call["url"])
    assert 'resource.labels.method="AuthorizeUser"' in logging_call["body"]["filter"]
    assert "principalEmail" not in logging_call["params"]["fields"]
    assert "textPayload" not in logging_call["params"]["fields"]
    assert "receiveTimestamp" not in logging_call["params"]["fields"]
    assert response.logging_enabled is None
    assert all("securityGateways" not in call["url"] for call in transport.calls)
    assert response.entries[0].principal is None
    assert response.entries[0].resource is None
    assert response.entries[0].payload == {}
    assert "must-not-leak" not in response.model_dump_json()


def test_connection_log_query_freshly_confirms_exact_gateway_logging_marker() -> None:
    transport = ObservabilityTransport()
    response = GoogleGatewayObservability(transport).list_logs(
        spec(), run_id="run-1", category=GatewayLogCategory.CONNECTION
    )

    gateway_call = next(
        call for call in transport.calls if "/securityGateways/" in call["url"]
    )
    assert gateway_call == {
        "method": "GET",
        "url": (
            "https://beyondcorp.googleapis.com/v1/projects/enterprise-secgw-01/"
            "locations/global/securityGateways/default"
        ),
        "params": {"fields": "logging"},
        "body": None,
    }
    assert response.logging_enabled is True


class GatewayLoggingStateTransport(ObservabilityTransport):
    def __init__(self, gateway_payload: dict[str, Any]) -> None:
        super().__init__()
        self.gateway_payload = gateway_payload

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if method == "GET" and "/securityGateways/" in url:
            self.calls.append(
                {"method": method, "url": url, "params": params, "body": json_body}
            )
            return 200, self.gateway_payload
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_connection_log_query_reports_missing_gateway_logging_as_disabled() -> None:
    transport = GatewayLoggingStateTransport({})
    response = GoogleGatewayObservability(transport).list_logs(
        spec(), run_id="run-1", category=GatewayLogCategory.CONNECTION
    )

    assert response.logging_enabled is False


def test_connection_log_query_rejects_malformed_gateway_logging_before_log_read() -> None:
    transport = GatewayLoggingStateTransport({"logging": {"enabled": True}})

    try:
        GoogleGatewayObservability(transport).list_logs(
            spec(), run_id="run-1", category=GatewayLogCategory.CONNECTION
        )
    except ValueError as error:
        assert str(error) == "security-gateway-logging-state-invalid"
    else:
        raise AssertionError("malformed gateway logging state was accepted")
    assert all("entries:list" not in call["url"] for call in transport.calls)


class LogPaginationTransport(ObservabilityTransport):
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        super().__init__()
        self.pages = pages
        self.page_index = 0

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
        if "entries:list" not in url:
            return 200, {"logging": {}}
        page = self.pages[min(self.page_index, len(self.pages) - 1)]
        self.page_index += 1
        return 200, page


def test_log_query_follows_empty_page_token_until_later_entry() -> None:
    transport = LogPaginationTransport(
        [
            {"entries": [], "nextPageToken": "page-2"},
            {"entries": [{"insertId": "later", "severity": "INFO"}]},
        ]
    )
    response = GoogleGatewayObservability(transport).list_logs(
        spec(), run_id="run-paged", category=GatewayLogCategory.ADMIN
    )

    logging_calls = [call for call in transport.calls if "entries:list" in call["url"]]
    assert response.entries[0].insert_id == "later"
    assert "pageToken" not in logging_calls[0]["body"]
    assert logging_calls[1]["body"]["pageToken"] == "page-2"
    assert "nextPageToken" in logging_calls[0]["params"]["fields"]


@pytest.mark.parametrize("token", [None, 7])
def test_log_query_rejects_present_non_string_page_token(token: object) -> None:
    transport = LogPaginationTransport([{"entries": [], "nextPageToken": token}])

    with pytest.raises(ValueError, match="cloud-logging-page-token-invalid"):
        GoogleGatewayObservability(transport).list_logs(
            spec(), run_id="run-token", category=GatewayLogCategory.ADMIN
        )


def test_log_query_rejects_repeated_page_token() -> None:
    transport = LogPaginationTransport(
        [{"entries": [], "nextPageToken": "repeat"}]
    )

    with pytest.raises(ValueError, match="cloud-logging-page-token-invalid"):
        GoogleGatewayObservability(transport).list_logs(
            spec(), run_id="run-repeat", category=GatewayLogCategory.ADMIN
        )
    assert transport.page_index == 2


def test_log_query_rejects_incomplete_page_cap() -> None:
    transport = LogPaginationTransport(
        [
            {"entries": [], "nextPageToken": f"page-{index}"}
            for index in range(1, 101)
        ]
    )

    with pytest.raises(ValueError, match="cloud-logging-pagination-incomplete"):
        GoogleGatewayObservability(transport).list_logs(
            spec(), run_id="run-cap", category=GatewayLogCategory.ADMIN
        )
    assert transport.page_index == 100


def test_log_query_rejects_malformed_entry_before_returning_partial_results() -> None:
    transport = LogPaginationTransport([{"entries": [None]}])

    with pytest.raises(ValueError, match="cloud-logging-entries-invalid"):
        GoogleGatewayObservability(transport).list_logs(
            spec(), run_id="run-items", category=GatewayLogCategory.ADMIN
        )
