from typing import Any

from fastapi.testclient import TestClient

from sgstudio.api.main import SESSION_NONCE, app, connection_validator
from sgstudio.domain.models import ConnectionValidation
from sgstudio.providers.connections import GoogleConnectionValidator


class FakeConnectionTransport:
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
        if "cloudresourcemanager" in url:
            assert method == "GET"
            return 200, {"projectId": "enterprise-secgw-01"}
        assert "chromepolicy.googleapis.com" in url
        if url.endswith("/policies:resolve"):
            assert method == "POST"
            assert params is None
            assert json_body == {
                "policySchemaFilter": "chrome.users.*",
                "policyTargetKey": {"targetResource": "orgunits/03-test-ou"},
                "pageSize": 1,
            }
            return 200, {"resolvedPolicies": []}
        assert method == "GET"
        assert params == {"pageSize": 1}
        assert json_body is None
        return 200, {"policySchemas": [{"schemaName": "chrome.users.ShowHomeButton"}]}


def test_connection_validator_performs_real_resource_reads() -> None:
    validator = GoogleConnectionValidator(
        FakeConnectionTransport(),
        principal_hint="adc:authorized-user",
        credential_kind="Credentials",
    )

    cloud = validator.validate_cloud("enterprise-secgw-01")
    workspace = validator.validate_workspace("C012abcde", "03-test-ou")

    assert cloud.resource_id == "enterprise-secgw-01"
    assert workspace.resource_id == "C012abcde"
    assert cloud.read_only is True
    assert workspace.provider == "workspace"


class FakeConnectionValidator:
    def validate_cloud(self, project_id: str) -> ConnectionValidation:
        return ConnectionValidation(
            provider="google_cloud",
            status="connected",
            principal_hint="operator@example.com",
            resource_id=project_id,
            credential_kind="AuthorizedUserCredentials",
        )

    def validate_workspace(
        self,
        customer_id: str,
        target_ou_id: str | None = None,
    ) -> ConnectionValidation:
        del target_ou_id
        return ConnectionValidation(
            provider="workspace",
            status="connected",
            principal_hint="admin@example.com",
            resource_id=customer_id,
            credential_kind="AuthorizedUserCredentials",
        )


def test_connection_validation_endpoints_are_injectable() -> None:
    app.dependency_overrides[connection_validator] = lambda: FakeConnectionValidator()
    client = TestClient(app)
    try:
        cloud = client.post(
            "/api/v1/connections/google-cloud/validate",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "X-SGS-Session": SESSION_NONCE,
            },
            json={"project_id": "enterprise-secgw-01"},
        )
        workspace = client.post(
            "/api/v1/connections/workspace/validate",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "X-SGS-Session": SESSION_NONCE,
            },
            json={"customer_id": "C012abcde"},
        )
    finally:
        app.dependency_overrides.pop(connection_validator, None)

    assert cloud.status_code == 200
    assert cloud.json()["principal_hint"] == "operator@example.com"
    assert workspace.status_code == 200
    assert workspace.json()["resource_id"] == "C012abcde"
