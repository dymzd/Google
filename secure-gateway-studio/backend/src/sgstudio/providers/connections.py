from __future__ import annotations

from typing import Protocol

from google.auth.exceptions import DefaultCredentialsError, RefreshError

from sgstudio.domain.models import ConnectionValidation
from sgstudio.providers.google_rest import GoogleAuthorizedTransport, JsonTransport


class ConnectionValidator(Protocol):
    def validate_cloud(self, project_id: str) -> ConnectionValidation: ...

    def validate_workspace(
        self,
        customer_id: str,
        target_ou_id: str | None = None,
    ) -> ConnectionValidation: ...


class GoogleConnectionValidator:
    def __init__(
        self,
        transport: JsonTransport,
        *,
        principal_hint: str,
        credential_kind: str,
    ) -> None:
        self._transport = transport
        self._principal_hint = principal_hint
        self._credential_kind = credential_kind

    def validate_cloud(self, project_id: str) -> ConnectionValidation:
        _, project = self._transport.request_json(
            "GET",
            f"https://cloudresourcemanager.googleapis.com/v3/projects/{project_id}",
        )
        if project.get("projectId") != project_id:
            raise ValueError("Google Cloud returned an unexpected project identity")
        return ConnectionValidation(
            provider="google_cloud",
            status="connected",
            principal_hint=self._principal_hint,
            resource_id=project_id,
            credential_kind=self._credential_kind,
        )

    def validate_workspace(
        self,
        customer_id: str,
        target_ou_id: str | None = None,
    ) -> ConnectionValidation:
        self._transport.request_json(
            "GET",
            f"https://chromepolicy.googleapis.com/v1/customers/{customer_id}/policySchemas",
            params={"pageSize": 1},
        )
        if target_ou_id:
            self._transport.request_json(
                "POST",
                (
                    f"https://chromepolicy.googleapis.com/v1/customers/"
                    f"{customer_id}/policies:resolve"
                ),
                json_body={
                    "policySchemaFilter": "chrome.users.*",
                    "policyTargetKey": {"targetResource": f"orgunits/{target_ou_id}"},
                    "pageSize": 1,
                },
            )
        return ConnectionValidation(
            provider="workspace",
            status="connected",
            principal_hint=self._principal_hint,
            resource_id=customer_id,
            credential_kind=self._credential_kind,
        )


def create_google_connection_validator() -> GoogleConnectionValidator:
    try:
        transport = GoogleAuthorizedTransport.from_adc()
    except (DefaultCredentialsError, RefreshError) as error:
        raise RuntimeError(
            "Application Default Credentials are unavailable. Run "
            "`gcloud auth application-default login "
            "--impersonate-service-account=SERVICE_ACCOUNT_EMAIL`."
        ) from error
    return GoogleConnectionValidator(
        transport,
        principal_hint=transport.metadata.principal_hint,
        credential_kind=transport.metadata.kind,
    )
