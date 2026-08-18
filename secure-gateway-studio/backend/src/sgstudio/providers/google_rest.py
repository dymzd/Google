from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

import google.auth
from google.auth.credentials import Credentials
from google.auth.transport.requests import AuthorizedSession

ALLOWED_GOOGLE_API_HOSTS = {
    "accesscontextmanager.googleapis.com",
    "admin.googleapis.com",
    "beyondcorp.googleapis.com",
    "chromepolicy.googleapis.com",
    "chromemanagement.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "cloudbilling.googleapis.com",
    "compute.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "licensing.googleapis.com",
    "logging.googleapis.com",
    "privateca.googleapis.com",
    "secretmanager.googleapis.com",
    "serviceusage.googleapis.com",
}

DEFAULT_SCOPES = (
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/chrome.management.policy",
    "https://www.googleapis.com/auth/chrome.management.profiles.readonly",
    "https://www.googleapis.com/auth/apps.licensing",
)


class JsonTransport(Protocol):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]: ...


class GoogleApiError(RuntimeError):
    def __init__(self, *, status_code: int, method: str, host: str, detail: str) -> None:
        super().__init__(f"Google API request failed ({status_code})")
        self.status_code = status_code
        self.method = method
        self.host = host
        self.detail = detail


@dataclass(frozen=True)
class CredentialMetadata:
    kind: str
    quota_project_id: str | None
    principal_hint: str


class GoogleAuthorizedTransport:
    """Allowlisted Google REST transport backed by local ADC.

    The transport never accepts arbitrary hosts and never serializes credentials.
    """

    def __init__(
        self,
        credentials: Credentials,
        *,
        quota_project_id: str | None = None,
        timeout_seconds: int = 20,
    ) -> None:
        self._session = AuthorizedSession(credentials)
        self._timeout_seconds = timeout_seconds
        self.metadata = CredentialMetadata(
            kind=self._credential_kind(credentials),
            quota_project_id=quota_project_id,
            principal_hint=self._principal_hint(credentials),
        )

    @classmethod
    def from_adc(cls) -> GoogleAuthorizedTransport:
        credentials, quota_project_id = google.auth.default(scopes=DEFAULT_SCOPES)
        if credentials.__class__.__module__ == "google.oauth2.service_account":
            raise RuntimeError(
                "Long-lived service account key ADC is not accepted. Use keyless "
                "`gcloud auth application-default login "
                "--impersonate-service-account=SERVICE_ACCOUNT_EMAIL`."
            )
        return cls(credentials, quota_project_id=quota_project_id)

    @staticmethod
    def _principal_hint(credentials: Credentials) -> str:
        service_account_email = getattr(credentials, "service_account_email", None)
        if isinstance(service_account_email, str) and service_account_email:
            return service_account_email
        return f"adc:{type(credentials).__name__}"

    @staticmethod
    def _credential_kind(credentials: Credentials) -> str:
        if credentials.__class__.__module__ == "google.auth.impersonated_credentials":
            return "ImpersonatedServiceAccount"
        return type(credentials).__name__

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_GOOGLE_API_HOSTS:
            raise ValueError("Google REST transport rejected a non-allowlisted API URL")

        response = self._session.request(
            method=method,
            url=url,
            params=params,
            json=json_body,
            timeout=(5, self._timeout_seconds),
            allow_redirects=False,
            headers={"Accept": "application/json"},
        )
        if response.status_code not in accepted_statuses:
            detail = response.text[:500] if response.text else "No response body"
            raise GoogleApiError(
                status_code=response.status_code,
                method=method.upper(),
                host=parsed.hostname,
                detail=detail,
            )
        if response.status_code == 204 or not response.content:
            return response.status_code, {}
        payload = response.json()
        if not isinstance(payload, dict):
            raise GoogleApiError(
                status_code=response.status_code,
                method=method.upper(),
                host=parsed.hostname,
                detail="Expected a JSON object response",
            )
        return response.status_code, payload
