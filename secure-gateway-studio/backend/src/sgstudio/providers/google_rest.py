from __future__ import annotations

import json
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
    "openidconnect.googleapis.com",
    "privateca.googleapis.com",
    "secretmanager.googleapis.com",
    "serviceusage.googleapis.com",
}

DEFAULT_SCOPES = (
    "openid",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/chrome.management.policy",
    "https://www.googleapis.com/auth/chrome.management.profiles.readonly",
    "https://www.googleapis.com/auth/apps.licensing",
    "https://www.googleapis.com/auth/userinfo.email",
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


@dataclass(frozen=True)
class GoogleUserIdentity:
    email: str
    subject: str


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
        self._credentials = credentials
        self._session = AuthorizedSession(credentials)
        self._timeout_seconds = timeout_seconds
        self.metadata = CredentialMetadata(
            kind=self._credential_kind(credentials),
            quota_project_id=quota_project_id,
            principal_hint=self._principal_hint(credentials),
        )

    @classmethod
    def from_adc(
        cls, *, require_impersonation: bool = False
    ) -> GoogleAuthorizedTransport:
        credentials, quota_project_id = google.auth.default(scopes=DEFAULT_SCOPES)
        if credentials.__class__.__module__ == "google.oauth2.service_account":
            raise RuntimeError(
                "Long-lived service account key ADC is not accepted. Use keyless "
                "`gcloud auth application-default login "
                "--impersonate-service-account=SERVICE_ACCOUNT_EMAIL`."
            )
        if (
            require_impersonation
            and cls._credential_kind(credentials) != "ImpersonatedServiceAccount"
        ):
            raise RuntimeError(
                "Cloud mutations require keyless impersonated service-account ADC; "
                "ordinary user ADC is read-only in Secure Gateway Studio"
            )
        return cls(credentials, quota_project_id=quota_project_id)

    def impersonation_source_user(self) -> GoogleUserIdentity:
        """Return the Google-attested human behind the impersonated ADC.

        Cloud SDK's active account is deliberately not consulted: gcloud's CLI
        credential store and Application Default Credentials are independent.
        """
        if self.metadata.kind != "ImpersonatedServiceAccount":
            raise RuntimeError("Impersonated ADC is required to attest its source user")
        source = getattr(self._credentials, "_source_credentials", None)
        if source is None or source.__class__.__module__ != "google.oauth2.credentials":
            raise RuntimeError(
                "The impersonated ADC source must be a Google human user credential"
            )
        response = AuthorizedSession(source).get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            timeout=self._timeout_seconds,
        )
        if response.status_code != 200:
            raise RuntimeError("Google could not attest the impersonated ADC source user")
        try:
            payload = response.json()
        except ValueError as error:
            raise RuntimeError(
                "Google returned an invalid source-user attestation"
            ) from error
        email = payload.get("email") if isinstance(payload, dict) else None
        subject = payload.get("sub") if isinstance(payload, dict) else None
        if (
            not isinstance(email, str)
            or not email
            or any(character.isspace() for character in email)
            or email.count("@") != 1
            or payload.get("email_verified") is not True
            or not isinstance(subject, str)
            or not subject
            or any(character.isspace() for character in subject)
        ):
            raise RuntimeError("Google returned an invalid source-user attestation")
        return GoogleUserIdentity(email=email.lower(), subject=subject)

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
        if response.status_code == 204:
            if response.status_code in accepted_statuses:
                return response.status_code, {}
            raise GoogleApiError(
                status_code=response.status_code,
                method=method.upper(),
                host=parsed.hostname,
                detail="No response body",
            )
        if not response.content:
            raise GoogleApiError(
                status_code=response.status_code,
                method=method.upper(),
                host=parsed.hostname,
                detail="Expected a non-empty JSON object response",
            )
        try:
            payload = response.json()
        except ValueError as error:
            raise GoogleApiError(
                status_code=response.status_code,
                method=method.upper(),
                host=parsed.hostname,
                detail="Expected a valid JSON object response",
            ) from error
        if not isinstance(payload, dict):
            raise GoogleApiError(
                status_code=response.status_code,
                method=method.upper(),
                host=parsed.hostname,
                detail="Expected a JSON object response",
            )
        if response.status_code not in accepted_statuses:
            raise GoogleApiError(
                status_code=response.status_code,
                method=method.upper(),
                host=parsed.hostname,
                detail=json.dumps(
                    payload,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        return response.status_code, payload
