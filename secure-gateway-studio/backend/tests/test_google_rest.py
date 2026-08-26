import pytest
from google.auth import impersonated_credentials
from google.auth.credentials import AnonymousCredentials

import sgstudio.providers.google_rest as google_rest
from sgstudio.providers.google_rest import (
    DEFAULT_SCOPES,
    GoogleApiError,
    GoogleAuthorizedTransport,
)


def test_impersonated_credentials_expose_target_service_account() -> None:
    credentials = impersonated_credentials.Credentials(
        source_credentials=AnonymousCredentials(),
        target_principal=("secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com"),
        target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )

    transport = GoogleAuthorizedTransport(credentials)

    assert transport.metadata.kind == "ImpersonatedServiceAccount"
    assert transport.metadata.principal_hint == (
        "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com"
    )


def test_service_account_key_adc_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    class ServiceAccountKeyCredentials(AnonymousCredentials):
        __module__ = "google.oauth2.service_account"

    monkeypatch.setattr(
        google_rest.google.auth,
        "default",
        lambda **_: (ServiceAccountKeyCredentials(), "enterprise-secgw-01"),
    )

    with pytest.raises(RuntimeError, match="Long-lived service account key ADC"):
        GoogleAuthorizedTransport.from_adc()


def test_mutation_transport_rejects_ordinary_user_adc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        google_rest.google.auth,
        "default",
        lambda **_: (AnonymousCredentials(), "enterprise-secgw-01"),
    )

    with pytest.raises(RuntimeError, match="ordinary user ADC is read-only"):
        GoogleAuthorizedTransport.from_adc(require_impersonation=True)


def test_adc_scopes_include_licensing_and_source_user_attestation() -> None:
    assert "https://www.googleapis.com/auth/apps.licensing" in DEFAULT_SCOPES
    assert "https://www.googleapis.com/auth/userinfo.email" in DEFAULT_SCOPES
    assert "openid" in DEFAULT_SCOPES


def test_impersonation_source_user_uses_google_userinfo_not_cli_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class HumanCredentials(AnonymousCredentials):
        __module__ = "google.oauth2.credentials"

    class ImpersonatedCredentials(AnonymousCredentials):
        __module__ = "google.auth.impersonated_credentials"
        service_account_email = (
            "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com"
        )

        def __init__(self) -> None:
            self._source_credentials = HumanCredentials()

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {
                "email": "Operator@Example.com",
                "email_verified": True,
                "sub": "google-subject-123",
            }

    class Session:
        def __init__(self, credentials) -> None:
            self.credentials = credentials

        def get(self, url: str, *, timeout: int):
            assert isinstance(self.credentials, HumanCredentials)
            assert url == "https://openidconnect.googleapis.com/v1/userinfo"
            assert timeout == 20
            return Response()

    monkeypatch.setattr(google_rest, "AuthorizedSession", Session)

    identity = GoogleAuthorizedTransport(
        ImpersonatedCredentials()
    ).impersonation_source_user()

    assert identity.email == "operator@example.com"
    assert identity.subject == "google-subject-123"


class _TransportResponse:
    def __init__(self, status_code: int, body: bytes, payload=...) -> None:
        self.status_code = status_code
        self.content = body
        self.text = body.decode("utf-8", errors="replace")
        self._payload = payload

    def json(self):
        if self._payload is ...:
            raise ValueError("invalid json")
        return self._payload


class _TransportSession:
    def __init__(self, response: _TransportResponse) -> None:
        self.response = response

    def request(self, **_kwargs):
        return self.response


def _transport_with_response(response: _TransportResponse) -> GoogleAuthorizedTransport:
    transport = GoogleAuthorizedTransport(AnonymousCredentials())
    transport._session = _TransportSession(response)  # type: ignore[assignment]
    return transport


def test_transport_accepts_object_json_and_explicit_http_204_only() -> None:
    transport = _transport_with_response(
        _TransportResponse(200, b'{"items":[]}', {"items": []})
    )
    assert transport.request_json(
        "GET", "https://compute.googleapis.com/compute/v1/projects/demo"
    ) == (200, {"items": []})

    no_content = _transport_with_response(_TransportResponse(204, b""))
    assert no_content.request_json(
        "DELETE",
        "https://compute.googleapis.com/compute/v1/projects/demo/global/networks/example",
        accepted_statuses=(204,),
    ) == (204, {})


@pytest.mark.parametrize("status_code", [200, 201, 202, 404])
def test_transport_rejects_unexpected_empty_bodies(status_code: int) -> None:
    transport = _transport_with_response(_TransportResponse(status_code, b""))

    with pytest.raises(GoogleApiError) as captured:
        transport.request_json(
            "GET",
            "https://compute.googleapis.com/compute/v1/projects/demo",
            accepted_statuses=(status_code,),
        )

    assert captured.value.status_code == status_code
    assert captured.value.detail == "Expected a non-empty JSON object response"


@pytest.mark.parametrize(
    ("body", "payload"),
    [
        (b"<html>tenant-secret</html>", ...),
        (b"[]", []),
        (b"null", None),
        (b"true", True),
        (b'"text"', "text"),
        (b"42", 42),
    ],
)
def test_transport_rejects_non_object_json_without_retaining_raw_body(
    body: bytes,
    payload,
) -> None:
    transport = _transport_with_response(_TransportResponse(200, body, payload))

    with pytest.raises(GoogleApiError) as captured:
        transport.request_json(
            "GET", "https://admin.googleapis.com/admin/directory/v1/groups"
        )

    assert "tenant-secret" not in captured.value.detail
    assert "tenant-secret" not in str(captured.value)


def test_transport_sanitizes_malformed_non_success_response() -> None:
    transport = _transport_with_response(
        _TransportResponse(403, b"not-json operator@example.com")
    )

    with pytest.raises(GoogleApiError) as captured:
        transport.request_json(
            "GET", "https://admin.googleapis.com/admin/directory/v1/groups"
        )

    assert captured.value.status_code == 403
    assert captured.value.detail == "Expected a valid JSON object response"
    assert "operator@example.com" not in captured.value.detail
