import pytest
from google.auth import impersonated_credentials
from google.auth.credentials import AnonymousCredentials

import sgstudio.providers.google_rest as google_rest
from sgstudio.providers.google_rest import GoogleAuthorizedTransport


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
