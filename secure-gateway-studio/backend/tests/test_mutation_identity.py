import json
from pathlib import Path

import pytest

from sgstudio.providers.google_rest import CredentialMetadata, GoogleUserIdentity
from sgstudio.providers.mutation_identity import MutationIdentityAuthorizer

PROJECT_ID = "enterprise-secgw-01"
DEPLOYER_EMAIL = (
    "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com"
)
DEPLOYER_ID = "123456789012345678901"


class FakeTransport:
    def __init__(
        self,
        *,
        source_email: str = "operator@example.com",
        source_subject: str = "google-subject-1",
        unique_id: str = DEPLOYER_ID,
        policy_members: list[str] | None = None,
    ) -> None:
        self.metadata = CredentialMetadata(
            kind="ImpersonatedServiceAccount",
            quota_project_id=PROJECT_ID,
            principal_hint=DEPLOYER_EMAIL,
        )
        self._source = GoogleUserIdentity(
            email=source_email,
            subject=source_subject,
        )
        self._unique_id = unique_id
        self._policy_members = policy_members or ["user:operator@example.com"]

    def impersonation_source_user(self) -> GoogleUserIdentity:
        return self._source

    def request_json(self, method: str, url: str, **kwargs):
        del kwargs
        if method == "GET" and ":getIamPolicy" not in url:
            return 200, {
                "email": DEPLOYER_EMAIL,
                "uniqueId": self._unique_id,
                "disabled": False,
            }
        if method == "POST" and url.endswith(":getIamPolicy"):
            return 200, {
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "members": self._policy_members,
                    }
                ]
            }
        raise AssertionError((method, url))


def write_pin(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "projects": {
                    PROJECT_ID: {
                        "project_id": PROJECT_ID,
                        "service_account_email": DEPLOYER_EMAIL,
                        "service_account_unique_id": DEPLOYER_ID,
                        "service_account_iam_bindings": [
                            {
                                "role": "roles/iam.serviceAccountTokenCreator",
                                "members": ["user:operator@example.com"],
                            }
                        ],
                        "custom_role": (
                            f"projects/{PROJECT_ID}/roles/secureGatewayPocDeployer"
                        ),
                        "custom_role_etag": "role-etag-1",
                    }
                },
            }
        ),
        encoding="utf-8",
    )


def test_authorizer_binds_google_attested_adc_source_and_immutable_deployer(
    tmp_path: Path,
) -> None:
    pin_path = tmp_path / "pins.json"
    write_pin(pin_path)

    identity = MutationIdentityAuthorizer(
        FakeTransport(),  # type: ignore[arg-type]
        pin_path=pin_path,
    ).resolve(PROJECT_ID)

    assert identity.operator_email == "operator@example.com"
    assert identity.operator_subject == "google-subject-1"
    assert identity.service_account_unique_id == DEPLOYER_ID


def test_authorizer_rejects_different_adc_source_even_if_cli_might_show_pin_owner(
    tmp_path: Path,
) -> None:
    pin_path = tmp_path / "pins.json"
    write_pin(pin_path)

    with pytest.raises(RuntimeError, match="source user does not match"):
        MutationIdentityAuthorizer(
            FakeTransport(source_email="other-operator@example.com"),  # type: ignore[arg-type]
            pin_path=pin_path,
        ).resolve(PROJECT_ID)


def test_authorizer_rejects_recreated_same_email_service_account(tmp_path: Path) -> None:
    pin_path = tmp_path / "pins.json"
    write_pin(pin_path)

    with pytest.raises(RuntimeError, match="immutable bootstrap ownership pin"):
        MutationIdentityAuthorizer(
            FakeTransport(unique_id="999999999999999999999"),  # type: ignore[arg-type]
            pin_path=pin_path,
        ).resolve(PROJECT_ID)


def test_authorizer_rejects_service_account_token_creator_policy_drift(
    tmp_path: Path,
) -> None:
    pin_path = tmp_path / "pins.json"
    write_pin(pin_path)

    with pytest.raises(RuntimeError, match="immutable bootstrap ownership pin"):
        MutationIdentityAuthorizer(
            FakeTransport(  # type: ignore[arg-type]
                policy_members=[
                    "user:operator@example.com",
                    "user:attacker@example.com",
                ]
            ),
            pin_path=pin_path,
        ).resolve(PROJECT_ID)
