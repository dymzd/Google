from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

from sgstudio.domain.models import MutationIdentity
from sgstudio.providers.google_rest import GoogleAuthorizedTransport


class MutationIdentityAuthorizer:
    """Resolve and verify the human operator and immutable keyless deployer.

    The bootstrap pin is local non-secret evidence. Every authorization also
    performs a fresh IAM GET using the same impersonated transport that will be
    used for the mutation, preventing same-email service-account replacement.
    """

    def __init__(
        self,
        transport: GoogleAuthorizedTransport,
        *,
        pin_path: Path,
    ) -> None:
        self.transport = transport
        self._pin_path = pin_path.resolve()

    def resolve(self, project_id: str) -> MutationIdentity:
        expected_email = (
            f"secure-gateway-deployer@{project_id}.iam.gserviceaccount.com"
        )
        metadata = self.transport.metadata
        if (
            metadata.kind != "ImpersonatedServiceAccount"
            or metadata.principal_hint != expected_email
        ):
            raise RuntimeError(
                "Cloud mutations require ADC impersonating the project-bound "
                "Secure Gateway Studio deployer service account"
            )
        pin = self._load_pin(project_id, expected_email)
        source_user = self.transport.impersonation_source_user()
        if source_user.email != pin["operator_email"]:
            raise RuntimeError(
                "The impersonated ADC source user does not match the reviewed "
                "bootstrap operator"
            )
        encoded_email = quote(expected_email, safe="")
        _, account = self.transport.request_json(
            "GET",
            (
                f"https://iam.googleapis.com/v1/projects/{project_id}/"
                f"serviceAccounts/{encoded_email}"
            ),
            accepted_statuses=(200,),
        )
        _, account_policy = self.transport.request_json(
            "POST",
            (
                f"https://iam.googleapis.com/v1/projects/{project_id}/"
                f"serviceAccounts/{encoded_email}:getIamPolicy"
            ),
            json_body={"options": {"requestedPolicyVersion": 3}},
            accepted_statuses=(200,),
        )
        unique_id = account.get("uniqueId")
        if (
            account.get("email") != expected_email
            or not isinstance(unique_id, str)
            or not unique_id.isdigit()
            or account.get("disabled") is True
            or unique_id != pin["service_account_unique_id"]
            or self._normalise_bindings(account_policy.get("bindings"))
            != pin["service_account_iam_bindings"]
        ):
            raise RuntimeError(
                "The live deployer service account does not match its immutable "
                "bootstrap ownership pin"
            )
        return MutationIdentity(
            operator_email=source_user.email,
            operator_subject=source_user.subject,
            project_id=project_id,
            service_account_email=expected_email,
            service_account_unique_id=unique_id,
        )

    def _load_pin(self, project_id: str, expected_email: str) -> dict[str, object]:
        try:
            document = json.loads(self._pin_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(
                "The immutable deployer bootstrap ownership pin is unavailable"
            ) from error
        projects = document.get("projects") if isinstance(document, dict) else None
        pin = projects.get(project_id) if isinstance(projects, dict) else None
        unique_id = pin.get("service_account_unique_id") if isinstance(pin, dict) else None
        bindings = (
            pin.get("service_account_iam_bindings") if isinstance(pin, dict) else None
        )
        operator_email = self._sole_token_creator(bindings)
        if (
            document.get("version") != 1
            or not isinstance(pin, dict)
            or pin.get("project_id") != project_id
            or pin.get("service_account_email") != expected_email
            or not isinstance(unique_id, str)
            or not unique_id.isdigit()
            or operator_email is None
            or pin.get("pending_mutation") is not None
        ):
            raise RuntimeError(
                "The immutable deployer bootstrap ownership pin is missing or invalid"
            )
        return {
            "service_account_unique_id": unique_id,
            "operator_email": operator_email,
            "service_account_iam_bindings": self._normalise_bindings(bindings),
        }

    @staticmethod
    def _sole_token_creator(raw: object) -> str | None:
        if not isinstance(raw, list):
            return None
        token_creator_bindings = [
            binding
            for binding in raw
            if isinstance(binding, dict)
            and binding.get("role") == "roles/iam.serviceAccountTokenCreator"
        ]
        if len(token_creator_bindings) != 1:
            return None
        binding = token_creator_bindings[0]
        if "condition" in binding:
            return None
        members = binding.get("members")
        if (
            not isinstance(members, list)
            or len(members) != 1
            or not isinstance(members[0], str)
            or not members[0].startswith("user:")
        ):
            return None
        email = members[0].removeprefix("user:").lower()
        if email.count("@") != 1 or any(character.isspace() for character in email):
            return None
        return email

    @staticmethod
    def _normalise_bindings(raw: object) -> list[dict[str, object]]:
        if not isinstance(raw, list):
            return []
        normalised: list[dict[str, object]] = []
        for binding in raw:
            if not isinstance(binding, dict) or not isinstance(binding.get("role"), str):
                raise RuntimeError("The deployer service-account IAM pin is malformed")
            members = binding.get("members", [])
            if not isinstance(members, list) or any(
                not isinstance(member, str) for member in members
            ):
                raise RuntimeError("The deployer service-account IAM pin is malformed")
            item: dict[str, object] = {
                "role": binding["role"],
                "members": sorted(set(members)),
            }
            if "condition" in binding:
                condition = binding["condition"]
                if not isinstance(condition, dict):
                    raise RuntimeError(
                        "The deployer service-account IAM pin is malformed"
                    )
                item["condition"] = {
                    key: condition[key]
                    for key in ("title", "description", "expression")
                    if isinstance(condition.get(key), str)
                }
            normalised.append(item)
        return sorted(
            normalised,
            key=lambda item: json.dumps(
                item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
        )


def create_mutation_identity_authorizer(
    *, pin_path: Path
) -> MutationIdentityAuthorizer:
    return MutationIdentityAuthorizer(
        GoogleAuthorizedTransport.from_adc(require_impersonation=True),
        pin_path=pin_path,
    )
