from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from sgstudio.domain.iam_policy import validate_iam_policy_v3


@dataclass(frozen=True)
class DeployerBootstrapResult:
    project_id: str
    operator_email: str
    service_account_email: str
    service_account_unique_id: str
    custom_role: str
    access_policy_id: str | None
    adc_command: str


class DeployerBootstrapper(Protocol):
    def bootstrap(
        self,
        project_id: str,
        *,
        allow_ownership_migration: bool = False,
    ) -> DeployerBootstrapResult: ...


class BootstrapOwnershipError(RuntimeError):
    """Fail-closed bootstrap decision with a stable browser-facing code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class GcloudDeployerBootstrapper:
    """Bootstrap the keyless deployer with the active gcloud user.

    Commands are passed as argument arrays without a shell. The browser-facing
    API validates the project ID and requires an explicit BOOTSTRAP confirmation.
    """

    _account_pattern = re.compile(r"^[^\s@]+@[^\s@]+$")
    _account_id = "secure-gateway-deployer"
    # The legacy role ID is already installed in customer projects. Its
    # manifest now covers every supported PoC and Production execution path.
    _role_id = "secureGatewayPocDeployer"
    _legacy_020_role_definition_digest = (
        "9e52930185796ea4ba7fca0b2dc69fad5d8e309b445d773aae974ea34402dcf3"
    )

    def __init__(
        self,
        *,
        gcloud_path: str | None = None,
        access_policy_id: str | None = None,
        pin_path: Path | None = None,
    ) -> None:
        self._gcloud = gcloud_path or shutil.which("gcloud") or ""
        if not self._gcloud:
            raise RuntimeError("gcloud CLI is required for automatic deployer setup")
        self._role_file = (
            Path(__file__).resolve().parents[4]
            / "infrastructure"
            / "iam"
            / "secure-gateway-poc-deployer-role.yaml"
        )
        if not self._role_file.is_file():
            raise RuntimeError("The bundled deployer role manifest is unavailable")
        self._pin_path = (
            pin_path
            if pin_path is not None
            else Path.cwd() / ".local" / "secure-gateway-bootstrap-pins.json"
        ).resolve()
        configured_policy = (
            access_policy_id
            if access_policy_id is not None
            else os.getenv("SGSTUDIO_ACCESS_POLICY_ID", "")
        ).strip()
        self._access_policy_id = configured_policy if configured_policy.isdigit() else None

    @staticmethod
    def _normalise_bindings(value: object) -> list[dict[str, object]]:
        if value is None:
            return []
        try:
            validated = validate_iam_policy_v3({"version": 3, "bindings": value})
        except ValueError as error:
            raise RuntimeError(
                "The deployer service-account IAM policy is malformed"
            ) from error
        bindings = validated.get("bindings", [])
        for binding in bindings:
            binding["members"] = sorted(binding["members"])
        return sorted(
            bindings,
            key=lambda binding: json.dumps(
                binding,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

    @staticmethod
    def _validated_iam_policy(policy: object) -> dict[str, object]:
        try:
            return validate_iam_policy_v3(policy, require_etag=True)
        except ValueError as error:
            raise RuntimeError("Google returned a malformed IAM policy") from error

    def _role_manifest_definition(self) -> dict[str, object]:
        definition: dict[str, object] = {"includedPermissions": []}
        permissions = definition["includedPermissions"]
        assert isinstance(permissions, list)
        for raw_line in self._role_file.read_text(encoding="utf-8").splitlines():
            if raw_line.startswith("title: "):
                definition["title"] = raw_line.removeprefix("title: ")
            elif raw_line.startswith("description: "):
                definition["description"] = raw_line.removeprefix("description: ")
            elif raw_line.startswith("stage: "):
                definition["stage"] = raw_line.removeprefix("stage: ")
            elif raw_line.startswith("  - "):
                permissions.append(raw_line.removeprefix("  - ").strip())
        if any(field not in definition for field in ("title", "description", "stage")):
            raise RuntimeError("The bundled deployer role manifest is malformed")
        return definition

    @staticmethod
    def _role_definition_digest(role: dict[str, object]) -> str | None:
        permissions = role.get("includedPermissions")
        if (
            not isinstance(role.get("title"), str)
            or not isinstance(role.get("description"), str)
            or not isinstance(role.get("stage"), str)
            or not isinstance(permissions, list)
            or any(not isinstance(permission, str) for permission in permissions)
        ):
            return None
        canonical = {
            "description": role["description"],
            "includedPermissions": sorted(permissions),
            "stage": role["stage"],
            "title": role["title"],
        }
        encoded = json.dumps(
            canonical,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return sha256(encoded).hexdigest()

    def _is_known_migration_role(
        self,
        role: dict[str, object],
        expected_name: str,
    ) -> bool:
        if role.get("name") != expected_name or role.get("deleted") is True:
            return False
        digest = self._role_definition_digest(role)
        return digest in {
            self._role_definition_digest(self._role_manifest_definition()),
            self._legacy_020_role_definition_digest,
        }

    @classmethod
    def _assert_legacy_service_account_iam(
        cls,
        policy: dict[str, object],
        operator_email: str,
    ) -> list[dict[str, object]]:
        validated = cls._validated_iam_policy(policy)
        bindings = cls._normalise_bindings(validated.get("bindings"))
        expected = [
            {
                "role": "roles/iam.serviceAccountTokenCreator",
                "members": [f"user:{operator_email}"],
            }
        ]
        if bindings != expected:
            raise BootstrapOwnershipError(
                "legacy-deployer-service-account-iam-unsafe",
                "The legacy deployer service account must have exactly one "
                "unconditional Token Creator principal: the current operator. "
                "Nothing was adopted or granted.",
            )
        return bindings

    @classmethod
    def _sole_token_creator_operator(
        cls,
        bindings: object,
    ) -> str | None:
        normalised = cls._normalise_bindings(bindings)
        if len(normalised) != 1:
            return None
        binding = normalised[0]
        members = binding.get("members")
        if (
            binding.get("role") != "roles/iam.serviceAccountTokenCreator"
            or "condition" in binding
            or not isinstance(members, list)
            or len(members) != 1
            or not isinstance(members[0], str)
        ):
            return None
        match = re.fullmatch(r"user:([^@\s]+@[^@\s]+\.[^@\s]+)", members[0])
        return match.group(1).lower() if match else None

    @classmethod
    def _assert_legacy_project_iam(
        cls,
        policy: dict[str, object],
        service_account_member: str,
        role_name: str,
    ) -> None:
        validated = cls._validated_iam_policy(policy)
        bindings = cls._normalise_bindings(validated.get("bindings"))
        expected_roles = {
            role_name,
            "roles/browser",
            "roles/serviceusage.serviceUsageConsumer",
        }
        attached = [
            binding
            for binding in bindings
            if service_account_member in binding["members"]
        ]
        custom_role_bindings = [
            binding for binding in bindings if binding["role"] == role_name
        ]
        safe = (
            len(attached) == len(expected_roles)
            and all("condition" not in binding for binding in attached)
            and {str(binding["role"]) for binding in attached} == expected_roles
            and len(custom_role_bindings) == 1
            and "condition" not in custom_role_bindings[0]
            and custom_role_bindings[0]["members"] == [service_account_member]
        )
        if not safe:
            raise BootstrapOwnershipError(
                "legacy-deployer-project-iam-unsafe",
                "The legacy deployer has project bindings outside the exact 0.2.0 "
                "allowlist, or required bindings are missing. Nothing was adopted "
                "or granted.",
            )

    @staticmethod
    def _parent_resource(value: object) -> str | None:
        if isinstance(value, str) and re.fullmatch(
            r"(?:organizations|folders)/\d+", value
        ):
            return value
        if isinstance(value, dict):
            parent_type = value.get("type")
            parent_id = value.get("id")
            if (
                parent_type in {"organization", "folder"}
                and isinstance(parent_id, (str, int))
                and str(parent_id).isdigit()
            ):
                collection = (
                    "organizations" if parent_type == "organization" else "folders"
                )
                return f"{collection}/{parent_id}"
        return None

    def _project_policy_context(self, project_id: str) -> tuple[str, set[str]]:
        project = self._json(
            "projects",
            "describe",
            project_id,
            "--format=json",
        )
        project_number = project.get("projectNumber")
        if not isinstance(project_number, (str, int)) or not str(
            project_number
        ).isdigit():
            raise BootstrapOwnershipError(
                "project-number-invalid",
                "Google Cloud did not return the project's immutable numeric id.",
            )
        applicable_scopes = {f"projects/{project_number}"}
        parent = self._parent_resource(project.get("parent"))
        seen_folders: set[str] = set()
        folder_count = 0
        while parent is not None:
            if parent.startswith("organizations/"):
                return parent, applicable_scopes
            # Check the parent returned by the tenth folder before enforcing
            # Resource Manager's ten-level folder nesting limit. Cycles and an
            # eleventh folder remain fail-closed.
            if folder_count >= 10 or parent in seen_folders:
                break
            seen_folders.add(parent)
            folder_count += 1
            applicable_scopes.add(parent)
            folder_id = parent.removeprefix("folders/")
            folder = self._json(
                "resource-manager",
                "folders",
                "describe",
                folder_id,
                "--format=json",
            )
            parent = self._parent_resource(folder.get("parent"))
        raise BootstrapOwnershipError(
            "project-not-in-organization",
            "The Google Cloud project is not attached to an organization.",
        )

    def _validate_access_policy(self, project_id: str) -> None:
        if self._access_policy_id is None:
            return
        organization, applicable_scopes = self._project_policy_context(project_id)
        policy = self._json(
            "access-context-manager",
            "policies",
            "describe",
            self._access_policy_id,
            "--format=json",
        )
        expected_name = f"accessPolicies/{self._access_policy_id}"
        if policy.get("name") != expected_name:
            raise BootstrapOwnershipError(
                "access-policy-identity-mismatch",
                "Google returned an unexpected Access Context Manager policy identity.",
            )
        if policy.get("parent") != organization:
            raise BootstrapOwnershipError(
                "access-policy-organization-mismatch",
                "The Access Context Manager policy belongs to another organization.",
            )
        raw_scopes = policy.get("scopes", [])
        if (
            not isinstance(raw_scopes, list)
            or any(
                not isinstance(scope, str)
                or re.fullmatch(r"(?:projects|folders)/\d+", scope) is None
                for scope in raw_scopes
            )
        ):
            raise BootstrapOwnershipError(
                "access-policy-response-invalid",
                "Google returned malformed Access Context Manager policy scopes.",
            )
        if raw_scopes and not any(scope in applicable_scopes for scope in raw_scopes):
            raise BootstrapOwnershipError(
                "access-policy-scope-mismatch",
                "The Access Context Manager policy is not scoped to this project "
                "or one of its ancestor folders.",
            )

    def _load_pin(
        self,
        project_id: str,
        service_account_email: str,
        role_name: str,
    ) -> dict[str, object] | None:
        if not self._pin_path.exists():
            return None
        try:
            document = json.loads(self._pin_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("The bootstrap ownership pin file is unreadable") from error
        if not isinstance(document, dict) or document.get("version") != 1:
            raise RuntimeError("The bootstrap ownership pin file is malformed")
        projects = document.get("projects")
        if not isinstance(projects, dict):
            raise RuntimeError("The bootstrap ownership pin file is malformed")
        raw = projects.get(project_id)
        if raw is None:
            return None
        if not isinstance(raw, dict):
            raise RuntimeError("The persisted deployer ownership record is malformed")
        unique_id = raw.get("service_account_unique_id")
        role_etag = raw.get("custom_role_etag")
        pending_mutation = raw.get("pending_mutation")
        bindings = self._normalise_bindings(raw.get("service_account_iam_bindings"))
        inferred_operator = self._sole_token_creator_operator(bindings)
        operator_email = raw.get("operator_email", inferred_operator)
        ownership_token = raw.get("service_account_ownership_token")
        if (
            raw.get("project_id") != project_id
            or raw.get("service_account_email") != service_account_email
            or not isinstance(unique_id, str)
            or not unique_id.isdigit()
            or raw.get("custom_role") != role_name
            or not (role_etag is None or (isinstance(role_etag, str) and role_etag))
            or not (
                pending_mutation is None or isinstance(pending_mutation, dict)
            )
            or not isinstance(operator_email, str)
            or self._account_pattern.fullmatch(operator_email) is None
            or not (
                ownership_token is None
                or (
                    isinstance(ownership_token, str)
                    and re.fullmatch(r"[0-9a-f-]{20,64}", ownership_token)
                )
            )
        ):
            raise RuntimeError(
                "The persisted deployer ownership record does not match this project"
            )
        return {
            "project_id": project_id,
            "service_account_email": service_account_email,
            "service_account_unique_id": unique_id,
            "operator_email": operator_email.lower(),
            "service_account_ownership_token": ownership_token,
            "service_account_iam_bindings": bindings,
            "custom_role": role_name,
            "custom_role_etag": role_etag,
            "pending_mutation": pending_mutation,
        }

    def _save_pin(self, pin: dict[str, object]) -> None:
        project_id = pin["project_id"]
        if not isinstance(project_id, str):
            raise RuntimeError("The deployer ownership record is malformed")
        if self._pin_path.exists():
            try:
                document = json.loads(self._pin_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise RuntimeError("The bootstrap ownership pin file is unreadable") from error
            if not isinstance(document, dict) or document.get("version") != 1:
                raise RuntimeError("The bootstrap ownership pin file is malformed")
            projects = document.get("projects")
            if not isinstance(projects, dict):
                raise RuntimeError("The bootstrap ownership pin file is malformed")
        else:
            document = {"version": 1, "projects": {}}
            projects = document["projects"]
        projects[project_id] = pin
        self._write_pin_document(document)

    def _write_pin_document(self, document: dict[str, object]) -> None:
        self._pin_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=self._pin_path.parent,
            prefix=f".{self._pin_path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(document, handle, ensure_ascii=False, sort_keys=True, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, self._pin_path)
        finally:
            temporary_path.unlink(missing_ok=True)

    def _load_service_account_create_intent(
        self,
        project_id: str,
        service_account_email: str,
        operator_email: str,
    ) -> dict[str, str] | None:
        if not self._pin_path.exists():
            return None
        try:
            document = json.loads(self._pin_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("The bootstrap ownership pin file is unreadable") from error
        intents = document.get("pending_service_account_creates", {})
        if not isinstance(intents, dict):
            raise RuntimeError("The bootstrap ownership pin file is malformed")
        raw = intents.get(project_id)
        if raw is None:
            return None
        if (
            not isinstance(raw, dict)
            or raw.get("phase") != "sending"
            or raw.get("service_account_email") != service_account_email
            or raw.get("operator_email") != operator_email
            or not isinstance(raw.get("ownership_token"), str)
            or not re.fullmatch(r"[0-9a-f-]{20,64}", str(raw["ownership_token"]))
        ):
            raise RuntimeError("The service-account create checkpoint is malformed")
        return {key: str(value) for key, value in raw.items()}

    def _save_service_account_create_intent(
        self,
        project_id: str,
        intent: dict[str, str],
    ) -> None:
        if self._pin_path.exists():
            try:
                document = json.loads(self._pin_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise RuntimeError("The bootstrap ownership pin file is unreadable") from error
        else:
            document = {"version": 1, "projects": {}}
        if not isinstance(document, dict) or document.get("version") != 1:
            raise RuntimeError("The bootstrap ownership pin file is malformed")
        intents = document.setdefault("pending_service_account_creates", {})
        if not isinstance(intents, dict):
            raise RuntimeError("The bootstrap ownership pin file is malformed")
        intents[project_id] = intent
        self._write_pin_document(document)

    def _clear_service_account_create_intent(self, project_id: str) -> None:
        if not self._pin_path.exists():
            return
        try:
            document = json.loads(self._pin_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("The bootstrap ownership pin file is unreadable") from error
        intents = document.get("pending_service_account_creates")
        if isinstance(intents, dict):
            intents.pop(project_id, None)
            if not intents:
                document.pop("pending_service_account_creates", None)
            self._write_pin_document(document)

    @staticmethod
    def _pending_bootstrap_mutation(
        pin: dict[str, object],
    ) -> dict[str, object] | None:
        pending = pin.get("pending_mutation")
        if pending is None:
            return None
        if (
            not isinstance(pending, dict)
            or pending.get("phase") != "sending"
            or pending.get("kind")
            not in {"custom_role", "service_account_iam"}
        ):
            raise RuntimeError("The bootstrap mutation checkpoint is malformed")
        return pending

    def _checkpoint_bootstrap_mutation(
        self,
        pin: dict[str, object],
        mutation: dict[str, object],
    ) -> None:
        if self._pending_bootstrap_mutation(pin) is not None:
            raise RuntimeError("A bootstrap mutation is already awaiting reconciliation")
        pin["pending_mutation"] = {
            **mutation,
            "phase": "sending",
        }
        self._save_pin(pin)

    def _complete_bootstrap_mutation(self, pin: dict[str, object]) -> None:
        pin.pop("pending_mutation", None)
        self._save_pin(pin)

    def bootstrap(
        self,
        project_id: str,
        *,
        allow_ownership_migration: bool = False,
    ) -> DeployerBootstrapResult:
        operator_email = self._run(
            "auth",
            "list",
            "--filter=status:ACTIVE",
            "--format=value(account)",
        ).strip()
        if not self._account_pattern.fullmatch(operator_email):
            raise RuntimeError("No active gcloud user account was found")

        # A configured Access Policy is a privilege target. Validate its
        # immutable identity, organization and 2026 scoped-policy applicability
        # before creating or granting anything.
        self._validate_access_policy(project_id)

        service_account_email = (
            f"{self._account_id}@{project_id}.iam.gserviceaccount.com"
        )
        role_name = f"projects/{project_id}/roles/{self._role_id}"
        pin = self._load_pin(project_id, service_account_email, role_name)
        if pin is not None and pin.get("operator_email") != operator_email.lower():
            raise RuntimeError(
                "The active gcloud operator differs from the sole operator pinned "
                "to this deployer. Use an explicit reviewed operator rotation."
            )
        create_intent = self._load_service_account_create_intent(
            project_id,
            service_account_email,
            operator_email.lower(),
        )
        migration_unique_id: str | None = None
        account = self._optional_json(
            "iam",
            "service-accounts",
            "describe",
            service_account_email,
            f"--project={project_id}",
            "--format=json",
        )
        if account is None:
            if pin is not None:
                raise RuntimeError(
                    "The pinned deployer service account no longer exists. "
                    "Review the deletion and migrate explicitly before bootstrap."
                )
            if create_intent is None:
                create_intent = {
                    "phase": "sending",
                    "service_account_email": service_account_email,
                    "operator_email": operator_email.lower(),
                    "ownership_token": str(uuid4()),
                }
                self._save_service_account_create_intent(project_id, create_intent)
            description = (
                "Secure Gateway Studio ownership:"
                f"{create_intent['ownership_token']}"
            )
            try:
                account = self._json(
                    "iam",
                    "service-accounts",
                    "create",
                    self._account_id,
                    f"--project={project_id}",
                    "--display-name=Secure Gateway Studio deployer",
                    f"--description={description}",
                    "--quiet",
                    "--format=json",
                )
            except RuntimeError:
                # gcloud may have lost the successful response. Only the exact
                # random marker makes a fresh same-name account adoptable.
                account = self._optional_json(
                    "iam",
                    "service-accounts",
                    "describe",
                    service_account_email,
                    f"--project={project_id}",
                    "--format=json",
                )
                if account is None:
                    raise
            unique_id = self._service_account_unique_id(
                account,
                service_account_email,
                expected_ownership_token=create_intent["ownership_token"],
            )
            pin = {
                "project_id": project_id,
                "service_account_email": service_account_email,
                "service_account_unique_id": unique_id,
                "operator_email": operator_email.lower(),
                "service_account_ownership_token": create_intent["ownership_token"],
                "service_account_iam_bindings": [],
                "custom_role": role_name,
                "custom_role_etag": None,
            }
            self._save_pin(pin)
            self._clear_service_account_create_intent(project_id)
        else:
            if create_intent is not None:
                unique_id = self._service_account_unique_id(
                    account,
                    service_account_email,
                    expected_ownership_token=create_intent["ownership_token"],
                )
                pin = {
                    "project_id": project_id,
                    "service_account_email": service_account_email,
                    "service_account_unique_id": unique_id,
                    "operator_email": operator_email.lower(),
                    "service_account_ownership_token": create_intent["ownership_token"],
                    "service_account_iam_bindings": [],
                    "custom_role": role_name,
                    "custom_role_etag": None,
                }
                self._save_pin(pin)
                self._clear_service_account_create_intent(project_id)
            elif pin is None:
                if not allow_ownership_migration:
                    raise BootstrapOwnershipError(
                        "service-account-identity-unpinned",
                        "The reserved deployer service-account name already exists "
                        "but has no immutable SGS ownership record. It was not "
                        "granted any role; use the explicit 0.2.0 migration review.",
                    )
                migration_unique_id = self._service_account_unique_id(
                    account,
                    service_account_email,
                )
                unique_id = migration_unique_id
            else:
                unique_id = self._service_account_unique_id(
                    account,
                    service_account_email,
                    expected_unique_id=str(pin["service_account_unique_id"]),
                    expected_ownership_token=(
                        str(pin["service_account_ownership_token"])
                        if pin.get("service_account_ownership_token") is not None
                        else None
                    ),
                )

        pending = self._pending_bootstrap_mutation(pin) if pin is not None else None
        if pending is not None and pending.get("kind") == "service_account_iam":
            before_bindings = self._normalise_bindings(
                pending.get("before_bindings")
            )
            expected_bindings = self._normalise_bindings(
                pending.get("expected_bindings")
            )
            if (
                pending.get("operator_email") != operator_email
                or not expected_bindings
            ):
                raise RuntimeError("The bootstrap IAM checkpoint is malformed")
            live_policy = self._json(
                "iam",
                "service-accounts",
                "get-iam-policy",
                service_account_email,
                f"--project={project_id}",
                "--format=json",
            )
            live_policy = self._validated_iam_policy(live_policy)
            live_bindings = self._normalise_bindings(live_policy.get("bindings"))
            if live_bindings == expected_bindings:
                pin["service_account_iam_bindings"] = expected_bindings
                self._complete_bootstrap_mutation(pin)
            elif live_bindings == before_bindings:
                self._complete_bootstrap_mutation(pin)
            else:
                raise RuntimeError(
                    "The deployer service-account IAM write has an ambiguous "
                    "response and concurrent policy changes; review it manually."
                )

        role = self._optional_json(
            "iam",
            "roles",
            "describe",
            self._role_id,
            f"--project={project_id}",
            "--format=json",
        )
        role_write_reconciled = False
        desired_role_digest = self._role_definition_digest(
            self._role_manifest_definition()
        )
        if desired_role_digest is None:
            raise RuntimeError("The bundled deployer role manifest is malformed")
        pending = self._pending_bootstrap_mutation(pin) if pin is not None else None
        if pending is not None:
            if (
                pending.get("kind") != "custom_role"
                or pending.get("role_name") != role_name
                or pending.get("expected_definition_digest")
                != desired_role_digest
                or pending.get("action") not in {"create", "update"}
            ):
                raise RuntimeError("The bootstrap role checkpoint is malformed")
            if role is None:
                if (
                    pending.get("action") != "create"
                    or pending.get("before_etag") is not None
                ):
                    raise RuntimeError(
                        "The deployer role write has an ambiguous response; review it manually."
                    )
                self._complete_bootstrap_mutation(pin)
            else:
                live_etag = self._role_etag(role, role_name)
                live_digest = self._role_definition_digest(role)
                if live_digest == desired_role_digest:
                    pin["custom_role_etag"] = live_etag
                    self._complete_bootstrap_mutation(pin)
                    role_write_reconciled = True
                elif (
                    pending.get("action") == "update"
                    and live_etag == pending.get("before_etag")
                ):
                    self._complete_bootstrap_mutation(pin)
                else:
                    raise RuntimeError(
                        "The deployer role write has an ambiguous response and the "
                        "live definition changed; review it manually."
                    )
        if role is None:
            if pin is None:
                raise BootstrapOwnershipError(
                    "legacy-deployer-role-mismatch",
                    "The exact 0.2.0 deployer custom role was not found. Nothing "
                    "was adopted or granted.",
                )
            if pin["custom_role_etag"] is not None:
                raise RuntimeError(
                    "The pinned deployer custom role no longer exists. Review the "
                    "deletion and migrate explicitly before bootstrap."
                )
            self._checkpoint_bootstrap_mutation(
                pin,
                {
                    "kind": "custom_role",
                    "action": "create",
                    "role_name": role_name,
                    "before_etag": None,
                    "expected_definition_digest": desired_role_digest,
                },
            )
            role = self._json(
                "iam",
                "roles",
                "create",
                self._role_id,
                f"--project={project_id}",
                f"--file={self._role_file}",
                "--quiet",
                "--format=json",
            )
            role_etag = self._role_etag(role, role_name)
            pin["custom_role_etag"] = role_etag
            self._complete_bootstrap_mutation(pin)
        else:
            if pin is None:
                if migration_unique_id is None or not self._is_known_migration_role(
                    role,
                    role_name,
                ):
                    raise BootstrapOwnershipError(
                        "legacy-deployer-role-mismatch",
                        "The reserved role does not exactly match a known 0.2.0 or "
                        "current SGS deployer definition. Nothing was adopted or "
                        "granted.",
                    )
                migration_account_policy = self._json(
                    "iam",
                    "service-accounts",
                    "get-iam-policy",
                    service_account_email,
                    f"--project={project_id}",
                    "--format=json",
                )
                migration_account_bindings = (
                    self._assert_legacy_service_account_iam(
                        migration_account_policy,
                        operator_email,
                    )
                )
                migration_project_policy = self._json(
                    "projects",
                    "get-iam-policy",
                    project_id,
                    "--format=json",
                )
                self._assert_legacy_project_iam(
                    migration_project_policy,
                    f"serviceAccount:{service_account_email}",
                    role_name,
                )
                pin = {
                    "project_id": project_id,
                    "service_account_email": service_account_email,
                    "service_account_unique_id": migration_unique_id,
                    "operator_email": operator_email.lower(),
                    "service_account_ownership_token": None,
                    "service_account_iam_bindings": migration_account_bindings,
                    "custom_role": role_name,
                    "custom_role_etag": self._role_etag(role, role_name),
                }
                self._save_pin(pin)
            pinned_etag = pin["custom_role_etag"]
            if pinned_etag is None:
                raise RuntimeError(
                    "The reserved deployer role name already exists but has no SGS "
                    "ownership record. It was not expanded or granted; review it "
                    "and migrate explicitly."
                )
            observed_etag = self._role_etag(role, role_name)
            if observed_etag != pinned_etag:
                raise RuntimeError(
                    "The pinned deployer custom role was changed outside this "
                    "bootstrap. Review it before migrating the ownership record."
                )
            if role_write_reconciled or (
                self._role_definition_digest(role) == desired_role_digest
            ):
                role_etag = observed_etag
            else:
                self._checkpoint_bootstrap_mutation(
                    pin,
                    {
                        "kind": "custom_role",
                        "action": "update",
                        "role_name": role_name,
                        "before_etag": observed_etag,
                        "expected_definition_digest": desired_role_digest,
                    },
                )
                role = self._json(
                    "iam",
                    "roles",
                    "update",
                    self._role_id,
                    f"--project={project_id}",
                    f"--file={self._role_file}",
                    "--quiet",
                    "--format=json",
                )
                role_etag = self._role_etag(role, role_name)
                pin["custom_role_etag"] = role_etag
                self._complete_bootstrap_mutation(pin)
        pin["custom_role_etag"] = role_etag
        self._save_pin(pin)

        member = f"serviceAccount:{service_account_email}"
        observed_account_policy = self._json(
            "iam",
            "service-accounts",
            "get-iam-policy",
            service_account_email,
            f"--project={project_id}",
            "--format=json",
        )
        observed_account_policy = self._validated_iam_policy(observed_account_policy)
        observed_bindings = self._normalise_bindings(
            observed_account_policy.get("bindings")
        )
        if observed_bindings != pin["service_account_iam_bindings"]:
            raise RuntimeError(
                "The deployer service account has unreviewed IAM principals. No "
                "project role was granted; review the policy and migrate explicitly."
            )
        expected_bindings = self._merge_binding(
            observed_bindings,
            role="roles/iam.serviceAccountTokenCreator",
            member=f"user:{operator_email}",
        )
        if expected_bindings != observed_bindings:
            expected_policy = self._policy_with_bindings(
                observed_account_policy,
                [
                    (
                        "roles/iam.serviceAccountTokenCreator",
                        f"user:{operator_email}",
                    )
                ],
            )
            self._checkpoint_bootstrap_mutation(
                pin,
                {
                    "kind": "service_account_iam",
                    "operator_email": operator_email,
                    "before_bindings": observed_bindings,
                    "expected_bindings": expected_bindings,
                },
            )
            self._set_iam_policy(
                expected_policy,
                command_prefix=(
                    "iam",
                    "service-accounts",
                    "set-iam-policy",
                    service_account_email,
                ),
                command_suffix=(f"--project={project_id}",),
            )
            confirmed_account_policy = self._json(
                "iam",
                "service-accounts",
                "get-iam-policy",
                service_account_email,
                f"--project={project_id}",
                "--format=json",
            )
            confirmed_account_policy = self._validated_iam_policy(
                confirmed_account_policy
            )
            confirmed_bindings = self._normalise_bindings(
                confirmed_account_policy.get("bindings")
            )
            if confirmed_bindings != expected_bindings:
                raise RuntimeError(
                    "The deployer service-account IAM policy changed during bootstrap. "
                    "No project role was granted."
                )
            pin["service_account_iam_bindings"] = confirmed_bindings
            self._complete_bootstrap_mutation(pin)

        if self._access_policy_id:
            self._ensure_iam_bindings(
                get_command=(
                    "access-context-manager",
                    "policies",
                    "get-iam-policy",
                    self._access_policy_id,
                ),
                set_command_prefix=(
                    "access-context-manager",
                    "policies",
                    "set-iam-policy",
                    self._access_policy_id,
                ),
                grants=[("roles/accesscontextmanager.policyEditor", member)],
            )

        self._ensure_iam_bindings(
            get_command=(
                "projects",
                "get-iam-policy",
                project_id,
            ),
            set_command_prefix=("projects", "set-iam-policy", project_id),
            grants=[
                (role_name, member),
                ("roles/browser", member),
                ("roles/serviceusage.serviceUsageConsumer", member),
            ],
        )

        return DeployerBootstrapResult(
            project_id=project_id,
            operator_email=operator_email,
            service_account_email=service_account_email,
            service_account_unique_id=unique_id,
            custom_role=role_name,
            access_policy_id=self._access_policy_id,
            adc_command=(
                "gcloud auth application-default login "
                f"--impersonate-service-account={service_account_email}"
            ),
        )

    @staticmethod
    def _service_account_unique_id(
        account: dict[str, object],
        expected_email: str,
        *,
        expected_unique_id: str | None = None,
        expected_ownership_token: str | None = None,
    ) -> str:
        unique_id = account.get("uniqueId")
        if (
            account.get("email") != expected_email
            or account.get("displayName") != "Secure Gateway Studio deployer"
            or not isinstance(unique_id, str)
            or not unique_id.isdigit()
            or (
                expected_unique_id is not None
                and unique_id != expected_unique_id
            )
            or (
                expected_ownership_token is not None
                and account.get("description")
                != f"Secure Gateway Studio ownership:{expected_ownership_token}"
            )
            or account.get("disabled") is True
        ):
            raise RuntimeError(
                "The reserved deployer service-account name is occupied by an "
                "incompatible account"
            )
        return unique_id

    @staticmethod
    def _role_etag(role: dict[str, object], expected_name: str) -> str:
        etag = role.get("etag")
        if (
            role.get("name") != expected_name
            or not isinstance(etag, str)
            or not etag
            or role.get("deleted") is True
        ):
            raise RuntimeError(
                "The reserved deployer role name is occupied by an incompatible role"
            )
        return etag

    @classmethod
    def _merge_binding(
        cls,
        bindings: list[dict[str, object]],
        *,
        role: str,
        member: str,
    ) -> list[dict[str, object]]:
        merged = json.loads(json.dumps(bindings))
        target = next(
            (
                binding
                for binding in merged
                if binding.get("role") == role and "condition" not in binding
            ),
            None,
        )
        if target is None:
            merged.append({"role": role, "members": [member]})
        else:
            members = target.setdefault("members", [])
            if member not in members:
                members.append(member)
        return cls._normalise_bindings(merged)

    @classmethod
    def _policy_with_bindings(
        cls,
        policy: dict[str, object],
        grants: list[tuple[str, str]],
    ) -> dict[str, object]:
        updated = cls._validated_iam_policy(policy)
        bindings = cls._normalise_bindings(updated.get("bindings"))
        for role, member in grants:
            bindings = cls._merge_binding(bindings, role=role, member=member)
        updated["version"] = 3
        updated["bindings"] = bindings
        try:
            return validate_iam_policy_v3(updated, require_etag=True)
        except ValueError as error:
            raise RuntimeError("The outgoing bootstrap IAM policy is malformed") from error

    def _set_iam_policy(
        self,
        policy: dict[str, object],
        *,
        command_prefix: tuple[str, ...],
        command_suffix: tuple[str, ...] = (),
    ) -> dict[str, object]:
        validated = self._validated_iam_policy(policy)
        descriptor, temporary_name = tempfile.mkstemp(suffix=".json")
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(validated, handle, ensure_ascii=False, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            response = self._json(
                *command_prefix,
                str(temporary_path),
                *command_suffix,
                "--quiet",
                "--format=json",
            )
            return self._validated_iam_policy(response)
        finally:
            temporary_path.unlink(missing_ok=True)

    def _ensure_iam_bindings(
        self,
        *,
        get_command: tuple[str, ...],
        set_command_prefix: tuple[str, ...],
        set_command_suffix: tuple[str, ...] = (),
        grants: list[tuple[str, str]],
    ) -> dict[str, object]:
        current = self._validated_iam_policy(self._json(*get_command, "--format=json"))
        current_bindings = self._normalise_bindings(current.get("bindings"))
        updated = self._policy_with_bindings(current, grants)
        if self._normalise_bindings(updated.get("bindings")) == current_bindings:
            return current
        return self._set_iam_policy(
            updated,
            command_prefix=set_command_prefix,
            command_suffix=set_command_suffix,
        )

    def _optional_json(self, *arguments: str) -> dict[str, object] | None:
        result = subprocess.run(
            [self._gcloud, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return self._decode_json(result.stdout)
        detail = (result.stderr or result.stdout).strip()[-500:]
        if re.search(r"NOT_FOUND|not found|does not exist", detail, re.IGNORECASE):
            return None
        raise RuntimeError(self._command_error_detail(detail))

    def _json(self, *arguments: str) -> dict[str, object]:
        return self._decode_json(self._run(*arguments))

    @staticmethod
    def _decode_json(value: str) -> dict[str, object]:
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as error:
            raise RuntimeError("gcloud returned malformed JSON") from error
        if not isinstance(decoded, dict):
            raise RuntimeError("gcloud returned an unexpected JSON value")
        return decoded

    @staticmethod
    def _command_error_detail(detail: str) -> str:
        if (
            "Reauthentication failed" in detail
            or "cannot prompt during non-interactive execution" in detail
        ):
            return (
                "The active gcloud user credentials require reauthentication. "
                "Run `gcloud auth login`, complete browser sign-in, then retry "
                "automatic deployer setup."
            )
        return detail or "gcloud command failed"

    def _succeeds(self, *arguments: str) -> bool:
        result = subprocess.run(
            [self._gcloud, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0

    def _run(self, *arguments: str) -> str:
        result = subprocess.run(
            [self._gcloud, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-500:]
            raise RuntimeError(self._command_error_detail(detail))
        return result.stdout
