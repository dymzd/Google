import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from sgstudio.domain.planner import REQUIRED_PERMISSIONS
from sgstudio.providers.gcloud_bootstrap import GcloudDeployerBootstrapper

BOOTSTRAP_IAM_TARGETS = [
    (
        ("iam", "service-accounts", "get-iam-policy", "deployer@example.com"),
        ("iam", "service-accounts", "set-iam-policy", "deployer@example.com"),
    ),
    (
        ("access-context-manager", "policies", "get-iam-policy", "123456789"),
        ("access-context-manager", "policies", "set-iam-policy", "123456789"),
    ),
    (
        ("projects", "get-iam-policy", "project-1"),
        ("projects", "set-iam-policy", "project-1"),
    ),
]


@pytest.mark.parametrize(
    ("get_command", "set_command"),
    BOOTSTRAP_IAM_TARGETS,
    ids=["service-account", "access-policy", "project"],
)
@pytest.mark.parametrize(
    "malformed_binding",
    [
        {
            "role": "roles/viewer",
            "members": ["user:duplicate@example.com", "user:duplicate@example.com"],
        },
        {
            "role": "roles/viewer",
            "members": ["user:owner@example.com"],
            "condition": {
                "title": "Unrelated",
                "expression": "true",
                "unknown": "must-not-round-trip",
            },
        },
        {
            "role": "roles/viewer",
            "members": ["user:owner@example.com"],
            "unknown": True,
        },
    ],
    ids=["duplicate-member", "malformed-condition", "unknown-binding-field"],
)
def test_bootstrap_all_iam_targets_reject_malformed_policy_before_set(
    monkeypatch: pytest.MonkeyPatch,
    get_command: tuple[str, ...],
    set_command: tuple[str, ...],
    malformed_binding: dict[str, object],
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(gcloud_path="/usr/bin/false")
    calls: list[tuple[str, ...]] = []

    def json_result(*args: str):
        calls.append(args)
        if args[: len(get_command)] == get_command:
            return {
                "version": 3,
                "etag": "fresh",
                "bindings": [malformed_binding],
            }
        raise AssertionError(args)

    monkeypatch.setattr(bootstrapper, "_json", json_result)

    with pytest.raises(RuntimeError, match="malformed IAM policy"):
        bootstrapper._ensure_iam_bindings(
            get_command=get_command,
            set_command_prefix=set_command,
            grants=[("roles/browser", "serviceAccount:deployer@example.com")],
        )

    assert not any(call[: len(set_command)] == set_command for call in calls)


def test_bootstrap_iam_rmw_preserves_legal_condition_location_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(gcloud_path="/usr/bin/false")
    current = {
        "version": 3,
        "etag": "fresh",
        "bindings": [
            {
                "role": "roles/viewer",
                "members": ["user:owner@example.com"],
                "condition": {
                    "title": "Source guard",
                    "expression": "resource.name.startsWith('projects/example')",
                    "description": "Keep this exact condition metadata.",
                    "location": "bootstrap-policy.json:12",
                },
            }
        ],
    }
    sent: list[dict[str, object]] = []

    def json_result(*args: str):
        if args[:2] == ("projects", "get-iam-policy"):
            return current
        if args[:2] == ("projects", "set-iam-policy"):
            policy_path = Path(args[3])
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            sent.append(policy)
            return policy
        raise AssertionError(args)

    monkeypatch.setattr(bootstrapper, "_json", json_result)

    bootstrapper._ensure_iam_bindings(
        get_command=("projects", "get-iam-policy", "project-1"),
        set_command_prefix=("projects", "set-iam-policy", "project-1"),
        grants=[("roles/browser", "serviceAccount:deployer@example.com")],
    )

    assert len(sent) == 1
    assert sent[0]["bindings"][0]["condition"] == current["bindings"][0]["condition"]


def test_bootstrap_manifest_covers_all_supported_execution_paths() -> None:
    bootstrapper = GcloudDeployerBootstrapper(gcloud_path="/usr/bin/false")
    manifest = bootstrapper._role_file.read_text(encoding="utf-8")
    permissions = {
        line.removeprefix("  - ").strip()
        for line in manifest.splitlines()
        if line.startswith("  - ")
    }
    permissions_supplied_by_base_roles = {
        "accesscontextmanager.accessLevels.get",
        "resourcemanager.projects.get",
        "resourcemanager.projects.getIamPolicy",
        "serviceusage.operations.get",
        "serviceusage.services.get",
        "serviceusage.services.list",
        "serviceusage.services.use",
    }

    assert permissions == REQUIRED_PERMISSIONS - permissions_supplied_by_base_roles
    assert manifest.startswith("title: Secure Gateway Studio Deployer\n")


def test_noninteractive_reauthentication_failure_has_actionable_remediation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(gcloud_path="/usr/bin/false")

    def failed_run(*args, **kwargs):
        del args, kwargs
        return CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr=(
                "Reauthentication failed. cannot prompt during non-interactive "
                "execution."
            ),
        )

    monkeypatch.setattr("sgstudio.providers.gcloud_bootstrap.subprocess.run", failed_run)

    with pytest.raises(RuntimeError, match="gcloud auth login"):
        bootstrapper._run("iam", "roles", "describe", "example")


def test_gcloud_policy_context_accepts_the_ten_folder_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(gcloud_path="/usr/bin/false")
    folder_calls: list[int] = []

    def json_result(*args: str):
        if args[:2] == ("projects", "describe"):
            return {
                "projectNumber": "111",
                "parent": {"type": "folder", "id": "10"},
            }
        if args[:3] == ("resource-manager", "folders", "describe"):
            folder_id = int(args[3])
            folder_calls.append(folder_id)
            return {
                "parent": (
                    {"type": "organization", "id": "123"}
                    if folder_id == 1
                    else {"type": "folder", "id": str(folder_id - 1)}
                )
            }
        raise AssertionError(args)

    monkeypatch.setattr(bootstrapper, "_json", json_result)

    organization, scopes = bootstrapper._project_policy_context("project-1")

    assert organization == "organizations/123"
    assert folder_calls == list(range(10, 0, -1))
    assert scopes == {"projects/111"} | {f"folders/{item}" for item in range(1, 11)}


@pytest.mark.parametrize(
    ("depth", "cycle"),
    [(11, False), (3, True)],
    ids=["eleven-folders", "cycle"],
)
def test_gcloud_policy_context_rejects_invalid_hierarchies(
    monkeypatch: pytest.MonkeyPatch,
    depth: int,
    cycle: bool,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(gcloud_path="/usr/bin/false")
    folder_calls: list[int] = []

    def json_result(*args: str):
        if args[:2] == ("projects", "describe"):
            return {
                "projectNumber": "111",
                "parent": {"type": "folder", "id": str(depth)},
            }
        if args[:3] == ("resource-manager", "folders", "describe"):
            folder_id = int(args[3])
            folder_calls.append(folder_id)
            return {
                "parent": (
                    {"type": "folder", "id": str(depth)}
                    if cycle and folder_id == depth - 1
                    else {"type": "organization", "id": "123"}
                    if folder_id == 1
                    else {"type": "folder", "id": str(folder_id - 1)}
                )
            }
        raise AssertionError(args)

    monkeypatch.setattr(bootstrapper, "_json", json_result)

    with pytest.raises(RuntimeError, match="not attached to an organization"):
        bootstrapper._project_policy_context("project-1")

    assert len(folder_calls) <= 10


def test_bootstrap_grants_access_policy_editor_without_removing_reader(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(
        gcloud_path="/usr/bin/false",
        access_policy_id="123456789",
        pin_path=tmp_path / "bootstrap-pins.json",
    )
    calls: list[tuple[str, ...]] = []
    account_binding_added = False
    written_policies: list[tuple[tuple[str, ...], dict[str, object]]] = []
    account_email = "secure-gateway-deployer@project-1.iam.gserviceaccount.com"
    role_name = "projects/project-1/roles/secureGatewayPocDeployer"

    def optional_json(*args: str):
        calls.append(args)
        return None

    def json_result(*args: str):
        nonlocal account_binding_added
        calls.append(args)
        if args[:2] == ("projects", "describe"):
            return {
                "projectNumber": "111",
                "parent": {"type": "organization", "id": "123"},
            }
        if args[:3] == ("access-context-manager", "policies", "describe"):
            return {
                "name": "accessPolicies/123456789",
                "parent": "organizations/123",
            }
        if args[:3] == ("iam", "service-accounts", "create"):
            description = next(
                arg.removeprefix("--description=")
                for arg in args
                if arg.startswith("--description=")
            )
            return {
                "email": account_email,
                "uniqueId": "123456789012345678901",
                "displayName": "Secure Gateway Studio deployer",
                "description": description,
            }
        if args[:3] == ("iam", "roles", "create"):
            return {"name": role_name, "etag": "role-etag-1"}
        if args[:3] == ("iam", "service-accounts", "get-iam-policy"):
            return {
                "etag": "account-etag",
                "bindings": (
                    [
                        {
                            "role": "roles/iam.serviceAccountTokenCreator",
                            "members": ["user:admin@example.com"],
                        }
                    ]
                    if account_binding_added
                    else []
                ),
            }
        if args[:3] == ("iam", "service-accounts", "set-iam-policy"):
            policy = json.loads(Path(args[4]).read_text(encoding="utf-8"))
            written_policies.append((args[:3], policy))
            account_binding_added = True
            return policy
        if args[:3] == ("access-context-manager", "policies", "get-iam-policy"):
            return {
                "version": 1,
                "etag": "access-etag",
                "bindings": [
                    {
                        "role": "roles/accesscontextmanager.policyReader",
                        "members": ["group:readers@example.com"],
                    }
                ],
            }
        if args[:3] == ("access-context-manager", "policies", "set-iam-policy"):
            policy = json.loads(Path(args[4]).read_text(encoding="utf-8"))
            written_policies.append((args[:3], policy))
            return policy
        if args[:2] == ("projects", "get-iam-policy"):
            return {"version": 1, "etag": "project-etag", "bindings": []}
        if args[:2] == ("projects", "set-iam-policy"):
            policy = json.loads(Path(args[3]).read_text(encoding="utf-8"))
            written_policies.append((args[:2], policy))
            return policy
        raise AssertionError(args)

    def run(*args: str) -> str:
        nonlocal account_binding_added
        calls.append(args)
        if args[:2] == ("auth", "list"):
            return "admin@example.com\n"
        return ""

    monkeypatch.setattr(bootstrapper, "_optional_json", optional_json)
    monkeypatch.setattr(bootstrapper, "_json", json_result)
    monkeypatch.setattr(bootstrapper, "_run", run)

    result = bootstrapper.bootstrap("project-1")

    access_policy = next(
        policy
        for command, policy in written_policies
        if command == ("access-context-manager", "policies", "set-iam-policy")
    )
    assert {binding["role"] for binding in access_policy["bindings"]} == {
        "roles/accesscontextmanager.policyEditor",
        "roles/accesscontextmanager.policyReader",
    }
    assert result.service_account_unique_id == "123456789012345678901"
    assert bootstrapper._pin_path.is_file()


def test_bootstrap_rejects_unpinned_precreated_service_account_before_grants(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(
        gcloud_path="/usr/bin/false",
        pin_path=tmp_path / "bootstrap-pins.json",
    )
    calls: list[tuple[str, ...]] = []
    account_email = "secure-gateway-deployer@project-1.iam.gserviceaccount.com"

    def run(*args: str) -> str:
        calls.append(args)
        return "admin@example.com\n" if args[:2] == ("auth", "list") else ""

    def optional_json(*args: str):
        calls.append(args)
        return {
            "email": account_email,
            "uniqueId": "123456789012345678901",
            "displayName": "Secure Gateway Studio deployer",
        }

    monkeypatch.setattr(bootstrapper, "_run", run)
    monkeypatch.setattr(bootstrapper, "_optional_json", optional_json)

    with pytest.raises(RuntimeError, match="no immutable SGS ownership record"):
        bootstrapper.bootstrap("project-1")

    assert not any(call[:2] == ("projects", "add-iam-policy-binding") for call in calls)


def test_explicit_020_migration_pins_only_after_exact_role_and_iam_audits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(
        gcloud_path="/usr/bin/false",
        pin_path=tmp_path / "bootstrap-pins.json",
    )
    project_id = "project-1"
    account_email = f"secure-gateway-deployer@{project_id}.iam.gserviceaccount.com"
    role_name = f"projects/{project_id}/roles/secureGatewayPocDeployer"
    member = f"serviceAccount:{account_email}"
    calls: list[tuple[str, ...]] = []

    def run(*args: str) -> str:
        calls.append(args)
        return "admin@example.com\n" if args[:2] == ("auth", "list") else ""

    def optional_json(*args: str):
        calls.append(args)
        if args[:3] == ("iam", "service-accounts", "describe"):
            return {
                "email": account_email,
                "uniqueId": "123456789012345678901",
                "displayName": "Secure Gateway Studio deployer",
            }
        if args[:3] == ("iam", "roles", "describe"):
            return {
                **bootstrapper._role_manifest_definition(),
                "name": role_name,
                "etag": "legacy-role-etag",
            }
        raise AssertionError(args)

    def json_result(*args: str):
        calls.append(args)
        if args[:3] == ("iam", "service-accounts", "get-iam-policy"):
            return {
                "etag": "account-etag",
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "members": ["user:admin@example.com"],
                    }
                ],
            }
        if args[:2] == ("projects", "get-iam-policy"):
            return {
                "etag": "project-etag",
                "bindings": [
                    {"role": role_name, "members": [member]},
                    {"role": "roles/browser", "members": [member]},
                    {
                        "role": "roles/serviceusage.serviceUsageConsumer",
                        "members": [member],
                    },
                ],
            }
        if args[:3] == ("iam", "roles", "update"):
            return {
                **bootstrapper._role_manifest_definition(),
                "name": role_name,
                "etag": "current-role-etag",
            }
        raise AssertionError(args)

    monkeypatch.setattr(bootstrapper, "_run", run)
    monkeypatch.setattr(bootstrapper, "_optional_json", optional_json)
    monkeypatch.setattr(bootstrapper, "_json", json_result)

    result = bootstrapper.bootstrap(project_id, allow_ownership_migration=True)

    pin = bootstrapper._load_pin(project_id, account_email, role_name)
    assert result.service_account_unique_id == "123456789012345678901"
    assert pin is not None
    assert pin["service_account_unique_id"] == "123456789012345678901"
    assert pin["custom_role_etag"] == "legacy-role-etag"
    assert not any(call[:3] == ("iam", "roles", "update") for call in calls)
    assert any(call[:2] == ("projects", "get-iam-policy") for call in calls)


def test_explicit_020_migration_rejects_additional_token_creator(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(
        gcloud_path="/usr/bin/false",
        pin_path=tmp_path / "bootstrap-pins.json",
    )
    project_id = "project-1"
    account_email = f"secure-gateway-deployer@{project_id}.iam.gserviceaccount.com"
    role_name = f"projects/{project_id}/roles/secureGatewayPocDeployer"
    calls: list[tuple[str, ...]] = []

    def run(*args: str) -> str:
        calls.append(args)
        return "admin@example.com\n" if args[:2] == ("auth", "list") else ""

    def optional_json(*args: str):
        calls.append(args)
        if args[:3] == ("iam", "service-accounts", "describe"):
            return {
                "email": account_email,
                "uniqueId": "123456789012345678901",
                "displayName": "Secure Gateway Studio deployer",
            }
        return {
            **bootstrapper._role_manifest_definition(),
            "name": role_name,
            "etag": "legacy-role-etag",
        }

    def json_result(*args: str):
        calls.append(args)
        if args[:3] == ("iam", "service-accounts", "get-iam-policy"):
            return {
                "etag": "account-etag",
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "members": [
                            "user:admin@example.com",
                            "user:attacker@example.com",
                        ],
                    }
                ],
            }
        raise AssertionError(args)

    monkeypatch.setattr(bootstrapper, "_run", run)
    monkeypatch.setattr(bootstrapper, "_optional_json", optional_json)
    monkeypatch.setattr(bootstrapper, "_json", json_result)

    with pytest.raises(
        RuntimeError,
        match="exactly one unconditional Token Creator principal",
    ):
        bootstrapper.bootstrap(project_id, allow_ownership_migration=True)

    assert not bootstrapper._pin_path.exists()
    assert not any(call[:2] == ("projects", "get-iam-policy") for call in calls)
    assert not any(call[:2] == ("projects", "add-iam-policy-binding") for call in calls)


def test_bootstrap_rejects_access_policy_scoped_to_another_project_before_create(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(
        gcloud_path="/usr/bin/false",
        access_policy_id="123456789",
        pin_path=tmp_path / "bootstrap-pins.json",
    )
    calls: list[tuple[str, ...]] = []

    def run(*args: str) -> str:
        calls.append(args)
        return "admin@example.com\n" if args[:2] == ("auth", "list") else ""

    def json_result(*args: str):
        calls.append(args)
        if args[:2] == ("projects", "describe"):
            return {
                "projectNumber": "111",
                "parent": {"type": "organization", "id": "123"},
            }
        if args[:3] == ("access-context-manager", "policies", "describe"):
            return {
                "name": "accessPolicies/123456789",
                "parent": "organizations/123",
                "scopes": ["projects/999"],
            }
        raise AssertionError(args)

    monkeypatch.setattr(bootstrapper, "_run", run)
    monkeypatch.setattr(bootstrapper, "_json", json_result)

    with pytest.raises(RuntimeError, match="not scoped to this project"):
        bootstrapper.bootstrap("project-1")

    assert not any(call[:3] == ("iam", "service-accounts", "create") for call in calls)


def test_role_update_response_loss_reconciles_exact_managed_definition_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(
        gcloud_path="/usr/bin/false",
        pin_path=tmp_path / "bootstrap-pins.json",
    )
    project_id = "project-1"
    account_email = f"secure-gateway-deployer@{project_id}.iam.gserviceaccount.com"
    role_name = f"projects/{project_id}/roles/secureGatewayPocDeployer"
    bindings = [
        {
            "role": "roles/iam.serviceAccountTokenCreator",
            "members": ["user:admin@example.com"],
        }
    ]
    bootstrapper._save_pin(
        {
            "project_id": project_id,
            "service_account_email": account_email,
            "service_account_unique_id": "123456789012345678901",
            "service_account_iam_bindings": bindings,
            "custom_role": role_name,
            "custom_role_etag": "role-etag-before",
        }
    )
    role_state = {
        **bootstrapper._role_manifest_definition(),
        "description": "An older reviewed SGS role definition",
        "name": role_name,
        "etag": "role-etag-before",
    }
    update_attempts = 0

    def run(*args: str) -> str:
        return "admin@example.com\n" if args[:2] == ("auth", "list") else ""

    def optional_json(*args: str):
        if args[:3] == ("iam", "service-accounts", "describe"):
            return {
                "email": account_email,
                "uniqueId": "123456789012345678901",
                "displayName": "Secure Gateway Studio deployer",
            }
        if args[:3] == ("iam", "roles", "describe"):
            return dict(role_state)
        raise AssertionError(args)

    def json_result(*args: str):
        nonlocal update_attempts, role_state
        if args[:3] == ("iam", "roles", "update"):
            update_attempts += 1
            role_state = {
                **bootstrapper._role_manifest_definition(),
                "name": role_name,
                "etag": "role-etag-after",
            }
            raise RuntimeError("simulated response loss")
        if args[:3] == ("iam", "service-accounts", "get-iam-policy"):
            return {"version": 1, "etag": "account-etag", "bindings": bindings}
        if args[:2] == ("projects", "get-iam-policy"):
            member = f"serviceAccount:{account_email}"
            return {
                "version": 1,
                "etag": "project-etag",
                "bindings": [
                    {"role": role_name, "members": [member]},
                    {"role": "roles/browser", "members": [member]},
                    {
                        "role": "roles/serviceusage.serviceUsageConsumer",
                        "members": [member],
                    },
                ],
            }
        raise AssertionError(args)

    monkeypatch.setattr(bootstrapper, "_run", run)
    monkeypatch.setattr(bootstrapper, "_optional_json", optional_json)
    monkeypatch.setattr(bootstrapper, "_json", json_result)

    with pytest.raises(RuntimeError, match="response loss"):
        bootstrapper.bootstrap(project_id)
    pending = bootstrapper._load_pin(project_id, account_email, role_name)
    assert pending is not None
    assert pending["pending_mutation"]["kind"] == "custom_role"

    result = bootstrapper.bootstrap(project_id)
    recovered = bootstrapper._load_pin(project_id, account_email, role_name)

    assert result.service_account_unique_id == "123456789012345678901"
    assert update_attempts == 1
    assert recovered is not None
    assert recovered["custom_role_etag"] == "role-etag-after"
    assert recovered["pending_mutation"] is None


def test_service_account_iam_response_loss_reconciles_exact_binding_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(
        gcloud_path="/usr/bin/false",
        pin_path=tmp_path / "bootstrap-pins.json",
    )
    project_id = "project-1"
    account_email = f"secure-gateway-deployer@{project_id}.iam.gserviceaccount.com"
    role_name = f"projects/{project_id}/roles/secureGatewayPocDeployer"
    bootstrapper._save_pin(
        {
            "project_id": project_id,
            "service_account_email": account_email,
            "service_account_unique_id": "123456789012345678901",
            "operator_email": "admin@example.com",
            "service_account_iam_bindings": [],
            "custom_role": role_name,
            "custom_role_etag": "role-etag-1",
        }
    )
    live_bindings: list[dict[str, object]] = []
    binding_attempts = 0

    def run(*args: str) -> str:
        if args[:2] == ("auth", "list"):
            return "admin@example.com\n"
        return ""

    def optional_json(*args: str):
        if args[:3] == ("iam", "service-accounts", "describe"):
            return {
                "email": account_email,
                "uniqueId": "123456789012345678901",
                "displayName": "Secure Gateway Studio deployer",
            }
        if args[:3] == ("iam", "roles", "describe"):
            return {
                **bootstrapper._role_manifest_definition(),
                "name": role_name,
                "etag": "role-etag-1",
            }
        raise AssertionError(args)

    def json_result(*args: str):
        nonlocal binding_attempts, live_bindings
        if args[:3] == ("iam", "service-accounts", "get-iam-policy"):
            return {
                "version": 1,
                "etag": "account-etag",
                "bindings": live_bindings,
            }
        if args[:3] == ("iam", "service-accounts", "set-iam-policy"):
            binding_attempts += 1
            policy = json.loads(Path(args[4]).read_text(encoding="utf-8"))
            live_bindings = policy["bindings"]
            raise RuntimeError("simulated response loss")
        if args[:2] == ("projects", "get-iam-policy"):
            member = f"serviceAccount:{account_email}"
            return {
                "version": 1,
                "etag": "project-etag",
                "bindings": [
                    {"role": role_name, "members": [member]},
                    {"role": "roles/browser", "members": [member]},
                    {
                        "role": "roles/serviceusage.serviceUsageConsumer",
                        "members": [member],
                    },
                ],
            }
        raise AssertionError(args)

    monkeypatch.setattr(bootstrapper, "_run", run)
    monkeypatch.setattr(bootstrapper, "_optional_json", optional_json)
    monkeypatch.setattr(bootstrapper, "_json", json_result)

    with pytest.raises(RuntimeError, match="response loss"):
        bootstrapper.bootstrap(project_id)
    pending = bootstrapper._load_pin(project_id, account_email, role_name)
    assert pending is not None
    assert pending["pending_mutation"]["kind"] == "service_account_iam"

    bootstrapper.bootstrap(project_id)
    recovered = bootstrapper._load_pin(project_id, account_email, role_name)

    assert binding_attempts == 1
    assert recovered is not None
    assert recovered["service_account_iam_bindings"] == live_bindings
    assert recovered["pending_mutation"] is None


def test_bootstrap_rejects_unreviewed_service_account_iam_before_project_grants(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(
        gcloud_path="/usr/bin/false",
        pin_path=tmp_path / "bootstrap-pins.json",
    )
    account_email = "secure-gateway-deployer@project-1.iam.gserviceaccount.com"
    role_name = "projects/project-1/roles/secureGatewayPocDeployer"
    bootstrapper._save_pin(
        {
            "project_id": "project-1",
            "service_account_email": account_email,
            "service_account_unique_id": "123456789012345678901",
            "operator_email": "admin@example.com",
            "service_account_iam_bindings": [],
            "custom_role": role_name,
            "custom_role_etag": "role-etag-1",
        }
    )
    calls: list[tuple[str, ...]] = []

    def run(*args: str) -> str:
        calls.append(args)
        return "admin@example.com\n" if args[:2] == ("auth", "list") else ""

    def optional_json(*args: str):
        calls.append(args)
        if args[:3] == ("iam", "service-accounts", "describe"):
            return {
                "email": account_email,
                "uniqueId": "123456789012345678901",
                "displayName": "Secure Gateway Studio deployer",
            }
        return {"name": role_name, "etag": "role-etag-1"}

    def json_result(*args: str):
        calls.append(args)
        if args[:3] == ("iam", "roles", "update"):
            return {"name": role_name, "etag": "role-etag-2"}
        if args[:3] == ("iam", "service-accounts", "get-iam-policy"):
            return {
                "etag": "account-etag",
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "members": ["user:attacker@example.com"],
                    }
                ],
            }
        raise AssertionError(args)

    monkeypatch.setattr(bootstrapper, "_run", run)
    monkeypatch.setattr(bootstrapper, "_optional_json", optional_json)
    monkeypatch.setattr(bootstrapper, "_json", json_result)

    with pytest.raises(RuntimeError, match="unreviewed IAM principals"):
        bootstrapper.bootstrap("project-1")

    assert not any(call[:2] == ("projects", "add-iam-policy-binding") for call in calls)


def test_service_account_create_response_loss_recovers_exact_marker_without_duplicate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(
        gcloud_path="/usr/bin/false",
        pin_path=tmp_path / "bootstrap-pins.json",
    )
    project_id = "project-1"
    account_email = f"secure-gateway-deployer@{project_id}.iam.gserviceaccount.com"
    role_name = f"projects/{project_id}/roles/secureGatewayPocDeployer"
    live_account: dict[str, object] | None = None
    create_attempts = 0

    def run(*args: str) -> str:
        nonlocal create_attempts, live_account
        if args[:2] == ("auth", "list"):
            return "admin@example.com\n"
        if args[:3] == ("iam", "service-accounts", "create"):
            create_attempts += 1
            description = next(
                arg.removeprefix("--description=")
                for arg in args
                if arg.startswith("--description=")
            )
            live_account = {
                "email": account_email,
                "uniqueId": "123456789012345678901",
                "displayName": "Secure Gateway Studio deployer",
                "description": description,
            }
            raise RuntimeError("simulated create response loss")
        return ""

    def optional_json(*args: str):
        if args[:3] == ("iam", "service-accounts", "describe"):
            return live_account
        if args[:3] == ("iam", "roles", "describe"):
            raise RuntimeError("stop after account reconciliation")
        raise AssertionError(args)

    monkeypatch.setattr(bootstrapper, "_run", run)
    monkeypatch.setattr(bootstrapper, "_optional_json", optional_json)

    for _ in range(2):
        with pytest.raises(RuntimeError, match="stop after account reconciliation"):
            bootstrapper.bootstrap(project_id)

    pin = bootstrapper._load_pin(project_id, account_email, role_name)
    assert pin is not None
    assert pin["service_account_unique_id"] == "123456789012345678901"
    assert pin["operator_email"] == "admin@example.com"
    assert isinstance(pin["service_account_ownership_token"], str)
    assert create_attempts == 1
    document = json.loads((tmp_path / "bootstrap-pins.json").read_text())
    assert "pending_service_account_creates" not in document


def test_existing_pin_cannot_expand_to_a_different_operator(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bootstrapper = GcloudDeployerBootstrapper(
        gcloud_path="/usr/bin/false",
        pin_path=tmp_path / "bootstrap-pins.json",
    )
    project_id = "project-1"
    account_email = f"secure-gateway-deployer@{project_id}.iam.gserviceaccount.com"
    role_name = f"projects/{project_id}/roles/secureGatewayPocDeployer"
    bootstrapper._save_pin(
        {
            "project_id": project_id,
            "service_account_email": account_email,
            "service_account_unique_id": "123456789012345678901",
            "operator_email": "alice@example.com",
            "service_account_ownership_token": None,
            "service_account_iam_bindings": [
                {
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "members": ["user:alice@example.com"],
                }
            ],
            "custom_role": role_name,
            "custom_role_etag": "role-etag",
        }
    )
    calls: list[tuple[str, ...]] = []

    def run(*args: str) -> str:
        calls.append(args)
        return "bob@example.com\n" if args[:2] == ("auth", "list") else ""

    monkeypatch.setattr(bootstrapper, "_run", run)
    with pytest.raises(RuntimeError, match="differs from the sole operator"):
        bootstrapper.bootstrap(project_id)
    assert calls == [("auth", "list", "--filter=status:ACTIVE", "--format=value(account)")]
