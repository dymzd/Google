from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient
from google.auth.exceptions import RefreshError

import sgstudio.api.main as api_main
from sgstudio.api.main import (
    SESSION_NONCE,
    acceptance_verifier,
    app,
    deployer_bootstrapper,
    gateway_observability,
    mutation_authorizer,
    repository,
    resource_executor,
    setup_catalog_provider,
)
from sgstudio.domain.models import (
    AcceptanceStatus,
    AcceptanceTestId,
    AccessPrincipal,
    DeploymentSpec,
    DiscoverySnapshot,
    MutationIdentity,
    PreflightResult,
    PrincipalType,
    ResourceChange,
    RunStatus,
    SetupOption,
)
from sgstudio.domain.planner import (
    REQUIRED_APIS,
    REQUIRED_PERMISSIONS,
    DesiredStatePlanner,
)
from sgstudio.domain.teardown import build_teardown_plan
from sgstudio.providers.acceptance import AcceptanceFinding
from sgstudio.providers.gcloud_bootstrap import (
    BootstrapOwnershipError,
    DeployerBootstrapResult,
)
from sgstudio.providers.local_artifacts import CertificateArtifactStore
from sgstudio.storage import StateRepository

client = TestClient(app)
SESSION_HEADERS = {"X-SGS-Session": SESSION_NONCE}


class FakeDeployerBootstrapper:
    def bootstrap(
        self,
        project_id: str,
        *,
        allow_ownership_migration: bool = False,
    ) -> DeployerBootstrapResult:
        del allow_ownership_migration
        return DeployerBootstrapResult(
            project_id=project_id,
            operator_email="admin@example.com",
            service_account_email=(
                f"secure-gateway-deployer@{project_id}.iam.gserviceaccount.com"
            ),
            service_account_unique_id="123456789012345678901",
            custom_role=f"projects/{project_id}/roles/secureGatewayPocDeployer",
            access_policy_id="123456789",
            adc_command="gcloud auth application-default login --impersonate-service-account=test",
        )


def test_deployer_bootstrap_requires_confirmation_and_is_injectable() -> None:
    app.dependency_overrides[deployer_bootstrapper] = FakeDeployerBootstrapper
    try:
        missing_confirmation = client.post(
            "/api/v1/bootstrap/google-cloud/deployer",
            headers=SESSION_HEADERS,
            json={"project_id": "enterprise-secgw-01"},
        )
        response = client.post(
            "/api/v1/bootstrap/google-cloud/deployer",
            headers=SESSION_HEADERS,
            json={"project_id": "enterprise-secgw-01", "confirmation": "BOOTSTRAP"},
        )
    finally:
        app.dependency_overrides.clear()

    assert missing_confirmation.status_code == 422
    assert response.status_code == 200
    assert response.json()["operator_email"] == "admin@example.com"
    assert response.json()["service_account_email"].startswith(
        "secure-gateway-deployer@"
    )
    assert response.json()["service_account_unique_id"] == "123456789012345678901"


def test_deployer_bootstrap_requires_exact_explicit_ownership_migration_token() -> None:
    observed: list[bool] = []

    class MigrationBootstrapper(FakeDeployerBootstrapper):
        def bootstrap(
            self,
            project_id: str,
            *,
            allow_ownership_migration: bool = False,
        ) -> DeployerBootstrapResult:
            observed.append(allow_ownership_migration)
            return super().bootstrap(
                project_id,
                allow_ownership_migration=allow_ownership_migration,
            )

    app.dependency_overrides[deployer_bootstrapper] = MigrationBootstrapper
    try:
        invalid = client.post(
            "/api/v1/bootstrap/google-cloud/deployer",
            headers=SESSION_HEADERS,
            json={
                "project_id": "enterprise-secgw-01",
                "confirmation": "BOOTSTRAP",
                "ownership_migration_confirmation": "YES",
            },
        )
        migrated = client.post(
            "/api/v1/bootstrap/google-cloud/deployer",
            headers=SESSION_HEADERS,
            json={
                "project_id": "enterprise-secgw-01",
                "confirmation": "BOOTSTRAP",
                "ownership_migration_confirmation": "MIGRATE_EXISTING_DEPLOYER",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert invalid.status_code == 422
    assert migrated.status_code == 200
    assert observed == [True]


def test_deployer_bootstrap_returns_stable_unpinned_identity_problem_code() -> None:
    class UnpinnedBootstrapper:
        def bootstrap(
            self,
            project_id: str,
            *,
            allow_ownership_migration: bool = False,
        ) -> DeployerBootstrapResult:
            del project_id, allow_ownership_migration
            raise BootstrapOwnershipError(
                "service-account-identity-unpinned",
                "Explicit migration review is required.",
            )

    app.dependency_overrides[deployer_bootstrapper] = UnpinnedBootstrapper
    try:
        response = client.post(
            "/api/v1/bootstrap/google-cloud/deployer",
            headers=SESSION_HEADERS,
            json={
                "project_id": "enterprise-secgw-01",
                "confirmation": "BOOTSTRAP",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "service-account-identity-unpinned"


def test_health_is_loopback_service() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["bind"] == "loopback"
    assert response.json()["session_nonce"] == SESSION_NONCE
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_local_poc_root_download_requires_session_and_returns_only_public_pem(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SGSTUDIO_STATE_PATH", str(tmp_path / "state.db"))
    store = CertificateArtifactStore(tmp_path / "artifacts")
    store.write_root_certificate(
        "secure-gateway-http-offload",
        b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
    )

    unauthenticated = client.get("/api/v1/certificates/local-poc/secure-gateway-http-offload")
    response = client.get(
        "/api/v1/certificates/local-poc/secure-gateway-http-offload",
        headers=SESSION_HEADERS,
    )

    assert unauthenticated.status_code == 403
    assert response.status_code == 200
    assert response.content.startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY" not in response.content
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"].endswith(
        'filename="secure-gateway-http-offload-poc-root.pem"'
    )


def test_mutation_rejects_non_loopback_origin() -> None:
    response = client.post(
        "/api/v1/plans",
        headers={"Origin": "https://evil.example", **SESSION_HEADERS},
        json={},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "origin-rejected"


def test_mutation_requires_local_session_nonce() -> None:
    response = client.post("/api/v1/plans", json={})
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "session-invalid"


def test_repository_dependency_is_singleton_under_concurrent_first_access(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SGSTUDIO_STATE_PATH", str(tmp_path / "concurrent.db"))
    monkeypatch.setattr(api_main, "_repository_instance", None)

    with ThreadPoolExecutor(max_workers=8) as pool:
        instances = list(pool.map(lambda _: api_main.repository(), range(16)))

    assert len({id(instance) for instance in instances}) == 1


def test_credential_bound_dependencies_reload_adc_after_bootstrap_transition(
    monkeypatch,
) -> None:
    calls: list[tuple[str, bool]] = []

    def factory(name: str):
        def create(*, require_impersonation: bool = False):
            calls.append((name, require_impersonation))
            return object()

        return create

    monkeypatch.setattr(
        api_main, "create_google_connection_validator", factory("connection")
    )
    monkeypatch.setattr(
        api_main, "create_google_discovery_provider", factory("discovery")
    )
    monkeypatch.setattr(
        api_main, "create_google_setup_catalog_provider", lambda: object()
    )
    monkeypatch.setattr(
        api_main, "create_google_gateway_observability", factory("observability")
    )
    monkeypatch.setattr(
        api_main, "create_google_acceptance_verifier", factory("acceptance")
    )

    first_user_validation = api_main.connection_validator()
    second_user_validation = api_main.connection_validator()
    first_trusted_validation = api_main.trusted_connection_validator()
    second_trusted_validation = api_main.trusted_connection_validator()
    first_trusted_preflight = api_main.discovery_provider()
    second_trusted_preflight = api_main.discovery_provider()
    first_catalog = api_main.setup_catalog_provider()
    second_catalog = api_main.setup_catalog_provider()
    first_logs = api_main.gateway_observability()
    second_logs = api_main.gateway_observability()
    first_acceptance = api_main.acceptance_verifier()
    second_acceptance = api_main.acceptance_verifier()

    assert first_user_validation is not second_user_validation
    assert first_trusted_validation is not second_trusted_validation
    assert first_trusted_preflight is not second_trusted_preflight
    assert first_catalog is not second_catalog
    assert first_logs is not second_logs
    assert first_acceptance is not second_acceptance
    assert calls == [
        ("connection", False),
        ("connection", False),
        ("connection", True),
        ("connection", True),
        ("discovery", True),
        ("discovery", True),
        ("observability", True),
        ("observability", True),
        ("acceptance", True),
        ("acceptance", True),
    ]


def _specification() -> DeploymentSpec:
    return DeploymentSpec(
        project_id="enterprise-secgw-01",
        ca_pool="projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise",
        ca_name=(
            "projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise/"
            "certificateAuthorities/issuing"
        ),
        target_ou_id="03-test-ou",
        managed_chrome_access_level="accessPolicies/123456789/accessLevels/managed_chrome",
        source_image="projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
        chrome_enterprise_premium_license_confirmed=True,
        workspace_services_confirmed=True,
        endpoint_verification_confirmed=True,
        test_ou_confirmed=True,
        principals=[AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")],
    )


def _mutation_identity(
    operator_email: str = "operator@example.com",
    *,
    operator_subject: str | None = None,
    service_account_unique_id: str = "123456789012345678901",
) -> MutationIdentity:
    return MutationIdentity(
        operator_email=operator_email,
        operator_subject=operator_subject or f"subject:{operator_email}",
        project_id="enterprise-secgw-01",
        service_account_email=(
            "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com"
        ),
        service_account_unique_id=service_account_unique_id,
    )


def _ready_snapshot(
    *, cloud_identity: str = "operator@example.com"
) -> DiscoverySnapshot:
    """Return a gate-complete discovery fixture for approval/API tests."""

    specification = _specification()
    return DiscoverySnapshot(
        existing_resource_keys={
            "accesscontextmanager:access_level:"
            "accessPolicies/123456789/accessLevels/managed_chrome",
            f"compute:source_image:{specification.source_image}",
        },
        enabled_apis=REQUIRED_APIS,
        granted_permissions=REQUIRED_PERMISSIONS,
        cloud_identity=cloud_identity,
        workspace_identity="admin@example.com",
        billing_enabled=True,
        source_image_binding={
            "name": specification.source_image,
            "id": "1234567890123456789",
            "self_link": (
                "https://www.googleapis.com/compute/v1/"
                f"{specification.source_image}"
            ),
        },
    )


class FakeMutationAuthorizer:
    def __init__(self, identity: MutationIdentity | None = None) -> None:
        self.identity = identity or _mutation_identity()

    def resolve(self, project_id: str) -> MutationIdentity:
        assert project_id == self.identity.project_id
        return self.identity


class SuccessfulExecutor:
    def authorize_mutation(self, project_id: str) -> MutationIdentity:
        assert project_id == "enterprise-secgw-01"
        return _mutation_identity()

    def apply(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        del change, spec

    def rollback(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        del change, spec


class CountingObservability:
    def __init__(self) -> None:
        self.calls = 0

    def list_logs(
        self,
        specification: DeploymentSpec,
        *,
        run_id: str,
        category: object,
        hours: int,
        limit: int,
    ) -> dict[str, object]:
        del specification, hours, limit
        self.calls += 1
        return {
            "run_id": run_id,
            "category": str(getattr(category, "value", category)),
            "entries": [],
            "logging_enabled": True,
            "data_access_notice": False,
            "setup_notice": None,
        }


class FakeSetupCatalogProvider:
    def list_organizational_units(self, customer_id: str) -> list[SetupOption]:
        assert customer_id == "C012abcde"
        return [SetupOption(value="03-test-ou", label="/PoC/Secure Gateway")]

    def list_groups(self, customer_id: str) -> list[SetupOption]:
        assert customer_id == "C012abcde"
        return [
            SetupOption(
                value="secure-access@example.com",
                label="Secure Access",
                description="secure-access@example.com",
            )
        ]

    def list_access_levels(self, project_id: str) -> list[SetupOption]:
        assert project_id == "enterprise-secgw-01"
        return [
            SetupOption(
                value="accessPolicies/123/accessLevels/managed_chrome",
                label="Managed Chrome",
            )
        ]


class ExpiredSetupCatalogProvider:
    def list_organizational_units(self, customer_id: str) -> list[SetupOption]:
        del customer_id
        raise RefreshError("Reauthentication is needed")

    def list_groups(self, customer_id: str) -> list[SetupOption]:
        del customer_id
        raise RefreshError("Reauthentication is needed")

    def list_access_levels(self, project_id: str) -> list[SetupOption]:
        del project_id
        raise RefreshError("Reauthentication is needed")


def test_setup_option_endpoints_are_session_bound_and_return_safe_options() -> None:
    app.dependency_overrides[setup_catalog_provider] = FakeSetupCatalogProvider
    try:
        unauthorized = client.post(
            "/api/v1/setup-options/organizational-units",
            json={"customer_id": "C012abcde"},
        )
        organizational_units = client.post(
            "/api/v1/setup-options/organizational-units",
            headers=SESSION_HEADERS,
            json={"customer_id": "C012abcde"},
        )
        groups = client.post(
            "/api/v1/setup-options/groups",
            headers=SESSION_HEADERS,
            json={"customer_id": "C012abcde"},
        )
        access_levels = client.post(
            "/api/v1/setup-options/access-levels",
            headers=SESSION_HEADERS,
            json={"project_id": "enterprise-secgw-01"},
        )
    finally:
        app.dependency_overrides.clear()

    assert unauthorized.status_code == 403
    assert organizational_units.json()[0]["value"] == "03-test-ou"
    assert groups.json()[0]["value"] == "secure-access@example.com"
    assert access_levels.json()[0]["label"] == "Managed Chrome"


def test_expired_setup_catalog_adc_returns_actionable_reauthentication() -> None:
    app.dependency_overrides[setup_catalog_provider] = ExpiredSetupCatalogProvider
    try:
        responses = [
            client.post(
                "/api/v1/setup-options/organizational-units",
                headers=SESSION_HEADERS,
                json={"customer_id": "C012abcde"},
            ),
            client.post(
                "/api/v1/setup-options/groups",
                headers=SESSION_HEADERS,
                json={"customer_id": "C012abcde"},
            ),
            client.post(
                "/api/v1/setup-options/access-levels",
                headers=SESSION_HEADERS,
                json={"project_id": "enterprise-secgw-01"},
            ),
        ]
    finally:
        app.dependency_overrides.clear()

    for response in responses:
        assert response.status_code == 428
        assert response.json()["detail"]["code"] == "adc-unavailable"
        assert "application-default login" in response.json()["detail"]["message"]


def test_approval_identity_is_server_attested_and_cannot_be_overridden(
    tmp_path: Path,
) -> None:
    state_repository = StateRepository(tmp_path / "attested-approval.db")
    specification = _specification()
    snapshot = _ready_snapshot(cloud_identity="attested-operator@example.com")
    prepared = state_repository.store_prepared_plan(
        specification,
        PreflightResult(snapshot=snapshot),
        DesiredStatePlanner().build_plan(specification, snapshot),
    )
    app.dependency_overrides[repository] = lambda: state_repository
    app.dependency_overrides[mutation_authorizer] = lambda: FakeMutationAuthorizer(
        _mutation_identity("attested-operator@example.com")
    )
    try:
        spoofed = client.post(
            "/api/v1/approvals",
            headers=SESSION_HEADERS,
            json={
                "plan_id": prepared.plan_id,
                "approved_by": "spoofed@example.com",
                "confirmation": "APPROVE",
            },
        )
        response = client.post(
            "/api/v1/approvals",
            headers=SESSION_HEADERS,
            json={
                "plan_id": prepared.plan_id,
                "confirmation": "APPROVE",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert spoofed.status_code == 422
    assert response.status_code == 200
    assert response.json()["approved_by"] == "attested-operator@example.com"
    assert state_repository.list_audit_events()[0].actor == ("attested-operator@example.com")


def test_apply_consumes_exact_approval_once_and_exposes_run(
    tmp_path: Path,
) -> None:
    state_repository = StateRepository(tmp_path / "api-state.db")
    specification = _specification()
    plan = DesiredStatePlanner().build_plan(
        specification,
        _ready_snapshot(),
    )
    approval = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
        mutation_identity=_mutation_identity(),
    )
    app.dependency_overrides[repository] = lambda: state_repository
    app.dependency_overrides[mutation_authorizer] = lambda: FakeMutationAuthorizer()
    app.dependency_overrides[resource_executor] = SuccessfulExecutor
    payload = {
        "approval_id": approval.approval_id,
        "confirmation": "APPLY",
    }
    try:
        response = client.post("/api/v1/runs", headers=SESSION_HEADERS, json=payload)
        assert response.status_code == 202
        run = response.json()
        assert run["status"] == "running"

        read_response = client.get(f"/api/v1/runs/{run['run_id']}")
        assert read_response.status_code == 200
        assert read_response.json()["status"] == "succeeded"
        assert read_response.json()["configuration_hash"] == plan.configuration_hash

        replay = client.post("/api/v1/runs", headers=SESSION_HEADERS, json=payload)
        assert replay.status_code == 409
        assert replay.json()["detail"]["code"] == "approval-invalid"
    finally:
        app.dependency_overrides.clear()


def test_gateway_logs_require_the_exact_run_bound_operator_and_deployer(
    tmp_path: Path,
) -> None:
    state_repository = StateRepository(tmp_path / "logs-identity.db")
    specification = _specification()
    identity = _mutation_identity()
    plan = DesiredStatePlanner().build_plan(
        specification,
        DiscoverySnapshot(
            existing_resource_keys={
                "accesscontextmanager:access_level:"
                "accessPolicies/123456789/accessLevels/managed_chrome",
                "compute:source_image:"
                "projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
            },
            enabled_apis=REQUIRED_APIS,
            granted_permissions=REQUIRED_PERMISSIONS,
            cloud_identity=identity.operator_email,
            workspace_identity="admin@example.com",
            billing_enabled=True,
            source_image_binding={
                "name": specification.source_image,
                "id": "1234567890123456789",
                "self_link": (
                    "https://www.googleapis.com/compute/v1/"
                    f"{specification.source_image}"
                ),
            },
        ),
    )
    approval = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by=identity.operator_email,
        mutation_identity=identity,
    )
    _, run = state_repository.consume_approval_and_create_run(
        approval.approval_id,
        current_identity=identity,
    )
    observability = CountingObservability()
    current_identity = {"value": identity}
    app.dependency_overrides[repository] = lambda: state_repository
    app.dependency_overrides[gateway_observability] = lambda: observability
    app.dependency_overrides[mutation_authorizer] = lambda: FakeMutationAuthorizer(
        current_identity["value"]
    )
    try:
        for wrong_identity in (
            _mutation_identity("other-operator@example.com"),
            _mutation_identity(service_account_unique_id="999999999999999999999"),
        ):
            current_identity["value"] = wrong_identity
            rejected = client.get(
                f"/api/v1/runs/{run.run_id}/logs?category=connection",
                headers=SESSION_HEADERS,
            )
            assert rejected.status_code == 409
            assert rejected.json()["detail"]["code"] == (
                "deployment-log-identity-mismatch"
            )
            assert observability.calls == 0

        current_identity["value"] = identity
        accepted = client.get(
            f"/api/v1/runs/{run.run_id}/logs?category=connection",
            headers=SESSION_HEADERS,
        )
        assert accepted.status_code == 200
        assert accepted.json()["logging_enabled"] is True
        assert observability.calls == 1
    finally:
        app.dependency_overrides.clear()


def test_apply_rejects_browser_supplied_actor_without_consuming_approval(
    tmp_path: Path,
) -> None:
    state_repository = StateRepository(tmp_path / "apply-actor.db")
    specification = _specification()
    plan = DesiredStatePlanner().build_plan(
        specification,
        _ready_snapshot(),
    )
    approval = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
        mutation_identity=_mutation_identity(),
    )
    app.dependency_overrides[repository] = lambda: state_repository
    app.dependency_overrides[resource_executor] = SuccessfulExecutor
    try:
        response = client.post(
            "/api/v1/runs",
            headers=SESSION_HEADERS,
            json={
                "approval_id": approval.approval_id,
                "actor": "spoofed@example.com",
                "confirmation": "APPLY",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    preserved = state_repository.get_approval(approval.approval_id)
    assert preserved is not None
    assert preserved.consumed_at is None


def test_apply_rejection_for_active_run_preserves_losing_approval(
    tmp_path: Path,
) -> None:
    state_repository = StateRepository(tmp_path / "active-run.db")
    specification = _specification()
    plan = DesiredStatePlanner().build_plan(
        specification,
        _ready_snapshot(),
    )
    winner = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator-a@example.com",
        mutation_identity=_mutation_identity("operator-a@example.com"),
    )
    loser = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
        mutation_identity=_mutation_identity(),
    )
    state_repository.consume_approval_and_create_run(
        winner.approval_id,
        current_identity=_mutation_identity("operator-a@example.com"),
    )
    app.dependency_overrides[repository] = lambda: state_repository
    app.dependency_overrides[resource_executor] = SuccessfulExecutor
    try:
        response = client.post(
            "/api/v1/runs",
            headers=SESSION_HEADERS,
            json={
                "approval_id": loser.approval_id,
                "confirmation": "APPLY",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "approval-invalid"
    assert "Another deployment run is active" in response.json()["detail"]["message"]
    preserved = state_repository.get_approval(loser.approval_id)
    assert preserved is not None
    assert preserved.consumed_at is None


def test_evidence_export_contains_chain_head_and_runs(tmp_path: Path) -> None:
    state_repository = StateRepository(tmp_path / "evidence-state.db")
    state_repository.save_draft(_specification(), actor="auditor@example.com")
    app.dependency_overrides[repository] = lambda: state_repository
    try:
        response = client.get("/api/v1/evidence/export")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.headers["content-disposition"].endswith('"secure-gateway-studio-evidence.json"')
    bundle = response.json()
    assert bundle["schema_version"] == 2
    assert bundle["acceptance"] == []
    assert bundle["integrity"]["valid"] is True
    assert bundle["integrity"]["chain_head_hash"]
    assert bundle["audit_events"][0]["event_type"] == "draft.saved"


def test_latest_teardown_endpoint_restores_reload_state(tmp_path: Path) -> None:
    state_repository = StateRepository(tmp_path / "latest-teardown.db")
    specification = _specification()
    plan = DesiredStatePlanner().build_plan(
        specification,
        _ready_snapshot(),
    )
    approval = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
        mutation_identity=_mutation_identity(),
    )
    approval = state_repository.consume_approval(
        approval.approval_id,
        actor="operator@example.com",
    )
    run = state_repository.create_run(approval, actor="operator@example.com")
    state_repository.finish_run(
        run.run_id,
        status=RunStatus.SUCCEEDED,
        actor="operator@example.com",
    )
    owned_change = next(change for change in plan.changes if change.owned_after_apply)
    state_repository.claim_resource(
        f"{owned_change.provider}:{owned_change.resource_type}:{owned_change.resource_name}",
        run_id=run.run_id,
    )
    teardown_plan = build_teardown_plan(state_repository, run.run_id)
    teardown = state_repository.create_teardown_run(
        source_run_id=run.run_id,
        plan_hash=teardown_plan.plan_hash,
        resources=teardown_plan.resources,
        actor="operator@example.com",
        current_identity=_mutation_identity(),
    )
    app.dependency_overrides[repository] = lambda: state_repository
    try:
        response = client.get(
            f"/api/v1/runs/{run.run_id}/teardowns/latest",
            headers=SESSION_HEADERS,
        )
        missing = client.get(
            "/api/v1/runs/missing/teardowns/latest",
            headers=SESSION_HEADERS,
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["teardown_id"] == teardown.teardown_id
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "teardown-not-found"


def test_operator_acceptance_endpoint_records_evidence_and_readiness(
    tmp_path: Path,
) -> None:
    state_repository = StateRepository(tmp_path / "acceptance-api.db")
    specification = _specification()
    plan = DesiredStatePlanner().build_plan(
        specification,
        _ready_snapshot(),
    )
    approval = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
        mutation_identity=_mutation_identity(),
    )
    approval = state_repository.consume_approval(
        approval.approval_id,
        actor="operator@example.com",
    )
    run = state_repository.create_run(approval, actor="operator@example.com")
    state_repository.finish_run(
        run.run_id,
        status=RunStatus.SUCCEEDED,
        actor="operator@example.com",
    )
    app.dependency_overrides[repository] = lambda: state_repository
    app.dependency_overrides[mutation_authorizer] = lambda: FakeMutationAuthorizer()
    try:
        spoofed_actor = client.post(
            f"/api/v1/runs/{run.run_id}/acceptance-results",
            headers=SESSION_HEADERS,
            json={
                "test_id": "T07",
                "case_key": "macos",
                "status": "user_confirmed",
                "summary": "Browser-supplied actor must be rejected",
                "evidence": "Sanitized evidence",
                "actor": "spoofed@example.com",
                "confirmation": "RECORD",
            },
        )
        response = client.post(
            f"/api/v1/runs/{run.run_id}/acceptance-results",
            headers=SESSION_HEADERS,
            json={
                "test_id": "T07",
                "case_key": "macos",
                "status": "user_confirmed",
                "summary": "Authorized managed Chrome reached the application",
                "evidence": "Screenshot reference SHA-256: abc123",
                "confirmation": "RECORD",
            },
        )
        readiness = client.get(f"/api/v1/runs/{run.run_id}/acceptance")
        invalid_case = client.post(
            f"/api/v1/runs/{run.run_id}/acceptance-results",
            headers=SESSION_HEADERS,
            json={
                "test_id": "T07",
                "case_key": "default",
                "status": "user_confirmed",
                "summary": "Generic evidence must not satisfy platform cases",
                "evidence": "Sanitized generic evidence",
                "confirmation": "RECORD",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert spoofed_actor.status_code == 422
    assert response.status_code == 201
    assert response.json()["source"] == "operator"
    assert response.json()["case_key"] == "macos"
    assert response.json()["actor"] == "operator@example.com"
    assert readiness.status_code == 200
    assert "T01" in readiness.json()["missing_tests"]
    assert readiness.json()["production_ready"] is False
    assert invalid_case.status_code == 409
    assert invalid_case.json()["detail"]["code"] == "acceptance-result-invalid"


class SuccessfulAcceptanceVerifier:
    def verify(self, specification: DeploymentSpec) -> list[AcceptanceFinding]:
        del specification
        return [
            AcceptanceFinding(
                test_id=test_id,
                status=AcceptanceStatus.PASSED,
                summary=f"{test_id.value} system verification passed",
                evidence=f'{{"test_id":"{test_id.value}","status":"passed"}}',
            )
            for test_id in (
                AcceptanceTestId.T01,
                AcceptanceTestId.T02,
                AcceptanceTestId.T03,
                AcceptanceTestId.T04,
                AcceptanceTestId.T05,
            )
        ]


def test_system_acceptance_endpoint_records_machine_findings(
    tmp_path: Path,
) -> None:
    state_repository = StateRepository(tmp_path / "system-acceptance-api.db")
    specification = _specification()
    plan = DesiredStatePlanner().build_plan(
        specification,
        _ready_snapshot(),
    )
    approval = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
        mutation_identity=_mutation_identity(),
    )
    approval = state_repository.consume_approval(
        approval.approval_id,
        actor="operator@example.com",
    )
    run = state_repository.create_run(approval, actor="operator@example.com")
    state_repository.finish_run(
        run.run_id,
        status=RunStatus.SUCCEEDED,
        actor="operator@example.com",
    )
    app.dependency_overrides[repository] = lambda: state_repository
    app.dependency_overrides[mutation_authorizer] = lambda: FakeMutationAuthorizer()
    app.dependency_overrides[acceptance_verifier] = SuccessfulAcceptanceVerifier
    try:
        response = client.post(
            f"/api/v1/runs/{run.run_id}/acceptance/verify",
            headers=SESSION_HEADERS,
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert set(payload["satisfied_tests"]) == {"T01", "T02", "T03", "T04", "T05"}
    assert all(result["source"] == "system" for result in payload["results"])
    assert payload["production_ready"] is False
