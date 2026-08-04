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
from sgstudio.providers.acceptance import AcceptanceFinding
from sgstudio.providers.gcloud_bootstrap import DeployerBootstrapResult
from sgstudio.providers.local_artifacts import CertificateArtifactStore
from sgstudio.storage import StateRepository

client = TestClient(app)
SESSION_HEADERS = {"X-SGS-Session": SESSION_NONCE}


class FakeDeployerBootstrapper:
    def bootstrap(self, project_id: str) -> DeployerBootstrapResult:
        return DeployerBootstrapResult(
            project_id=project_id,
            operator_email="admin@example.com",
            service_account_email=(
                f"secure-gateway-deployer@{project_id}.iam.gserviceaccount.com"
            ),
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


def test_health_is_loopback_service() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["bind"] == "loopback"
    assert response.json()["session_nonce"] == SESSION_NONCE
    assert response.headers["cache-control"] == "no-store"


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


class SuccessfulExecutor:
    def apply(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        del change, spec

    def rollback(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        del change, spec


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
    snapshot = DiscoverySnapshot(
        existing_resource_keys={
            "accesscontextmanager:access_level:"
            "accessPolicies/123456789/accessLevels/managed_chrome",
            "compute:source_image:projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
        },
        enabled_apis=REQUIRED_APIS,
        granted_permissions=REQUIRED_PERMISSIONS,
        cloud_identity="attested-operator@example.com",
        workspace_identity="admin@example.com",
        billing_enabled=True,
    )
    prepared = state_repository.store_prepared_plan(
        specification,
        PreflightResult(snapshot=snapshot),
        DesiredStatePlanner().build_plan(specification, snapshot),
    )
    app.dependency_overrides[repository] = lambda: state_repository
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
        DiscoverySnapshot(
            existing_resource_keys={
                "accesscontextmanager:access_level:"
                "accessPolicies/123456789/accessLevels/managed_chrome",
                "compute:source_image:"
                "projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
            },
            enabled_apis=REQUIRED_APIS,
            granted_permissions=REQUIRED_PERMISSIONS,
            cloud_identity="operator@example.com",
            workspace_identity="admin@example.com",
            billing_enabled=True,
        ),
    )
    approval = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
    )
    app.dependency_overrides[repository] = lambda: state_repository
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


def test_apply_rejects_browser_supplied_actor_without_consuming_approval(
    tmp_path: Path,
) -> None:
    state_repository = StateRepository(tmp_path / "apply-actor.db")
    specification = _specification()
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
            cloud_identity="operator@example.com",
            workspace_identity="admin@example.com",
            billing_enabled=True,
        ),
    )
    approval = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
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
        DiscoverySnapshot(
            existing_resource_keys={
                "accesscontextmanager:access_level:"
                "accessPolicies/123456789/accessLevels/managed_chrome",
                "compute:source_image:"
                "projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
            },
            enabled_apis=REQUIRED_APIS,
            granted_permissions=REQUIRED_PERMISSIONS,
            cloud_identity="operator@example.com",
            workspace_identity="admin@example.com",
            billing_enabled=True,
        ),
    )
    winner = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator-a@example.com",
    )
    loser = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator-b@example.com",
    )
    state_repository.consume_approval_and_create_run(
        winner.approval_id,
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


def test_operator_acceptance_endpoint_records_evidence_and_readiness(
    tmp_path: Path,
) -> None:
    state_repository = StateRepository(tmp_path / "acceptance-api.db")
    specification = _specification()
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
            cloud_identity="operator@example.com",
            workspace_identity="admin@example.com",
            billing_enabled=True,
        ),
    )
    approval = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
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
        DiscoverySnapshot(
            existing_resource_keys={
                "accesscontextmanager:access_level:"
                "accessPolicies/123456789/accessLevels/managed_chrome",
                "compute:source_image:"
                "projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
            },
            enabled_apis=REQUIRED_APIS,
            granted_permissions=REQUIRED_PERMISSIONS,
            cloud_identity="operator@example.com",
            workspace_identity="admin@example.com",
            billing_enabled=True,
        ),
    )
    approval = state_repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
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
