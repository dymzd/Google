import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sgstudio.domain.models import (
    AcceptanceStatus,
    AcceptanceTestId,
    AccessPrincipal,
    BackendKind,
    BackendLocation,
    ChromePlatform,
    DeploymentMode,
    DeploymentSpec,
    DiscoverySnapshot,
    EvidenceSource,
    PreflightResult,
    PrincipalType,
    ResourceChange,
    RiskLevel,
    RunStatus,
)
from sgstudio.domain.planner import (
    REQUIRED_APIS,
    REQUIRED_PERMISSIONS,
    DesiredStatePlanner,
)
from sgstudio.domain.teardown import build_teardown_plan, deployment_details
from sgstudio.storage import StateRepository


def deployment_spec() -> DeploymentSpec:
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


def test_draft_round_trip(tmp_path: Path) -> None:
    repository = StateRepository(tmp_path / "state.db")
    spec = deployment_spec()
    deployment_id = repository.save_draft(spec)

    restored = repository.get_draft(deployment_id)
    assert restored == spec
    assert repository.get_draft("missing") is None


def test_teardown_plan_is_hash_bound_and_uses_active_ownership(tmp_path: Path) -> None:
    repository = StateRepository(tmp_path / "teardown.db")
    run = succeeded_run(repository)
    assert run is not None
    approval = repository.get_approval(run.approval_id)
    assert approval is not None
    owned_change = next(change for change in approval.plan.changes if change.owned_after_apply)
    resource_key = (
        f"{owned_change.provider}:{owned_change.resource_type}:{owned_change.resource_name}"
    )
    repository.claim_resource(resource_key, run_id=run.run_id)

    details = deployment_details(repository, run.run_id)
    plan = build_teardown_plan(repository, run.run_id)

    assert details.teardown_available is True
    assert [resource.resource_key for resource in plan.resources] == [resource_key]
    assert plan.confirmation.startswith(f"DELETE {approval.specification.name} ")
    assert len(plan.plan_hash) == 64

    teardown = repository.create_teardown_run(
        source_run_id=run.run_id,
        plan_hash=plan.plan_hash,
        resource_keys=[resource_key],
        actor="operator@example.com",
    )
    repository.start_teardown_operation(teardown.teardown_id, resource_key)
    repository.finish_teardown_operation(
        teardown.teardown_id, resource_key, status="succeeded"
    )
    completed = repository.finish_teardown_run(
        teardown.teardown_id, status="succeeded", actor="operator@example.com"
    )

    assert completed.status == "succeeded"
    assert completed.operations[0].status == "succeeded"
    assert "teardown.succeeded" in {
        event.event_type for event in repository.list_audit_events()
    }


def test_latest_reapply_resolves_the_active_ownership_run(tmp_path: Path) -> None:
    repository = StateRepository(tmp_path / "reapply-teardown.db")
    owner_run = succeeded_run(repository)
    assert owner_run is not None
    owner_approval = repository.get_approval(owner_run.approval_id)
    assert owner_approval is not None
    owned_change = next(
        change for change in owner_approval.plan.changes if change.owned_after_apply
    )
    resource_key = (
        f"{owned_change.provider}:{owned_change.resource_type}:"
        f"{owned_change.resource_name}"
    )
    repository.claim_resource(resource_key, run_id=owner_run.run_id)

    latest_run = succeeded_run(repository)
    assert latest_run is not None
    details = deployment_details(repository, latest_run.run_id)
    plan = build_teardown_plan(repository, latest_run.run_id)

    assert details.run.run_id == latest_run.run_id
    assert details.ownership_run_id == owner_run.run_id
    assert plan.run_id == owner_run.run_id
    assert [resource.resource_key for resource in plan.resources] == [resource_key]


def succeeded_run(
    repository: StateRepository,
    spec: DeploymentSpec | None = None,
):
    spec = spec or deployment_spec()
    plan = DesiredStatePlanner().build_plan(
        spec,
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
    approval = repository.approve_plan(
        plan,
        specification=spec,
        approved_by="operator@example.com",
    )
    approval = repository.consume_approval(
        approval.approval_id,
        actor="operator@example.com",
    )
    run = repository.create_run(approval, actor="operator@example.com")
    repository.finish_run(
        run.run_id,
        status=RunStatus.SUCCEEDED,
        actor="operator@example.com",
    )
    return repository.get_run(run.run_id)


def test_approval_is_hash_bound_expiring_and_single_use(tmp_path: Path) -> None:
    repository = StateRepository(tmp_path / "state.db")
    plan = DesiredStatePlanner().build_plan(
        deployment_spec(),
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

    approval = repository.approve_plan(
        plan,
        specification=deployment_spec(),
        approved_by="operator@example.com",
    )

    assert approval.plan.can_apply is True
    assert approval.configuration_hash == plan.configuration_hash
    assert approval.plan_hash
    consumed = repository.consume_approval(
        approval.approval_id,
        configuration_hash=plan.configuration_hash,
        actor="operator@example.com",
    )
    assert consumed.consumed_at is not None

    with pytest.raises(ValueError, match="invalid, expired, consumed"):
        repository.consume_approval(
            approval.approval_id,
            configuration_hash=plan.configuration_hash,
            actor="operator@example.com",
        )

    event_types = {event.event_type for event in repository.list_audit_events()}
    assert {"plan.approved", "plan.consumed"} <= event_types


def test_atomic_apply_allows_only_one_active_run(tmp_path: Path) -> None:
    database_path = tmp_path / "atomic-apply.db"
    repository = StateRepository(database_path)
    spec = deployment_spec()
    plan = DesiredStatePlanner().build_plan(
        spec,
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
    approvals = [
        repository.approve_plan(
            plan,
            specification=spec,
            approved_by=f"operator-{index}@example.com",
        )
        for index in range(2)
    ]
    repositories = [repository, StateRepository(database_path)]

    def start(attempt: tuple[StateRepository, str]):
        contender, approval_id = attempt
        try:
            return contender.consume_approval_and_create_run(
                approval_id,
            )
        except ValueError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                start,
                zip(
                    repositories,
                    [approval.approval_id for approval in approvals],
                    strict=True,
                ),
            )
        )

    successes = [result for result in results if isinstance(result, tuple)]
    failures = [result for result in results if isinstance(result, ValueError)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert "Another deployment run is active" in str(failures[0])
    assert len([run for run in repository.list_runs() if run.status is RunStatus.RUNNING]) == 1
    assert (
        sum(
            repository.get_approval(approval.approval_id).consumed_at is not None
            for approval in approvals
        )
        == 1
    )


def test_approval_rejects_unresolved_blocking_gates(tmp_path: Path) -> None:
    repository = StateRepository(tmp_path / "state.db")
    blocked_plan = DesiredStatePlanner().build_plan(deployment_spec())

    with pytest.raises(ValueError, match="Blocking deployment gates"):
        repository.approve_plan(
            blocked_plan,
            specification=deployment_spec(),
            approved_by="operator@example.com",
        )


def test_prepared_plan_approval_requires_attested_cloud_identity(
    tmp_path: Path,
) -> None:
    repository = StateRepository(tmp_path / "missing-identity.db")
    spec = deployment_spec()
    snapshot = DiscoverySnapshot(
        existing_resource_keys={
            "accesscontextmanager:access_level:"
            "accessPolicies/123456789/accessLevels/managed_chrome",
            "compute:source_image:projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
        },
        enabled_apis=REQUIRED_APIS,
        granted_permissions=REQUIRED_PERMISSIONS,
        workspace_identity="admin@example.com",
        billing_enabled=True,
    )
    prepared = repository.store_prepared_plan(
        spec,
        PreflightResult(snapshot=snapshot),
        DesiredStatePlanner().build_plan(spec, snapshot),
    )

    with pytest.raises(ValueError, match="server-attested Google Cloud identity"):
        repository.approve_prepared_plan(prepared.plan_id)


def test_acceptance_results_compute_production_readiness(tmp_path: Path) -> None:
    repository = StateRepository(tmp_path / "acceptance.db")
    run = succeeded_run(repository)
    assert run is not None

    for test_id in (
        AcceptanceTestId.T01,
        AcceptanceTestId.T02,
        AcceptanceTestId.T03,
        AcceptanceTestId.T04,
        AcceptanceTestId.T05,
    ):
        repository.record_acceptance_result(
            run_id=run.run_id,
            test_id=test_id,
            status=AcceptanceStatus.PASSED,
            source=EvidenceSource.SYSTEM,
            summary=f"{test_id.value} machine verification passed",
            evidence=f"sanitized system evidence for {test_id.value}",
            actor="system",
        )
    for test_id, case_key in (
        (AcceptanceTestId.T06, "default"),
        (AcceptanceTestId.T07, "macos"),
        (AcceptanceTestId.T07, "windows"),
        (AcceptanceTestId.T07, "linux"),
        (AcceptanceTestId.T07, "chromeos"),
        (AcceptanceTestId.T08, "default"),
        (AcceptanceTestId.T09, "unauthorized_principal"),
        (AcceptanceTestId.T09, "unmanaged_browser"),
    ):
        repository.record_acceptance_result(
            run_id=run.run_id,
            test_id=test_id,
            case_key=case_key,
            status=AcceptanceStatus.USER_CONFIRMED,
            source=EvidenceSource.OPERATOR,
            summary=f"{test_id.value} {case_key} evidence confirmed",
            evidence=f"sanitized endpoint evidence for {test_id.value} {case_key}",
            actor="operator@example.com",
        )

    readiness = repository.acceptance_readiness(run.run_id)

    assert readiness.acceptance_complete is True
    assert readiness.production_ready is True
    assert readiness.missing_tests == []
    assert len(readiness.results) == 13
    assert len(readiness.required_cases) == 13
    assert repository.verify_audit_chain()[0] is True


def test_greenfield_poc_can_resolve_t06_with_operator_skip(tmp_path: Path) -> None:
    poc_repository = StateRepository(tmp_path / "poc-t06-skip.db")
    poc_spec = deployment_spec().model_copy(
        update={
            "mode": DeploymentMode.POC,
            "platforms": {ChromePlatform.MACOS},
        }
    )
    poc_run = succeeded_run(poc_repository, poc_spec)
    assert poc_run is not None
    poc_repository.record_acceptance_result(
        run_id=poc_run.run_id,
        test_id=AcceptanceTestId.T06,
        status=AcceptanceStatus.SKIPPED,
        source=EvidenceSource.OPERATOR,
        summary="No pre-existing Secure Gateway control application in this greenfield PoC",
        evidence="demo-server1.internal returned ERR_NAME_NOT_RESOLVED",
        actor="operator@example.com",
    )

    poc_readiness = poc_repository.acceptance_readiness(poc_run.run_id)
    assert AcceptanceTestId.T06 in poc_readiness.satisfied_tests
    assert AcceptanceTestId.T06 not in poc_readiness.missing_tests

    production_repository = StateRepository(tmp_path / "production-t06-skip.db")
    production_run = succeeded_run(production_repository)
    assert production_run is not None
    production_repository.record_acceptance_result(
        run_id=production_run.run_id,
        test_id=AcceptanceTestId.T06,
        status=AcceptanceStatus.SKIPPED,
        source=EvidenceSource.OPERATOR,
        summary="No pre-existing Secure Gateway control application",
        evidence="demo-server1.internal returned ERR_NAME_NOT_RESOLVED",
        actor="operator@example.com",
    )

    production_readiness = production_repository.acceptance_readiness(
        production_run.run_id
    )
    assert AcceptanceTestId.T06 not in production_readiness.satisfied_tests
    assert AcceptanceTestId.T06 in production_readiness.missing_tests


def test_production_readiness_requires_every_platform_and_denial_case(
    tmp_path: Path,
) -> None:
    repository = StateRepository(tmp_path / "scoped-acceptance.db")
    run = succeeded_run(repository)
    assert run is not None

    for platform in ("macos", "windows", "linux"):
        repository.record_acceptance_result(
            run_id=run.run_id,
            test_id=AcceptanceTestId.T07,
            case_key=platform,
            status=AcceptanceStatus.USER_CONFIRMED,
            source=EvidenceSource.OPERATOR,
            summary=f"T07 passed on {platform}",
            evidence=f"sanitized screenshot hash for {platform}",
            actor="operator@example.com",
        )
    repository.record_acceptance_result(
        run_id=run.run_id,
        test_id=AcceptanceTestId.T09,
        case_key="unauthorized_principal",
        status=AcceptanceStatus.USER_CONFIRMED,
        source=EvidenceSource.OPERATOR,
        summary="Unauthorized principal was denied",
        evidence="sanitized denial evidence",
        actor="operator@example.com",
    )

    readiness = repository.acceptance_readiness(run.run_id)
    missing = {
        (requirement.test_id, requirement.case_key) for requirement in readiness.missing_cases
    }

    assert (AcceptanceTestId.T07, "chromeos") in missing
    assert (AcceptanceTestId.T09, "unmanaged_browser") in missing
    assert readiness.production_ready is False


def test_operator_confirmation_cannot_replace_machine_verification(
    tmp_path: Path,
) -> None:
    repository = StateRepository(tmp_path / "operator-only.db")
    run = succeeded_run(repository)
    assert run is not None

    repository.record_acceptance_result(
        run_id=run.run_id,
        test_id=AcceptanceTestId.T01,
        status=AcceptanceStatus.USER_CONFIRMED,
        source=EvidenceSource.OPERATOR,
        summary="Operator observed backend response",
        evidence="sanitized manual observation",
        actor="operator@example.com",
    )

    readiness = repository.acceptance_readiness(run.run_id)

    assert AcceptanceTestId.T01 in readiness.missing_tests
    assert readiness.production_ready is False


def test_existing_backend_allows_operator_confirmation_for_t01(
    tmp_path: Path,
) -> None:
    repository = StateRepository(tmp_path / "existing-backend.db")
    spec = deployment_spec().model_copy(
        update={
            "backend_kind": BackendKind.EXISTING_HTTP,
            "existing_backend_url": "http://backend.corp.internal",
            "existing_backend_location": BackendLocation.GCP,
            "existing_backend_connectivity_confirmed": True,
        }
    )
    run = succeeded_run(repository, spec)
    assert run is not None

    repository.record_acceptance_result(
        run_id=run.run_id,
        test_id=AcceptanceTestId.T01,
        status=AcceptanceStatus.USER_CONFIRMED,
        source=EvidenceSource.OPERATOR,
        summary="Existing backend returned HTTP 200 inside the private VPC",
        evidence="Sanitized operator probe output: status=200",
        actor="operator@example.com",
    )

    readiness = repository.acceptance_readiness(run.run_id)

    assert AcceptanceTestId.T01 in readiness.satisfied_tests
    assert AcceptanceTestId.T01 in readiness.operator_confirmable_tests


def test_acceptance_schema_v6_migrates_existing_results_without_loss(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "acceptance-v5.db"
    repository = StateRepository(database_path)
    run = succeeded_run(repository)
    assert run is not None
    repository.record_acceptance_result(
        run_id=run.run_id,
        test_id=AcceptanceTestId.T01,
        status=AcceptanceStatus.PASSED,
        source=EvidenceSource.SYSTEM,
        summary="Legacy T01 passed",
        evidence="legacy sanitized evidence",
        actor="system",
    )

    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            ALTER TABLE acceptance_results RENAME TO acceptance_results_v6;
            CREATE TABLE acceptance_results (
                result_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                test_id TEXT NOT NULL,
                status TEXT NOT NULL,
                source TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence TEXT NOT NULL,
                actor TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE(run_id, test_id),
                FOREIGN KEY(run_id) REFERENCES deployment_runs(run_id)
            );
            INSERT INTO acceptance_results(
                result_id, run_id, test_id, status, source, summary,
                evidence, actor, recorded_at
            )
            SELECT result_id, run_id, test_id, status, source, summary,
                   evidence, actor, recorded_at
            FROM acceptance_results_v6;
            DROP TABLE acceptance_results_v6;
            DELETE FROM schema_migrations WHERE version = 6;
            """
        )

    migrated = StateRepository(database_path)
    results = migrated.list_acceptance_results(run_id=run.run_id)

    assert len(results) == 1
    assert results[0].test_id is AcceptanceTestId.T01
    assert results[0].case_key == "default"
    with sqlite3.connect(database_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(acceptance_results)")}
        versions = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
    assert "case_key" in columns
    assert 6 in versions


def test_acceptance_evidence_rejects_credentials(tmp_path: Path) -> None:
    repository = StateRepository(tmp_path / "secret-evidence.db")
    run = succeeded_run(repository)
    assert run is not None

    with pytest.raises(ValueError, match="credentials or keys"):
        repository.record_acceptance_result(
            run_id=run.run_id,
            test_id=AcceptanceTestId.T07,
            status=AcceptanceStatus.USER_CONFIRMED,
            source=EvidenceSource.OPERATOR,
            summary="Endpoint evidence",
            evidence="Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            actor="operator@example.com",
        )


def test_audit_chain_detects_database_tampering(tmp_path: Path) -> None:
    database_path = tmp_path / "state.db"
    repository = StateRepository(database_path)
    repository.save_draft(deployment_spec())

    assert repository.verify_audit_chain() == (True, 1)

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE audit_events SET payload_json = ?",
            ('{"configuration_hash":"tampered"}',),
        )
        connection.commit()

    assert repository.verify_audit_chain() == (False, 1)


def test_restart_marks_in_flight_run_and_operation_interrupted(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "state.db"
    repository = StateRepository(database_path)
    spec = deployment_spec()
    plan = DesiredStatePlanner().build_plan(
        spec,
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
    approval = repository.approve_plan(
        plan,
        specification=spec,
        approved_by="operator@example.com",
    )
    consumed = repository.consume_approval(
        approval.approval_id,
        actor="operator@example.com",
    )
    run = repository.create_run(consumed, actor="operator@example.com")
    repository.start_operation(
        run.run_id,
        ResourceChange(
            provider="gcp",
            resource_type="network",
            resource_name="interrupted-network",
            action="create",
            risk=RiskLevel.MEDIUM,
            summary="test",
            owned_after_apply=True,
        ),
    )

    restarted_repository = StateRepository(database_path)
    recovered = restarted_repository.get_run(run.run_id)

    assert recovered is not None
    assert recovered.status is RunStatus.INTERRUPTED
    assert recovered.operations[0].status.value == "interrupted"
    assert recovered.operations[0].error_code == "process-restarted"
    assert "run.interrupted" in {
        event.event_type for event in restarted_repository.list_audit_events()
    }
