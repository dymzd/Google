from pathlib import Path

import pytest

from sgstudio.domain.execution import DeploymentExecutor, ProviderExecutionError
from sgstudio.domain.models import (
    AccessPrincipal,
    DeploymentSpec,
    DiscoverySnapshot,
    OperationStatus,
    PrincipalType,
    ResourceChange,
    RunPhase,
    RunStatus,
    SourceImageBinding,
)
from sgstudio.domain.planner import (
    REQUIRED_APIS,
    REQUIRED_PERMISSIONS,
    DesiredStatePlanner,
)
from sgstudio.domain.teardown import build_teardown_plan
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


def consumed_approval(repository: StateRepository, *, existing_shared: bool = False):
    existing_keys = (
        {
            "beyondcorp:security_gateway:default",
            "chromepolicy:extension_install:ekajlcmdfcigmdbphhifahdfjbkciflj",
            "chromepolicy:extension_configuration:ekajlcmdfcigmdbphhifahdfjbkciflj",
        }
        if existing_shared
        else set()
    )
    existing_keys.add(
        "accesscontextmanager:access_level:accessPolicies/123456789/accessLevels/managed_chrome"
    )
    existing_keys.add(
        "compute:source_image:projects/enterprise-secgw-01/global/images/sgs-nginx-20260730"
    )
    plan = DesiredStatePlanner().build_plan(
        deployment_spec(),
        DiscoverySnapshot(
            existing_resource_keys=existing_keys,
            enabled_apis=REQUIRED_APIS,
            granted_permissions=REQUIRED_PERMISSIONS,
            cloud_identity="operator@example.com",
            workspace_identity="admin@example.com",
            billing_enabled=True,
            source_image_binding=SourceImageBinding(
                name=(
                    "projects/enterprise-secgw-01/global/images/"
                    "sgs-nginx-20260730"
                ),
                id="987654321",
                self_link=(
                    "https://www.googleapis.com/compute/v1/projects/"
                    "enterprise-secgw-01/global/images/sgs-nginx-20260730"
                ),
            ),
        ),
    )
    approval = repository.approve_plan(
        plan,
        specification=deployment_spec(),
        approved_by="operator@example.com",
    )
    return repository.consume_approval(
        approval.approval_id,
        configuration_hash=approval.configuration_hash,
        actor="operator@example.com",
    )


class RecordingProvider:
    def __init__(self, fail_name: str | None = None) -> None:
        self.fail_name = fail_name
        self.applied: list[str] = []
        self.rolled_back: list[str] = []
        self.bound_run_id: str | None = None

    def bind_run(self, run_id: str) -> None:
        self.bound_run_id = run_id

    def apply(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        del spec
        if change.resource_name == self.fail_name:
            raise ProviderExecutionError("injected-failure")
        self.applied.append(change.resource_name)

    def rollback(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        del spec
        self.rolled_back.append(change.resource_name)


def test_execution_invokes_exact_reversal_for_all_mutations_in_reverse_order(
    tmp_path: Path,
) -> None:
    repository = StateRepository(tmp_path / "state.db")
    approval = consumed_approval(repository)
    provider = RecordingProvider(fail_name="secure-gateway-http-offload-offload-mig")

    run = DeploymentExecutor(provider, repository).execute(
        approval,
        deployment_spec(),
        actor="operator@example.com",
    )

    assert run.status is RunStatus.ROLLED_BACK
    assert provider.bound_run_id == run.run_id
    # The failing external mutation is also compensated because its durable
    # send intent was claimed before provider execution.
    assert provider.rolled_back == [
        "secure-gateway-http-offload-offload-mig",
        *reversed(provider.applied),
    ]
    assert "default" not in provider.rolled_back
    assert any(operation.error_code == "injected-failure" for operation in run.operations)


def test_successful_execution_skips_shared_reused_resources(tmp_path: Path) -> None:
    repository = StateRepository(tmp_path / "state.db")
    approval = consumed_approval(repository, existing_shared=True)
    provider = RecordingProvider()

    run = DeploymentExecutor(provider, repository).execute(
        approval,
        deployment_spec(),
        actor="operator@example.com",
    )

    assert run.status is RunStatus.SUCCEEDED
    assert "default" not in provider.applied
    assert "ekajlcmdfcigmdbphhifahdfjbkciflj" not in provider.applied
    managed_extension_operations = [
        operation
        for operation in run.operations
        if operation.resource_key.endswith(":ekajlcmdfcigmdbphhifahdfjbkciflj")
    ]
    assert len(managed_extension_operations) == 2


def test_successful_execution_persists_provider_teardown_metadata(tmp_path: Path) -> None:
    class MetadataProvider(RecordingProvider):
        @staticmethod
        def ownership_metadata(
            change: ResourceChange,
            spec: DeploymentSpec,
        ) -> dict[str, object] | None:
            del spec
            if change.resource_type != "gateway_iam":
                return None
            return {"kind": "iam_policy_delta", "marker": change.resource_name}

    repository = StateRepository(tmp_path / "ownership-metadata.db")
    approval = consumed_approval(repository)
    provider = MetadataProvider()

    run = DeploymentExecutor(provider, repository).execute(
        approval,
        deployment_spec(),
        actor="operator@example.com",
    )

    metadata = repository.active_owned_resource_metadata(run.run_id)
    assert metadata["beyondcorp:gateway_iam:default-service-discovery-users"] == {
        "kind": "iam_policy_delta",
        "marker": "default-service-discovery-users",
    }


@pytest.mark.parametrize("tamper", ["plan_hash", "configuration_hash"])
def test_execution_revalidates_approval_integrity_before_provider_work(
    tmp_path: Path,
    tamper: str,
) -> None:
    repository = StateRepository(tmp_path / f"execution-{tamper}-tamper.db")
    approval = consumed_approval(repository)
    if tamper == "plan_hash":
        approval.plan_hash = "0" * 64
    else:
        approval.plan.configuration_hash = "0" * 64
    provider = RecordingProvider()

    with pytest.raises(ValueError, match="hash"):
        DeploymentExecutor(provider, repository).execute(
            approval,
            deployment_spec(),
            actor="operator@example.com",
        )

    assert provider.bound_run_id is None
    assert provider.applied == []
    assert repository.list_runs() == []


def test_provider_preparation_fails_run_before_any_external_mutation(
    tmp_path: Path,
) -> None:
    repository = StateRepository(tmp_path / "prepare-before-mutation.db")
    approval = consumed_approval(repository)

    class PreparationFailureProvider(RecordingProvider):
        def __init__(self) -> None:
            super().__init__()
            self.events: list[str] = []

        def bind_plan(self, plan) -> None:
            assert plan is approval.plan
            self.events.append("bind-plan")

        def prepare_apply(self, candidate: DeploymentSpec) -> None:
            assert candidate == deployment_spec()
            self.events.append("prepare")
            raise ProviderExecutionError("certificate-alias-drift")

        def apply(self, change: ResourceChange, candidate: DeploymentSpec) -> None:
            self.events.append("apply")
            super().apply(change, candidate)

    provider = PreparationFailureProvider()

    run = DeploymentExecutor(provider, repository).execute(
        approval,
        deployment_spec(),
        actor="operator@example.com",
    )

    assert run.status is RunStatus.FAILED
    assert run.operations == []
    assert provider.applied == []
    assert provider.events == ["bind-plan", "prepare"]


def test_private_ca_is_preclaimed_before_apply_and_released_after_compensation(
    tmp_path: Path,
) -> None:
    repository = StateRepository(tmp_path / "preclaim.db")
    approval = consumed_approval(repository)

    class FailingCaProvider(RecordingProvider):
        @staticmethod
        def requires_preclaim(change: ResourceChange, spec: DeploymentSpec) -> bool:
            del spec
            return change.provider == "privateca" and change.resource_type == "certificate"

        def apply(self, change: ResourceChange, spec: DeploymentSpec) -> None:
            if change.provider == "privateca" and change.resource_type == "certificate":
                assert self.bound_run_id is not None
                assert (
                    f"privateca:certificate:{change.resource_name}"
                    in repository.active_owned_resource_keys(self.bound_run_id)
                )
                raise ProviderExecutionError("injected-ca-failure")
            super().apply(change, spec)

    provider = FailingCaProvider()
    run = DeploymentExecutor(provider, repository).execute(
        approval,
        deployment_spec(),
        actor="operator@example.com",
    )

    assert run.status is RunStatus.ROLLED_BACK
    assert repository.active_owned_resource_keys(run.run_id) == set()


def test_interrupted_preclaimed_ca_resumes_rollback_before_teardown(tmp_path: Path) -> None:
    state_path = tmp_path / "interrupted-preclaim.db"
    repository = StateRepository(state_path)
    approval = consumed_approval(repository)
    run = repository.create_run(approval, actor="operator@example.com")
    ca_change = next(
        change
        for change in approval.plan.changes
        if change.provider == "privateca" and change.resource_type == "certificate"
    )
    operation = repository.start_operation(run.run_id, ca_change)
    repository.claim_resource(operation.resource_key, run_id=run.run_id)
    repository.fail_operation_and_begin_rollback(
        operation.operation_id,
        error_code="provider-response-ambiguous",
    )

    recovered = StateRepository(state_path)
    recovered_run = recovered.get_run(run.run_id)
    assert recovered_run is not None
    assert recovered_run.status is RunStatus.INTERRUPTED

    teardown = build_teardown_plan(recovered, run.run_id)
    assert teardown.can_destroy is False

    provider = RecordingProvider()
    completed = DeploymentExecutor(provider, recovered).execute(
        approval,
        deployment_spec(),
        actor="operator@example.com",
        existing_run=recovered_run,
    )

    assert completed.status is RunStatus.ROLLED_BACK
    assert ca_change.resource_name in provider.rolled_back
    assert recovered.active_owned_resource_keys(run.run_id) == set()


def test_restart_after_provider_rollback_response_retries_compensation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "rollback-response-gap.db"
    repository = StateRepository(database)
    approval = consumed_approval(repository)
    run = repository.create_run(approval, actor="operator@example.com")
    change = next(
        item
        for item in approval.plan.changes
        if item.owned_after_apply and item.action.value == "create"
    )
    operation = repository.start_operation(run.run_id, change)
    repository.complete_operation_and_claim(
        operation.operation_id,
        run_id=run.run_id,
        metadata={"kind": "test", "identity": "immutable"},
    )
    repository.begin_run_rollback(run.run_id)

    class CrashAfterRollback(RecordingProvider):
        def rollback(self, change: ResourceChange, spec: DeploymentSpec) -> None:
            super().rollback(change, spec)
            raise RuntimeError("simulated process termination")

    active = repository.get_run(run.run_id)
    assert active is not None and active.phase is RunPhase.ROLLING_BACK
    with pytest.raises(RuntimeError, match="process termination"):
        DeploymentExecutor(CrashAfterRollback(), repository).execute(
            approval,
            deployment_spec(),
            actor="operator@example.com",
            existing_run=active,
        )

    restarted = StateRepository(database)
    interrupted = restarted.get_run(run.run_id)
    assert interrupted is not None
    assert interrupted.status is RunStatus.INTERRUPTED
    assert interrupted.phase is RunPhase.ROLLING_BACK
    resumed_provider = RecordingProvider()
    completed = DeploymentExecutor(resumed_provider, restarted).execute(
        approval,
        deployment_spec(),
        actor="operator@example.com",
        existing_run=interrupted,
    )

    assert completed.status is RunStatus.ROLLED_BACK
    assert resumed_provider.rolled_back == [change.resource_name]
    assert restarted.active_owned_resource_keys(run.run_id) == set()


def test_restart_repairs_legacy_rolled_back_to_inventory_release_gap(
    tmp_path: Path,
) -> None:
    database = tmp_path / "rollback-release-gap.db"
    repository = StateRepository(database)
    approval = consumed_approval(repository)
    run = repository.create_run(approval, actor="operator@example.com")
    change = next(
        item
        for item in approval.plan.changes
        if item.owned_after_apply and item.action.value == "create"
    )
    operation = repository.start_operation(run.run_id, change)
    repository.complete_operation_and_claim(
        operation.operation_id,
        run_id=run.run_id,
        metadata={"kind": "test", "identity": "immutable"},
    )
    repository.begin_run_rollback(run.run_id)
    repository.complete_operation(
        operation.operation_id,
        status=OperationStatus.ROLLED_BACK,
    )
    assert operation.resource_key in repository.active_owned_resource_keys(run.run_id)

    restarted = StateRepository(database)
    interrupted = restarted.get_run(run.run_id)
    assert interrupted is not None
    provider = RecordingProvider()
    completed = DeploymentExecutor(provider, restarted).execute(
        approval,
        deployment_spec(),
        actor="operator@example.com",
        existing_run=interrupted,
    )

    assert completed.status is RunStatus.ROLLED_BACK
    assert provider.rolled_back == []
    assert restarted.active_owned_resource_keys(run.run_id) == set()
