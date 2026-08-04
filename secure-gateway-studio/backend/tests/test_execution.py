from pathlib import Path

from sgstudio.domain.execution import DeploymentExecutor, ProviderExecutionError
from sgstudio.domain.models import (
    AccessPrincipal,
    DeploymentSpec,
    DiscoverySnapshot,
    PrincipalType,
    ResourceChange,
    RunStatus,
)
from sgstudio.domain.planner import (
    REQUIRED_APIS,
    REQUIRED_PERMISSIONS,
    DesiredStatePlanner,
)
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
    assert provider.rolled_back == list(reversed(provider.applied))
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
