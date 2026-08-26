import json
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
    CertificateStrategy,
    ChromePlatform,
    DeploymentMode,
    DeploymentSpec,
    DiscoverySnapshot,
    EvidenceSource,
    MutationIdentity,
    PreflightResult,
    PrincipalType,
    PublicCertificateBinding,
    ResourceChange,
    RiskLevel,
    RunStatus,
    SourceImageBinding,
)
from sgstudio.domain.planner import (
    REQUIRED_APIS,
    REQUIRED_PERMISSIONS,
    DesiredStatePlanner,
)
from sgstudio.domain.teardown import (
    TeardownExecutor,
    build_teardown_plan,
    deployment_details,
)
from sgstudio.providers.discovery import discovery_ownership_proofs
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


def public_certificate_spec() -> DeploymentSpec:
    return deployment_spec().model_copy(
        update={
            "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
            "private_hostname": "gateway.secure-access.jp",
            "public_certificate_secret": (
                "projects/enterprise-secgw-01/secrets/operator-public-tls"
            ),
            "ca_pool": None,
            "ca_name": None,
        }
    )


def public_certificate_binding(version: int = 7) -> PublicCertificateBinding:
    return PublicCertificateBinding(
        secret_version_name=(
            "projects/enterprise-secgw-01/secrets/operator-public-tls/"
            f"versions/{version}"
        ),
        payload_sha256="ab" * 32,
    )


def source_image_binding() -> SourceImageBinding:
    name = "projects/enterprise-secgw-01/global/images/sgs-nginx-20260730"
    return SourceImageBinding(
        name=name,
        id="987654321",
        self_link=f"https://www.googleapis.com/compute/v1/{name}",
    )


def public_certificate_snapshot() -> DiscoverySnapshot:
    return DiscoverySnapshot(
        existing_resource_keys={
            "accesscontextmanager:access_level:"
            "accessPolicies/123456789/accessLevels/managed_chrome",
            "compute:source_image:"
            "projects/enterprise-secgw-01/global/images/sgs-nginx-20260730",
            "secretmanager:secret:operator-public-tls",
        },
        enabled_apis=REQUIRED_APIS,
        granted_permissions=REQUIRED_PERMISSIONS,
        cloud_identity="operator@example.com",
        workspace_identity="admin@example.com",
        billing_enabled=True,
        source_image_binding=source_image_binding(),
        public_certificate_binding=public_certificate_binding(),
    )


def mutation_identity(
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
        resources=plan.resources,
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


def test_multi_resource_teardown_uses_immutable_snapshot_after_each_release(
    tmp_path: Path,
) -> None:
    class RecordingDestroyer:
        def __init__(self) -> None:
            self.destroyed: list[str] = []

        def bind_run(self, _run_id: str) -> None:
            return

        def bind_ownership_metadata(self, _metadata) -> None:
            return

        def destroy(self, change, _specification):
            self.destroyed.append(
                f"{change.provider}:{change.resource_type}:{change.resource_name}"
            )
            return "deleted"

    repository = StateRepository(tmp_path / "multi-teardown.db")
    run = succeeded_run(repository)
    assert run is not None
    approval = repository.get_approval(run.approval_id)
    assert approval is not None
    owned_changes = [
        change
        for change in approval.plan.changes
        if change.owned_after_apply and change.action.value == "create"
    ][:2]
    assert len(owned_changes) == 2
    keys = [
        f"{change.provider}:{change.resource_type}:{change.resource_name}"
        for change in owned_changes
    ]
    for index, key in enumerate(keys):
        repository.claim_resource(
            key,
            run_id=run.run_id,
            metadata={"kind": "test", "identity": f"immutable-{index}"},
        )
    plan = build_teardown_plan(repository, run.run_id)
    teardown = repository.create_teardown_run(
        source_run_id=run.run_id,
        plan_hash=plan.plan_hash,
        resources=plan.resources,
        actor="operator@example.com",
    )
    destroyer = RecordingDestroyer()
    completed = TeardownExecutor(destroyer, repository).execute(
        teardown,
        actor="operator@example.com",
    )

    assert completed.status == "succeeded"
    assert len(destroyer.destroyed) == 2
    assert repository.active_owned_resource_keys(run.run_id) == set()
    instruction = repository.get_teardown_instruction(teardown.teardown_id)
    assert instruction is not None
    assert len(instruction["resources"]) == 2


def test_interrupted_teardown_resumes_only_unfinished_snapshot_operations(
    tmp_path: Path,
) -> None:
    class RecordingDestroyer:
        def __init__(self) -> None:
            self.destroyed: list[str] = []

        def bind_run(self, _run_id: str) -> None:
            return

        def bind_ownership_metadata(self, _metadata) -> None:
            return

        def destroy(self, change, _specification):
            self.destroyed.append(
                f"{change.provider}:{change.resource_type}:{change.resource_name}"
            )
            return "deleted"

    database = tmp_path / "resume-teardown.db"
    repository = StateRepository(database)
    run = succeeded_run(repository)
    assert run is not None
    approval = repository.get_approval(run.approval_id)
    assert approval is not None
    owned_changes = [
        change
        for change in approval.plan.changes
        if change.owned_after_apply and change.action.value == "create"
    ][:2]
    keys = [
        f"{change.provider}:{change.resource_type}:{change.resource_name}"
        for change in owned_changes
    ]
    for index, key in enumerate(keys):
        repository.claim_resource(
            key,
            run_id=run.run_id,
            metadata={"kind": "test", "identity": f"immutable-{index}"},
        )
    plan = build_teardown_plan(repository, run.run_id)
    teardown = repository.create_teardown_run(
        source_run_id=run.run_id,
        plan_hash=plan.plan_hash,
        resources=plan.resources,
        actor="operator@example.com",
    )
    first = teardown.operations[0].resource_key
    repository.start_teardown_operation(teardown.teardown_id, first)
    repository.complete_teardown_operation_and_release(
        teardown.teardown_id,
        first,
        run_id=run.run_id,
        status="succeeded",
        release=True,
    )

    restarted = StateRepository(database)
    interrupted = restarted.get_teardown_run(teardown.teardown_id)
    assert interrupted is not None and interrupted.status == "interrupted"
    destroyer = RecordingDestroyer()
    completed = TeardownExecutor(destroyer, restarted).execute(
        interrupted,
        actor="operator@example.com",
    )

    assert completed.status == "succeeded"
    assert destroyer.destroyed == [
        operation.resource_key
        for operation in teardown.operations
        if operation.resource_key != first
    ]
    assert restarted.active_owned_resource_keys(run.run_id) == set()


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


def test_repeated_runs_keep_separate_exact_resource_ownership(tmp_path: Path) -> None:
    repository = StateRepository(tmp_path / "rotation-ownership.db")
    first = succeeded_run(repository)
    second = succeeded_run(repository)
    assert first is not None and second is not None
    resource_key = "privateca:certificate:secure-gateway-http-offload-certificate"
    first_metadata = {
        "kind": "privateca_certificate",
        "certificate_name": "projects/p/locations/l/caPools/p/certificates/first",
        "authority_name": "projects/p/locations/l/caPools/p/certificateAuthorities/ca",
        "csr_sha256": "a" * 64,
    }
    second_metadata = {
        **first_metadata,
        "certificate_name": "projects/p/locations/l/caPools/p/certificates/second",
        "csr_sha256": "b" * 64,
    }
    repository.claim_resource(resource_key, run_id=first.run_id, metadata=first_metadata)
    repository.claim_resource(resource_key, run_id=second.run_id, metadata=second_metadata)

    assert repository.active_owned_resource_keys(first.run_id) == {resource_key}
    assert repository.active_owned_resource_keys(second.run_id) == {resource_key}
    assert repository.active_owned_resource_metadata(first.run_id)[resource_key] == first_metadata
    assert repository.active_owned_resource_metadata(second.run_id)[resource_key] == second_metadata


def test_discovery_ownership_metadata_uses_one_exact_stable_provider_scope(
    tmp_path: Path,
) -> None:
    repository = StateRepository(tmp_path / "discovery-ownership-scope.db")
    run = succeeded_run(repository)
    assert run is not None
    resource_key = "compute:network:secure-gateway-http-offload-vpc"
    metadata = {
        "kind": "generic_created_resource",
        "phase": "applied",
        "resource_key": resource_key,
        "ownership_marker": (
            "Secure Gateway Studio ownership-token="
            "d36ac6fb-431c-441a-ae78-3736e425ee25; "
            "Managed by Secure Gateway Studio"
        ),
        "provider_identity_field": "id",
        "provider_identity": "network-immutable-123",
    }
    repository.claim_resource(resource_key, run_id=run.run_id, metadata=metadata)

    safely_changed = deployment_spec().model_copy(
        update={
            "managed_chrome_access_level": "accessPolicies/123/accessLevels/new-level",
            "principals": [
                AccessPrincipal(
                    type=PrincipalType.USER,
                    value="new-operator@example.com",
                )
            ],
        }
    )
    wrong_region = deployment_spec().model_copy(
        update={
            "region": "us-central1",
            "zone": "us-central1-a",
            "secondary_zone": "us-central1-b",
        }
    )

    assert repository.active_discovery_ownership_metadata(deployment_spec()) == {
        resource_key: metadata
    }
    assert repository.active_discovery_ownership_metadata(safely_changed) == {
        resource_key: metadata
    }
    assert repository.active_discovery_ownership_metadata(wrong_region) == {}


def test_shared_gateway_success_checkpoint_is_discovery_proof_not_teardown_ownership(
    tmp_path: Path,
) -> None:
    repository = StateRepository(tmp_path / "shared-gateway-discovery-proof.db")
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
            source_image_binding=source_image_binding(),
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
    gateway_key = "beyondcorp:security_gateway:default"
    gateway_change = next(
        change
        for change in plan.changes
        if f"{change.provider}:{change.resource_type}:{change.resource_name}"
        == gateway_key
    )
    assert gateway_change.action.value == "create"
    assert gateway_change.owned_after_apply is False
    operation = repository.start_operation(run.run_id, gateway_change)
    checkpoint = {
        "kind": "generic_created_resource",
        "phase": "applied",
        "resource_key": gateway_key,
        "ownership_marker": None,
        "provider_identity_field": "createTime",
        "provider_identity": "2026-08-24T00:00:42Z",
    }
    repository.checkpoint_operation(operation.operation_id, checkpoint)
    repository.complete_operation_and_claim(
        operation.operation_id,
        run_id=run.run_id,
        metadata=checkpoint,
    )
    repository.finish_run(
        run.run_id,
        status=RunStatus.SUCCEEDED,
        actor="operator@example.com",
    )

    assert gateway_key not in repository.active_owned_resource_keys(run.run_id)
    assert repository.active_discovery_ownership_metadata(spec)[gateway_key] == checkpoint
    proofs = discovery_ownership_proofs(
        repository.active_discovery_ownership_metadata(spec)
    )
    assert proofs[gateway_key].provider_identity == "2026-08-24T00:00:42Z"

    second_plan = DesiredStatePlanner().build_plan(
        spec,
        DiscoverySnapshot(existing_resource_keys={gateway_key}),
    )
    second_gateway = next(
        change
        for change in second_plan.changes
        if f"{change.provider}:{change.resource_type}:{change.resource_name}"
        == gateway_key
    )
    assert second_gateway.action.value == "reuse"
    assert second_gateway.owned_after_apply is False

    teardown = build_teardown_plan(repository, run.run_id)
    teardown_gateway = next(
        resource for resource in teardown.resources if resource.resource_key == gateway_key
    )
    assert teardown_gateway.owned is False
    assert teardown_gateway.teardown_action == "delete_if_empty"


def test_discovery_ownership_metadata_aggregates_rotation_runs_per_resource_key(
    tmp_path: Path,
) -> None:
    repository = StateRepository(tmp_path / "discovery-ownership-rotation.db")
    first = succeeded_run(repository)
    second = succeeded_run(repository)
    assert first is not None and second is not None
    network_key = "compute:network:secure-gateway-http-offload-vpc"
    version_key = "secretmanager:secret_version:secure-gateway-http-offload-tls"
    network_metadata = {
        "kind": "generic_created_resource",
        "phase": "applied",
        "resource_key": network_key,
        "ownership_marker": (
            "Secure Gateway Studio ownership-token="
            "d36ac6fb-431c-441a-ae78-3736e425ee25; "
            "Managed by Secure Gateway Studio"
        ),
        "provider_identity_field": "id",
        "provider_identity": "network-immutable-123",
    }
    old_version_metadata = {
        "kind": "secret_version",
        "phase": "applied",
        "resource_key": version_key,
        "ownership_token": "72dba29a-6f77-4614-8f62-84529be3b926",
        "version_name": (
            "projects/enterprise-secgw-01/secrets/"
            "secure-gateway-http-offload-tls/versions/1"
        ),
    }
    new_version_metadata = {
        **old_version_metadata,
        "ownership_token": "7d07fe4e-9ab4-4b7b-91ee-4be504754c17",
        "version_name": (
            "projects/enterprise-secgw-01/secrets/"
            "secure-gateway-http-offload-tls/versions/2"
        ),
    }
    repository.claim_resource(
        network_key,
        run_id=first.run_id,
        metadata=network_metadata,
    )
    repository.claim_resource(
        version_key,
        run_id=first.run_id,
        metadata=old_version_metadata,
    )
    repository.claim_resource(
        version_key,
        run_id=second.run_id,
        metadata=new_version_metadata,
    )

    active = repository.active_discovery_ownership_metadata(deployment_spec())
    assert active == {
        network_key: network_metadata,
        version_key: new_version_metadata,
    }
    proofs = discovery_ownership_proofs(active)
    assert proofs[network_key].provider_identity == "network-immutable-123"
    assert proofs[version_key].provider_identity == new_version_metadata["version_name"]

    plan = DesiredStatePlanner().build_plan(
        deployment_spec(),
        DiscoverySnapshot(existing_resource_keys={network_key, version_key}),
    )
    changes = {
        f"{change.provider}:{change.resource_type}:{change.resource_name}": change
        for change in plan.changes
    }
    assert changes[network_key].action.value == "no_change"
    assert changes[network_key].owned_after_apply is False
    assert changes[version_key].action.value == "no_change"
    assert changes[version_key].owned_after_apply is False


def test_discovery_ownership_metadata_drops_only_tied_conflicting_key(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "discovery-ownership-tie.db"
    repository = StateRepository(database_path)
    first = succeeded_run(repository)
    second = succeeded_run(repository)
    assert first is not None and second is not None
    network_key = "compute:network:secure-gateway-http-offload-vpc"
    version_key = "secretmanager:secret_version:secure-gateway-http-offload-tls"
    network_metadata = {
        "kind": "generic_created_resource",
        "phase": "applied",
        "resource_key": network_key,
        "ownership_marker": (
            "Secure Gateway Studio ownership-token="
            "d36ac6fb-431c-441a-ae78-3736e425ee25"
        ),
        "provider_identity_field": "id",
        "provider_identity": "network-immutable-123",
    }
    first_version = {
        "kind": "secret_version",
        "phase": "applied",
        "resource_key": version_key,
        "ownership_token": "72dba29a-6f77-4614-8f62-84529be3b926",
        "version_name": "projects/p/secrets/s/versions/1",
    }
    second_version = {
        **first_version,
        "ownership_token": "7d07fe4e-9ab4-4b7b-91ee-4be504754c17",
        "version_name": "projects/p/secrets/s/versions/2",
    }
    repository.claim_resource(
        network_key,
        run_id=first.run_id,
        metadata=network_metadata,
    )
    repository.claim_resource(
        version_key,
        run_id=first.run_id,
        metadata=first_version,
    )
    repository.claim_resource(
        version_key,
        run_id=second.run_id,
        metadata=second_version,
    )
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            UPDATE resource_ownership SET acquired_at = ?
            WHERE resource_key = ?
            """,
            ("2026-08-24T00:00:00+00:00", version_key),
        )

    active = repository.active_discovery_ownership_metadata(deployment_spec())
    assert active == {network_key: network_metadata}


def test_skipped_teardown_fails_and_keeps_resource_ownership(tmp_path: Path) -> None:
    class SkippingDestroyer:
        def __init__(self):
            self.bound_run_id = None

        def bind_run(self, run_id):
            self.bound_run_id = run_id

        def destroy(self, change, specification):
            del change, specification
            return "skipped"

    repository = StateRepository(tmp_path / "skipped-teardown.db")
    run = succeeded_run(repository)
    assert run is not None
    approval = repository.get_approval(run.approval_id)
    assert approval is not None
    owned_change = next(
        change
        for change in approval.plan.changes
        if change.owned_after_apply and change.action.value == "create"
    )
    resource_key = (
        f"{owned_change.provider}:{owned_change.resource_type}:"
        f"{owned_change.resource_name}"
    )
    repository.claim_resource(resource_key, run_id=run.run_id)
    plan = build_teardown_plan(repository, run.run_id)
    teardown = repository.create_teardown_run(
        source_run_id=run.run_id,
        plan_hash=plan.plan_hash,
        resources=plan.resources,
        actor="operator@example.com",
    )

    destroyer = SkippingDestroyer()
    completed = TeardownExecutor(destroyer, repository).execute(
        teardown,
        actor="operator@example.com",
    )

    assert destroyer.bound_run_id == run.run_id
    assert completed.status == "failed"
    assert completed.operations[0].status == "skipped"
    assert resource_key in repository.active_owned_resource_keys(run.run_id)


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
            source_image_binding=source_image_binding(),
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
            source_image_binding=source_image_binding(),
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
            source_image_binding=source_image_binding(),
        ),
    )
    approvals = [
        repository.approve_plan(
            plan,
            specification=spec,
            approved_by=f"operator-{index}@example.com",
            mutation_identity=mutation_identity(f"operator-{index}@example.com"),
        )
        for index in range(2)
    ]
    identities = {
        approval.approval_id: mutation_identity(approval.approved_by)
        for approval in approvals
    }
    repositories = [repository, StateRepository(database_path)]

    def start(attempt: tuple[StateRepository, str]):
        contender, approval_id = attempt
        try:
            return contender.consume_approval_and_create_run(
                approval_id,
                current_identity=identities[approval_id],
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


def test_public_certificate_binding_is_copied_from_approval_to_run(tmp_path: Path) -> None:
    repository = StateRepository(tmp_path / "public-binding.db")
    specification = public_certificate_spec()
    plan = DesiredStatePlanner().build_plan(
        specification,
        public_certificate_snapshot(),
    )
    approval = repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
    )
    consumed = repository.consume_approval(
        approval.approval_id,
        actor="operator@example.com",
    )

    run = repository.create_run(consumed, actor="operator@example.com")
    restored = repository.get_run(run.run_id)

    assert run.public_certificate_binding == public_certificate_binding()
    assert restored is not None
    assert restored.public_certificate_binding == approval.plan.public_certificate_binding


def test_resume_atomically_rejects_run_public_certificate_binding_drift(
    tmp_path: Path,
) -> None:
    database = tmp_path / "public-binding-resume.db"
    repository = StateRepository(database)
    specification = public_certificate_spec()
    plan = DesiredStatePlanner().build_plan(
        specification,
        public_certificate_snapshot(),
    )
    approval = repository.approve_plan(
        plan,
        specification=specification,
        approved_by="operator@example.com",
    )
    consumed = repository.consume_approval(
        approval.approval_id,
        actor="operator@example.com",
    )
    run = repository.create_run(consumed, actor="operator@example.com")
    restarted = StateRepository(database)
    assert restarted.get_run(run.run_id).status is RunStatus.INTERRUPTED
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            UPDATE deployment_runs
            SET public_certificate_binding_json = ?
            WHERE run_id = ?
            """,
            (public_certificate_binding(8).model_dump_json(), run.run_id),
        )
        connection.commit()

    with pytest.raises(ValueError, match="differs from its approval"):
        restarted.resume_run(run.run_id)

    preserved = restarted.get_run(run.run_id)
    assert preserved is not None
    assert preserved.status is RunStatus.INTERRUPTED


@pytest.mark.parametrize(
    "current_identity",
    [
        mutation_identity("other-operator@example.com"),
        mutation_identity(operator_subject="replacement-human-subject"),
        mutation_identity(service_account_unique_id="999999999999999999999"),
    ],
    ids=["different-operator", "recreated-human", "recreated-service-account"],
)
def test_atomic_apply_rejects_identity_changes_without_consuming_approval(
    tmp_path: Path,
    current_identity: MutationIdentity,
) -> None:
    repository = StateRepository(tmp_path / "identity-continuity.db")
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
            source_image_binding=source_image_binding(),
        ),
    )
    approval = repository.approve_plan(
        plan,
        specification=spec,
        approved_by="operator@example.com",
        mutation_identity=mutation_identity(),
    )

    with pytest.raises(ValueError, match="differs from the approved identity"):
        repository.consume_approval_and_create_run(
            approval.approval_id,
            current_identity=current_identity,
        )

    preserved = repository.get_approval(approval.approval_id)
    assert preserved is not None and preserved.consumed_at is None
    assert repository.list_runs() == []


def test_apply_and_teardown_share_one_global_lifecycle_slot(tmp_path: Path) -> None:
    repository = StateRepository(tmp_path / "lifecycle-slot.db")
    source_run = succeeded_run(repository)
    assert source_run is not None
    source_approval = repository.get_approval(source_run.approval_id)
    assert source_approval is not None
    owned_change = next(
        change for change in source_approval.plan.changes if change.owned_after_apply
    )
    resource_key = (
        f"{owned_change.provider}:{owned_change.resource_type}:"
        f"{owned_change.resource_name}"
    )
    repository.claim_resource(resource_key, run_id=source_run.run_id)
    teardown_plan = build_teardown_plan(repository, source_run.run_id)
    repository.create_teardown_run(
        source_run_id=source_run.run_id,
        plan_hash=teardown_plan.plan_hash,
        resources=teardown_plan.resources,
        actor="operator@example.com",
    )
    next_approval = repository.approve_plan(
        source_approval.plan,
        specification=source_approval.specification,
        approved_by="operator@example.com",
        mutation_identity=mutation_identity(),
    )
    with pytest.raises(ValueError, match="teardown is active"):
        repository.consume_approval_and_create_run(
            next_approval.approval_id,
            current_identity=mutation_identity(),
        )

    other = StateRepository(tmp_path / "lifecycle-slot-reverse.db")
    completed = succeeded_run(other)
    assert completed is not None
    completed_approval = other.get_approval(completed.approval_id)
    assert completed_approval is not None
    other.claim_resource(resource_key, run_id=completed.run_id)
    active_approval = other.approve_plan(
        completed_approval.plan,
        specification=completed_approval.specification,
        approved_by="operator@example.com",
        mutation_identity=mutation_identity(),
    )
    _, active_run = other.consume_approval_and_create_run(
        active_approval.approval_id,
        current_identity=mutation_identity(),
    )
    assert active_run.status is RunStatus.RUNNING
    active_teardown_plan = build_teardown_plan(other, completed.run_id)
    with pytest.raises(ValueError, match="deployment run is active"):
        other.create_teardown_run(
            source_run_id=completed.run_id,
            plan_hash=active_teardown_plan.plan_hash,
            resources=active_teardown_plan.resources,
            actor="operator@example.com",
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
        source_image_binding=source_image_binding(),
    )
    prepared = repository.store_prepared_plan(
        spec,
        PreflightResult(snapshot=snapshot),
        DesiredStatePlanner().build_plan(spec, snapshot),
    )

    with pytest.raises(ValueError, match="server-attested Google Cloud identity"):
        repository.approve_prepared_plan(prepared.plan_id)


def test_prepared_plan_tampering_is_rejected_before_approval(tmp_path: Path) -> None:
    database_path = tmp_path / "prepared-tamper.db"
    repository = StateRepository(database_path)
    spec = deployment_spec()
    snapshot = DiscoverySnapshot(
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
        source_image_binding=source_image_binding(),
    )
    prepared = repository.store_prepared_plan(
        spec,
        PreflightResult(snapshot=snapshot),
        DesiredStatePlanner().build_plan(spec, snapshot),
    )
    tampered = prepared.plan.model_dump(mode="json")
    tampered["changes"][0]["summary"] = "tampered mutation"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE prepared_plans SET plan_json = ? WHERE plan_id = ?",
            (json.dumps(tampered), prepared.plan_id),
        )
        connection.commit()

    with pytest.raises(ValueError, match="Stored plan hash"):
        repository.approve_prepared_plan(prepared.plan_id)

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM approved_plans").fetchone()[0] == 0


@pytest.mark.parametrize(
    ("column", "expected"),
    [
        ("plan_json", "Stored plan hash"),
        ("specification_json", "Plan configuration hash"),
        ("configuration_hash", "Stored configuration hash"),
    ],
)
def test_atomic_consume_rejects_tampered_approval_without_consuming_or_starting_run(
    tmp_path: Path,
    column: str,
    expected: str,
) -> None:
    database_path = tmp_path / f"approval-{column}-tamper.db"
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
            source_image_binding=source_image_binding(),
        ),
    )
    approval = repository.approve_plan(
        plan,
        specification=spec,
        approved_by="operator@example.com",
        mutation_identity=mutation_identity(),
    )
    if column == "plan_json":
        value = approval.plan.model_dump(mode="json")
        value["changes"][0]["summary"] = "tampered mutation"
        serialized = json.dumps(value)
    elif column == "specification_json":
        value = approval.specification.model_dump(mode="json")
        value["name"] = "tampered-deployment"
        serialized = json.dumps(value)
    else:
        serialized = "0" * 64
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            f"UPDATE approved_plans SET {column} = ? WHERE approval_id = ?",
            (serialized, approval.approval_id),
        )
        connection.commit()

    with pytest.raises(ValueError, match=expected):
        repository.consume_approval_and_create_run(
            approval.approval_id,
            current_identity=mutation_identity(),
        )

    with sqlite3.connect(database_path) as connection:
        consumed_at = connection.execute(
            "SELECT consumed_at FROM approved_plans WHERE approval_id = ?",
            (approval.approval_id,),
        ).fetchone()[0]
        run_count = connection.execute("SELECT COUNT(*) FROM deployment_runs").fetchone()[0]
    assert consumed_at is None
    assert run_count == 0


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


def test_audit_integrity_detects_acceptance_row_tampering(tmp_path: Path) -> None:
    database_path = tmp_path / "acceptance-tamper.db"
    repository = StateRepository(database_path)
    run = succeeded_run(repository)
    assert run is not None
    repository.record_acceptance_result(
        run_id=run.run_id,
        test_id=AcceptanceTestId.T07,
        case_key="macos",
        status=AcceptanceStatus.USER_CONFIRMED,
        source=EvidenceSource.OPERATOR,
        summary="macOS access was confirmed",
        evidence="screenshot digest abc123",
        actor="operator@example.com",
    )
    assert repository.verify_audit_chain()[0] is True

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE acceptance_results SET evidence = ? WHERE run_id = ?",
            ("tampered evidence", run.run_id),
        )
        connection.commit()

    assert repository.verify_audit_chain()[0] is False


def test_v10_migrates_legacy_acceptance_event_without_rewriting_history(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "acceptance-v10.db"
    repository = StateRepository(database_path)
    run = succeeded_run(repository)
    assert run is not None
    result = repository.record_acceptance_result(
        run_id=run.run_id,
        test_id=AcceptanceTestId.T07,
        case_key="macos",
        status=AcceptanceStatus.USER_CONFIRMED,
        source=EvidenceSource.OPERATOR,
        summary="macOS access was confirmed",
        evidence="screenshot digest abc123",
        actor="operator@example.com",
    )

    # Exact v0.2.0 payload shape: it authenticated the evidence digest but did
    # not bind the mutable row's result_id or complete canonical record.
    legacy_payload = {
        "run_id": result.run_id,
        "test_id": result.test_id.value,
        "case_key": result.case_key,
        "status": result.status.value,
        "source": result.source.value,
        "evidence_sha256": (
            "1e2f384da35bedec79e2b47b5da5f738e53cd66e1accddd275ecdc2f3cdd727f"
        ),
    }
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        event = connection.execute(
            """
            SELECT rowid, id, deployment_id, event_type, actor, created_at,
                   previous_hash, event_hash
            FROM audit_events
            WHERE event_type = 'acceptance.recorded'
            ORDER BY rowid DESC LIMIT 1
            """
        ).fetchone()
        assert event is not None
        legacy_payload_json = json.dumps(legacy_payload, separators=(",", ":"), sort_keys=True)
        legacy_hash = StateRepository._audit_hash(
            event_id=event["id"],
            deployment_id=event["deployment_id"],
            event_type=event["event_type"],
            actor=event["actor"],
            payload_json=legacy_payload_json,
            created_at=event["created_at"],
            previous_hash=event["previous_hash"],
        )
        connection.execute(
            "UPDATE audit_events SET payload_json = ?, event_hash = ? WHERE rowid = ?",
            (legacy_payload_json, legacy_hash, event["rowid"]),
        )
        connection.execute("DELETE FROM schema_migrations WHERE version = 10")
        connection.commit()
        legacy_event = connection.execute(
            "SELECT * FROM audit_events WHERE rowid = ?", (event["rowid"],)
        ).fetchone()
        legacy_count = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]

    migrated = StateRepository(database_path)
    assert migrated.verify_audit_chain()[0] is True
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        unchanged = connection.execute(
            "SELECT * FROM audit_events WHERE rowid = ?", (event["rowid"],)
        ).fetchone()
        appended = connection.execute(
            "SELECT * FROM audit_events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        assert unchanged is not None
        assert dict(unchanged) == dict(legacy_event)
        assert appended is not None
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == (
            legacy_count + 1
        )
        appended_payload = json.loads(appended["payload_json"])
        assert appended["event_type"] == "acceptance.recorded"
        assert appended["previous_hash"] == legacy_hash
        assert appended_payload["result_id"] == result.result_id
        assert appended_payload["record_digest"]
        assert appended_payload["legacy_event_id"] == event["id"]

        connection.execute(
            "UPDATE acceptance_results SET summary = ? WHERE result_id = ?",
            ("tampered after migration", result.result_id),
        )
        connection.commit()

    assert migrated.verify_audit_chain()[0] is False


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
            source_image_binding=source_image_binding(),
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
