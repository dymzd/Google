from __future__ import annotations

from typing import Literal, Protocol

from sgstudio.domain.canonical import canonical_digest
from sgstudio.domain.execution import ProviderExecutionError
from sgstudio.domain.models import (
    ChangeAction,
    DeploymentDetails,
    DeploymentResource,
    DeploymentSpec,
    OperationStatus,
    ResourceChange,
    RunStatus,
    TeardownPlan,
    TeardownRun,
)
from sgstudio.domain.teardown_instruction import teardown_instruction
from sgstudio.storage.repository import StateRepository


class ResourceDestroyer(Protocol):
    def destroy(
        self, change: ResourceChange, specification: DeploymentSpec
    ) -> Literal["deleted", "skipped"]: ...


def deployment_details(repository: StateRepository, run_id: str) -> DeploymentDetails:
    run = repository.get_run(run_id)
    if run is None:
        raise ValueError("Deployment run was not found")
    approval = repository.get_approval(run.approval_id)
    if approval is None:
        raise ValueError("Deployment approval was not found")
    requested_approval = approval
    ownership_run = run
    owned = repository.active_owned_resource_keys(run_id)
    if not owned:
        for candidate_run_id in repository.run_ids_with_active_ownership():
            candidate_run = repository.get_run(candidate_run_id)
            if candidate_run is None:
                continue
            candidate_approval = repository.get_approval(candidate_run.approval_id)
            if candidate_approval is None:
                continue
            candidate_spec = candidate_approval.specification
            requested_spec = requested_approval.specification
            if (
                candidate_spec.project_id == requested_spec.project_id
                and candidate_spec.name == requested_spec.name
                and candidate_spec.gateway_id == requested_spec.gateway_id
            ):
                ownership_run = candidate_run
                approval = candidate_approval
                owned = repository.active_owned_resource_keys(candidate_run_id)
                break
    operation_by_key = {
        operation.resource_key: operation for operation in ownership_run.operations
    }
    resources: list[DeploymentResource] = []
    for change in approval.plan.changes:
        key = _key(change)
        operation = operation_by_key.get(key)
        gateway_created = (
            change.provider == "beyondcorp"
            and change.resource_type == "security_gateway"
            and operation is not None
            and operation.action is ChangeAction.CREATE
            and operation.status is OperationStatus.SUCCEEDED
        )
        teardown_action: Literal["delete", "delete_if_empty", "retain"] = "retain"
        if key in owned:
            teardown_action = "delete"
        elif gateway_created:
            teardown_action = "delete_if_empty"
        resources.append(
            DeploymentResource(
                resource_key=key,
                summary=change.summary,
                provider=change.provider,
                resource_type=change.resource_type,
                resource_name=change.resource_name,
                owned=key in owned,
                teardown_action=teardown_action,
            )
        )
    spec = approval.specification
    return DeploymentDetails(
        run=run,
        ownership_run_id=(
            ownership_run.run_id if ownership_run.run_id != run.run_id else None
        ),
        deployment_name=spec.name,
        project_id=spec.project_id,
        gateway_id=spec.gateway_id,
        backend_kind=spec.backend_kind,
        application_hostname=spec.application_hostname,
        application_port=spec.application_port,
        resources=resources,
        teardown_available=(
            run.status
            not in {RunStatus.PENDING, RunStatus.RUNNING, RunStatus.INTERRUPTED}
            and any(item.teardown_action != "retain" for item in resources)
        ),
    )


def build_teardown_plan(repository: StateRepository, run_id: str) -> TeardownPlan:
    details = deployment_details(repository, run_id)
    effective_run_id = details.ownership_run_id or run_id
    effective_run = repository.get_run(effective_run_id)
    if effective_run is None:
        raise ValueError("Deployment ownership run was not found")
    delete_resources = [
        item for item in reversed(details.resources) if item.teardown_action != "retain"
    ]
    retained = [item for item in details.resources if item.teardown_action == "retain"]
    ownership_metadata = repository.active_owned_resource_metadata(effective_run_id)
    plan_hash = canonical_digest(
        teardown_instruction(
            run_id=effective_run_id,
            configuration_hash=effective_run.configuration_hash,
            resources=delete_resources,
            ownership_metadata=ownership_metadata,
        )
    )
    return TeardownPlan(
        run_id=effective_run_id,
        plan_hash=plan_hash,
        confirmation=f"DELETE {details.deployment_name} {plan_hash[:12]}",
        resources=delete_resources,
        retained_resources=retained,
        can_destroy=details.teardown_available and bool(delete_resources),
    )


class TeardownExecutor:
    def __init__(self, provider: ResourceDestroyer, repository: StateRepository) -> None:
        self._provider = provider
        self._repository = repository

    def execute(self, teardown: TeardownRun, *, actor: str) -> TeardownRun:
        if teardown.status == "interrupted":
            teardown = self._repository.resume_teardown_run(teardown.teardown_id)
        run = self._repository.get_run(teardown.source_run_id)
        if run is None:
            raise ValueError("Deployment run was not found")
        approval = self._repository.get_approval(run.approval_id)
        if approval is None:
            raise ValueError("Deployment approval was not found")
        bind_run = getattr(self._provider, "bind_run", None)
        if callable(bind_run):
            bind_run(run.run_id)
        bind_ownership_metadata = getattr(self._provider, "bind_ownership_metadata", None)
        instruction = self._repository.get_teardown_instruction(teardown.teardown_id)
        if instruction is None or canonical_digest(instruction) != teardown.plan_hash:
            return self._repository.finish_teardown_run(
                teardown.teardown_id, status="failed", actor=actor
            )
        if instruction.get("run_id") != run.run_id:
            return self._repository.finish_teardown_run(
                teardown.teardown_id, status="failed", actor=actor
            )
        instruction_resources = instruction.get("resources")
        if not isinstance(instruction_resources, list):
            return self._repository.finish_teardown_run(
                teardown.teardown_id, status="failed", actor=actor
            )
        resources_by_key = {
            item.get("resource_key"): item
            for item in instruction_resources
            if isinstance(item, dict) and isinstance(item.get("resource_key"), str)
        }
        immutable_metadata = {
            key: value["ownership_metadata"]
            for key, value in resources_by_key.items()
            if isinstance(value.get("ownership_metadata"), dict)
        }
        if callable(bind_ownership_metadata):
            bind_ownership_metadata(immutable_metadata)
        changes = {_key(change): change for change in approval.plan.changes}
        for operation in teardown.operations:
            if operation.status in {"succeeded", "skipped"}:
                continue
            resource = resources_by_key.get(operation.resource_key)
            if resource is None:
                self._repository.finish_teardown_operation(
                    teardown.teardown_id,
                    operation.resource_key,
                    status="failed",
                    error_code="teardown-instruction-invalid",
                )
                return self._repository.finish_teardown_run(
                    teardown.teardown_id, status="failed", actor=actor
                )
            expected_identity = {
                "provider": resource.get("provider"),
                "resource_type": resource.get("resource_type"),
                "resource_name": resource.get("resource_name"),
            }
            change = changes.get(operation.resource_key)
            if change is not None and expected_identity != {
                "provider": change.provider,
                "resource_type": change.resource_type,
                "resource_name": change.resource_name,
            }:
                change = None
            if change is None:
                self._repository.finish_teardown_operation(
                    teardown.teardown_id,
                    operation.resource_key,
                    status="failed",
                    error_code="teardown-resource-missing-from-approved-plan",
                )
                return self._repository.finish_teardown_run(
                    teardown.teardown_id, status="failed", actor=actor
                )
            if resource.get("owned") is True:
                current_metadata = self._repository.active_owned_resource_metadata(
                    run.run_id
                ).get(operation.resource_key)
                if current_metadata != resource.get("ownership_metadata"):
                    self._repository.finish_teardown_operation(
                        teardown.teardown_id,
                        operation.resource_key,
                        status="failed",
                        error_code="teardown-inventory-changed",
                    )
                    return self._repository.finish_teardown_run(
                        teardown.teardown_id, status="failed", actor=actor
                    )
            self._repository.start_teardown_operation(
                teardown.teardown_id, operation.resource_key
            )
            try:
                outcome = self._provider.destroy(change, approval.specification)
            except ProviderExecutionError as error:
                self._repository.finish_teardown_operation(
                    teardown.teardown_id,
                    operation.resource_key,
                    status="failed",
                    error_code=error.error_code,
                )
                return self._repository.finish_teardown_run(
                    teardown.teardown_id, status="failed", actor=actor
                )
            self._repository.complete_teardown_operation_and_release(
                teardown.teardown_id,
                operation.resource_key,
                run_id=run.run_id,
                status="skipped" if outcome == "skipped" else "succeeded",
                release=resource.get("owned") is True and outcome != "skipped",
            )
            if outcome == "skipped":
                return self._repository.finish_teardown_run(
                    teardown.teardown_id, status="failed", actor=actor
                )
        return self._repository.finish_teardown_run(
            teardown.teardown_id, status="succeeded", actor=actor
        )


def _key(change: ResourceChange) -> str:
    return f"{change.provider}:{change.resource_type}:{change.resource_name}"
