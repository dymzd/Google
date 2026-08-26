from __future__ import annotations

from typing import Protocol

from sgstudio.domain.models import (
    ApprovedPlan,
    ChangeAction,
    DeploymentRun,
    DeploymentSpec,
    OperationStatus,
    ResourceChange,
    RunOperation,
    RunPhase,
    RunStatus,
)
from sgstudio.domain.planner import assert_plan_integrity
from sgstudio.storage.repository import StateRepository


class ResourceExecutor(Protocol):
    def apply(self, change: ResourceChange, spec: DeploymentSpec) -> None: ...

    def rollback(self, change: ResourceChange, spec: DeploymentSpec) -> None: ...


class ProviderExecutionError(RuntimeError):
    def __init__(self, error_code: str) -> None:
        super().__init__("Provider operation failed")
        self.error_code = error_code


class DeploymentExecutor:
    """Checkpointed sequential execution with ownership-bounded rollback."""

    def __init__(self, provider: ResourceExecutor, repository: StateRepository) -> None:
        self._provider = provider
        self._repository = repository

    def execute(
        self,
        approval: ApprovedPlan,
        spec: DeploymentSpec,
        *,
        actor: str,
        existing_run: DeploymentRun | None = None,
    ) -> DeploymentRun:
        if approval.consumed_at is None:
            raise ValueError("Approval must be atomically consumed before execution")
        assert_plan_integrity(
            approval.plan,
            approval.specification,
            stored_configuration_hash=approval.configuration_hash,
            stored_plan_hash=approval.plan_hash,
        )
        if approval.specification != spec:
            raise ValueError("Apply specification differs from the approved specification")
        if not approval.plan.can_apply:
            raise ValueError("Approved plan is not applyable")

        run = existing_run or self._repository.create_run(approval, actor=actor)
        if run.approval_id != approval.approval_id:
            raise ValueError("Existing run is not bound to the consumed approval")
        if run.configuration_hash != approval.configuration_hash:
            raise ValueError("Existing run configuration differs from the consumed approval")
        if run.public_certificate_binding != approval.plan.public_certificate_binding:
            raise ValueError(
                "Existing run public certificate binding differs from the consumed approval"
            )
        if run.source_image_binding != approval.plan.source_image_binding:
            raise ValueError(
                "Existing run source image binding differs from the consumed approval"
            )
        if run.status is RunStatus.INTERRUPTED:
            run = self._repository.resume_run(run.run_id)
        elif run.status is not RunStatus.RUNNING:
            raise ValueError("Existing run is not active or resumable")
        bind_run = getattr(self._provider, "bind_run", None)
        if callable(bind_run):
            bind_run(run.run_id)
        bind_plan = getattr(self._provider, "bind_plan", None)
        if callable(bind_plan):
            bind_plan(approval.plan)
        bind_ownership_metadata = getattr(self._provider, "bind_ownership_metadata", None)
        if callable(bind_ownership_metadata):
            bind_ownership_metadata(
                self._repository.active_owned_resource_metadata(run.run_id)
            )
        rollback_required = run.phase is RunPhase.ROLLING_BACK
        if run.phase is RunPhase.APPLYING:
            prepare_apply = getattr(self._provider, "prepare_apply", None)
            if callable(prepare_apply):
                try:
                    prepare_apply(spec)
                except ProviderExecutionError as error:
                    active_ownership = self._repository.active_owned_resource_keys(
                        run.run_id
                    )
                    current = self._repository.get_run(run.run_id)
                    has_applied_operation = current is not None and any(
                        operation.status is OperationStatus.SUCCEEDED
                        for operation in current.operations
                    )
                    if active_ownership or has_applied_operation:
                        self._repository.begin_run_rollback(run.run_id)
                        rollback_required = True
                    else:
                        self._repository.finish_run(
                            run.run_id,
                            status=RunStatus.FAILED,
                            actor=actor,
                        )
                        failed = self._repository.get_run(run.run_id)
                        if failed is None:
                            raise RuntimeError("Failed run disappeared") from error
                        return failed
            if rollback_required:
                self._repository.begin_run_rollback(run.run_id)
            else:
                for ordinal, change in enumerate(approval.plan.changes):
                    operation = self._repository.start_operation(
                        run.run_id,
                        change,
                        ordinal=ordinal,
                    )
                    if operation.status in {
                        OperationStatus.SUCCEEDED,
                        OperationStatus.SKIPPED,
                    }:
                        continue
                    if operation.status in {
                        OperationStatus.FAILED,
                        OperationStatus.ROLLED_BACK,
                    }:
                        # Covers a restart after the failure record committed but
                        # before the run phase transition committed in older data.
                        self._repository.begin_run_rollback(run.run_id)
                        rollback_required = True
                        break
                    if operation.status is not OperationStatus.RUNNING:
                        raise ValueError("Durable operation is not resumable")
                    if change.action in {ChangeAction.NO_CHANGE, ChangeAction.REUSE}:
                        self._repository.complete_operation(
                            operation.operation_id,
                            status=OperationStatus.SKIPPED,
                        )
                        continue
                    if change.action is ChangeAction.CONFLICT:
                        self._repository.fail_operation_and_begin_rollback(
                            operation.operation_id,
                            error_code="resource-conflict",
                        )
                        rollback_required = True
                        break

                    self._bind_provider_operation(change, spec, operation)
                    # Every approved CREATE is an external mutation, including
                    # shared IAM/Chrome RMW operations. Claim the exact intent
                    # before the provider may persist a `sending` checkpoint. This
                    # keeps response-loss/timeout states visible and compensatable
                    # across a process restart instead of silently finalizing an
                    # orphaned external mutation as rolled back.
                    preclaimed = change.action is ChangeAction.CREATE
                    active_ownership = self._repository.active_owned_resource_keys(
                        run.run_id
                    )
                    if preclaimed and operation.resource_key not in active_ownership:
                        preclaim_metadata = getattr(
                            self._provider, "preclaim_metadata", None
                        )
                        metadata = (
                            preclaim_metadata(change, spec)
                            if callable(preclaim_metadata)
                            else None
                        )
                        self._repository.claim_resource(
                            operation.resource_key,
                            run_id=run.run_id,
                            metadata=metadata,
                        )
                    try:
                        self._provider.apply(change, spec)
                    except ProviderExecutionError as error:
                        self._repository.fail_operation_and_begin_rollback(
                            operation.operation_id,
                            error_code=error.error_code,
                        )
                        rollback_required = True
                        break
                    else:
                        ownership_metadata = getattr(
                            self._provider, "ownership_metadata", None
                        )
                        metadata = (
                            ownership_metadata(change, spec)
                            if callable(ownership_metadata)
                            else None
                        )
                        self._repository.complete_operation_and_claim(
                            operation.operation_id,
                            run_id=run.run_id,
                            metadata=metadata,
                        )

        if not rollback_required:
            self._repository.finish_run(
                run.run_id,
                status=RunStatus.SUCCEEDED,
                actor=actor,
            )
            completed = self._repository.get_run(run.run_id)
            if completed is None:
                raise RuntimeError("Completed run disappeared")
            return completed

        self._repository.begin_run_rollback(run.run_id)
        current = self._repository.get_run(run.run_id)
        if current is None:
            raise RuntimeError("Rollback run disappeared")
        changes = {
            f"{change.provider}:{change.resource_type}:{change.resource_name}": change
            for change in approval.plan.changes
        }
        active_ownership = self._repository.active_owned_resource_keys(run.run_id)
        rollback_failed = False
        for operation in reversed(current.operations):
            change = changes.get(operation.resource_key)
            if change is None:
                rollback_failed = True
                continue
            should_compensate = operation.status is OperationStatus.SUCCEEDED or (
                operation.status is OperationStatus.FAILED
                and operation.resource_key in active_ownership
            )
            if operation.status is OperationStatus.ROLLED_BACK:
                # Repairs the legacy crash gap between ROLLED_BACK and release.
                self._repository.complete_rollback_and_release(
                    operation.operation_id,
                    run_id=run.run_id,
                )
                continue
            if not should_compensate:
                continue
            self._bind_provider_operation(change, spec, operation)
            try:
                self._provider.rollback(change, spec)
            except ProviderExecutionError:
                rollback_failed = True
                continue
            self._repository.complete_rollback_and_release(
                operation.operation_id,
                run_id=run.run_id,
            )

        final_status = RunStatus.ROLLBACK_FAILED if rollback_failed else RunStatus.ROLLED_BACK
        self._repository.finish_run(run.run_id, status=final_status, actor=actor)
        completed = self._repository.get_run(run.run_id)
        if completed is None:
            raise RuntimeError("Completed run disappeared")
        return completed

    def _bind_provider_operation(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
        operation: RunOperation,
    ) -> None:
        bind_operation = getattr(self._provider, "bind_operation", None)
        if not callable(bind_operation):
            return

        def checkpoint(value: dict[str, object]) -> None:
            self._repository.checkpoint_operation(operation.operation_id, value)

        bind_operation(change, spec, operation, checkpoint)
