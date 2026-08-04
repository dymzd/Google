from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sgstudio.domain.models import (
    ApprovedPlan,
    ChangeAction,
    DeploymentRun,
    DeploymentSpec,
    OperationStatus,
    ResourceChange,
    RunOperation,
    RunStatus,
)
from sgstudio.storage.repository import StateRepository


class ResourceExecutor(Protocol):
    def apply(self, change: ResourceChange, spec: DeploymentSpec) -> None: ...

    def rollback(self, change: ResourceChange, spec: DeploymentSpec) -> None: ...


class ProviderExecutionError(RuntimeError):
    def __init__(self, error_code: str) -> None:
        super().__init__("Provider operation failed")
        self.error_code = error_code


@dataclass(frozen=True)
class AppliedChange:
    change: ResourceChange
    operation: RunOperation


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
        if approval.configuration_hash != approval.plan.configuration_hash:
            raise ValueError("Approval plan hash binding is invalid")
        if approval.specification != spec:
            raise ValueError("Apply specification differs from the approved specification")
        if not approval.plan.can_apply:
            raise ValueError("Approved plan is not applyable")

        run = existing_run or self._repository.create_run(approval, actor=actor)
        if run.approval_id != approval.approval_id:
            raise ValueError("Existing run is not bound to the consumed approval")
        applied: list[AppliedChange] = []
        failure_status: RunStatus | None = None

        for change in approval.plan.changes:
            operation = self._repository.start_operation(run.run_id, change)
            if change.action in {ChangeAction.NO_CHANGE, ChangeAction.REUSE}:
                self._repository.complete_operation(
                    operation.operation_id,
                    status=OperationStatus.SKIPPED,
                )
                continue
            if change.action is ChangeAction.CONFLICT:
                self._repository.complete_operation(
                    operation.operation_id,
                    status=OperationStatus.FAILED,
                    error_code="resource-conflict",
                )
                failure_status = RunStatus.FAILED
                break

            try:
                self._provider.apply(change, spec)
            except ProviderExecutionError as error:
                self._repository.complete_operation(
                    operation.operation_id,
                    status=OperationStatus.FAILED,
                    error_code=error.error_code,
                )
                failure_status = RunStatus.FAILED
                break
            else:
                self._repository.complete_operation(
                    operation.operation_id,
                    status=OperationStatus.SUCCEEDED,
                )
                applied.append(AppliedChange(change=change, operation=operation))
                if change.owned_after_apply:
                    self._repository.claim_resource(
                        operation.resource_key,
                        run_id=run.run_id,
                    )

        if failure_status is None:
            self._repository.finish_run(
                run.run_id,
                status=RunStatus.SUCCEEDED,
                actor=actor,
            )
            completed = self._repository.get_run(run.run_id)
            if completed is None:
                raise RuntimeError("Completed run disappeared")
            return completed

        rollback_failed = False
        for applied_change in reversed(applied):
            try:
                self._provider.rollback(applied_change.change, spec)
            except ProviderExecutionError:
                rollback_failed = True
                continue
            self._repository.complete_operation(
                applied_change.operation.operation_id,
                status=OperationStatus.ROLLED_BACK,
            )
            if applied_change.change.owned_after_apply:
                self._repository.release_resource(
                    applied_change.operation.resource_key,
                    run_id=run.run_id,
                )

        final_status = RunStatus.ROLLBACK_FAILED if rollback_failed else RunStatus.ROLLED_BACK
        self._repository.finish_run(run.run_id, status=final_status, actor=actor)
        completed = self._repository.get_run(run.run_id)
        if completed is None:
            raise RuntimeError("Completed run disappeared")
        return completed
