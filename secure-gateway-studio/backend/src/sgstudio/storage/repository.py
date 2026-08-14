from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock

from sgstudio.domain.models import (
    AcceptanceReadiness,
    AcceptanceRequirement,
    AcceptanceResult,
    AcceptanceStatus,
    AcceptanceTestId,
    ApprovedPlan,
    AuditEvent,
    ChangeAction,
    DeploymentPlan,
    DeploymentRun,
    DeploymentSpec,
    EvidenceSource,
    OperationStatus,
    PreflightResult,
    PreparedPlan,
    ResourceChange,
    RunOperation,
    RunStatus,
    TeardownOperation,
    TeardownRun,
)


class StateRepository:
    """SQLite state store for non-secret deployment metadata and audit events."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self._lock = RLock()
        self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._migrate()
        self._recover_interrupted_runs()
        self.database_path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _migrate(self) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS deployment_drafts (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    schema_version INTEGER NOT NULL,
                    configuration_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    deployment_id TEXT,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_hash TEXT,
                    event_hash TEXT,
                    FOREIGN KEY(deployment_id) REFERENCES deployment_drafts(id)
                );

                CREATE TABLE IF NOT EXISTS approved_plans (
                    approval_id TEXT PRIMARY KEY,
                    configuration_hash TEXT NOT NULL,
                    plan_hash TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    specification_json TEXT,
                    approved_by TEXT NOT NULL,
                    approved_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS prepared_plans (
                    plan_id TEXT PRIMARY KEY,
                    configuration_hash TEXT NOT NULL,
                    specification_json TEXT NOT NULL,
                    preflight_json TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS deployment_runs (
                    run_id TEXT PRIMARY KEY,
                    approval_id TEXT NOT NULL,
                    configuration_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    FOREIGN KEY(approval_id) REFERENCES approved_plans(approval_id)
                );

                CREATE TABLE IF NOT EXISTS run_operations (
                    operation_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    resource_key TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    owned_after_apply INTEGER NOT NULL,
                    error_code TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    FOREIGN KEY(run_id) REFERENCES deployment_runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS resource_ownership (
                    resource_key TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    released_at TEXT,
                    FOREIGN KEY(run_id) REFERENCES deployment_runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS acceptance_results (
                    result_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    test_id TEXT NOT NULL,
                    case_key TEXT NOT NULL DEFAULT 'default',
                    status TEXT NOT NULL,
                    source TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    UNIQUE(run_id, test_id, case_key),
                    FOREIGN KEY(run_id) REFERENCES deployment_runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS teardown_runs (
                    teardown_id TEXT PRIMARY KEY,
                    source_run_id TEXT NOT NULL,
                    plan_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    FOREIGN KEY(source_run_id) REFERENCES deployment_runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS teardown_operations (
                    teardown_id TEXT NOT NULL,
                    resource_key TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    error_code TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    PRIMARY KEY(teardown_id, resource_key),
                    FOREIGN KEY(teardown_id) REFERENCES teardown_runs(teardown_id)
                );

                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (1, CURRENT_TIMESTAMP);

                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (2, CURRENT_TIMESTAMP);

                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (3, CURRENT_TIMESTAMP);

                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (4, CURRENT_TIMESTAMP);

                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (5, CURRENT_TIMESTAMP);

                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (7, CURRENT_TIMESTAMP);
                """
            )
            acceptance_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(acceptance_results)")
            }
            if "case_key" not in acceptance_columns:
                connection.executescript(
                    """
                    ALTER TABLE acceptance_results
                    RENAME TO acceptance_results_v5;

                    CREATE TABLE acceptance_results (
                        result_id TEXT PRIMARY KEY,
                        run_id TEXT NOT NULL,
                        test_id TEXT NOT NULL,
                        case_key TEXT NOT NULL DEFAULT 'default',
                        status TEXT NOT NULL,
                        source TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        evidence TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        recorded_at TEXT NOT NULL,
                        UNIQUE(run_id, test_id, case_key),
                        FOREIGN KEY(run_id) REFERENCES deployment_runs(run_id)
                    );

                    INSERT INTO acceptance_results(
                        result_id, run_id, test_id, case_key, status, source,
                        summary, evidence, actor, recorded_at
                    )
                    SELECT result_id, run_id, test_id, 'default', status, source,
                           summary, evidence, actor, recorded_at
                    FROM acceptance_results_v5;

                    DROP TABLE acceptance_results_v5;
                    """
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (6, CURRENT_TIMESTAMP)
                """
            )
            approved_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(approved_plans)")
            }
            if "specification_json" not in approved_columns:
                connection.execute("ALTER TABLE approved_plans ADD COLUMN specification_json TEXT")
            audit_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(audit_events)")
            }
            if "previous_hash" not in audit_columns:
                connection.execute("ALTER TABLE audit_events ADD COLUMN previous_hash TEXT")
            if "event_hash" not in audit_columns:
                connection.execute("ALTER TABLE audit_events ADD COLUMN event_hash TEXT")
            self._backfill_audit_chain(connection)
            connection.commit()

    def _recover_interrupted_runs(self) -> None:
        """Fail closed when the process stopped during a provider mutation."""
        now = datetime.now(UTC).isoformat()
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT run_id
                FROM deployment_runs
                WHERE status IN (?, ?)
                """,
                (RunStatus.PENDING.value, RunStatus.RUNNING.value),
            ).fetchall()
            for row in rows:
                run_id = row["run_id"]
                interrupted_operations = connection.execute(
                    """
                    UPDATE run_operations
                    SET status = ?, error_code = ?, completed_at = ?
                    WHERE run_id = ? AND status IN (?, ?)
                    """,
                    (
                        OperationStatus.INTERRUPTED.value,
                        "process-restarted",
                        now,
                        run_id,
                        OperationStatus.PENDING.value,
                        OperationStatus.RUNNING.value,
                    ),
                ).rowcount
                connection.execute(
                    """
                    UPDATE deployment_runs
                    SET status = ?, completed_at = ?
                    WHERE run_id = ?
                    """,
                    (RunStatus.INTERRUPTED.value, now, run_id),
                )
                self._insert_audit_event(
                    connection,
                    event_type="run.interrupted",
                    actor="system",
                    payload={
                        "run_id": run_id,
                        "status": RunStatus.INTERRUPTED.value,
                        "interrupted_operations": interrupted_operations,
                        "reason": "process-restarted",
                    },
                )
            teardown_rows = connection.execute(
                """
                SELECT teardown_id FROM teardown_runs
                WHERE status IN ('pending', 'running')
                """
            ).fetchall()
            for row in teardown_rows:
                teardown_id = row["teardown_id"]
                connection.execute(
                    """
                    UPDATE teardown_operations
                    SET status = 'failed', error_code = 'process-restarted',
                        completed_at = ?
                    WHERE teardown_id = ? AND status IN ('pending', 'running')
                    """,
                    (now, teardown_id),
                )
                connection.execute(
                    """
                    UPDATE teardown_runs
                    SET status = 'interrupted', completed_at = ?
                    WHERE teardown_id = ?
                    """,
                    (now, teardown_id),
                )
                self._insert_audit_event(
                    connection,
                    event_type="teardown.interrupted",
                    actor="system",
                    payload={"teardown_id": teardown_id, "reason": "process-restarted"},
                )
            connection.commit()

    def save_draft(
        self,
        spec: DeploymentSpec,
        deployment_id: str | None = None,
        actor: str = "local-operator",
    ) -> str:
        deployment_id = deployment_id or str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        payload = spec.model_dump(mode="json")
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        with self._lock, closing(self._connect()) as connection:
            configuration_hash = hashlib.sha256(serialized.encode()).hexdigest()
            connection.execute(
                """
                INSERT INTO deployment_drafts(
                    id, name, schema_version, configuration_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    schema_version = excluded.schema_version,
                    configuration_json = excluded.configuration_json,
                    updated_at = excluded.updated_at
                """,
                (deployment_id, spec.name, spec.schema_version, serialized, now, now),
            )
            self._insert_audit_event(
                connection,
                deployment_id=deployment_id,
                event_type="draft.saved",
                actor=actor,
                payload={"configuration_hash": configuration_hash},
            )
            connection.commit()
        return deployment_id

    def get_draft(self, deployment_id: str) -> DeploymentSpec | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT configuration_json FROM deployment_drafts WHERE id = ?",
                (deployment_id,),
            ).fetchone()

        if row is None:
            return None
        return DeploymentSpec.model_validate_json(row["configuration_json"])

    def store_prepared_plan(
        self,
        specification: DeploymentSpec,
        preflight: PreflightResult,
        plan: DeploymentPlan,
        *,
        ttl_minutes: int = 30,
    ) -> PreparedPlan:
        if not 1 <= ttl_minutes <= 120:
            raise ValueError("Plan TTL must be between 1 and 120 minutes")
        now = datetime.now(UTC)
        artifact = PreparedPlan(
            plan_id=str(uuid.uuid4()),
            specification=specification,
            preflight=preflight,
            plan=plan,
            created_at=now,
            expires_at=now + timedelta(minutes=ttl_minutes),
        )
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO prepared_plans(
                    plan_id, configuration_hash, specification_json,
                    preflight_json, plan_json, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.plan_id,
                    plan.configuration_hash,
                    specification.model_dump_json(),
                    preflight.model_dump_json(),
                    plan.model_dump_json(),
                    artifact.created_at.isoformat(),
                    artifact.expires_at.isoformat(),
                ),
            )
            self._insert_audit_event(
                connection,
                event_type="plan.prepared",
                actor=preflight.snapshot.cloud_identity or "system:unidentified-adc",
                payload={
                    "plan_id": artifact.plan_id,
                    "configuration_hash": plan.configuration_hash,
                    "expires_at": artifact.expires_at.isoformat(),
                },
            )
            connection.commit()
        return artifact

    def get_prepared_plan(self, plan_id: str) -> PreparedPlan | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT plan_id, specification_json, preflight_json, plan_json,
                       created_at, expires_at
                FROM prepared_plans WHERE plan_id = ?
                """,
                (plan_id,),
            ).fetchone()
        if row is None:
            return None
        return PreparedPlan(
            plan_id=row["plan_id"],
            specification=DeploymentSpec.model_validate_json(row["specification_json"]),
            preflight=PreflightResult.model_validate_json(row["preflight_json"]),
            plan=DeploymentPlan.model_validate_json(row["plan_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
        )

    def approve_prepared_plan(
        self,
        plan_id: str,
        *,
        ttl_minutes: int = 30,
    ) -> ApprovedPlan:
        artifact = self.get_prepared_plan(plan_id)
        if artifact is None:
            raise ValueError("Prepared plan was not found")
        if artifact.expires_at <= datetime.now(UTC):
            raise ValueError("Prepared plan has expired; run preflight again")
        approved_by = artifact.preflight.snapshot.cloud_identity
        if not approved_by:
            raise ValueError(
                "Prepared plan has no server-attested Google Cloud identity; "
                "run preflight with authenticated ADC"
            )
        return self.approve_plan(
            artifact.plan,
            specification=artifact.specification,
            approved_by=approved_by,
            ttl_minutes=ttl_minutes,
        )

    def approve_plan(
        self,
        plan: DeploymentPlan,
        *,
        specification: DeploymentSpec,
        approved_by: str,
        ttl_minutes: int = 30,
    ) -> ApprovedPlan:
        if not approved_by.strip():
            raise ValueError("approved_by is required")
        if not 1 <= ttl_minutes <= 120:
            raise ValueError("Approval TTL must be between 1 and 120 minutes")

        approved_plan = plan.model_copy(deep=True)
        for gate in approved_plan.gates:
            if gate.gate_id == "human-approval":
                gate.status = "pass"
                gate.detail = f"Approved by {approved_by.strip()}."
        approved_plan.can_apply = all(
            gate.status == "pass" for gate in approved_plan.gates if gate.blocking
        )
        if not approved_plan.can_apply:
            raise ValueError("Blocking deployment gates must pass before approval")

        serialized_plan = json.dumps(
            approved_plan.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        now = datetime.now(UTC)
        approval = ApprovedPlan(
            approval_id=str(uuid.uuid4()),
            configuration_hash=approved_plan.configuration_hash,
            plan_hash=hashlib.sha256(serialized_plan.encode()).hexdigest(),
            plan=approved_plan,
            specification=specification,
            approved_by=approved_by.strip(),
            approved_at=now,
            expires_at=now + timedelta(minutes=ttl_minutes),
        )
        serialized_approval_plan = approval.plan.model_dump_json()

        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO approved_plans(
                    approval_id, configuration_hash, plan_hash, plan_json,
                    specification_json, approved_by, approved_at, expires_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    approval.approval_id,
                    approval.configuration_hash,
                    approval.plan_hash,
                    serialized_approval_plan,
                    approval.specification.model_dump_json(),
                    approval.approved_by,
                    approval.approved_at.isoformat(),
                    approval.expires_at.isoformat(),
                ),
            )
            self._insert_audit_event(
                connection,
                event_type="plan.approved",
                actor=approval.approved_by,
                payload={
                    "approval_id": approval.approval_id,
                    "configuration_hash": approval.configuration_hash,
                    "plan_hash": approval.plan_hash,
                    "expires_at": approval.expires_at.isoformat(),
                },
            )
            connection.commit()
        return approval

    def get_approval(self, approval_id: str) -> ApprovedPlan | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT approval_id, configuration_hash, plan_hash, plan_json,
                       specification_json, approved_by, approved_at, expires_at,
                       consumed_at
                FROM approved_plans
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()
        if row is None:
            return None
        return self._approval_from_row(row)

    @staticmethod
    def _approval_from_row(row: sqlite3.Row) -> ApprovedPlan:
        if not row["specification_json"]:
            raise RuntimeError("Legacy approval lacks an approved specification")
        return ApprovedPlan(
            approval_id=row["approval_id"],
            configuration_hash=row["configuration_hash"],
            plan_hash=row["plan_hash"],
            plan=DeploymentPlan.model_validate_json(row["plan_json"]),
            specification=DeploymentSpec.model_validate_json(row["specification_json"]),
            approved_by=row["approved_by"],
            approved_at=datetime.fromisoformat(row["approved_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            consumed_at=(
                datetime.fromisoformat(row["consumed_at"]) if row["consumed_at"] else None
            ),
        )

    def consume_approval(
        self,
        approval_id: str,
        *,
        actor: str,
        configuration_hash: str | None = None,
    ) -> ApprovedPlan:
        now = datetime.now(UTC)
        with self._lock, closing(self._connect()) as connection:
            if configuration_hash is None:
                cursor = connection.execute(
                    """
                    UPDATE approved_plans
                    SET consumed_at = ?
                    WHERE approval_id = ?
                      AND consumed_at IS NULL
                      AND expires_at > ?
                    """,
                    (now.isoformat(), approval_id, now.isoformat()),
                )
            else:
                cursor = connection.execute(
                    """
                    UPDATE approved_plans
                    SET consumed_at = ?
                    WHERE approval_id = ?
                      AND configuration_hash = ?
                      AND consumed_at IS NULL
                      AND expires_at > ?
                    """,
                    (
                        now.isoformat(),
                        approval_id,
                        configuration_hash,
                        now.isoformat(),
                    ),
                )
            if cursor.rowcount != 1:
                connection.rollback()
                raise ValueError("Approval is invalid, expired, consumed, or configuration changed")
            self._insert_audit_event(
                connection,
                event_type="plan.consumed",
                actor=actor,
                payload={
                    "approval_id": approval_id,
                    "configuration_hash": configuration_hash or "server-bound",
                },
            )
            connection.commit()

        approval = self.get_approval(approval_id)
        if approval is None:
            raise RuntimeError("Consumed approval disappeared")
        return approval

    def consume_approval_and_create_run(
        self,
        approval_id: str,
    ) -> tuple[ApprovedPlan, DeploymentRun]:
        """Atomically consume one approval and acquire the single Apply slot."""
        now = datetime.now(UTC)
        run_id = str(uuid.uuid4())
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                """
                SELECT run_id
                FROM deployment_runs
                WHERE status IN (?, ?)
                LIMIT 1
                """,
                (RunStatus.PENDING.value, RunStatus.RUNNING.value),
            ).fetchone()
            if active is not None:
                connection.rollback()
                raise ValueError(f"Another deployment run is active: {active['run_id']}")
            cursor = connection.execute(
                """
                UPDATE approved_plans
                SET consumed_at = ?
                WHERE approval_id = ?
                  AND consumed_at IS NULL
                  AND expires_at > ?
                """,
                (now.isoformat(), approval_id, now.isoformat()),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise ValueError("Approval is invalid, expired, consumed, or configuration changed")
            row = connection.execute(
                """
                SELECT approval_id, configuration_hash, plan_hash, plan_json,
                       specification_json, approved_by, approved_at, expires_at,
                       consumed_at
                FROM approved_plans
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise RuntimeError("Consumed approval disappeared")
            approval = self._approval_from_row(row)
            actor = approval.approved_by
            run = DeploymentRun(
                run_id=run_id,
                approval_id=approval.approval_id,
                configuration_hash=approval.configuration_hash,
                status=RunStatus.RUNNING,
                started_at=now,
            )
            connection.execute(
                """
                INSERT INTO deployment_runs(
                    run_id, approval_id, configuration_hash, status, started_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.approval_id,
                    run.configuration_hash,
                    run.status.value,
                    run.started_at.isoformat(),
                ),
            )
            self._insert_audit_event(
                connection,
                event_type="plan.consumed",
                actor=actor,
                payload={
                    "approval_id": approval.approval_id,
                    "configuration_hash": approval.configuration_hash,
                },
            )
            self._insert_audit_event(
                connection,
                event_type="run.started",
                actor=actor,
                payload={
                    "run_id": run.run_id,
                    "approval_id": run.approval_id,
                    "configuration_hash": run.configuration_hash,
                },
            )
            connection.commit()
        return approval, run

    def list_audit_events(self, *, limit: int = 100) -> list[AuditEvent]:
        safe_limit = max(1, min(limit, 500))
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT id, deployment_id, event_type, actor, payload_json, created_at
                       , previous_hash, event_hash
                FROM audit_events
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        return [
            AuditEvent(
                event_id=row["id"],
                deployment_id=row["deployment_id"],
                event_type=row["event_type"],
                actor=row["actor"],
                payload=json.loads(row["payload_json"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                previous_hash=row["previous_hash"],
                event_hash=row["event_hash"],
            )
            for row in rows
        ]

    def create_run(self, approval: ApprovedPlan, *, actor: str) -> DeploymentRun:
        now = datetime.now(UTC)
        run = DeploymentRun(
            run_id=str(uuid.uuid4()),
            approval_id=approval.approval_id,
            configuration_hash=approval.configuration_hash,
            status=RunStatus.RUNNING,
            started_at=now,
        )
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                """
                SELECT run_id
                FROM deployment_runs
                WHERE status IN (?, ?)
                LIMIT 1
                """,
                (RunStatus.PENDING.value, RunStatus.RUNNING.value),
            ).fetchone()
            if active is not None:
                connection.rollback()
                raise ValueError(f"Another deployment run is active: {active['run_id']}")
            connection.execute(
                """
                INSERT INTO deployment_runs(
                    run_id, approval_id, configuration_hash, status, started_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.approval_id,
                    run.configuration_hash,
                    run.status.value,
                    run.started_at.isoformat(),
                ),
            )
            self._insert_audit_event(
                connection,
                event_type="run.started",
                actor=actor,
                payload={
                    "run_id": run.run_id,
                    "approval_id": run.approval_id,
                    "configuration_hash": run.configuration_hash,
                },
            )
            connection.commit()
        return run

    def start_operation(self, run_id: str, change: ResourceChange) -> RunOperation:
        operation = RunOperation(
            operation_id=str(uuid.uuid4()),
            resource_key=(f"{change.provider}:{change.resource_type}:{change.resource_name}"),
            action=change.action,
            status=OperationStatus.RUNNING,
            owned_after_apply=change.owned_after_apply,
            started_at=datetime.now(UTC),
        )
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO run_operations(
                    operation_id, run_id, resource_key, action, status,
                    owned_after_apply, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation.operation_id,
                    run_id,
                    operation.resource_key,
                    operation.action.value,
                    operation.status.value,
                    int(operation.owned_after_apply),
                    operation.started_at.isoformat(),
                ),
            )
            self._insert_audit_event(
                connection,
                event_type="operation.started",
                actor="system",
                payload={
                    "run_id": run_id,
                    "operation_id": operation.operation_id,
                    "resource_key": operation.resource_key,
                    "action": operation.action.value,
                    "owned_after_apply": operation.owned_after_apply,
                },
            )
            connection.commit()
        return operation

    def complete_operation(
        self,
        operation_id: str,
        *,
        status: OperationStatus,
        error_code: str | None = None,
    ) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                UPDATE run_operations
                SET status = ?, error_code = ?, completed_at = ?
                WHERE operation_id = ?
                """,
                (status.value, error_code, datetime.now(UTC).isoformat(), operation_id),
            )
            operation = connection.execute(
                "SELECT run_id, resource_key FROM run_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            self._insert_audit_event(
                connection,
                event_type="operation.completed",
                actor="system",
                payload={
                    "run_id": operation["run_id"] if operation else "unknown",
                    "operation_id": operation_id,
                    "resource_key": (operation["resource_key"] if operation else "unknown"),
                    "status": status.value,
                    "error_code": error_code,
                },
            )
            connection.commit()

    def claim_resource(self, resource_key: str, *, run_id: str) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO resource_ownership(resource_key, run_id, acquired_at, released_at)
                VALUES (?, ?, ?, NULL)
                ON CONFLICT(resource_key) DO UPDATE SET
                    run_id = excluded.run_id,
                    acquired_at = excluded.acquired_at,
                    released_at = NULL
                """,
                (resource_key, run_id, datetime.now(UTC).isoformat()),
            )
            connection.commit()

    def release_resource(self, resource_key: str, *, run_id: str) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                UPDATE resource_ownership
                SET released_at = ?
                WHERE resource_key = ? AND run_id = ? AND released_at IS NULL
                """,
                (datetime.now(UTC).isoformat(), resource_key, run_id),
            )
            connection.commit()

    def finish_run(self, run_id: str, *, status: RunStatus, actor: str) -> None:
        now = datetime.now(UTC)
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                UPDATE deployment_runs
                SET status = ?, completed_at = ?
                WHERE run_id = ?
                """,
                (status.value, now.isoformat(), run_id),
            )
            self._insert_audit_event(
                connection,
                event_type=f"run.{status.value}",
                actor=actor,
                payload={"run_id": run_id, "status": status.value},
            )
            connection.commit()

    def get_run(self, run_id: str) -> DeploymentRun | None:
        with self._lock, closing(self._connect()) as connection:
            run_row = connection.execute(
                """
                SELECT run_id, approval_id, configuration_hash, status,
                       started_at, completed_at
                FROM deployment_runs
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if run_row is None:
                return None
            operation_rows = connection.execute(
                """
                SELECT operation_id, resource_key, action, status, owned_after_apply,
                       error_code, started_at, completed_at
                FROM run_operations
                WHERE run_id = ?
                ORDER BY started_at
                """,
                (run_id,),
            ).fetchall()
        operations = [
            RunOperation(
                operation_id=row["operation_id"],
                resource_key=row["resource_key"],
                action=ChangeAction(row["action"]),
                status=OperationStatus(row["status"]),
                owned_after_apply=bool(row["owned_after_apply"]),
                error_code=row["error_code"],
                started_at=datetime.fromisoformat(row["started_at"]),
                completed_at=(
                    datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
                ),
            )
            for row in operation_rows
        ]
        return DeploymentRun(
            run_id=run_row["run_id"],
            approval_id=run_row["approval_id"],
            configuration_hash=run_row["configuration_hash"],
            status=RunStatus(run_row["status"]),
            started_at=datetime.fromisoformat(run_row["started_at"]),
            completed_at=(
                datetime.fromisoformat(run_row["completed_at"]) if run_row["completed_at"] else None
            ),
            operations=operations,
        )

    def list_runs(self, *, limit: int = 100) -> list[DeploymentRun]:
        safe_limit = max(1, min(limit, 500))
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT run_id
                FROM deployment_runs
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        runs = [self.get_run(row["run_id"]) for row in rows]
        return [run for run in runs if run is not None]

    def active_owned_resource_keys(self, run_id: str) -> set[str]:
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT resource_key FROM resource_ownership
                WHERE run_id = ? AND released_at IS NULL
                """,
                (run_id,),
            ).fetchall()
        return {row["resource_key"] for row in rows}

    def run_ids_with_active_ownership(self) -> list[str]:
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT run_id, MAX(acquired_at) AS latest_acquisition
                FROM resource_ownership
                WHERE released_at IS NULL
                GROUP BY run_id
                ORDER BY latest_acquisition DESC
                """
            ).fetchall()
        return [row["run_id"] for row in rows]

    def create_teardown_run(
        self,
        *,
        source_run_id: str,
        plan_hash: str,
        resource_keys: list[str],
        actor: str,
    ) -> TeardownRun:
        now = datetime.now(UTC)
        teardown_id = str(uuid.uuid4())
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            source = connection.execute(
                "SELECT status FROM deployment_runs WHERE run_id = ?",
                (source_run_id,),
            ).fetchone()
            if source is None:
                connection.rollback()
                raise ValueError("Deployment run was not found")
            if source["status"] != RunStatus.SUCCEEDED.value:
                connection.rollback()
                raise ValueError("Only a successful deployment can be torn down")
            active = connection.execute(
                """
                SELECT teardown_id FROM teardown_runs
                WHERE status IN ('pending', 'running') LIMIT 1
                """
            ).fetchone()
            if active is not None:
                connection.rollback()
                raise ValueError(f"Another teardown is active: {active['teardown_id']}")
            previous = connection.execute(
                """
                SELECT teardown_id FROM teardown_runs
                WHERE source_run_id = ? AND status = 'succeeded' LIMIT 1
                """,
                (source_run_id,),
            ).fetchone()
            if previous is not None:
                connection.rollback()
                raise ValueError("This deployment has already been torn down")
            connection.execute(
                """
                INSERT INTO teardown_runs(
                    teardown_id, source_run_id, plan_hash, status, started_at
                ) VALUES (?, ?, ?, 'pending', ?)
                """,
                (teardown_id, source_run_id, plan_hash, now.isoformat()),
            )
            connection.executemany(
                """
                INSERT INTO teardown_operations(
                    teardown_id, resource_key, ordinal, status
                ) VALUES (?, ?, ?, 'pending')
                """,
                [
                    (teardown_id, resource_key, ordinal)
                    for ordinal, resource_key in enumerate(resource_keys)
                ],
            )
            self._insert_audit_event(
                connection,
                event_type="teardown.started",
                actor=actor,
                payload={
                    "teardown_id": teardown_id,
                    "source_run_id": source_run_id,
                    "plan_hash": plan_hash,
                    "resource_count": len(resource_keys),
                },
            )
            connection.commit()
        created = self.get_teardown_run(teardown_id)
        if created is None:
            raise RuntimeError("Created teardown run disappeared")
        return created

    def get_teardown_run(self, teardown_id: str) -> TeardownRun | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT teardown_id, source_run_id, plan_hash, status,
                       started_at, completed_at
                FROM teardown_runs WHERE teardown_id = ?
                """,
                (teardown_id,),
            ).fetchone()
            if row is None:
                return None
            operation_rows = connection.execute(
                """
                SELECT resource_key, status, error_code, started_at, completed_at
                FROM teardown_operations
                WHERE teardown_id = ? ORDER BY ordinal
                """,
                (teardown_id,),
            ).fetchall()
        return TeardownRun(
            teardown_id=row["teardown_id"],
            source_run_id=row["source_run_id"],
            plan_hash=row["plan_hash"],
            status=row["status"],
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=(
                datetime.fromisoformat(row["completed_at"])
                if row["completed_at"]
                else None
            ),
            operations=[
                TeardownOperation(
                    resource_key=operation["resource_key"],
                    status=operation["status"],
                    error_code=operation["error_code"],
                    started_at=(
                        datetime.fromisoformat(operation["started_at"])
                        if operation["started_at"]
                        else None
                    ),
                    completed_at=(
                        datetime.fromisoformat(operation["completed_at"])
                        if operation["completed_at"]
                        else None
                    ),
                )
                for operation in operation_rows
            ],
        )

    def start_teardown_operation(self, teardown_id: str, resource_key: str) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                "UPDATE teardown_runs SET status = 'running' WHERE teardown_id = ?",
                (teardown_id,),
            )
            connection.execute(
                """
                UPDATE teardown_operations SET status = 'running', started_at = ?
                WHERE teardown_id = ? AND resource_key = ?
                """,
                (now, teardown_id, resource_key),
            )
            connection.commit()

    def finish_teardown_operation(
        self,
        teardown_id: str,
        resource_key: str,
        *,
        status: str,
        error_code: str | None = None,
    ) -> None:
        if status not in {"succeeded", "failed", "skipped"}:
            raise ValueError("Invalid teardown operation status")
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                UPDATE teardown_operations
                SET status = ?, error_code = ?, completed_at = ?
                WHERE teardown_id = ? AND resource_key = ?
                """,
                (
                    status,
                    error_code,
                    datetime.now(UTC).isoformat(),
                    teardown_id,
                    resource_key,
                ),
            )
            connection.commit()

    def finish_teardown_run(
        self, teardown_id: str, *, status: str, actor: str
    ) -> TeardownRun:
        if status not in {"succeeded", "failed"}:
            raise ValueError("Invalid teardown status")
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT source_run_id FROM teardown_runs WHERE teardown_id = ?",
                (teardown_id,),
            ).fetchone()
            if row is None:
                raise ValueError("Teardown run was not found")
            connection.execute(
                """
                UPDATE teardown_runs SET status = ?, completed_at = ?
                WHERE teardown_id = ?
                """,
                (status, datetime.now(UTC).isoformat(), teardown_id),
            )
            self._insert_audit_event(
                connection,
                event_type=f"teardown.{status}",
                actor=actor,
                payload={
                    "teardown_id": teardown_id,
                    "source_run_id": row["source_run_id"],
                },
            )
            connection.commit()
        finished = self.get_teardown_run(teardown_id)
        if finished is None:
            raise RuntimeError("Finished teardown run disappeared")
        return finished

    def record_audit_event(
        self, *, event_type: str, actor: str, payload: dict[str, object]
    ) -> None:
        with self._lock, closing(self._connect()) as connection:
            self._insert_audit_event(
                connection,
                event_type=event_type,
                actor=actor,
                payload=payload,
            )
            connection.commit()

    def record_acceptance_result(
        self,
        *,
        run_id: str,
        test_id: AcceptanceTestId,
        case_key: str = "default",
        status: AcceptanceStatus,
        source: EvidenceSource,
        summary: str,
        evidence: str,
        actor: str,
    ) -> AcceptanceResult:
        result = AcceptanceResult(
            result_id=str(uuid.uuid4()),
            run_id=run_id,
            test_id=test_id,
            case_key=case_key,
            status=status,
            source=source,
            summary=summary,
            evidence=evidence,
            actor=actor,
            recorded_at=datetime.now(UTC),
        )
        with self._lock, closing(self._connect()) as connection:
            run = connection.execute(
                "SELECT status FROM deployment_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise ValueError("Deployment run was not found")
            if run["status"] != RunStatus.SUCCEEDED.value:
                raise ValueError("Acceptance evidence requires a succeeded deployment run")
            connection.execute(
                """
                INSERT INTO acceptance_results(
                    result_id, run_id, test_id, case_key, status, source, summary,
                    evidence, actor, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, test_id, case_key) DO UPDATE SET
                    result_id = excluded.result_id,
                    status = excluded.status,
                    source = excluded.source,
                    summary = excluded.summary,
                    evidence = excluded.evidence,
                    actor = excluded.actor,
                    recorded_at = excluded.recorded_at
                """,
                (
                    result.result_id,
                    result.run_id,
                    result.test_id.value,
                    result.case_key,
                    result.status.value,
                    result.source.value,
                    result.summary,
                    result.evidence,
                    result.actor,
                    result.recorded_at.isoformat(),
                ),
            )
            self._insert_audit_event(
                connection,
                event_type="acceptance.recorded",
                actor=actor,
                payload={
                    "run_id": run_id,
                    "test_id": result.test_id.value,
                    "case_key": result.case_key,
                    "status": result.status.value,
                    "source": result.source.value,
                    "evidence_sha256": hashlib.sha256(result.evidence.encode()).hexdigest(),
                },
            )
            connection.commit()
        return result

    def list_acceptance_results(
        self,
        *,
        run_id: str | None = None,
        limit: int = 500,
    ) -> list[AcceptanceResult]:
        safe_limit = max(1, min(limit, 1000))
        query = """
            SELECT result_id, run_id, test_id, case_key, status, source, summary,
                   evidence, actor, recorded_at
            FROM acceptance_results
        """
        parameters: tuple[str | int, ...]
        if run_id is not None:
            query += " WHERE run_id = ?"
            parameters = (run_id, safe_limit)
        else:
            parameters = (safe_limit,)
        query += " ORDER BY recorded_at DESC LIMIT ?"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [
            AcceptanceResult(
                result_id=row["result_id"],
                run_id=row["run_id"],
                test_id=AcceptanceTestId(row["test_id"]),
                case_key=row["case_key"],
                status=AcceptanceStatus(row["status"]),
                source=EvidenceSource(row["source"]),
                summary=row["summary"],
                evidence=row["evidence"],
                actor=row["actor"],
                recorded_at=datetime.fromisoformat(row["recorded_at"]),
            )
            for row in rows
        ]

    def acceptance_readiness(self, run_id: str) -> AcceptanceReadiness:
        run = self.get_run(run_id)
        if run is None:
            raise ValueError("Deployment run was not found")
        approval = self.get_approval(run.approval_id)
        if approval is None:
            raise ValueError("Deployment approval was not found")
        results = self.list_acceptance_results(run_id=run_id)
        required_cases = self._acceptance_requirements(approval.specification)
        by_case = {(result.test_id, result.case_key): result for result in results}
        satisfied_cases: list[AcceptanceRequirement] = []
        for requirement in required_cases:
            result = by_case.get((requirement.test_id, requirement.case_key))
            if result is None:
                continue
            if not requirement.operator_confirmable:
                if (
                    result.status is AcceptanceStatus.PASSED
                    and result.source is EvidenceSource.SYSTEM
                ):
                    satisfied_cases.append(requirement)
            elif result.status in {
                AcceptanceStatus.PASSED,
                AcceptanceStatus.USER_CONFIRMED,
            }:
                satisfied_cases.append(requirement)
            elif (
                approval.specification.mode.value == "poc"
                and requirement.test_id is AcceptanceTestId.T06
                and result.status is AcceptanceStatus.SKIPPED
                and result.source is EvidenceSource.OPERATOR
            ):
                # T06 is a regression control against an already-existing,
                # known-good Secure Gateway application. A greenfield PoC may
                # not have that control application. Preserve the observation
                # in the audit trail without blocking PoC acceptance; a
                # Production run still requires a real pass/confirmation.
                satisfied_cases.append(requirement)
        satisfied_keys = {
            (requirement.test_id, requirement.case_key) for requirement in satisfied_cases
        }
        missing_cases = [
            requirement
            for requirement in required_cases
            if (requirement.test_id, requirement.case_key) not in satisfied_keys
        ]
        required_tests = list(dict.fromkeys(requirement.test_id for requirement in required_cases))
        operator_cases = [
            requirement for requirement in required_cases if requirement.operator_confirmable
        ]
        operator_tests = list(dict.fromkeys(requirement.test_id for requirement in operator_cases))
        missing_test_set = {requirement.test_id for requirement in missing_cases}
        missing_tests = [test_id for test_id in required_tests if test_id in missing_test_set]
        satisfied_tests = [test_id for test_id in required_tests if test_id not in missing_test_set]
        complete = run.status is RunStatus.SUCCEEDED and not missing_cases
        integrity_valid, _ = self.verify_audit_chain()
        return AcceptanceReadiness(
            run_id=run_id,
            mode=approval.specification.mode,
            acceptance_complete=complete,
            production_ready=(
                complete and approval.specification.mode.value == "production" and integrity_valid
            ),
            required_tests=required_tests,
            operator_confirmable_tests=operator_tests,
            satisfied_tests=satisfied_tests,
            missing_tests=missing_tests,
            required_cases=required_cases,
            operator_confirmable_cases=operator_cases,
            satisfied_cases=satisfied_cases,
            missing_cases=missing_cases,
            results=results,
        )

    @staticmethod
    def _acceptance_requirements(
        specification: DeploymentSpec,
    ) -> list[AcceptanceRequirement]:
        if specification.backend_kind.value == "direct_https":
            requirements = [
                AcceptanceRequirement(
                    test_id=AcceptanceTestId.T05,
                    case_key="default",
                    operator_confirmable=False,
                ),
                AcceptanceRequirement(
                    test_id=AcceptanceTestId.T06,
                    case_key="default",
                    operator_confirmable=True,
                ),
            ]
            platform_order = ("macos", "windows", "linux", "chromeos")
            selected_platforms = {
                platform.value for platform in specification.platforms
            }
            requirements.extend(
                AcceptanceRequirement(
                    test_id=AcceptanceTestId.T07,
                    case_key=platform,
                    operator_confirmable=True,
                )
                for platform in platform_order
                if platform in selected_platforms
            )
            if specification.mode.value == "production":
                requirements.extend(
                    [
                        AcceptanceRequirement(
                            test_id=AcceptanceTestId.T08,
                            case_key="default",
                            operator_confirmable=True,
                        ),
                        AcceptanceRequirement(
                            test_id=AcceptanceTestId.T09,
                            case_key="unauthorized-principal",
                            operator_confirmable=True,
                        ),
                        AcceptanceRequirement(
                            test_id=AcceptanceTestId.T09,
                            case_key="unmanaged-browser",
                            operator_confirmable=True,
                        ),
                    ]
                )
            return requirements
        if specification.backend_kind.value == "internal_https_lb":
            requirements = [
                AcceptanceRequirement(
                    test_id=AcceptanceTestId.T01,
                    case_key="default",
                    operator_confirmable=False,
                ),
                AcceptanceRequirement(
                    test_id=AcceptanceTestId.T03,
                    case_key="default",
                    operator_confirmable=True,
                ),
                AcceptanceRequirement(
                    test_id=AcceptanceTestId.T04,
                    case_key="default",
                    operator_confirmable=False,
                ),
                AcceptanceRequirement(
                    test_id=AcceptanceTestId.T05,
                    case_key="default",
                    operator_confirmable=False,
                ),
                AcceptanceRequirement(
                    test_id=AcceptanceTestId.T06,
                    case_key="default",
                    operator_confirmable=True,
                ),
            ]
            platform_order = ("macos", "windows", "linux", "chromeos")
            selected_platforms = {
                platform.value for platform in specification.platforms
            }
            requirements.extend(
                AcceptanceRequirement(
                    test_id=AcceptanceTestId.T07,
                    case_key=platform,
                    operator_confirmable=True,
                )
                for platform in platform_order
                if platform in selected_platforms
            )
            if specification.mode.value == "production":
                requirements.extend(
                    [
                        AcceptanceRequirement(
                            test_id=AcceptanceTestId.T08,
                            case_key="default",
                            operator_confirmable=True,
                        ),
                        AcceptanceRequirement(
                            test_id=AcceptanceTestId.T09,
                            case_key="unauthorized-principal",
                            operator_confirmable=True,
                        ),
                        AcceptanceRequirement(
                            test_id=AcceptanceTestId.T09,
                            case_key="unmanaged-browser",
                            operator_confirmable=True,
                        ),
                    ]
                )
            return requirements
        existing_backend = specification.backend_kind.value == "existing_http"
        requirements = [
            AcceptanceRequirement(
                test_id=AcceptanceTestId.T01,
                case_key="default",
                operator_confirmable=existing_backend,
            ),
            *[
                AcceptanceRequirement(
                    test_id=test_id,
                    case_key="default",
                    operator_confirmable=False,
                )
                for test_id in (
                    AcceptanceTestId.T02,
                    AcceptanceTestId.T03,
                    AcceptanceTestId.T04,
                    AcceptanceTestId.T05,
                )
            ],
            AcceptanceRequirement(
                test_id=AcceptanceTestId.T06,
                case_key="default",
                operator_confirmable=True,
            ),
        ]
        platform_order = ("macos", "windows", "linux", "chromeos")
        selected_platforms = {platform.value for platform in specification.platforms}
        requirements.extend(
            AcceptanceRequirement(
                test_id=AcceptanceTestId.T07,
                case_key=platform,
                operator_confirmable=True,
            )
            for platform in platform_order
            if platform in selected_platforms
        )
        if specification.mode.value == "production":
            requirements.extend(
                [
                    AcceptanceRequirement(
                        test_id=AcceptanceTestId.T08,
                        case_key="default",
                        operator_confirmable=True,
                    ),
                    AcceptanceRequirement(
                        test_id=AcceptanceTestId.T09,
                        case_key="unauthorized_principal",
                        operator_confirmable=True,
                    ),
                    AcceptanceRequirement(
                        test_id=AcceptanceTestId.T09,
                        case_key="unmanaged_browser",
                        operator_confirmable=True,
                    ),
                ]
            )
        return requirements

    def audit_chain_head(self) -> str | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT event_hash
                FROM audit_events
                ORDER BY rowid DESC
                LIMIT 1
                """
            ).fetchone()
        if row is None or not isinstance(row["event_hash"], str):
            return None
        return row["event_hash"]

    def verify_audit_chain(self) -> tuple[bool, int]:
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT id, deployment_id, event_type, actor, payload_json,
                       created_at, previous_hash, event_hash
                FROM audit_events ORDER BY rowid
                """
            ).fetchall()
        previous_hash: str | None = None
        for row in rows:
            expected = self._audit_hash(
                event_id=row["id"],
                deployment_id=row["deployment_id"],
                event_type=row["event_type"],
                actor=row["actor"],
                payload_json=row["payload_json"],
                created_at=row["created_at"],
                previous_hash=previous_hash,
            )
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                return False, len(rows)
            previous_hash = expected
        return True, len(rows)

    @classmethod
    def _backfill_audit_chain(cls, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            """
            SELECT rowid, id, deployment_id, event_type, actor, payload_json,
                   created_at, previous_hash, event_hash
            FROM audit_events ORDER BY rowid
            """
        ).fetchall()
        if any(row["event_hash"] is not None for row in rows):
            return
        previous_hash: str | None = None
        for row in rows:
            event_hash = cls._audit_hash(
                event_id=row["id"],
                deployment_id=row["deployment_id"],
                event_type=row["event_type"],
                actor=row["actor"],
                payload_json=row["payload_json"],
                created_at=row["created_at"],
                previous_hash=previous_hash,
            )
            if row["previous_hash"] != previous_hash or row["event_hash"] != event_hash:
                connection.execute(
                    """
                    UPDATE audit_events
                    SET previous_hash = ?, event_hash = ?
                    WHERE rowid = ?
                    """,
                    (previous_hash, event_hash, row["rowid"]),
                )
            previous_hash = event_hash

    @staticmethod
    def _audit_hash(
        *,
        event_id: str,
        deployment_id: str | None,
        event_type: str,
        actor: str,
        payload_json: str,
        created_at: str,
        previous_hash: str | None,
    ) -> str:
        canonical = json.dumps(
            {
                "actor": actor,
                "created_at": created_at,
                "deployment_id": deployment_id,
                "event_id": event_id,
                "event_type": event_type,
                "payload": json.loads(payload_json),
                "previous_hash": previous_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _insert_audit_event(
        connection: sqlite3.Connection,
        *,
        event_type: str,
        actor: str,
        payload: dict[str, str | int | bool | None],
        deployment_id: str | None = None,
    ) -> None:
        event_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        previous_row = connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous_row["event_hash"] if previous_row else None
        event_hash = StateRepository._audit_hash(
            event_id=event_id,
            deployment_id=deployment_id,
            event_type=event_type,
            actor=actor,
            payload_json=payload_json,
            created_at=created_at,
            previous_hash=previous_hash,
        )
        connection.execute(
            """
            INSERT INTO audit_events(
                id, deployment_id, event_type, actor, payload_json, created_at,
                previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                deployment_id,
                event_type,
                actor,
                payload_json,
                created_at,
                previous_hash,
                event_hash,
            ),
        )
