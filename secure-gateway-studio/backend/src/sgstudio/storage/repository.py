from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock

from sgstudio.domain.canonical import canonical_digest, canonical_json
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
    DeploymentResource,
    DeploymentRun,
    DeploymentSpec,
    EvidenceSource,
    MutationIdentity,
    OperationStatus,
    PreflightResult,
    PreparedPlan,
    PublicCertificateBinding,
    ResourceChange,
    RunOperation,
    RunPhase,
    RunStatus,
    SourceImageBinding,
    TeardownOperation,
    TeardownRun,
)
from sgstudio.domain.planner import assert_plan_integrity, canonical_plan_hash
from sgstudio.domain.teardown_instruction import teardown_instruction


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

    @staticmethod
    def _assert_mutation_identity(
        raw_identity: object,
        current_identity: MutationIdentity,
    ) -> None:
        if not isinstance(raw_identity, str):
            raise ValueError(
                "Legacy lifecycle state has no immutable deployer identity; "
                "create a newly approved deployment"
            )
        try:
            stored = MutationIdentity.model_validate_json(raw_identity)
        except ValueError as error:
            raise ValueError("Stored mutation identity is invalid") from error
        if stored != current_identity:
            raise ValueError(
                "Current operator/deployer identity differs from the approved identity"
            )

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
                    consumed_at TEXT,
                    mutation_identity_json TEXT
                );

                CREATE TABLE IF NOT EXISTS prepared_plans (
                    plan_id TEXT PRIMARY KEY,
                    configuration_hash TEXT NOT NULL,
                    plan_hash TEXT NOT NULL,
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
                    phase TEXT NOT NULL DEFAULT 'applying',
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    mutation_identity_json TEXT,
                    public_certificate_binding_json TEXT,
                    source_image_binding_json TEXT,
                    FOREIGN KEY(approval_id) REFERENCES approved_plans(approval_id)
                );

                CREATE TABLE IF NOT EXISTS run_operations (
                    operation_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    request_id TEXT,
                    resource_key TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    owned_after_apply INTEGER NOT NULL,
                    ordinal INTEGER,
                    intent_json TEXT,
                    intent_digest TEXT,
                    checkpoint_json TEXT,
                    error_code TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    FOREIGN KEY(run_id) REFERENCES deployment_runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS resource_ownership (
                    run_id TEXT NOT NULL,
                    resource_key TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    released_at TEXT,
                    metadata_json TEXT,
                    PRIMARY KEY(run_id, resource_key),
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
                    instruction_json TEXT,
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
            ownership_columns = list(
                connection.execute("PRAGMA table_info(resource_ownership)")
            )
            ownership_names = {row["name"] for row in ownership_columns}
            ownership_primary_key = {
                row["name"]: row["pk"] for row in ownership_columns if row["pk"]
            }
            if (
                "metadata_json" not in ownership_names
                or ownership_primary_key != {"run_id": 1, "resource_key": 2}
            ):
                connection.executescript(
                    """
                    ALTER TABLE resource_ownership RENAME TO resource_ownership_v8;

                    CREATE TABLE resource_ownership (
                        run_id TEXT NOT NULL,
                        resource_key TEXT NOT NULL,
                        acquired_at TEXT NOT NULL,
                        released_at TEXT,
                        metadata_json TEXT,
                        PRIMARY KEY(run_id, resource_key),
                        FOREIGN KEY(run_id) REFERENCES deployment_runs(run_id)
                    );

                    INSERT INTO resource_ownership(
                        run_id, resource_key, acquired_at, released_at, metadata_json
                    )
                    SELECT run_id, resource_key, acquired_at, released_at, NULL
                    FROM resource_ownership_v8;

                    DROP TABLE resource_ownership_v8;
                    """
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (8, CURRENT_TIMESTAMP)
                """
            )
            prepared_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(prepared_plans)")
            }
            if "plan_hash" not in prepared_columns:
                connection.execute("ALTER TABLE prepared_plans ADD COLUMN plan_hash TEXT")
                prepared_rows = connection.execute(
                    "SELECT plan_id, plan_json FROM prepared_plans"
                ).fetchall()
                for row in prepared_rows:
                    plan = DeploymentPlan.model_validate_json(row["plan_json"])
                    connection.execute(
                        "UPDATE prepared_plans SET plan_hash = ? WHERE plan_id = ?",
                        (canonical_plan_hash(plan), row["plan_id"]),
                    )
            connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (9, CURRENT_TIMESTAMP)
                """
            )
            self._backfill_audit_chain(connection)
            acceptance_link_migration = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 10"
            ).fetchone()
            if acceptance_link_migration is None:
                self._append_legacy_acceptance_audit_links(connection)
                connection.execute(
                    """
                    INSERT INTO schema_migrations(version, applied_at)
                    VALUES (10, CURRENT_TIMESTAMP)
                    """
                )
            operation_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(run_operations)")
            }
            for name, definition in {
                "request_id": "TEXT",
                "ordinal": "INTEGER",
                "intent_json": "TEXT",
                "intent_digest": "TEXT",
                "checkpoint_json": "TEXT",
            }.items():
                if name not in operation_columns:
                    connection.execute(
                        f"ALTER TABLE run_operations ADD COLUMN {name} {definition}"
                    )
            operation_rows = connection.execute(
                """
                SELECT operation_id, run_id, resource_key, action,
                       owned_after_apply, started_at, request_id, ordinal,
                       intent_json, intent_digest
                FROM run_operations
                ORDER BY run_id, started_at, operation_id
                """
            ).fetchall()
            ordinals: dict[str, int] = {}
            for row in operation_rows:
                ordinal = ordinals.get(row["run_id"], 0)
                ordinals[row["run_id"]] = ordinal + 1
                intent = {
                    "schema_version": 1,
                    "legacy": True,
                    "resource_key": row["resource_key"],
                    "action": row["action"],
                    "owned_after_apply": bool(row["owned_after_apply"]),
                }
                intent_json = row["intent_json"] or canonical_json(intent)
                intent_digest = row["intent_digest"] or canonical_digest(
                    json.loads(intent_json)
                )
                request_id = row["request_id"] or str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"sgstudio-operation:{row['run_id']}:{row['resource_key']}",
                    )
                )
                connection.execute(
                    """
                    UPDATE run_operations
                    SET request_id = ?, ordinal = COALESCE(ordinal, ?),
                        intent_json = ?, intent_digest = ?
                    WHERE operation_id = ?
                    """,
                    (request_id, ordinal, intent_json, intent_digest, row["operation_id"]),
                )
            teardown_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(teardown_runs)")
            }
            if "instruction_json" not in teardown_columns:
                connection.execute("ALTER TABLE teardown_runs ADD COLUMN instruction_json TEXT")
            connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (11, CURRENT_TIMESTAMP)
                """
            )
            run_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(deployment_runs)")
            }
            if "phase" not in run_columns:
                connection.execute(
                    "ALTER TABLE deployment_runs ADD COLUMN phase TEXT NOT NULL DEFAULT 'applying'"
                )
                connection.execute(
                    """
                    UPDATE deployment_runs SET phase = ?
                    WHERE status IN (?, ?, ?, ?)
                    """,
                    (
                        RunPhase.FINALIZED.value,
                        RunStatus.SUCCEEDED.value,
                        RunStatus.FAILED.value,
                        RunStatus.ROLLED_BACK.value,
                        RunStatus.ROLLBACK_FAILED.value,
                    ),
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (12, CURRENT_TIMESTAMP)
                """
            )
            approved_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(approved_plans)")
            }
            if "mutation_identity_json" not in approved_columns:
                connection.execute(
                    "ALTER TABLE approved_plans ADD COLUMN mutation_identity_json TEXT"
                )
            run_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(deployment_runs)")
            }
            if "mutation_identity_json" not in run_columns:
                connection.execute(
                    "ALTER TABLE deployment_runs ADD COLUMN mutation_identity_json TEXT"
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (13, CURRENT_TIMESTAMP)
                """
            )
            run_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(deployment_runs)")
            }
            if "public_certificate_binding_json" not in run_columns:
                connection.execute(
                    "ALTER TABLE deployment_runs "
                    "ADD COLUMN public_certificate_binding_json TEXT"
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (14, CURRENT_TIMESTAMP)
                """
            )
            run_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(deployment_runs)")
            }
            if "source_image_binding_json" not in run_columns:
                connection.execute(
                    "ALTER TABLE deployment_runs ADD COLUMN source_image_binding_json TEXT"
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (15, CURRENT_TIMESTAMP)
                """
            )
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
                    SET status = 'pending', error_code = 'process-restarted',
                        started_at = NULL, completed_at = NULL
                    WHERE teardown_id = ? AND status IN ('pending', 'running')
                    """,
                    (teardown_id,),
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
        serialized = canonical_json(payload)

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
        assert_plan_integrity(plan, specification)
        now = datetime.now(UTC)
        artifact = PreparedPlan(
            plan_id=str(uuid.uuid4()),
            plan_hash=canonical_plan_hash(plan),
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
                    plan_id, configuration_hash, plan_hash, specification_json,
                    preflight_json, plan_json, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.plan_id,
                    plan.configuration_hash,
                    artifact.plan_hash,
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
                       configuration_hash, plan_hash, created_at, expires_at
                FROM prepared_plans WHERE plan_id = ?
                """,
                (plan_id,),
            ).fetchone()
        if row is None:
            return None
        specification = DeploymentSpec.model_validate_json(row["specification_json"])
        plan = DeploymentPlan.model_validate_json(row["plan_json"])
        assert_plan_integrity(
            plan,
            specification,
            stored_configuration_hash=row["configuration_hash"],
            stored_plan_hash=row["plan_hash"],
        )
        return PreparedPlan(
            plan_id=row["plan_id"],
            plan_hash=row["plan_hash"],
            specification=specification,
            preflight=PreflightResult.model_validate_json(row["preflight_json"]),
            plan=plan,
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
        )

    def approve_prepared_plan(
        self,
        plan_id: str,
        *,
        ttl_minutes: int = 30,
        mutation_identity: MutationIdentity | None = None,
    ) -> ApprovedPlan:
        artifact = self.get_prepared_plan(plan_id)
        if artifact is None:
            raise ValueError("Prepared plan was not found")
        if artifact.expires_at <= datetime.now(UTC):
            raise ValueError("Prepared plan has expired; run preflight again")
        approved_by = (
            mutation_identity.operator_email
            if mutation_identity is not None
            else artifact.preflight.snapshot.cloud_identity
        )
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
            mutation_identity=mutation_identity,
        )

    def approve_plan(
        self,
        plan: DeploymentPlan,
        *,
        specification: DeploymentSpec,
        approved_by: str,
        ttl_minutes: int = 30,
        mutation_identity: MutationIdentity | None = None,
    ) -> ApprovedPlan:
        if not approved_by.strip():
            raise ValueError("approved_by is required")
        if not 1 <= ttl_minutes <= 120:
            raise ValueError("Approval TTL must be between 1 and 120 minutes")
        assert_plan_integrity(plan, specification)
        if mutation_identity is not None and (
            mutation_identity.operator_email != approved_by.strip()
            or mutation_identity.project_id != specification.project_id
            or mutation_identity.service_account_email
            != (
                "secure-gateway-deployer@"
                f"{specification.project_id}.iam.gserviceaccount.com"
            )
        ):
            raise ValueError("Approval mutation identity is not project-bound")

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

        now = datetime.now(UTC)
        approval = ApprovedPlan(
            approval_id=str(uuid.uuid4()),
            configuration_hash=approved_plan.configuration_hash,
            plan_hash=canonical_plan_hash(approved_plan),
            plan=approved_plan,
            specification=specification,
            approved_by=approved_by.strip(),
            approved_at=now,
            expires_at=now + timedelta(minutes=ttl_minutes),
            mutation_identity=mutation_identity,
        )
        serialized_approval_plan = approval.plan.model_dump_json()

        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO approved_plans(
                    approval_id, configuration_hash, plan_hash, plan_json,
                    specification_json, approved_by, approved_at, expires_at, consumed_at,
                    mutation_identity_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
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
                    (
                        approval.mutation_identity.model_dump_json()
                        if approval.mutation_identity is not None
                        else None
                    ),
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
                       consumed_at, mutation_identity_json
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
        plan = DeploymentPlan.model_validate_json(row["plan_json"])
        specification = DeploymentSpec.model_validate_json(row["specification_json"])
        assert_plan_integrity(
            plan,
            specification,
            stored_configuration_hash=row["configuration_hash"],
            stored_plan_hash=row["plan_hash"],
        )
        return ApprovedPlan(
            approval_id=row["approval_id"],
            configuration_hash=row["configuration_hash"],
            plan_hash=row["plan_hash"],
            plan=plan,
            specification=specification,
            approved_by=row["approved_by"],
            approved_at=datetime.fromisoformat(row["approved_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            mutation_identity=(
                MutationIdentity.model_validate_json(row["mutation_identity_json"])
                if row["mutation_identity_json"]
                else None
            ),
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
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT approval_id, configuration_hash, plan_hash, plan_json,
                       specification_json, approved_by, approved_at, expires_at,
                       consumed_at, mutation_identity_json
                FROM approved_plans
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise ValueError("Approval is invalid, expired, consumed, or configuration changed")
            try:
                approval = self._approval_from_row(row)
            except (RuntimeError, ValueError):
                connection.rollback()
                raise
            if (
                approval.consumed_at is not None
                or approval.expires_at <= now
                or (
                    configuration_hash is not None
                    and configuration_hash != approval.configuration_hash
                )
            ):
                connection.rollback()
                raise ValueError("Approval is invalid, expired, consumed, or configuration changed")
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
            approval = approval.model_copy(update={"consumed_at": now})
            self._insert_audit_event(
                connection,
                event_type="plan.consumed",
                actor=actor,
                payload={
                    "approval_id": approval_id,
                    "configuration_hash": approval.configuration_hash,
                },
            )
            connection.commit()
        return approval

    def consume_approval_and_create_run(
        self,
        approval_id: str,
        *,
        current_identity: MutationIdentity,
    ) -> tuple[ApprovedPlan, DeploymentRun]:
        """Atomically consume one approval and acquire the single Apply slot."""
        now = datetime.now(UTC)
        run_id = str(uuid.uuid4())
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT approval_id, configuration_hash, plan_hash, plan_json,
                       specification_json, approved_by, approved_at, expires_at,
                       consumed_at, mutation_identity_json
                FROM approved_plans
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise ValueError("Approval is invalid, expired, consumed, or configuration changed")
            try:
                approval = self._approval_from_row(row)
            except (RuntimeError, ValueError):
                connection.rollback()
                raise
            if approval.consumed_at is not None or approval.expires_at <= now:
                connection.rollback()
                raise ValueError("Approval is invalid, expired, consumed, or configuration changed")
            if approval.mutation_identity is None or (
                approval.mutation_identity != current_identity
                or approval.approved_by != current_identity.operator_email
                or approval.specification.project_id != current_identity.project_id
            ):
                connection.rollback()
                raise ValueError(
                    "Current operator/deployer identity differs from the approved identity; "
                    "run preflight and approve again"
                )
            active = connection.execute(
                """
                SELECT run_id
                FROM deployment_runs
                WHERE status IN (?, ?, ?)
                LIMIT 1
                """,
                (
                    RunStatus.PENDING.value,
                    RunStatus.RUNNING.value,
                    RunStatus.INTERRUPTED.value,
                ),
            ).fetchone()
            if active is not None:
                connection.rollback()
                raise ValueError(f"Another deployment run is active: {active['run_id']}")
            active_teardown = connection.execute(
                """
                SELECT teardown_id FROM teardown_runs
                WHERE status IN ('pending', 'running')
                LIMIT 1
                """
            ).fetchone()
            if active_teardown is not None:
                connection.rollback()
                raise ValueError(
                    f"A teardown is active: {active_teardown['teardown_id']}"
                )
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
            approval = approval.model_copy(update={"consumed_at": now})
            actor = current_identity.operator_email
            run = DeploymentRun(
                run_id=run_id,
                approval_id=approval.approval_id,
                configuration_hash=approval.configuration_hash,
                status=RunStatus.RUNNING,
                phase=RunPhase.APPLYING,
                started_at=now,
                mutation_identity=current_identity,
                public_certificate_binding=approval.plan.public_certificate_binding,
                source_image_binding=approval.plan.source_image_binding,
            )
            connection.execute(
                """
                INSERT INTO deployment_runs(
                    run_id, approval_id, configuration_hash, status, phase, started_at,
                    mutation_identity_json, public_certificate_binding_json,
                    source_image_binding_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.approval_id,
                    run.configuration_hash,
                    run.status.value,
                    run.phase.value,
                    run.started_at.isoformat(),
                    current_identity.model_dump_json(),
                    (
                        run.public_certificate_binding.model_dump_json()
                        if run.public_certificate_binding is not None
                        else None
                    ),
                    (
                        run.source_image_binding.model_dump_json()
                        if run.source_image_binding is not None
                        else None
                    ),
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
            phase=RunPhase.APPLYING,
            started_at=now,
            mutation_identity=approval.mutation_identity,
            public_certificate_binding=approval.plan.public_certificate_binding,
            source_image_binding=approval.plan.source_image_binding,
        )
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                """
                SELECT run_id
                FROM deployment_runs
                WHERE status IN (?, ?, ?)
                LIMIT 1
                """,
                (
                    RunStatus.PENDING.value,
                    RunStatus.RUNNING.value,
                    RunStatus.INTERRUPTED.value,
                ),
            ).fetchone()
            if active is not None:
                connection.rollback()
                raise ValueError(f"Another deployment run is active: {active['run_id']}")
            connection.execute(
                """
                INSERT INTO deployment_runs(
                    run_id, approval_id, configuration_hash, status, phase, started_at,
                    mutation_identity_json, public_certificate_binding_json,
                    source_image_binding_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.approval_id,
                    run.configuration_hash,
                    run.status.value,
                    run.phase.value,
                    run.started_at.isoformat(),
                    (
                        run.mutation_identity.model_dump_json()
                        if run.mutation_identity is not None
                        else None
                    ),
                    (
                        run.public_certificate_binding.model_dump_json()
                        if run.public_certificate_binding is not None
                        else None
                    ),
                    (
                        run.source_image_binding.model_dump_json()
                        if run.source_image_binding is not None
                        else None
                    ),
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

    @staticmethod
    def _operation_intent(change: ResourceChange) -> dict[str, object]:
        return {
            "schema_version": 1,
            "change": change.model_dump(mode="json"),
        }

    @staticmethod
    def _operation_request_id(run_id: str, resource_key: str) -> str:
        return str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"sgstudio-operation:{run_id}:{resource_key}",
            )
        )

    @staticmethod
    def _operation_from_row(row: sqlite3.Row) -> RunOperation:
        checkpoint_raw = row["checkpoint_json"]
        checkpoint = json.loads(checkpoint_raw) if isinstance(checkpoint_raw, str) else None
        return RunOperation(
            operation_id=row["operation_id"],
            request_id=row["request_id"],
            resource_key=row["resource_key"],
            action=ChangeAction(row["action"]),
            status=OperationStatus(row["status"]),
            owned_after_apply=bool(row["owned_after_apply"]),
            intent_digest=row["intent_digest"],
            checkpoint=checkpoint if isinstance(checkpoint, dict) else None,
            error_code=row["error_code"],
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=(
                datetime.fromisoformat(row["completed_at"])
                if row["completed_at"]
                else None
            ),
        )

    def start_operation(
        self,
        run_id: str,
        change: ResourceChange,
        *,
        ordinal: int = 0,
    ) -> RunOperation:
        """Durably create or resume one exact provider mutation intent."""
        resource_key = f"{change.provider}:{change.resource_type}:{change.resource_name}"
        intent = self._operation_intent(change)
        intent_json = canonical_json(intent)
        intent_digest = canonical_digest(intent)
        request_id = self._operation_request_id(run_id, resource_key)
        now = datetime.now(UTC)
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT operation_id, run_id, request_id, resource_key, action,
                       status, owned_after_apply, intent_digest, checkpoint_json,
                       error_code, started_at, completed_at
                FROM run_operations
                WHERE run_id = ? AND resource_key = ?
                ORDER BY ordinal, started_at
                LIMIT 1
                """,
                (run_id, resource_key),
            ).fetchone()
            if existing is not None:
                if (
                    existing["request_id"] != request_id
                    or existing["action"] != change.action.value
                    or bool(existing["owned_after_apply"]) != change.owned_after_apply
                    or existing["intent_digest"] != intent_digest
                ):
                    connection.rollback()
                    raise ValueError("Durable operation intent differs from the approved plan")
                if existing["status"] == OperationStatus.INTERRUPTED.value:
                    connection.execute(
                        """
                        UPDATE run_operations
                        SET status = ?, error_code = NULL, completed_at = NULL
                        WHERE operation_id = ?
                        """,
                        (OperationStatus.RUNNING.value, existing["operation_id"]),
                    )
                    self._insert_audit_event(
                        connection,
                        event_type="operation.resumed",
                        actor="system",
                        payload={
                            "run_id": run_id,
                            "operation_id": existing["operation_id"],
                            "request_id": request_id,
                            "resource_key": resource_key,
                        },
                    )
                    existing = connection.execute(
                        """
                        SELECT operation_id, run_id, request_id, resource_key, action,
                               status, owned_after_apply, intent_digest, checkpoint_json,
                               error_code, started_at, completed_at
                        FROM run_operations WHERE operation_id = ?
                        """,
                        (existing["operation_id"],),
                    ).fetchone()
                connection.commit()
                if existing is None:
                    raise RuntimeError("Resumed operation disappeared")
                return self._operation_from_row(existing)

            operation_id = str(
                uuid.uuid5(uuid.NAMESPACE_URL, f"sgstudio-operation-record:{request_id}")
            )
            connection.execute(
                """
                INSERT INTO run_operations(
                    operation_id, run_id, request_id, resource_key, action,
                    status, owned_after_apply, ordinal, intent_json,
                    intent_digest, checkpoint_json, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                """,
                (
                    operation_id,
                    run_id,
                    request_id,
                    resource_key,
                    change.action.value,
                    OperationStatus.RUNNING.value,
                    int(change.owned_after_apply),
                    ordinal,
                    intent_json,
                    intent_digest,
                    now.isoformat(),
                ),
            )
            self._insert_audit_event(
                connection,
                event_type="operation.started",
                actor="system",
                payload={
                    "run_id": run_id,
                    "operation_id": operation_id,
                    "request_id": request_id,
                    "intent_digest": intent_digest,
                    "resource_key": resource_key,
                    "action": change.action.value,
                    "owned_after_apply": change.owned_after_apply,
                },
            )
            connection.commit()
        operation = self.get_operation(operation_id)
        if operation is None:
            raise RuntimeError("Created operation disappeared")
        return operation

    def get_operation(self, operation_id: str) -> RunOperation | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT operation_id, run_id, request_id, resource_key, action,
                       status, owned_after_apply, intent_digest, checkpoint_json,
                       error_code, started_at, completed_at
                FROM run_operations WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
        return self._operation_from_row(row) if row is not None else None

    def checkpoint_operation(
        self,
        operation_id: str,
        checkpoint: dict[str, object],
    ) -> None:
        """Persist a non-secret provider checkpoint before the external write."""
        serialized = canonical_json(checkpoint)
        digest = canonical_digest(checkpoint)
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT run_id, request_id, resource_key, status
                FROM run_operations WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
            if row is None or row["status"] not in {
                OperationStatus.RUNNING.value,
                OperationStatus.INTERRUPTED.value,
                OperationStatus.SUCCEEDED.value,
                OperationStatus.FAILED.value,
                OperationStatus.ROLLED_BACK.value,
            }:
                connection.rollback()
                raise ValueError("Operation is not checkpointable")
            connection.execute(
                "UPDATE run_operations SET checkpoint_json = ? WHERE operation_id = ?",
                (serialized, operation_id),
            )
            # A mutation intent is claimed before the provider can write. Keep
            # the active claim and its latest non-secret recovery proof in the
            # same transaction as the operation checkpoint so a process crash
            # cannot leave an externally-applied mutation without a durable
            # locator/managed-after image.
            connection.execute(
                """
                UPDATE resource_ownership SET metadata_json = ?
                WHERE run_id = ? AND resource_key = ? AND released_at IS NULL
                """,
                (serialized, row["run_id"], row["resource_key"]),
            )
            self._insert_audit_event(
                connection,
                event_type="operation.checkpointed",
                actor="system",
                payload={
                    "run_id": row["run_id"],
                    "operation_id": operation_id,
                    "request_id": row["request_id"],
                    "resource_key": row["resource_key"],
                    "checkpoint_digest": digest,
                    "kind": checkpoint.get("kind"),
                    "phase": checkpoint.get("phase"),
                },
            )
            connection.commit()

    def complete_operation_and_claim(
        self,
        operation_id: str,
        *,
        run_id: str,
        metadata: dict[str, object] | None,
    ) -> None:
        """Atomically commit provider success and its teardown authority."""
        now = datetime.now(UTC).isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                """
                SELECT run_id, resource_key, request_id, owned_after_apply, status
                FROM run_operations WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
            if operation is None or operation["run_id"] != run_id:
                connection.rollback()
                raise ValueError("Operation does not belong to the deployment run")
            if operation["status"] == OperationStatus.SUCCEEDED.value:
                connection.commit()
                return
            if operation["status"] != OperationStatus.RUNNING.value:
                connection.rollback()
                raise ValueError("Operation is not running")
            connection.execute(
                """
                UPDATE run_operations
                SET status = ?, error_code = NULL, completed_at = ?
                WHERE operation_id = ?
                """,
                (OperationStatus.SUCCEEDED.value, now, operation_id),
            )
            if bool(operation["owned_after_apply"]):
                connection.execute(
                    """
                    INSERT INTO resource_ownership(
                        run_id, resource_key, acquired_at, released_at, metadata_json
                    ) VALUES (?, ?, ?, NULL, ?)
                    ON CONFLICT(run_id, resource_key) DO UPDATE SET
                        acquired_at = excluded.acquired_at,
                        released_at = NULL,
                        metadata_json = COALESCE(
                            excluded.metadata_json,
                            resource_ownership.metadata_json
                        )
                    """,
                    (
                        run_id,
                        operation["resource_key"],
                        now,
                        canonical_json(metadata) if metadata is not None else None,
                    ),
                )
            else:
                # Shared RMW operations use a temporary intent claim while the
                # provider result is uncertain. A confirmed success commits the
                # operation and releases that temporary claim atomically; later
                # run rollback still uses the SUCCEEDED operation checkpoint.
                connection.execute(
                    """
                    UPDATE resource_ownership SET released_at = ?
                    WHERE run_id = ? AND resource_key = ? AND released_at IS NULL
                    """,
                    (now, run_id, operation["resource_key"]),
                )
            self._insert_audit_event(
                connection,
                event_type="operation.completed",
                actor="system",
                payload={
                    "run_id": run_id,
                    "operation_id": operation_id,
                    "request_id": operation["request_id"],
                    "resource_key": operation["resource_key"],
                    "status": OperationStatus.SUCCEEDED.value,
                    "error_code": None,
                    "ownership_digest": (
                        canonical_digest(metadata) if metadata is not None else None
                    ),
                },
            )
            connection.commit()

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

    def claim_resource(
        self,
        resource_key: str,
        *,
        run_id: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO resource_ownership(
                    run_id, resource_key, acquired_at, released_at, metadata_json
                )
                VALUES (?, ?, ?, NULL, ?)
                ON CONFLICT(run_id, resource_key) DO UPDATE SET
                    acquired_at = excluded.acquired_at,
                    released_at = NULL,
                    metadata_json = COALESCE(
                        excluded.metadata_json,
                        resource_ownership.metadata_json
                    )
                """,
                (
                    run_id,
                    resource_key,
                    datetime.now(UTC).isoformat(),
                    canonical_json(metadata) if metadata is not None else None,
                ),
            )
            connection.commit()

    def fail_operation_and_begin_rollback(
        self,
        operation_id: str,
        *,
        error_code: str,
    ) -> None:
        """Atomically persist Apply failure and enter the rollback phase."""
        now = datetime.now(UTC).isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                """
                SELECT run_id, resource_key, status FROM run_operations
                WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
            if operation is None or operation["status"] not in {
                OperationStatus.RUNNING.value,
                OperationStatus.FAILED.value,
            }:
                connection.rollback()
                raise ValueError("Operation cannot enter rollback")
            connection.execute(
                """
                UPDATE run_operations
                SET status = ?, error_code = ?, completed_at = ?
                WHERE operation_id = ?
                """,
                (
                    OperationStatus.FAILED.value,
                    error_code,
                    now,
                    operation_id,
                ),
            )
            connection.execute(
                """
                UPDATE deployment_runs SET phase = ?
                WHERE run_id = ? AND status = ?
                """,
                (
                    RunPhase.ROLLING_BACK.value,
                    operation["run_id"],
                    RunStatus.RUNNING.value,
                ),
            )
            self._insert_audit_event(
                connection,
                event_type="operation.completed",
                actor="system",
                payload={
                    "run_id": operation["run_id"],
                    "operation_id": operation_id,
                    "resource_key": operation["resource_key"],
                    "status": OperationStatus.FAILED.value,
                    "error_code": error_code,
                },
            )
            connection.commit()

    def begin_run_rollback(self, run_id: str) -> None:
        """Idempotently persist the rollback phase before compensation."""
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status, phase FROM deployment_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None or row["status"] != RunStatus.RUNNING.value:
                connection.rollback()
                raise ValueError("Deployment run cannot enter rollback")
            if row["phase"] != RunPhase.ROLLING_BACK.value:
                connection.execute(
                    "UPDATE deployment_runs SET phase = ? WHERE run_id = ?",
                    (RunPhase.ROLLING_BACK.value, run_id),
                )
                self._insert_audit_event(
                    connection,
                    event_type="run.rollback_started",
                    actor="system",
                    payload={"run_id": run_id},
                )
            connection.commit()

    def complete_rollback_and_release(
        self,
        operation_id: str,
        *,
        run_id: str,
    ) -> None:
        """Atomically checkpoint compensation and release owned inventory."""
        now = datetime.now(UTC).isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                """
                SELECT run_id, resource_key, status, owned_after_apply
                FROM run_operations WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
            if operation is None or operation["run_id"] != run_id:
                connection.rollback()
                raise ValueError("Operation does not belong to the deployment run")
            if operation["status"] not in {
                OperationStatus.SUCCEEDED.value,
                OperationStatus.FAILED.value,
                OperationStatus.ROLLED_BACK.value,
            }:
                connection.rollback()
                raise ValueError("Operation is not compensatable")
            connection.execute(
                """
                UPDATE run_operations
                SET status = ?, completed_at = ?
                WHERE operation_id = ?
                """,
                (OperationStatus.ROLLED_BACK.value, now, operation_id),
            )
            # Both durable resources and temporary shared-mutation intent
            # claims are released only after compensation is confirmed.
            connection.execute(
                """
                UPDATE resource_ownership SET released_at = ?
                WHERE run_id = ? AND resource_key = ? AND released_at IS NULL
                """,
                (now, run_id, operation["resource_key"]),
            )
            self._insert_audit_event(
                connection,
                event_type="operation.completed",
                actor="system",
                payload={
                    "run_id": run_id,
                    "operation_id": operation_id,
                    "resource_key": operation["resource_key"],
                    "status": OperationStatus.ROLLED_BACK.value,
                    "error_code": None,
                },
            )
            connection.commit()

    def resume_run(
        self,
        run_id: str,
        *,
        current_identity: MutationIdentity | None = None,
    ) -> DeploymentRun:
        """Reacquire the Apply slot for one fail-closed interrupted run."""
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT deployment_runs.status,
                       deployment_runs.mutation_identity_json,
                       deployment_runs.public_certificate_binding_json,
                       deployment_runs.source_image_binding_json,
                       approved_plans.plan_json,
                       approved_plans.plan_hash
                FROM deployment_runs
                JOIN approved_plans
                  ON approved_plans.approval_id = deployment_runs.approval_id
                WHERE deployment_runs.run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if row is None or row["status"] != RunStatus.INTERRUPTED.value:
                connection.rollback()
                raise ValueError("Deployment run is not resumable")
            if current_identity is not None:
                self._assert_mutation_identity(
                    row["mutation_identity_json"], current_identity
                )
            try:
                approved_plan = DeploymentPlan.model_validate_json(row["plan_json"])
                if canonical_plan_hash(approved_plan) != row["plan_hash"]:
                    raise ValueError("Stored approved plan hash is invalid")
                raw_binding = row["public_certificate_binding_json"]
                run_binding = (
                    PublicCertificateBinding.model_validate_json(raw_binding)
                    if raw_binding is not None
                    else None
                )
                raw_image_binding = row["source_image_binding_json"]
                run_image_binding = (
                    SourceImageBinding.model_validate_json(raw_image_binding)
                    if raw_image_binding is not None
                    else None
                )
            except ValueError as error:
                connection.rollback()
                raise ValueError("Stored public certificate run binding is invalid") from error
            if run_binding != approved_plan.public_certificate_binding:
                connection.rollback()
                raise ValueError(
                    "Deployment run public certificate binding differs from its approval"
                )
            if run_image_binding != approved_plan.source_image_binding:
                connection.rollback()
                raise ValueError(
                    "Deployment run source image binding differs from its approval"
                )
            active = connection.execute(
                """
                SELECT run_id FROM deployment_runs
                WHERE status IN (?, ?, ?) AND run_id != ? LIMIT 1
                """,
                (
                    RunStatus.PENDING.value,
                    RunStatus.RUNNING.value,
                    RunStatus.INTERRUPTED.value,
                    run_id,
                ),
            ).fetchone()
            active_teardown = connection.execute(
                """
                SELECT teardown_id FROM teardown_runs
                WHERE status IN ('pending', 'running') LIMIT 1
                """
            ).fetchone()
            if active is not None or active_teardown is not None:
                connection.rollback()
                raise ValueError("Another deployment lifecycle operation is active")
            connection.execute(
                """
                UPDATE deployment_runs
                SET status = ?, completed_at = NULL
                WHERE run_id = ?
                """,
                (RunStatus.RUNNING.value, run_id),
            )
            self._insert_audit_event(
                connection,
                event_type="run.resumed",
                actor=(
                    current_identity.operator_email
                    if current_identity is not None
                    else "system"
                ),
                payload={"run_id": run_id, "status": RunStatus.RUNNING.value},
            )
            connection.commit()
        resumed = self.get_run(run_id)
        if resumed is None:
            raise RuntimeError("Resumed run disappeared")
        return resumed

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
                SET status = ?, phase = ?, completed_at = ?
                WHERE run_id = ?
                """,
                (
                    status.value,
                    RunPhase.FINALIZED.value,
                    now.isoformat(),
                    run_id,
                ),
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
                SELECT run_id, approval_id, configuration_hash, status, phase,
                       started_at, completed_at, mutation_identity_json,
                       public_certificate_binding_json, source_image_binding_json
                FROM deployment_runs
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if run_row is None:
                return None
            operation_rows = connection.execute(
                """
                SELECT operation_id, run_id, request_id, resource_key, action,
                       status, owned_after_apply, intent_digest, checkpoint_json,
                       error_code, started_at, completed_at
                FROM run_operations
                WHERE run_id = ?
                ORDER BY ordinal, started_at
                """,
                (run_id,),
            ).fetchall()
        operations = [self._operation_from_row(row) for row in operation_rows]
        return DeploymentRun(
            run_id=run_row["run_id"],
            approval_id=run_row["approval_id"],
            configuration_hash=run_row["configuration_hash"],
            status=RunStatus(run_row["status"]),
            phase=RunPhase(run_row["phase"]),
            started_at=datetime.fromisoformat(run_row["started_at"]),
            completed_at=(
                datetime.fromisoformat(run_row["completed_at"]) if run_row["completed_at"] else None
            ),
            operations=operations,
            mutation_identity=(
                MutationIdentity.model_validate_json(run_row["mutation_identity_json"])
                if run_row["mutation_identity_json"]
                else None
            ),
            public_certificate_binding=(
                PublicCertificateBinding.model_validate_json(
                    run_row["public_certificate_binding_json"]
                )
                if run_row["public_certificate_binding_json"]
                else None
            ),
            source_image_binding=(
                SourceImageBinding.model_validate_json(run_row["source_image_binding_json"])
                if run_row["source_image_binding_json"]
                else None
            ),
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

    def active_owned_resource_metadata(
        self, run_id: str
    ) -> dict[str, dict[str, object]]:
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT resource_key, metadata_json FROM resource_ownership
                WHERE run_id = ? AND released_at IS NULL
                """,
                (run_id,),
            ).fetchall()
        result: dict[str, dict[str, object]] = {}
        for row in rows:
            raw = row["metadata_json"]
            if not isinstance(raw, str):
                continue
            value = json.loads(raw)
            if isinstance(value, dict):
                result[row["resource_key"]] = value
        return result

    @staticmethod
    def _discovery_ownership_scope(specification: DeploymentSpec) -> tuple[str, ...]:
        """Return provider URL and Workspace target scope for ownership reuse."""

        return (
            specification.project_id,
            specification.name,
            specification.gateway_id,
            specification.region,
            specification.zone,
            specification.secondary_zone,
            specification.upstream_project_id,
            specification.customer_id,
            specification.target_ou_id,
        )

    def active_discovery_ownership_metadata(
        self,
        specification: DeploymentSpec,
    ) -> dict[str, dict[str, object]]:
        """Load active ownership proof for the exact provider scope.

        Configuration fields such as principals, access levels, and certificate
        rotation settings may safely change without changing a managed
        resource's provider URL. Conversely, project/region/zone/upstream and
        Workspace target changes must never inherit proof from another scope.

        Successful re-apply and certificate rotation can split active ownership
        across runs: unchanged resources remain claimed by the older run while
        a replacement version is claimed by the newer one. Aggregate those
        integrity-validated runs per resource key. A newer active checkpoint for
        the same key supersedes an older checkpoint; an exact timestamp tie with
        different metadata is ambiguous and supplies no authority for that key.
        """

        requested_scope = self._discovery_ownership_scope(specification)
        matching_run_ids: list[str] = []
        shared_checkpoint_run_ids: list[str] = []
        for run_id in self._run_ids_with_discovery_evidence():
            try:
                run = self.get_run(run_id)
                if run is None:
                    continue
                approval = self.get_approval(run.approval_id)
            except (RuntimeError, ValueError):
                # Invalid legacy/tampered lifecycle state supplies no proof.
                # A valid older proof still has to match the exact live marker
                # and provider identity, so ignoring this run cannot authorize
                # a replaced or foreign provider object.
                continue
            if approval is None or run.configuration_hash != approval.configuration_hash:
                continue
            if self._discovery_ownership_scope(approval.specification) != requested_scope:
                continue
            approved_changes = {
                f"{change.provider}:{change.resource_type}:{change.resource_name}": change
                for change in approval.plan.changes
            }
            operations_valid = all(
                (
                    (approved_change := approved_changes.get(operation.resource_key))
                    is not None
                    and operation.request_id
                    == self._operation_request_id(run_id, operation.resource_key)
                    and operation.action is approved_change.action
                    and operation.owned_after_apply
                    is approved_change.owned_after_apply
                    and operation.intent_digest
                    == canonical_digest(self._operation_intent(approved_change))
                )
                for operation in run.operations
            )
            if not operations_valid:
                continue
            matching_run_ids.append(run_id)
            if run.status is RunStatus.SUCCEEDED:
                shared_checkpoint_run_ids.append(run_id)
        if not matching_run_ids:
            return {}
        return self._newest_active_owned_resource_metadata(
            matching_run_ids,
            shared_checkpoint_run_ids=shared_checkpoint_run_ids,
        )

    def _run_ids_with_discovery_evidence(self) -> list[str]:
        """Return runs with active ownership or retained shared CREATE proof."""

        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT run_id, MAX(evidence_at) AS latest_evidence
                FROM (
                    SELECT run_id, acquired_at AS evidence_at
                    FROM resource_ownership
                    WHERE released_at IS NULL
                    UNION ALL
                    SELECT operations.run_id,
                           COALESCE(operations.completed_at, operations.started_at)
                    FROM run_operations AS operations
                    JOIN deployment_runs AS runs ON runs.run_id = operations.run_id
                    WHERE operations.action = ?
                      AND operations.status = ?
                      AND operations.owned_after_apply = 0
                      AND operations.checkpoint_json IS NOT NULL
                      AND runs.status = ?
                )
                GROUP BY run_id
                ORDER BY latest_evidence DESC, run_id DESC
                """,
                (
                    ChangeAction.CREATE.value,
                    OperationStatus.SUCCEEDED.value,
                    RunStatus.SUCCEEDED.value,
                ),
            ).fetchall()
        return [row["run_id"] for row in rows]

    def _newest_active_owned_resource_metadata(
        self,
        run_ids: list[str],
        *,
        shared_checkpoint_run_ids: list[str],
    ) -> dict[str, dict[str, object]]:
        placeholders = ", ".join("?" for _ in run_ids)
        with self._lock, closing(self._connect()) as connection:
            rows = list(
                connection.execute(
                f"""
                SELECT run_id, resource_key, acquired_at, metadata_json
                FROM resource_ownership
                WHERE released_at IS NULL AND run_id IN ({placeholders})
                ORDER BY resource_key, acquired_at DESC, run_id DESC
                """,
                tuple(run_ids),
                ).fetchall()
            )
            if shared_checkpoint_run_ids:
                checkpoint_placeholders = ", ".join(
                    "?" for _ in shared_checkpoint_run_ids
                )
                rows.extend(
                    connection.execute(
                        f"""
                        SELECT run_id, resource_key,
                               COALESCE(completed_at, started_at) AS acquired_at,
                               checkpoint_json AS metadata_json
                        FROM run_operations
                        WHERE run_id IN ({checkpoint_placeholders})
                          AND action = ?
                          AND status = ?
                          AND owned_after_apply = 0
                          AND checkpoint_json IS NOT NULL
                        """,
                        (
                            *shared_checkpoint_run_ids,
                            ChangeAction.CREATE.value,
                            OperationStatus.SUCCEEDED.value,
                        ),
                    ).fetchall()
                )

        candidates: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            candidates.setdefault(row["resource_key"], []).append(row)

        result: dict[str, dict[str, object]] = {}
        for resource_key, resource_rows in candidates.items():
            latest_acquired_at = max(row["acquired_at"] for row in resource_rows)
            latest_rows = [
                row
                for row in resource_rows
                if row["acquired_at"] == latest_acquired_at
            ]
            decoded: list[dict[str, object]] = []
            invalid = False
            for row in latest_rows:
                raw = row["metadata_json"]
                if not isinstance(raw, str):
                    invalid = True
                    break
                try:
                    value = json.loads(raw)
                except json.JSONDecodeError:
                    invalid = True
                    break
                if not isinstance(value, dict):
                    invalid = True
                    break
                decoded.append(value)
            if invalid or not decoded:
                continue
            if len({canonical_json(value) for value in decoded}) != 1:
                continue
            result[resource_key] = decoded[0]
        return result

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
        resources: list[DeploymentResource],
        actor: str,
        current_identity: MutationIdentity | None = None,
    ) -> TeardownRun:
        now = datetime.now(UTC)
        teardown_id = str(uuid.uuid4())
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            source = connection.execute(
                """
                SELECT status, configuration_hash, mutation_identity_json
                FROM deployment_runs
                WHERE run_id = ?
                """,
                (source_run_id,),
            ).fetchone()
            if source is None:
                connection.rollback()
                raise ValueError("Deployment run was not found")
            if current_identity is not None:
                self._assert_mutation_identity(
                    source["mutation_identity_json"], current_identity
                )
                if actor != current_identity.operator_email:
                    connection.rollback()
                    raise ValueError("Teardown actor differs from the current operator")
            if source["status"] in {
                RunStatus.PENDING.value,
                RunStatus.RUNNING.value,
                RunStatus.INTERRUPTED.value,
            }:
                connection.rollback()
                raise ValueError("An active deployment cannot be torn down")
            active_run = connection.execute(
                """
                SELECT run_id FROM deployment_runs
                WHERE status IN (?, ?, ?)
                LIMIT 1
                """,
                (
                    RunStatus.PENDING.value,
                    RunStatus.RUNNING.value,
                    RunStatus.INTERRUPTED.value,
                ),
            ).fetchone()
            if active_run is not None:
                connection.rollback()
                raise ValueError(
                    f"A deployment run is active: {active_run['run_id']}"
                )
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
            metadata_rows = connection.execute(
                """
                SELECT resource_key, metadata_json FROM resource_ownership
                WHERE run_id = ? AND released_at IS NULL
                """,
                (source_run_id,),
            ).fetchall()
            ownership_metadata: dict[str, dict[str, object]] = {}
            active_owned: set[str] = set()
            for metadata_row in metadata_rows:
                active_owned.add(metadata_row["resource_key"])
                raw = metadata_row["metadata_json"]
                if isinstance(raw, str):
                    value = json.loads(raw)
                    if isinstance(value, dict):
                        ownership_metadata[metadata_row["resource_key"]] = value
            requested_owned = {
                resource.resource_key for resource in resources if resource.owned
            }
            if requested_owned != active_owned:
                connection.rollback()
                raise ValueError("Teardown ownership inventory changed before start")
            instruction = teardown_instruction(
                run_id=source_run_id,
                configuration_hash=source["configuration_hash"],
                resources=resources,
                ownership_metadata=ownership_metadata,
            )
            if canonical_digest(instruction) != plan_hash:
                connection.rollback()
                raise ValueError("Teardown instruction differs from the approved plan")
            connection.execute(
                """
                INSERT INTO teardown_runs(
                    teardown_id, source_run_id, plan_hash, instruction_json,
                    status, started_at
                ) VALUES (?, ?, ?, ?, 'pending', ?)
                """,
                (
                    teardown_id,
                    source_run_id,
                    plan_hash,
                    canonical_json(instruction),
                    now.isoformat(),
                ),
            )
            connection.executemany(
                """
                INSERT INTO teardown_operations(
                    teardown_id, resource_key, ordinal, status
                ) VALUES (?, ?, ?, 'pending')
                """,
                [
                    (teardown_id, resource.resource_key, ordinal)
                    for ordinal, resource in enumerate(resources)
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
                    "instruction_digest": canonical_digest(instruction),
                    "resource_count": len(resources),
                },
            )
            connection.commit()
        created = self.get_teardown_run(teardown_id)
        if created is None:
            raise RuntimeError("Created teardown run disappeared")
        return created

    def get_teardown_instruction(
        self, teardown_id: str
    ) -> dict[str, object] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT instruction_json FROM teardown_runs WHERE teardown_id = ?",
                (teardown_id,),
            ).fetchone()
        if row is None or not isinstance(row["instruction_json"], str):
            return None
        value = json.loads(row["instruction_json"])
        return value if isinstance(value, dict) else None

    def resume_teardown_run(
        self,
        teardown_id: str,
        *,
        current_identity: MutationIdentity | None = None,
    ) -> TeardownRun:
        """Reacquire the global lifecycle slot for an interrupted teardown."""
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT teardown_runs.status, deployment_runs.mutation_identity_json
                FROM teardown_runs
                JOIN deployment_runs
                  ON deployment_runs.run_id = teardown_runs.source_run_id
                WHERE teardown_runs.teardown_id = ?
                """,
                (teardown_id,),
            ).fetchone()
            if row is None or row["status"] != "interrupted":
                connection.rollback()
                raise ValueError("Teardown run is not resumable")
            if current_identity is not None:
                self._assert_mutation_identity(
                    row["mutation_identity_json"], current_identity
                )
            active_run = connection.execute(
                """
                SELECT run_id FROM deployment_runs
                WHERE status IN (?, ?, ?) LIMIT 1
                """,
                (
                    RunStatus.PENDING.value,
                    RunStatus.RUNNING.value,
                    RunStatus.INTERRUPTED.value,
                ),
            ).fetchone()
            active_teardown = connection.execute(
                """
                SELECT teardown_id FROM teardown_runs
                WHERE status IN ('pending', 'running') AND teardown_id != ?
                LIMIT 1
                """,
                (teardown_id,),
            ).fetchone()
            if active_run is not None or active_teardown is not None:
                connection.rollback()
                raise ValueError("Another deployment lifecycle operation is active")
            connection.execute(
                """
                UPDATE teardown_runs
                SET status = 'running', completed_at = NULL
                WHERE teardown_id = ?
                """,
                (teardown_id,),
            )
            self._insert_audit_event(
                connection,
                event_type="teardown.resumed",
                actor=(
                    current_identity.operator_email
                    if current_identity is not None
                    else "system"
                ),
                payload={"teardown_id": teardown_id},
            )
            connection.commit()
        resumed = self.get_teardown_run(teardown_id)
        if resumed is None:
            raise RuntimeError("Resumed teardown disappeared")
        return resumed

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

    def get_latest_teardown_for_run(self, run_id: str) -> TeardownRun | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT teardown_id FROM teardown_runs
                WHERE source_run_id = ?
                ORDER BY started_at DESC, teardown_id DESC
                LIMIT 1
                """,
                (run_id,),
            ).fetchone()
        return self.get_teardown_run(row["teardown_id"]) if row is not None else None

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

    def complete_teardown_operation_and_release(
        self,
        teardown_id: str,
        resource_key: str,
        *,
        run_id: str,
        status: str,
        release: bool,
    ) -> None:
        """Atomically checkpoint destructive success and release its authority."""
        if status not in {"succeeded", "skipped"}:
            raise ValueError("Invalid successful teardown operation status")
        now = datetime.now(UTC).isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                """
                SELECT status FROM teardown_operations
                WHERE teardown_id = ? AND resource_key = ?
                """,
                (teardown_id, resource_key),
            ).fetchone()
            if operation is None:
                connection.rollback()
                raise ValueError("Teardown operation was not found")
            if operation["status"] in {"succeeded", "skipped"}:
                connection.commit()
                return
            connection.execute(
                """
                UPDATE teardown_operations
                SET status = ?, error_code = NULL, completed_at = ?
                WHERE teardown_id = ? AND resource_key = ?
                """,
                (status, now, teardown_id, resource_key),
            )
            if release:
                released = connection.execute(
                    """
                    UPDATE resource_ownership SET released_at = ?
                    WHERE run_id = ? AND resource_key = ? AND released_at IS NULL
                    """,
                    (now, run_id, resource_key),
                ).rowcount
                if released != 1:
                    connection.rollback()
                    raise ValueError("Teardown ownership release was not exact")
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
        current_identity: MutationIdentity | None = None,
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
                """
                SELECT status, mutation_identity_json FROM deployment_runs
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if run is None:
                raise ValueError("Deployment run was not found")
            if run["status"] != RunStatus.SUCCEEDED.value:
                raise ValueError("Acceptance evidence requires a succeeded deployment run")
            if current_identity is not None:
                self._assert_mutation_identity(
                    run["mutation_identity_json"], current_identity
                )
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
                payload=self._acceptance_audit_payload(result),
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
            acceptance_rows = connection.execute(
                """
                SELECT result_id, run_id, test_id, case_key, status, source, summary,
                       evidence, actor, recorded_at
                FROM acceptance_results
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
        if not self._verify_acceptance_audit_links(acceptance_rows, rows):
            return False, len(rows)
        return True, len(rows)

    @staticmethod
    def _verify_acceptance_audit_links(
        acceptance_rows: list[sqlite3.Row],
        audit_rows: list[sqlite3.Row],
    ) -> bool:
        latest_events: dict[tuple[str, str, str], dict[str, object]] = {}
        for row in audit_rows:
            if row["event_type"] != "acceptance.recorded":
                continue
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, json.JSONDecodeError):
                return False
            if not isinstance(payload, dict):
                return False
            key_values = (
                payload.get("run_id"),
                payload.get("test_id"),
                payload.get("case_key"),
            )
            if not all(isinstance(value, str) for value in key_values):
                return False
            latest_events[key_values] = payload

        current: dict[tuple[str, str, str], tuple[str, str]] = {}
        for row in acceptance_rows:
            try:
                result = AcceptanceResult(
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
            except (TypeError, ValueError):
                return False
            key = (result.run_id, result.test_id.value, result.case_key)
            current[key] = (
                result.result_id,
                canonical_digest(result.model_dump(mode="json")),
            )

        if set(current) != set(latest_events):
            return False
        return all(
            latest_events[key].get("result_id") == result_id
            and latest_events[key].get("record_digest") == digest
            for key, (result_id, digest) in current.items()
        )

    @staticmethod
    def _acceptance_audit_payload(result: AcceptanceResult) -> dict[str, str]:
        return {
            "result_id": result.result_id,
            "run_id": result.run_id,
            "test_id": result.test_id.value,
            "case_key": result.case_key,
            "status": result.status.value,
            "source": result.source.value,
            "evidence_sha256": hashlib.sha256(result.evidence.encode()).hexdigest(),
            "record_digest": canonical_digest(result.model_dump(mode="json")),
        }

    @classmethod
    def _append_legacy_acceptance_audit_links(
        cls,
        connection: sqlite3.Connection,
    ) -> None:
        """Bind v0.2.0 acceptance rows without rewriting historic events.

        The old event payload authenticated the run/test/case/status/source and
        evidence digest, but not the row identity or the complete row.  Only
        that exact legacy shape is upgraded.  A partially populated modern
        payload remains invalid so opening a database cannot bless tampering.
        """
        audit_rows = connection.execute(
            """
            SELECT id, payload_json
            FROM audit_events
            WHERE event_type = 'acceptance.recorded'
            ORDER BY rowid
            """
        ).fetchall()
        latest: dict[tuple[str, str, str], tuple[str, dict[str, object]]] = {}
        for event in audit_rows:
            try:
                payload = json.loads(event["payload_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            key_values = (
                payload.get("run_id"),
                payload.get("test_id"),
                payload.get("case_key"),
            )
            if all(isinstance(value, str) for value in key_values):
                latest[key_values] = (event["id"], payload)

        acceptance_rows = connection.execute(
            """
            SELECT result_id, run_id, test_id, case_key, status, source, summary,
                   evidence, actor, recorded_at
            FROM acceptance_results
            ORDER BY recorded_at, result_id
            """
        ).fetchall()
        for row in acceptance_rows:
            try:
                result = AcceptanceResult(
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
            except (TypeError, ValueError):
                continue
            key = (result.run_id, result.test_id.value, result.case_key)
            legacy = latest.get(key)
            if legacy is None:
                continue
            legacy_event_id, payload = legacy
            if "result_id" in payload or "record_digest" in payload:
                continue
            expected_legacy_fields = {
                "run_id": result.run_id,
                "test_id": result.test_id.value,
                "case_key": result.case_key,
                "status": result.status.value,
                "source": result.source.value,
                "evidence_sha256": hashlib.sha256(result.evidence.encode()).hexdigest(),
            }
            if any(payload.get(name) != value for name, value in expected_legacy_fields.items()):
                continue
            migrated_payload = cls._acceptance_audit_payload(result)
            migrated_payload["migration_version"] = "10"
            migrated_payload["legacy_event_id"] = legacy_event_id
            cls._insert_audit_event(
                connection,
                event_type="acceptance.recorded",
                actor="system",
                payload=migrated_payload,
            )

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
        return canonical_digest(
            {
                "actor": actor,
                "created_at": created_at,
                "deployment_id": deployment_id,
                "event_id": event_id,
                "event_type": event_type,
                "payload": json.loads(payload_json),
                "previous_hash": previous_hash,
            }
        )

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
        payload_json = canonical_json(payload)
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
