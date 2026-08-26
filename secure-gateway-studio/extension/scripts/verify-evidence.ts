/** Evidence exports must use the public snake_case schema without data loss. */

import {
  acceptanceResultDto,
  auditEventDto,
  deploymentResourceDto,
  deploymentRunDto,
} from "../src/storage/evidence.ts";
import { buildAuditEvent } from "../src/storage/audit.ts";
import {
  acceptanceAuditPayload,
  acceptanceRecordDigest,
  migrateLegacyAcceptanceRecord,
  verifyEvidenceIntegrity,
} from "../src/storage/acceptance-integrity.ts";

const failures: string[] = [];
let passed = 0;
function check(name: string, condition: boolean): void {
  if (condition) passed += 1;
  else failures.push(name);
}

const run = deploymentRunDto({
  runId: "run-1",
  approvalId: "approval-1",
  configurationHash: "a".repeat(64),
  status: "succeeded",
  startedAt: "2026-01-01T00:00:00Z",
  finishedAt: "2026-01-01T00:01:00Z",
  steps: [{
    index: 0,
    requestId: "request-1",
    digest: "b".repeat(64),
    status: "done",
    error: null,
    change: { provider: "beyondcorp", resource_type: "application", resource_name: "app", action: "create" },
  }],
});
check("run uses public identifiers", run.run_id === "run-1" && run.approval_id === "approval-1");
check("run operations are preserved", Array.isArray(run.operations) && run.operations.length === 1);
check(
  "operation identity matches durable execution and audit evidence",
  (run.operations as Record<string, unknown>[])[0]?.operation_id === "request-1" &&
    (run.operations as Record<string, unknown>[])[0]?.operation_digest === "b".repeat(64),
);

const acceptance = acceptanceResultDto({
  id: "run-1:T05:default",
  runId: "run-1",
  testId: "T05",
  caseKey: "default",
  status: "passed",
  source: "system_verified",
  summary: "exact",
  evidence: "{}",
  actor: "operator@example.com",
  recordedAt: "2026-01-01T00:02:00Z",
});
check("acceptance is included in the public schema", acceptance.test_id === "T05" && acceptance.source === "system");

const storedAcceptance = {
  id: "result-1",
  resultId: "result-1",
  runId: "run-1",
  testId: "T05",
  caseKey: "default",
  status: "passed",
  source: "system_verified",
  summary: "Gateway connectivity verified",
  evidence: "HTTP 200 from the exact application endpoint",
  actor: "operator@example.com",
  recordedAt: "2026-01-01T00:02:00Z",
};
const acceptanceEvent = buildAuditEvent({
  eventId: "event-acceptance-1",
  deploymentId: "run-1",
  eventType: "acceptance.recorded",
  actor: storedAcceptance.actor,
  payload: acceptanceAuditPayload(storedAcceptance),
  createdAt: storedAcceptance.recordedAt,
  previousHash: null,
});
check(
  "full acceptance record digest is bound one-to-one to its audit event",
  verifyEvidenceIntegrity([acceptanceEvent], [storedAcceptance]).valid,
);
check(
  "tampering summary/evidence metadata makes exported integrity false",
  !verifyEvidenceIntegrity(
    [acceptanceEvent],
    [{ ...storedAcceptance, summary: "tampered summary" }],
  ).valid,
);
check(
  "duplicate digest events violate the exact one-to-one relation",
  !verifyEvidenceIntegrity([
    acceptanceEvent,
    buildAuditEvent({
      ...acceptanceEvent,
      eventId: "event-acceptance-duplicate",
      previousHash: acceptanceEvent.eventHash,
    }),
  ], [storedAcceptance]).valid,
);
check(
  "digest covers every canonical acceptance field",
  acceptanceRecordDigest(storedAcceptance) !== acceptanceRecordDigest({
    ...storedAcceptance,
    caseKey: "windows",
  }),
);

// A v2 database already has an old acceptance event whose payload cannot be
// rewritten without breaking the historical chain. The v3 upgrade appends a
// full-record migration binding and preserves the legacy event verbatim.
const legacyRow = {
  id: "run-legacy:T07:macos",
  runId: "run-legacy",
  testId: "T07",
  caseKey: "macos",
  status: "user_confirmed",
  source: "operator_confirmed",
  summary: "Browser reached the app",
  evidence: "Screenshot hash legacy-123",
  actor: "legacy@example.com",
  recordedAt: "2026-01-01T00:00:00Z",
};
const legacyEvent = buildAuditEvent({
  eventId: "legacy-event",
  deploymentId: null,
  eventType: "acceptance.recorded",
  actor: legacyRow.actor,
  payload: {
    run_id: legacyRow.runId,
    test_id: legacyRow.testId,
    status: legacyRow.status,
    source: legacyRow.source,
    evidence_sha256: "0".repeat(64),
  },
  createdAt: legacyRow.recordedAt,
  previousHash: null,
});
const migratedRow = migrateLegacyAcceptanceRecord(legacyRow);
const migrationEvent = buildAuditEvent({
  eventId: "migration-event",
  deploymentId: legacyRow.runId,
  eventType: "acceptance.integrity_migrated",
  actor: "system:migration",
  payload: acceptanceAuditPayload(migratedRow),
  createdAt: "2026-08-24T00:00:00Z",
  previousHash: legacyEvent.eventHash,
});
check(
  "v2 legacy payload plus v3 migration binding verifies without rewriting history",
  verifyEvidenceIntegrity([legacyEvent, migrationEvent], [migratedRow]).valid,
);
check(
  "a migrated legacy row is still fail-closed after row tampering",
  !verifyEvidenceIntegrity(
    [legacyEvent, migrationEvent],
    [{ ...migratedRow, evidence: "changed after migration" }],
  ).valid,
);

const audit = auditEventDto(buildAuditEvent({
  eventId: "event-1",
  deploymentId: null,
  eventType: "acceptance.recorded",
  actor: "operator@example.com",
  payload: { test_id: "T05" },
  createdAt: "2026-01-01T00:02:00Z",
  previousHash: null,
}));
check("audit hash is exported", typeof audit.event_hash === "string" && audit.event_hash.length === 64);

const resource = deploymentResourceDto({
  runId: "run-1",
  resourceKey: "beyondcorp:application:app",
  provider: "beyondcorp",
  resourceType: "application",
  resourceName: "app",
  owned: true,
  shared: false,
});
check("ownership is exported", resource.resource_key === "beyondcorp:application:app" && resource.owned === true);

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} checks`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} evidence checks passed.`);
