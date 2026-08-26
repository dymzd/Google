/** Public evidence DTO mapping. IndexedDB records intentionally stay camelCase. */

import type { AuditEventRecord } from "./audit.ts";

type UnknownRecord = Record<string, unknown>;

export function deploymentRunDto(record: UnknownRecord): UnknownRecord {
  const steps = Array.isArray(record.steps) ? (record.steps as UnknownRecord[]) : [];
  // A terminal engine checkpoint is not externally complete until ownership
  // finalization commits. Report it as running during that narrow recovery
  // state so UI/evidence never claims a resource-less success.
  const status = record.finalizationPending === true
    ? "running"
    : String(record.state ?? record.status ?? "interrupted");
  return {
    run_id: String(record.runId ?? ""),
    approval_id: String(record.approvalId ?? ""),
    configuration_hash: String(record.configurationHash ?? ""),
    status,
    started_at: String(record.startedAt ?? ""),
    completed_at: record.finishedAt ?? null,
    operations: steps.map((step, index) => {
      const change = (step.change ?? {}) as UnknownRecord;
      return {
        operation_id:
          typeof step.requestId === "string"
            ? step.requestId
            : `${String(record.runId ?? "run")}:${String(step.index ?? index)}`,
        operation_digest: typeof step.digest === "string" ? step.digest : null,
        resource_key: [change.provider, change.resource_type, change.resource_name]
          .map(String)
          .join(":"),
        action: String(change.action ?? "create"),
        status: String(step.status ?? "pending"),
        error_code: step.error == null ? null : String(step.error),
      };
    }),
  };
}

export function acceptanceResultDto(record: UnknownRecord): UnknownRecord {
  return {
    result_id: String(record.resultId ?? record.id ?? ""),
    run_id: String(record.runId ?? ""),
    test_id: String(record.testId ?? ""),
    case_key: String(record.caseKey ?? "default"),
    status: String(record.status ?? "failed"),
    source: record.source === "system_verified" ? "system" : "operator",
    summary: String(record.summary ?? ""),
    evidence: String(record.evidence ?? ""),
    actor: String(record.actor ?? ""),
    recorded_at: String(record.recordedAt ?? ""),
  };
}

export function auditEventDto(record: AuditEventRecord): UnknownRecord {
  return {
    event_id: record.eventId,
    deployment_id: record.deploymentId,
    event_type: record.eventType,
    actor: record.actor,
    payload: record.payload,
    created_at: record.createdAt,
    previous_hash: record.previousHash,
    event_hash: record.eventHash,
  };
}

export function deploymentResourceDto(record: UnknownRecord): UnknownRecord {
  return {
    run_id: String(record.runId ?? ""),
    resource_key: String(record.resourceKey ?? ""),
    provider: String(record.provider ?? ""),
    resource_type: String(record.resourceType ?? ""),
    resource_name: String(record.resourceName ?? ""),
    owned: record.owned === true,
    shared: record.shared === true,
  };
}
