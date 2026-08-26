/** Cross-store integrity binding for acceptance evidence and audit events. */

import { canonicalDigestSync } from "../domain/canonical.ts";
import { verifyAuditChain, type AuditEventRecord, type ChainVerification } from "./audit.ts";

export type UnknownAcceptanceRecord = Record<string, unknown>;

export function normalizedAcceptanceRecord(
  record: UnknownAcceptanceRecord,
): Record<string, unknown> {
  return {
    result_id: String(record.resultId ?? record.id ?? ""),
    run_id: String(record.runId ?? ""),
    test_id: String(record.testId ?? ""),
    case_key: String(record.caseKey ?? "default"),
    status: String(record.status ?? ""),
    source: String(record.source ?? ""),
    summary: String(record.summary ?? ""),
    evidence: String(record.evidence ?? ""),
    actor: String(record.actor ?? ""),
    recorded_at: String(record.recordedAt ?? ""),
  };
}

export function acceptanceRecordDigest(record: UnknownAcceptanceRecord): string {
  return canonicalDigestSync(normalizedAcceptanceRecord(record));
}

/** Upgrade one 0.2.0 row without changing its public identity or evidence. */
export function migrateLegacyAcceptanceRecord(
  record: UnknownAcceptanceRecord,
): UnknownAcceptanceRecord {
  const resultId = String(record.resultId ?? record.id ?? "");
  if (resultId === "") throw new Error("acceptance-migration-result-id-missing");
  return { ...record, id: resultId, resultId };
}

export function acceptanceAuditPayload(record: UnknownAcceptanceRecord): Record<string, unknown> {
  const normalized = normalizedAcceptanceRecord(record);
  return {
    result_id: normalized.result_id,
    run_id: normalized.run_id,
    test_id: normalized.test_id,
    case_key: normalized.case_key,
    acceptance_record_sha256: acceptanceRecordDigest(record),
  };
}

export interface EvidenceIntegrityVerification extends ChainVerification {
  acceptanceRecordCount: number;
  acceptanceEventCount: number;
  acceptanceValid: boolean;
  reason: string | null;
}

/**
 * Verify a strict one-to-one relation between acceptance rows and digest-bound
 * audit events. Legacy 0.2.0 events remain in the chain but are not bindings;
 * the v3 upgrade appends one `acceptance.integrity_migrated` binding per row.
 */
export function verifyEvidenceIntegrity(
  events: readonly AuditEventRecord[],
  acceptance: readonly UnknownAcceptanceRecord[],
): EvidenceIntegrityVerification {
  const chain = verifyAuditChain(events);
  const bindingEvents = events.filter((event) => {
    if (event.eventType !== "acceptance.recorded" &&
        event.eventType !== "acceptance.integrity_migrated") return false;
    const payload = event.payload;
    return typeof payload.result_id === "string" &&
      typeof payload.acceptance_record_sha256 === "string";
  });
  const result = (acceptanceValid: boolean, reason: string | null) => ({
    ...chain,
    valid: chain.valid && acceptanceValid,
    acceptanceRecordCount: acceptance.length,
    acceptanceEventCount: bindingEvents.length,
    acceptanceValid,
    reason: chain.valid ? reason : "audit-chain-invalid",
  });
  if (!chain.valid) return result(false, "audit-chain-invalid");
  if (bindingEvents.length !== acceptance.length) {
    return result(false, "acceptance-record-event-count-mismatch");
  }

  const rowsById = new Map<string, UnknownAcceptanceRecord>();
  for (const row of acceptance) {
    const id = String(row.resultId ?? row.id ?? "");
    if (id === "" || rowsById.has(id)) {
      return result(false, "acceptance-record-identity-invalid");
    }
    rowsById.set(id, row);
  }
  const seen = new Set<string>();
  for (const event of bindingEvents) {
    const payload = event.payload;
    const id = String(payload.result_id);
    const row = rowsById.get(id);
    if (row === undefined || seen.has(id)) {
      return result(false, "acceptance-event-identity-invalid");
    }
    const expected = acceptanceAuditPayload(row);
    if (
      payload.run_id !== expected.run_id ||
      payload.test_id !== expected.test_id ||
      payload.case_key !== expected.case_key ||
      payload.acceptance_record_sha256 !== expected.acceptance_record_sha256
    ) {
      return result(false, "acceptance-record-digest-mismatch");
    }
    seen.add(id);
  }
  return result(seen.size === acceptance.length, seen.size === acceptance.length
    ? null
    : "acceptance-record-unbound");
}
