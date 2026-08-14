/**
 * Audit chain. Port of the hash-chain half of `storage/repository.py`.
 *
 * Each event carries the digest of the previous one, so removing or editing an
 * event breaks every hash after it. `verify_audit_chain` in the Python
 * implementation is what turns the event log into evidence; this reproduces it
 * exactly, including the field set and its ordering, because the digest is
 * taken over the canonical form and any difference changes every hash.
 *
 * The Python side computes `payload_json` with `canonical_json` and then hashes
 * a record that embeds the *parsed* payload -- not the string. That indirection
 * is preserved here: it is why a payload that round-trips differently would
 * change the chain.
 */

import { canonicalDigestSync, canonicalJson } from "../domain/canonical.ts";

export interface AuditEventInput {
  eventId: string;
  deploymentId: string | null;
  eventType: string;
  actor: string;
  payload: Record<string, unknown>;
  createdAt: string;
  previousHash: string | null;
}

export interface AuditEventRecord extends AuditEventInput {
  payloadJson: string;
  eventHash: string;
}

/**
 * Digest of one event, matching `StateRepository._audit_hash`.
 *
 * Synchronous so it can run inside the IndexedDB transaction that reads the
 * previous hash and writes this event. Splitting those across transactions
 * would let a concurrent write interleave and silently fork the chain.
 */
export function auditHash(input: AuditEventInput): string {
  return canonicalDigestSync({
    actor: input.actor,
    created_at: input.createdAt,
    deployment_id: input.deploymentId,
    event_id: input.eventId,
    event_type: input.eventType,
    payload: input.payload,
    previous_hash: input.previousHash,
  });
}

export function buildAuditEvent(input: AuditEventInput): AuditEventRecord {
  return {
    ...input,
    payloadJson: canonicalJson(input.payload),
    eventHash: auditHash(input),
  };
}

export interface ChainVerification {
  valid: boolean;
  eventCount: number;
  chainHeadHash: string | null;
  /** Index of the first event whose hash or link does not hold. */
  brokenAt: number | null;
}

/** Recompute every link. Mirrors `StateRepository.verify_audit_chain`. */
export function verifyAuditChain(events: readonly AuditEventRecord[]): ChainVerification {
  let previous: string | null = null;
  for (const [index, event] of events.entries()) {
    if (event.previousHash !== previous) {
      return { valid: false, eventCount: events.length, chainHeadHash: null, brokenAt: index };
    }
    const expected = auditHash({
      eventId: event.eventId,
      deploymentId: event.deploymentId,
      eventType: event.eventType,
      actor: event.actor,
      payload: JSON.parse(event.payloadJson) as Record<string, unknown>,
      createdAt: event.createdAt,
      previousHash: event.previousHash,
    });
    if (expected !== event.eventHash) {
      return { valid: false, eventCount: events.length, chainHeadHash: null, brokenAt: index };
    }
    previous = event.eventHash;
  }
  return {
    valid: true,
    eventCount: events.length,
    chainHeadHash: previous,
    brokenAt: null,
  };
}
