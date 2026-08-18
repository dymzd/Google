/**
 * Audit chain parity and tamper detection.
 *
 * The chain is what makes the event log evidence rather than a list. These
 * checks confirm the ported digest matches the Python reference for a known
 * record, that a modified event breaks verification, and that a removed event
 * does too.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-audit.ts
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { auditHash, buildAuditEvent, verifyAuditChain } from "../src/storage/audit.ts";
import type { AuditEventRecord } from "../src/storage/audit.ts";

const failures: string[] = [];
let passed = 0;

function check(name: string, condition: boolean, detail = ""): void {
  if (condition) passed += 1;
  else failures.push(`${name}${detail ? `\n      ${detail}` : ""}`);
}

function chain(count: number): AuditEventRecord[] {
  const events: AuditEventRecord[] = [];
  let previousHash: string | null = null;
  for (let index = 0; index < count; index += 1) {
    const event = buildAuditEvent({
      eventId: `event-${index}`,
      deploymentId: index % 2 === 0 ? null : "deployment-1",
      eventType: index === 0 ? "plan.consumed" : "run.started",
      actor: "operator@example.com",
      payload: { index, configuration_hash: "a".repeat(64) },
      createdAt: `2026-08-04T0${index}:00:00+00:00`,
      previousHash,
    });
    events.push(event);
    previousHash = event.eventHash;
  }
  return events;
}

// -- parity with the Python reference chain -----------------------------------
{
  interface GoldenEvent {
    event_id: string;
    deployment_id: string | null;
    event_type: string;
    actor: string;
    payload: Record<string, unknown>;
    payload_json: string;
    created_at: string;
    previous_hash: string | null;
    event_hash: string;
  }

  const goldenPath = resolve(
    dirname(fileURLToPath(import.meta.url)),
    "../../backend/tests/fixtures/audit/golden.json",
  );
  const golden = JSON.parse(readFileSync(goldenPath, "utf8")) as {
    chain_head_hash: string;
    events: GoldenEvent[];
  };

  const ported: AuditEventRecord[] = [];
  for (const event of golden.events) {
    const built = buildAuditEvent({
      eventId: event.event_id,
      deploymentId: event.deployment_id,
      eventType: event.event_type,
      actor: event.actor,
      payload: event.payload,
      createdAt: event.created_at,
      previousHash: event.previous_hash,
    });
    check(
      `golden ${event.event_type}: payload serialises identically`,
      built.payloadJson === event.payload_json,
      `python=${JSON.stringify(event.payload_json)} extension=${JSON.stringify(built.payloadJson)}`,
    );
    check(
      `golden ${event.event_type}: digest matches Python`,
      built.eventHash === event.event_hash,
      `python=${event.event_hash} extension=${built.eventHash}`,
    );
    ported.push(built);
  }

  const verified = verifyAuditChain(ported);
  check("ported chain verifies end to end", verified.valid, `brokenAt=${verified.brokenAt}`);
  check(
    "ported chain head matches Python",
    verified.chainHeadHash === golden.chain_head_hash,
    `python=${golden.chain_head_hash} extension=${verified.chainHeadHash}`,
  );
}

// -- digest shape matches the Python record -----------------------------------
{
  // Field set and ordering are fixed by the canonical form; a renamed or
  // reordered field changes every hash the product has issued.
  const digest = auditHash({
    eventId: "3f2c",
    deploymentId: null,
    eventType: "run.started",
    actor: "operator@example.com",
    payload: { run_id: "abc" },
    createdAt: "2026-08-04T00:00:00+00:00",
    previousHash: null,
  });
  check("digest is 64 hex characters", /^[0-9a-f]{64}$/.test(digest), digest);

  const reordered = auditHash({
    previousHash: null,
    createdAt: "2026-08-04T00:00:00+00:00",
    payload: { run_id: "abc" },
    actor: "operator@example.com",
    eventType: "run.started",
    deploymentId: null,
    eventId: "3f2c",
  });
  check("digest is independent of argument order", digest === reordered);
}

// -- an intact chain verifies -------------------------------------------------
{
  const events = chain(5);
  const result = verifyAuditChain(events);
  check("intact chain verifies", result.valid && result.brokenAt === null);
  check("reports the chain head", result.chainHeadHash === events[4].eventHash);
  check("reports the event count", result.eventCount === 5);
}

// -- an empty chain is valid --------------------------------------------------
{
  const result = verifyAuditChain([]);
  check("empty chain is valid with a null head", result.valid && result.chainHeadHash === null);
}

// -- tampering is detected ----------------------------------------------------
{
  const events = chain(5);
  const tampered = [...events];
  tampered[2] = {
    ...tampered[2],
    payloadJson: JSON.stringify({ index: 99, configuration_hash: "b".repeat(64) }),
  };
  const result = verifyAuditChain(tampered);
  check("edited payload breaks the chain at that event", !result.valid && result.brokenAt === 2);
}

{
  const events = chain(5);
  const removed = events.filter((_, index) => index !== 2);
  const result = verifyAuditChain(removed);
  check("removed event breaks the chain", !result.valid && result.brokenAt === 2);
}

{
  const events = chain(5);
  const reordered = [events[0], events[2], events[1], events[3], events[4]];
  const result = verifyAuditChain(reordered);
  check("reordered events break the chain", !result.valid && result.brokenAt === 1);
}

{
  const events = chain(3);
  const relinked = [...events];
  relinked[1] = { ...relinked[1], previousHash: "0".repeat(64) };
  const result = verifyAuditChain(relinked);
  check("rewritten link breaks the chain", !result.valid && result.brokenAt === 1);
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} checks\n`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} audit chain checks passed.`);
