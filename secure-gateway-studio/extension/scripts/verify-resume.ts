/**
 * Crash-resume behaviour of the apply engine.
 *
 * A Manifest V3 service worker can be torn down between any two operations, so
 * the interesting question is not "does Apply work" but "does Apply still work
 * when the worker dies at the worst possible moment". These checks kill the
 * worker at every step boundary, and separately at the exact point where a
 * mutation has been sent but its completion has not been recorded, and assert
 * that each external operation happens exactly once.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-resume.ts
 */

import {
  MAX_ATTEMPTS,
  RunEngine,
  isActive,
  planRun,
  type RunRecord,
  type RunStore,
  type Scheduler,
  type StepExecutor,
} from "../src/runtime/run-engine.ts";
import type { ResourceChange } from "../src/domain/planner.ts";
import { parseDeploymentSpec, type DeploymentSpec } from "../src/domain/spec.ts";

const failures: string[] = [];
let passed = 0;

function check(name: string, condition: boolean, detail = ""): void {
  if (condition) passed += 1;
  else failures.push(`${name}${detail ? `\n      ${detail}` : ""}`);
}

const SPEC: DeploymentSpec = parseDeploymentSpec({
  project_id: "enterprise-secgw-01",
  mode: "poc",
  target_ou_id: "03-test-ou",
  managed_chrome_access_level: "accessPolicies/123456789/accessLevels/managed_chrome",
  test_ou_confirmed: true,
  principals: [{ type: "group", value: "secure-access@example.com" }],
  backend_kind: "direct_https",
  network_strategy: "existing",
  vpc_name: "private-app-vpc",
  subnet_name: null,
  source_image: null,
  certificate_strategy: "public_trusted",
  existing_backend_url: "https://10.20.0.10:8443",
  existing_backend_location: "gcp",
  existing_backend_connectivity_confirmed: true,
});

function change(name: string, owned = true): ResourceChange {
  return {
    provider: "beyondcorp",
    resource_type: "application",
    resource_name: name,
    action: "create",
    risk: "high",
    summary: name,
    owned_after_apply: owned,
    dependencies: [],
  };
}

const CHANGES: ResourceChange[] = [
  change("gateway"),
  change("gateway-iam"),
  change("upstream-access", false),
  change("application"),
  change("application-iam"),
];

/**
 * Storage that survives "worker death" by holding a serialised copy, exactly
 * as IndexedDB would.
 */
class MemoryStore implements RunStore {
  private serialised = new Map<string, string>();

  async load(runId: string): Promise<RunRecord | null> {
    const raw = this.serialised.get(runId);
    return raw === undefined ? null : (JSON.parse(raw) as RunRecord);
  }

  async save(record: RunRecord): Promise<void> {
    this.serialised.set(record.runId, JSON.stringify(record));
  }
}

class NullScheduler implements Scheduler {
  async schedule(): Promise<void> {}
  async cancel(): Promise<void> {}
}

class CountingExecutor implements StepExecutor {
  readonly applied: string[] = [];
  readonly rolledBack: string[] = [];
  /** Throw after recording, simulating a crash once the call has landed. */
  crashAfterApplying: string | null = null;
  failFor: string | null = null;

  async apply(target: ResourceChange): Promise<void> {
    if (this.failFor === target.resource_name) {
      throw new Error(`permanent failure on ${target.resource_name}`);
    }
    this.applied.push(target.resource_name);
    if (this.crashAfterApplying === target.resource_name) {
      this.crashAfterApplying = null;
      throw new Error("worker terminated after the call landed");
    }
  }

  async rollback(target: ResourceChange): Promise<void> {
    this.rolledBack.push(target.resource_name);
  }
}

function newRun(): RunRecord {
  return planRun({
    runId: "run-1",
    approvalId: "approval-1",
    configurationHash: "a".repeat(64),
    changes: CHANGES,
  });
}

// -- happy path ---------------------------------------------------------------
{
  const store = new MemoryStore();
  const executor = new CountingExecutor();
  const engine = new RunEngine(store, executor, new NullScheduler());
  await store.save(newRun());
  const record = await engine.drain("run-1", SPEC);

  check("uninterrupted run succeeds", record.state === "succeeded", record.state);
  check(
    "every change applied exactly once, in order",
    executor.applied.join(",") === CHANGES.map((c) => c.resource_name).join(","),
    executor.applied.join(","),
  );
}

// -- worker dies at every step boundary --------------------------------------
{
  // Each iteration runs N ticks, discards the engine entirely (as a terminated
  // worker would), then resumes from storage alone.
  for (let killAfter = 1; killAfter <= CHANGES.length; killAfter += 1) {
    const store = new MemoryStore();
    const executor = new CountingExecutor();
    await store.save(newRun());

    let engine = new RunEngine(store, executor, new NullScheduler());
    for (let tick = 0; tick < killAfter; tick += 1) {
      await engine.tick("run-1", SPEC);
    }
    // Worker torn down: nothing survives but the store.
    engine = new RunEngine(store, executor, new NullScheduler());
    const record = await engine.drain("run-1", SPEC);

    check(
      `resumes to success after termination at step ${killAfter}`,
      record.state === "succeeded",
      record.state,
    );
    const counts = new Map<string, number>();
    for (const name of executor.applied) counts.set(name, (counts.get(name) ?? 0) + 1);
    const duplicated = [...counts.entries()].filter(([, count]) => count > 1);
    check(
      `no duplicate work after termination at step ${killAfter}`,
      duplicated.length === 0,
      JSON.stringify(duplicated),
    );
    check(
      `all work completed after termination at step ${killAfter}`,
      counts.size === CHANGES.length,
      `${counts.size} of ${CHANGES.length}`,
    );
  }
}

// -- crash between the call landing and the record being written --------------
{
  // The genuinely hard case: the mutation reached Google, then the worker died
  // before "done" was committed. Storage cannot distinguish this from "never
  // ran", so recovery must re-run and the executor's idempotency must absorb it.
  const store = new MemoryStore();
  const executor = new CountingExecutor();
  executor.crashAfterApplying = "upstream-access";
  const engine = new RunEngine(store, executor, new NullScheduler());
  await store.save(newRun());
  const record = await engine.drain("run-1", SPEC);

  check("run still succeeds after a mid-write crash", record.state === "succeeded", record.state);
  const repeats = executor.applied.filter((name) => name === "upstream-access").length;
  check(
    "the ambiguous step is retried exactly once, not abandoned",
    repeats === 2,
    `applied ${repeats} time(s)`,
  );
  const step = record.steps.find((item) => item.change.resource_name === "upstream-access");
  check("the retried step records its attempts", (step?.attempts ?? 0) === 2, String(step?.attempts));
}

// -- permanent failure rolls back owned resources in reverse ------------------
{
  const store = new MemoryStore();
  const executor = new CountingExecutor();
  executor.failFor = "application";
  const engine = new RunEngine(store, executor, new NullScheduler());
  await store.save(newRun());
  const record = await engine.drain("run-1", SPEC);

  check("a permanently failing step ends rolled back", record.state === "rolled_back", record.state);
  check(
    "the failing step is retried up to the attempt limit",
    (record.steps.find((s) => s.change.resource_name === "application")?.attempts ?? 0) ===
      MAX_ATTEMPTS,
  );
  check(
    "rollback runs in reverse order",
    executor.rolledBack.join(",") === "gateway-iam,gateway",
    executor.rolledBack.join(","),
  );
  check(
    "shared resources are never rolled back",
    !executor.rolledBack.includes("upstream-access"),
    executor.rolledBack.join(","),
  );
}

// -- rollback also survives termination ---------------------------------------
{
  const store = new MemoryStore();
  const executor = new CountingExecutor();
  executor.failFor = "application";
  await store.save(newRun());

  let engine = new RunEngine(store, executor, new NullScheduler());
  for (let tick = 0; tick < 6; tick += 1) await engine.tick("run-1", SPEC);
  engine = new RunEngine(store, executor, new NullScheduler());
  const record = await engine.drain("run-1", SPEC);

  check("rollback completes after termination", record.state === "rolled_back", record.state);
  const counts = new Map<string, number>();
  for (const name of executor.rolledBack) counts.set(name, (counts.get(name) ?? 0) + 1);
  check(
    "no resource is rolled back twice",
    [...counts.values()].every((count) => count === 1),
    JSON.stringify([...counts.entries()]),
  );
}

// -- the idempotency token survives a restart ---------------------------------
{
  // If the token were regenerated on resume, a retried create would be a second
  // create rather than a no-op. This is the crash path, so it is the case that
  // matters most.
  const store = new MemoryStore();
  const executor = new CountingExecutor();
  await store.save(newRun());

  let engine = new RunEngine(store, executor, new NullScheduler());
  await engine.tick("run-1", SPEC);
  const before = (await store.load("run-1"))!.steps.map((step) => step.requestId);

  engine = new RunEngine(store, executor, new NullScheduler());
  await engine.drain("run-1", SPEC);
  const after = (await store.load("run-1"))!.steps.map((step) => step.requestId);

  check("request ids persist across termination", before.join(",") === after.join(","));
  check(
    "each step carries a distinct request id",
    new Set(after).size === after.length,
    after.join(","),
  );
  check(
    "request ids are UUIDs",
    after.every((id) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)),
  );
}

// -- non-create actions never execute -----------------------------------------
{
  const store = new MemoryStore();
  const executor = new CountingExecutor();
  const engine = new RunEngine(store, executor, new NullScheduler());
  await store.save(
    planRun({
      runId: "run-1",
      approvalId: "approval-1",
      configurationHash: "a".repeat(64),
      changes: [
        change("created"),
        { ...change("reused"), action: "reuse" },
        { ...change("unchanged"), action: "no_change" },
        { ...change("conflicted"), action: "conflict" },
      ],
    }),
  );
  const record = await engine.drain("run-1", SPEC);

  check("only create actions execute", executor.applied.join(",") === "created", executor.applied.join(","));
  check("run succeeds", record.state === "succeeded" && !isActive(record.state));
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} checks\n`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} crash-resume checks passed.`);
