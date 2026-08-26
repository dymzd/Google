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
  residualResourceRecords,
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
  readonly scheduled: string[] = [];
  readonly cancelled: string[] = [];
  async schedule(runId: string): Promise<void> { this.scheduled.push(runId); }
  async cancel(runId: string): Promise<void> { this.cancelled.push(runId); }
}

class CountingExecutor implements StepExecutor {
  readonly applied: string[] = [];
  readonly appliedRequestIds: Array<string | undefined> = [];
  readonly rolledBack: string[] = [];
  readonly rolledBackRequestIds: Array<string | undefined> = [];
  /** Throw after recording, simulating a crash once the call has landed. */
  crashAfterApplying: string | null = null;
  failFor: string | null = null;

  async apply(
    target: ResourceChange,
    _spec: DeploymentSpec,
    context?: { requestId: string },
  ): Promise<void> {
    if (this.failFor === target.resource_name) {
      throw new Error(`permanent failure on ${target.resource_name}`);
    }
    this.applied.push(target.resource_name);
    this.appliedRequestIds.push(context?.requestId);
    if (this.crashAfterApplying === target.resource_name) {
      this.crashAfterApplying = null;
      throw new Error("worker terminated after the call landed");
    }
  }

  async rollback(
    target: ResourceChange,
    _spec: DeploymentSpec,
    context: { requestId: string },
  ): Promise<void> {
    this.rolledBack.push(target.resource_name);
    this.rolledBackRequestIds.push(context.requestId);
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
  const scheduler = new NullScheduler();
  const engine = new RunEngine(store, executor, scheduler);
  await store.save(newRun());
  const record = await engine.drain("run-1", SPEC);

  check("uninterrupted run succeeds", record.state === "succeeded", record.state);
  check(
    "every change applied exactly once, in order",
    executor.applied.join(",") === CHANGES.map((c) => c.resource_name).join(","),
    executor.applied.join(","),
  );
  check(
    "terminal success remains durably pending until ownership finalization",
    record.finalizationPending === true && scheduler.cancelled.length === 0,
    JSON.stringify({ pending: record.finalizationPending, cancelled: scheduler.cancelled }),
  );
  const afterWorkerDeath = await store.load("run-1");
  check(
    "a crash before inventory commit leaves a resumable finalization marker",
    afterWorkerDeath?.state === "succeeded" && afterWorkerDeath.finalizationPending === true,
    JSON.stringify(afterWorkerDeath),
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
  const createRequestIds = new Map(
    record.steps.map((step) => [step.change.resource_name, step.requestId]),
  );
  check(
    "rollback uses a distinct deterministic request id for each create operation",
    executor.rolledBackRequestIds.every((rollbackId, index) => {
      const createId = createRequestIds.get(executor.rolledBack[index] ?? "");
      return typeof rollbackId === "string" && rollbackId !== createId &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
          .test(rollbackId);
    }),
    JSON.stringify({
      createRequestIds: Object.fromEntries(createRequestIds),
      rollbackRequestIds: executor.rolledBackRequestIds,
    }),
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
  check(
    "the persisted request id is passed to every external apply",
    executor.appliedRequestIds.every((id, index) => id === after[index]),
    executor.appliedRequestIds.join(","),
  );
}

// -- compensation data is committed before a shared mutation -----------------
{
  const store = new MemoryStore();
  let restored: unknown;
  class CheckpointExecutor implements StepExecutor {
    async apply(
      _target: ResourceChange,
      _spec: DeploymentSpec,
      context: Parameters<StepExecutor["apply"]>[2],
    ): Promise<void> {
      await context.checkpointBeforeImage?.({ etag: "before-shared-write" });
      throw new Error("write outcome could not be confirmed");
    }

    async rollback(
      _target: ResourceChange,
      _spec: DeploymentSpec,
      context: Parameters<NonNullable<StepExecutor["rollback"]>>[2],
    ): Promise<void> {
      restored = context.beforeImage;
    }
  }
  const target = { ...change("shared-policy"), owned_after_apply: true };
  await store.save(
    planRun({
      runId: "run-1",
      approvalId: "approval-1",
      configurationHash: "a".repeat(64),
      changes: [target],
    }),
  );
  const engine = new RunEngine(store, new CheckpointExecutor(), new NullScheduler());
  const record = await engine.drain("run-1", SPEC);
  check("checkpointed before-image survives failure", record.steps[0]?.beforeImage !== undefined);
  check(
    "rollback receives the checkpoint saved before mutation",
    (restored as { etag?: unknown } | undefined)?.etag === "before-shared-write",
    JSON.stringify(restored),
  );
}

// -- rollback failure is terminal but never reported as success ---------------
{
  const store = new MemoryStore();
  class RollbackFailureExecutor extends CountingExecutor {
    override async rollback(): Promise<void> {
      throw new Error("delete denied");
    }
  }
  const executor = new RollbackFailureExecutor();
  executor.failFor = "application";
  await store.save(newRun());
  const engine = new RunEngine(store, executor, new NullScheduler());
  const record = await engine.drain("run-1", SPEC);
  check(
    "a failed compensation is not reported as rolled back",
    record.state === "rollback_failed" && record.finalizationPending === true,
    record.state,
  );
  const residual = residualResourceRecords(record);
  check(
    "failed compensations remain in exact teardown inventory",
    residual.map((item) => item.resourceName).join(",") ===
      "gateway,gateway-iam,application",
    residual.map((item) => item.resourceName).join(","),
  );
  check(
    "residual inventory retains stable Apply request ids",
    residual.every((item) => typeof item.requestId === "string" && item.requestId.length > 0),
  );
}

// -- a shared before-image survives a failed restore for later teardown -------
{
  const record = planRun({
    runId: "run-residual-shared",
    approvalId: "approval-1",
    configurationHash: "a".repeat(64),
    changes: [change("shared-policy", false)],
  });
  record.state = "rollback_failed";
  record.steps[0]!.status = "rollback_failed";
  record.steps[0]!.beforeImage = { etag: "before-shared-write" };
  const residual = residualResourceRecords(record);
  check(
    "failed shared restore remains shared rather than becoming owned",
    residual.length === 1 && residual[0]!.owned === false && residual[0]!.shared === true,
    JSON.stringify(residual),
  );
  check(
    "failed shared restore retains its exact before-image",
    (residual[0]?.beforeImage as { etag?: unknown } | undefined)?.etag ===
      "before-shared-write",
    JSON.stringify(residual[0]?.beforeImage),
  );
}

// -- a modified shared resource is restored, not deleted ----------------------
{
  const store = new MemoryStore();
  const restored: string[] = [];
  class SharedMutationExecutor implements StepExecutor {
    async apply(target: ResourceChange): Promise<{ beforeImage?: unknown }> {
      if (target.resource_name === "later-failure") throw new Error("stop");
      return { beforeImage: { etag: "shared-before" } };
    }

    async rollback(
      target: ResourceChange,
      _spec: DeploymentSpec,
      context: Parameters<NonNullable<StepExecutor["rollback"]>>[2],
    ): Promise<void> {
      if ((context.beforeImage as { etag?: unknown } | undefined)?.etag === "shared-before") {
        restored.push(target.resource_name);
      }
    }
  }
  await store.save(
    planRun({
      runId: "run-1",
      approvalId: "approval-1",
      configurationHash: "a".repeat(64),
      changes: [
        change("shared-iam", false),
        change("later-failure"),
      ],
    }),
  );
  const engine = new RunEngine(store, new SharedMutationExecutor(), new NullScheduler());
  const record = await engine.drain("run-1", SPEC);
  check("shared mutation failure path terminates", record.state === "rolled_back", record.state);
  check(
    "completed shared mutation is restored from its before-image",
    restored.join(",") === "shared-iam",
    restored.join(","),
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
