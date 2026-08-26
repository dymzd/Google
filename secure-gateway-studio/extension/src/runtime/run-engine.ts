/**
 * Resumable apply engine.
 *
 * The local application ran Apply as one long function with in-process polling.
 * A Manifest V3 service worker is terminated whenever the browser decides it is
 * idle -- mid-Apply, between two Google calls, with resources already created.
 * So the loop is inverted: instead of a function that runs to completion, this
 * is a state machine that persists after every step and can be resumed from
 * nothing but storage.
 *
 * The product specification tracks cross-restart mutation resume as deferred
 * (Phase C). Under MV3 it is not deferrable: an Apply that cannot resume leaves
 * a half-built deployment with no owner.
 *
 * Exactly-once is the property that matters, and it is achieved by ordering
 * rather than by locking:
 *
 *   1. mark the step `running` and commit,
 *   2. perform the external call,
 *   3. mark the step `done` and commit.
 *
 * A crash between 1 and 2 leaves a `running` step that never ran; a crash
 * between 2 and 3 leaves a `running` step that did. The two are
 * indistinguishable from storage alone, so recovery re-runs the step and the
 * executor's own idempotency absorbs the repeat. That is why every mutation is
 * keyed by its request digest: a repeated create must reconcile, not duplicate.
 */

import { canonicalDigestSync } from "../domain/canonical.ts";
import { compensationCapability } from "../domain/compensation.ts";
import type {
  PublicCertificateBinding,
  ResourceChange,
  SourceImageBinding,
} from "../domain/planner.ts";
import type { DeploymentSpec } from "../domain/spec.ts";

export const LIFECYCLE_SCHEMA_VERSION = 1;

export type StepStatus = "pending" | "running" | "done" | "failed" | "rollback_failed";

export interface RunStep {
  /** Durable lifecycle schema; absent only on records created by older builds. */
  schemaVersion?: number;
  index: number;
  change: ResourceChange;
  /** Digest of the intended operation; the idempotency key. */
  digest: string;
  /**
   * Token Google deduplicates creates by.
   *
   * Generated once when the run is planned and persisted with the step, so a
   * retry after a service-worker restart presents the same value. Deriving it
   * from anything in memory would produce a fresh token on the retry path --
   * which under Manifest V3 is the normal path -- and create a duplicate
   * resource instead of reconciling.
   */
  requestId: string;
  status: StepStatus;
  attempts: number;
  error: string | null;
  /** Provider before-image needed to restore a modified shared resource. */
  beforeImage?: unknown;
}

export type RunState =
  | "running"
  | "interrupted"
  | "succeeded"
  | "failed"
  | "rolling_back"
  | "rolled_back"
  | "rollback_failed"
  | "rollback_unavailable"
  | "deleted";

export interface RunRecord {
  /** Durable lifecycle schema; absent only on records created by older builds. */
  schemaVersion?: number;
  runId: string;
  approvalId: string;
  configurationHash: string;
  /** Exact immutable public-certificate input copied from the approved plan. */
  publicCertificateBinding?: PublicCertificateBinding | null;
  /** Exact immutable Compute image identity copied from the approved plan. */
  sourceImageBinding?: SourceImageBinding | null;
  state: RunState;
  steps: RunStep[];
  /** Terminal state still needs an atomic ownership-inventory commit. */
  finalizationPending?: boolean;
  finalizedAt?: string | null;
  /** Authentication interruption retains the exact engine phase for Resume. */
  interruptedFrom?: "running" | "rolling_back";
  reauthRequired?: boolean;
  interruptionErrorCode?: string;
}

/**
 * Google Compute request IDs deduplicate across mutation methods in a scope.
 * Reusing a create ID for delete makes Google reject compensation because the
 * existing operation belongs to a different API method. Derive a separate,
 * stable UUID so rollback retries remain idempotent across MV3 restarts.
 */
export function rollbackRequestId(createRequestId: string): string {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      .test(createRequestId)
  ) {
    throw new Error("Invalid create request id for rollback");
  }
  const digest = canonicalDigestSync({
    create_request_id: createRequestId.toLowerCase(),
    phase: "rollback-v1",
  });
  const variant = ((Number.parseInt(digest[16] as string, 16) & 0x3) | 0x8).toString(16);
  return `${digest.slice(0, 8)}-${digest.slice(8, 12)}-5${digest.slice(13, 16)}-` +
    `${variant}${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
}

/** Storage the engine needs. Narrow on purpose so it can be faked in tests. */
export interface RunStore {
  load(runId: string): Promise<RunRecord | null>;
  save(record: RunRecord): Promise<void>;
}

export interface StepExecutor {
  apply(
    change: ResourceChange,
    spec: DeploymentSpec,
    context: StepExecutionContext,
  ): Promise<StepApplyResult | void>;
  rollback?(
    change: ResourceChange,
    spec: DeploymentSpec,
    context: StepExecutionContext,
  ): Promise<void>;
}

export interface RunAuditTransition {
  eventType: string;
  payload: Record<string, unknown>;
}

function operationPayload(record: RunRecord, step: RunStep): Record<string, unknown> {
  return {
    run_id: record.runId,
    operation_id: step.requestId,
    operation_digest: step.digest,
    resource_key:
      `${step.change.provider}:${step.change.resource_type}:${step.change.resource_name}`,
    action: step.change.action,
    owned_after_apply: step.change.owned_after_apply,
    attempt: step.attempts,
  };
}

/**
 * Derive audit evidence from two durable run snapshots.
 *
 * Keeping this pure makes duplicate suppression mechanical: saving an
 * unchanged checkpoint yields no events. The IndexedDB adapter appends these
 * events in the same transaction as the new snapshot, so the hash chain can
 * never claim an operation transition that the run record did not commit.
 */
export function runAuditTransitions(
  previous: RunRecord | null,
  next: RunRecord,
): RunAuditTransition[] {
  if (previous === null) return [];
  const events: RunAuditTransition[] = [];
  const previousSteps = new Map(previous.steps.map((step) => [step.digest, step]));

  for (const step of next.steps) {
    const old = previousSteps.get(step.digest);
    if (
      step.status === "running" &&
      (old?.status !== "running" || old.attempts !== step.attempts)
    ) {
      events.push({
        eventType: "operation.started",
        payload: operationPayload(next, step),
      });
      continue;
    }
    if (old?.status === "running" && step.status === "done") {
      events.push({
        eventType: "operation.completed",
        payload: { ...operationPayload(next, step), status: "succeeded", error_code: null },
      });
      continue;
    }
    if (
      previous.state === "rolling_back" && next.state === "rolling_back" &&
      (old?.status === "done" || old?.status === "failed") && step.status === "pending"
    ) {
      events.push({
        eventType: "operation.completed",
        payload: { ...operationPayload(next, step), status: "rolled_back", error_code: null },
      });
      continue;
    }
    if (
      (old?.status === "running" && step.status === "pending" && step.error !== null) ||
      (step.status === "failed" && old?.status !== "failed") ||
      (step.status === "rollback_failed" && old?.status !== "rollback_failed")
    ) {
      events.push({
        eventType: "operation.completed",
        payload: {
          ...operationPayload(next, step),
          status: step.status === "rollback_failed" ? "rollback_failed" : "failed",
          error_code: step.error,
        },
      });
    }
  }

  const terminalEvent: Partial<Record<RunState, string>> = {
    succeeded: "run.succeeded",
    rolled_back: "run.rolled_back",
    rollback_failed: "run.rollback_failed",
  };
  const eventType = terminalEvent[next.state];
  if (eventType !== undefined && previous.state !== next.state) {
    events.push({
      eventType,
      payload: {
        run_id: next.runId,
        approval_id: next.approvalId,
        configuration_hash: next.configurationHash,
        status: next.state,
      },
    });
  }
  return events;
}

export interface StepExecutionContext {
  runId: string;
  stepIndex: number;
  /** Stable across retries and service-worker restarts. */
  requestId: string;
  /** Persisted result of the original apply, when the provider modified state. */
  beforeImage?: unknown;
  /** Commit compensation data before the provider mutates shared state. */
  checkpointBeforeImage?: (beforeImage: unknown) => Promise<void>;
}

export interface StepApplyResult {
  beforeImage?: unknown;
}

export interface ResourceOwnershipRecord {
  resourceKey: string;
  provider: string;
  resourceType: string;
  resourceName: string;
  owned: boolean;
  shared: boolean;
  /** Provider state required to restore an in-place mutation. */
  beforeImage?: unknown;
  /** Stable Apply token retained for evidence and recovery. */
  requestId?: string;
}

/** Convert a successful plan into the narrow ownership inventory teardown uses. */
export function resourceRecordsForPlan(
  changes: readonly ResourceChange[],
): ResourceOwnershipRecord[] {
  return changes
    .filter((change) => change.action === "create" || change.action === "reuse")
    .map((change) => {
      const owned = change.action === "create" && change.owned_after_apply;
      return {
        resourceKey: `${change.provider}:${change.resource_type}:${change.resource_name}`,
        provider: change.provider,
        resourceType: change.resource_type,
        resourceName: change.resource_name,
        owned,
        shared: change.action === "reuse" || !owned,
      };
    });
}

/**
 * Inventory the resources that still need compensation after rollback could
 * not finish.
 *
 * A successfully compensated step is reset to `pending` by `rollbackStep`, so
 * only the candidates below can still exist externally. Persisting this
 * narrow residual set lets an operator retry teardown without ever claiming
 * ownership of a resource that rollback already removed.
 */
export function residualResourceRecords(record: RunRecord): ResourceOwnershipRecord[] {
  if (record.state !== "rollback_failed" && record.state !== "rollback_unavailable") {
    return [];
  }

  return record.steps
    .filter(
      (step) =>
        step.status === "rollback_failed" ||
        (step.status === "done" &&
          (step.change.owned_after_apply || step.beforeImage !== undefined)) ||
        (step.status === "failed" &&
          (step.change.owned_after_apply || step.beforeImage !== undefined)),
    )
    .map((step) => {
      const owned = step.change.owned_after_apply;
      return {
        resourceKey:
          `${step.change.provider}:${step.change.resource_type}:${step.change.resource_name}`,
        provider: step.change.provider,
        resourceType: step.change.resource_type,
        resourceName: step.change.resource_name,
        owned,
        shared: !owned,
        beforeImage: step.beforeImage,
        requestId: step.requestId,
      };
    });
}

export interface RollbackCompensationIssue {
  stepIndex: number;
  resourceKey: string;
  errorCode: string;
}

export interface RollbackCompensationPreflight {
  available: boolean;
  candidateStepIndexes: number[];
  issues: RollbackCompensationIssue[];
}

function rollbackCandidate(step: RunStep): boolean {
  return step.status === "rollback_failed" ||
    (step.status === "done" &&
      (step.change.owned_after_apply || step.beforeImage !== undefined)) ||
    (step.status === "failed" &&
      (step.change.owned_after_apply || step.beforeImage !== undefined));
}

/** Classify an entire rollback without touching a provider or mutable cache. */
export function rollbackCompensationPreflight(
  record: Pick<RunRecord, "steps">,
): RollbackCompensationPreflight {
  const candidates = record.steps.filter(rollbackCandidate);
  const inspected = record.steps.filter(
    (step) => rollbackCandidate(step) || step.beforeImage !== undefined,
  );
  const issues = inspected.flatMap((step): RollbackCompensationIssue[] => {
    const capability = compensationCapability(step.change, step.beforeImage);
    return capability.available
      ? []
      : [{
          stepIndex: step.index,
          resourceKey:
            `${step.change.provider}:${step.change.resource_type}:${step.change.resource_name}`,
          errorCode: capability.errorCode,
        }];
  });
  return {
    available: issues.length === 0,
    candidateStepIndexes: [...new Set([
      ...candidates.map((step) => step.index),
      ...issues.map((issue) => issue.stepIndex),
    ])],
    issues,
  };
}

/** Wakes the engine again after the worker may have been torn down. */
export interface Scheduler {
  schedule(runId: string): Promise<void>;
  cancel(runId: string): Promise<void>;
}

export const MAX_ATTEMPTS = 3;

export function planRun(options: {
  runId: string;
  approvalId: string;
  configurationHash: string;
  changes: ResourceChange[];
  publicCertificateBinding?: PublicCertificateBinding | null;
  sourceImageBinding?: SourceImageBinding | null;
}): RunRecord {
  const steps = options.changes
    // `no_change` and `reuse` describe what is already there; `conflict` is
    // blocked at plan time and must never reach execution.
    .filter((change) => change.action === "create")
    .map((change, index) => ({
      schemaVersion: LIFECYCLE_SCHEMA_VERSION,
      index,
      change,
      digest: canonicalDigestSync({
        run_id: options.runId,
        provider: change.provider,
        resource_type: change.resource_type,
        resource_name: change.resource_name,
      }),
      requestId: crypto.randomUUID(),
      status: "pending" as StepStatus,
      attempts: 0,
      error: null,
    }));
  return {
    schemaVersion: LIFECYCLE_SCHEMA_VERSION,
    runId: options.runId,
    approvalId: options.approvalId,
    configurationHash: options.configurationHash,
    publicCertificateBinding: options.publicCertificateBinding ?? null,
    sourceImageBinding: options.sourceImageBinding ?? null,
    state: "running",
    steps,
    finalizationPending: false,
    finalizedAt: null,
  };
}

function requireFinalization(record: RunRecord): void {
  record.finalizationPending = true;
  record.finalizedAt = null;
}

export class RunEngine {
  private readonly store: RunStore;
  private readonly executor: StepExecutor;
  private readonly scheduler: Scheduler;

  constructor(store: RunStore, executor: StepExecutor, scheduler: Scheduler) {
    this.store = store;
    this.executor = executor;
    this.scheduler = scheduler;
  }

  /**
   * Advance the run by exactly one step, then return.
   *
   * One step per invocation is deliberate: it bounds how much work a single
   * service-worker lifetime has to survive, and makes the resume path the
   * normal path rather than an exceptional one.
   */
  async tick(runId: string, spec: DeploymentSpec): Promise<RunRecord> {
    const record = await this.store.load(runId);
    if (record === null) throw new Error(`Unknown run ${runId}`);

    if (record.state === "rolling_back") return this.rollbackStep(record, spec);
    if (record.state !== "running") {
      if (record.finalizationPending === true) await this.scheduler.schedule(runId);
      else await this.scheduler.cancel(runId);
      return record;
    }

    const step = record.steps.find((item) => item.status !== "done");
    if (step === undefined) {
      record.state = "succeeded";
      requireFinalization(record);
      await this.store.save(record);
      await this.scheduler.schedule(runId);
      return record;
    }

    if (step.status === "failed") {
      record.state = "rolling_back";
      await this.store.save(record);
      await this.scheduler.schedule(runId);
      return record;
    }

    // Commit the intent before acting. A crash after this point may or may not
    // have performed the call; recovery re-runs it and relies on the
    // executor's idempotency.
    step.status = "running";
    step.attempts += 1;
    await this.store.save(record);

    try {
      const result = await this.executor.apply(step.change, spec, {
        runId: record.runId,
        stepIndex: step.index,
        requestId: step.requestId,
        beforeImage: step.beforeImage,
        checkpointBeforeImage: async (beforeImage: unknown) => {
          step.beforeImage = structuredClone(beforeImage);
          await this.store.save(record);
        },
      });
      if (result !== undefined && result.beforeImage !== undefined) {
        step.beforeImage = result.beforeImage;
      }
      step.status = "done";
      step.error = null;
      await this.store.save(record);
    } catch (error) {
      step.error = (error as Error).message;
      if (step.attempts >= MAX_ATTEMPTS) {
        step.status = "failed";
        record.state = "rolling_back";
      } else {
        // Leave it pending so the next tick retries; attempts is already
        // incremented, so a permanently failing step cannot spin forever.
        step.status = "pending";
      }
      await this.store.save(record);
    }

    await this.scheduler.schedule(runId);
    return record;
  }

  /**
   * Undo completed steps in reverse order.
   *
   * Only steps this run completed are touched. Anything it merely reused stays
   * put -- the planner already marked those `owned_after_apply: false`, and
   * deleting a shared gateway because one application failed would take down
   * every other application on it.
   */
  private async rollbackStep(record: RunRecord, spec: DeploymentSpec): Promise<RunRecord> {
    if (this.executor.rollback === undefined) {
      record.state = "rollback_unavailable";
      requireFinalization(record);
      await this.store.save(record);
      await this.scheduler.schedule(record.runId);
      return record;
    }

    const step = [...record.steps]
      .reverse()
      .find(
        (item) =>
          (item.status === "done" &&
            (item.change.owned_after_apply || item.beforeImage !== undefined)) ||
          (item.status === "failed" && item.beforeImage !== undefined),
      );

    if (step === undefined) {
      record.state = record.steps.some((item) => item.status === "rollback_failed")
        ? "rollback_failed"
        : "rolled_back";
      requireFinalization(record);
      await this.store.save(record);
      await this.scheduler.schedule(record.runId);
      return record;
    }

    try {
      await this.executor.rollback(step.change, spec, {
        runId: record.runId,
        stepIndex: step.index,
        requestId: rollbackRequestId(step.requestId),
        beforeImage: step.beforeImage,
      });
      step.status = "pending";
      step.error = null;
    } catch (error) {
      // A rollback failure must not strand the run in a loop; record it and
      // move on so the remaining resources are still released.
      step.error = `rollback: ${(error as Error).message}`;
      step.status = "rollback_failed";
    }
    await this.store.save(record);
    await this.scheduler.schedule(record.runId);
    return record;
  }

  /**
   * Drive a run to a terminal state.
   *
   * Used when the worker happens to stay alive. It is not the contract: the
   * contract is that `tick` alone, called repeatedly by an alarm, gets there.
   */
  async drain(runId: string, spec: DeploymentSpec, maxTicks = 500): Promise<RunRecord> {
    let record = await this.store.load(runId);
    if (record === null) throw new Error(`Unknown run ${runId}`);
    for (let tick = 0; tick < maxTicks && isActive(record.state); tick += 1) {
      record = await this.tick(runId, spec);
    }
    return record;
  }
}

export function isActive(state: RunState): boolean {
  return state === "running" || state === "rolling_back";
}
