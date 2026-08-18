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
import type { ResourceChange } from "../domain/planner.ts";
import type { DeploymentSpec } from "../domain/spec.ts";

export type StepStatus = "pending" | "running" | "done" | "failed";

export interface RunStep {
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
}

export type RunState = "running" | "succeeded" | "failed" | "rolling_back" | "rolled_back";

export interface RunRecord {
  runId: string;
  approvalId: string;
  configurationHash: string;
  state: RunState;
  steps: RunStep[];
}

/** Storage the engine needs. Narrow on purpose so it can be faked in tests. */
export interface RunStore {
  load(runId: string): Promise<RunRecord | null>;
  save(record: RunRecord): Promise<void>;
}

export interface StepExecutor {
  apply(change: ResourceChange, spec: DeploymentSpec): Promise<void>;
  rollback?(change: ResourceChange, spec: DeploymentSpec): Promise<void>;
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
}): RunRecord {
  const steps = options.changes
    // `no_change` and `reuse` describe what is already there; `conflict` is
    // blocked at plan time and must never reach execution.
    .filter((change) => change.action === "create")
    .map((change, index) => ({
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
    runId: options.runId,
    approvalId: options.approvalId,
    configurationHash: options.configurationHash,
    state: "running",
    steps,
  };
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
      await this.scheduler.cancel(runId);
      return record;
    }

    const step = record.steps.find((item) => item.status !== "done");
    if (step === undefined) {
      record.state = "succeeded";
      await this.store.save(record);
      await this.scheduler.cancel(runId);
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
      await this.executor.apply(step.change, spec);
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
    const step = [...record.steps]
      .reverse()
      .find((item) => item.status === "done" && item.change.owned_after_apply);

    if (step === undefined) {
      record.state = "rolled_back";
      await this.store.save(record);
      await this.scheduler.cancel(record.runId);
      return record;
    }

    try {
      await this.executor.rollback?.(step.change, spec);
    } catch (error) {
      // A rollback failure must not strand the run in a loop; record it and
      // move on so the remaining resources are still released.
      step.error = `rollback: ${(error as Error).message}`;
    }
    step.status = "pending";
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
