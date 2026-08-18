/**
 * State repository. Port of `storage/repository.py` onto IndexedDB.
 *
 * This is a redesign rather than a translation. Three properties from the
 * SQLite implementation have to survive, and each is achieved differently:
 *
 *   - **One Apply slot across concurrent requests.** SQLite used
 *     `BEGIN IMMEDIATE` plus a process-wide `RLock`. Here the check and the
 *     write share one IndexedDB transaction, and the transaction aborts if the
 *     slot is taken. Nothing may be awaited inside it that is not an IndexedDB
 *     request, or the transaction auto-commits mid-way -- which is why the
 *     audit digest is synchronous.
 *
 *   - **Single-use, expiring, hash-bound approvals.** Consumption is a
 *     conditional write inside the same transaction as run creation, so a
 *     second caller cannot observe an approval as unconsumed and race in.
 *
 *   - **Confidentiality of the store.** SQLite relied on file mode `0600`.
 *     IndexedDB is scoped to the extension origin, which no page and no other
 *     extension can reach. The guarantee is comparable; the mechanism is not,
 *     and it is worth stating plainly that deleting the browser profile
 *     destroys the store, so evidence export is the only durable record.
 */

import { buildAuditEvent, type AuditEventRecord } from "./audit.ts";
import { canonicalDigestSync } from "../domain/canonical.ts";

export const DATABASE_NAME = "secure-gateway-studio";
export const DATABASE_VERSION = 2;

export const STORE = {
  drafts: "deployment_drafts",
  resources: "deployment_resources",
  acceptance: "acceptance_results",
  teardowns: "deployment_teardowns",
  plans: "prepared_plans",
  approvals: "approved_plans",
  runs: "deployment_runs",
  operations: "run_operations",
  audit: "audit_events",
} as const;

export type RunStatus = "pending" | "running" | "succeeded" | "failed" | "interrupted";

export interface ApprovedPlanRecord {
  approvalId: string;
  configurationHash: string;
  planHash: string;
  planJson: string;
  specificationJson: string;
  approvedBy: string;
  approvedAt: string;
  expiresAt: string;
  consumedAt: string | null;
}

export interface DeploymentRunRecord {
  runId: string;
  approvalId: string;
  configurationHash: string;
  status: RunStatus;
  startedAt: string;
  finishedAt: string | null;
}

export class ApprovalRejected extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalRejected";
  }
}

export class ApplySlotBusy extends Error {
  constructor(runId: string) {
    super(`Another deployment run is active: ${runId}`);
    this.name = "ApplySlotBusy";
  }
}

function request<T>(source: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    source.onsuccess = () => resolve(source.result);
    source.onerror = () => reject(source.error);
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error ?? new Error("Transaction aborted"));
  });
}

export function openDatabase(factory: IDBFactory = indexedDB): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const open = factory.open(DATABASE_NAME, DATABASE_VERSION);
    open.onupgradeneeded = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains(STORE.drafts)) {
        db.createObjectStore(STORE.drafts, { keyPath: "deploymentId" });
      }
      if (!db.objectStoreNames.contains(STORE.plans)) {
        db.createObjectStore(STORE.plans, { keyPath: "planId" });
      }
      if (!db.objectStoreNames.contains(STORE.approvals)) {
        db.createObjectStore(STORE.approvals, { keyPath: "approvalId" });
      }
      if (!db.objectStoreNames.contains(STORE.runs)) {
        const runs = db.createObjectStore(STORE.runs, { keyPath: "runId" });
        runs.createIndex("status", "status", { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE.operations)) {
        const operations = db.createObjectStore(STORE.operations, { keyPath: "operationId" });
        operations.createIndex("runId", "runId", { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE.resources)) {
        // Keyed by run so teardown can ask "what did this deployment create"
        // without inferring it from a plan that may since have changed.
        const resources = db.createObjectStore(STORE.resources, { keyPath: "id" });
        resources.createIndex("runId", "runId", { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE.acceptance)) {
        const acceptance = db.createObjectStore(STORE.acceptance, { keyPath: "id" });
        acceptance.createIndex("runId", "runId", { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE.teardowns)) {
        db.createObjectStore(STORE.teardowns, { keyPath: "teardownId" });
      }
      if (!db.objectStoreNames.contains(STORE.audit)) {
        // Auto-incrementing key preserves insertion order, which the chain
        // depends on: event N links to N-1 by position, not by timestamp.
        db.createObjectStore(STORE.audit, { keyPath: "sequence", autoIncrement: true });
      }
    };
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}

export interface Clock {
  now(): Date;
  uuid(): string;
}

export const systemClock: Clock = {
  now: () => new Date(),
  uuid: () => crypto.randomUUID(),
};

export class StateRepository {
  private readonly db: IDBDatabase;
  private readonly clock: Clock;

  constructor(db: IDBDatabase, clock: Clock = systemClock) {
    this.db = db;
    this.clock = clock;
  }

  /**
   * Consume one approval and acquire the single Apply slot, atomically.
   *
   * Port of `consume_approval_and_create_run`. Every read and write below runs
   * in one IndexedDB transaction; the audit digest is computed synchronously
   * so no await can slip in and let the transaction commit early.
   */
  async consumeApprovalAndCreateRun(
    approvalId: string,
  ): Promise<{ approval: ApprovedPlanRecord; run: DeploymentRunRecord }> {
    const now = this.clock.now();
    const nowIso = now.toISOString();
    const runId = this.clock.uuid();

    const transaction = this.db.transaction(
      [STORE.approvals, STORE.runs, STORE.audit],
      "readwrite",
    );
    const approvals = transaction.objectStore(STORE.approvals);
    const runs = transaction.objectStore(STORE.runs);
    const audit = transaction.objectStore(STORE.audit);

    const active = (await request(
      runs.index("status").getAll(IDBKeyRange.only("running")),
    )) as DeploymentRunRecord[];
    const pending = (await request(
      runs.index("status").getAll(IDBKeyRange.only("pending")),
    )) as DeploymentRunRecord[];
    const blocking = [...active, ...pending][0];
    if (blocking !== undefined) {
      transaction.abort();
      throw new ApplySlotBusy(blocking.runId);
    }

    const approval = (await request(approvals.get(approvalId))) as
      | ApprovedPlanRecord
      | undefined;
    if (
      approval === undefined ||
      approval.consumedAt !== null ||
      Date.parse(approval.expiresAt) <= now.getTime()
    ) {
      transaction.abort();
      throw new ApprovalRejected(
        "Approval is invalid, expired, consumed, or configuration changed",
      );
    }

    const consumed: ApprovedPlanRecord = { ...approval, consumedAt: nowIso };
    await request(approvals.put(consumed));

    const run: DeploymentRunRecord = {
      runId,
      approvalId: consumed.approvalId,
      configurationHash: consumed.configurationHash,
      status: "running",
      startedAt: nowIso,
      finishedAt: null,
    };
    await request(runs.add(run));

    let previousHash = await this.chainHead(audit);
    for (const [eventType, payload] of [
      [
        "plan.consumed",
        { approval_id: consumed.approvalId, configuration_hash: consumed.configurationHash },
      ],
      [
        "run.started",
        {
          run_id: run.runId,
          approval_id: run.approvalId,
          configuration_hash: run.configurationHash,
        },
      ],
    ] as [string, Record<string, unknown>][]) {
      const event = buildAuditEvent({
        eventId: this.clock.uuid(),
        deploymentId: null,
        eventType,
        actor: consumed.approvedBy,
        payload,
        createdAt: nowIso,
        previousHash,
      });
      await request(audit.add(event));
      previousHash = event.eventHash;
    }

    await transactionDone(transaction);
    return { approval: consumed, run };
  }

  /** Every recorded run, newest first. */
  async runs(): Promise<DeploymentRunRecord[]> {
    const transaction = this.db.transaction([STORE.runs], "readonly");
    const records = (await request(
      transaction.objectStore(STORE.runs).getAll(),
    )) as DeploymentRunRecord[];
    await transactionDone(transaction);
    return records.sort((left, right) => {
      const rightDate = right.startedAt ?? "";
      const leftDate = left.startedAt ?? "";
      return rightDate.localeCompare(leftDate);
    });
  }

  /** Persist a prepared plan so approval can bind to exactly these bytes. */
  async storePreparedPlan(record: {
    planId: string;
    specificationJson: string;
    preflightJson: string;
    planJson: string;
    configurationHash: string;
  }): Promise<void> {
    const transaction = this.db.transaction([STORE.plans], "readwrite");
    await request(
      transaction.objectStore(STORE.plans).put({
        ...record,
        createdAt: this.clock.now().toISOString(),
      }),
    );
    await transactionDone(transaction);
  }

  async preparedPlan(planId: string): Promise<Record<string, unknown> | undefined> {
    const transaction = this.db.transaction([STORE.plans], "readonly");
    const record = (await request(transaction.objectStore(STORE.plans).get(planId))) as
      | Record<string, unknown>
      | undefined;
    await transactionDone(transaction);
    return record;
  }

  /**
   * Approve a prepared plan.
   *
   * The approval carries the plan hash and an expiry. Apply re-checks both, so
   * an approval cannot be replayed against a plan that has since changed, and
   * cannot be held indefinitely.
   */
  async storeApproval(record: {
    planId: string;
    approvedBy: string;
    ttlMinutes: number;
  }): Promise<ApprovedPlanRecord> {
    const plan = await this.preparedPlan(record.planId);
    if (plan === undefined) {
      throw new ApprovalRejected("The prepared plan was not found");
    }
    const now = this.clock.now();
    const approval: ApprovedPlanRecord = {
      approvalId: this.clock.uuid(),
      configurationHash: plan.configurationHash as string,
      planHash: canonicalDigestSync(JSON.parse(plan.planJson as string)),
      planJson: plan.planJson as string,
      specificationJson: plan.specificationJson as string,
      approvedBy: record.approvedBy,
      approvedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + record.ttlMinutes * 60_000).toISOString(),
      consumedAt: null,
    };

    const transaction = this.db.transaction([STORE.approvals, STORE.audit], "readwrite");
    await request(transaction.objectStore(STORE.approvals).add(approval));
    const audit = transaction.objectStore(STORE.audit);
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: null,
      eventType: "plan.approved",
      actor: record.approvedBy,
      payload: {
        approval_id: approval.approvalId,
        configuration_hash: approval.configurationHash,
        plan_hash: approval.planHash,
      },
      createdAt: approval.approvedAt,
      previousHash: await this.chainHead(audit),
    });
    await request(audit.add(event));
    await transactionDone(transaction);
    return approval;
  }

  async approval(approvalId: string): Promise<ApprovedPlanRecord | undefined> {
    const transaction = this.db.transaction([STORE.approvals], "readonly");
    const record = (await request(transaction.objectStore(STORE.approvals).get(approvalId))) as
      | ApprovedPlanRecord
      | undefined;
    await transactionDone(transaction);
    return record;
  }

  async run(runId: string): Promise<DeploymentRunRecord | undefined> {
    const transaction = this.db.transaction([STORE.runs], "readonly");
    const record = (await request(transaction.objectStore(STORE.runs).get(runId))) as
      | DeploymentRunRecord
      | undefined;
    await transactionDone(transaction);
    return record;
  }

  /** Record what a run created, so teardown deletes only that. */
  async recordResources(
    runId: string,
    resources: readonly {
      resourceKey: string;
      provider: string;
      resourceType: string;
      resourceName: string;
      owned: boolean;
      shared: boolean;
    }[],
  ): Promise<void> {
    const transaction = this.db.transaction([STORE.resources], "readwrite");
    const store = transaction.objectStore(STORE.resources);
    for (const resource of resources) {
      await request(store.put({ id: `${runId}:${resource.resourceKey}`, runId, ...resource }));
    }
    await transactionDone(transaction);
  }

  async resources(runId: string): Promise<Record<string, unknown>[]> {
    const transaction = this.db.transaction([STORE.resources], "readonly");
    const records = (await request(
      transaction.objectStore(STORE.resources).index("runId").getAll(IDBKeyRange.only(runId)),
    )) as Record<string, unknown>[];
    await transactionDone(transaction);
    return records;
  }

  /** Operator-confirmed and machine-verified acceptance outcomes. */
  async recordAcceptance(record: {
    runId: string;
    testId: string;
    status: string;
    summary: string;
    evidence: string;
    source: string;
    actor: string;
  }): Promise<void> {
    const now = this.clock.now().toISOString();
    const transaction = this.db.transaction([STORE.acceptance, STORE.audit], "readwrite");
    await request(
      transaction.objectStore(STORE.acceptance).put({
        id: `${record.runId}:${record.testId}`,
        recordedAt: now,
        ...record,
      }),
    );
    const audit = transaction.objectStore(STORE.audit);
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: null,
      eventType: "acceptance.recorded",
      actor: record.actor,
      payload: {
        run_id: record.runId,
        test_id: record.testId,
        status: record.status,
        source: record.source,
        // The evidence text itself is hashed rather than copied: it is operator
        // prose and may name hosts or people.
        evidence_sha256: canonicalDigestSync(record.evidence),
      },
      createdAt: now,
      previousHash: await this.chainHead(audit),
    });
    await request(audit.add(event));
    await transactionDone(transaction);
  }

  async acceptance(runId: string): Promise<Record<string, unknown>[]> {
    const transaction = this.db.transaction([STORE.acceptance], "readonly");
    const records = (await request(
      transaction.objectStore(STORE.acceptance).index("runId").getAll(IDBKeyRange.only(runId)),
    )) as Record<string, unknown>[];
    await transactionDone(transaction);
    return records;
  }

  async markRunDeleted(runId: string): Promise<void> {
    const transaction = this.db.transaction([STORE.runs], "readwrite");
    const store = transaction.objectStore(STORE.runs);
    const run = (await request(store.get(runId))) as DeploymentRunRecord | undefined;
    if (run) {
      await request(store.put({ ...run, status: "deleted" }));
    }
    await transactionDone(transaction);
  }

  async markAllRunsDeleted(): Promise<void> {
    const transaction = this.db.transaction([STORE.runs], "readwrite");
    const store = transaction.objectStore(STORE.runs);
    const runs = (await request(store.getAll())) as DeploymentRunRecord[];
    for (const run of runs) {
      await request(store.put({ ...run, status: "deleted" }));
    }
    await transactionDone(transaction);
  }

  async recordTeardown(record: Record<string, unknown>): Promise<void> {
    const transaction = this.db.transaction([STORE.teardowns], "readwrite");
    await request(transaction.objectStore(STORE.teardowns).put(record));
    await transactionDone(transaction);
  }

  async teardown(teardownId: string): Promise<Record<string, unknown> | undefined> {
    const transaction = this.db.transaction([STORE.teardowns], "readonly");
    const record = (await request(
      transaction.objectStore(STORE.teardowns).get(teardownId),
    )) as Record<string, unknown> | undefined;
    await transactionDone(transaction);
    return record;
  }

  /** Every audit event in insertion order. */
  async auditEvents(): Promise<AuditEventRecord[]> {
    const transaction = this.db.transaction([STORE.audit], "readonly");
    const events = (await request(
      transaction.objectStore(STORE.audit).getAll(),
    )) as AuditEventRecord[];
    await transactionDone(transaction);
    return events;
  }

  /** Append a standalone audit event with cryptographic chaining. */
  async recordAuditEvent(event: {
    deploymentId: string | null;
    eventType: string;
    actor: string;
    payload: Record<string, unknown>;
  }): Promise<void> {
    const transaction = this.db.transaction([STORE.audit], "readwrite");
    const audit = transaction.objectStore(STORE.audit);
    const previousHash = await this.chainHead(audit);
    const auditEvent = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: event.deploymentId,
      eventType: event.eventType,
      actor: event.actor,
      payload: event.payload,
      createdAt: this.clock.now().toISOString(),
      previousHash,
    });
    await request(audit.add(auditEvent));
    await transactionDone(transaction);
  }

  /**
   * Mark runs and operations left in flight by a previous session.
   *
   * Port of the startup reconciliation. A service worker can stop at any
   * point, so this runs far more often than the desktop application's restart
   * path did -- it is the mechanism, not an edge case.
   */
  async reconcileInterruptedRuns(): Promise<string[]> {
    const transaction = this.db.transaction([STORE.runs, STORE.audit], "readwrite");
    const runs = transaction.objectStore(STORE.runs);
    const audit = transaction.objectStore(STORE.audit);
    const nowIso = this.clock.now().toISOString();

    const inFlight = [
      ...((await request(runs.index("status").getAll(IDBKeyRange.only("running")))) as
        DeploymentRunRecord[]),
      ...((await request(runs.index("status").getAll(IDBKeyRange.only("pending")))) as
        DeploymentRunRecord[]),
    ];

    let previousHash = await this.chainHead(audit);
    const interrupted: string[] = [];
    for (const run of inFlight) {
      await request(runs.put({ ...run, status: "interrupted", finishedAt: nowIso }));
      const event = buildAuditEvent({
        eventId: this.clock.uuid(),
        deploymentId: null,
        eventType: "run.interrupted",
        actor: "system",
        payload: { run_id: run.runId, configuration_hash: run.configurationHash },
        createdAt: nowIso,
        previousHash,
      });
      await request(audit.add(event));
      previousHash = event.eventHash;
      interrupted.push(run.runId);
    }

    await transactionDone(transaction);
    return interrupted;
  }

  private async chainHead(audit: IDBObjectStore): Promise<string | null> {
    const cursor = await request(audit.openCursor(null, "prev"));
    if (cursor === null) return null;
    return (cursor.value as AuditEventRecord).eventHash;
  }
}
