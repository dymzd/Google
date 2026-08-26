/** Real IndexedDB lifecycle-lock and atomic-finalization regressions. */

import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";

import { canonicalDigestSync } from "../src/domain/canonical.ts";
import { configurationHash } from "../src/domain/planner.ts";
import { parseDeploymentSpec, specToJson } from "../src/domain/spec.ts";
import {
  ApprovalRejected,
  ApplySlotBusy,
  CEP_MUTATION_LEASE_MS,
  CepMutationLeaseBusy,
  StateRepository,
  STORE,
  TeardownSlotBusy,
  openDatabase,
  teardownImmutableDigest,
  type ApprovedPlanRecord,
  type Clock,
} from "../src/storage/repository.ts";
import {
  finalizeUserDataConsent,
  prepareUserDataConsentMigration,
  secureObjectStore,
} from "../src/storage/secure-storage.ts";
import {
  LIFECYCLE_SCHEMA_VERSION,
  RunEngine,
  residualResourceRecords,
  type RunRecord,
  type RunStore,
  type Scheduler,
} from "../src/runtime/run-engine.ts";
import { route, RouteError, type RouteContext } from "../src/background/router.ts";
import { GoogleResourceExecutor, type Transport } from "../src/providers/executor.ts";
import { discoveryOwnershipProofs } from "../src/providers/discovery.ts";

function request<T>(source: IDBRequest<T> | Promise<T>): Promise<T> {
  if (source instanceof Promise) return source;
  return new Promise((resolve, reject) => {
    source.onsuccess = () => resolve(source.result);
    source.onerror = () => reject(source.error);
  });
}

function done(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error ?? new Error("aborted"));
  });
}

let uuidCounter = 0;
const clock: Clock = {
  now: () => new Date("2026-08-24T00:00:00Z"),
  uuid: () => `test-id-${++uuidCounter}`,
};

const spec = parseDeploymentSpec({
  project_id: "enterprise-secgw-01",
  mode: "poc",
  target_ou_id: "03-test-ou",
  managed_chrome_access_level: "NONE",
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
const configHash = configurationHash(spec);
const deployerIdentity = {
  serviceAccountEmail:
    "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
  serviceAccountUniqueId: "123456789012345678901",
  projectId: "enterprise-secgw-01",
  operatorEmail: "operator@example.com",
  operatorSubject: "operator-subject-123",
};
const currentApprovalIdentity = {
  operator: "operator@example.com",
  deployerIdentity,
};

function approval(id: string): ApprovedPlanRecord {
  const plan = {
    configuration_hash: configHash,
    can_apply: true,
    gates: [{ gate_id: "human-approval", blocking: true, status: "pass" }],
    changes: [{
      provider: "beyondcorp",
      resource_type: "application",
      resource_name: "demo-app",
      action: "create",
      risk: "high",
      summary: "Create demo app",
      owned_after_apply: true,
      dependencies: [],
    }],
  };
  return {
    schemaVersion: LIFECYCLE_SCHEMA_VERSION,
    approvalId: id,
    configurationHash: configHash,
    planHash: canonicalDigestSync(plan),
    planJson: JSON.stringify(plan),
    specificationJson: JSON.stringify(specToJson(spec)),
    approvedBy: "operator@example.com",
    approvedAt: "2026-08-24T00:00:00Z",
    expiresAt: "2026-08-24T01:00:00Z",
    consumedAt: null,
    deployerIdentity,
  };
}

async function database(factory = new IDBFactory()): Promise<IDBDatabase> {
  const db = await openDatabase(factory);
  await prepareUserDataConsentMigration({
    database: db,
    sensitiveStores: Object.values(STORE),
  });
  await finalizeUserDataConsent(db);
  return db;
}

async function put(db: IDBDatabase, storeName: string, value: unknown): Promise<void> {
  const transaction = db.transaction([storeName], "readwrite");
  const complete = done(transaction);
  await request(secureObjectStore(transaction, storeName).put(value));
  await complete;
}

const failures: string[] = [];
let passed = 0;
function check(name: string, condition: boolean): void {
  if (condition) passed += 1;
  else failures.push(name);
}

// A safely isolated replacement is a first-class approval/run identity. It is
// still bound by project, immutable numeric id, and operator subject.
{
  const db = await database();
  const replacementIdentity = {
    ...deployerIdentity,
    serviceAccountEmail:
      "secure-gateway-studio-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
    serviceAccountUniqueId: "223456789012345678901",
  };
  await put(db, STORE.approvals, {
    ...approval("approval-isolated-replacement"),
    deployerIdentity: replacementIdentity,
  });
  const consumed = await new StateRepository(db, clock).consumeApprovalAndCreateRun(
    "approval-isolated-replacement",
    { operator: "operator@example.com", deployerIdentity: replacementIdentity },
  );
  check(
    "isolated replacement deployer identity survives approval consumption",
    consumed.run.deployerIdentity?.serviceAccountEmail === replacementIdentity.serviceAccountEmail &&
      consumed.run.deployerIdentity?.serviceAccountUniqueId ===
        replacementIdentity.serviceAccountUniqueId,
  );
}

// A terminal compensation failure remains recoverable after an extension
// update fixes the provider request. Explicit resume retries only the residual
// rollback steps under the original approval and deployer identity.
{
  const db = await database();
  const repository = new StateRepository(db, clock);
  await put(db, STORE.approvals, approval("approval-rollback-retry"));
  const { run } = await repository.consumeApprovalAndCreateRun(
    "approval-rollback-retry",
    currentApprovalIdentity,
  );
  const failed = {
    ...run,
    state: "rollback_failed",
    status: "rollback_failed",
    finalizationPending: true,
    finalizedAt: "2026-08-24T00:05:00Z",
    finishedAt: "2026-08-24T00:05:00Z",
    steps: run.steps.map((step) => ({
      ...step,
      status: "rollback_failed",
      error: "rollback: request-id method collision",
      beforeImage: {
        kind: "generic_created_resource",
        protocolVersion: 2,
        phase: "applied",
        resourceKey: `beyondcorp:application:${step.change.resource_name}`,
        createUrl:
          `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
          `/locations/global/securityGateways/${spec.gateway_id}/applications`,
        resourceUrl:
          `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
          `/locations/global/securityGateways/${spec.gateway_id}` +
          `/applications/${step.change.resource_name}`,
        createRequestId: step.requestId,
        expectedParamsDigest: "a".repeat(64),
        expectedPayloadDigest: "b".repeat(64),
        ownershipMarker: null,
        providerIdentityField: "createTime",
        providerIdentity: "2026-08-24T00:00:00Z",
      },
    })),
  };
  await put(db, STORE.runs, failed);

  let resumed: Awaited<ReturnType<StateRepository["resumeRun"]>> | undefined;
  try {
    resumed = await repository.resumeRun(run.runId, currentApprovalIdentity);
  } catch {
    resumed = undefined;
  }
  check(
    "an operator can explicitly retry a rollback_failed run without a new approval",
    resumed?.state === "rolling_back" && resumed.status === "rolling_back" &&
      resumed.finalizationPending === false && resumed.finishedAt === null &&
      resumed.steps.every((step) => step.status === "done" && step.error === null),
  );
}

// Older extension builds could persist terminal-looking rows without either a
// lifecycle schema or a durable ownership checkpoint. Adoption classifies the
// complete run once and seals it instead of retrying an impossible rollback.
for (const legacyState of ["failed", "rollback_unavailable"] as const) {
  const db = await database();
  const repository = new StateRepository(db, clock);
  const approvalId = `approval-recover-${legacyState}`;
  await put(db, STORE.approvals, approval(approvalId));
  const { run } = await repository.consumeApprovalAndCreateRun(
    approvalId,
    currentApprovalIdentity,
  );
  const consumedApproval = await repository.approval(approvalId);
  if (consumedApproval === undefined) throw new Error("consumed approval missing");
  const { schemaVersion: _approvalSchema, ...legacyApproval } = consumedApproval;
  await put(db, STORE.approvals, legacyApproval);
  const { schemaVersion: _runSchema, ...runWithoutSchema } = run;
  await put(db, STORE.runs, {
    ...runWithoutSchema,
    state: legacyState,
    status: legacyState,
    finalizationPending: false,
    finalizedAt: "2026-08-24T00:05:00Z",
    finishedAt: "2026-08-24T00:05:00Z",
    steps: run.steps.map((step) => ({
      ...Object.fromEntries(Object.entries(step).filter(([key]) => key !== "schemaVersion")),
      status: "done",
      error: legacyState === "failed" ? "legacy apply failure" : null,
    })),
  });

  let resumed: Awaited<ReturnType<StateRepository["resumeRun"]>> | undefined;
  try {
    resumed = await repository.resumeRun(run.runId, currentApprovalIdentity);
  } catch {
    resumed = undefined;
  }
  check(
    `${legacyState} without ownership evidence is sealed as rollback_unavailable`,
    resumed?.state === "rollback_unavailable" && resumed.status === "rollback_unavailable" &&
      resumed.finalizationPending === true &&
      resumed.steps.every((step) =>
        step.schemaVersion === LIFECYCLE_SCHEMA_VERSION &&
        step.status === "rollback_failed" &&
        step.error === "rollback: generic-resource-ownership-checkpoint-missing"
      ),
  );
  db.close();
}

// Cross the production seam that the earlier lifecycle and resume suites kept
// separate: encrypted legacy records -> repository resume -> real RunEngine ->
// real GoogleResourceExecutor. One residual step has an IAM before-image and
// another has none. A retry must classify the whole rollback before invoking
// either compensation; otherwise the valid IAM step performs a Google SET
// while the other step can only fail with a missing-ownership checkpoint.
{
  const db = await database();
  const repository = new StateRepository(db, clock);
  const approvalId = "approval-legacy-preflight-seam";
  const baseApproval = approval(approvalId);
  const legacyPlan = JSON.parse(baseApproval.planJson) as {
    changes: Array<Record<string, unknown>>;
    [key: string]: unknown;
  };
  legacyPlan.changes = [
    {
      provider: "beyondcorp",
      resource_type: "gateway_iam",
      resource_name: "default-service-discovery-users",
      action: "create",
      risk: "high",
      summary: "Gateway IAM",
      owned_after_apply: true,
      dependencies: [],
    },
    {
      provider: "cloudresourcemanager",
      resource_type: "project_iam",
      resource_name: "secure-gateway-private-https-upstream-access",
      action: "create",
      risk: "high",
      summary: "Upstream access IAM",
      owned_after_apply: true,
      dependencies: [],
    },
  ];
  await put(db, STORE.approvals, {
    ...baseApproval,
    planJson: JSON.stringify(legacyPlan),
    planHash: canonicalDigestSync(legacyPlan),
  });
  const { run } = await repository.consumeApprovalAndCreateRun(
    approvalId,
    currentApprovalIdentity,
  );
  const seamApproval = await repository.approval(approvalId);
  if (seamApproval === undefined) throw new Error("consumed approval missing");
  const { schemaVersion: _seamApprovalSchema, ...legacySeamApproval } = seamApproval;
  await put(db, STORE.approvals, legacySeamApproval);
  const beforePolicy = {
    version: 3,
    etag: "before-etag",
    bindings: [{ role: "roles/viewer", members: ["user:owner@example.com"] }],
  };
  const afterPolicy = {
    version: 3,
    etag: "after-etag",
    bindings: [
      ...beforePolicy.bindings,
      {
        role: "roles/beyondcorp.serviceDiscoveryUser",
        members: ["group:secure-access@example.com"],
      },
    ],
  };
  const { schemaVersion: _seamRunSchema, ...legacySeamRun } = run;
  const legacyRun = {
    ...legacySeamRun,
    state: "rollback_failed" as const,
    status: "rollback_failed" as const,
    finishedAt: "2026-08-24T00:05:00Z",
    finalizationPending: true,
    steps: run.steps.map((step, index) => {
      const { schemaVersion: _stepSchema, ...legacyStep } = step;
      return {
        ...legacyStep,
        status: "rollback_failed" as const,
        error: "rollback: legacy checkpoint failure",
        ...(index === 0
          ? {
            beforeImage: {
              kind: "iam",
              phase: "applied",
              getUrl:
                `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
                `/locations/global/securityGateways/${spec.gateway_id}:getIamPolicy`,
              setUrl:
                `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
                `/locations/global/securityGateways/${spec.gateway_id}:setIamPolicy`,
              policy: beforePolicy,
              afterPolicy,
            },
          }
          : {}),
      };
    }),
  };
  await put(db, STORE.runs, legacyRun);

  const resumed = await repository.resumeRun(run.runId, currentApprovalIdentity);
  let googleMutations = 0;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method !== "GET") googleMutations += 1;
      if (url.endsWith(":getIamPolicy")) {
        return { status: 200, payload: { ...afterPolicy, etag: "fresh-etag" } };
      }
      if (url.endsWith(":setIamPolicy")) return { status: 200, payload: {} };
      return { status: options.acceptedStatuses?.includes(404) ? 404 : 200, payload: {} };
    },
  };
  const store: RunStore = {
    async load(id) {
      return (await repository.run(id) as (RunRecord & { status?: string }) | undefined) ?? null;
    },
    async save(record) {
      await put(db, STORE.runs, { ...record, status: record.state });
    },
  };
  const scheduler: Scheduler = {
    async schedule() {},
    async cancel() {},
  };
  const terminal = await new RunEngine(
    store,
    new GoogleResourceExecutor(transport),
    scheduler,
  ).drain(run.runId, spec);
  const residual = residualResourceRecords(terminal);
  check(
    "legacy rollback preflight terminalizes before the real executor can mutate Google",
    terminal.state === "rollback_unavailable" && googleMutations === 0 &&
      residual.length === 2 &&
      terminal.steps.some((step) =>
        step.error?.includes("iam-ownership-checkpoint-missing")
      ),
  );
  db.close();
}

// A fully valid legacy row is adopted once, stamped across approval/run/step,
// and never re-enters a legacy branch during execution.
{
  const db = await database();
  const repository = new StateRepository(db, clock);
  const approvalId = "approval-legacy-schema-adoption";
  const baseApproval = approval(approvalId);
  const safePlan = JSON.parse(baseApproval.planJson) as {
    changes: Array<Record<string, unknown>>;
    [key: string]: unknown;
  };
  safePlan.changes = [{
    provider: "serviceusage",
    resource_type: "project_services",
    resource_name: "required-apis",
    action: "create",
    risk: "medium",
    summary: "Required APIs",
    owned_after_apply: true,
    dependencies: [],
  }];
  await put(db, STORE.approvals, {
    ...baseApproval,
    planJson: JSON.stringify(safePlan),
    planHash: canonicalDigestSync(safePlan),
  });
  const { run } = await repository.consumeApprovalAndCreateRun(
    approvalId,
    currentApprovalIdentity,
  );
  const consumedApproval = await repository.approval(approvalId);
  if (consumedApproval === undefined) throw new Error("consumed approval missing");
  const { schemaVersion: _approvalSchema, ...legacyApproval } = consumedApproval;
  const { schemaVersion: _runSchema, ...legacyRun } = run;
  await put(db, STORE.approvals, legacyApproval);
  await put(db, STORE.runs, {
    ...legacyRun,
    state: "rollback_failed",
    status: "rollback_failed",
    finishedAt: "2026-08-24T00:05:00Z",
    steps: run.steps.map((step) => {
      const { schemaVersion: _stepSchema, ...legacyStep } = step;
      return {
        ...legacyStep,
        status: "rollback_failed",
        error: "rollback: legacy transient error",
      };
    }),
  });
  const adopted = await repository.resumeRun(run.runId, currentApprovalIdentity);
  const adoptedApproval = await repository.approval(approvalId);
  let googleCalls = 0;
  const transport: Transport = {
    async requestJson() {
      googleCalls += 1;
      return { status: 500, payload: {} };
    },
  };
  const store: RunStore = {
    async load(id) {
      return (await repository.run(id) as (RunRecord & { status?: string }) | undefined) ?? null;
    },
    async save(record) {
      await put(db, STORE.runs, { ...record, status: record.state });
    },
  };
  const scheduler: Scheduler = {
    async schedule() {},
    async cancel() {},
  };
  const terminal = await new RunEngine(
    store,
    new GoogleResourceExecutor(transport),
    scheduler,
  ).drain(run.runId, spec);
  check(
    "valid legacy lifecycle records are adopted once before real execution",
    adopted.state === "rolling_back" &&
      adopted.schemaVersion === LIFECYCLE_SCHEMA_VERSION &&
      adopted.steps.every((step) => step.schemaVersion === LIFECYCLE_SCHEMA_VERSION) &&
      adoptedApproval?.schemaVersion === LIFECYCLE_SCHEMA_VERSION &&
      terminal.state === "rolled_back" && googleCalls === 0,
  );
  db.close();
}

// Builds released before immutable deployer binding stored the consumed
// approval and full run checkpoint, but neither row carried deployerIdentity.
// An explicit recovery click may bind that exact legacy pair to the currently
// live-attested deployer; it must not require a replacement plan.
{
  const db = await database();
  const repository = new StateRepository(db, clock);
  const approvalId = "approval-recover-legacy-identity";
  const {
    deployerIdentity: _approvalIdentity,
    schemaVersion: _approvalSchema,
    ...legacyApproval
  } = approval(approvalId);
  await put(db, STORE.approvals, legacyApproval);
  const currentApproval = approval(approvalId);
  await put(db, STORE.approvals, currentApproval);
  const { run } = await repository.consumeApprovalAndCreateRun(
    approvalId,
    currentApprovalIdentity,
  );
  const {
    deployerIdentity: _runIdentity,
    schemaVersion: _runSchema,
    ...legacyRun
  } = run;
  const consumed = await repository.approval(approvalId);
  if (consumed === undefined) throw new Error("consumed approval missing");
  const {
    deployerIdentity: _consumedIdentity,
    schemaVersion: _consumedSchema,
    ...legacyConsumedApproval
  } = consumed;
  await put(db, STORE.approvals, {
    ...legacyConsumedApproval,
    // The old route incorrectly used cloudIdentity(), which resolves to the
    // deployer SA after bootstrap, instead of the signed-in administrator.
    approvedBy: deployerIdentity.serviceAccountEmail,
  });
  await put(db, STORE.runs, {
    ...legacyRun,
    state: "failed",
    status: "failed",
    finishedAt: "2026-08-24T00:05:00Z",
    steps: run.steps.map((step) => {
      const { schemaVersion: _stepSchema, ...legacyStep } = step;
      return { ...legacyStep, status: "done" };
    }),
  });
  const replacementDeployerIdentity = {
    ...deployerIdentity,
    serviceAccountEmail:
      "secure-gateway-studio-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
    serviceAccountUniqueId: "987654321098765432109",
  };
  const replacementCurrentIdentity = {
    operator: "operator@example.com",
    deployerIdentity: replacementDeployerIdentity,
  };

  let resumed: Awaited<ReturnType<StateRepository["resumeRun"]>> | undefined;
  try {
    resumed = await repository.resumeRun(run.runId, replacementCurrentIdentity);
  } catch {
    resumed = undefined;
  }
  const reboundApproval = await repository.approval(approvalId);
  let resumedAgain: Awaited<ReturnType<StateRepository["resumeRun"]>> | undefined;
  if (resumed !== undefined) {
    try {
      resumedAgain = await repository.resumeRun(run.runId, replacementCurrentIdentity);
    } catch {
      resumedAgain = undefined;
    }
  }
  check(
    "a service-account-attributed legacy approval adopts the live-attested human and deployer",
      resumed?.state === "rollback_unavailable" &&
      resumedAgain === undefined &&
      resumed.schemaVersion === LIFECYCLE_SCHEMA_VERSION &&
      canonicalDigestSync(resumed.deployerIdentity) ===
        canonicalDigestSync(replacementDeployerIdentity) &&
      canonicalDigestSync(reboundApproval?.deployerIdentity) ===
        canonicalDigestSync(replacementDeployerIdentity) &&
      (reboundApproval as unknown as { legacyOperatorBinding?: { operatorSubject?: string } })
        ?.legacyOperatorBinding?.operatorSubject === replacementDeployerIdentity.operatorSubject,
  );
  db.close();
}

{
  const db = await database();
  const repository = new StateRepository(db, clock);
  const approvalId = "approval-recover-unrelated-legacy-operator";
  await put(db, STORE.approvals, approval(approvalId));
  const { run } = await repository.consumeApprovalAndCreateRun(
    approvalId,
    currentApprovalIdentity,
  );
  const consumed = await repository.approval(approvalId);
  if (consumed === undefined) throw new Error("consumed approval missing");
  const { deployerIdentity: _approvalIdentity, ...legacyApproval } = consumed;
  const { deployerIdentity: _runIdentity, ...legacyRun } = run;
  await put(db, STORE.approvals, {
    ...legacyApproval,
    approvedBy:
      "secure-gateway-deployer@other-project-01.iam.gserviceaccount.com",
  });
  await put(db, STORE.runs, {
    ...legacyRun,
    state: "failed",
    status: "failed",
    finishedAt: "2026-08-24T00:05:00Z",
    steps: run.steps.map((step) => ({ ...step, status: "done" })),
  });
  let rejected = false;
  try {
    await repository.resumeRun(run.runId, currentApprovalIdentity);
  } catch (error) {
    rejected = error instanceof ApprovalRejected;
  }
  const unchangedApproval = await repository.approval(approvalId);
  check(
    "legacy recovery rejects a supported deployer name from another project",
    rejected && unchangedApproval?.deployerIdentity === undefined,
  );
  db.close();
}

{
  const db = await database();
  const repository = new StateRepository(db, clock);
  const approvalId = "approval-recover-tampered-legacy-checkpoint";
  await put(db, STORE.approvals, approval(approvalId));
  const { run } = await repository.consumeApprovalAndCreateRun(
    approvalId,
    currentApprovalIdentity,
  );
  const consumed = await repository.approval(approvalId);
  if (consumed === undefined) throw new Error("consumed approval missing");
  const { deployerIdentity: _approvalIdentity, ...legacyApproval } = consumed;
  const { deployerIdentity: _runIdentity, ...legacyRun } = run;
  await put(db, STORE.approvals, legacyApproval);
  await put(db, STORE.runs, {
    ...legacyRun,
    state: "failed",
    status: "failed",
    finishedAt: "2026-08-24T00:05:00Z",
    steps: run.steps.map((step, index) => index === 0
      ? {
          ...step,
          status: "done",
          change: { ...step.change, resource_name: "not-the-approved-resource" },
        }
      : { ...step, status: "done" }),
  });
  let rejected = false;
  try {
    await repository.resumeRun(run.runId, currentApprovalIdentity);
  } catch (error) {
    rejected = error instanceof ApprovalRejected;
  }
  const unchangedApproval = await repository.approval(approvalId);
  check(
    "legacy identity adoption rejects a checkpoint that differs from the consumed plan",
    rejected && unchangedApproval?.deployerIdentity === undefined,
  );
  db.close();
}

// Recovery remains bound to the exact consumed configuration and approval.
// A terminal-looking legacy status must not weaken those original gates.
{
  const db = await database();
  const repository = new StateRepository(db, clock);
  const approvalId = "approval-recover-hash-mismatch";
  await put(db, STORE.approvals, approval(approvalId));
  const { run } = await repository.consumeApprovalAndCreateRun(
    approvalId,
    currentApprovalIdentity,
  );
  await put(db, STORE.runs, {
    ...run,
    configurationHash: "different-configuration-hash",
    state: "failed",
    status: "failed",
    finishedAt: "2026-08-24T00:05:00Z",
    steps: run.steps.map((step) => ({ ...step, status: "done" })),
  });
  let rejected = false;
  try {
    await repository.resumeRun(run.runId, currentApprovalIdentity);
  } catch (error) {
    rejected = error instanceof ApprovalRejected;
  }
  check("legacy recovery rejects a run with a different configuration hash", rejected);
  db.close();
}

// CEP provision/licensing/DLP mutations use durable encrypted leases rather
// than a worker-local mutex. Overlapping scopes conflict atomically; a worker
// crash can be recovered after expiry only with the exact same request digest.
{
  const db = await database();
  let leaseNow = new Date("2026-08-24T00:00:00Z");
  let leaseUuid = 0;
  const repository = new StateRepository(db, {
    now: () => new Date(leaseNow),
    uuid: () => `lease-id-${++leaseUuid}`,
  });
  const customerScope = `cep:customer:${"c".repeat(64)}`;
  const ouScope = `cep:ou:${"d".repeat(64)}`;
  const requestDigest = "e".repeat(64);
  const first = await repository.acquireCepMutationLease({
    scopeKeys: [ouScope, customerScope],
    operationKind: "provision",
    requestDigest,
  });
  await put(db, STORE.approvals, approval("approval-blocked-by-cep"));
  let applyBlocked = false;
  try {
    await repository.consumeApprovalAndCreateRun(
      "approval-blocked-by-cep",
      currentApprovalIdentity,
    );
  } catch (error) {
    applyBlocked = error instanceof ApplySlotBusy;
  }
  let teardownBlocked = false;
  try {
    await repository.startTeardown({
      teardownId: "teardown-blocked-by-cep",
      runId: "completed-run",
      status: "pending",
      instructions: [],
      configurationHash: configHash,
      planHash: "1".repeat(64),
    }, currentApprovalIdentity);
  } catch (error) {
    teardownBlocked = error instanceof TeardownSlotBusy;
  }
  check("CEP leases atomically block both Apply and teardown lifecycle starts", applyBlocked && teardownBlocked);
  let overlappingBlocked = false;
  try {
    await repository.acquireCepMutationLease({
      scopeKeys: [ouScope],
      operationKind: "assign_licenses",
      requestDigest: "f".repeat(64),
    });
  } catch (error) {
    overlappingBlocked = error instanceof CepMutationLeaseBusy &&
      error.code === "cep-mutation-active";
  }
  check("CEP customer and OU scopes are acquired atomically", overlappingBlocked);

  leaseNow = new Date(leaseNow.getTime() + CEP_MUTATION_LEASE_MS + 1);
  let differentRequestBlocked = false;
  try {
    await repository.acquireCepMutationLease({
      scopeKeys: [ouScope, customerScope],
      operationKind: "provision",
      requestDigest: "0".repeat(64),
    });
  } catch (error) {
    differentRequestBlocked = error instanceof CepMutationLeaseBusy &&
      error.code === "cep-mutation-recovery-required";
  }
  check("an expired CEP saga cannot be replaced by a different request", differentRequestBlocked);

  const recovered = await repository.acquireCepMutationLease({
    scopeKeys: [customerScope, ouScope],
    operationKind: "provision",
    requestDigest,
  });
  check(
    "an expired CEP saga resumes with its stable operation id and a fresh owner",
    recovered.recovered && recovered.operationId === first.operationId &&
      recovered.ownerToken !== first.ownerToken,
  );
  let expiredOwnerFenced = false;
  try {
    await repository.renewCepMutationLease(first);
  } catch {
    expiredOwnerFenced = true;
  }
  check("an expired CEP owner cannot renew after exact-request recovery", expiredOwnerFenced);
  await repository.releaseCepMutationLease(recovered);
  check("CEP lease release removes every acquired scope", (await repository.cepMutationLeases()).length === 0);
}

{
  const db = await database();
  await put(db, STORE.runs, {
    runId: "apply-blocks-cep",
    approvalId: "approval",
    configurationHash: configHash,
    status: "running",
    state: "running",
    startedAt: "2026-08-24T00:00:00Z",
    finishedAt: null,
    steps: [{ requestId: "step", status: "running" }],
  });
  let blocked = false;
  try {
    await new StateRepository(db, clock).acquireCepMutationLease({
      scopeKeys: [`cep:ou:${"9".repeat(64)}`],
      operationKind: "assign_licenses",
      requestDigest: "8".repeat(64),
    });
  } catch (error) {
    blocked = error instanceof CepMutationLeaseBusy && error.code === "cep-lifecycle-active";
  }
  check("active Apply atomically blocks CEP mutation lease acquisition", blocked);
}

// Approval consumption and complete RunRecord creation share one commit.
{
  const db = await database();
  await put(db, STORE.approvals, approval("approval-complete"));
  const repository = new StateRepository(db, clock);
  const { run } = await repository.consumeApprovalAndCreateRun(
    "approval-complete",
    currentApprovalIdentity,
  );
  const durable = await repository.run(run.runId) as unknown as RunRecord;
  check(
    "approval commit contains complete non-placeholder steps",
    durable.steps.length === 1 && durable.steps[0]?.requestId.length === 36 &&
      durable.steps[0]?.change.resource_name === "demo-app",
  );
}

// The immutable numeric SecretVersion and decoded payload digest are copied
// into the durable RunRecord in the same transaction as approval consumption.
// Resume revalidates that copy against the still hash-bound approved plan.
{
  const db = await database();
  const publicBinding = {
    secret_version_name: "projects/enterprise-secgw-01/secrets/public-tls/versions/7",
    payload_sha256: "a".repeat(64),
  };
  const record = approval("approval-public-certificate-binding");
  const plan = JSON.parse(record.planJson) as Record<string, unknown>;
  plan.public_certificate_binding = publicBinding;
  record.planJson = JSON.stringify(plan);
  record.planHash = canonicalDigestSync(plan);
  await put(db, STORE.approvals, record);
  const repository = new StateRepository(db, clock);
  const { run } = await repository.consumeApprovalAndCreateRun(
    record.approvalId,
    currentApprovalIdentity,
  );
  check(
    "approval consumption atomically binds the exact public certificate into the run",
    canonicalDigestSync(run.publicCertificateBinding) === canonicalDigestSync(publicBinding),
  );

  await put(db, STORE.runs, {
    ...run,
    publicCertificateBinding: {
      ...publicBinding,
      payload_sha256: "b".repeat(64),
    },
  });
  let rejected = false;
  try {
    await repository.resumeRun(run.runId, currentApprovalIdentity);
  } catch (error) {
    rejected = error instanceof ApprovalRejected;
  }
  check("resume rejects a run whose public certificate binding changed", rejected);
}

// A durable approval cannot move to another administrator who signs into the
// same Chrome profile after the original approver signs out.
{
  const db = await database();
  await put(db, STORE.approvals, approval("approval-wrong-operator"));
  const repository = new StateRepository(db, clock);
  let blocked = false;
  try {
    await repository.consumeApprovalAndCreateRun("approval-wrong-operator", {
      ...currentApprovalIdentity,
      operator: "different-admin@example.com",
    });
  } catch (error) {
    blocked = error instanceof ApprovalRejected;
  }
  const durable = await repository.approval("approval-wrong-operator");
  check(
    "a different signed-in administrator cannot consume another actor's approval",
    blocked && durable?.consumedAt === null && (await repository.runs()).length === 0,
  );
}

// Deleting and recreating the deployer at the same email changes its immutable
// numeric id and invalidates the existing approval.
{
  const db = await database();
  await put(db, STORE.approvals, approval("approval-wrong-deployer"));
  const repository = new StateRepository(db, clock);
  let blocked = false;
  try {
    await repository.consumeApprovalAndCreateRun("approval-wrong-deployer", {
      operator: currentApprovalIdentity.operator,
      deployerIdentity: {
        ...deployerIdentity,
        serviceAccountUniqueId: "999999999999999999999",
      },
    });
  } catch (error) {
    blocked = error instanceof ApprovalRejected;
  }
  const durable = await repository.approval("approval-wrong-deployer");
  check(
    "a same-name replacement deployer cannot consume an existing approval",
    blocked && durable?.consumedAt === null && (await repository.runs()).length === 0,
  );
}

// Apply is blocked by any active teardown, even one for another run.
{
  const db = await database();
  await put(db, STORE.approvals, approval("approval-blocked-by-teardown"));
  await put(db, STORE.teardowns, {
    teardownId: "td-other",
    runId: "other-run",
    status: "running",
  });
  let blocked = false;
  try {
    await new StateRepository(db, clock)
      .consumeApprovalAndCreateRun(
        "approval-blocked-by-teardown",
        currentApprovalIdentity,
      );
  } catch (error) {
    blocked = error instanceof ApplySlotBusy;
  }
  check("Apply and teardown are globally mutually exclusive", blocked);
}

// Apply is blocked throughout rollback, not only pending/running Apply.
{
  const db = await database();
  await put(db, STORE.approvals, approval("approval-blocked-by-rollback"));
  await put(db, STORE.runs, {
    runId: "rolling-run",
    approvalId: "old-approval",
    configurationHash: configHash,
    status: "rolling_back",
    state: "rolling_back",
    startedAt: "2026-08-24T00:00:00Z",
    finishedAt: null,
    steps: [],
  });
  let blocked = false;
  try {
    await new StateRepository(db, clock)
      .consumeApprovalAndCreateRun(
        "approval-blocked-by-rollback",
        currentApprovalIdentity,
      );
  } catch (error) {
    blocked = error instanceof ApplySlotBusy;
  }
  check("rolling_back holds the global Apply slot", blocked);
}

// Teardown sees active Apply in the same transaction.
{
  const db = await database();
  await put(db, STORE.runs, {
    runId: "active-apply",
    approvalId: "approval",
    configurationHash: configHash,
    status: "running",
    state: "running",
    startedAt: "2026-08-24T00:00:00Z",
    finishedAt: null,
    steps: [],
  });
  let blocked = false;
  try {
    await new StateRepository(db, clock).startTeardown({
      teardownId: "td-blocked",
      runId: "completed-run",
      configurationHash: configHash,
      planHash: "p".repeat(64),
      instructions: [],
      status: "running",
    }, currentApprovalIdentity);
  } catch (error) {
    blocked = error instanceof TeardownSlotBusy;
  }
  check("teardown start is blocked by active Apply", blocked);
}

// Teardown itself is a single global slot, not one slot per source run.
{
  const db = await database();
  await put(db, STORE.teardowns, {
    teardownId: "td-first",
    runId: "run-first",
    status: "pending",
  });
  let blocked = false;
  try {
    await new StateRepository(db, clock).startTeardown({
      teardownId: "td-second",
      runId: "run-second",
      configurationHash: configHash,
      planHash: "p".repeat(64),
      instructions: [],
      status: "running",
    }, currentApprovalIdentity);
  } catch (error) {
    blocked = error instanceof TeardownSlotBusy;
  }
  check("an active teardown blocks teardown for every other run", blocked);
}

// A terminal-looking run is still active until ownership finalization commits.
{
  const db = await database();
  await put(db, STORE.runs, {
    runId: "unfinalized-run",
    approvalId: "approval",
    configurationHash: configHash,
    status: "succeeded",
    state: "succeeded",
    finalizationPending: true,
    startedAt: "2026-08-24T00:00:00Z",
    finishedAt: "2026-08-24T00:01:00Z",
    steps: [],
  });
  let blocked = false;
  try {
    await new StateRepository(db, clock).startTeardown({
      teardownId: "td-before-finalization",
      runId: "unfinalized-run",
      configurationHash: configHash,
      planHash: "p".repeat(64),
      instructions: [],
      status: "running",
    }, currentApprovalIdentity);
  } catch (error) {
    blocked = error instanceof TeardownSlotBusy;
  }
  check("unfinished ownership finalization retains the lifecycle slot", blocked);
}

// A browser crash after terminal checkpoint leaves a marker; reopening then
// finalizes run + ownership in one transaction before any alarm may clear.
{
  const factory = new IDBFactory();
  let db = await database(factory);
  await put(db, STORE.approvals, approval("approval-finalize"));
  let repository = new StateRepository(db, clock);
  const { run } = await repository.consumeApprovalAndCreateRun(
    "approval-finalize",
    currentApprovalIdentity,
  );
  await put(db, STORE.runs, {
    ...run,
    status: "succeeded",
    state: "succeeded",
    finalizationPending: true,
    steps: run.steps.map((step) => ({ ...step, status: "done" })),
  });
  db.close();
  db = await openDatabase(factory);
  repository = new StateRepository(db, clock);
  const pending = await repository.run(run.runId) as unknown as RunRecord;
  check("terminal crash marker survives database reopen", pending.finalizationPending === true);
  await repository.finalizeRunInventory(pending, [{
    resourceKey: "beyondcorp:application:demo-app",
    provider: "beyondcorp",
    resourceType: "application",
    resourceName: "demo-app",
    owned: true,
    shared: false,
    requestId: pending.steps[0]?.requestId,
  }]);
  const finalized = await repository.run(run.runId);
  const resources = await repository.resources(run.runId);
  check(
    "terminal marker and ownership inventory commit atomically",
    finalized?.finalizationPending === false && resources.length === 1 &&
      resources[0]?.resourceName === "demo-app",
  );
  if (finalized === undefined) throw new Error("finalized run missing");
  const reclassified: RunRecord = {
    ...(finalized as unknown as RunRecord),
    state: "rollback_unavailable" as const,
    finalizationPending: true,
    finalizedAt: null,
  };
  await put(db, STORE.runs, { ...reclassified, status: reclassified.state });
  await repository.finalizeRunInventory(reclassified, []);
  check(
    "refinalization replaces stale ownership rows with the exact residual set",
    (await repository.resources(run.runId)).length === 0,
  );
}

// Markerless BeyondCorp proofs are accepted only from an integrity-valid,
// finalized run for this exact approved specification.
{
  const factory = new IDBFactory();
  const db = await database(factory);
  await put(db, STORE.approvals, approval("approval-gateway-proof"));
  const repository = new StateRepository(db, clock);
  const { run } = await repository.consumeApprovalAndCreateRun(
    "approval-gateway-proof",
    currentApprovalIdentity,
  );
  const requestId = run.steps[0]!.requestId;
  const resourceUrl =
    `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
    "/locations/global/securityGateways/default";
  const checkpoint = {
    kind: "generic_created_resource",
    protocolVersion: 2,
    phase: "applied",
    resourceKey: "beyondcorp:security_gateway:default",
    createUrl: resourceUrl.slice(0, resourceUrl.lastIndexOf("/")),
    resourceUrl,
    createRequestId: requestId,
    expectedParamsDigest: canonicalDigestSync({
      securityGatewayId: "default",
      requestId,
    }),
    expectedPayloadDigest: canonicalDigestSync({
      displayName: "default",
      serviceDiscovery: {},
      logging: {},
    }),
    ownershipMarker: null,
    providerIdentityField: "createTime",
    providerIdentity: "2026-08-24T00:00:01Z",
  };
  await put(db, STORE.runs, {
    ...run,
    status: "succeeded",
    state: "succeeded",
    finalizationPending: true,
    steps: run.steps.map((step) => ({ ...step, status: "done" })),
  });
  const pending = await repository.run(run.runId) as unknown as RunRecord;
  await repository.finalizeRunInventory(pending, [{
    resourceKey: "beyondcorp:security_gateway:default",
    provider: "beyondcorp",
    resourceType: "security_gateway",
    resourceName: "default",
    owned: false,
    shared: true,
    requestId,
    beforeImage: checkpoint,
  }]);

  const exact = await repository.ownershipProofResources(spec);
  const proof = discoveryOwnershipProofs(exact, spec)[
    "beyondcorp:security_gateway:default"
  ];
  const otherProject = parseDeploymentSpec({
    ...specToJson(spec),
    project_id: "enterprise-secgw-02",
  });
  const crossScope = await repository.ownershipProofResources(otherProject);
  const ambiguous = discoveryOwnershipProofs([
    ...exact,
    {
      ...exact[0],
      id: "other-run:beyondcorp:security_gateway:default",
      runId: "other-run",
      beforeImage: {
        ...checkpoint,
        providerIdentity: "2026-08-24T00:00:02Z",
      },
    },
  ], spec);
  check(
    "finalized same-scope shared gateway createTime is usable without becoming owned",
    proof?.providerIdentityField === "createTime" &&
      proof.providerIdentity === "2026-08-24T00:00:01Z" && exact[0]?.owned === false,
  );
  check("ownership proof lookup rejects a cross-project configuration", crossScope.length === 0);
  check(
    "conflicting exact-scope provider identities drop only the ambiguous resource key",
    ambiguous["beyondcorp:security_gateway:default"] === undefined,
  );
  db.close();
}

// Both post-deploy IAM ownership deltas advance in one resources+runs commit.
{
  const db = await database();
  const runId = "policy-update-run";
  const approved = approval("approval");
  approved.consumedAt = "2026-08-24T00:00:00Z";
  await put(db, STORE.approvals, approved);
  await put(db, STORE.runs, {
    runId,
    approvalId: "approval",
    configurationHash: configHash,
    status: "succeeded",
    state: "succeeded",
    finalizationPending: false,
    deployerIdentity,
    startedAt: "2026-08-24T00:00:00Z",
    finishedAt: "2026-08-24T00:01:00Z",
    steps: [],
  });
  const original = { etag: "original", bindings: [] };
  const applied = { etag: "applied", bindings: [{ role: "roles/test", members: ["user:a"] }] };
  const updated = { etag: "updated", bindings: [{ role: "roles/test", members: ["user:b"] }] };
  const beforeImage = {
    kind: "iam",
    getUrl: "https://example.test:getIamPolicy",
    setUrl: "https://example.test:setIamPolicy",
    policy: original,
    afterPolicy: applied,
  };
  for (const [key, type] of [
    ["beyondcorp:application_iam:app-access", "application_iam"],
    ["beyondcorp:gateway_iam:gateway-access", "gateway_iam"],
  ]) {
    await put(db, STORE.resources, {
      id: `${runId}:${key}`,
      runId,
      resourceKey: key,
      provider: "beyondcorp",
      resourceType: type,
      resourceName: key.split(":").at(-1),
      owned: true,
      shared: false,
      beforeImage,
    });
  }
  const repository = new StateRepository(db, clock);
  const target = (resourceKey: string) => ({
    resourceKey,
    getUrl: "https://example.test:getIamPolicy",
    setUrl: "https://example.test:setIamPolicy",
    beforePolicy: applied,
    afterPolicy: updated,
    inventoryBeforeImageDigest: canonicalDigestSync(beforeImage),
  });
  const checkpointId = "policy-checkpoint";
  await repository.beginRunPolicyUpdate(runId, {
    checkpointId,
    requestedAccessLevel: "NONE",
    principals: ["user:b"],
    actor: "operator@example.com",
    startedAt: "2026-08-24T00:02:00Z",
    phase: "prepared",
    application: target("beyondcorp:application_iam:app-access"),
    gateway: target("beyondcorp:gateway_iam:gateway-access"),
  }, currentApprovalIdentity);
  await repository.checkpointRunPolicyUpdatePhase(runId, checkpointId, "application_applied");
  await repository.checkpointRunPolicyUpdatePhase(runId, checkpointId, "gateway_applied");
  await repository.commitRunPolicyUpdate(runId, checkpointId);
  const resources = await repository.resources(runId);
  const committedRun = await repository.run(runId);
  check(
    "both latest IAM deltas and run state commit together",
    resources.length === 2 && resources.every((resource) =>
      JSON.stringify((resource.beforeImage as { policy?: unknown }).policy) ===
        JSON.stringify(original) &&
      JSON.stringify((resource.beforeImage as { afterPolicy?: unknown }).afterPolicy) ===
        JSON.stringify(updated)) &&
      committedRun?.policyUpdateCheckpoint === undefined,
  );
}

// Initial teardown and post-deploy policy mutation re-check the human and
// deployer identities inside the same transaction that acquires the lifecycle
// slot. A profile switch cannot race a read-only router check.
{
  const db = await database();
  const runId = "actor-continuity-run";
  const approved = approval("actor-continuity-approval");
  approved.consumedAt = "2026-08-24T00:00:00Z";
  await put(db, STORE.approvals, approved);
  await put(db, STORE.runs, {
    runId,
    approvalId: approved.approvalId,
    configurationHash: configHash,
    status: "succeeded",
    state: "succeeded",
    finalizationPending: false,
    deployerIdentity,
    startedAt: "2026-08-24T00:00:00Z",
    finishedAt: "2026-08-24T00:01:00Z",
    steps: [],
  });
  const bobIdentity = {
    ...deployerIdentity,
    operatorEmail: "different-admin@example.com",
    operatorSubject: "different-admin-subject-123",
  };
  const bob = { operator: "different-admin@example.com", deployerIdentity: bobIdentity };
  const repository = new StateRepository(db, clock);
  let updateRejected = false;
  try {
    const target = {
      resourceKey: "beyondcorp:application_iam:app-access",
      getUrl: "https://example.test:getIamPolicy",
      setUrl: "https://example.test:setIamPolicy",
      beforePolicy: { etag: "before" },
      afterPolicy: { etag: "after" },
      inventoryBeforeImageDigest: "a".repeat(64),
    };
    await repository.beginRunPolicyUpdate(runId, {
      protocolVersion: 2,
      checkpointId: "actor-continuity-checkpoint",
      requestedAccessLevel: "NONE",
      principals: ["user:other@example.com"],
      actor: bob.operator,
      startedAt: "2026-08-24T00:02:00Z",
      phase: "prepared",
      application: target,
      gateway: { ...target, resourceKey: "beyondcorp:gateway_iam:gateway-access" },
    }, bob);
  } catch (error) {
    updateRejected = error instanceof ApprovalRejected;
  }
  let teardownRejected = false;
  try {
    await repository.startTeardown({
      teardownId: "actor-continuity-teardown",
      runId,
      configurationHash: configHash,
      planHash: "b".repeat(64),
      instructions: [],
      status: "running",
      startedAt: "2026-08-24T00:02:00Z",
    }, bob);
  } catch (error) {
    teardownRejected = error instanceof ApprovalRejected;
  }
  check(
    "initial teardown and policy update atomically reject a different operator",
    updateRejected && teardownRejected &&
      (await repository.run(runId))?.policyUpdateCheckpoint === undefined &&
      await repository.teardown("actor-continuity-teardown") === undefined,
  );
}

// The last provider success atomically releases inventory, terminalizes the
// teardown, marks both run state fields deleted, and appends its evidence.
{
  const db = await database();
  const runId = "atomic-teardown-run";
  const teardownId = "atomic-teardown";
  const resourceKey = "beyondcorp:application:demo-app";
  await put(db, STORE.runs, {
    runId,
    approvalId: "approval",
    configurationHash: configHash,
    status: "succeeded",
    state: "succeeded",
    finalizationPending: false,
    startedAt: "2026-08-24T00:00:00Z",
    finishedAt: "2026-08-24T00:01:00Z",
    steps: [],
  });
  await put(db, STORE.resources, {
    id: `${runId}:${resourceKey}`,
    runId,
    resourceKey,
    provider: "beyondcorp",
    resourceType: "application",
    resourceName: "demo-app",
    owned: true,
    shared: false,
  });
  const teardown: Record<string, unknown> = {
    teardownId,
    runId,
    configurationHash: configHash,
    planHash: "f".repeat(64),
    status: "running",
    startedAt: "2026-08-24T00:02:00Z",
    completedAt: null,
    instructions: [{ resourceKey }],
    operations: [{
      resource_key: resourceKey,
      request_id: "request-id",
      status: "running",
      error_code: null,
      started_at: "2026-08-24T00:02:00Z",
      completed_at: null,
    }],
  };
  teardown.immutableDigest = teardownImmutableDigest(teardown);
  await put(db, STORE.teardowns, teardown);

  const repository = new StateRepository(db, clock);
  await repository.commitTeardownResourceSuccess({
    teardownId,
    runId,
    resourceKey,
    outcome: "deleted",
    completedAt: "2026-08-24T00:03:00Z",
  });
  const firstAuditCount = (await repository.auditEvents()).length;
  // A retry after acknowledgement loss must not append duplicate evidence.
  await repository.commitTeardownResourceSuccess({
    teardownId,
    runId,
    resourceKey,
    outcome: "deleted",
    completedAt: "2026-08-24T00:03:00Z",
  });
  const durableRun = await repository.run(runId);
  const durableTeardown = await repository.teardown(teardownId);
  check(
    "final teardown commit is atomic and sets state plus status deleted",
    (await repository.resources(runId)).length === 0 &&
      durableRun?.status === "deleted" && durableRun.state === "deleted" &&
      durableTeardown?.status === "succeeded" &&
      (durableTeardown.operations as Array<{ status: string }>)[0]?.status === "succeeded",
  );
  check(
    "final teardown commit is idempotent without duplicate audit events",
    firstAuditCount === 2 && (await repository.auditEvents()).length === firstAuditCount,
  );
}

// Acceptance evidence is valid only for a finalized successful run, and the
// status check shares the same transaction as the evidence row.
{
  const evidence = {
    testId: "T01",
    status: "passed",
    summary: "Verified",
    evidence: "machine result",
    source: "system_verified",
    actor: "operator@example.com",
  };
  const rejectedStates = ["running", "interrupted", "failed"] as const;
  let rejected = 0;
  for (const status of rejectedStates) {
    const db = await database();
    const runId = `acceptance-${status}`;
    await put(db, STORE.runs, {
      runId,
      approvalId: "approval",
      configurationHash: configHash,
      status,
      state: status,
      startedAt: "2026-08-24T00:00:00Z",
      finishedAt: status === "running" ? null : "2026-08-24T00:01:00Z",
      steps: [],
    });
    const repository = new StateRepository(db, clock);
    try {
      await repository.recordAcceptance({ runId, ...evidence });
    } catch (error) {
      if ((error as Error).message === "acceptance-run-not-succeeded") rejected += 1;
    }
  }
  check(
    "acceptance rows reject running, interrupted, and failed runs",
    rejected === rejectedStates.length,
  );

  const db = await database();
  const runId = "acceptance-succeeded";
  await put(db, STORE.runs, {
    runId,
    approvalId: "approval",
    configurationHash: configHash,
    status: "succeeded",
    state: "succeeded",
    finalizationPending: false,
    startedAt: "2026-08-24T00:00:00Z",
    finishedAt: "2026-08-24T00:01:00Z",
    steps: [],
  });
  const repository = new StateRepository(db, clock);
  await repository.recordAcceptance({ runId, ...evidence });
  check(
    "acceptance row and audit event commit for a finalized successful run",
    (await repository.acceptance(runId)).length === 1 &&
      (await repository.auditEvents()).some((event) => event.eventType === "acceptance.recorded"),
  );
}

// Upgrade/cold-start recovery closes the legacy 0.2.0 window where the final
// inventory delete committed but progress and run deletion did not.
{
  const db = await database();
  const runId = "legacy-final-release-run";
  const teardownId = "legacy-final-release-teardown";
  const resourceKey = "beyondcorp:application:legacy-app";
  await put(db, STORE.runs, {
    runId,
    approvalId: "approval",
    configurationHash: configHash,
    status: "succeeded",
    state: "succeeded",
    startedAt: "2026-08-24T00:00:00Z",
    finishedAt: "2026-08-24T00:01:00Z",
    steps: [],
  });
  const teardown: Record<string, unknown> = {
    teardownId,
    runId,
    configurationHash: configHash,
    planHash: "e".repeat(64),
    status: "running",
    startedAt: "2026-08-24T00:02:00Z",
    completedAt: null,
    instructions: [{ resourceKey }],
    operations: [{
      resource_key: resourceKey,
      request_id: "request-id",
      status: "running",
      error_code: null,
      started_at: "2026-08-24T00:02:00Z",
      completed_at: null,
    }],
  };
  teardown.immutableDigest = teardownImmutableDigest(teardown);
  await put(db, STORE.teardowns, teardown);

  const repository = new StateRepository(db, clock);
  const interrupted = await repository.reconcileInterruptedTeardowns();
  const recoveredRun = await repository.run(runId);
  const recoveredTeardown = await repository.teardown(teardownId);
  check(
    "cold start terminalizes a legacy final-release crash idempotently",
    interrupted.length === 0 && recoveredRun?.state === "deleted" &&
      recoveredRun.status === "deleted" && recoveredTeardown?.status === "succeeded" &&
      (recoveredTeardown.operations as Array<{ status: string }>)[0]?.status === "succeeded",
  );
  const auditCount = (await repository.auditEvents()).length;
  await repository.reconcileInterruptedTeardowns();
  check(
    "cold teardown reconciliation does not duplicate terminal evidence",
    (await repository.auditEvents()).length === auditCount,
  );
}

// Tenant logs are evidence-bearing run data. A different signed-in operator
// or a same-name replacement deployer must be rejected before either the
// Security Gateway state read or Cloud Logging query reaches Google.
{
  const factory = new IDBFactory();
  Object.defineProperty(globalThis, "indexedDB", {
    configurable: true,
    value: factory,
  });
  const db = await database(factory);
  const approved = approval("logs-identity-approval");
  approved.consumedAt = "2026-08-24T00:00:00Z";
  await put(db, STORE.approvals, approved);
  await put(db, STORE.runs, {
    runId: "logs-identity-run",
    approvalId: approved.approvalId,
    configurationHash: configHash,
    status: "succeeded",
    state: "succeeded",
    finalizationPending: false,
    deployerIdentity,
    startedAt: "2026-08-24T00:00:00Z",
    finishedAt: "2026-08-24T00:01:00Z",
    steps: [],
  });
  const providerCalls: string[] = [];
  const transport: Transport = {
    async requestJson(method, url) {
      providerCalls.push(`${method} ${url}`);
      return { status: 200, payload: {} };
    },
  };
  let operator = "different-admin@example.com";
  let liveDeployer = deployerIdentity;
  const routeContext = {
    discoveryTransport: transport,
    transport,
    administratorTransport: transport,
    cloudIdentity: async () => liveDeployer.serviceAccountEmail,
    operatorEmail: async () => operator,
    accessPolicyId: async () => undefined,
    rememberAccessPolicyId: async () => undefined,
    bootstrapOwnershipPin: async () => undefined,
    assertBootstrapOperator: async () => undefined,
    checkpointBootstrapOwnershipPin: async () => undefined,
    clearBootstrapOwnershipPin: async () => undefined,
    legacyDeployerIdentity: async () => undefined,
    rememberDeployer: async () => undefined,
    requireDeployer: async (_projectId, expected) => {
      if (JSON.stringify(expected) !== JSON.stringify(liveDeployer)) {
        throw new Error("deployer-identity-changed");
      }
      return liveDeployer;
    },
    startApply: async () => ({ run_id: "unused" }),
    resumeApply: async () => ({}),
    runState: async () => ({}),
  } as RouteContext;

  let wrongOperatorRejected = false;
  try {
    await route(
      routeContext,
      "GET",
      "/api/v1/runs/logs-identity-run/logs?category=connection",
      undefined,
    );
  } catch (error) {
    wrongOperatorRejected = error instanceof RouteError &&
      error.code === "operator-identity-changed";
  }
  operator = deployerIdentity.operatorEmail;
  liveDeployer = {
    ...deployerIdentity,
    serviceAccountUniqueId: "999999999999999999999",
  };
  let wrongDeployerRejected = false;
  try {
    await route(
      routeContext,
      "GET",
      "/api/v1/runs/logs-identity-run/logs?category=connection",
      undefined,
    );
  } catch (error) {
    wrongDeployerRejected = (error as Error).message === "deployer-identity-changed";
  }
  check(
    "gateway log reads reject changed operator/deployer before every Google call",
    wrongOperatorRejected && wrongDeployerRejected && providerCalls.length === 0,
  );
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} lifecycle checks`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} IndexedDB lifecycle checks passed.`);
