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
 *   - **Confidentiality of the store.** Every product row is AES-256-GCM
 *     encrypted before IndexedDB sees it. A durable non-extractable CryptoKey
 *     survives MV3 worker restarts through structured clone, while AAD binds
 *     each ciphertext to its schema, store, and hashed record key. Deleting
 *     the browser profile destroys the key and store together, so evidence
 *     export remains the administrator's portable record.
 */

import { buildAuditEvent, type AuditEventRecord } from "./audit.ts";
import {
  acceptanceAuditPayload,
} from "./acceptance-integrity.ts";
import { canonicalDigestSync } from "../domain/canonical.ts";
import { isSupportedDeployerServiceAccountEmail } from "../domain/deployer-identity.ts";
import { configurationHash, type DeploymentPlan } from "../domain/planner.ts";
import { parseDeploymentSpec, type DeploymentSpec } from "../domain/spec.ts";
import {
  LIFECYCLE_SCHEMA_VERSION,
  planRun,
  rollbackCompensationPreflight,
  type ResourceOwnershipRecord,
  type RollbackCompensationPreflight,
  type RunRecord,
} from "../runtime/run-engine.ts";
import {
  activateAcceptedEncryption,
  ensureSecureSchema,
  secureObjectStore,
  type SecureObjectStore,
} from "./secure-storage.ts";

export const DATABASE_NAME = "secure-gateway-studio";
export const DATABASE_VERSION = 5;

export const STORE = {
  drafts: "deployment_drafts",
  resources: "deployment_resources",
  acceptance: "acceptance_results",
  teardowns: "deployment_teardowns",
  plans: "prepared_plans",
  approvals: "approved_plans",
  runs: "deployment_runs",
  operations: "run_operations",
  cepLeases: "cep_mutation_leases",
  audit: "audit_events",
} as const;

export type RunStatus =
  | "pending"
  | "running"
  | "rolling_back"
  | "succeeded"
  | "failed"
  | "rolled_back"
  | "rollback_failed"
  | "rollback_unavailable"
  | "interrupted"
  | "cancelled"
  | "deleted";

export interface DeployerIdentityBinding {
  serviceAccountEmail: string;
  serviceAccountUniqueId: string;
  projectId: string;
  /** Google-attested human identity that is the sole Token Creator. */
  operatorEmail: string;
  /** Immutable Google account subject; email alone can be reassigned. */
  operatorSubject: string;
}

export interface ApprovedPlanRecord {
  /** Durable lifecycle schema; absent only on records created by older builds. */
  schemaVersion?: number;
  approvalId: string;
  configurationHash: string;
  planHash: string;
  planJson: string;
  specificationJson: string;
  approvedBy: string;
  approvedAt: string;
  expiresAt: string;
  consumedAt: string | null;
  /** Exact pinned product-scoped identity trusted when the operator approved. */
  deployerIdentity: DeployerIdentityBinding;
  /**
   * Older builds incorrectly attributed approval to the deployer SA. This
   * marker preserves that historical value while binding recovery to the
   * Google-attested human email and immutable subject.
   */
  legacyOperatorBinding?: {
    legacyApprovedBy: string;
    operatorEmail: string;
    operatorSubject: string;
    adoptedAt: string;
  };
}

export interface DeploymentRunRecord {
  /** Durable lifecycle schema; absent only on records created by older builds. */
  schemaVersion?: number;
  runId: string;
  approvalId: string;
  configurationHash: string;
  status: RunStatus;
  /** Durable engine state. Newer records keep this equal to `status`. */
  state?: RunStatus;
  startedAt: string;
  finishedAt: string | null;
  managedChromeAccessLevel?: string;
  policyPrincipals?: string[];
  /** Terminal engine state is not complete until ownership is atomically committed. */
  finalizationPending?: boolean;
  finalizedAt?: string | null;
  /** Durable saga checkpoint for post-deploy IAM policy changes. */
  policyUpdateCheckpoint?: PolicyUpdateCheckpoint;
  /** Immutable copy of the identity bound into the consumed approval. */
  deployerIdentity?: DeployerIdentityBinding;
  /** Only legacy/manual interruption records use this; normal MV3 resumes stay active. */
  interruptedFrom?: "running" | "rolling_back";
  reauthRequired?: boolean;
  interruptionErrorCode?: string;
}

export interface PolicyUpdateResourceCheckpoint {
  resourceKey: string;
  getUrl: string;
  setUrl: string;
  beforePolicy: Record<string, unknown>;
  afterPolicy: Record<string, unknown>;
  inventoryBeforeImageDigest: string;
}

export interface PolicyUpdateCheckpoint {
  /** v2 checkpoints persist a `*_sending` boundary before every provider call. */
  protocolVersion?: 2;
  checkpointId: string;
  requestedAccessLevel: string;
  principals: string[];
  actor: string;
  startedAt: string;
  phase:
    | "prepared"
    | "application_sending"
    | "application_applied"
    | "gateway_sending"
    | "gateway_applied";
  application: PolicyUpdateResourceCheckpoint;
  gateway: PolicyUpdateResourceCheckpoint;
}

export type PolicyUpdateTarget = "application" | "gateway";

/**
 * Decide which provider writes are proven to belong to this saga.
 *
 * A `*_sending` checkpoint means the worker may have died after the request
 * reached Google but before its response was durably observed. A matching
 * live binding is not proof that this request created it, so cold recovery
 * and response-loss handling must retain the checkpoint for manual review.
 * An explicit HTTP rejection is different: it proves that target did not
 * apply and permits compensation of only earlier, confirmed targets.
 */
export function policyUpdateCompensationTargets(
  phase: PolicyUpdateCheckpoint["phase"],
  currentRequestDefinitelyRejected = false,
  protocolVersion?: PolicyUpdateCheckpoint["protocolVersion"],
): PolicyUpdateTarget[] | null {
  if (protocolVersion !== 2) {
    // 0.2.0 wrote only post-response phases. `prepared` may therefore mean
    // Application response loss, and `application_applied` may mean Gateway
    // response loss. Preserve both as manual residuals during upgrade.
    if (phase === "prepared" || phase === "application_applied") return null;
    if (phase === "gateway_applied") return ["application", "gateway"];
  }
  switch (phase) {
    case "prepared":
      return [];
    case "application_sending":
      return currentRequestDefinitelyRejected ? [] : null;
    case "application_applied":
      return ["application"];
    case "gateway_sending":
      return currentRequestDefinitelyRejected ? ["application"] : null;
    case "gateway_applied":
      return ["application", "gateway"];
  }
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

export class TeardownSlotBusy extends Error {
  constructor(runId: string) {
    super(`A teardown is already active for run ${runId}`);
    this.name = "TeardownSlotBusy";
  }
}

export class CepMutationLeaseBusy extends Error {
  readonly code:
    | "cep-mutation-active"
    | "cep-mutation-recovery-required"
    | "cep-lifecycle-active";
  readonly leaseKey: string;

  constructor(
    code:
      | "cep-mutation-active"
      | "cep-mutation-recovery-required"
      | "cep-lifecycle-active",
    leaseKey: string,
  ) {
    super(
      code === "cep-mutation-active"
        ? `A CEP mutation is already active for ${leaseKey}`
        : code === "cep-mutation-recovery-required"
          ? `An interrupted CEP mutation for ${leaseKey} must be resumed with its exact request`
          : `Deployment lifecycle work is active for ${leaseKey}`,
    );
    this.name = "CepMutationLeaseBusy";
    this.code = code;
    this.leaseKey = leaseKey;
  }
}

/** Longer than the external transport timeout; renewals fence every mutation. */
export const CEP_MUTATION_LEASE_MS = 5 * 60_000;

export interface CepMutationLeaseRecord {
  leaseKey: string;
  operationId: string;
  operationKind: "provision" | "rollback" | "assign_licenses";
  requestDigest: string;
  ownerToken: string;
  acquiredAt: string;
  updatedAt: string;
  expiresAt: string;
}

export interface CepMutationLeaseHandle {
  scopeKeys: string[];
  operationId: string;
  operationKind: CepMutationLeaseRecord["operationKind"];
  requestDigest: string;
  ownerToken: string;
  recovered: boolean;
  expiresAt: string;
}

export const ACTIVE_RUN_STATUSES: readonly RunStatus[] = [
  "pending",
  "running",
  "rolling_back",
];

export function runHasActiveWork(record: Partial<DeploymentRunRecord>): boolean {
  const status = record.state ?? record.status;
  return ACTIVE_RUN_STATUSES.includes(status as RunStatus) ||
    record.finalizationPending === true ||
    record.policyUpdateCheckpoint !== undefined;
}

export function teardownHasActiveWork(record: Record<string, unknown>): boolean {
  return record.status === "pending" || record.status === "running";
}

export function teardownImmutableDigest(record: Record<string, unknown>): string {
  return canonicalDigestSync({
    teardown_id: String(record.teardownId ?? ""),
    run_id: String(record.runId ?? ""),
    configuration_hash: String(record.configurationHash ?? ""),
    plan_hash: String(record.planHash ?? ""),
    instructions: Array.isArray(record.instructions)
      ? structuredClone(record.instructions)
      : [],
  });
}

/**
 * Build the complete engine checkpoint before the approval transaction writes.
 * There is never a durable `running` record with an empty/placeholder step set.
 */
export function initialRunRecord(options: {
  approval: ApprovedPlanRecord;
  runId: string;
  startedAt: string;
}): DeploymentRunRecord & RunRecord {
  const plan = JSON.parse(options.approval.planJson) as DeploymentPlan;
  if (!Array.isArray(plan.changes)) {
    throw new ApprovalRejected("The approved plan has no executable change list");
  }
  const engine = planRun({
    runId: options.runId,
    approvalId: options.approval.approvalId,
    configurationHash: options.approval.configurationHash,
    changes: plan.changes,
    publicCertificateBinding: plan.public_certificate_binding ?? null,
    sourceImageBinding: plan.source_image_binding ?? null,
  });
  return {
    ...engine,
    status: "running",
    startedAt: options.startedAt,
    finishedAt: null,
    finalizationPending: false,
    finalizedAt: null,
    deployerIdentity: structuredClone(options.approval.deployerIdentity),
  };
}

function validDeployerIdentity(value: unknown): value is DeployerIdentityBinding {
  if (typeof value !== "object" || value === null) return false;
  const identity = value as Partial<DeployerIdentityBinding>;
  return typeof identity.projectId === "string" &&
    /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(identity.projectId) &&
    isSupportedDeployerServiceAccountEmail(
      identity.serviceAccountEmail,
      identity.projectId,
    ) &&
    typeof identity.serviceAccountUniqueId === "string" &&
    /^\d+$/.test(identity.serviceAccountUniqueId) &&
    typeof identity.operatorEmail === "string" &&
    /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(identity.operatorEmail) &&
    identity.operatorEmail === identity.operatorEmail.toLowerCase() &&
    typeof identity.operatorSubject === "string" &&
    /^[A-Za-z0-9_-]{6,255}$/.test(identity.operatorSubject);
}

function sameDeployerIdentity(left: unknown, right: unknown): boolean {
  return validDeployerIdentity(left) && validDeployerIdentity(right) &&
    canonicalDigestSync(left) === canonicalDigestSync(right);
}

function approvalOperatorMatches(
  approval: ApprovedPlanRecord,
  current: { operator: string; deployerIdentity: DeployerIdentityBinding },
): boolean {
  const operator = current.operator.trim().toLowerCase();
  if (operator === approval.approvedBy.trim().toLowerCase()) return true;
  const binding = approval.legacyOperatorBinding;
  return binding !== undefined &&
    sameDeployerIdentity(current.deployerIdentity, approval.deployerIdentity) &&
    binding.legacyApprovedBy === approval.approvedBy &&
    isSupportedDeployerServiceAccountEmail(
      binding.legacyApprovedBy,
      current.deployerIdentity.projectId,
    ) &&
    binding.operatorEmail === operator &&
    binding.operatorEmail === current.deployerIdentity.operatorEmail &&
    binding.operatorSubject === current.deployerIdentity.operatorSubject &&
    Number.isFinite(Date.parse(binding.adoptedAt));
}

function currentIdentityMatchesRunApproval(
  run: DeploymentRunRecord,
  approval: ApprovedPlanRecord | undefined,
  current: { operator: string; deployerIdentity: DeployerIdentityBinding },
): boolean {
  return approval !== undefined && approval.consumedAt !== null &&
    approvalOperatorMatches(approval, current) &&
    sameDeployerIdentity(current.deployerIdentity, run.deployerIdentity) &&
    sameDeployerIdentity(current.deployerIdentity, approval.deployerIdentity);
}

interface IamInventoryBeforeImage {
  kind: "iam";
  getUrl?: string;
  getMethod?: "GET" | "POST";
  setUrl: string;
  policy: Record<string, unknown>;
  afterPolicy: Record<string, unknown>;
}

export function iamInventoryBeforeImage(value: unknown): IamInventoryBeforeImage {
  if (
    typeof value !== "object" || value === null ||
    (value as { kind?: unknown }).kind !== "iam" ||
    typeof (value as { setUrl?: unknown }).setUrl !== "string" ||
    typeof (value as { policy?: unknown }).policy !== "object" ||
    (value as { policy?: unknown }).policy === null ||
    typeof (value as { afterPolicy?: unknown }).afterPolicy !== "object" ||
    (value as { afterPolicy?: unknown }).afterPolicy === null
  ) {
    throw new Error("iam-inventory-before-image-invalid");
  }
  return structuredClone(value) as IamInventoryBeforeImage;
}

export function withLatestIamAfterPolicy(
  value: unknown,
  afterPolicy: Record<string, unknown>,
): IamInventoryBeforeImage {
  const before = iamInventoryBeforeImage(value);
  return { ...before, afterPolicy: structuredClone(afterPolicy) };
}

interface StoredPlanGate {
  gate_id?: unknown;
  status?: unknown;
  blocking?: unknown;
  detail?: unknown;
}

interface StoredPlan {
  can_apply?: unknown;
  gates?: unknown;
}

/**
 * Refuse approval and Apply for a plan whose server-computed safety gates do
 * not pass. Kept as a pure function so the invariant can be regression-tested
 * without an IndexedDB/browser harness.
 */
export function assertPlanCanApply(planJson: string): void {
  let plan: StoredPlan;
  try {
    plan = JSON.parse(planJson) as StoredPlan;
  } catch {
    throw new ApprovalRejected("The prepared plan is invalid");
  }

  const gates = Array.isArray(plan.gates) ? (plan.gates as StoredPlanGate[]) : [];
  const blockingGate = gates.find(
    (gate) => gate.blocking === true && gate.status !== "pass",
  );
  if (plan.can_apply !== true || blockingGate !== undefined) {
    throw new ApprovalRejected(
      "The prepared plan contains blocking safety gates and cannot be approved",
    );
  }
}

/**
 * Validate an unapproved plan and record the one transition approval is
 * allowed to make: `human-approval` pending -> pass. Every other blocking
 * safety decision remains server-computed and immutable.
 */
export function approvePlanJson(planJson: string, approvedBy: string): string {
  if (approvedBy.trim() === "") throw new ApprovalRejected("approved_by is required");
  let plan: StoredPlan & Record<string, unknown>;
  try {
    plan = JSON.parse(planJson) as StoredPlan & Record<string, unknown>;
  } catch {
    throw new ApprovalRejected("The prepared plan is invalid");
  }
  if (!Array.isArray(plan.gates)) {
    throw new ApprovalRejected("The prepared plan has no safety gates");
  }
  const gates = plan.gates as StoredPlanGate[];
  const approvalGate = gates.find((gate) => gate.gate_id === "human-approval");
  if (approvalGate === undefined || approvalGate.blocking !== true) {
    throw new ApprovalRejected("The prepared plan has no blocking human approval gate");
  }
  const blocked = gates.find(
    (gate) =>
      gate.gate_id !== "human-approval" &&
      gate.blocking === true &&
      gate.status !== "pass",
  );
  if (blocked !== undefined) {
    throw new ApprovalRejected("Blocking deployment gates must pass before approval");
  }
  approvalGate.status = "pass";
  approvalGate.detail = `Approved by ${approvedBy.trim()}.`;
  plan.can_apply = true;
  const approved = JSON.stringify(plan);
  assertPlanCanApply(approved);
  return approved;
}

export function assertApprovalTtl(ttlMinutes: number): void {
  if (!Number.isInteger(ttlMinutes) || ttlMinutes < 1 || ttlMinutes > 120) {
    throw new ApprovalRejected("Approval TTL must be between 1 and 120 minutes");
  }
}

export function assertPreparedPlanFresh(expiresAt: unknown, now: Date): void {
  if (typeof expiresAt !== "string" || Date.parse(expiresAt) <= now.getTime()) {
    throw new ApprovalRejected("The prepared plan has expired; run preflight again");
  }
}

/** Recompute the immutable plan/specification binding shared with legacy approvals. */
function assertApprovalPayloadIntegrity(approval: ApprovedPlanRecord): string {
  let plan: Record<string, unknown>;
  let specification: Record<string, unknown>;
  try {
    const parsedPlan = JSON.parse(approval.planJson) as unknown;
    const parsedSpecification = JSON.parse(approval.specificationJson) as unknown;
    if (
      parsedPlan === null || Array.isArray(parsedPlan) || typeof parsedPlan !== "object" ||
      parsedSpecification === null || Array.isArray(parsedSpecification) ||
      typeof parsedSpecification !== "object"
    ) {
      throw new Error("approval payload is not an object");
    }
    plan = parsedPlan as Record<string, unknown>;
    specification = parsedSpecification as Record<string, unknown>;
  } catch {
    throw new ApprovalRejected("The approved plan or specification is invalid");
  }

  let expectedConfigurationHash: string;
  let specificationProjectId: string;
  try {
    const parsed = parseDeploymentSpec(specification);
    expectedConfigurationHash = configurationHash(parsed);
    specificationProjectId = parsed.project_id;
  } catch {
    throw new ApprovalRejected("The approved specification is invalid");
  }
  if (
    canonicalDigestSync(plan) !== approval.planHash ||
    expectedConfigurationHash !== approval.configurationHash ||
    plan.configuration_hash !== approval.configurationHash
  ) {
    throw new ApprovalRejected(
      "The approved plan or specification no longer matches its recorded hash",
    );
  }
  return specificationProjectId;
}

/** Recompute every binding an approval relies on before it can mutate state. */
export function assertApprovalIntegrity(approval: ApprovedPlanRecord): void {
  const specificationProjectId = assertApprovalPayloadIntegrity(approval);
  if (
    !validDeployerIdentity(approval.deployerIdentity) ||
    approval.deployerIdentity.projectId !== specificationProjectId
  ) {
    throw new ApprovalRejected(
      "The approved deployer identity does not match the approved project",
    );
  }
  if (approval.legacyOperatorBinding !== undefined) {
    const binding = approval.legacyOperatorBinding;
    if (
      binding.legacyApprovedBy !== approval.approvedBy ||
      !isSupportedDeployerServiceAccountEmail(
        binding.legacyApprovedBy,
        approval.deployerIdentity.projectId,
      ) ||
      binding.operatorEmail !== approval.deployerIdentity.operatorEmail ||
      binding.operatorSubject !== approval.deployerIdentity.operatorSubject ||
      !Number.isFinite(Date.parse(binding.adoptedAt))
    ) {
      throw new ApprovalRejected("The legacy operator binding is invalid");
    }
  }
}

/**
 * Prove that a durable legacy checkpoint is exactly the executable portion of
 * its consumed plan before adding the immutable identity fields newer builds
 * persist. Dynamic status, attempts and before-images are intentionally not
 * rewritten or trusted as identity evidence.
 */
function assertLegacyRunCheckpointIntegrity(
  run: DeploymentRunRecord & RunRecord,
  approval: ApprovedPlanRecord,
): void {
  let plan: DeploymentPlan;
  try {
    plan = JSON.parse(approval.planJson) as DeploymentPlan;
  } catch {
    throw new ApprovalRejected("The legacy run's approved plan is invalid");
  }
  const changes = Array.isArray(plan.changes)
    ? plan.changes.filter((change) => change.action === "create")
    : [];
  if (
    run.runId.trim() === "" ||
    run.approvalId !== approval.approvalId ||
    run.configurationHash !== approval.configurationHash ||
    changes.length !== run.steps.length
  ) {
    throw new ApprovalRejected(
      "The legacy run checkpoint does not match its consumed approval. Nothing was adopted.",
    );
  }
  for (const [index, step] of run.steps.entries()) {
    const change = changes[index];
    const expectedDigest = canonicalDigestSync({
      run_id: run.runId,
      provider: change.provider,
      resource_type: change.resource_type,
      resource_name: change.resource_name,
    });
    if (
      step.index !== index ||
      canonicalDigestSync(step.change) !== canonicalDigestSync(change) ||
      step.digest !== expectedDigest ||
      typeof step.requestId !== "string" || step.requestId.trim() === ""
    ) {
      throw new ApprovalRejected(
        "The legacy run checkpoint does not match its consumed approval. Nothing was adopted.",
      );
    }
  }
}

type LifecycleSchemaState = "current" | "legacy" | "inconsistent";

function lifecycleSchemaState(
  run: DeploymentRunRecord & RunRecord,
  approval: ApprovedPlanRecord,
): LifecycleSchemaState {
  const versions = [
    run.schemaVersion,
    approval.schemaVersion,
    ...run.steps.map((step) => step.schemaVersion),
  ];
  if (versions.every((version) => version === LIFECYCLE_SCHEMA_VERSION)) return "current";
  if (versions.every((version) => version === undefined)) return "legacy";
  return "inconsistent";
}

function sameRollbackPreflight(
  left: RollbackCompensationPreflight | undefined,
  right: RollbackCompensationPreflight,
): boolean {
  return left === undefined || canonicalDigestSync(left) === canonicalDigestSync(right);
}

const EVIDENCE_SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bBearer\s+[A-Za-z0-9._~+/-]{16,}/i,
  /"?(?:access_token|refresh_token|private_key)"?\s*[:=]/i,
  /\bya29\.[A-Za-z0-9_-]+/,
];

export function assertAcceptanceRecord(record: {
  testId: string;
  caseKey?: string;
  status: string;
  summary: string;
  evidence: string;
  source: string;
}): void {
  const caseKey = record.caseKey ?? "default";
  if (!/^T0[1-9]$/.test(record.testId)) throw new Error("acceptance-test-id-invalid");
  if (!/^[a-z0-9][a-z0-9_-]{2,63}$/.test(caseKey)) throw new Error("acceptance-case-invalid");
  if (!["passed", "failed", "user_confirmed", "skipped"].includes(record.status)) {
    throw new Error("acceptance-status-invalid");
  }
  if (!["system_verified", "operator_confirmed"].includes(record.source)) {
    throw new Error("acceptance-source-invalid");
  }
  if (record.summary.trim().length < 3 || record.summary.length > 500) {
    throw new Error("acceptance-summary-invalid");
  }
  if (record.evidence.trim().length < 3 || record.evidence.length > 4_000) {
    throw new Error("acceptance-evidence-invalid");
  }
  if (EVIDENCE_SECRET_PATTERNS.some((pattern) => pattern.test(record.evidence))) {
    throw new Error("acceptance-evidence-contains-secret");
  }
}

function request<T>(source: IDBRequest<T> | Promise<T>): Promise<T> {
  if (source instanceof Promise) return source;
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

let cachedDb: IDBDatabase | null = null;
let cachedDbPromise: Promise<IDBDatabase> | null = null;

export function openDatabase(factory: IDBFactory = indexedDB): Promise<IDBDatabase> {
  const cacheConnection = factory === indexedDB;
  if (cacheConnection) {
    if (cachedDb !== null) return Promise.resolve(cachedDb);
    // Activation of the persisted encryption key is part of opening the
    // repository. Share that whole promise so a concurrent request cannot see
    // the connection during the small window before its key is cached.
    if (cachedDbPromise !== null) return cachedDbPromise;
  }
  const opening = new Promise<IDBDatabase>((resolve, reject) => {
    const open = factory.open(DATABASE_NAME, DATABASE_VERSION);
    open.onupgradeneeded = (event) => {
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
      if (!db.objectStoreNames.contains(STORE.cepLeases)) {
        db.createObjectStore(STORE.cepLeases, { keyPath: "leaseKey" });
      }
      const upgrade = open.transaction;
      if (upgrade === null) throw new Error("secure-schema-upgrade-transaction-missing");
      // Never iterate a pre-0.2.1 product store here. Encryption migration is
      // triggered only by the administrator's affirmative disclosure action.
      ensureSecureSchema(db, upgrade, event.oldVersion);
    };
    open.onsuccess = () => {
      const db = open.result;
      if (cacheConnection) {
        db.onversionchange = () => {
          db.close();
          if (cachedDb === db) cachedDb = null;
          cachedDbPromise = null;
        };
        db.onclose = () => {
          if (cachedDb === db) cachedDb = null;
          cachedDbPromise = null;
        };
      }
      void activateAcceptedEncryption(db).then(() => {
        if (cacheConnection) {
          cachedDb = db;
          cachedDbPromise = null;
        }
        resolve(db);
      }, (error: unknown) => {
        if (cacheConnection) cachedDbPromise = null;
        db.close();
        reject(error);
      });
    };
    open.onerror = () => {
      if (cacheConnection) cachedDbPromise = null;
      reject(open.error);
    };
  });
  if (cacheConnection) cachedDbPromise = opening;
  return opening;
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
    current: {
      operator: string;
      deployerIdentity: DeployerIdentityBinding;
    },
  ): Promise<{ approval: ApprovedPlanRecord; run: DeploymentRunRecord & RunRecord }> {
    const now = this.clock.now();
    const nowIso = now.toISOString();
    const runId = this.clock.uuid();

    const transaction = this.db.transaction(
      [STORE.approvals, STORE.runs, STORE.teardowns, STORE.cepLeases, STORE.audit],
      "readwrite",
    );
    const approvals = secureObjectStore(transaction, STORE.approvals);
    const runs = secureObjectStore(transaction, STORE.runs);
    const teardowns = secureObjectStore(transaction, STORE.teardowns);
    const cepLeases = secureObjectStore(transaction, STORE.cepLeases);
    const audit = secureObjectStore(transaction, STORE.audit);

    const blockingRun = ((await request(runs.getAll())) as DeploymentRunRecord[])
      .find(runHasActiveWork);
    if (blockingRun !== undefined) {
      transaction.abort();
      throw new ApplySlotBusy(blockingRun.runId);
    }
    const blockingTeardown = ((await request(teardowns.getAll())) as Record<string, unknown>[])
      .find(teardownHasActiveWork);
    if (blockingTeardown !== undefined) {
      transaction.abort();
      throw new ApplySlotBusy(
        `teardown:${String(blockingTeardown.teardownId ?? blockingTeardown.runId ?? "active")}`,
      );
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
    const blockingCep = (await request(cepLeases.getAll()) as CepMutationLeaseRecord[])[0];
    if (blockingCep !== undefined) {
      transaction.abort();
      throw new ApplySlotBusy(`cep:${blockingCep.operationId}`);
    }
    if (
      current.operator.trim().toLowerCase() !== approval.approvedBy.trim().toLowerCase() ||
      !sameDeployerIdentity(current.deployerIdentity, approval.deployerIdentity)
    ) {
      transaction.abort();
      throw new ApprovalRejected(
        "The current operator or deployer identity differs from the approved identity. Reapprove the plan.",
      );
    }

    // Re-check at consumption time as well as approval time. This protects
    // upgrades from previously persisted approvals and makes the repository,
    // rather than the UI, the final safety boundary.
    try {
      assertPlanCanApply(approval.planJson);
      assertApprovalIntegrity(approval);
    } catch (error) {
      transaction.abort();
      throw error;
    }

    const consumed: ApprovedPlanRecord = { ...approval, consumedAt: nowIso };
    await request(approvals.put(consumed));

    let run: DeploymentRunRecord & RunRecord;
    try {
      run = initialRunRecord({ approval: consumed, runId, startedAt: nowIso });
    } catch (error) {
      transaction.abort();
      throw error;
    }
    await request(runs.add(run));

    let previousHash = await this.chainHead(audit);
    for (const [eventType, payload] of [
      [
        "plan.consumed",
        {
          approval_id: consumed.approvalId,
          configuration_hash: consumed.configurationHash,
          deployer_identity_sha256: canonicalDigestSync(consumed.deployerIdentity),
        },
      ],
      [
        "run.started",
        {
          run_id: run.runId,
          approval_id: run.approvalId,
          configuration_hash: run.configurationHash,
          deployer_identity_sha256: canonicalDigestSync(run.deployerIdentity),
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
      secureObjectStore(transaction, STORE.runs).getAll(),
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
  }): Promise<{ createdAt: string; expiresAt: string }> {
    const now = this.clock.now();
    const expiresAt = new Date(now.getTime() + 30 * 60_000).toISOString();
    let actor = "system:unidentified";
    try {
      const preflight = JSON.parse(record.preflightJson) as {
        snapshot?: { cloud_identity?: unknown };
      };
      if (typeof preflight.snapshot?.cloud_identity === "string" &&
          preflight.snapshot.cloud_identity.trim() !== "") {
        actor = preflight.snapshot.cloud_identity;
      }
    } catch {
      throw new ApprovalRejected("The prepared preflight result is invalid");
    }
    const transaction = this.db.transaction([STORE.plans, STORE.audit], "readwrite");
    await request(
      secureObjectStore(transaction, STORE.plans).put({
        ...record,
        createdAt: now.toISOString(),
        expiresAt,
      }),
    );
    const audit = secureObjectStore(transaction, STORE.audit);
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: null,
      eventType: "plan.prepared",
      actor,
      payload: {
        plan_id: record.planId,
        configuration_hash: record.configurationHash,
        expires_at: expiresAt,
      },
      createdAt: now.toISOString(),
      previousHash: await this.chainHead(audit),
    });
    await request(audit.add(event));
    await transactionDone(transaction);
    return { createdAt: now.toISOString(), expiresAt };
  }

  /**
   * Atomically serialise CEP tenant mutations across MV3 worker instances.
   * An expired lease may be reclaimed only by the exact same request digest;
   * a different request must not run over an interrupted list-before-create
   * saga whose external effects have not yet been reconciled.
   */
  async acquireCepMutationLease(options: {
    scopeKeys: readonly string[];
    operationKind: CepMutationLeaseRecord["operationKind"];
    requestDigest: string;
  }): Promise<CepMutationLeaseHandle> {
    const scopeKeys = [...new Set(options.scopeKeys)].sort();
    if (
      scopeKeys.length === 0 || scopeKeys.length > 2 ||
      scopeKeys.some((key) => !/^cep:(?:customer|ou):[0-9a-f]{64}$/.test(key)) ||
      !/^[0-9a-f]{64}$/.test(options.requestDigest)
    ) throw new Error("cep-mutation-lease-input-invalid");

    const transaction = this.db.transaction(
      [STORE.cepLeases, STORE.runs, STORE.teardowns],
      "readwrite",
    );
    const store = secureObjectStore(transaction, STORE.cepLeases);
    const runs = secureObjectStore(transaction, STORE.runs);
    const teardowns = secureObjectStore(transaction, STORE.teardowns);
    const activeRun = ((await request(runs.getAll())) as DeploymentRunRecord[])
      .find(runHasActiveWork);
    const activeTeardown = ((await request(teardowns.getAll())) as Record<string, unknown>[])
      .find(teardownHasActiveWork);
    if (activeRun !== undefined || activeTeardown !== undefined) {
      transaction.abort();
      throw new CepMutationLeaseBusy(
        "cep-lifecycle-active",
        activeRun?.runId ?? `teardown:${String(activeTeardown?.teardownId ?? "active")}`,
      );
    }
    const now = this.clock.now();
    const nowMs = now.getTime();
    const existing = await Promise.all(scopeKeys.map(async (leaseKey) =>
      await request(store.get(leaseKey)) as CepMutationLeaseRecord | undefined));

    let recovered = false;
    let operationId: string | undefined;
    for (let index = 0; index < scopeKeys.length; index += 1) {
      const record = existing[index];
      if (record === undefined) continue;
      const expiry = Date.parse(record.expiresAt);
      if (!Number.isFinite(expiry) || expiry > nowMs) {
        transaction.abort();
        throw new CepMutationLeaseBusy("cep-mutation-active", scopeKeys[index] as string);
      }
      if (
        record.requestDigest !== options.requestDigest ||
        record.operationKind !== options.operationKind
      ) {
        transaction.abort();
        throw new CepMutationLeaseBusy(
          "cep-mutation-recovery-required",
          scopeKeys[index] as string,
        );
      }
      if (operationId !== undefined && operationId !== record.operationId) {
        transaction.abort();
        throw new Error("cep-mutation-lease-set-inconsistent");
      }
      operationId = record.operationId;
      recovered = true;
    }

    operationId ??= this.clock.uuid();
    const ownerToken = this.clock.uuid();
    const nowIso = now.toISOString();
    const expiresAt = new Date(nowMs + CEP_MUTATION_LEASE_MS).toISOString();
    for (const leaseKey of scopeKeys) {
      await request(store.put({
        leaseKey,
        operationId,
        operationKind: options.operationKind,
        requestDigest: options.requestDigest,
        ownerToken,
        acquiredAt: existing.find((record) => record?.leaseKey === leaseKey)?.acquiredAt ?? nowIso,
        updatedAt: nowIso,
        expiresAt,
      } satisfies CepMutationLeaseRecord));
    }
    await transactionDone(transaction);
    return {
      scopeKeys,
      operationId,
      operationKind: options.operationKind,
      requestDigest: options.requestDigest,
      ownerToken,
      recovered,
      expiresAt,
    };
  }

  async renewCepMutationLease(handle: CepMutationLeaseHandle): Promise<CepMutationLeaseHandle> {
    const transaction = this.db.transaction([STORE.cepLeases], "readwrite");
    const store = secureObjectStore(transaction, STORE.cepLeases);
    const now = this.clock.now();
    const expiresAt = new Date(now.getTime() + CEP_MUTATION_LEASE_MS).toISOString();
    for (const leaseKey of handle.scopeKeys) {
      const record = await request(store.get(leaseKey)) as CepMutationLeaseRecord | undefined;
      if (
        record === undefined || record.ownerToken !== handle.ownerToken ||
        record.operationId !== handle.operationId || record.requestDigest !== handle.requestDigest
      ) {
        transaction.abort();
        throw new Error("cep-mutation-lease-lost");
      }
      await request(store.put({ ...record, updatedAt: now.toISOString(), expiresAt }));
    }
    await transactionDone(transaction);
    return { ...handle, expiresAt };
  }

  async releaseCepMutationLease(handle: CepMutationLeaseHandle): Promise<void> {
    const transaction = this.db.transaction([STORE.cepLeases], "readwrite");
    const store = secureObjectStore(transaction, STORE.cepLeases);
    for (const leaseKey of handle.scopeKeys) {
      const record = await request(store.get(leaseKey)) as CepMutationLeaseRecord | undefined;
      if (
        record === undefined || record.ownerToken !== handle.ownerToken ||
        record.operationId !== handle.operationId || record.requestDigest !== handle.requestDigest
      ) {
        transaction.abort();
        throw new Error("cep-mutation-lease-lost");
      }
      await request(store.delete(leaseKey));
    }
    await transactionDone(transaction);
  }

  async cepMutationLeases(): Promise<CepMutationLeaseRecord[]> {
    const transaction = this.db.transaction([STORE.cepLeases], "readonly");
    const records = await request(
      secureObjectStore(transaction, STORE.cepLeases).getAll(),
    ) as CepMutationLeaseRecord[];
    await transactionDone(transaction);
    return records;
  }

  async preparedPlan(planId: string): Promise<Record<string, unknown> | undefined> {
    const transaction = this.db.transaction([STORE.plans], "readonly");
    const record = (await request(secureObjectStore(transaction, STORE.plans).get(planId))) as
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
    deployerIdentity: DeployerIdentityBinding;
  }): Promise<ApprovedPlanRecord> {
    const plan = await this.preparedPlan(record.planId);
    if (plan === undefined) {
      throw new ApprovalRejected("The prepared plan was not found");
    }
    const now = this.clock.now();
    if (!validDeployerIdentity(record.deployerIdentity)) {
      throw new ApprovalRejected("A project-bound deployer identity is required for approval");
    }
    assertApprovalTtl(record.ttlMinutes);
    assertPreparedPlanFresh(plan.expiresAt, now);
    let preparedSpecification: Record<string, unknown>;
    let preparedPlan: Record<string, unknown>;
    try {
      preparedSpecification = JSON.parse(plan.specificationJson as string) as Record<string, unknown>;
      preparedPlan = JSON.parse(plan.planJson as string) as Record<string, unknown>;
      const preparedConfigurationHash = configurationHash(
        parseDeploymentSpec(preparedSpecification),
      );
      if (
        preparedSpecification.project_id !== record.deployerIdentity.projectId ||
        preparedConfigurationHash !== plan.configurationHash ||
        preparedPlan.configuration_hash !== plan.configurationHash
      ) {
        throw new Error("prepared plan hash binding mismatch");
      }
    } catch {
      throw new ApprovalRejected(
        "The prepared plan or specification no longer matches its configuration hash",
      );
    }
    const approvedPlanJson = approvePlanJson(plan.planJson as string, record.approvedBy);
    const approval: ApprovedPlanRecord = {
      schemaVersion: LIFECYCLE_SCHEMA_VERSION,
      approvalId: this.clock.uuid(),
      configurationHash: plan.configurationHash as string,
      planHash: canonicalDigestSync(JSON.parse(approvedPlanJson)),
      planJson: approvedPlanJson,
      specificationJson: plan.specificationJson as string,
      approvedBy: record.approvedBy,
      approvedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + record.ttlMinutes * 60_000).toISOString(),
      consumedAt: null,
      deployerIdentity: structuredClone(record.deployerIdentity),
    };

    const transaction = this.db.transaction([STORE.approvals, STORE.audit], "readwrite");
    await request(secureObjectStore(transaction, STORE.approvals).add(approval));
    const audit = secureObjectStore(transaction, STORE.audit);
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: null,
      eventType: "plan.approved",
      actor: record.approvedBy,
      payload: {
        approval_id: approval.approvalId,
        configuration_hash: approval.configurationHash,
        plan_hash: approval.planHash,
        expires_at: approval.expiresAt,
        deployer_identity_sha256: canonicalDigestSync(approval.deployerIdentity),
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
    const record = (await request(secureObjectStore(transaction, STORE.approvals).get(approvalId))) as
      | ApprovedPlanRecord
      | undefined;
    await transactionDone(transaction);
    return record;
  }

  async run(runId: string): Promise<DeploymentRunRecord | undefined> {
    const transaction = this.db.transaction([STORE.runs], "readonly");
    const record = (await request(secureObjectStore(transaction, STORE.runs).get(runId))) as
      | DeploymentRunRecord
      | undefined;
    await transactionDone(transaction);
    return record;
  }

  /** Record what a run created, so teardown deletes only that. */
  async recordResources(
    runId: string,
    resources: readonly ResourceOwnershipRecord[],
  ): Promise<void> {
    const transaction = this.db.transaction([STORE.resources], "readwrite");
    const store = secureObjectStore(transaction, STORE.resources);
    for (const resource of resources) {
      await request(store.put({ id: `${runId}:${resource.resourceKey}`, runId, ...resource }));
    }
    await transactionDone(transaction);
  }

  async resources(runId: string): Promise<Record<string, unknown>[]> {
    const transaction = this.db.transaction([STORE.resources], "readonly");
    const records = (await request(
      secureObjectStore(transaction, STORE.resources).index("runId").getAll(IDBKeyRange.only(runId)),
    )) as Record<string, unknown>[];
    await transactionDone(transaction);
    return records;
  }

  /**
   * Reacquire the global lifecycle slot for the same durable Apply record.
   * This never consumes another approval or constructs replacement steps.
   */
  async resumeRun(
    runId: string,
    current: { operator: string; deployerIdentity: DeployerIdentityBinding },
    expectedRollbackPreflight?: RollbackCompensationPreflight,
  ): Promise<DeploymentRunRecord & RunRecord> {
    const transaction = this.db.transaction(
      [STORE.runs, STORE.approvals, STORE.teardowns, STORE.cepLeases, STORE.audit],
      "readwrite",
    );
    const runs = secureObjectStore(transaction, STORE.runs);
    const approvals = secureObjectStore(transaction, STORE.approvals);
    const teardowns = secureObjectStore(transaction, STORE.teardowns);
    const cepLeases = secureObjectStore(transaction, STORE.cepLeases);
    const audit = secureObjectStore(transaction, STORE.audit);
    const storedRun = (await request(runs.get(runId))) as DeploymentRunRecord | undefined;
    let run = storedRun as (DeploymentRunRecord & RunRecord) | undefined;
    const state = run?.state ?? run?.status;
    if (
      run === undefined ||
      ![
        "running",
        "rolling_back",
        "failed",
        "rollback_failed",
        "rollback_unavailable",
        "interrupted",
      ].includes(String(state)) ||
      !Array.isArray((run as unknown as RunRecord).steps) ||
      (run as unknown as RunRecord).steps.length === 0
    ) {
      transaction.abort();
      throw new Error("run-not-resumable");
    }
    let approval = (await request(approvals.get(run.approvalId))) as
      | ApprovedPlanRecord
      | undefined;
    if (approval === undefined || approval.consumedAt === null) {
      transaction.abort();
      throw new ApprovalRejected("The consumed approval for this run is missing.");
    }
    const runIdentityMissing = run.deployerIdentity === undefined;
    const approvalIdentityMissing = approval.deployerIdentity === undefined;
    const legacyIdentityPair = runIdentityMissing && approvalIdentityMissing;
    const legacyServiceAccountAttribution = legacyIdentityPair &&
      isSupportedDeployerServiceAccountEmail(
        approval.approvedBy.trim().toLowerCase(),
        current.deployerIdentity.projectId,
      );
    if (!approvalOperatorMatches(approval, current) && !legacyServiceAccountAttribution) {
      transaction.abort();
      throw new ApprovalRejected(
        "The signed-in Google account differs from the operator who approved this run.",
      );
    }
    if (run.configurationHash !== approval.configurationHash) {
      transaction.abort();
      throw new ApprovalRejected(
        "The run configuration hash differs from its consumed approval. Nothing was resumed.",
      );
    }
    if (runIdentityMissing !== approvalIdentityMissing) {
      transaction.abort();
      throw new ApprovalRejected(
        "The legacy run and approval have incomplete deployer identity binding. Nothing was adopted.",
      );
    }
    if (!legacyIdentityPair && (
      !sameDeployerIdentity(current.deployerIdentity, run.deployerIdentity) ||
      !sameDeployerIdentity(current.deployerIdentity, approval.deployerIdentity)
    )) {
      transaction.abort();
      throw new ApprovalRejected(
        "The immutable deployer identity differs from the identity bound to this run.",
      );
    }
    let approvalProjectId: string;
    try {
      approvalProjectId = legacyIdentityPair
        ? assertApprovalPayloadIntegrity(approval)
        : (assertApprovalIntegrity(approval), approval.deployerIdentity.projectId);
    } catch (error) {
      transaction.abort();
      throw error;
    }
    let identityAdopted = false;
    if (legacyIdentityPair) {
      if (current.deployerIdentity.projectId !== approvalProjectId) {
        transaction.abort();
        throw new ApprovalRejected(
          "The live-attested deployer belongs to a different project. Nothing was adopted.",
        );
      }
      try {
        assertLegacyRunCheckpointIntegrity(run, approval);
      } catch (error) {
        transaction.abort();
        throw error;
      }
      approval = {
        ...approval,
        deployerIdentity: structuredClone(current.deployerIdentity),
        ...(legacyServiceAccountAttribution
          ? {
              legacyOperatorBinding: {
                legacyApprovedBy: approval.approvedBy,
                operatorEmail: current.deployerIdentity.operatorEmail,
                operatorSubject: current.deployerIdentity.operatorSubject,
                adoptedAt: this.clock.now().toISOString(),
              },
            }
          : {}),
      };
      run = {
        ...run,
        deployerIdentity: structuredClone(current.deployerIdentity),
      };
      await request(approvals.put(approval));
      await request(runs.put(run));
      identityAdopted = true;
    }
    const approvedPlan = JSON.parse(approval.planJson) as DeploymentPlan;
    if (
      canonicalDigestSync((run as unknown as RunRecord).publicCertificateBinding ?? null) !==
      canonicalDigestSync(approvedPlan.public_certificate_binding ?? null)
    ) {
      transaction.abort();
      throw new ApprovalRejected(
        "The run public-certificate binding differs from the approved plan.",
      );
    }
    if (
      canonicalDigestSync((run as unknown as RunRecord).sourceImageBinding ?? null) !==
      canonicalDigestSync(approvedPlan.source_image_binding ?? null)
    ) {
      transaction.abort();
      throw new ApprovalRejected(
        "The run source-image binding differs from the approved plan.",
      );
    }
    const otherRun = ((await request(runs.getAll())) as DeploymentRunRecord[])
      .find((candidate) => candidate.runId !== runId && runHasActiveWork(candidate));
    const activeTeardown = ((await request(teardowns.getAll())) as Record<string, unknown>[])
      .find(teardownHasActiveWork);
    if (otherRun !== undefined || activeTeardown !== undefined) {
      transaction.abort();
      throw new ApplySlotBusy(otherRun?.runId ?? `teardown:${String(activeTeardown?.teardownId)}`);
    }
    const activeCep = (await request(cepLeases.getAll()) as CepMutationLeaseRecord[])[0];
    if (activeCep !== undefined) {
      transaction.abort();
      throw new ApplySlotBusy(`cep:${activeCep.operationId}`);
    }
    const schemaState = lifecycleSchemaState(run, approval);
    if (schemaState === "legacy") {
      try {
        assertLegacyRunCheckpointIntegrity(run, approval);
      } catch (error) {
        transaction.abort();
        throw error;
      }
    }
    const rollbackPreflight = rollbackCompensationPreflight(run);
    if (!sameRollbackPreflight(expectedRollbackPreflight, rollbackPreflight)) {
      transaction.abort();
      throw new ApprovalRejected(
        "The rollback checkpoint changed after preflight. Nothing was resumed.",
      );
    }
    if (state === "rollback_unavailable" && schemaState === "current") {
      transaction.abort();
      throw new Error("run-not-resumable");
    }
    if (!rollbackPreflight.available || schemaState === "inconsistent") {
      const issueByStep = new Map(
        rollbackPreflight.issues.map((issue) => [issue.stepIndex, issue.errorCode]),
      );
      const sealedSteps = run.steps.map((step) => {
        const errorCode = issueByStep.get(step.index) ??
          (schemaState === "inconsistent" ? "lifecycle-schema-inconsistent" : undefined);
        return {
          ...step,
          schemaVersion: LIFECYCLE_SCHEMA_VERSION,
          ...(errorCode === undefined
            ? {}
            : {
                status: "rollback_failed" as const,
                error: `rollback: ${errorCode}`,
              }),
        };
      });
      approval = { ...approval, schemaVersion: LIFECYCLE_SCHEMA_VERSION };
      const sealed: DeploymentRunRecord & RunRecord = {
        ...run,
        schemaVersion: LIFECYCLE_SCHEMA_VERSION,
        state: "rollback_unavailable",
        status: "rollback_unavailable",
        steps: sealedSteps,
        finishedAt: this.clock.now().toISOString(),
        finalizationPending: true,
        finalizedAt: null,
        interruptedFrom: undefined,
        reauthRequired: false,
        interruptionErrorCode: undefined,
      };
      await request(approvals.put(approval));
      await request(runs.put(sealed));
      let previousHash = await this.chainHead(audit);
      if (identityAdopted) {
        const adoptionEvent = buildAuditEvent({
          eventId: this.clock.uuid(),
          deploymentId: runId,
          eventType: "run.legacy_deployer_identity_adopted",
          actor: current.operator,
          payload: {
            run_id: runId,
            approval_id: approval.approvalId,
            configuration_hash: approval.configurationHash,
            deployer_identity_sha256: canonicalDigestSync(current.deployerIdentity),
            operator_subject_sha256: canonicalDigestSync(
              current.deployerIdentity.operatorSubject,
            ),
          },
          createdAt: this.clock.now().toISOString(),
          previousHash,
        });
        await request(audit.add(adoptionEvent));
        previousHash = adoptionEvent.eventHash;
      }
      const unavailableEvent = buildAuditEvent({
        eventId: this.clock.uuid(),
        deploymentId: runId,
        eventType: "run.rollback_unavailable",
        actor: current.operator,
        payload: {
          run_id: runId,
          issue_count: rollbackPreflight.issues.length,
          residual_count: rollbackPreflight.candidateStepIndexes.length,
          issue_digest: canonicalDigestSync(rollbackPreflight.issues),
          schema_state: schemaState,
        },
        createdAt: this.clock.now().toISOString(),
        previousHash,
      });
      await request(audit.add(unavailableEvent));
      await transactionDone(transaction);
      return sealed;
    }
    if (schemaState !== "current") {
      approval = { ...approval, schemaVersion: LIFECYCLE_SCHEMA_VERSION };
      run = {
        ...run,
        schemaVersion: LIFECYCLE_SCHEMA_VERSION,
        steps: run.steps.map((step) => ({
          ...step,
          schemaVersion: LIFECYCLE_SCHEMA_VERSION,
        })),
      };
      await request(approvals.put(approval));
      await request(runs.put(run));
    }
    const resumedState = state === "interrupted"
      ? run.interruptedFrom ?? "running"
      : state === "failed" || state === "rollback_failed" || state === "rollback_unavailable"
      ? "rolling_back"
      : state as "running" | "rolling_back";
    const resumedSteps = state === "rollback_failed"
      ? (run as unknown as RunRecord).steps.map((step) =>
        step.status === "rollback_failed"
          ? { ...step, status: "done" as const, error: null }
          : step
      )
      : (run as unknown as RunRecord).steps;
    const resumed: DeploymentRunRecord & RunRecord = {
      ...run,
      state: resumedState,
      status: resumedState,
      steps: resumedSteps,
      finishedAt: null,
      finalizationPending: false,
      finalizedAt: null,
      interruptedFrom: undefined,
      reauthRequired: false,
      interruptionErrorCode: undefined,
    };
    await request(runs.put(resumed));
    let previousHash = await this.chainHead(audit);
    if (identityAdopted) {
      const adoptionEvent = buildAuditEvent({
        eventId: this.clock.uuid(),
        deploymentId: runId,
        eventType: "run.legacy_deployer_identity_adopted",
        actor: current.operator,
        payload: {
          run_id: runId,
          approval_id: approval.approvalId,
          configuration_hash: approval.configurationHash,
          deployer_identity_sha256: canonicalDigestSync(current.deployerIdentity),
          legacy_approved_by_kind: approval.legacyOperatorBinding === undefined
            ? "human_email"
            : "deployer_service_account",
          operator_subject_sha256: canonicalDigestSync(
            current.deployerIdentity.operatorSubject,
          ),
        },
        createdAt: this.clock.now().toISOString(),
        previousHash,
      });
      await request(audit.add(adoptionEvent));
      previousHash = adoptionEvent.eventHash;
    }
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: runId,
      eventType: "run.resumed",
      actor: current.operator,
      payload: { run_id: runId, status: resumedState },
      createdAt: this.clock.now().toISOString(),
      previousHash,
    });
    await request(audit.add(event));
    await transactionDone(transaction);
    return resumed;
  }

  /** Acquire a durable saga slot before either post-deploy IAM write. */
  async beginRunPolicyUpdate(
    runId: string,
    checkpoint: PolicyUpdateCheckpoint,
    current: { operator: string; deployerIdentity: DeployerIdentityBinding },
  ): Promise<void> {
    const transaction = this.db.transaction(
      [STORE.runs, STORE.approvals, STORE.teardowns, STORE.cepLeases, STORE.audit],
      "readwrite",
    );
    const runs = secureObjectStore(transaction, STORE.runs);
    const approvals = secureObjectStore(transaction, STORE.approvals);
    const teardowns = secureObjectStore(transaction, STORE.teardowns);
    const cepLeases = secureObjectStore(transaction, STORE.cepLeases);
    const audit = secureObjectStore(transaction, STORE.audit);
    const run = (await request(runs.get(runId))) as DeploymentRunRecord | undefined;
    if (
      run === undefined ||
      (run.state ?? run.status) !== "succeeded" ||
      run.finalizationPending === true ||
      run.policyUpdateCheckpoint !== undefined
    ) {
      transaction.abort();
      throw new Error("run-policy-update-not-available");
    }
    const approval = (await request(approvals.get(run.approvalId))) as
      | ApprovedPlanRecord
      | undefined;
    if (
      !currentIdentityMatchesRunApproval(run, approval, current) ||
      checkpoint.actor.trim().toLowerCase() !== current.operator.trim().toLowerCase()
    ) {
      transaction.abort();
      throw new ApprovalRejected(
        "The current operator or deployer identity differs from the approved run.",
      );
    }
    const otherActiveRun = ((await request(runs.getAll())) as DeploymentRunRecord[])
      .find((item) => item.runId !== runId && runHasActiveWork(item));
    const activeTeardown = ((await request(teardowns.getAll())) as Record<string, unknown>[])
      .find(teardownHasActiveWork);
    const activeCep = (await request(cepLeases.getAll()) as CepMutationLeaseRecord[])[0];
    if (otherActiveRun !== undefined || activeTeardown !== undefined || activeCep !== undefined) {
      transaction.abort();
      throw new Error("run-policy-update-slot-busy");
    }
    await request(runs.put({ ...run, policyUpdateCheckpoint: structuredClone(checkpoint) }));
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: runId,
      eventType: "access_level.update_checkpointed",
      actor: checkpoint.actor,
      payload: {
        run_id: runId,
        checkpoint_id: checkpoint.checkpointId,
        requested_access_level: checkpoint.requestedAccessLevel,
      },
      createdAt: checkpoint.startedAt,
      previousHash: await this.chainHead(audit),
    });
    await request(audit.add(event));
    await transactionDone(transaction);
  }

  async checkpointRunPolicyUpdatePhase(
    runId: string,
    checkpointId: string,
    phase: PolicyUpdateCheckpoint["phase"],
  ): Promise<void> {
    const transaction = this.db.transaction([STORE.runs], "readwrite");
    const runs = secureObjectStore(transaction, STORE.runs);
    const run = (await request(runs.get(runId))) as DeploymentRunRecord | undefined;
    if (run?.policyUpdateCheckpoint?.checkpointId !== checkpointId) {
      transaction.abort();
      throw new Error("run-policy-update-checkpoint-changed");
    }
    await request(runs.put({
      ...run,
      policyUpdateCheckpoint: { ...run.policyUpdateCheckpoint, phase },
    }));
    await transactionDone(transaction);
  }

  /**
   * After both provider writes succeed, atomically advance both IAM deltas and
   * the run's public policy state. The original pre-Apply policies remain the
   * teardown baseline; only each managed `afterPolicy` moves forward.
   */
  async commitRunPolicyUpdate(
    runId: string,
    checkpointId: string,
  ): Promise<void> {
    const transaction = this.db.transaction(
      [STORE.runs, STORE.resources, STORE.audit],
      "readwrite",
    );
    const runs = secureObjectStore(transaction, STORE.runs);
    const resources = secureObjectStore(transaction, STORE.resources);
    const audit = secureObjectStore(transaction, STORE.audit);
    const run = (await request(runs.get(runId))) as DeploymentRunRecord | undefined;
    const checkpoint = run?.policyUpdateCheckpoint;
    if (run === undefined || checkpoint?.checkpointId !== checkpointId) {
      transaction.abort();
      throw new Error("run-policy-update-checkpoint-changed");
    }
    if (checkpoint.phase !== "gateway_applied") {
      transaction.abort();
      throw new Error("run-policy-update-provider-writes-incomplete");
    }

    for (const target of [checkpoint.application, checkpoint.gateway]) {
      const id = `${runId}:${target.resourceKey}`;
      const resource = (await request(resources.get(id))) as Record<string, unknown> | undefined;
      if (
        resource === undefined ||
        canonicalDigestSync(resource.beforeImage ?? null) !== target.inventoryBeforeImageDigest
      ) {
        transaction.abort();
        throw new Error("run-policy-update-inventory-changed");
      }
      await request(resources.put({
        ...resource,
        beforeImage: withLatestIamAfterPolicy(resource.beforeImage, target.afterPolicy),
      }));
    }

    const { policyUpdateCheckpoint: _checkpoint, ...withoutCheckpoint } = run;
    const now = this.clock.now().toISOString();
    await request(runs.put({
      ...withoutCheckpoint,
      managedChromeAccessLevel: checkpoint.requestedAccessLevel,
      policyPrincipals: [...checkpoint.principals],
    }));
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: runId,
      eventType: "access_level.inventory_advanced",
      actor: checkpoint.actor,
      payload: {
        run_id: runId,
        checkpoint_id: checkpoint.checkpointId,
        updated_access_level: checkpoint.requestedAccessLevel,
        resource_keys: [
          checkpoint.application.resourceKey,
          checkpoint.gateway.resourceKey,
        ],
      },
      createdAt: now,
      previousHash: await this.chainHead(audit),
    });
    await request(audit.add(event));
    await transactionDone(transaction);
  }

  /** Clear a recovered/compensated policy-update saga only after both restores. */
  async abortRunPolicyUpdate(
    runId: string,
    checkpointId: string,
    errorCode: string,
  ): Promise<void> {
    const transaction = this.db.transaction([STORE.runs, STORE.audit], "readwrite");
    const runs = secureObjectStore(transaction, STORE.runs);
    const audit = secureObjectStore(transaction, STORE.audit);
    const run = (await request(runs.get(runId))) as DeploymentRunRecord | undefined;
    const checkpoint = run?.policyUpdateCheckpoint;
    if (run === undefined || checkpoint?.checkpointId !== checkpointId) {
      transaction.abort();
      throw new Error("run-policy-update-checkpoint-changed");
    }
    const { policyUpdateCheckpoint: _checkpoint, ...withoutCheckpoint } = run;
    await request(runs.put(withoutCheckpoint));
    const now = this.clock.now().toISOString();
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: runId,
      eventType: "access_level.update_compensated",
      actor: "system",
      payload: {
        run_id: runId,
        checkpoint_id: checkpointId,
        error_code: errorCode,
      },
      createdAt: now,
      previousHash: await this.chainHead(audit),
    });
    await request(audit.add(event));
    await transactionDone(transaction);
  }

  /**
   * Complete a terminal run and its exact ownership inventory atomically.
   *
   * The engine first persists `finalizationPending=true`. A browser crash can
   * therefore happen anywhere before this transaction and cold start will
   * retry it. Within this transaction there is no observable terminal run
   * whose ownership rows are missing.
   */
  async finalizeRunInventory(
    expected: RunRecord,
    resources: readonly ResourceOwnershipRecord[],
  ): Promise<void> {
    const transaction = this.db.transaction(
      [STORE.runs, STORE.resources, STORE.audit],
      "readwrite",
    );
    const runs = secureObjectStore(transaction, STORE.runs);
    const inventory = secureObjectStore(transaction, STORE.resources);
    const audit = secureObjectStore(transaction, STORE.audit);
    const current = (await request(runs.get(expected.runId))) as
      | (DeploymentRunRecord & RunRecord)
      | undefined;
    if (current === undefined) {
      transaction.abort();
      throw new Error("run-not-found");
    }
    if (
      current.state !== expected.state ||
      canonicalDigestSync(current.steps ?? []) !== canonicalDigestSync(expected.steps)
    ) {
      transaction.abort();
      throw new Error("run-finalization-checkpoint-changed");
    }
    if (current.finalizationPending !== true) {
      // Idempotent retry after the transaction committed but before its caller
      // cleared the alarm. Refuse a mismatched retry rather than rewriting it.
      const existing = (await request(
        inventory.index("runId").getAll(IDBKeyRange.only(expected.runId)),
      )) as Record<string, unknown>[];
      const normalize = (value: Record<string, unknown>) => ({
        resourceKey: value.resourceKey,
        provider: value.provider,
        resourceType: value.resourceType,
        resourceName: value.resourceName,
        owned: value.owned,
        shared: value.shared,
        beforeImage: value.beforeImage ?? null,
        requestId: value.requestId ?? null,
      });
      if (
        canonicalDigestSync(existing.map(normalize).sort((a, b) =>
          String(a.resourceKey).localeCompare(String(b.resourceKey)))) !==
        canonicalDigestSync(resources.map((value) => normalize(value as unknown as Record<string, unknown>))
          .sort((a, b) => String(a.resourceKey).localeCompare(String(b.resourceKey))))
      ) {
        transaction.abort();
        throw new Error("run-finalization-inventory-mismatch");
      }
      await transactionDone(transaction);
      return;
    }

    const existingInventory = (await request(
      inventory.index("runId").getAll(IDBKeyRange.only(expected.runId)),
    )) as Record<string, unknown>[];
    const desiredIds = new Set(
      resources.map((resource) => `${expected.runId}:${resource.resourceKey}`),
    );
    for (const existing of existingInventory) {
      const id = String(existing.id ?? "");
      if (id !== "" && !desiredIds.has(id)) await request(inventory.delete(id));
    }
    for (const resource of resources) {
      await request(inventory.put({
        id: `${expected.runId}:${resource.resourceKey}`,
        runId: expected.runId,
        ...structuredClone(resource),
      }));
    }
    const now = this.clock.now().toISOString();
    await request(runs.put({
      ...current,
      status: expected.state,
      state: expected.state,
      finalizationPending: false,
      finalizedAt: now,
    }));
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: expected.runId,
      eventType: "run.finalized",
      actor: "system",
      payload: {
        run_id: expected.runId,
        state: expected.state,
        resource_count: resources.length,
        inventory_sha256: canonicalDigestSync(resources.map((resource) => ({
          ...resource,
          beforeImage: resource.beforeImage ?? null,
          requestId: resource.requestId ?? null,
        }))),
      },
      createdAt: now,
      previousHash: await this.chainHead(audit),
    });
    await request(audit.add(event));
    await transactionDone(transaction);
  }

  async allResources(): Promise<Record<string, unknown>[]> {
    const transaction = this.db.transaction([STORE.resources], "readonly");
    const records = (await request(
      secureObjectStore(transaction, STORE.resources).getAll(),
    )) as Record<string, unknown>[];
    await transactionDone(transaction);
    return records;
  }

  /**
   * Return only ownership rows whose finalized run is bound to this exact spec.
   *
   * Resource keys intentionally omit project/scope, so reducing the global
   * inventory directly can lend project A's markerless proof to project B.
   * Approval integrity and exact configuration binding make that impossible.
   */
  async ownershipProofResources(spec: DeploymentSpec): Promise<Record<string, unknown>[]> {
    const transaction = this.db.transaction(
      [STORE.resources, STORE.runs, STORE.approvals],
      "readonly",
    );
    const [resources, runs, approvals] = await Promise.all([
      request(secureObjectStore(transaction, STORE.resources).getAll()) as
        Promise<Record<string, unknown>[]>,
      request(secureObjectStore(transaction, STORE.runs).getAll()) as
        Promise<DeploymentRunRecord[]>,
      request(secureObjectStore(transaction, STORE.approvals).getAll()) as
        Promise<ApprovedPlanRecord[]>,
    ]);
    await transactionDone(transaction);

    const targetHash = configurationHash(spec);
    const approvalById = new Map(approvals.map((item) => [item.approvalId, item]));
    const eligibleRunIds = new Set<string>();
    for (const run of runs) {
      const state = run.state ?? run.status;
      if (
        !["succeeded", "rollback_failed", "rollback_unavailable"].includes(state) ||
        (run.state !== undefined && run.status !== undefined && run.state !== run.status) ||
        run.finalizationPending === true ||
        typeof run.finalizedAt !== "string" || !Number.isFinite(Date.parse(run.finalizedAt)) ||
        run.configurationHash !== targetHash || typeof run.approvalId !== "string"
      ) continue;
      const approval = approvalById.get(run.approvalId);
      if (
        approval === undefined || approval.configurationHash !== targetHash ||
        approval.consumedAt === null ||
        canonicalDigestSync(run.deployerIdentity ?? null) !==
          canonicalDigestSync(approval.deployerIdentity)
      ) continue;
      try {
        assertApprovalIntegrity(approval);
      } catch {
        continue;
      }
      eligibleRunIds.add(run.runId);
    }
    return resources.filter(
      (resource) => typeof resource.runId === "string" && eligibleRunIds.has(resource.runId),
    );
  }

  async releaseResources(runId: string, resourceKeys: readonly string[]): Promise<void> {
    const transaction = this.db.transaction([STORE.resources], "readwrite");
    const store = secureObjectStore(transaction, STORE.resources);
    for (const resourceKey of resourceKeys) {
      await request(store.delete(`${runId}:${resourceKey}`));
    }
    await transactionDone(transaction);
  }

  /**
   * Commit one successful provider teardown without opening a crash gap.
   *
   * For the final operation this transaction also marks the teardown terminal,
   * marks both durable run-state fields deleted, and appends both audit events.
   * Retrying after a committed transaction is a no-op; a half-commit is not an
   * IndexedDB state that can be observed.
   */
  async commitTeardownResourceSuccess(options: {
    teardownId: string;
    runId: string;
    resourceKey: string;
    outcome: string;
    completedAt: string;
  }): Promise<Record<string, unknown>> {
    const transaction = this.db.transaction(
      [STORE.resources, STORE.teardowns, STORE.runs, STORE.audit],
      "readwrite",
    );
    const resources = secureObjectStore(transaction, STORE.resources);
    const teardowns = secureObjectStore(transaction, STORE.teardowns);
    const runs = secureObjectStore(transaction, STORE.runs);
    const audit = secureObjectStore(transaction, STORE.audit);
    const existing = (await request(teardowns.get(options.teardownId))) as
      | Record<string, unknown>
      | undefined;
    if (
      existing === undefined ||
      existing.runId !== options.runId ||
      existing.immutableDigest !== teardownImmutableDigest(existing)
    ) {
      transaction.abort();
      throw new Error("teardown-immutable-snapshot-changed");
    }
    const instructions = Array.isArray(existing.instructions)
      ? existing.instructions as Array<Record<string, unknown>>
      : [];
    if (!instructions.some((item) => item.resourceKey === options.resourceKey)) {
      transaction.abort();
      throw new Error("teardown-resource-not-approved");
    }
    const operations = structuredClone(
      Array.isArray(existing.operations) ? existing.operations : [],
    ) as Array<Record<string, unknown>>;
    const operation = operations.find((item) => item.resource_key === options.resourceKey);
    if (operation === undefined) {
      transaction.abort();
      throw new Error("teardown-operation-missing");
    }

    const resourceId = `${options.runId}:${options.resourceKey}`;
    if (operation.status === "succeeded") {
      if (await request(resources.get(resourceId)) !== undefined) {
        transaction.abort();
        throw new Error("teardown-success-inventory-present");
      }
      await transactionDone(transaction);
      return existing;
    }
    if (operation.status !== "running") {
      transaction.abort();
      throw new Error("teardown-operation-not-running");
    }

    operation.status = "succeeded";
    operation.error_code = null;
    operation.completed_at = options.completedAt;
    await request(resources.delete(resourceId));

    const allCompleted = operations.length > 0 &&
      operations.every((item) => item.status === "succeeded");
    if (allCompleted) {
      for (const instruction of instructions) {
        const resourceKey = instruction.resourceKey;
        if (
          typeof resourceKey !== "string" ||
          await request(resources.get(`${options.runId}:${resourceKey}`)) !== undefined
        ) {
          transaction.abort();
          throw new Error("teardown-final-inventory-remains");
        }
      }
    }

    const updated: Record<string, unknown> = {
      ...existing,
      operations,
      ...(allCompleted
        ? { status: "succeeded", completedAt: options.completedAt }
        : {}),
    };
    await request(teardowns.put(updated));

    let previousHash = await this.chainHead(audit);
    const resourceEvent = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: options.runId,
      eventType: "teardown.resource_succeeded",
      actor: "system",
      payload: {
        teardown_id: options.teardownId,
        resource_key: options.resourceKey,
        outcome: options.outcome,
      },
      createdAt: options.completedAt,
      previousHash,
    });
    await request(audit.add(resourceEvent));
    previousHash = resourceEvent.eventHash;

    if (allCompleted) {
      const run = (await request(runs.get(options.runId))) as
        | DeploymentRunRecord
        | undefined;
      if (run === undefined) {
        transaction.abort();
        throw new Error("teardown-source-run-missing");
      }
      await request(runs.put({
        ...run,
        status: "deleted",
        state: "deleted",
        finalizationPending: false,
      }));
      const completedEvent = buildAuditEvent({
        eventId: this.clock.uuid(),
        deploymentId: options.runId,
        eventType: "teardown.succeeded",
        actor: "system",
        payload: {
          teardown_id: options.teardownId,
          run_id: options.runId,
          plan_hash: existing.planHash,
        },
        createdAt: options.completedAt,
        previousHash,
      });
      await request(audit.add(completedEvent));
    }
    await transactionDone(transaction);
    return updated;
  }

  /** Operator-confirmed and machine-verified acceptance outcomes. */
  async recordAcceptance(record: {
    runId: string;
    testId: string;
    caseKey?: string;
    status: string;
    summary: string;
    evidence: string;
    source: string;
    actor: string;
  }): Promise<void> {
    assertAcceptanceRecord(record);
    const now = this.clock.now().toISOString();
    const caseKey = record.caseKey ?? "default";
    const resultId = this.clock.uuid();
    const storedRecord = {
      id: resultId,
      resultId,
      recordedAt: now,
      ...record,
      caseKey,
    };
    const transaction = this.db.transaction(
      [STORE.acceptance, STORE.audit, STORE.runs],
      "readwrite",
    );
    const run = (await request(
      secureObjectStore(transaction, STORE.runs).get(record.runId),
    )) as DeploymentRunRecord | undefined;
    if (
      run === undefined || (run.state ?? run.status) !== "succeeded" ||
      runHasActiveWork(run)
    ) {
      transaction.abort();
      throw new Error("acceptance-run-not-succeeded");
    }
    await request(
      secureObjectStore(transaction, STORE.acceptance).add(storedRecord),
    );
    const audit = secureObjectStore(transaction, STORE.audit);
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: null,
      eventType: "acceptance.recorded",
      actor: record.actor,
      // Bind every canonical field while keeping operator prose out of the
      // event payload. Cross-store verification requires exactly one such
      // digest event for each immutable acceptance result row.
      payload: acceptanceAuditPayload(storedRecord),
      createdAt: now,
      previousHash: await this.chainHead(audit),
    });
    await request(audit.add(event));
    await transactionDone(transaction);
  }

  async acceptance(runId: string): Promise<Record<string, unknown>[]> {
    const transaction = this.db.transaction([STORE.acceptance], "readonly");
    const records = (await request(
      secureObjectStore(transaction, STORE.acceptance)
        .index("runId").getAll(IDBKeyRange.only(runId)),
    )) as Record<string, unknown>[];
    await transactionDone(transaction);
    return records;
  }

  async allAcceptance(): Promise<Record<string, unknown>[]> {
    const transaction = this.db.transaction([STORE.acceptance], "readonly");
    const records = (await request(
      secureObjectStore(transaction, STORE.acceptance).getAll(),
    )) as Record<string, unknown>[];
    await transactionDone(transaction);
    return records;
  }

  async markRunDeleted(runId: string): Promise<void> {
    const transaction = this.db.transaction([STORE.runs], "readwrite");
    const store = secureObjectStore(transaction, STORE.runs);
    const run = (await request(store.get(runId))) as DeploymentRunRecord | undefined;
    if (run) {
      await request(store.put({
        ...run,
        status: "deleted",
        state: "deleted",
        finalizationPending: false,
      }));
    }
    await transactionDone(transaction);
  }

  async updateTeardownProgress(record: Record<string, unknown>): Promise<void> {
    const transaction = this.db.transaction([STORE.teardowns], "readwrite");
    const store = secureObjectStore(transaction, STORE.teardowns);
    const teardownId = String(record.teardownId ?? "");
    const existing = (await request(store.get(teardownId))) as
      | Record<string, unknown>
      | undefined;
    if (
      existing === undefined ||
      existing.immutableDigest !== teardownImmutableDigest(existing) ||
      existing.immutableDigest !== teardownImmutableDigest(record)
    ) {
      transaction.abort();
      throw new Error("teardown-immutable-snapshot-changed");
    }
    await request(store.put({ ...record, immutableDigest: existing.immutableDigest }));
    await transactionDone(transaction);
  }

  async startTeardown(
    record: Record<string, unknown> & { runId: string },
    current: { operator: string; deployerIdentity: DeployerIdentityBinding },
  ): Promise<void> {
    const transaction = this.db.transaction(
      [STORE.teardowns, STORE.runs, STORE.approvals, STORE.cepLeases, STORE.audit],
      "readwrite",
    );
    const store = secureObjectStore(transaction, STORE.teardowns);
    const runs = secureObjectStore(transaction, STORE.runs);
    const approvals = secureObjectStore(transaction, STORE.approvals);
    const cepLeases = secureObjectStore(transaction, STORE.cepLeases);
    const audit = secureObjectStore(transaction, STORE.audit);
    const existing = (await request(store.getAll())) as Record<string, unknown>[];
    const activeTeardown = existing.find(teardownHasActiveWork);
    if (activeTeardown !== undefined) {
      transaction.abort();
      throw new TeardownSlotBusy(
        String(activeTeardown.teardownId ?? activeTeardown.runId ?? record.runId),
      );
    }
    const activeRun = ((await request(runs.getAll())) as DeploymentRunRecord[])
      .find(runHasActiveWork);
    if (activeRun !== undefined) {
      transaction.abort();
      throw new TeardownSlotBusy(activeRun.runId);
    }
    const activeCep = (await request(cepLeases.getAll()) as CepMutationLeaseRecord[])[0];
    if (activeCep !== undefined) {
      transaction.abort();
      throw new TeardownSlotBusy(`cep:${activeCep.operationId}`);
    }
    const run = (await request(runs.get(record.runId))) as DeploymentRunRecord | undefined;
    const approval = run === undefined
      ? undefined
      : (await request(approvals.get(run.approvalId))) as ApprovedPlanRecord | undefined;
    if (run === undefined || !currentIdentityMatchesRunApproval(run, approval, current)) {
      transaction.abort();
      throw new ApprovalRejected(
        "The current operator or deployer identity differs from the approved run.",
      );
    }
    const stored = structuredClone(record);
    stored.immutableDigest = teardownImmutableDigest(stored);
    await request(store.add(stored));
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: record.runId,
      eventType: "teardown.started",
      actor: current.operator,
      payload: {
        teardown_id: String(record.teardownId ?? ""),
        run_id: record.runId,
        plan_hash: String(record.planHash ?? ""),
      },
      createdAt: String(record.startedAt ?? this.clock.now().toISOString()),
      previousHash: await this.chainHead(audit),
    });
    await request(audit.add(event));
    await transactionDone(transaction);
  }

  async teardown(teardownId: string): Promise<Record<string, unknown> | undefined> {
    const transaction = this.db.transaction([STORE.teardowns], "readonly");
    const record = (await request(
      secureObjectStore(transaction, STORE.teardowns).get(teardownId),
    )) as Record<string, unknown> | undefined;
    await transactionDone(transaction);
    return record;
  }

  async latestTeardown(runId: string): Promise<Record<string, unknown> | undefined> {
    const transaction = this.db.transaction([STORE.teardowns], "readonly");
    const records = (await request(
      secureObjectStore(transaction, STORE.teardowns).getAll(),
    )) as Record<string, unknown>[];
    await transactionDone(transaction);
    return records
      .filter((record) => record.runId === runId)
      .sort((left, right) => {
        const byTime = String(right.startedAt ?? "").localeCompare(String(left.startedAt ?? ""));
        return byTime !== 0
          ? byTime
          : String(right.teardownId ?? "").localeCompare(String(left.teardownId ?? ""));
      })[0];
  }

  /** Atomically reacquire the lifecycle slot for one interrupted teardown. */
  async resumeTeardown(
    teardownId: string,
    current: { operator: string; deployerIdentity: DeployerIdentityBinding },
  ): Promise<Record<string, unknown>> {
    const transaction = this.db.transaction(
      [STORE.teardowns, STORE.runs, STORE.approvals, STORE.cepLeases, STORE.audit],
      "readwrite",
    );
    const teardowns = secureObjectStore(transaction, STORE.teardowns);
    const runs = secureObjectStore(transaction, STORE.runs);
    const approvals = secureObjectStore(transaction, STORE.approvals);
    const cepLeases = secureObjectStore(transaction, STORE.cepLeases);
    const audit = secureObjectStore(transaction, STORE.audit);
    const teardown = (await request(teardowns.get(teardownId))) as
      | Record<string, unknown>
      | undefined;
    if (
      teardown === undefined || teardown.status !== "interrupted" ||
      teardown.immutableDigest !== teardownImmutableDigest(teardown)
    ) {
      transaction.abort();
      throw new Error("teardown-not-resumable");
    }
    const runId = String(teardown.runId ?? "");
    const run = (await request(runs.get(runId))) as DeploymentRunRecord | undefined;
    const approval = run === undefined
      ? undefined
      : (await request(approvals.get(run.approvalId))) as ApprovedPlanRecord | undefined;
    if (
      run === undefined || approval === undefined ||
      !approvalOperatorMatches(approval, current) ||
      !sameDeployerIdentity(current.deployerIdentity, run.deployerIdentity) ||
      !sameDeployerIdentity(current.deployerIdentity, approval.deployerIdentity)
    ) {
      transaction.abort();
      throw new ApprovalRejected(
        "The current operator or deployer identity differs from the interrupted teardown.",
      );
    }
    const activeRun = ((await request(runs.getAll())) as DeploymentRunRecord[])
      .find(runHasActiveWork);
    const activeTeardown = ((await request(teardowns.getAll())) as Record<string, unknown>[])
      .find((candidate) => candidate.teardownId !== teardownId && teardownHasActiveWork(candidate));
    const activeCep = (await request(cepLeases.getAll()) as CepMutationLeaseRecord[])[0];
    if (activeRun !== undefined || activeTeardown !== undefined || activeCep !== undefined) {
      transaction.abort();
      throw new TeardownSlotBusy(
        activeRun?.runId ?? String(activeTeardown?.teardownId ?? `cep:${activeCep?.operationId}`),
      );
    }
    const resumed = { ...teardown, status: "running", completedAt: null };
    await request(teardowns.put(resumed));
    const event = buildAuditEvent({
      eventId: this.clock.uuid(),
      deploymentId: runId,
      eventType: "teardown.resumed",
      actor: current.operator,
      payload: { teardown_id: teardownId, run_id: runId },
      createdAt: this.clock.now().toISOString(),
      previousHash: await this.chainHead(audit),
    });
    await request(audit.add(event));
    await transactionDone(transaction);
    return resumed;
  }

  /** Read-only guard used before clearing credentials/session state. */
  async activeTeardowns(): Promise<Record<string, unknown>[]> {
    const transaction = this.db.transaction([STORE.teardowns], "readonly");
    const records = (await request(
      secureObjectStore(transaction, STORE.teardowns).getAll(),
    )) as Record<string, unknown>[];
    await transactionDone(transaction);
    return records.filter(
      (record) => record.status === "pending" || record.status === "running",
    );
  }

  /**
   * Reconcile a worker-terminated teardown in one transaction.
   *
   * Version 0.2.0 could durably release the final inventory row before saving
   * operation progress. A missing approved row is therefore durable proof that
   * the provider call returned successfully. Complete that legacy finalization
   * atomically; otherwise mark the still-owned remainder interrupted.
   */
  async reconcileInterruptedTeardowns(): Promise<string[]> {
    const transaction = this.db.transaction(
      [STORE.teardowns, STORE.resources, STORE.runs, STORE.audit],
      "readwrite",
    );
    const store = secureObjectStore(transaction, STORE.teardowns);
    const resources = secureObjectStore(transaction, STORE.resources);
    const runs = secureObjectStore(transaction, STORE.runs);
    const audit = secureObjectStore(transaction, STORE.audit);
    const records = (await request(store.getAll())) as Record<string, unknown>[];
    const interrupted: string[] = [];
    const now = this.clock.now().toISOString();
    let previousHash = await this.chainHead(audit);
    for (const record of records) {
      if (record.status !== "pending" && record.status !== "running") continue;
      const teardownId = String(record.teardownId ?? "");
      const runId = typeof record.runId === "string" ? record.runId : "";
      const instructions = Array.isArray(record.instructions)
        ? record.instructions as Array<Record<string, unknown>>
        : [];
      const operations = structuredClone(
        Array.isArray(record.operations) ? record.operations : [],
      ) as Array<Record<string, unknown>>;
      const recoveredKeys: string[] = [];
      let allReleased = instructions.length > 0 && runId !== "";
      for (const instruction of instructions) {
        const resourceKey = instruction.resourceKey;
        if (typeof resourceKey !== "string") {
          allReleased = false;
          continue;
        }
        const owned = await request(resources.get(`${runId}:${resourceKey}`));
        if (owned !== undefined) {
          allReleased = false;
          continue;
        }
        const operation = operations.find((item) => item.resource_key === resourceKey);
        if (operation === undefined) {
          allReleased = false;
          continue;
        }
        if (operation.status !== "succeeded") {
          operation.status = "succeeded";
          operation.error_code = null;
          operation.completed_at = now;
          recoveredKeys.push(resourceKey);
        }
      }
      allReleased = allReleased && operations.length > 0 &&
        operations.every((item) => item.status === "succeeded");

      const run = runId === ""
        ? undefined
        : (await request(runs.get(runId))) as DeploymentRunRecord | undefined;
      if (allReleased && run !== undefined) {
        await request(store.put({
          ...record,
          operations,
          status: "succeeded",
          completedAt: now,
        }));
        await request(runs.put({
          ...run,
          status: "deleted",
          state: "deleted",
          finalizationPending: false,
        }));
        for (const resourceKey of recoveredKeys) {
          const event = buildAuditEvent({
            eventId: this.clock.uuid(),
            deploymentId: runId,
            eventType: "teardown.resource_succeeded",
            actor: "system",
            payload: {
              teardown_id: teardownId,
              resource_key: resourceKey,
              outcome: "recovered-after-release",
            },
            createdAt: now,
            previousHash,
          });
          await request(audit.add(event));
          previousHash = event.eventHash;
        }
        const event = buildAuditEvent({
          eventId: this.clock.uuid(),
          deploymentId: runId,
          eventType: "teardown.succeeded",
          actor: "system",
          payload: {
            teardown_id: teardownId,
            run_id: runId,
            plan_hash: record.planHash ?? null,
            recovered: true,
          },
          createdAt: now,
          previousHash,
        });
        await request(audit.add(event));
        previousHash = event.eventHash;
        continue;
      }
      await request(
        store.put({
          ...record,
          operations,
          status: "interrupted",
          completedAt: now,
        }),
      );
      if (teardownId !== "") {
        const event = buildAuditEvent({
          eventId: this.clock.uuid(),
          deploymentId: runId || null,
          eventType: "teardown.interrupted",
          actor: "system",
          payload: { teardown_id: teardownId, run_id: runId || null },
          createdAt: now,
          previousHash,
        });
        await request(audit.add(event));
        previousHash = event.eventHash;
        interrupted.push(teardownId);
      }
    }
    await transactionDone(transaction);
    return interrupted;
  }

  /** Every audit event in insertion order. */
  async auditEvents(): Promise<AuditEventRecord[]> {
    const transaction = this.db.transaction([STORE.audit], "readonly");
    const events = (await request(
      secureObjectStore(transaction, STORE.audit).getAll(),
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
    const audit = secureObjectStore(transaction, STORE.audit);
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

  private async chainHead(audit: SecureObjectStore): Promise<string | null> {
    const cursor = await request(audit.openCursor(null, "prev"));
    if (cursor === null) return null;
    return (cursor.value as AuditEventRecord).eventHash;
  }
}
