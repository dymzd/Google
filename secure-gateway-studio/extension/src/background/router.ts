/**
 * Route table: the API surface the local FastAPI app used to serve.
 *
 * The React layer still asks for `/api/v1/plans`; the worker answers it. That
 * keeps the seam at the transport and leaves `api.ts` and every component above
 * it untouched between the two builds.
 *
 * Routes not yet ported return a typed `route-not-ported` error naming the
 * route. That is deliberate: a stub returning plausible data would let the UI
 * appear to work while doing nothing, and the difference would only surface
 * against a real Google project. An explicit refusal is visible immediately and
 * is honest about what Phase 3 covers.
 */

import { buildPlan, type ResourceChange } from "../domain/planner.ts";
import { AuthenticationError } from "../auth/tokens.ts";
import { canonicalDigestSync } from "../domain/canonical.ts";
import {
  applicationHostname,
  applicationPort,
  iamMember,
  parseDeploymentSpec,
  specToJson,
} from "../domain/spec.ts";
import {
  discoveryOwnershipProofs,
  GoogleDiscoveryProvider,
} from "../providers/discovery.ts";
import { GoogleSetupCatalog } from "../providers/catalog.ts";
import {
  bootstrapDeployer,
  type BootstrapOwnershipCheckpoint,
  type BootstrapOwnershipPin,
} from "../providers/bootstrap.ts";
import { GatewayObservability, type LogCategory } from "../providers/observability.ts";
import {
  assertTeardownSnapshotIntegrity,
  buildTeardownExecutionSnapshot,
  buildTeardownPlan,
  type DeploymentResource,
  type TeardownInstruction,
} from "../domain/teardown.ts";
import { replaceOwnedIamBinding } from "../domain/iam-policy.ts";
import { GoogleAcceptanceVerifier, acceptanceRequirements } from "../providers/acceptance.ts";
import {
  CEP_LICENSE_PROVIDER_MAX_NETWORK_WAIT_MS,
  CEP_LICENSE_REQUEST_TIMEOUT_MS,
  CepMutationOutcomeAmbiguous,
  CepProvider,
  CepTargetValidationError,
  resolveConfirmedCepTargetOu,
  type CepCustomRoleConfig,
  type CepLicenseAssignConfig,
  type CepProvisionConfig,
  type CepRollbackConfig,
} from "../providers/cep-provider.ts";
import {
  GoogleApiError,
  GoogleResourceExecutor,
  isConfirmedIamEtagConflict,
  isDefiniteMutationRejection,
  restoreIamPolicyWithFreshEtag,
  type Transport,
} from "../providers/executor.ts";
import {
  CepMutationLeaseBusy,
  openDatabase,
  StateRepository,
  STORE,
  iamInventoryBeforeImage,
  policyUpdateCompensationTargets,
  type DeployerIdentityBinding,
  type CepMutationLeaseHandle,
  type DeploymentRunRecord,
  type PolicyUpdateCheckpoint,
} from "../storage/repository.ts";
import {
  encryptedLocalGet,
  encryptedLocalGetMany,
  encryptedLocalRemove,
  encryptedLocalSet,
  finalizeUserDataConsent,
  prepareUserDataConsentMigration,
  userDataConsentStatus,
} from "../storage/secure-storage.ts";
import { verifyEvidenceIntegrity } from "../storage/acceptance-integrity.ts";
import {
  acceptanceResultDto,
  auditEventDto,
  deploymentResourceDto,
  deploymentRunDto,
} from "../storage/evidence.ts";

export interface RouteContext {
  /** Read-only Cloud discovery may use the administrator before bootstrap. */
  discoveryTransport: Transport;
  /** Cloud mutation transport; it must never fall back to an administrator token. */
  transport: Transport;
  /**
   * Calls that authorize against a Workspace user rather than a Cloud project.
   * The deployer service account is not a Workspace identity, so Directory,
   * Chrome Policy, and Cloud Identity have to run as the administrator.
   */
  administratorTransport: Transport;
  cloudIdentity: () => Promise<string>;
  /** Signed-in administrator, for the Token Creator binding bootstrap adds. */
  operatorEmail: () => Promise<string>;
  /** Configured Access Context Manager policy, when the operator has set one. */
  accessPolicyId: (projectId?: string) => Promise<string | undefined>;
  /** Credential label returned by Cloud connection validation. */
  cloudCredentialKind?: () => Promise<string>;
  /** Persist the administrator-discovered policy before bootstrap switches identity. */
  rememberAccessPolicyId: (
    projectId: string,
    policyId: string | null,
  ) => Promise<void>;
  /** Durable ownership record written before bootstrap grants Cloud roles. */
  bootstrapOwnershipPin: (projectId: string) => Promise<unknown>;
  /** Existing pins may be operated only by their sole pinned human. */
  assertBootstrapOperator: (projectId: string, pin: unknown) => Promise<void>;
  checkpointBootstrapOwnershipPin: (pin: BootstrapOwnershipCheckpoint) => Promise<void>;
  clearBootstrapOwnershipPin: (projectId: string) => Promise<void>;
  /** Tombstone an operator-confirmed provider-deleted immutable deployer identity. */
  retireDeletedBootstrapOwnershipPin?: (pin: BootstrapOwnershipPin) => Promise<void>;
  /** Legacy 0.2.0 identity hint; it is never sufficient without strict provider audit. */
  legacyDeployerIdentity: () => Promise<{
    serviceAccountEmail: string;
    projectId: string;
  } | undefined>;
  /** Persist the deployer account so later impersonation can find it. */
  rememberDeployer: (
    email: string,
    projectId: string,
    uniqueId: string,
    policyId?: string | null,
  ) => Promise<void>;
  /** Mint and verify the exact project-bound impersonated deployer identity. */
  requireDeployer: (
    projectId: string,
    expected?: DeployerIdentityBinding,
  ) => Promise<DeployerIdentityBinding>;
  /** Durable cross-worker CEP mutation lease; production must never omit it. */
  acquireCepMutationLease?: (options: {
    scopeKeys: readonly string[];
    operationKind: "provision" | "rollback" | "assign_licenses";
    requestDigest: string;
  }) => Promise<CepMutationLeaseHandle>;
  renewCepMutationLease?: (handle: CepMutationLeaseHandle) => Promise<CepMutationLeaseHandle>;
  releaseCepMutationLease?: (handle: CepMutationLeaseHandle) => Promise<void>;
  /** Test seam may shorten the production five-second per-call CEP deadline. */
  cepLicenseRequestTimeoutMs?: number;
  startApply: (approvalId: string) => Promise<{ run_id: string }>;
  /** Re-schedule this exact durable run; never consume/create another one. */
  resumeApply: (runId: string) => Promise<unknown>;
  runState: (runId: string) => Promise<unknown>;
  signOut?: () => Promise<void>;
}

export class RouteError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "RouteError";
    this.status = status;
    this.code = code;
  }
}

const CEP_LEASE_HEARTBEAT_MS = 30_000;

function cepMutationScopeKeys(
  operationKind: "provision" | "rollback" | "assign_licenses",
  request: CepProvisionConfig | CepRollbackConfig | CepLicenseAssignConfig,
): string[] {
  const customerId = request.customer_id.trim();
  const targetOuId = request.target_ou_id.trim();
  if (customerId === "" || targetOuId === "") {
    throw new RouteError(400, "cep-scope-invalid", "CEP customer_id and target_ou_id are required.");
  }
  const scopes = [
    `cep:ou:${canonicalDigestSync({
      customer_id: customerId,
      target_ou_id: targetOuId,
    })}`,
  ];
  const rollbackModules = operationKind === "rollback"
    ? (request as CepRollbackConfig).rollback_modules
    : undefined;
  const customerWideDlp = operationKind === "provision"
    ? (request as CepProvisionConfig).dlp_detectors === true ||
      (request as CepProvisionConfig).dlp_rules === true ||
      (request as CepProvisionConfig).dlp_matrix !== undefined
    : operationKind === "rollback" &&
      (rollbackModules === undefined || rollbackModules.length === 0 ||
        rollbackModules.includes("dlpDetectors") || rollbackModules.includes("dlpRules"));
  if (customerWideDlp) {
    scopes.push(`cep:customer:${canonicalDigestSync({ customer_id: customerId })}`);
  }
  return scopes.sort();
}

async function canonicalCepCustomerId(
  transport: Transport,
  customerId: string,
): Promise<string> {
  const candidate = typeof customerId === "string" ? customerId.trim() : "";
  if (candidate === "" || /[/?#]/.test(candidate)) {
    throw new RouteError(400, "cep-customer-invalid", "CEP customer_id is invalid.");
  }
  const response = await transport.requestJson(
    "GET",
    `https://admin.googleapis.com/admin/directory/v1/customers/${encodeURIComponent(candidate)}`,
  );
  const canonical = response.payload.id;
  if (typeof canonical !== "string" || !/^C[0-9A-Za-z]+$/.test(canonical)) {
    throw new RouteError(
      502,
      "cep-customer-identity-invalid",
      "Directory API did not return a canonical Workspace customer identity.",
    );
  }
  return canonical;
}

const CEP_LICENSE_AUTH_TIMEOUT_MS = 10_000;
export const CEP_LICENSE_ROUTE_MAX_NETWORK_WAIT_MS =
  CEP_LICENSE_AUTH_TIMEOUT_MS +
  2 * CEP_LICENSE_REQUEST_TIMEOUT_MS +
  CEP_LICENSE_PROVIDER_MAX_NETWORK_WAIT_MS;

function withinCepLicenseRouteDeadline<T>(
  operation: Promise<T>,
  timeoutMs: number,
  code: string,
  message: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new RouteError(504, code, message));
    }, timeoutMs);
    // Attaching both handlers means a late rejection remains observed after
    // the route deadline. The bounded target/customer calls are read-only.
    operation.then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function boundedCepLicenseReadTransport(
  delegate: Transport,
  timeoutMs: number = CEP_LICENSE_REQUEST_TIMEOUT_MS,
): Transport {
  return {
    requestJson(method, url, options) {
      if (method.toUpperCase() !== "GET") {
        return Promise.reject(new Error("cep-license-preguard-must-be-read-only"));
      }
      return withinCepLicenseRouteDeadline(
        delegate.requestJson(method, url, options),
        timeoutMs,
        "cep-license-preguard-timeout",
        "CEP licence assignment stopped because a customer or OU confirmation read timed out.",
      );
    },
  };
}

async function withCepMutationLease<T>(
  context: RouteContext,
  operationKind: "provision" | "rollback" | "assign_licenses",
  request: CepProvisionConfig | CepRollbackConfig | CepLicenseAssignConfig,
  mutate: (administrator: Transport, cloud: Transport) => Promise<T>,
): Promise<T> {
  if (
    context.acquireCepMutationLease === undefined ||
    context.renewCepMutationLease === undefined ||
    context.releaseCepMutationLease === undefined
  ) {
    throw new RouteError(
      503,
      "cep-mutation-lease-unavailable",
      "Durable CEP mutation coordination is unavailable.",
    );
  }
  // `my_customer` and its canonical C... id identify the same tenant. Resolve
  // before deriving the durable lease key so aliases cannot split the mutex
  // and race two list-before-create flows.
  const requestedLicenseTimeout = context.cepLicenseRequestTimeoutMs;
  const licenseRequestTimeout =
    typeof requestedLicenseTimeout === "number" &&
      Number.isFinite(requestedLicenseTimeout) && requestedLicenseTimeout > 0
      ? Math.min(requestedLicenseTimeout, CEP_LICENSE_REQUEST_TIMEOUT_MS)
      : CEP_LICENSE_REQUEST_TIMEOUT_MS;
  const coordinationTransport = operationKind === "assign_licenses"
    ? boundedCepLicenseReadTransport(context.administratorTransport, licenseRequestTimeout)
    : context.administratorTransport;
  const canonicalCustomer = await canonicalCepCustomerId(
    coordinationTransport,
    request.customer_id,
  );
  request.customer_id = canonicalCustomer;
  if (operationKind !== "rollback") {
    try {
      const target = await resolveConfirmedCepTargetOu(
        coordinationTransport,
        request as CepProvisionConfig | CepLicenseAssignConfig,
      );
      // From this point on, downstream code receives only the fresh
      // Directory value, never a caller-supplied display path.
      request.target_ou_path = target.path;
    } catch (error) {
      if (error instanceof CepTargetValidationError) {
        throw new RouteError(error.status, error.code, error.message);
      }
      throw error;
    }
  }
  const requestDigest = canonicalDigestSync({ operation_kind: operationKind, request });
  let handle: CepMutationLeaseHandle;
  try {
    handle = await context.acquireCepMutationLease({
      scopeKeys: cepMutationScopeKeys(operationKind, request),
      operationKind,
      requestDigest,
    });
  } catch (error) {
    if (error instanceof CepMutationLeaseBusy) {
      throw new RouteError(409, error.code, error.message);
    }
    throw error;
  }

  let leaseFailure: unknown;
  let renewalTail: Promise<void> = Promise.resolve();
  const renewFence = async (): Promise<void> => {
    if (leaseFailure !== undefined) throw leaseFailure;
    const attempt = renewalTail.then(async () => {
      if (leaseFailure !== undefined) throw leaseFailure;
      try {
        handle = await context.renewCepMutationLease!(handle);
      } catch (error) {
        leaseFailure ??= error;
        throw error;
      }
    });
    renewalTail = attempt.catch(() => undefined);
    await attempt;
  };
  const guardedTransport = (delegate: Transport): Transport =>
    new Proxy(delegate, {
      get(target, property, receiver) {
        if (property !== "requestJson") return Reflect.get(target, property, receiver);
        return async (
          method: string,
          url: string,
          options?: Parameters<Transport["requestJson"]>[2],
        ) => {
          if (["POST", "PUT", "PATCH", "DELETE"].includes(method.toUpperCase())) {
            try {
              await renewFence();
            } catch (error) {
              throw Object.assign(
                new Error(`cep-mutation-lease-fence: ${(error as Error).message}`),
                { cepMutationLeaseFence: true, cause: error },
              );
            }
          }
          return target.requestJson(method, url, options);
        };
      },
    });
  const heartbeat = setInterval(() => {
    void renewFence().catch(() => undefined);
  }, CEP_LEASE_HEARTBEAT_MS);

  let result: T | undefined;
  let mutationFailure: unknown;
  try {
    result = await mutate(
      guardedTransport(context.administratorTransport),
      guardedTransport(context.transport),
    );
  } catch (error) {
    mutationFailure = error;
  } finally {
    clearInterval(heartbeat);
  }

  const retainForReconciliation = mutationFailure instanceof CepMutationOutcomeAmbiguous;
  if (leaseFailure === undefined && !retainForReconciliation) {
    try {
      await context.releaseCepMutationLease(handle);
    } catch (error) {
      leaseFailure = error;
    }
  }
  if (mutationFailure instanceof CepMutationOutcomeAmbiguous) {
    throw new RouteError(
      503,
      mutationFailure.code,
      `${mutationFailure.message} Retry the exact request after the durable lease expires.`,
    );
  }
  if (mutationFailure !== undefined) throw mutationFailure;
  if (leaseFailure !== undefined) {
    throw new RouteError(
      503,
      "cep-mutation-lease-lost",
      "The CEP mutation completed without a durable lease handoff; retry the exact request after recovery.",
    );
  }
  return result as T;
}

function parseExtensionDeploymentSpec(input: Record<string, unknown>) {
  return parseDeploymentSpec(input);
}

/** Resolve the human actor for actions that require an operator decision. */
export async function humanAuditActor(
  context: Pick<RouteContext, "operatorEmail">,
): Promise<string> {
  const email = (await context.operatorEmail()).trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    throw new RouteError(
      401,
      "operator-identity-unavailable",
      "A signed-in administrator identity is required for this action.",
    );
  }
  return email;
}

function teardownDto(record: Record<string, unknown>): Record<string, unknown> {
  return {
    teardown_id: String(record.teardownId ?? ""),
    source_run_id: String(record.runId ?? ""),
    plan_hash: String(record.planHash ?? ""),
    status: String(record.status ?? "interrupted"),
    started_at: String(record.startedAt ?? ""),
    completed_at: record.completedAt ?? null,
    operations: Array.isArray(record.operations) ? record.operations : [],
  };
}

/** Continue the exact immutable teardown snapshot already stored in IDB. */
async function executeDurableTeardown(
  context: RouteContext,
  repository: StateRepository,
  teardownId: string,
  spec: ReturnType<typeof parseDeploymentSpec>,
): Promise<Record<string, unknown>> {
  let durable = await repository.teardown(teardownId);
  if (durable === undefined || durable.status !== "running") {
    throw new RouteError(409, "teardown-not-running", "Teardown is not running.");
  }
  const runId = String(durable.runId ?? "");
  const configurationHash = String(durable.configurationHash ?? "");
  const planHash = String(durable.planHash ?? "");
  const instructions = durable.instructions as TeardownInstruction[];
  assertTeardownSnapshotIntegrity({ runId, configurationHash, planHash, instructions });
  const executor = new GoogleResourceExecutor(context.transport, {
    workspaceTransport: context.administratorTransport,
  });

  for (let index = 0; index < instructions.length; index += 1) {
    durable = await repository.teardown(teardownId);
    if (durable === undefined || durable.status !== "running") {
      throw new Error("teardown-durable-snapshot-missing");
    }
    const currentInstructions = durable.instructions as TeardownInstruction[];
    assertTeardownSnapshotIntegrity({
      runId,
      configurationHash,
      planHash,
      instructions: currentInstructions,
    });
    const instruction = currentInstructions[index];
    if (instruction === undefined || instruction.resourceKey !== instructions[index]?.resourceKey) {
      throw new Error("teardown-operation-order-changed");
    }
    const operations = structuredClone(durable.operations) as Array<Record<string, unknown>>;
    const operation = operations[index];
    if (operation === undefined || operation.resource_key !== instruction.resourceKey) {
      throw new Error("teardown-operation-missing");
    }
    if (operation.status === "succeeded") continue;
    operation.status = "running";
    operation.error_code = null;
    operation.started_at = operation.started_at ?? new Date().toISOString();
    const running = { ...durable, operations };
    await repository.updateTeardownProgress(running);

    const change: ResourceChange = {
      provider: instruction.provider,
      resource_type: instruction.resourceType,
      resource_name: instruction.resourceName,
      action: "create",
      risk: "high",
      summary: `Teardown ${instruction.resourceKey}`,
      owned_after_apply: instruction.owned,
      dependencies: [],
    };
    try {
      const outcome = await executor.destroy(
        change,
        spec,
        String(operation.request_id),
        instruction.beforeImagePresent ? instruction.beforeImage : undefined,
      );
      if (outcome === "skipped") {
        throw new Error(`teardown-skipped-${instruction.resourceType}`);
      }
      await repository.commitTeardownResourceSuccess({
        teardownId,
        runId,
        resourceKey: instruction.resourceKey,
        outcome,
        completedAt: new Date().toISOString(),
      });
    } catch (error) {
      const latest = await repository.teardown(teardownId);
      if (latest === undefined) throw error;
      if (error instanceof AuthenticationError) {
        const interrupted = {
          ...latest,
          status: "interrupted",
          completedAt: new Date().toISOString(),
          reauthRequired: error.code === "consent-required",
          interruptionErrorCode: error.code,
        };
        await repository.updateTeardownProgress(interrupted);
        await repository.recordAuditEvent({
          deploymentId: runId,
          eventType: "teardown.interrupted",
          actor: "system",
          payload: { teardown_id: teardownId, run_id: runId, error_code: error.code },
        });
        return teardownDto(interrupted);
      }
      const failedOperations = structuredClone(latest.operations) as Array<Record<string, unknown>>;
      const failed = failedOperations[index];
      if (failed !== undefined) {
        failed.status = "failed";
        failed.error_code = error instanceof Error ? error.message : "teardown-provider-failed";
        failed.completed_at = new Date().toISOString();
      }
      const failedRecord = {
        ...latest,
        operations: failedOperations,
        status: "failed",
        completedAt: failed?.completed_at ?? new Date().toISOString(),
      };
      await repository.updateTeardownProgress(failedRecord);
      await repository.recordAuditEvent({
        deploymentId: runId,
        eventType: "teardown.failed",
        actor: "system",
        payload: {
          teardown_id: teardownId,
          resource_key: instruction.resourceKey,
          error_code: failed?.error_code ?? "teardown-provider-failed",
        },
      });
      return teardownDto(failedRecord);
    }
  }
  const completed = await repository.teardown(teardownId);
  if (completed === undefined || completed.status !== "succeeded") {
    throw new Error("teardown-finalization-not-committed");
  }
  return teardownDto(completed);
}

/** Restore Application IAM after the paired Gateway IAM write fails. */
export function compensateApplicationIamPolicy(
  transport: Transport,
  applicationUrl: string,
  beforePolicy: Record<string, unknown>,
  afterPolicy: Record<string, unknown>,
): Promise<void> {
  return restoreIamPolicyWithFreshEtag(transport, {
    getUrl: `${applicationUrl}:getIamPolicy`,
    setUrl: `${applicationUrl}:setIamPolicy`,
    getMethod: "GET",
    beforePolicy,
    afterPolicy,
  });
}

/** Routes served by the worker. Anything else is refused by name. */
const PORTED = new Set([
  "GET /api/v1/privacy/consent",
  "POST /api/v1/privacy/consent/prepare",
  "POST /api/v1/privacy/consent/finalize",
  "GET /api/v1/client-state",
  "POST /api/v1/client-state",
  "POST /api/v1/auth/sign-out",
  "POST /api/v1/connections/google-cloud/validate",
  "POST /api/v1/connections/workspace/validate",
  "POST /api/v1/bootstrap/google-cloud/deployer",
  "POST /api/v1/setup-options/organizational-units",
  "POST /api/v1/setup-options/groups",
  "POST /api/v1/setup-options/access-levels",
  "POST /api/v1/setup-options/vpc-networks",
  "POST /api/v1/setup-options/recommended-poc-source-image",
  "POST /api/v1/preflight",
  "POST /api/v1/plans",
  "GET /api/v1/plans/{}",
  "POST /api/v1/approvals",
  "GET /api/v1/approvals/{}",
  "POST /api/v1/runs",
  "POST /api/v1/runs/{}/resume",
  "GET /api/v1/runs",
  "GET /api/v1/runs/{}",
  "GET /api/v1/runs/{}/details",
  "GET /api/v1/runs/{}/logs",
  "GET /api/v1/runs/{}/acceptance",
  "POST /api/v1/runs/{}/acceptance-results",
  "POST /api/v1/runs/{}/acceptance/verify",
  "POST /api/v1/runs/{}/update-access-level",
  "GET /api/v1/runs/{}/teardown-plan",
  "POST /api/v1/runs/{}/teardowns",
  "GET /api/v1/runs/{}/teardowns/latest",
  "GET /api/v1/teardowns/{}",
  "POST /api/v1/teardowns/{}/resume",
  "GET /api/v1/evidence/audit-events",
  "GET /api/v1/evidence/integrity",
  "GET /api/v1/evidence/export",
  "GET /api/v1/health",
  "GET /api/v1/certificates/local-poc/{}",
  "POST /api/v1/cep/provision",
  "POST /api/v1/cep/rollback",
  "POST /api/v1/cep/roles",
  "POST /api/v1/cep/script",
  "POST /api/v1/cep/assign-licenses",
]);

/**
 * Collapse identifier segments so a request matches its declared route.
 *
 * `/api/v1/runs/abc` and `/api/v1/runs/{}` are the same route; the identifier
 * is data. Fixed sub-resources such as `/details` are kept, because those are
 * different routes.
 */
const KNOWN_SUBRESOURCES = new Set([
  "acceptance",
  "acceptance-results",
  "verify",
  "details",
  "logs",
  "enable",
  "update-access-level",
  "teardown-plan",
  "teardowns",
  "latest",
  "resume",
]);

function templateKey(method: string, path: string): string {
  const segments = path.split("/");
  const shaped = segments.map((segment, index) => {
    if (index < 4) return segment;
    return KNOWN_SUBRESOURCES.has(segment) ? segment : "{}";
  });
  return `${method} ${shaped.join("/")}`;
}

function normalise(path: string): string {
  return path.split("?")[0].replace(/\/$/, "");
}

export async function route(
  context: RouteContext,
  method: "GET" | "POST",
  path: string,
  body: unknown,
): Promise<unknown> {
  const clean = normalise(path);
  const key = `${method} ${clean}`;

  if (key === "GET /api/v1/privacy/consent") {
    return userDataConsentStatus(await openDatabase());
  }

  if (key === "POST /api/v1/privacy/consent/prepare") {
    const request = body as {
      legacy_setup?: unknown;
      legacy_workflow?: unknown;
    } | undefined;
    const legacyClientState: Record<string, unknown> = {};
    if (request?.legacy_setup !== undefined) {
      legacyClientState["frontend:setup"] = structuredClone(request.legacy_setup);
    }
    if (request?.legacy_workflow !== undefined) {
      legacyClientState["frontend:workflow"] = structuredClone(request.legacy_workflow);
    }
    // This is the sole permitted cleartext read and is reachable only from the
    // affirmative disclosure button. Consent remains `prepared` until both
    // Chrome storage surfaces have been erased.
    const legacyLocalState = await chrome.storage.local.get(null);
    const db = await openDatabase();
    await prepareUserDataConsentMigration({
      database: db,
      sensitiveStores: Object.values(STORE),
      legacyLocalState,
      legacyClientState,
    });
    await chrome.storage.local.clear();
    return { prepared: true };
  }

  if (key === "POST /api/v1/privacy/consent/finalize") {
    const db = await openDatabase();
    await finalizeUserDataConsent(db);
    return userDataConsentStatus(db);
  }

  if (key === "GET /api/v1/client-state") {
    const db = await openDatabase();
    const state = await encryptedLocalGetMany(db, ["frontend:setup", "frontend:workflow"]);
    return {
      setup: state["frontend:setup"] ?? null,
      workflow: state["frontend:workflow"] ?? null,
    };
  }

  if (key === "POST /api/v1/client-state") {
    const request = body as { setup?: unknown; workflow?: unknown } | undefined;
    const writes: Record<string, unknown> = {};
    const removals: string[] = [];
    for (const [field, storageKey] of [
      ["setup", "frontend:setup"],
      ["workflow", "frontend:workflow"],
    ] as const) {
      if (request === undefined || !(field in request)) continue;
      const value = request[field];
      if (value === null) removals.push(storageKey);
      else if (typeof value === "object" && value !== null && !Array.isArray(value)) {
        writes[storageKey] = structuredClone(value);
      } else {
        throw new RouteError(400, "client-state-invalid", `${field} must be an object or null`);
      }
    }
    const db = await openDatabase();
    if (Object.keys(writes).length > 0) await encryptedLocalSet(db, writes);
    if (removals.length > 0) await encryptedLocalRemove(db, removals);
    return { stored: true };
  }

  if (key === "GET /api/v1/health") {
    return { status: "ok", version: chrome.runtime.getManifest().version };
  }

  if (key === "POST /api/v1/auth/sign-out") {
    if (context.signOut) {
      await context.signOut();
    }
    return { success: true };
  }

  async function cloudCatalog(
    projectId: string,
    policyId?: string,
  ): Promise<GoogleSetupCatalog> {
    const configuredPolicyId =
      policyId ?? await context.accessPolicyId(projectId);
    return new GoogleSetupCatalog(context.discoveryTransport, {
      principalHint: await context.cloudIdentity(),
      credentialKind:
        (await context.cloudCredentialKind?.()) ?? "cloud_credential",
      accessPolicyId: configuredPolicyId,
    });
  }

  async function administratorCloudCatalog(
    policyId?: string,
  ): Promise<GoogleSetupCatalog> {
    return new GoogleSetupCatalog(context.administratorTransport, {
      principalHint: await context.operatorEmail(),
      credentialKind: "administrator",
      accessPolicyId: policyId,
    });
  }

  async function workspaceCatalog(): Promise<GoogleSetupCatalog> {
    return new GoogleSetupCatalog(context.administratorTransport, {
      principalHint: await context.operatorEmail(),
      credentialKind: "administrator",
    });
  }

  if (key === "POST /api/v1/connections/google-cloud/validate") {
    const projectId = (body as { project_id: string }).project_id;
    const validation = await (await cloudCatalog(projectId)).validateCloud(projectId);
    await context.rememberAccessPolicyId(projectId, validation.access_policy_id);
    return validation;
  }

  if (key === "POST /api/v1/connections/workspace/validate") {
    const request = body as { customer_id: string; target_ou_id?: string };
    return (await workspaceCatalog()).validateWorkspace(request.customer_id, request.target_ou_id);
  }

  if (key === "POST /api/v1/bootstrap/google-cloud/deployer") {
    // Creates the product-scoped deployer and grants the operator Token
    // Creator on it. Until this runs there is nothing to impersonate, so it is
    // the first action that must succeed in a fresh project.
    const request = body as {
      project_id: string;
      access_policy_id?: string | null;
      confirmation?: string;
      ownership_migration_confirmation?: string;
      replacement_deployer_confirmation?: string;
      deleted_deployer_rebootstrap_confirmation?: string;
    };
    const projectId = request.project_id;
    if (request.confirmation !== "BOOTSTRAP") {
      throw new RouteError(
        400,
        "bootstrap-confirmation-required",
        "Explicit BOOTSTRAP confirmation is required.",
      );
    }
    const migrationRequested =
      request.ownership_migration_confirmation === "MIGRATE_EXISTING_DEPLOYER";
    const replacementRequested =
      request.replacement_deployer_confirmation === "CREATE_ISOLATED_REPLACEMENT";
    const deletedRebootstrapRequested =
      request.deleted_deployer_rebootstrap_confirmation ===
        "RECREATE_DELETED_DEPLOYER";
    if (
      request.ownership_migration_confirmation !== undefined &&
      !migrationRequested
    ) {
      throw new RouteError(
        400,
        "ownership-migration-confirmation-invalid",
        "The legacy deployer migration confirmation is invalid.",
      );
    }
    if (
      request.replacement_deployer_confirmation !== undefined &&
      !replacementRequested
    ) {
      throw new RouteError(
        400,
        "replacement-deployer-confirmation-invalid",
        "The isolated replacement deployer confirmation is invalid.",
      );
    }
    if (
      request.deleted_deployer_rebootstrap_confirmation !== undefined &&
      !deletedRebootstrapRequested
    ) {
      throw new RouteError(
        400,
        "deleted-deployer-rebootstrap-confirmation-invalid",
        "The deleted deployer recreation confirmation is invalid.",
      );
    }
    if ([migrationRequested, replacementRequested, deletedRebootstrapRequested]
        .filter(Boolean).length > 1) {
      throw new RouteError(
        400,
        "bootstrap-mode-conflict",
        "Legacy adoption, isolated replacement, and deleted-deployer recreation cannot be requested together.",
      );
    }
    const requestedPolicyId = request.access_policy_id?.trim() || undefined;
    if (requestedPolicyId !== undefined && !/^\d+$/.test(requestedPolicyId)) {
      throw new RouteError(
        400,
        "access-policy-id-invalid",
        "access_policy_id must contain digits only.",
      );
    }
    const candidatePolicyId =
      requestedPolicyId ?? await context.accessPolicyId(projectId);
    // Revalidate request/local state against this project's organization. An
    // arbitrary stale policy id must never receive a deployer binding.
    const resolvedPolicyId = await (
      await administratorCloudCatalog(candidatePolicyId)
    ).discoverAccessPolicyId(projectId);
    await context.rememberAccessPolicyId(projectId, resolvedPolicyId);
    const ownershipPin = await context.bootstrapOwnershipPin(projectId);
    if (deletedRebootstrapRequested && ownershipPin === undefined) {
      throw new RouteError(
        409,
        "deleted-deployer-pin-missing",
        "No pinned deployer identity is available for explicit deleted-identity recreation.",
      );
    }
    if (ownershipPin !== undefined) {
      // Guard before bootstrap can PATCH a role or merge an IAM binding. A
      // second administrator is never added implicitly to an existing pin.
      await context.assertBootstrapOperator(projectId, ownershipPin);
    }
    const bootstrapOptions = {
      transport: context.administratorTransport,
      operatorEmail: await context.operatorEmail(),
      accessPolicyId: resolvedPolicyId ?? undefined,
      ownershipPin,
      checkpointOwnershipPin: context.checkpointBootstrapOwnershipPin,
      clearOwnershipPin: context.clearBootstrapOwnershipPin,
      ...(migrationRequested
        ? {
            allowOwnershipMigration: true,
            legacyDeployerIdentity: await context.legacyDeployerIdentity(),
          }
        : {}),
      ...(replacementRequested ? { createReplacementDeployer: true } : {}),
      ...(deletedRebootstrapRequested
        ? {
            allowDeletedOwnedDeployerRebootstrap: true,
            retireDeletedOwnershipPin: context.retireDeletedBootstrapOwnershipPin,
          }
        : {}),
    };
    const result = await bootstrapDeployer(projectId, bootstrapOptions);
    await context.rememberDeployer(
      result.service_account_email,
      projectId,
      result.service_account_unique_id,
      result.access_policy_id,
    );
    return result;
  }

  if (key === "POST /api/v1/setup-options/organizational-units") {
    const customerId = (body as { customer_id: string }).customer_id;
    return { options: await (await workspaceCatalog()).listOrganizationalUnits(customerId) };
  }

  if (key === "POST /api/v1/setup-options/groups") {
    const customerId = (body as { customer_id: string }).customer_id;
    return { options: await (await workspaceCatalog()).listGroups(customerId) };
  }

  if (key === "POST /api/v1/setup-options/access-levels") {
    const projectId = (body as { project_id: string }).project_id;
    const existing = await (await cloudCatalog(projectId)).listAccessLevels(projectId);
    const defaults = [
      {
        value: "NONE",
        label: "（アクセスレベル制限なし・認証済みグループ全ユーザー）",
        description: "BeyondCorp のアクセスレベル条件を付けずに全グループユーザーへ開放します",
      },
    ];
    return { options: [...defaults, ...existing] };
  }

  if (key === "POST /api/v1/setup-options/vpc-networks") {
    const projectId = (body as { project_id: string }).project_id;
    return { options: await (await cloudCatalog(projectId)).listVpcNetworks(projectId) };
  }

  if (key === "POST /api/v1/setup-options/recommended-poc-source-image") {
    const projectId = (body as { project_id: string }).project_id;
    return {
      option: await (await cloudCatalog(projectId)).recommendedPocSourceImage(),
    };
  }

  if (key === "POST /api/v1/preflight") {
    const spec = parseExtensionDeploymentSpec(
      (body as { specification: Record<string, unknown> }).specification,
    );
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const provider = new GoogleDiscoveryProvider(context.discoveryTransport, {
      cloudIdentity: await context.cloudIdentity(),
      workspaceTransport: context.administratorTransport,
      ownershipProofs: discoveryOwnershipProofs(
        await repository.ownershipProofResources(spec),
        spec,
      ),
    });
    return provider.preflight(spec);
  }

  if (key === "POST /api/v1/plans") {
    const spec = parseExtensionDeploymentSpec(
      (body as { specification: Record<string, unknown> }).specification,
    );
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const provider = new GoogleDiscoveryProvider(context.discoveryTransport, {
      cloudIdentity: await context.cloudIdentity(),
      workspaceTransport: context.administratorTransport,
      ownershipProofs: discoveryOwnershipProofs(
        await repository.ownershipProofResources(spec),
        spec,
      ),
    });
    const preflight = await provider.preflight(spec);
    const plan = buildPlan(spec, preflight.snapshot);
    const planId = crypto.randomUUID();
    const storedPlan = await repository.storePreparedPlan({
      planId,
      specificationJson: JSON.stringify(specToJson(spec)),
      preflightJson: JSON.stringify(preflight),
      planJson: JSON.stringify(plan),
      configurationHash: plan.configuration_hash,
    });
    return {
      plan_id: planId,
      specification: specToJson(spec),
      preflight,
      plan,
      created_at: storedPlan.createdAt,
      expires_at: storedPlan.expiresAt,
    };
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/plans/{}") {
    const db = await openDatabase();
    const record = await new StateRepository(db).preparedPlan(clean.split("/").pop() as string);
    if (record === undefined) throw new RouteError(404, "plan-not-found", "Plan not found");
    return {
      plan_id: record.planId,
      specification: JSON.parse(record.specificationJson as string),
      preflight: JSON.parse(record.preflightJson as string),
      plan: JSON.parse(record.planJson as string),
      created_at: record.createdAt,
      expires_at: record.expiresAt,
    };
  }

  if (key === "POST /api/v1/approvals") {
    // Approval binds to the plan hash and expires. Apply re-checks both, so a
    // stale approval cannot be replayed against a plan that has since changed.
    const request_ = body as { plan_id: string; ttl_minutes?: number };
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const prepared = await repository.preparedPlan(request_.plan_id);
    if (prepared === undefined) throw new RouteError(404, "plan-not-found", "Plan not found");
    const approvedSpec = parseExtensionDeploymentSpec(
      JSON.parse(String(prepared.specificationJson)) as Record<string, unknown>,
    );
    const actor = await humanAuditActor(context);
    const approval = await repository.storeApproval({
      planId: request_.plan_id,
      approvedBy: actor,
      ttlMinutes: request_.ttl_minutes ?? 30,
      deployerIdentity: await context.requireDeployer(approvedSpec.project_id),
    });
    await encryptedLocalSet(db, {
      [`spec:${approval.approvalId}`]: JSON.parse(approval.specificationJson),
    });
    return {
      approval_id: approval.approvalId,
      configuration_hash: approval.configurationHash,
      plan_hash: approval.planHash,
      approved_by: approval.approvedBy,
      approved_at: approval.approvedAt,
      expires_at: approval.expiresAt,
      consumed_at: approval.consumedAt,
      plan: JSON.parse(approval.planJson),
      specification: JSON.parse(approval.specificationJson),
    };
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/approvals/{}") {
    const db = await openDatabase();
    const approval = await new StateRepository(db).approval(clean.split("/").pop() as string);
    if (approval === undefined) {
      throw new RouteError(404, "approval-not-found", "Approval not found");
    }
    return {
      approval_id: approval.approvalId,
      configuration_hash: approval.configurationHash,
      plan_hash: approval.planHash,
      approved_by: approval.approvedBy,
      approved_at: approval.approvedAt,
      expires_at: approval.expiresAt,
      consumed_at: approval.consumedAt,
      plan: JSON.parse(approval.planJson),
      specification: JSON.parse(approval.specificationJson),
    };
  }

  async function buildAcceptanceReadiness(
    repository: StateRepository,
    runId: string,
  ) {
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const approval = await repository.approval(run.approvalId);
    const spec = approval
      ? parseExtensionDeploymentSpec(
          JSON.parse(approval.specificationJson) as Record<string, unknown>,
        )
      : null;
    const recorded = await repository.acceptance(runId);
    const history = recorded.map((r: any) => ({
      result_id: r.resultId ?? `res-${r.testId}`,
      run_id: r.runId,
      test_id: r.testId,
      case_key: r.caseKey ?? "default",
      status: r.status,
      source: r.source === "system_verified" ? "system" : "operator",
      summary: r.summary,
      evidence: r.evidence,
      actor: r.actor,
      recorded_at: r.recordedAt,
    }));
    const latestByCase = new Map<string, (typeof history)[number]>();
    for (const result of history.sort((left, right) =>
      String(left.recorded_at).localeCompare(String(right.recorded_at)))) {
      latestByCase.set(`${result.test_id}:${result.case_key}:${result.source}`, result);
    }
    const results = [...latestByCase.values()];
    const reqs = spec ? acceptanceRequirements(spec) : [];
    const requiredCases = reqs.map((req) => ({
      test_id: req.test_id,
      case_key: req.case_key,
      operator_confirmable: req.operator_confirmable,
      source: req.source,
      allow_poc_skip: req.allow_poc_skip,
    }));
    const operatorCases = requiredCases.filter((c) => c.operator_confirmable);
    const satisfiedCases = requiredCases.filter((required) =>
      results.some((result: any) => {
        if (result.test_id !== required.test_id || result.case_key !== required.case_key) {
          return false;
        }
        if (required.source === "system_verified") {
          return result.source === "system" && result.status === "passed";
        }
        if (result.source !== "operator") return false;
        if (result.status === "passed" || result.status === "user_confirmed") return true;
        return (
          spec?.mode === "poc" &&
          required.allow_poc_skip &&
          result.status === "skipped" &&
          typeof result.evidence === "string" &&
          result.evidence.trim().length >= 3
        );
      }),
    );
    const missingCases = requiredCases.filter(
      (c) =>
        !satisfiedCases.some(
          (s) => s.test_id === c.test_id && s.case_key === c.case_key,
        ),
    );
    const integrity = verifyEvidenceIntegrity(
      await repository.auditEvents(),
      await repository.allAcceptance(),
    );
    const complete = run.status === "succeeded" &&
      run.finalizationPending !== true && missingCases.length === 0;

    return {
      run_id: runId,
      mode: spec?.mode ?? "poc",
      acceptance_complete: complete,
      production_ready: complete && spec?.mode === "production" && integrity.valid,
      required_tests: Array.from(new Set(requiredCases.map((c) => c.test_id))),
      operator_confirmable_tests: Array.from(new Set(operatorCases.map((c) => c.test_id))),
      satisfied_tests: Array.from(new Set(satisfiedCases.map((c) => c.test_id))),
      missing_tests: Array.from(new Set(missingCases.map((c) => c.test_id))),
      required_cases: requiredCases,
      operator_confirmable_cases: operatorCases,
      satisfied_cases: satisfiedCases,
      missing_cases: missingCases,
      results,
    };
  }

  if (key === "GET /api/v1/runs") {
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const records = await repository.runs();
    return records.map((record) =>
      deploymentRunDto(record as unknown as Record<string, unknown>),
    );
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/runs/{}/details") {
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const runId = clean.split("/")[4];
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const approval = await repository.approval(run.approvalId);
    const spec = approval
      ? parseExtensionDeploymentSpec(
          JSON.parse(approval.specificationJson) as Record<string, unknown>,
        )
      : null;
    const plan = approval ? JSON.parse(approval.planJson) : null;
    const inventory = await repository.resources(runId);
    const teardownPlan = spec
      ? buildTeardownPlan(
          runId,
          run.configurationHash,
          spec.name,
          inventory.map((resource) => ({
            resourceKey: String(resource.resourceKey),
            provider: String(resource.provider),
            resourceType: String(resource.resourceType),
            resourceName: String(resource.resourceName),
            owned: resource.owned === true,
            shared: resource.shared === true,
            beforeImage: resource.beforeImage,
            requestId:
              typeof resource.requestId === "string" ? resource.requestId : undefined,
          })),
        )
      : null;
    const teardownActionByKey = new Map(
      [...(teardownPlan?.resources ?? []), ...(teardownPlan?.retained_resources ?? [])]
        .map((resource) => [resource.resource_key, resource.teardown_action]),
    );
    const summaryByKey = new Map<string, string>(
      (plan?.changes ?? []).map((change: any) => [
        `${change.provider}:${change.resource_type}:${change.resource_name}`,
        String(change.summary ?? ""),
      ]),
    );
    return {
      run: deploymentRunDto(run as unknown as Record<string, unknown>),
      ownership_run_id: inventory.length > 0 ? run.runId : null,
      deployment_name: spec?.name ?? "default",
      project_id: spec?.project_id ?? "",
      gateway_id: spec?.gateway_id ?? "default",
      backend_kind: spec?.backend_kind ?? "direct_https",
      application_hostname: spec ? applicationHostname(spec) : "",
      application_port: spec ? applicationPort(spec) : 443,
      resources: inventory.map((resource) => ({
        resource_key: resource.resourceKey,
        summary: summaryByKey.get(String(resource.resourceKey)) ?? "",
        provider: resource.provider,
        resource_type: resource.resourceType,
        resource_name: resource.resourceName,
        owned: resource.owned === true,
        teardown_action: teardownActionByKey.get(String(resource.resourceKey)) ?? "retain",
      })),
      managed_chrome_access_level:
        run.managedChromeAccessLevel ?? spec?.managed_chrome_access_level ?? null,
      policy_principals:
        run.policyPrincipals ?? spec?.principals.map(iamMember) ?? [],
      target_group_email:
        spec?.principals.find((principal) => principal.type === "group")?.value ?? null,
      teardown_available: teardownPlan?.can_destroy === true,
    };
  }

  if (
    method === "POST" &&
    templateKey(method, clean) === "POST /api/v1/runs/{}/update-access-level"
  ) {
    const runId = clean.split("/")[4];
    const bodyObj = (body ?? {}) as { access_level?: string; principals?: string[] };
    const newAccessLevel = bodyObj.access_level ?? "";
    const requestedPrincipals = bodyObj.principals ?? [];
    const spec = await runSpecification(runId);
    const actor = await humanAuditActor(context);
    const targetAccessLevel = newAccessLevel.trim();
    if (
      targetAccessLevel !== "" &&
      targetAccessLevel !== "NONE" &&
      !/^accessPolicies\/[0-9]+\/accessLevels\/[A-Za-z][A-Za-z0-9_]{0,49}$/.test(
        targetAccessLevel,
      )
    ) {
      throw new RouteError(
        400,
        "access-level-invalid",
        "access_level must be NONE or a full Access Context Manager access level name.",
      );
    }
    if (!Array.isArray(requestedPrincipals) || requestedPrincipals.length > 100) {
      throw new RouteError(400, "principals-invalid", "At most 100 principals may be supplied.");
    }
    const gatewayUrl = `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}/locations/global/securityGateways/${spec.gateway_id}`;
    const applicationUrl = `${gatewayUrl}/applications/${spec.name}-app`;

    function formatMember(str: string): string {
      const trimmed = str.trim();
      if (!trimmed) return "";
      const prefixed = /^(user|group|serviceAccount):([^\s@]+@[^\s@]+)$/.exec(trimmed);
      if (prefixed) return `${prefixed[1]}:${prefixed[2].toLowerCase()}`;
      const domain = /^domain:([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)$/.exec(trimmed);
      if (domain && domain[1].includes(".")) return `domain:${domain[1].toLowerCase()}`;
      if (/^[^\s@]+@[^\s@]+$/.test(trimmed)) {
        return `user:${trimmed.toLowerCase()}`;
      }
      throw new RouteError(400, "principal-invalid", `Invalid IAM principal: ${trimmed}`);
    }

    const baseMembers = new Set<string>();
    (spec.principals ?? []).forEach((p) => {
      if (p.value) baseMembers.add(iamMember(p));
    });
    requestedPrincipals.forEach((p) => {
      const formatted = formatMember(p);
      if (formatted) baseMembers.add(formatted);
    });
    if (baseMembers.size === 0) {
      throw new RouteError(400, "principals-required", "At least one principal is required.");
    }

    const db = await openDatabase();
    const repository = new StateRepository(db);
    const run = await repository.run(runId);
    if (
      run?.status !== "succeeded" ||
      run.finalizationPending === true ||
      run.policyUpdateCheckpoint !== undefined
    ) {
      throw new RouteError(
        409,
        "run-not-updateable",
        "Access policy can be updated only for a finalized successful run with no active lifecycle operation.",
      );
    }
    const deployerIdentity = await context.requireDeployer(spec.project_id, run.deployerIdentity);
    const ownedInventory = await repository.resources(runId);
    const applicationInventory = ownedInventory.find(
      (item) => item.provider === "beyondcorp" && item.resourceType === "application_iam",
    );
    const gatewayInventory = ownedInventory.find(
      (item) => item.provider === "beyondcorp" && item.resourceType === "gateway_iam",
    );
    if (applicationInventory === undefined || gatewayInventory === undefined) {
      throw new RouteError(
        409,
        "iam-inventory-missing",
        "The exact Apply IAM before-images are required before access policy can be updated.",
      );
    }
    const applicationInventoryBefore = iamInventoryBeforeImage(
      applicationInventory.beforeImage,
    );
    const gatewayInventoryBefore = iamInventoryBeforeImage(gatewayInventory.beforeImage);

    // Read both policies before the first mutation. Same-role bindings with a
    // different condition belong to another administrator and must survive.
    const { payload: gwPolicy } = await context.transport.requestJson(
      "GET",
      `${gatewayUrl}:getIamPolicy`,
      { params: { "options.requestedPolicyVersion": 3 } },
    );
    // Fetch current Application IAM policy.
    const { payload: currentPolicy } = await context.transport.requestJson(
      "GET",
      `${applicationUrl}:getIamPolicy`,
      { params: { "options.requestedPolicyVersion": 3 } },
    );
    const condition =
      targetAccessLevel && targetAccessLevel !== "NONE" && targetAccessLevel !== ""
        ? {
            title: "Managed Chrome required",
            description: "Allow only profiles or browsers managed by this enterprise",
            expression: `'${targetAccessLevel}' in request.auth.access_levels`,
          }
        : undefined;
    const previousLevel =
      typeof (run as DeploymentRunRecord & { managedChromeAccessLevel?: unknown })
        .managedChromeAccessLevel === "string"
        ? String(
            (run as DeploymentRunRecord & { managedChromeAccessLevel?: unknown })
              .managedChromeAccessLevel,
          )
        : (spec.managed_chrome_access_level ?? "NONE");
    const previousCondition =
      previousLevel !== "" && previousLevel !== "NONE"
        ? {
            title: "Managed Chrome required",
            description: "Allow only profiles or browsers managed by this enterprise",
            expression: `'${previousLevel}' in request.auth.access_levels`,
          }
        : undefined;
    const previousMembers = new Set(
      run.policyPrincipals ?? spec.principals.map(iamMember),
    );

    // Remove only this run's previously managed members. Other roles,
    // conditions, and members remain untouched; malformed policies fail closed.
    const appPolicy = replaceOwnedIamBinding({
      policy: currentPolicy,
      role: "roles/beyondcorp.sgApplicationUser",
      previousCondition,
      targetCondition: condition,
      previousMembers,
      targetMembers: baseMembers,
    });
    const gatewayPolicy = replaceOwnedIamBinding({
      policy: gwPolicy,
      role: "roles/beyondcorp.serviceDiscoveryUser",
      previousMembers,
      targetMembers: baseMembers,
    });

    const applicationGetUrl = `${applicationUrl}:getIamPolicy`;
    const applicationSetUrl = `${applicationUrl}:setIamPolicy`;
    const gatewayGetUrl = `${gatewayUrl}:getIamPolicy`;
    const gatewaySetUrl = `${gatewayUrl}:setIamPolicy`;
    if (
      applicationInventoryBefore.setUrl !== applicationSetUrl ||
      gatewayInventoryBefore.setUrl !== gatewaySetUrl
    ) {
      throw new RouteError(
        409,
        "iam-inventory-target-mismatch",
        "The persisted IAM ownership target does not match this deployment.",
      );
    }
    const checkpoint: PolicyUpdateCheckpoint = {
      protocolVersion: 2,
      checkpointId: crypto.randomUUID(),
      requestedAccessLevel: targetAccessLevel || "NONE",
      principals: [...baseMembers].sort(),
      actor,
      startedAt: new Date().toISOString(),
      phase: "prepared",
      application: {
        resourceKey: String(applicationInventory.resourceKey),
        getUrl: applicationGetUrl,
        setUrl: applicationSetUrl,
        beforePolicy: structuredClone(currentPolicy),
        afterPolicy: structuredClone(appPolicy),
        inventoryBeforeImageDigest: canonicalDigestSync(applicationInventory.beforeImage ?? null),
      },
      gateway: {
        resourceKey: String(gatewayInventory.resourceKey),
        getUrl: gatewayGetUrl,
        setUrl: gatewaySetUrl,
        beforePolicy: structuredClone(gwPolicy),
        afterPolicy: structuredClone(gatewayPolicy),
        inventoryBeforeImageDigest: canonicalDigestSync(gatewayInventory.beforeImage ?? null),
      },
    };
    await repository.beginRunPolicyUpdate(runId, checkpoint, {
      operator: actor,
      deployerIdentity,
    });

    try {
      await repository.recordAuditEvent({
        deploymentId: runId,
        eventType: "access_level.update_started",
        actor,
        payload: {
          run_id: runId,
          previous_access_level: previousLevel,
          requested_access_level: targetAccessLevel || "NONE",
        },
      });
      // Application first is fail-closed for newly added principals: if the
      // gateway update fails they still cannot discover a route it did not
      // grant, and the failed audit event makes the partial result explicit.
      await repository.checkpointRunPolicyUpdatePhase(
        runId,
        checkpoint.checkpointId,
        "application_sending",
      );
      checkpoint.phase = "application_sending";
      await context.transport.requestJson("POST", `${applicationUrl}:setIamPolicy`, {
        jsonBody: {
          policy: appPolicy,
        },
      });
      checkpoint.phase = "application_applied";
      await repository.checkpointRunPolicyUpdatePhase(
        runId,
        checkpoint.checkpointId,
        "application_applied",
      );
      await repository.checkpointRunPolicyUpdatePhase(
        runId,
        checkpoint.checkpointId,
        "gateway_sending",
      );
      checkpoint.phase = "gateway_sending";
      await context.transport.requestJson("POST", `${gatewayUrl}:setIamPolicy`, {
        jsonBody: {
          policy: gatewayPolicy,
        },
      });
      checkpoint.phase = "gateway_applied";
      await repository.checkpointRunPolicyUpdatePhase(
        runId,
        checkpoint.checkpointId,
        "gateway_applied",
      );
      await repository.commitRunPolicyUpdate(runId, checkpoint.checkpointId);
    } catch (error) {
      let compensationError: unknown = null;
      const compensationTargets = policyUpdateCompensationTargets(
        checkpoint.phase,
        isConfirmedIamEtagConflict(error) ||
          (isDefiniteMutationRejection(error) &&
            (!(error instanceof GoogleApiError) || error.status !== 409)),
        checkpoint.protocolVersion,
      );
      if (compensationTargets === null) {
        await repository.recordAuditEvent({
          deploymentId: runId,
          eventType: "access_level.update_manual_review",
          actor,
          payload: {
            run_id: runId,
            checkpoint_id: checkpoint.checkpointId,
            phase: checkpoint.phase,
            requested_access_level: targetAccessLevel || "NONE",
            error_code: error instanceof Error ? error.message : "provider-response-lost",
          },
        });
        throw new RouteError(
          502,
          "access-level-update-ambiguous",
          "Google may have accepted an IAM write before its response was lost. The durable checkpoint was retained for manual review; no binding was automatically removed.",
        );
      }
      try {
        // Only writes with a definitive successful response are ours to
        // reverse. A rejected current request never authorizes deletion of a
        // subsequently matching binding created by another administrator.
        for (const targetName of compensationTargets) {
          const target = checkpoint[targetName];
          await restoreIamPolicyWithFreshEtag(context.transport, {
            getUrl: target.getUrl,
            setUrl: target.setUrl,
            getMethod: "GET",
            beforePolicy: target.beforePolicy,
            afterPolicy: target.afterPolicy,
          });
        }
        await repository.abortRunPolicyUpdate(
          runId,
          checkpoint.checkpointId,
          error instanceof Error ? error.message : "google-api-failed",
        );
      } catch (rollbackError) {
        compensationError = rollbackError;
      }
      await repository.recordAuditEvent({
        deploymentId: runId,
        eventType: "access_level.update_failed",
        actor,
        payload: {
          run_id: runId,
          requested_access_level: targetAccessLevel || "NONE",
          error_code: error instanceof Error ? error.message : "google-api-failed",
          compensation_error:
            compensationError instanceof Error ? compensationError.message : null,
        },
      });
      if (compensationError !== null) {
        throw new RouteError(
          502,
          "access-level-partial-update",
          "The paired IAM update did not complete and automatic restoration also failed. Review the durable checkpoint and audit event before retrying.",
        );
      }
      throw error;
    }
    await repository.recordAuditEvent({
      deploymentId: runId,
      eventType: "access_level.updated",
      actor,
      payload: {
        run_id: runId,
        previous_access_level: previousLevel,
        updated_access_level: targetAccessLevel || "NONE",
        application: `${spec.name}-app`,
        principal_count: baseMembers.size,
      },
    });

    return {
      success: true,
      access_level: targetAccessLevel || "NONE",
      run_id: runId,
      policy_principals: [...baseMembers].sort(),
    };
  }

  /** The specification a run was applied from, needed by the log views. */
  async function runSpecification(runId: string) {
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const approval = await repository.approval(run.approvalId);
    if (approval === undefined) {
      throw new RouteError(404, "approval-not-found", "The run's approval is missing");
    }
    return parseExtensionDeploymentSpec(
      JSON.parse(approval.specificationJson) as Record<string, unknown>,
    );
  }

  async function authorizeRunEvidenceMutation(runId: string) {
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const approval = await repository.approval(run.approvalId);
    if (approval === undefined) throw new RouteError(404, "approval-not-found", "Approval not found");
    const spec = parseExtensionDeploymentSpec(
      JSON.parse(approval.specificationJson) as Record<string, unknown>,
    );
    const actor = await humanAuditActor(context);
    if (actor !== approval.approvedBy.trim().toLowerCase()) {
      throw new RouteError(
        409,
        "operator-identity-changed",
        "The signed-in operator differs from the operator bound to this run.",
      );
    }
    await context.requireDeployer(spec.project_id, run.deployerIdentity);
    return { repository, spec, actor };
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/runs/{}/logs") {
    const runId = clean.split("/")[4];
    const url = new URL(`https://x${path}`);
    // Logs expose tenant activity from the run's project. Apply the same
    // human-subject and immutable deployer binding used for evidence writes
    // before either the gateway state read or the Cloud Logging query.
    const authorized = await authorizeRunEvidenceMutation(runId);
    return new GatewayObservability(context.transport).listLogs(
      authorized.spec,
      {
        runId,
        category: (url.searchParams.get("category") ?? "connection") as LogCategory,
        hours: Number(url.searchParams.get("hours") ?? 24),
        limit: Number(url.searchParams.get("limit") ?? 100),
      },
    );
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/runs/{}/acceptance") {
    const runId = clean.split("/")[4];
    const db = await openDatabase();
    return buildAcceptanceReadiness(new StateRepository(db), runId);
  }

  if (
    method === "POST" &&
    templateKey(method, clean) === "POST /api/v1/runs/{}/acceptance-results"
  ) {
    // Operator-confirmed outcomes. Recorded as such: the evidence model
    // distinguishes what a machine verified from what a person attested, and
    // conflating them would make the export worth less than it looks.
    const runId = clean.split("/")[4];
    const record = body as {
      test_id: string;
      case_key?: string;
      status: string;
      summary: string;
      evidence: string;
    };
    const authorized = await authorizeRunEvidenceMutation(runId);
    const spec = authorized.spec;
    const caseKey = record.case_key ?? "default";
    const requirement = acceptanceRequirements(spec).find(
      (item) => item.test_id === record.test_id && item.case_key === caseKey,
    );
    if (requirement === undefined || !requirement.operator_confirmable) {
      throw new RouteError(
        400,
        "acceptance-case-not-operator-confirmable",
        "This acceptance case is not an operator-confirmable requirement for the run.",
      );
    }
    if (
      record.status === "skipped" &&
      !(spec.mode === "poc" && requirement.allow_poc_skip)
    ) {
      throw new RouteError(
        400,
        "acceptance-skip-not-allowed",
        "Only the greenfield PoC T06 control may be skipped, and it requires a reason.",
      );
    }
    await authorized.repository.recordAcceptance({
      runId,
      testId: record.test_id,
      caseKey,
      status: record.status,
      summary: record.summary,
      evidence: record.evidence,
      source: "operator_confirmed",
      actor: authorized.actor,
    });
    return { recorded: true, test_id: record.test_id };
  }

  if (
    method === "POST" &&
    templateKey(method, clean) === "POST /api/v1/runs/{}/acceptance/verify"
  ) {
    const runId = clean.split("/")[4];
    const authorized = await authorizeRunEvidenceMutation(runId);
    const spec = authorized.spec;
    const verifier = new GoogleAcceptanceVerifier(context.discoveryTransport);
    const findings = await verifier.verify(spec, runId);
    const repository = authorized.repository;
    for (const finding of findings) {
      await repository.recordAcceptance({
        runId,
        testId: finding.test_id,
        caseKey: "default",
        status: finding.status,
        summary: finding.summary,
        evidence: finding.evidence,
        source: "system_verified",
        actor: authorized.actor,
      });
    }
    return buildAcceptanceReadiness(repository, runId);
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/runs/{}/teardown-plan") {
    const runId = clean.split("/")[4];
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const spec = await runSpecification(runId);
    const inventory = (await repository.resources(runId)).map((record) => ({
      resourceKey: record.resourceKey as string,
      provider: record.provider as string,
      resourceType: record.resourceType as string,
      resourceName: record.resourceName as string,
      owned: record.owned as boolean,
      shared: record.shared as boolean,
      beforeImage: record.beforeImage,
      requestId: typeof record.requestId === "string" ? record.requestId : undefined,
    }));
    return buildTeardownPlan(runId, run.configurationHash, spec.name, inventory);
  }

  if (method === "POST" && templateKey(method, clean) === "POST /api/v1/runs/{}/teardowns") {
    const runId = clean.split("/")[4];
    const submitted = body as { plan_hash: string; confirmation: string };
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const spec = await runSpecification(runId);
    const actor = await humanAuditActor(context);
    const deployerIdentity = await context.requireDeployer(spec.project_id, run.deployerIdentity);
    const inventory = (await repository.resources(runId)).map((record) => ({
      resourceKey: record.resourceKey as string,
      provider: record.provider as string,
      resourceType: record.resourceType as string,
      resourceName: record.resourceName as string,
      owned: record.owned as boolean,
      shared: record.shared as boolean,
      beforeImage: record.beforeImage,
      requestId: typeof record.requestId === "string" ? record.requestId : undefined,
    }));
    const plan = buildTeardownPlan(runId, run.configurationHash, spec.name, inventory);

    // Rebuilt and re-checked rather than trusted: the inventory may have moved
    // since the operator read it, and a teardown approved against one set of
    // resources must not run against another.
    if (submitted.plan_hash !== plan.plan_hash || submitted.confirmation !== plan.confirmation) {
      throw new RouteError(
        409,
        "teardown-plan-changed",
        "The teardown plan changed since it was reviewed. Reload and confirm again.",
      );
    }
    if (!plan.can_destroy || plan.resources.length === 0) {
      throw new RouteError(
        409,
        "teardown-empty",
        "This run has no recorded owned resources or shared changes to reverse.",
      );
    }

    const instructions = buildTeardownExecutionSnapshot(
      runId,
      run.configurationHash,
      inventory,
    );
    assertTeardownSnapshotIntegrity({
      runId,
      configurationHash: run.configurationHash,
      planHash: plan.plan_hash,
      instructions,
    });

    const teardownId = crypto.randomUUID();
    const now = new Date().toISOString();
    const operations: Array<{
      resource_key: string;
      request_id: string;
      status: "pending" | "running" | "succeeded" | "failed";
      error_code: string | null;
      started_at: string | null;
      completed_at: string | null;
    }> = instructions.map((instruction) => ({
      resource_key: instruction.resourceKey,
      request_id: instruction.requestId,
      status: "pending",
      error_code: null,
      started_at: null,
      completed_at: null,
    }));
    const teardownRecord: Record<string, unknown> & { runId: string } = {
      teardownId,
      runId,
      configurationHash: run.configurationHash,
      planHash: plan.plan_hash,
      status: "running",
      startedAt: now,
      resources: plan.resources,
      instructions: structuredClone(instructions),
      operations,
      completedAt: null,
    };
    await repository.startTeardown(teardownRecord, {
      operator: actor,
      deployerIdentity,
    });

    const executor = new GoogleResourceExecutor(context.transport, {
      workspaceTransport: context.administratorTransport,
    });
    for (let index = 0; index < instructions.length; index += 1) {
      // Re-read and validate the immutable snapshot before every provider
      // operation. A changed name, ownership flag, before-image, or requestId
      // is a hard stop rather than a different teardown.
      const durable = await repository.teardown(teardownId);
      if (durable === undefined || durable.planHash !== plan.plan_hash) {
        throw new Error("teardown-durable-snapshot-missing");
      }
      const durableInstructions = durable.instructions as TeardownInstruction[];
      assertTeardownSnapshotIntegrity({
        runId,
        configurationHash: run.configurationHash,
        planHash: plan.plan_hash,
        instructions: durableInstructions,
      });
      const instruction = durableInstructions[index];
      if (instruction === undefined || instruction.resourceKey !== instructions[index]?.resourceKey) {
        throw new Error("teardown-operation-order-changed");
      }
      const operation = operations[index];
      operation.status = "running";
      operation.started_at = new Date().toISOString();
      await repository.updateTeardownProgress(teardownRecord);

      const change: ResourceChange = {
        provider: instruction.provider,
        resource_type: instruction.resourceType,
        resource_name: instruction.resourceName,
        action: "create",
        risk: "high",
        summary: `Teardown ${instruction.resourceKey}`,
        owned_after_apply: instruction.owned,
        dependencies: [],
      };

      try {
        const outcome = await executor.destroy(
          change,
          spec,
          operation.request_id,
          instruction.beforeImagePresent ? instruction.beforeImage : undefined,
        );
        if (outcome === "skipped") {
          throw new Error(`teardown-skipped-${instruction.resourceType}`);
        }
        operation.status = "succeeded";
        operation.completed_at = new Date().toISOString();
        const durableProgress = await repository.commitTeardownResourceSuccess({
          teardownId,
          runId,
          resourceKey: instruction.resourceKey,
          outcome,
          completedAt: operation.completed_at,
        });
        teardownRecord.status = durableProgress.status;
        teardownRecord.completedAt = durableProgress.completedAt ?? null;
      } catch (error) {
        operation.status = "failed";
        operation.error_code =
          error instanceof Error ? error.message : "teardown-provider-failed";
        operation.completed_at = new Date().toISOString();
        teardownRecord.status = "failed";
        teardownRecord.completedAt = operation.completed_at;
        await repository.updateTeardownProgress(teardownRecord);
        await repository.recordAuditEvent({
          deploymentId: runId,
          eventType: "teardown.failed",
          actor: "system",
          payload: {
            teardown_id: teardownId,
            resource_key: instruction.resourceKey,
            error_code: operation.error_code,
          },
        });
        return {
          teardown_id: teardownId,
          source_run_id: runId,
          plan_hash: plan.plan_hash,
          status: "failed" as const,
          started_at: now,
          completed_at: teardownRecord.completedAt,
          operations,
        };
      }
    }

    const durableCompleted = await repository.teardown(teardownId);
    if (durableCompleted?.status !== "succeeded") {
      throw new Error("teardown-finalization-not-committed");
    }
    const completedAt = String(durableCompleted.completedAt ?? "");
    return {
      teardown_id: teardownId,
      source_run_id: runId,
      plan_hash: plan.plan_hash,
      status: "succeeded" as const,
      started_at: now,
      completed_at: completedAt,
      operations,
    };
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/teardowns/{}") {
    const db = await openDatabase();
    const record = await new StateRepository(db).teardown(clean.split("/").pop() as string);
    if (record === undefined) {
      throw new RouteError(404, "teardown-not-found", "Teardown not found");
    }
    const rawRecord = record as any;
    return {
      teardown_id: rawRecord.teardownId ?? clean.split("/").pop(),
      source_run_id: rawRecord.runId ?? "",
      plan_hash: rawRecord.planHash ?? "",
      status: rawRecord.status ?? "interrupted",
      started_at: rawRecord.startedAt ?? new Date().toISOString(),
      completed_at: rawRecord.completedAt ?? null,
      operations: Array.isArray(rawRecord.operations)
        ? rawRecord.operations
        : [],
    };
  }

  if (
    method === "GET" &&
    templateKey(method, clean) === "GET /api/v1/runs/{}/teardowns/latest"
  ) {
    const runId = clean.split("/")[4];
    const db = await openDatabase();
    const latest = await new StateRepository(db).latestTeardown(runId);
    if (latest === undefined) {
      throw new RouteError(404, "teardown-not-found", "No teardown exists for this run.");
    }
    return teardownDto(latest);
  }

  if (
    method === "POST" &&
    templateKey(method, clean) === "POST /api/v1/teardowns/{}/resume"
  ) {
    if ((body as { confirmation?: unknown } | undefined)?.confirmation !== "RESUME") {
      throw new RouteError(
        400,
        "resume-confirmation-required",
        "Explicit RESUME confirmation is required.",
      );
    }
    const teardownId = clean.split("/")[4];
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const existing = await repository.teardown(teardownId);
    if (existing === undefined) {
      throw new RouteError(404, "teardown-not-found", "Teardown not found.");
    }
    const runId = String(existing.runId ?? "");
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Source run not found.");
    const spec = await runSpecification(runId);
    const actor = await humanAuditActor(context);
    const deployerIdentity = await context.requireDeployer(spec.project_id, run.deployerIdentity);
    await repository.resumeTeardown(teardownId, { operator: actor, deployerIdentity });
    return executeDurableTeardown(context, repository, teardownId, spec);
  }

  if (key === "POST /api/v1/runs") {
    const approvalId = (body as { approval_id: string }).approval_id;
    return context.startApply(approvalId);
  }

  if (
    method === "POST" &&
    templateKey(method, clean) === "POST /api/v1/runs/{}/resume"
  ) {
    if ((body as { confirmation?: unknown } | undefined)?.confirmation !== "RESUME") {
      throw new RouteError(
        400,
        "resume-confirmation-required",
        "Explicit RESUME confirmation is required.",
      );
    }
    return context.resumeApply(clean.split("/")[4]);
  }

  if (method === "GET" && /^\/api\/v1\/runs\/[^/]+$/.test(clean)) {
    return context.runState(clean.split("/").pop() as string);
  }

  if (key === "GET /api/v1/evidence/audit-events") {
    const db = await openDatabase();
    const records = await new StateRepository(db).auditEvents();
    return records.map(auditEventDto);
  }

  if (key === "GET /api/v1/evidence/integrity") {
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const events = await repository.auditEvents();
    const verification = verifyEvidenceIntegrity(events, await repository.allAcceptance());
    return {
      valid: verification.valid,
      event_count: verification.eventCount,
      algorithm: "sha256-chain",
      chain_head_hash: verification.chainHeadHash,
      acceptance_record_count: verification.acceptanceRecordCount,
      acceptance_event_count: verification.acceptanceEventCount,
      acceptance_valid: verification.acceptanceValid,
      reason: verification.reason,
    };
  }

  if (key === "GET /api/v1/evidence/export") {
    // Deleting the browser profile destroys IndexedDB, so this bundle is the
    // only durable record of a deployment. It carries the chain verification
    // alongside the events, because events without the verification are not
    // evidence -- they are just a list.
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const events = await repository.auditEvents();
    const acceptanceRecords = await repository.allAcceptance();
    const verification = verifyEvidenceIntegrity(events, acceptanceRecords);
    return {
      schema_version: 4,
      generated_at: new Date().toISOString(),
      app_version: chrome.runtime.getManifest().version,
      integrity: {
        valid: verification.valid,
        event_count: verification.eventCount,
        algorithm: "sha256-chain",
        chain_head_hash: verification.chainHeadHash,
        acceptance_record_count: verification.acceptanceRecordCount,
        acceptance_event_count: verification.acceptanceEventCount,
        acceptance_valid: verification.acceptanceValid,
        reason: verification.reason,
      },
      runs: (await repository.runs()).map((record) =>
        deploymentRunDto(record as unknown as Record<string, unknown>),
      ),
      resources: (await repository.allResources()).map(deploymentResourceDto),
      acceptance: acceptanceRecords.map(acceptanceResultDto),
      audit_events: events.map(auditEventDto),
    };
  }

  if (method === "GET" && /^\/api\/v1\/certificates\/local-poc\/[^/]+$/.test(clean)) {
    const deploymentName = decodeURIComponent(clean.split("/").pop() as string);
    const bundle = await encryptedLocalGet<{
      certificateChainPem?: string[];
    }>(await openDatabase(), `certificate:name:${deploymentName}`) as
      | { certificateChainPem?: string[] }
      | undefined;
    if (bundle === undefined || !Array.isArray(bundle.certificateChainPem) || bundle.certificateChainPem.length === 0) {
      throw new RouteError(404, "certificate-not-issued", "No PoC root certificate for this deployment");
    }
    const rootPem = bundle.certificateChainPem.at(-1) as string;
    return { content: btoa(rootPem), contentType: "application/x-pem-file" };
  }

  /**
   * Workspace APIs first, Cloud APIs second. The CEP deployer straddles both,
   * and only the Workspace half has to run as the administrator.
   */
  async function cepProvider(
    routeContext: RouteContext,
    projectId?: string,
    administrator: Transport = routeContext.administratorTransport,
    cloud: Transport = routeContext.transport,
  ): Promise<CepProvider> {
    return new CepProvider(
      administrator,
      cloud,
      projectId ? await routeContext.accessPolicyId(projectId) : undefined,
      routeContext.cepLicenseRequestTimeoutMs === undefined
        ? undefined
        : { licenseRequestTimeoutMs: routeContext.cepLicenseRequestTimeoutMs },
    );
  }

  if (key === "POST /api/v1/cep/provision") {
    const request_ = body as CepProvisionConfig;
    if (typeof request_.project_id !== "string" || request_.project_id === "") {
      throw new RouteError(400, "project-required", "CEP Cloud mutations require project_id.");
    }
    await context.requireDeployer(request_.project_id);
    return withCepMutationLease(context, "provision", request_, async (administrator, cloud) =>
      await (await cepProvider(context, request_.project_id, administrator, cloud)).provision(request_));
  }

  if (key === "POST /api/v1/cep/rollback") {
    const request_ = body as CepRollbackConfig;
    if (typeof request_.project_id !== "string" || request_.project_id === "") {
      throw new RouteError(400, "project-required", "CEP Cloud mutations require project_id.");
    }
    await context.requireDeployer(request_.project_id);
    return withCepMutationLease(context, "rollback", request_, async (administrator, cloud) =>
      await (await cepProvider(context, request_.project_id, administrator, cloud)).rollback(request_));
  }

  if (key === "POST /api/v1/cep/roles") {
    const request_ = body as CepCustomRoleConfig;
    await context.requireDeployer(request_.project_id);
    return (await cepProvider(context, request_.project_id)).createCustomRoles(request_);
  }

  if (key === "POST /api/v1/cep/script") {
    const request_ = body as CepProvisionConfig;
    const script = await (
      await cepProvider(context, request_.project_id)
    ).generatePythonScript(request_);
    return { script, filename: "cep_configure.py" };
  }

  if (key === "POST /api/v1/cep/assign-licenses") {
    const request_ = body as CepLicenseAssignConfig;
    if (typeof request_.project_id !== "string" || request_.project_id === "") {
      throw new RouteError(400, "project-required", "License assignment requires project_id.");
    }
    await withinCepLicenseRouteDeadline(
      context.requireDeployer(request_.project_id),
      CEP_LICENSE_AUTH_TIMEOUT_MS,
      "cep-license-auth-timeout",
      "CEP licence assignment stopped because deployer identity verification timed out.",
    );
    return withCepMutationLease(context, "assign_licenses", request_, async (administrator, cloud) =>
      await (await cepProvider(context, request_.project_id, administrator, cloud)).assignLicenses(request_));
  }

  throw new RouteError(
    501,
    "route-not-ported",
    `${key} is not part of the Path B port. Ported routes: ${[...PORTED].sort().join(", ")}.`,
  );
}
