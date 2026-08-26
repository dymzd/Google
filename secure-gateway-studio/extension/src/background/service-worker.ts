/**
 * Service worker: the extension's only privileged context.
 *
 * Everything that touches Google or storage happens here. The page renders and
 * sends messages; it holds no token and issues no API call. That split is what
 * lets Apply keep running after the page is closed, and lets an alarm resume it
 * after the worker itself is torn down.
 *
 * A service worker starts cold on every wake. Nothing may be assumed to survive
 * in module scope: cold-start reconciliation restores durable alarms, and the
 * alarm handler reloads the run from storage rather than trusting a variable.
 */

import {
  AuthenticationError,
  chromeIdentity,
  DeployerCredentials,
  googleOperatorIdentity,
  type GoogleOperatorIdentity,
} from "../auth/tokens.ts";
import { buildPlan, configurationHash, type DeploymentPlan } from "../domain/planner.ts";
import { canonicalDigestSync } from "../domain/canonical.ts";
import { isSupportedDeployerServiceAccountEmail } from "../domain/deployer-identity.ts";
import { parseDeploymentSpec, SpecValidationError, applicationHostname, type DeploymentSpec } from "../domain/spec.ts";
import {
  discoveryOwnershipProofs,
  GoogleDiscoveryProvider,
} from "../providers/discovery.ts";
import { ConnectionError } from "../providers/catalog.ts";
import {
  assertBootstrapOwnershipOperator,
  BootstrapError,
  legacyDeployerIdentityFromStoredState,
  normaliseIamBindings,
  type BootstrapOwnershipCheckpoint,
  type BootstrapOwnershipPin,
} from "../providers/bootstrap.ts";
import {
  GoogleApiError,
  GoogleResourceExecutor,
  restoreIamPolicyWithFreshEtag,
  type PrivateCaMutationPhase,
  type Transport,
} from "../providers/executor.ts";
import {
  enterpriseCertificateId,
  CertificateIssuanceRejectedError,
  generateKeyAndCsr,
  issueEnterpriseCa,
  issueLocalPoc,
  type CertificateBundle,
  type EnterpriseCertificateRequest,
} from "../providers/certificates.ts";
import {
  openDatabase,
  ApplySlotBusy,
  runHasActiveWork,
  policyUpdateCompensationTargets,
  StateRepository,
  STORE,
  TeardownSlotBusy,
  type DeploymentRunRecord,
  type DeployerIdentityBinding,
  type PolicyUpdateCheckpoint,
} from "../storage/repository.ts";
import {
  encryptedLocalGetMany,
  encryptedLocalRemove,
  encryptedLocalSet,
  secureObjectStore,
  userDataConsentStatus,
} from "../storage/secure-storage.ts";
import { buildAuditEvent, type AuditEventRecord } from "../storage/audit.ts";
import {
  LIFECYCLE_SCHEMA_VERSION,
  RunEngine,
  isActive,
  rollbackCompensationPreflight,
  residualResourceRecords,
  resourceRecordsForPlan,
  runAuditTransitions,
  type RunRecord,
  type RunStore,
} from "../runtime/run-engine.ts";
import { err, ok, type Request, type Response } from "./messages.ts";
import { route, RouteError } from "./router.ts";
import { reconcileAfterConsent, registerColdStartWakeups } from "./cold-start.ts";
import { parseGoogleJsonResponse } from "./google-response.ts";

const VERSION = chrome.runtime.getManifest().version;
const ALARM_PREFIX = "sgs-run:";

function assertSupportedExtensionArchitecture(spec: DeploymentSpec): DeploymentSpec {
  return spec;
}

/** Google-attested human account controlling the administrator token. */
async function operatorIdentity(): Promise<GoogleOperatorIdentity> {
  return await googleOperatorIdentity();
}

/** Set once the operator has chosen a deployer service account to impersonate. */
async function operatorEmail(): Promise<string> {
  try {
    return (await operatorIdentity()).email;
  } catch {
    return "";
  }
}


let credentials: DeployerCredentials | null = null;

/** Disk-backed extension state, encrypted below the Chrome storage API layer. */
async function persistentGet(
  keys: string | readonly string[],
): Promise<Record<string, unknown>> {
  const db = await openDatabase();
  const list = typeof keys === "string" ? [keys] : keys;
  return encryptedLocalGetMany(db, list);
}

async function persistentSet(entries: Record<string, unknown>): Promise<void> {
  const db = await openDatabase();
  await encryptedLocalSet(db, entries);
}

async function persistentRemove(keys: string | readonly string[]): Promise<void> {
  const db = await openDatabase();
  await encryptedLocalRemove(db, keys);
}

/**
 * MV3 workers are torn down when idle, so module-scoped `credentials` is a
 * cache rather than persistent state. Restore from the encrypted persistent
 * state to preserve product-scoped impersonation across restarts.
 */
async function ensureCredentials(): Promise<DeployerCredentials | null> {
  if (credentials !== null) return credentials;
  const stored = await persistentGet([
    "deployerServiceAccount",
    "deployerServiceAccountUniqueId",
    "deployerProjectId",
  ]);
  const email = stored.deployerServiceAccount;
  const projectId = stored.deployerProjectId;
  const uniqueId = stored.deployerServiceAccountUniqueId;
  if (
    typeof projectId !== "string" ||
    !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId) ||
    !isSupportedDeployerServiceAccountEmail(email, projectId) ||
    typeof uniqueId !== "string" ||
    !/^\d+$/.test(uniqueId)
  ) return null;
  credentials = new DeployerCredentials({ serviceAccountEmail: email });
  return credentials;
}

async function bootstrapOwnershipPin(projectId: string): Promise<unknown> {
  const stored = await persistentGet("bootstrapOwnershipPins");
  const pins = stored.bootstrapOwnershipPins;
  return typeof pins === "object" && pins !== null
    ? (pins as Record<string, unknown>)[projectId]
    : undefined;
}

/**
 * Re-attest the human operator and the complete service-account IAM policy.
 * A token mint proves only that the current user has *some* Token Creator
 * grant; exact pin equality prevents Alice's deployment from being operated by
 * Bob after Bob is added as another principal.
 */
async function requirePinnedBootstrapOperator(
  projectId: string,
  pinValue?: unknown,
  requireStoredSubject = true,
): Promise<{ pin: BootstrapOwnershipPin; operator: GoogleOperatorIdentity }> {
  const operator = await operatorIdentity();
  const pin = assertBootstrapOwnershipOperator(
    pinValue ?? await bootstrapOwnershipPin(projectId),
    projectId,
    operator.email,
  );
  const stored = await persistentGet([
    "deployerOperatorEmail",
    "deployerOperatorSubject",
  ]);
  const storedIdentityPresent =
    typeof stored.deployerOperatorEmail === "string" ||
    typeof stored.deployerOperatorSubject === "string";
  if ((requireStoredSubject || storedIdentityPresent) && (
    stored.deployerOperatorEmail !== operator.email ||
    stored.deployerOperatorSubject !== operator.subject
  )) {
    throw new AuthenticationError(
      "operator-identity-changed",
      "The signed-in Google account differs from the immutable operator bound to this deployer.",
    );
  }
  const accountUrl =
    `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts/` +
    encodeURIComponent(pin.service_account_email);
  const { payload } = await administratorTransport.requestJson(
    "POST",
    `${accountUrl}:getIamPolicy`,
    { params: { "options.requestedPolicyVersion": 3 } },
  );
  const liveBindings = normaliseIamBindings(payload.bindings);
  if (
    canonicalDigestSync(liveBindings) !==
      canonicalDigestSync(pin.service_account_iam_bindings)
  ) {
    throw new AuthenticationError(
      "deployer-iam-policy-changed",
      "The live deployer IAM policy differs from the exact bootstrapped ownership pin.",
    );
  }
  return { pin, operator };
}

/** Operator-only preguard for a complete pin or an initial-create intent. */
async function requireBootstrapCheckpointOperator(
  projectId: string,
  value: unknown,
): Promise<void> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AuthenticationError("bootstrap-ownership-pin-invalid", "Bootstrap ownership state is malformed.");
  }
  const checkpoint = value as Record<string, unknown>;
  const operator = await operatorIdentity();
  if (
    checkpoint.project_id !== projectId ||
    checkpoint.operator_email !== operator.email
  ) {
    throw new AuthenticationError(
      "operator-identity-changed",
      "The signed-in Google account differs from the operator bound to this bootstrap checkpoint.",
    );
  }
  const stored = await persistentGet(["deployerOperatorEmail", "deployerOperatorSubject"]);
  const storedIdentityPresent =
    typeof stored.deployerOperatorEmail === "string" ||
    typeof stored.deployerOperatorSubject === "string";
  if (storedIdentityPresent && (
    stored.deployerOperatorEmail !== operator.email ||
    stored.deployerOperatorSubject !== operator.subject
  )) {
    throw new AuthenticationError(
      "operator-identity-changed",
      "The immutable Google operator subject differs from the bootstrap owner.",
    );
  }
}

async function requireDeployerIdentity(
  projectId: string,
  expected?: DeployerIdentityBinding,
): Promise<DeployerIdentityBinding> {
  const stored = await persistentGet([
    "deployerServiceAccount",
    "deployerServiceAccountUniqueId",
    "deployerProjectId",
    "deployerOperatorEmail",
    "deployerOperatorSubject",
  ]);
  const identity: DeployerIdentityBinding = {
    serviceAccountEmail: String(stored.deployerServiceAccount ?? ""),
    serviceAccountUniqueId: String(stored.deployerServiceAccountUniqueId ?? ""),
    projectId: String(stored.deployerProjectId ?? ""),
    operatorEmail: String(stored.deployerOperatorEmail ?? ""),
    operatorSubject: String(stored.deployerOperatorSubject ?? ""),
  };
  if (
    identity.projectId !== projectId ||
    !isSupportedDeployerServiceAccountEmail(identity.serviceAccountEmail, projectId) ||
    !/^\d+$/.test(identity.serviceAccountUniqueId)
  ) {
    throw new AuthenticationError(
      "deployer-project-mismatch",
      `Bootstrap and impersonate the Secure Gateway deployer for ${projectId} before continuing.`,
    );
  }
  if (
    expected !== undefined &&
    canonicalDigestSync(identity) !== canonicalDigestSync(expected)
  ) {
    throw new AuthenticationError(
      "deployer-identity-changed",
      "The configured deployer differs from the identity bound to this approval or run.",
    );
  }
  const current = await ensureCredentials();
  if (current === null) {
    throw new AuthenticationError("deployer-required", "Impersonated deployer state is missing.");
  }
  // Mint first, then verify the immutable numeric identity of the exact service
  // account. A deleted/recreated account with the same email is not equivalent.
  await current.accessToken();
  const { pin } = await requirePinnedBootstrapOperator(projectId);
  if (
    pin.service_account_email !== identity.serviceAccountEmail ||
    pin.service_account_unique_id !== identity.serviceAccountUniqueId
  ) {
    throw new AuthenticationError(
      "deployer-identity-changed",
      "The stored deployer differs from the immutable bootstrap ownership record.",
    );
  }
  const { payload } = await transport.requestJson(
    "GET",
    `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts/` +
      encodeURIComponent(identity.serviceAccountEmail),
  );
  if (
    payload.email !== identity.serviceAccountEmail ||
    payload.uniqueId !== identity.serviceAccountUniqueId
  ) {
    throw new AuthenticationError(
      "deployer-identity-changed",
      "The live deployer service account no longer matches its bootstrapped immutable identity.",
    );
  }
  return identity;
}

/**
 * The token to call Google with.
 *
 * Impersonation is the steady state, but it cannot be the only state: the
 * deployer service account does not exist until bootstrap creates it, and
 * bootstrap is itself a Google call. Before that point the administrator's own
 * token is the only credential there is, and the operations that run then --
 * project lookup, Chrome Policy access, and bootstrap itself -- are exactly the
 * ones that legitimately belong to the administrator.
 *
 * Once a deployer exists every mutation runs as that account, which is the
 * dedicated mutation-identity property the local application had and the port had to keep.
 */
async function deployerAccessToken(): Promise<string> {
  const current = await ensureCredentials();
  if (current === null) {
    throw new AuthenticationError(
      "deployer-required",
      "A project-bound impersonated deployer is required for Google Cloud mutations.",
    );
  }
  return current.accessToken();
}

/** Explicitly read-only discovery may use the administrator before bootstrap. */
async function discoveryAccessToken(): Promise<string> {
  const current = await ensureCredentials();
  return current === null
    ? chromeIdentity.getAuthToken(false)
    : current.accessToken();
}

/**
 * Transport factory. The token source is a parameter because not every Google
 * API the product calls will accept the same credential.
 *
 * The token is fetched per request rather than held, because the worker may
 * have restarted since the last call and a stale closure would carry a token
 * that no longer exists.
 */
function makeTransport(token: () => Promise<string>, invalidate: () => Promise<void>): Transport {
  return {
    async requestJson(method, url, options = {}) {
      const send = async (bearer: string): Promise<globalThis.Response> => {
        const target = new URL(url);
        for (const [key, value] of Object.entries(options.params ?? {})) {
          target.searchParams.set(key, String(value));
        }
        return fetch(target, {
          method,
          headers: {
            Authorization: `Bearer ${bearer}`,
            ...(options.jsonBody ? { "Content-Type": "application/json" } : {}),
          },
          body: options.jsonBody ? JSON.stringify(options.jsonBody) : undefined,
        });
      };

      let response = await send(await token());
      if (response.status === 401) {
        await invalidate();
        response = await send(await token());
      }

      const payload = parseGoogleJsonResponse(await response.text(), response.status);
      if (
        (response.status < 200 || response.status >= 300) &&
        !options.acceptedStatuses?.includes(response.status)
      ) {
        throw new GoogleApiError({
          status: response.status,
          method,
          url,
          payload,
        });
      }
      return { status: response.status, payload };
    },
  };
}

async function dropCachedAdministratorToken(): Promise<void> {
  try {
    const cachedToken = await chromeIdentity.getAuthToken(false);
    await chromeIdentity.removeCachedAuthToken(cachedToken);
  } catch (error) {
    if (error instanceof AuthenticationError && error.code === "consent-required") {
      // There is no usable cached token. Removal errors have their own code
      // and must propagate so a 401 retry cannot silently reuse the same token.
      return;
    }
    throw error;
  }
}

async function hasAdministratorSession(): Promise<boolean> {
  try {
    await operatorIdentity();
    return true;
  } catch (error) {
    if (error instanceof AuthenticationError && error.code === "consent-required") return false;
    throw error;
  }
}

/** Google Cloud calls: the deployer service account once one exists. */
const transport: Transport = makeTransport(deployerAccessToken, async () => {
  const current = await ensureCredentials();
  if (current !== null) await current.invalidate();
});

const discoveryTransport: Transport = makeTransport(discoveryAccessToken, async () => {
  const current = await ensureCredentials();
  if (current !== null) await current.invalidate();
  else await dropCachedAdministratorToken();
});

/**
 * Workspace calls: always the signed-in administrator.
 *
 * Directory, Chrome Policy, and Cloud Identity authorize against a Workspace
 * user and its admin roles. The deployer token has neither: it is minted by
 * `generateAccessToken`, which cannot carry a `subject`, so it is not a
 * Workspace identity at all and these APIs reject it. Routing them through the
 * administrator is not a loosening of the scoped-identity model -- the
 * alternative is not a narrower credential, it is a 403.
 */
const administratorTransport: Transport = makeTransport(
  () => chromeIdentity.getAuthToken(false),
  dropCachedAdministratorToken,
);

/** Run records live in the same database as everything else. */
function idbRequest<T>(source: IDBRequest<T> | Promise<T>): Promise<T> {
  if (source instanceof Promise) return source;
  return new Promise((resolve, reject) => {
    source.onsuccess = () => resolve(source.result);
    source.onerror = () => reject(source.error);
  });
}

function idbTransactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error ?? new Error("Transaction aborted"));
  });
}

class IndexedDbRunStore implements RunStore {
  async load(runId: string): Promise<RunRecord | null> {
    const db = await openDatabase();
    const transactionScope = db.transaction([STORE.runs], "readonly");
    const store = secureObjectStore(transactionScope, STORE.runs);
    const res = await store.get(runId) as (RunRecord & { status?: string }) | undefined;
    if (res === undefined) return null;
    if (res.status && !res.state) res.state = res.status as RunRecord["state"];
    if (!res.steps) res.steps = [];
    await idbTransactionDone(transactionScope);
    return res;
  }

  async save(record: RunRecord): Promise<void> {
    const db = await openDatabase();
    const transactionScope = db.transaction([STORE.runs, STORE.audit], "readwrite");
    const done = idbTransactionDone(transactionScope);
    const store = secureObjectStore(transactionScope, STORE.runs);
    const audit = secureObjectStore(transactionScope, STORE.audit);
    const existing = await idbRequest(store.get(record.runId)) as
      | (RunRecord & { status?: string; startedAt?: string; finishedAt?: string | null })
      | undefined;
    const previous: RunRecord | null = existing === undefined
      ? null
      : {
          ...existing,
          state: (existing.state ?? existing.status ?? "running") as RunRecord["state"],
          steps: existing.steps ?? [],
        };
    const now = new Date().toISOString();
    const merged = {
      ...(existing || {}),
      ...record,
      status: record.state,
      state: record.state,
      startedAt: existing?.startedAt || now,
      finishedAt: !isActive(record.state)
        ? existing?.finishedAt || now
        : null,
    };
    const transitions = runAuditTransitions(previous, record);
    const cursor = await idbRequest(audit.openCursor(null, "prev"));
    let previousHash = cursor === null
      ? null
      : (cursor.value as AuditEventRecord).eventHash;
    await idbRequest(store.put(merged));
    for (const transition of transitions) {
      const event = buildAuditEvent({
        eventId: crypto.randomUUID(),
        deploymentId: null,
        eventType: transition.eventType,
        actor: "system",
        payload: transition.payload,
        createdAt: now,
        previousHash,
      });
      await idbRequest(audit.add(event));
      previousHash = event.eventHash;
    }
    await done;
  }
}

const runStore = new IndexedDbRunStore();

const scheduler = {
  async schedule(runId: string): Promise<void> {
    // The minimum period is coarser than the old in-process poll interval.
    // Google's long-running operations are not sensitive to that; what matters
    // is that the wake-up survives the worker being torn down.
    await chrome.alarms.create(`${ALARM_PREFIX}${runId}`, { periodInMinutes: 1 });
  },
  async cancel(runId: string): Promise<void> {
    await chrome.alarms.clear(`${ALARM_PREFIX}${runId}`);
  },
};

// The immediate Apply loop and the first recurring alarm can overlap when a
// Google operation takes longer than a minute. MV3 runs one worker instance at
// a time but may dispatch both events into it, so keep one in-flight driver per
// run. After worker termination this set disappears and the durable alarm is
// free to resume from IndexedDB.
const executingRuns = new Set<string>();

async function executeRunExclusively(
  runId: string,
  work: () => Promise<void>,
): Promise<boolean> {
  if (executingRuns.has(runId)) return false;
  executingRuns.add(runId);
  try {
    await work();
    return true;
  } finally {
    executingRuns.delete(runId);
  }
}

let coldStartReconciliation: Promise<void> | null = null;

const CONSENT_API_PATHS = new Set([
  "/api/v1/privacy/consent",
  "/api/v1/privacy/consent/prepare",
  "/api/v1/privacy/consent/finalize",
]);

async function requireUserDataConsent(): Promise<void> {
  const db = await openDatabase();
  if (!(await userDataConsentStatus(db)).accepted) {
    throw new RouteError(
      428,
      "user-data-consent-required",
      "Accept the 0.2.1 data disclosure before accessing persisted extension state.",
    );
  }
}

async function compensatePolicyUpdate(
  checkpoint: PolicyUpdateCheckpoint,
): Promise<boolean> {
  const targetNames = policyUpdateCompensationTargets(
    checkpoint.phase,
    false,
    checkpoint.protocolVersion,
  );
  if (targetNames === null) return false;
  for (const targetName of targetNames) {
    const target = checkpoint[targetName];
    await restoreIamPolicyWithFreshEtag(transport, {
      getUrl: target.getUrl,
      setUrl: target.setUrl,
      getMethod: "GET",
      beforePolicy: target.beforePolicy,
      afterPolicy: target.afterPolicy,
    });
  }
  return true;
}

/** Reconcile durable work once per MV3 worker lifetime. */
function ensureColdStartReconciled(): Promise<void> {
  if (coldStartReconciliation !== null) return coldStartReconciliation;
  let database: IDBDatabase | null = null;
  coldStartReconciliation = reconcileAfterConsent({
    consentAccepted: async () => {
      database = await openDatabase();
      return (await userDataConsentStatus(database)).accepted;
    },
    inspectDurableState: async () => {
    const db = database ?? await openDatabase();
    const repository = new StateRepository(db);

    // A teardown route runs synchronously within its message event. If the
    // worker/browser died during it, the remaining inventory is still owned
    // and a new teardown can safely retry it after this honest terminal mark.
    await repository.reconcileInterruptedTeardowns();

    // Apply/rollback is explicitly resumable. Never relabel it interrupted.
    // Finalization and post-deploy IAM updates are durable sagas too: settle
    // those checkpoints before releasing the global lifecycle slot.
    for (const run of await repository.runs()) {
      const state = run.state ?? run.status;
      if (run.policyUpdateCheckpoint !== undefined) {
        try {
          const spec = await specForRun(run as unknown as RunRecord);
          await requireDeployerIdentity(spec.project_id, run.deployerIdentity);
          const recovered = await compensatePolicyUpdate(run.policyUpdateCheckpoint);
          if (!recovered) {
            continue;
          }
          await repository.abortRunPolicyUpdate(
            run.runId,
            run.policyUpdateCheckpoint.checkpointId,
            "worker-restart",
          );
        } catch {
          continue;
        }
      }
      if (run.finalizationPending === true) {
        try {
          const durable = await runStore.load(run.runId);
          if (durable === null) throw new Error("run-not-found");
          await finalizeRun(durable, await specForRun(durable));
        } catch {
          await scheduler.schedule(run.runId);
        }
        continue;
      }
      if (state === "running" || state === "rolling_back") {
        await scheduler.schedule(run.runId);
      }
    }
    },
  }).then(
    (accepted) => {
      if (accepted) return;
      // A later affirmative consent request will retry this worker-lifetime
      // reconciliation. No legacy product store is opened on this path.
      coldStartReconciliation = null;
    },
    (error: unknown) => {
      // A transient IndexedDB/alarm failure must not poison this worker for
      // the rest of its lifetime. The next browser lifecycle or message wake
      // gets a fresh reconciliation attempt.
      coldStartReconciliation = null;
      throw error;
    },
  );
  return coldStartReconciliation;
}

async function signOutSafely(): Promise<void> {
  const db = await openDatabase();
  const repository = new StateRepository(db);
  const active = (await repository.runs()).find(runHasActiveWork);
  if (active !== undefined) {
    throw new RouteError(
      409,
      "active-run-signout-blocked",
      `Deployment ${active.runId} is still active; wait for it to finish before signing out.`,
    );
  }
  const activeTeardown = (await repository.activeTeardowns())[0];
  if (activeTeardown !== undefined) {
    throw new RouteError(
      409,
      "active-teardown-signout-blocked",
      `Teardown ${String(activeTeardown.teardownId)} is still active; wait for it to finish before signing out.`,
    );
  }
  const activeCep = (await repository.cepMutationLeases())[0];
  if (activeCep !== undefined) {
    throw new RouteError(
      409,
      "active-cep-mutation-signout-blocked",
      `CEP operation ${activeCep.operationId} is still active; resume or finish it before signing out.`,
    );
  }
  // clearAllCachedAuthTokens is materially stronger than removing the current
  // access token: Chrome also clears account preferences and de-authorizes the
  // extension. Await it before reporting success; otherwise a silent token
  // request can immediately recreate the administrator session.
  await chromeIdentity.clearAllCachedAuthTokens();
  credentials = null;
  await chrome.storage.session.clear();
  // Specs and public certificate material are required for later evidence and
  // teardown. They are not credentials; deleting all local storage here would
  // make a completed run impossible to dismantle after signing back in.
  const storedIdentity = await persistentGet([
    "deployerServiceAccount",
    "deployerServiceAccountUniqueId",
    "deployerProjectId",
  ]);
  const legacyIdentity = legacyDeployerIdentityFromStoredState(storedIdentity);
  if (
    legacyIdentity !== undefined &&
    storedIdentity.deployerServiceAccountUniqueId === undefined
  ) {
    // Preserve only the non-secret 0.2.0 identity hint needed by the explicit
    // migration audit. It cannot mint a token and is not trusted as ownership.
    await persistentSet({
      legacyDeployerIdentityV020: {
        serviceAccountEmail: legacyIdentity.serviceAccountEmail,
        projectId: legacyIdentity.projectId,
      },
    });
  }
  await persistentRemove([
    "deployerServiceAccount",
    "deployerServiceAccountUniqueId",
    "deployerProjectId",
    "deployerOperatorEmail",
    "deployerOperatorSubject",
  ]);
}

/**
 * Retire one provider-confirmed deleted bootstrap identity without weakening
 * normal sign-out. The full pin digest and immutable ids remain as a bounded
 * tombstone, while active lifecycle work prevents identity replacement.
 */
async function retireDeletedBootstrapOwnershipPin(
  pin: BootstrapOwnershipPin,
): Promise<void> {
  await requireBootstrapCheckpointOperator(pin.project_id, pin);
  const repository = new StateRepository(await openDatabase());
  const activeRun = (await repository.runs()).find(runHasActiveWork);
  if (activeRun !== undefined) {
    throw new RouteError(
      409,
      "active-run-deployer-retirement-blocked",
      `Deployment ${activeRun.runId} is still active; the pinned deployer was not retired.`,
    );
  }
  const activeTeardown = (await repository.activeTeardowns())[0];
  if (activeTeardown !== undefined) {
    throw new RouteError(
      409,
      "active-teardown-deployer-retirement-blocked",
      `Teardown ${String(activeTeardown.teardownId)} is still active; the pinned deployer was not retired.`,
    );
  }
  const activeCep = (await repository.cepMutationLeases())[0];
  if (activeCep !== undefined) {
    throw new RouteError(
      409,
      "active-cep-deployer-retirement-blocked",
      `CEP operation ${activeCep.operationId} is still active; the pinned deployer was not retired.`,
    );
  }

  const stored = await persistentGet([
    "bootstrapOwnershipPins",
    "retiredBootstrapOwnershipPins",
  ]);
  const pins = typeof stored.bootstrapOwnershipPins === "object" &&
      stored.bootstrapOwnershipPins !== null
    ? { ...stored.bootstrapOwnershipPins as Record<string, unknown> }
    : {};
  if (
    canonicalDigestSync(pins[pin.project_id] ?? null) !==
      canonicalDigestSync(pin)
  ) {
    throw new RouteError(
      409,
      "bootstrap-ownership-pin-changed",
      "The deployer ownership pin changed after Cloud deletion preflight. Nothing was retired.",
    );
  }
  const retired = typeof stored.retiredBootstrapOwnershipPins === "object" &&
      stored.retiredBootstrapOwnershipPins !== null
    ? { ...stored.retiredBootstrapOwnershipPins as Record<string, unknown> }
    : {};
  const prior = Array.isArray(retired[pin.project_id])
    ? retired[pin.project_id] as unknown[]
    : [];
  retired[pin.project_id] = [
    ...prior,
    {
      version: 1,
      project_id: pin.project_id,
      service_account_email: pin.service_account_email,
      service_account_unique_id: pin.service_account_unique_id,
      custom_role: pin.custom_role,
      operator_email: pin.operator_email,
      retired_at: new Date().toISOString(),
      reason: "provider-confirmed-deleted",
      ownership_pin_sha256: canonicalDigestSync(pin),
    },
  ].slice(-8);
  delete pins[pin.project_id];
  await persistentSet({
    bootstrapOwnershipPins: pins,
    retiredBootstrapOwnershipPins: retired,
  });
  await persistentRemove([
    "deployerServiceAccount",
    "deployerServiceAccountUniqueId",
    "deployerProjectId",
    "deployerOperatorEmail",
    "deployerOperatorSubject",
  ]);
  credentials = null;
}

type PublicCertificateBundle = Omit<CertificateBundle, "privateKeyPem">;

interface EnterpriseCertificateRequestCheckpoint extends EnterpriseCertificateRequest {
  certificateName: string;
  hostname: string;
}

function publicCertificateBundle(bundle: CertificateBundle): PublicCertificateBundle {
  return {
    certificatePem: bundle.certificatePem,
    certificateChainPem: [...bundle.certificateChainPem],
    hostname: bundle.hostname,
    issuerResourceName: bundle.issuerResourceName,
  };
}

async function rememberCertificateBundle(
  runId: string,
  spec: DeploymentSpec,
  bundle: CertificateBundle,
): Promise<CertificateBundle> {
  const key = `certificate:${runId}`;
  const nameKey = `certificate:name:${spec.name}`;
  const publicBundle = publicCertificateBundle(bundle);
  await persistentSet({ [key]: publicBundle, [nameKey]: publicBundle });
  await chrome.storage.session.set({ [key]: bundle });
  return bundle;
}

function enterpriseRequestCheckpoint(
  value: unknown,
  certificateName: string,
  hostname: string,
): EnterpriseCertificateRequestCheckpoint | null {
  if (typeof value !== "object" || value === null) return null;
  const checkpoint = value as Partial<EnterpriseCertificateRequestCheckpoint>;
  return typeof checkpoint.csrPem === "string" && checkpoint.csrPem !== "" &&
      typeof checkpoint.privateKeyPem === "string" && checkpoint.privateKeyPem !== "" &&
      checkpoint.certificateName === certificateName && checkpoint.hostname === hostname
    ? checkpoint as EnterpriseCertificateRequestCheckpoint
    : null;
}

/**
 * Issue the owned enterprise certificate after its run step has checkpointed
 * the exact resource name. Key/CSR material reaches session storage before
 * the POST, so an MV3 worker restart retries the same mutation with the same
 * UUID and CSR instead of generating an unusable replacement key.
 */
async function issueEnterpriseCertificateForRun(
  runId: string,
  spec: DeploymentSpec,
  requestId: string,
  checkpointCsr: (
    csrPem: string,
    phase?: PrivateCaMutationPhase,
  ) => Promise<void>,
): Promise<CertificateBundle> {
  if (!spec.ca_pool || !spec.ca_name) throw new Error("privateca-configuration-missing");
  const certificateId = enterpriseCertificateId(spec.name, runId);
  const certificateName = `${spec.ca_pool}/certificates/${certificateId}`;
  const hostname = applicationHostname(spec);
  const requestKey = `certificate:request:${runId}`;
  const intentKey = `certificate:intent:${runId}`;

  const stored = await chrome.storage.session.get(requestKey);
  let request = enterpriseRequestCheckpoint(
    stored[requestKey],
    certificateName,
    hostname,
  );
  if (stored[requestKey] !== undefined && request === null) {
    throw new Error("certificate-request-checkpoint-invalid");
  }
  if (request === null) {
    const generated = await generateKeyAndCsr(hostname);
    request = {
      certificateName,
      hostname,
      csrPem: generated.csrPem,
      privateKeyPem: generated.privateKeyPem,
    };
    // The remote mutation must never be reachable before this await commits.
    await chrome.storage.session.set({ [requestKey]: request });
  }

  // This marker contains no private material. Both it and the durable run-step
  // CSR digest are committed before the create POST is reachable. A browser
  // restart can therefore distinguish our exact certificate from a pre-existing
  // name collision before attempting revoke.
  await persistentSet({
    [intentKey]: {
      protocolVersion: 1,
      phase: "prepared",
      certificateName,
      hostname,
      csrDigest: canonicalDigestSync(request.csrPem),
      // A CSR contains only public key/request material. Keeping it in the
      // encrypted durable store lets rollback prove the exact eventual
      // certificate after a full browser restart without persisting the key.
      csrPem: request.csrPem,
    },
  });
  await checkpointCsr(request.csrPem, "prepared");
  // This await is the commit boundary: the Private CA POST is unreachable
  // until the durable run-step ownership row records an ambiguous send.
  await checkpointCsr(request.csrPem, "sending");

  let bundle: CertificateBundle;
  try {
    bundle = await issueEnterpriseCa(transport, {
      hostname,
      caPool: spec.ca_pool,
      caName: spec.ca_name,
      certificateId,
      lifetimeDays: spec.certificate_lifetime_days,
      requestId,
      request,
    });
  } catch (error) {
    if (
      error instanceof CertificateIssuanceRejectedError ||
      (error instanceof GoogleApiError &&
        [400, 401, 403, 404, 412].includes(error.status))
    ) {
      await checkpointCsr(request.csrPem, "rejected");
    }
    throw error;
  }
  return rememberCertificateBundle(runId, spec, bundle);
}

/**
 * Issue or retrieve the certificate bundle for this run.
 *
 * Public material is persisted for the certificate/evidence screens. The
 * private key is kept in chrome.storage.session only: it survives MV3 worker
 * suspension inside the browser session but is never written to disk-backed
 * storage. If Chrome itself restarts mid-Apply, the encrypted public marker
 * makes us fail closed rather than silently issuing a mismatched replacement.
 */
async function certificateForRun(
  runId: string,
  spec: DeploymentSpec,
): Promise<CertificateBundle | undefined> {
  if (spec.certificate_strategy === "public_trusted") {
    return undefined;
  }
  const key = `certificate:${runId}`;
  const requestKey = `certificate:request:${runId}`;
  const intentKey = `certificate:intent:${runId}`;
  const ephemeral = await chrome.storage.session.get([key, requestKey]);
  if (ephemeral[key]) return ephemeral[key] as CertificateBundle;
  const persisted = await persistentGet([key, intentKey]);

  if (spec.certificate_strategy === "local_poc") {
    if (persisted[key]) throw new Error("certificate-key-material-unavailable");
    const bundle = await issueLocalPoc(
      applicationHostname(spec),
      spec.certificate_lifetime_days,
    );
    return rememberCertificateBundle(runId, spec, bundle);
  }

  if (spec.certificate_strategy === "enterprise_ca") {
    // A suspended worker keeps session storage, including the pre-POST CSR and
    // key checkpoint. A full browser restart does not; the durable marker then
    // forces rollback, whose privateca step revokes the exact certificate.
    if (ephemeral[requestKey] !== undefined) return undefined;
    if (persisted[key] !== undefined || persisted[intentKey] !== undefined) {
      throw new Error("certificate-key-material-unavailable");
    }
  }

  return undefined;
}

async function purgeEphemeralCertificate(runId: string, spec: DeploymentSpec): Promise<void> {
  await chrome.storage.session.remove([
    `certificate:${runId}`,
    `certificate:request:${runId}`,
    `certificate:name:${spec.name}`,
  ]);
  // The name-scoped public bundle remains available to the certificate and
  // evidence routes. The run-scoped local entry is only a crash marker while
  // Apply is active and can be removed once the run is terminal.
  await persistentRemove([
    `certificate:${runId}`,
    `certificate:intent:${runId}`,
  ]);
}

async function engineFor(runId: string, spec: DeploymentSpec): Promise<RunEngine> {
  const record = await runStore.load(runId);
  if (record === null) throw new Error("run-not-found");
  await requireDeployerIdentity(
    spec.project_id,
    (record as unknown as DeploymentRunRecord).deployerIdentity,
  );
  const certificate = record?.state === "rolling_back"
    ? undefined
    : await certificateForRun(runId, spec);
  const executor = new GoogleResourceExecutor(transport, {
    certificate,
    publicCertificateBinding: record.publicCertificateBinding ?? null,
    sourceImageBinding: record.sourceImageBinding ?? null,
    workspaceTransport: administratorTransport,
    accessPolicyId: await accessPolicyId(spec.project_id),
    issueEnterpriseCertificate: issueEnterpriseCertificateForRun,
  });
  if (record.state !== "rolling_back") {
    await executor.prepareApply(spec);
  }
  return new RunEngine(
    runStore,
    executor,
    scheduler,
  );
}

async function finalizeRun(
  record: RunRecord,
  spec: DeploymentSpec,
  plan?: DeploymentPlan,
): Promise<void> {
  let resources = residualResourceRecords(record);
  if (record.state === "succeeded") {
    let completedPlan = plan;
    if (completedPlan === undefined) {
      const db = await openDatabase();
      const approval = await new StateRepository(db).approval(record.approvalId);
      if (approval === undefined) throw new Error("run-approval-missing");
      completedPlan = JSON.parse(approval.planJson) as DeploymentPlan;
    }
    const stepByKey = new Map(
      record.steps.map((step) => [
        `${step.change.provider}:${step.change.resource_type}:${step.change.resource_name}`,
        step,
      ]),
    );
    resources = resourceRecordsForPlan(completedPlan.changes).map((resource) => {
      const step = stepByKey.get(resource.resourceKey);
      return {
        ...resource,
        beforeImage: step?.beforeImage,
        requestId: step?.requestId,
      };
    });
  } else if (record.state === "rollback_failed" || record.state === "rollback_unavailable") {
    // Checkpoint only the resources that compensation did not remove. This
    // must complete before certificate intent/key markers are purged: the
    // persisted before-image is the exact identifier a later teardown uses to
    // retry a failed Private CA revoke or restore a shared policy.
    resources = residualResourceRecords(record);
  }
  if (!isActive(record.state)) {
    const db = await openDatabase();
    await new StateRepository(db).finalizeRunInventory(record, resources);
    await scheduler.cancel(record.runId);
    await purgeEphemeralCertificate(record.runId, spec);
  }
}

async function scheduleRollbackAfterFatalError(runId: string, error: unknown): Promise<void> {
  const record = await runStore.load(runId);
  if (record === null || !isActive(record.state)) return;
  if (record.state === "rolling_back") {
    record.state = "rollback_failed";
    record.finalizationPending = true;
    record.finalizedAt = null;
    await runStore.save(record);
    await scheduler.schedule(runId);
    return;
  }
  const current = record.steps.find((step) => step.status !== "done");
  if (current !== undefined) {
    current.status = "failed";
    current.error = (error as Error).message;
  }
  record.state = "rolling_back";
  await runStore.save(record);
  await scheduler.schedule(runId);
}

async function interruptRunForAuthentication(
  runId: string,
  error: AuthenticationError,
): Promise<void> {
  const record = await runStore.load(runId);
  if (record !== null && isActive(record.state)) {
    record.interruptedFrom = record.state as "running" | "rolling_back";
    record.state = "interrupted";
    record.reauthRequired = error.code === "consent-required";
    record.interruptionErrorCode = error.code;
    await runStore.save(record);
  }
  // Do not turn revoked consent into a background prompt/retry loop. Explicit
  // Sign in + Resume re-attests the same operator/deployer/run first.
  await scheduler.cancel(runId);
}

/** Drive exactly one already-persisted run; both Apply and explicit Resume use it. */
async function driveDurableRun(runId: string, plan?: DeploymentPlan): Promise<void> {
  await executeRunExclusively(runId, async () => {
    try {
      const initial = await runStore.load(runId);
      if (initial === null) throw new Error("run-not-found");
      const lifecycleApproval = await new StateRepository(await openDatabase())
        .approval(initial.approvalId);
      const currentLifecycleSchema =
        initial.schemaVersion === LIFECYCLE_SCHEMA_VERSION &&
        initial.steps.every((step) => step.schemaVersion === LIFECYCLE_SCHEMA_VERSION) &&
        lifecycleApproval?.schemaVersion === LIFECYCLE_SCHEMA_VERSION;
      if (!currentLifecycleSchema) {
        // A cold-start wake has no freshly attested operator. Never let an old
        // record discover a new invariant inside the executor. Pause it locally
        // and require the explicit Resume path, which performs identity checks,
        // whole-run compensation preflight, and one-time schema adoption.
        initial.interruptedFrom = initial.state === "rolling_back"
          ? "rolling_back"
          : "running";
        initial.state = "interrupted";
        initial.reauthRequired = false;
        initial.interruptionErrorCode = "legacy-lifecycle-adoption-required";
        await runStore.save(initial);
        await scheduler.cancel(runId);
        return;
      }
      const spec = await specForRun(initial);
      let current: RunRecord | null = initial;
      while (current !== null && isActive(current.state)) {
        const currentEngine = await engineFor(runId, spec);
        current = await currentEngine.tick(runId, spec);
      }
      if (current !== null) await finalizeRun(current, spec, plan);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        await interruptRunForAuthentication(runId, error);
        return;
      }
      await scheduleRollbackAfterFatalError(runId, error);
    }
  });
}

async function handle(request: Request): Promise<Response<unknown>> {
  await requireUserDataConsent();
  await ensureColdStartReconciled();
  switch (request.kind) {
    case "health":
      return ok({
        status: "ok",
        version: VERSION,
        authenticated: await hasAdministratorSession(),
      });

    case "signIn": {
      // Establishes the administrator session. Impersonation starts later, once
      // bootstrap has created the deployer; until then this token is what the
      // setup calls use.
      // This explicit UI action is the only place allowed to prompt. Always
      // refresh administrator consent first even when deployer metadata
      // survived sign-out; the impersonation mint below remains silent and
      // consumes only the token Chrome just cached.
      await chromeIdentity.getAuthToken(true);
      const operator = await operatorIdentity();
      const boundOperator = await persistentGet([
        "deployerOperatorEmail",
        "deployerOperatorSubject",
      ]);
      const hasBoundOperator =
        typeof boundOperator.deployerOperatorEmail === "string" ||
        typeof boundOperator.deployerOperatorSubject === "string";
      if (hasBoundOperator && (
        boundOperator.deployerOperatorEmail !== operator.email ||
        boundOperator.deployerOperatorSubject !== operator.subject
      )) {
        throw new AuthenticationError(
          "operator-identity-changed",
          "The signed-in Google account differs from the immutable operator bound to this deployer.",
        );
      }
      const stored = await persistentGet([
        "deployerServiceAccount",
        "deployerServiceAccountUniqueId",
        "deployerProjectId",
      ]);
      const deployer = stored.deployerServiceAccount;
      const projectId = stored.deployerProjectId;
      const uniqueId = stored.deployerServiceAccountUniqueId;
      if (
        typeof projectId === "string" &&
        isSupportedDeployerServiceAccountEmail(deployer, projectId) &&
        typeof uniqueId === "string" && /^\d+$/.test(uniqueId)
      ) {
        credentials = new DeployerCredentials({ serviceAccountEmail: deployer });
        await credentials.accessToken();
      } else {
        credentials = null;
      }
      return ok({ authenticated: true, operator: operator.email });
    }

    case "signOut": {
      await signOutSafely();
      return ok({ authenticated: false });
    }

    case "preflight": {
      const spec = assertSupportedExtensionArchitecture(parseDeploymentSpec(request.spec));
      const db = await openDatabase();
      const repository = new StateRepository(db);
      const provider = new GoogleDiscoveryProvider(discoveryTransport, {
        cloudIdentity: await resolveDeployerEmail(),
        workspaceTransport: administratorTransport,
        ownershipProofs: discoveryOwnershipProofs(
          await repository.ownershipProofResources(spec),
          spec,
        ),
      });
      return ok(await provider.preflight(spec));
    }

    case "plan": {
      const spec = assertSupportedExtensionArchitecture(parseDeploymentSpec(request.spec));
      const db = await openDatabase();
      const repository = new StateRepository(db);
      const provider = new GoogleDiscoveryProvider(discoveryTransport, {
        cloudIdentity: await resolveDeployerEmail(),
        workspaceTransport: administratorTransport,
        ownershipProofs: discoveryOwnershipProofs(
          await repository.ownershipProofResources(spec),
          spec,
        ),
      });
      const preflight = await provider.preflight(spec);
      const plan: DeploymentPlan = buildPlan(spec, preflight.snapshot);
      return ok({ plan, snapshot: preflight.snapshot });
    }

    case "apply": {
      const db = await openDatabase();
      const repository = new StateRepository(db);
      const pendingApproval = await repository.approval(request.approvalId);
      if (pendingApproval === undefined) {
        throw new RouteError(404, "approval-not-found", "Approval not found");
      }
      const approvedSpec = assertSupportedExtensionArchitecture(
        parseDeploymentSpec(
          JSON.parse(pendingApproval.specificationJson) as Record<string, unknown>,
        ),
      );
      const currentOperator = (await operatorEmail()).trim().toLowerCase();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(currentOperator)) {
        throw new AuthenticationError(
          "operator-identity-unavailable",
          "The signed-in administrator identity is required to consume an approval.",
        );
      }
      const deployerIdentity = await requireDeployerIdentity(
        approvedSpec.project_id,
        pendingApproval.deployerIdentity,
      );
      // Approval consumption and Apply-slot acquisition are one transaction;
      // a second caller cannot observe the approval as unconsumed.
      const { approval, run } = await repository.consumeApprovalAndCreateRun(
        request.approvalId,
        { operator: currentOperator, deployerIdentity },
      );
      const plan = JSON.parse(approval.planJson) as DeploymentPlan;
      // The approval transaction already persisted the complete RunRecord,
      // including every step and stable requestId. There is no empty-run
      // initialization window for a worker crash to exploit.
      await scheduler.schedule(run.runId);

      // Execute non-blocking continuous tick loop immediately so apply finishes in seconds
      void driveDurableRun(run.runId, plan);

      return ok({ runId: run.runId });
    }

    case "runState": {
      const record = await runStore.load(request.runId);
      return record === null
        ? err("run-not-found", `Unknown run ${request.runId}`)
        : ok({ run: record });
    }

    case "auditChain": {
      const db = await openDatabase();
      return ok(await new StateRepository(db).auditEvents());
    }

    default:
      return err("unsupported-request", `Unsupported request ${JSON.stringify(request)}`);
  }
}

/**
 * The identity recorded as the audit actor.
 *
 * Before bootstrap that is the signed-in administrator, because no deployer
 * exists yet and the setup calls really are theirs. Afterwards it is the
 * deployer, matching the local application, where the actor was always taken
 * from the credential rather than supplied by the browser.
 */
async function resolveDeployerEmail(): Promise<string> {
  const stored = await persistentGet("deployerServiceAccount");
  const email = stored.deployerServiceAccount;
  if (typeof email === "string" && email !== "") return email;
  const operator = await operatorEmail();
  if (operator === "") {
    throw new Error("Sign in to Chrome with the administrator account first.");
  }
  return operator;
}

async function accessPolicyId(projectId?: string): Promise<string | undefined> {
  const stored = await persistentGet([
    "accessPolicyId",
    "accessPolicyProjectId",
  ]);
  if (
    projectId !== undefined &&
    stored.accessPolicyProjectId !== projectId
  ) {
    return undefined;
  }
  const value = stored.accessPolicyId;
  return typeof value === "string" && value !== "" ? value : undefined;
}

async function rememberAccessPolicyId(
  projectId: string,
  policyId: string | null,
): Promise<void> {
  if (policyId === null) {
    await persistentRemove([
      "accessPolicyId",
      "accessPolicyProjectId",
    ]);
    return;
  }
  if (!/^\d+$/.test(policyId)) throw new Error("access-policy-id-invalid");
  await persistentSet({
    accessPolicyId: policyId,
    accessPolicyProjectId: projectId,
  });
}

async function deploymentRunState(runId: string): Promise<Record<string, unknown>> {
  const record = await runStore.load(runId);
  if (record === null) {
    const db = await openDatabase();
    const run = await new StateRepository(db).run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", `Unknown run ${runId}`);
    return {
      run_id: run.runId,
      approval_id: run.approvalId,
      configuration_hash: run.configurationHash,
      status: run.status,
      started_at: run.startedAt,
      completed_at: run.finishedAt,
      operations: [],
      residual_resources: [],
      retry_available: false,
    };
  }
  const db = await openDatabase();
  const storedRun = await new StateRepository(db).run(runId);
  return {
    run_id: record.runId,
    approval_id: record.approvalId,
    configuration_hash: record.configurationHash,
    status: record.state,
    started_at: storedRun?.startedAt ?? null,
    completed_at: storedRun?.finishedAt ?? null,
    retry_available:
      record.state === "interrupted" || record.state === "failed" ||
      record.state === "rollback_failed" ||
      (record.state === "rollback_unavailable" &&
        record.schemaVersion !== LIFECYCLE_SCHEMA_VERSION),
    residual_resources: residualResourceRecords(record).map((resource) => ({
      resource_key: resource.resourceKey,
      provider: resource.provider,
      resource_type: resource.resourceType,
      resource_name: resource.resourceName,
      owned: resource.owned,
      shared: resource.shared,
    })),
    operations: (record.steps ?? []).map((step) => ({
      operation_id: step.requestId,
      operation_digest: step.digest,
      resource_key: `${step.change.provider}:${step.change.resource_type}:${step.change.resource_name}`,
      action: step.change.action,
      status: step.status === "done" ? "succeeded" : step.status,
      error_code: step.error,
    })),
  };
}

const routeContext = {
  discoveryTransport,
  transport,
  administratorTransport,
  cloudIdentity: resolveDeployerEmail,
  operatorEmail,
  accessPolicyId,
  cloudCredentialKind: async () =>
    (await ensureCredentials()) === null
      ? "administrator"
      : "impersonated_service_account",
  rememberAccessPolicyId,
  bootstrapOwnershipPin,
  assertBootstrapOperator: async (projectId: string, pin: unknown) => {
    await requireBootstrapCheckpointOperator(projectId, pin);
  },
  checkpointBootstrapOwnershipPin: async (pin: BootstrapOwnershipCheckpoint) => {
    const stored = await persistentGet("bootstrapOwnershipPins");
    const pins = typeof stored.bootstrapOwnershipPins === "object" &&
        stored.bootstrapOwnershipPins !== null
      ? stored.bootstrapOwnershipPins as Record<string, unknown>
      : {};
    await persistentSet({
      bootstrapOwnershipPins: {
        ...pins,
        [pin.project_id]: structuredClone(pin),
      },
    });
  },
  clearBootstrapOwnershipPin: async (projectId: string) => {
    const stored = await persistentGet("bootstrapOwnershipPins");
    const pins = typeof stored.bootstrapOwnershipPins === "object" &&
        stored.bootstrapOwnershipPins !== null
      ? { ...stored.bootstrapOwnershipPins as Record<string, unknown> }
      : {};
    delete pins[projectId];
    await persistentSet({ bootstrapOwnershipPins: pins });
  },
  retireDeletedBootstrapOwnershipPin,
  legacyDeployerIdentity: async () => {
    const stored = await persistentGet([
      "deployerServiceAccount",
      "deployerProjectId",
      "legacyDeployerIdentityV020",
    ]);
    return legacyDeployerIdentityFromStoredState(stored);
  },
  rememberDeployer: async (
    email: string,
    projectId: string,
    uniqueId: string,
    policyId?: string | null,
  ) => {
    const operator = await operatorIdentity();
    await persistentSet({
      deployerServiceAccount: email,
      deployerServiceAccountUniqueId: uniqueId,
      deployerProjectId: projectId,
      deployerOperatorEmail: operator.email,
      deployerOperatorSubject: operator.subject,
    });
    await persistentRemove("legacyDeployerIdentityV020");
    await rememberAccessPolicyId(projectId, policyId ?? null);
    credentials = new DeployerCredentials({ serviceAccountEmail: email });
    // A first cold-start pass may have retained provider work because the
    // deployer was unavailable. Bootstrap has now restored it, so retry those
    // durable checkpoints in this worker lifetime instead of waiting for a
    // browser restart.
    coldStartReconciliation = null;
    await ensureColdStartReconciled();
  },
  requireDeployer: requireDeployerIdentity,
  acquireCepMutationLease: async (options: Parameters<StateRepository["acquireCepMutationLease"]>[0]) =>
    await new StateRepository(await openDatabase()).acquireCepMutationLease(options),
  renewCepMutationLease: async (lease: Parameters<StateRepository["renewCepMutationLease"]>[0]) =>
    await new StateRepository(await openDatabase()).renewCepMutationLease(lease),
  releaseCepMutationLease: async (lease: Parameters<StateRepository["releaseCepMutationLease"]>[0]) =>
    await new StateRepository(await openDatabase()).releaseCepMutationLease(lease),
  signOut: async () => {
    await signOutSafely();
  },
  startApply: async (approvalId: string) => {
    const reply = (await handle({ kind: "apply", approvalId })) as {
      ok: true;
      value: { runId: string };
    };
    const db = await openDatabase();
    const run = await new StateRepository(db).run(reply.value.runId);
    return {
      run_id: reply.value.runId,
      approval_id: approvalId,
      configuration_hash: run?.configurationHash ?? "",
      status: run?.status ?? "running",
      started_at: run?.startedAt ?? new Date().toISOString(),
      completed_at: run?.finishedAt ?? null,
      operations: [],
    };
  },
  resumeApply: async (runId: string) => {
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", `Unknown run ${runId}`);
    const approval = await repository.approval(run.approvalId);
    if (approval === undefined || approval.consumedAt === null) {
      throw new RouteError(409, "run-resume-invalid", "The consumed approval is missing.");
    }
    const spec = assertSupportedExtensionArchitecture(
      parseDeploymentSpec(JSON.parse(approval.specificationJson)),
    );
    const operator = await operatorIdentity();
    const deployerIdentity = await requireDeployerIdentity(spec.project_id, run.deployerIdentity);
    const rollbackPreflight = rollbackCompensationPreflight(run as unknown as RunRecord);
    const resumed = await repository.resumeRun(runId, {
      operator: operator.email,
      deployerIdentity,
    }, rollbackPreflight);
    if (!isActive(resumed.state)) {
      await finalizeRun(resumed, spec);
      return deploymentRunState(runId);
    }
    await scheduler.schedule(runId);
    void driveDurableRun(runId);
    return deploymentRunState(runId);
  },
  runState: deploymentRunState,
};

interface ApiMessage {
  kind: "api";
  method: "GET" | "POST";
  path: string;
  body?: unknown;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const incoming = message as Request | ApiMessage;

  // Two shapes share the channel: the small typed control messages the shell
  // page uses, and the path-based API the ported React layer speaks.
  const work =
    (incoming as ApiMessage).kind === "api"
      ? (CONSENT_API_PATHS.has((incoming as ApiMessage).path)
          ? Promise.resolve()
          : requireUserDataConsent().then(() => ensureColdStartReconciled()))
        .then(() => route(
          routeContext,
          (incoming as ApiMessage).method,
          (incoming as ApiMessage).path,
          (incoming as ApiMessage).body,
        )).then((value) => ({ ok: true as const, value }))
      : handle(incoming as Request);

  work.then(sendResponse).catch((error: unknown) => {
    if (error instanceof RouteError) {
      sendResponse({ ok: false, status: error.status, code: error.code, message: error.message });
      return;
    }
    if (error instanceof ApplySlotBusy || error instanceof TeardownSlotBusy) {
      sendResponse({
        ok: false,
        status: 409,
        code: "lifecycle-slot-busy",
        message: error.message,
      });
      return;
    }
    if (error instanceof AuthenticationError) {
      sendResponse({
        ok: false,
        status: error.code === "consent-required"
          ? 401
          : error.code === "impersonation-denied"
            ? 403
            : 409,
        code: error.code,
        message: error.message,
      });
      return;
    }
    if (error instanceof BootstrapError) {
      sendResponse({
        ok: false,
        status: 409,
        code: error.code,
        message: error.message,
      });
      return;
    }
    if (error instanceof ConnectionError) {
      sendResponse({
        ok: false,
        status: 409,
        code: error.code,
        message: error.message,
      });
      return;
    }
    if (error instanceof GoogleApiError) {
      sendResponse({
        ok: false,
        status: error.status,
        code: `google-api-${error.status}`,
        message: error.message,
      });
      return;
    }
    const code = error instanceof SpecValidationError ? "spec-invalid" : "request-failed";
    sendResponse({ ok: false, status: 500, code, message: (error as Error).message });
  });
  // Keep the message channel open for the async reply.
  return true;
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (!alarm.name.startsWith(ALARM_PREFIX)) return;
  const runId = alarm.name.slice(ALARM_PREFIX.length);
  void executeRunExclusively(runId, async () => {
    try {
      await requireUserDataConsent();
      await ensureColdStartReconciled();
      const record = await runStore.load(runId);
      if (record === null) {
        await scheduler.cancel(runId);
        return;
      }
      if (!isActive(record.state)) {
        if (record.finalizationPending === true) {
          await finalizeRun(record, await specForRun(record));
        } else {
          await scheduler.cancel(runId);
        }
        return;
      }
      // The spec is reconstructed from the approval rather than held in memory;
      // this handler may be the first thing a cold worker runs.
      const spec = await specForRun(record);
      const currentEngine = await engineFor(runId, spec);
      const current = await currentEngine.tick(runId, spec);
      if (!isActive(current.state)) await finalizeRun(current, spec);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        await interruptRunForAuthentication(runId, error);
        return;
      }
      await scheduleRollbackAfterFatalError(runId, error);
    }
  });
});

async function specForRun(record: RunRecord) {
  const checkedSpec = (value: Record<string, unknown>): DeploymentSpec => {
    const spec = assertSupportedExtensionArchitecture(parseDeploymentSpec(value));
    if (configurationHash(spec) !== record.configurationHash) {
      throw new Error("run-specification-hash-mismatch");
    }
    return spec;
  };
  const stored = await persistentGet(`spec:${record.approvalId}`);
  const cached = stored[`spec:${record.approvalId}`];
  if (cached !== undefined) {
    return checkedSpec(cached as Record<string, unknown>);
  }
  // The encrypted persistent spec cache is not the source of truth. The
  // single-use approval in IndexedDB remains available after cache loss.
  const db = await openDatabase();
  const approval = await new StateRepository(db).approval(record.approvalId);
  if (approval === undefined) throw new Error("run-approval-missing");
  return checkedSpec(JSON.parse(approval.specificationJson) as Record<string, unknown>);
}

registerColdStartWakeups({
  onInstalled: chrome.runtime.onInstalled,
  onStartup: chrome.runtime.onStartup,
}, ensureColdStartReconciled);

// The action opens the wizard in a full tab rather than a popup: the plan and
// evidence views need the room, and a popup closes on focus loss, which would
// interrupt an operator mid-approval.
chrome.action.onClicked.addListener(() => {
  void chrome.tabs.create({ url: chrome.runtime.getURL("src/ui/index.html") });
});
