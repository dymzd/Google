/**
 * Cold start: the setup phase must work before a deployer exists.
 *
 * This check exists because its absence hid a second real failure, of the same
 * shape as the first. Endpoint coverage proved every route was reachable;
 * nothing proved the routes could actually run in the state a new operator is
 * in. The impersonation chain assumed the deployer service account already
 * existed, but bootstrap is what creates it — so bootstrap could never run,
 * and the two calls before it failed on a credential that could not yet be
 * minted.
 *
 * The pattern is worth naming: parity checks compare a working system against
 * a reference. They say nothing about reaching the working state.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-coldstart.ts
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  reconcileAfterConsent,
  registerColdStartWakeups,
} from "../src/background/cold-start.ts";

const here = dirname(fileURLToPath(import.meta.url));
const read = (relative: string): string =>
  readFileSync(resolve(here, relative), "utf8");

const worker = read("../src/background/service-worker.ts");
const authentication = read("../src/auth/tokens.ts");
const repository = read("../src/storage/repository.ts");
const coldStart = read("../src/background/cold-start.ts");
const finalizeBody = worker.slice(
  worker.indexOf("async function finalizeRun"),
  worker.indexOf("async function scheduleRollbackAfterFatalError"),
);
const manifest = JSON.parse(read("../manifest.json")) as { permissions: string[] };

const failures: string[] = [];
let passed = 0;

function check(name: string, condition: boolean, detail = ""): void {
  if (condition) passed += 1;
  else failures.push(`${name}${detail ? `\n      ${detail}` : ""}`);
}

check(
  "manifest uses one identity permission and attests the token through OIDC UserInfo",
  manifest.permissions.includes("identity") &&
    !manifest.permissions.includes("identity.email") &&
    /getAuthToken\(false\)/.test(authentication) &&
    /openidconnect\.googleapis\.com\/v1\/userinfo/.test(authentication) &&
    !/getProfileUserInfo/.test(worker),
  `permissions: ${manifest.permissions.join(", ")}`,
);

// Only the explicitly read-only discovery transport may fall back to the
// administrator. The mutation transport must fail until bootstrap succeeds.
check(
  "read-only discovery works before bootstrap without weakening mutations",
  /makeTransport\(discoveryAccessToken/.test(worker) &&
    /makeTransport\(deployerAccessToken/.test(worker) &&
    /A project-bound impersonated deployer is required/.test(worker),
  "only discoveryAccessToken may use the administrator before bootstrap",
);

check(
  "no code path demands a deployer before bootstrap",
  !/requireCredentials\(\)/.test(worker),
  "requireCredentials() throws until a deployer is stored, which bootstrap creates",
);

check(
  "cold-start execution pauses legacy lifecycle rows before constructing an executor",
  /currentLifecycleSchema/.test(worker) &&
    /legacy-lifecycle-adoption-required/.test(worker) &&
    worker.indexOf("if (!currentLifecycleSchema)") <
      worker.indexOf("const spec = await specForRun(initial)"),
  "legacy rows must enter the explicit identity-bound adoption path before provider I/O",
);

// The audit actor has to resolve to something in both states.
check(
  "the audit actor resolves before bootstrap",
  /if \(typeof email === "string" && email !== ""\) return email;/.test(worker) &&
    /operatorEmail\(\)/.test(worker),
  "resolveDeployerEmail() should fall back to the signed-in administrator",
);

check(
  "sign-in does not require a deployer",
  /case "signIn"[\s\S]{0,1400}?chromeIdentity\.getAuthToken\(true\)/.test(worker),
  "signIn should establish an administrator session when no deployer is stored",
);

// Once bootstrap has run, impersonation must actually take effect; otherwise
// every later mutation keeps the administrator's broader authority.
check(
  "bootstrap switches the session to the deployer",
  /rememberDeployer[\s\S]{0,1200}?new DeployerCredentials\(/.test(worker) &&
    /deployerServiceAccountUniqueId: uniqueId/.test(worker),
  "rememberDeployer() should replace the credential with the new deployer",
);

// The private key is needed while an Apply is active, but must not be written
// to persistent extension storage. Public certificate material can remain for
// the operator-facing certificate endpoint; the key lives only for the Chrome
// session and is purged when the run ends.
check(
  "certificate private keys are never persisted in chrome.storage.local",
  /chrome\.storage\.session\.(?:get|set)/.test(worker) &&
    /publicCertificateBundle/.test(worker) &&
    !/chrome\.storage\.local\.set\(\{ \[key\]: bundle/.test(worker),
  "store only the redacted public bundle in local storage and key material in session storage",
);

check(
  "certificate crash markers are run-scoped",
  /chrome\.storage\.session\.get\(\[key, requestKey\]\)/.test(worker) &&
    /persistentGet\(\[key, intentKey\]\)/.test(worker) &&
    !/persisted\[key\] \|\| persisted\[nameKey\]/.test(worker),
  "a previous deployment's public certificate must not block a later run with the same name",
);

check(
  "enterprise CA certificate IDs are run-scoped for safe rotation",
  /const certificateId = enterpriseCertificateId\(spec\.name, runId\)/.test(worker),
  "a fixed deployment certificate ID makes the second rotation fail with ALREADY_EXISTS",
);

const requestCheckpoint = worker.indexOf(
  "await chrome.storage.session.set({ [requestKey]: request })",
);
const enterpriseMutation = worker.indexOf("bundle = await issueEnterpriseCa");
check(
  "enterprise CA key and CSR are checkpointed before issuance",
  requestCheckpoint >= 0 && enterpriseMutation > requestCheckpoint &&
    /certificate:intent:\$\{runId\}/.test(worker) &&
    /requestId,\s*request,/.test(worker),
  "persist the session-only key/CSR, public intent marker, and durable phase before the stable requestId POST",
);

check(
  "enterprise CA issuance belongs to its durable executor step",
  /case "privateca:certificate"/.test(read("../src/providers/executor.ts")) &&
    /issueEnterpriseCertificate: issueEnterpriseCertificateForRun/.test(worker) &&
    !/if \(spec\.certificate_strategy === "enterprise_ca"[^}]+issueEnterpriseCa/s.test(worker),
  "engine construction must not create a certificate outside plan ownership and rollback",
);

check(
  "sign-out refuses to erase resume state while Apply is active",
  /async function signOutSafely/.test(worker) &&
    /repository\.runs\(\)\)\.find\(runHasActiveWork\)/.test(worker) &&
    /active-run-signout-blocked/.test(worker) &&
    /active-teardown-signout-blocked/.test(worker) &&
    (worker.match(/signOutSafely\(\)/g)?.length ?? 0) >= 3,
  "both message routes must share the active-run guard before clearing storage",
);

check(
  "sign-out preserves completed-run teardown and certificate evidence",
  /persistentRemove\(\[\s*"deployerServiceAccount"/.test(worker) &&
    !/encryptedLocalClear/.test(worker),
  "remove the credential selector only; approved specs and public certificates are durable state",
);

check(
  "cold-start recovery is gated by durable 0.2.1 consent metadata",
  /userDataConsentStatus\(db\)/.test(worker) &&
    /if \(!\(await userDataConsentStatus\(db\)\)\.accepted\)/.test(worker) &&
    /CONSENT_API_PATHS/.test(worker),
  "migration/resume must not read a legacy product row before the disclosure is accepted",
);

// Exercise the browser lifecycle wiring. An extension update can replace the
// worker while Chrome itself remains open, so onStartup will not run. Model an
// active durable run whose alarm disappeared during the update and require the
// top-level onInstalled listener to recreate it without any page/message wake.
class FakeEvent<TArgs extends readonly unknown[]> {
  private readonly listeners: Array<(...args: TArgs) => void> = [];

  addListener(listener: (...args: TArgs) => void): void {
    this.listeners.push(listener);
  }

  emit(...args: TArgs): void {
    for (const listener of this.listeners) listener(...args);
  }
}

const installed = new FakeEvent<readonly [details: { reason: "update" }]>();
const startup = new FakeEvent<readonly []>();
const activeDurableRuns = ["run-after-update"];
const alarms = new Set<string>();
let consentAccepted = false;
let durableInspections = 0;
const pendingReconciliations: Promise<void>[] = [];
const reconcile = (): Promise<void> => {
  const work = reconcileAfterConsent({
    consentAccepted: async () => consentAccepted,
    inspectDurableState: async () => {
      durableInspections += 1;
      for (const runId of activeDurableRuns) alarms.add(`sgs-run:${runId}`);
    },
  }).then(() => undefined);
  pendingReconciliations.push(work);
  return work;
};
registerColdStartWakeups({ onInstalled: installed, onStartup: startup }, reconcile);

installed.emit({ reason: "update" });
await Promise.all(pendingReconciliations.splice(0));
check(
  "an update wake does not inspect durable product state before consent",
  durableInspections === 0 && alarms.size === 0,
  JSON.stringify({ durableInspections, alarms: [...alarms] }),
);

consentAccepted = true;
installed.emit({ reason: "update" });
await Promise.all(pendingReconciliations.splice(0));
check(
  "top-level onInstalled recreates the missing alarm for an active durable run",
  durableInspections === 1 && alarms.has("sgs-run:run-after-update"),
  JSON.stringify({ durableInspections, alarms: [...alarms] }),
);

alarms.clear();
startup.emit();
await Promise.all(pendingReconciliations.splice(0));
check(
  "onStartup shares the same idempotent durable-run reconciliation",
  durableInspections === 2 && alarms.has("sgs-run:run-after-update"),
  JSON.stringify({ durableInspections, alarms: [...alarms] }),
);

check(
  "the production worker registers both update and startup cold-start wakes",
  /registerColdStartWakeups\(\{[\s\S]{0,180}?onInstalled: chrome\.runtime\.onInstalled[\s\S]{0,120}?onStartup: chrome\.runtime\.onStartup/.test(worker) &&
    /if \(!\(await options\.consentAccepted\(\)\)\) return false/.test(coldStart),
  "onInstalled must be wired at module scope through the same consent-gated reconciler",
);

const retryInstalled = new FakeEvent<readonly [details: { reason: "update" }]>();
const retryStartup = new FakeEvent<readonly []>();
let retryAttempts = 0;
registerColdStartWakeups(
  { onInstalled: retryInstalled, onStartup: retryStartup },
  async () => {
    retryAttempts += 1;
    if (retryAttempts === 1) throw new Error("transient-alarm-create-failure");
  },
);
retryInstalled.emit({ reason: "update" });
await Promise.resolve();
await Promise.resolve();
retryStartup.emit();
await Promise.resolve();
await Promise.resolve();
check(
  "a rejected update reconciliation does not block a later lifecycle retry",
  retryAttempts === 2 &&
    /transient IndexedDB\/alarm failure[\s\S]{0,220}?coldStartReconciliation = null/.test(worker),
  String(retryAttempts),
);

check(
  "the raw Google transport rejects every unapproved non-2xx response",
  /options\.acceptedStatuses\?\.includes\(response\.status\)/.test(worker) &&
    /throw new GoogleApiError/.test(worker),
  "route, discovery, catalog, and executor calls must share one fail-closed HTTP boundary",
);

check(
  "run snapshots and operation audit evidence commit atomically",
  /db\.transaction\(\[STORE\.runs, STORE\.audit\], "readwrite"\)/.test(worker) &&
    /runAuditTransitions\(previous, record\)/.test(worker) &&
    /audit\.add\(event\)/.test(worker),
  "IndexedDbRunStore.save must append transition events in the same transaction as the run",
);

check(
  "immediate Apply and alarm resume cannot tick one run concurrently",
  /const executingRuns = new Set<string>\(\)/.test(worker) &&
    /if \(executingRuns\.has\(runId\)\) return false/.test(worker),
  "a long Google operation can overlap the first alarm and duplicate non-requestId mutations",
);

check(
  "approval consumption stores complete steps in its lifecycle transaction",
  /STORE\.approvals, STORE\.runs, STORE\.teardowns, STORE\.cepLeases, STORE\.audit/.test(repository) &&
    /initialRunRecord\(\{ approval: consumed, runId, startedAt: nowIso \}\)/.test(repository) &&
    !/await runStore\.save\(initialRun\)/.test(worker),
  "a committed running row must already contain every stable step requestId",
);

check(
  "cold start completes terminal ownership finalization before clearing alarms",
  /run\.finalizationPending === true/.test(worker) &&
    /finalizeRunInventory\(record, resources\)/.test(finalizeBody) &&
    finalizeBody.indexOf("finalizeRunInventory(record, resources)") <
      finalizeBody.indexOf("scheduler.cancel(record.runId)"),
  "unfinished finalization must be resumed from IndexedDB before alarm cancellation",
);

check(
  "cold start compensates only confirmed post-deploy IAM writes",
  /run\.policyUpdateCheckpoint !== undefined/.test(worker) &&
    /compensatePolicyUpdate\(run\.policyUpdateCheckpoint\)/.test(worker) &&
    /if \(!recovered\)/.test(worker) &&
    /abortRunPolicyUpdate/.test(worker),
  "response-loss checkpoints must remain durable instead of deleting a coincident admin grant",
);

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} cold-start checks\n`);
  for (const failure of failures) console.error(`  ${failure}`);
  console.error(
    "\n  A new operator starts with no deployer service account. Every step up to\n" +
      "  and including bootstrap has to work in that state.",
  );
  process.exit(1);
}
console.log(`OK ${passed} cold-start checks passed.`);
