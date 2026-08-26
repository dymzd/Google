/** Consent-gated v3 -> v4 encryption migration and restart regression. */

import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";

import { acceptanceAuditPayload } from "../src/storage/acceptance-integrity.ts";
import { buildAuditEvent } from "../src/storage/audit.ts";
import {
  DATABASE_NAME,
  DATABASE_VERSION,
  openDatabase,
  StateRepository,
  STORE,
} from "../src/storage/repository.ts";
import {
  encryptedLocalGetMany,
  finalizeUserDataConsent,
  KEY_STORE,
  LOCAL_STATE_STORE,
  METADATA_STORE,
  prepareUserDataConsentMigration,
  SecureStorageError,
  userDataConsentStatus,
} from "../src/storage/secure-storage.ts";
import { legacyDeployerIdentityFromStoredState } from "../src/providers/bootstrap.ts";

function request<T>(source: IDBRequest<T>): Promise<T> {
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

function openLegacy(factory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const open = factory.open(DATABASE_NAME, 3);
    open.onupgradeneeded = () => {
      const db = open.result;
      db.createObjectStore(STORE.drafts, { keyPath: "deploymentId" });
      db.createObjectStore(STORE.plans, { keyPath: "planId" });
      db.createObjectStore(STORE.approvals, { keyPath: "approvalId" });
      const runs = db.createObjectStore(STORE.runs, { keyPath: "runId" });
      runs.createIndex("status", "status", { unique: false });
      const operations = db.createObjectStore(STORE.operations, { keyPath: "operationId" });
      operations.createIndex("runId", "runId", { unique: false });
      const resources = db.createObjectStore(STORE.resources, { keyPath: "id" });
      resources.createIndex("runId", "runId", { unique: false });
      const acceptance = db.createObjectStore(STORE.acceptance, { keyPath: "id" });
      acceptance.createIndex("runId", "runId", { unique: false });
      db.createObjectStore(STORE.teardowns, { keyPath: "teardownId" });
      db.createObjectStore(STORE.audit, { keyPath: "sequence", autoIncrement: true });
    };
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}

async function rawRows(database: IDBDatabase, storeName: string): Promise<unknown[]> {
  const transaction = database.transaction([storeName], "readonly");
  const completed = done(transaction);
  const rows = await request(transaction.objectStore(storeName).getAll());
  await completed;
  return rows;
}

async function rawPut(database: IDBDatabase, storeName: string, value: unknown): Promise<void> {
  const transaction = database.transaction([storeName], "readwrite");
  const completed = done(transaction);
  await request(transaction.objectStore(storeName).put(value));
  await completed;
}

function expectSecureFailure(error: unknown, code: string): boolean {
  return error instanceof SecureStorageError && error.code === code;
}

const factory = new IDBFactory();
const legacyRunId = "run-legacy-020";
const legacyRow = {
  id: "acceptance-legacy-020",
  resultId: "acceptance-legacy-020",
  runId: legacyRunId,
  testId: "T07",
  caseKey: "macos",
  status: "user_confirmed",
  source: "operator_confirmed",
  summary: "Managed browser reached gateway.enterprise.example.com",
  evidence: "Screenshot digest tenant-evidence-001",
  actor: "operator@enterprise.example.com",
  recordedAt: "2026-08-01T00:00:00Z",
};
const legacyEvent = buildAuditEvent({
  eventId: "legacy-acceptance-event",
  deploymentId: legacyRunId,
  eventType: "acceptance.recorded",
  actor: legacyRow.actor,
  payload: acceptanceAuditPayload(legacyRow),
  createdAt: legacyRow.recordedAt,
  previousHash: null,
});

const legacy = await openLegacy(factory);
const legacyProductStores = Object.values(STORE).filter((store) => store !== STORE.cepLeases);
const seed = legacy.transaction(legacyProductStores, "readwrite");
const seeded = done(seed);
await request(seed.objectStore(STORE.drafts).add({
  deploymentId: "draft-enterprise-secgw-01",
  administrator: "operator@enterprise.example.com",
  projectId: "enterprise-secgw-01",
}));
await request(seed.objectStore(STORE.plans).add({
  planId: "plan-legacy-020",
  configurationHash: "a".repeat(64),
  specificationJson: JSON.stringify({
    project_id: "enterprise-secgw-01",
    principals: [{ type: "group", value: "gateway-users@enterprise.example.com" }],
  }),
  preflightJson: JSON.stringify({ diagnostics: [{ detail: "tenant diagnostic payload" }] }),
  planJson: JSON.stringify({ changes: [{ resource_name: "gateway-enterprise-prod" }] }),
}));
await request(seed.objectStore(STORE.approvals).add({
  approvalId: "approval-legacy-020",
  approvedBy: "operator@enterprise.example.com",
  planJson: JSON.stringify({ resource_name: "gateway-enterprise-prod" }),
  specificationJson: JSON.stringify({ project_id: "enterprise-secgw-01" }),
}));
await request(seed.objectStore(STORE.runs).add({
  runId: legacyRunId,
  approvalId: "approval-legacy-020",
  configurationHash: "a".repeat(64),
  status: "running",
  state: "running",
  steps: [{ resourceName: "gateway-enterprise-prod" }],
}));
await request(seed.objectStore(STORE.operations).add({
  operationId: "operation-legacy-020",
  runId: legacyRunId,
  diagnostic: "tenant diagnostic payload",
}));
await request(seed.objectStore(STORE.resources).add({
  id: `${legacyRunId}:compute:instance:gateway-enterprise-prod`,
  runId: legacyRunId,
  resourceKey: "compute:instance:gateway-enterprise-prod",
  resourceName: "gateway-enterprise-prod",
  provider: "compute",
  resourceType: "instance",
  owned: true,
  shared: false,
}));
await request(seed.objectStore(STORE.teardowns).add({
  teardownId: "teardown-legacy-020",
  runId: legacyRunId,
  status: "pending",
  instructions: [{ resourceKey: "compute:instance:gateway-enterprise-prod" }],
}));
await request(seed.objectStore(STORE.acceptance).add(legacyRow));
await request(seed.objectStore(STORE.audit).add(legacyEvent));
await seeded;
legacy.close();

const upgraded = await openDatabase(factory);
if (upgraded.version !== DATABASE_VERSION) {
  throw new Error(`expected schema ${DATABASE_VERSION}, got ${upgraded.version}`);
}
if ((await userDataConsentStatus(upgraded)).accepted) {
  throw new Error("schema upgrade accepted disclosure without an affirmative action");
}
const beforeConsent = await rawRows(upgraded, STORE.acceptance);
if (JSON.stringify(beforeConsent) !== JSON.stringify([{ ...legacyRow }])) {
  throw new Error("v5 onupgradeneeded read or rewrote legacy sensitive rows before consent");
}
try {
  await new StateRepository(upgraded).allAcceptance();
  throw new Error("repository opened legacy cleartext before consent");
} catch (error) {
  if (!expectSecureFailure(error, "consent-required")) throw error;
}

await prepareUserDataConsentMigration({
  database: upgraded,
  sensitiveStores: Object.values(STORE),
  legacyLocalState: {
    deployerServiceAccount:
      "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
    accessPolicyId: "123456789",
  },
  legacyClientState: {
    "frontend:setup": {
      projectId: "enterprise-secgw-01",
      workspaceIdentity: "operator@enterprise.example.com",
    },
    "frontend:workflow": { runId: legacyRunId },
  },
});
const preparedStatus = await userDataConsentStatus(upgraded);
if (preparedStatus.accepted || !preparedStatus.migrationPrepared) {
  throw new Error("migration exposed encrypted rows before cleartext cleanup/finalize");
}
try {
  await new StateRepository(upgraded).allAcceptance();
  throw new Error("prepared-but-not-finalized state was readable");
} catch (error) {
  if (!expectSecureFailure(error, "consent-required")) throw error;
}

const forbidden = [
  "enterprise-secgw-01",
  "operator@enterprise.example.com",
  "gateway-users@enterprise.example.com",
  "gateway-enterprise-prod",
  "tenant diagnostic payload",
  "tenant-evidence-001",
];
for (const storeName of [...Object.values(STORE), LOCAL_STATE_STORE]) {
  const raw = await rawRows(upgraded, storeName);
  const rendered = JSON.stringify(raw);
  if (raw.some((row) => !(row as { __sgsEncrypted?: unknown }).__sgsEncrypted)) {
    throw new Error(`${storeName} contains a plaintext row after prepare`);
  }
  for (const cleartext of forbidden) {
    if (rendered.includes(cleartext)) {
      throw new Error(`${storeName} leaked cleartext ${cleartext}`);
    }
  }
}

await finalizeUserDataConsent(upgraded);
if (!(await userDataConsentStatus(upgraded)).accepted) {
  throw new Error("finalized consent was not durable");
}
// The first response may be lost after IndexedDB commits. Retrying the exact
// affirmative action must re-activate the persisted key and report success.
await finalizeUserDataConsent(upgraded);
if (!(await userDataConsentStatus(upgraded)).accepted) {
  throw new Error("consent finalization was not idempotent after response loss");
}
const repository = new StateRepository(upgraded);
const migratedLocalState = await encryptedLocalGetMany(upgraded, [
  "deployerServiceAccount",
  "deployerProjectId",
]);
const migratedLegacyDeployer = legacyDeployerIdentityFromStoredState(migratedLocalState);
if (
  migratedLegacyDeployer?.projectId !== "enterprise-secgw-01" ||
  migratedLegacyDeployer.serviceAccountEmail !==
    "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com"
) {
  throw new Error("the email-only 0.2.0 deployer identity was not recoverable after encryption migration");
}
const migratedRows = await repository.allAcceptance();
const migratedEvents = await repository.auditEvents();
if (
  migratedRows[0]?.actor !== legacyRow.actor ||
  migratedRows[0]?.evidence !== legacyRow.evidence ||
  migratedEvents[0]?.eventHash !== legacyEvent.eventHash ||
  migratedEvents[0]?.payloadJson !== legacyEvent.payloadJson
) {
  throw new Error("encryption migration rewrote audit or acceptance semantics");
}

const keyRows = await rawRows(upgraded, KEY_STORE) as Array<{ key?: CryptoKey }>;
const originalKey = keyRows[0]?.key;
if (
  originalKey === undefined ||
  originalKey.extractable ||
  originalKey.algorithm.name !== "AES-GCM" ||
  (originalKey.algorithm as AesKeyAlgorithm).length !== 256 ||
  !originalKey.usages.includes("encrypt") ||
  !originalKey.usages.includes("decrypt")
) {
  throw new Error("the durable AES-256-GCM CryptoKey is missing, extractable, or unusable");
}
try {
  await crypto.subtle.exportKey("raw", originalKey);
  throw new Error("the at-rest key could be exported");
} catch (error) {
  if (error instanceof Error && error.message === "the at-rest key could be exported") throw error;
}

upgraded.close();
const restarted = await openDatabase(factory);
if ((await new StateRepository(restarted).allAcceptance())[0]?.actor !== legacyRow.actor) {
  throw new Error("a restarted worker could not use the persisted non-extractable key");
}

const rawAcceptance = (await rawRows(restarted, STORE.acceptance))[0] as {
  ciphertext: ArrayBuffer;
};
const originalEnvelope = structuredClone(rawAcceptance);
const changed = structuredClone(rawAcceptance);
const bytes = new Uint8Array(changed.ciphertext);
bytes[0] ^= 0x80;
await rawPut(restarted, STORE.acceptance, changed);
try {
  await new StateRepository(restarted).allAcceptance();
  throw new Error("tampered ciphertext was accepted");
} catch (error) {
  if (!expectSecureFailure(error, "ciphertext-authentication-failed")) throw error;
}
await rawPut(restarted, STORE.acceptance, originalEnvelope);

const wrongKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"],
);
await rawPut(restarted, KEY_STORE, { name: "aes-gcm-data-v1", key: wrongKey });
restarted.close();
const wrongKeyRestart = await openDatabase(factory);
try {
  await new StateRepository(wrongKeyRestart).allAcceptance();
  throw new Error("ciphertext decrypted with a different persisted key");
} catch (error) {
  if (!expectSecureFailure(error, "ciphertext-authentication-failed")) throw error;
}
await rawPut(wrongKeyRestart, KEY_STORE, { name: "aes-gcm-data-v1", key: originalKey });

const metadataText = JSON.stringify(await rawRows(wrongKeyRestart, METADATA_STORE));
for (const cleartext of forbidden) {
  if (metadataText.includes(cleartext)) throw new Error(`metadata leaked ${cleartext}`);
}

console.log(
  "OK v3 state waits for consent, encrypts without semantic rewrites, survives restart, and fails closed on tamper/wrong key.",
);
