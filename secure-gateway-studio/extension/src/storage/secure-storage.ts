/**
 * At-rest protection for extension-owned persistent state.
 *
 * Chrome gives an extension an origin-private IndexedDB namespace, but that is
 * access control rather than encryption.  Every value in the product stores is
 * therefore wrapped with AES-256-GCM before it reaches IndexedDB.  The only
 * clear fields are irreversible key/index digests, lifecycle status, and the
 * audit-chain head hash needed to preserve transactional ordering.
 *
 * The AES key is deliberately non-extractable. IndexedDB structured clone can
 * persist a CryptoKey without turning it into raw key bytes; a restarted MV3
 * worker receives another non-extractable CryptoKey object.
 */

import { canonicalDigestSync } from "../domain/canonical.ts";
import { sha256HexOfString } from "../domain/sha256.ts";
import { acceptanceAuditPayload, migrateLegacyAcceptanceRecord } from "./acceptance-integrity.ts";
import { buildAuditEvent, type AuditEventRecord } from "./audit.ts";

export const ENCRYPTION_SCHEMA = 1;
export const CONSENT_VERSION = "0.2.1";
export const METADATA_STORE = "secure_metadata";
export const KEY_STORE = "secure_crypto_keys";
export const LOCAL_STATE_STORE = "secure_local_state";

const DATA_KEY_NAME = "aes-gcm-data-v1";
const CONSENT_METADATA_KEY = "user-data-consent";
const LEGACY_SCHEMA_METADATA_KEY = "legacy-schema-version";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const PRIMARY_KEY_PATH: Readonly<Record<string, string>> = {
  deployment_drafts: "deploymentId",
  prepared_plans: "planId",
  approved_plans: "approvalId",
  deployment_runs: "runId",
  run_operations: "operationId",
  deployment_resources: "id",
  acceptance_results: "id",
  deployment_teardowns: "teardownId",
  cep_mutation_leases: "leaseKey",
  audit_events: "sequence",
};

const RUN_ID_INDEX_STORES = new Set([
  "run_operations",
  "deployment_resources",
  "acceptance_results",
]);

type ConsentPhase = "prepared" | "accepted";

interface ConsentMetadata {
  key: typeof CONSENT_METADATA_KEY;
  phase: ConsentPhase;
  version: typeof CONSENT_VERSION;
  acceptedAt: string;
}

interface KeyRecord {
  name: typeof DATA_KEY_NAME;
  key: CryptoKey;
}

interface EncryptedEnvelope extends Record<string, unknown> {
  __sgsEncrypted: true;
  cryptoSchema: typeof ENCRYPTION_SCHEMA;
  recordKey: string;
  iv: Uint8Array<ArrayBuffer>;
  ciphertext: ArrayBuffer;
}

interface EncryptedLocalRecord extends EncryptedEnvelope {
  keyDigest: string;
}

export interface UserDataConsentStatus {
  accepted: boolean;
  migrationPrepared: boolean;
  version: string | null;
}

export class SecureStorageError extends Error {
  readonly code: string;

  constructor(code: string, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "SecureStorageError";
    this.code = code;
  }
}

const cachedKeys = new WeakMap<IDBDatabase, CryptoKey>();

function isValidDataKey(value: unknown): value is CryptoKey {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<CryptoKey>;
  const algorithm = candidate.algorithm as Partial<AesKeyAlgorithm> | undefined;
  return candidate.type === "secret" &&
    candidate.extractable === false &&
    algorithm?.name === "AES-GCM" &&
    algorithm.length === 256 &&
    Array.isArray(candidate.usages) &&
    candidate.usages.includes("encrypt") &&
    candidate.usages.includes("decrypt");
}

function idbRequest<T>(source: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    source.onsuccess = () => resolve(source.result);
    source.onerror = () => reject(source.error);
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.addEventListener("complete", () => resolve(), { once: true });
    transaction.addEventListener(
      "error",
      () => reject(transaction.error ?? new Error("IndexedDB transaction failed")),
      { once: true },
    );
    transaction.addEventListener(
      "abort",
      () => reject(transaction.error ?? new Error("IndexedDB transaction aborted")),
      { once: true },
    );
  });
}

/**
 * Resolve a non-IDB promise from an IDB request callback.
 *
 * Transactions are active only while an IndexedDB callback task is running.
 * WebCrypto completes in another task, so a small chain of harmless reads
 * keeps the transaction pending and hands the result back from the next IDB
 * callback. This preserves the all-or-nothing migration/write boundary.
 */
function waitForActiveTransaction<T>(
  transaction: IDBTransaction,
  operation: Promise<T>,
): Promise<T> {
  let settled = false;
  let result: T | undefined;
  let failure: unknown;
  operation.then(
    (value) => {
      result = value;
      settled = true;
    },
    (error: unknown) => {
      failure = error;
      settled = true;
    },
  );

  const store = transaction.objectStore(transaction.objectStoreNames[0]);
  return new Promise<T>((resolve, reject) => {
    const poll = () => {
      let keepAlive: IDBRequest<unknown>;
      try {
        keepAlive = store.get("__sgs_transaction_keepalive__");
      } catch (error) {
        reject(error);
        return;
      }
      const next = () => {
        if (!settled) {
          poll();
          return;
        }
        if (failure !== undefined) {
          try {
            transaction.abort();
          } catch {
            // It may already have been aborted by an IndexedDB request error.
          }
          reject(failure);
        } else resolve(result as T);
      };
      keepAlive.onsuccess = next;
      keepAlive.onerror = next;
    };
    poll();
  });
}

function isEnvelope(value: unknown): value is EncryptedEnvelope {
  if (typeof value !== "object" || value === null) return false;
  const envelope = value as Partial<EncryptedEnvelope>;
  return envelope.__sgsEncrypted === true &&
    envelope.cryptoSchema === ENCRYPTION_SCHEMA &&
    typeof envelope.recordKey === "string" &&
    envelope.recordKey.length === 64 &&
    envelope.iv instanceof Uint8Array &&
    envelope.iv.byteLength === 12 &&
    envelope.ciphertext instanceof ArrayBuffer;
}

function keyPath(storeName: string): string {
  const value = PRIMARY_KEY_PATH[storeName];
  if (value === undefined) {
    throw new SecureStorageError("unknown-store", `No encryption schema for ${storeName}`);
  }
  return value;
}

function logicalPrimaryKey(storeName: string, record: Record<string, unknown>): IDBValidKey {
  const value = record[keyPath(storeName)];
  if (storeName === "audit_events" && value === undefined) {
    const eventId = record.eventId;
    if (typeof eventId !== "string" || eventId === "") {
      throw new SecureStorageError("record-key-invalid", "Audit eventId is missing");
    }
    return eventId;
  }
  if (typeof value !== "string" && typeof value !== "number") {
    throw new SecureStorageError(
      "record-key-invalid",
      `The ${storeName} primary key is missing or unsupported`,
    );
  }
  return value;
}

function digestKey(namespace: string, value: IDBValidKey): string {
  return sha256HexOfString(`${namespace}\u0000${String(value)}`);
}

function physicalPrimaryKey(storeName: string, logical: IDBValidKey): IDBValidKey {
  if (storeName === "audit_events" && typeof logical === "number") return logical;
  return digestKey(`primary:${storeName}`, logical);
}

function recordKeyDigest(storeName: string, record: Record<string, unknown>): string {
  if (storeName === "audit_events") {
    const eventId = record.eventId;
    if (typeof eventId !== "string" || eventId === "") {
      throw new SecureStorageError("record-key-invalid", "Audit eventId is missing");
    }
    return digestKey("record:audit_events", eventId);
  }
  return digestKey(`record:${storeName}`, logicalPrimaryKey(storeName, record));
}

function associatedData(storeName: string, recordKey: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(textEncoder.encode(
    JSON.stringify({ schema: ENCRYPTION_SCHEMA, store: storeName, recordKey }),
  ));
}

function serialise(value: unknown): Uint8Array<ArrayBuffer> {
  const json = JSON.stringify(value);
  if (json === undefined) {
    throw new SecureStorageError("record-serialization-failed", "Persistent value is not JSON data");
  }
  return new Uint8Array(textEncoder.encode(json));
}

function parsePlaintext(bytes: ArrayBuffer): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(textDecoder.decode(bytes)) as unknown;
  } catch (error) {
    throw new SecureStorageError("ciphertext-invalid", "Encrypted state is not valid JSON", error);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new SecureStorageError("ciphertext-invalid", "Encrypted state is not an object");
  }
  return parsed as Record<string, unknown>;
}

function clearMetadata(
  storeName: string,
  record: Record<string, unknown>,
  recordKey: string,
): Record<string, unknown> {
  const metadata: Record<string, unknown> = {};
  const path = keyPath(storeName);
  const logical = logicalPrimaryKey(storeName, record);
  if (storeName === "audit_events") {
    if (typeof record.sequence === "number") metadata.sequence = record.sequence;
    if (typeof record.eventHash === "string") metadata.eventHash = record.eventHash;
  } else {
    metadata[path] = physicalPrimaryKey(storeName, logical);
  }
  if (storeName === "deployment_runs" && typeof record.status === "string") {
    metadata.status = record.status;
  }
  if (RUN_ID_INDEX_STORES.has(storeName) && typeof record.runId === "string") {
    metadata.runId = digestKey("index:runId", record.runId);
  }
  metadata.recordKey = recordKey;
  return metadata;
}

async function encryptRecord(
  key: CryptoKey,
  storeName: string,
  record: Record<string, unknown>,
): Promise<EncryptedEnvelope> {
  const recordKey = recordKeyDigest(storeName, record);
  const iv = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(12)));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: associatedData(storeName, recordKey),
      tagLength: 128,
    },
    key,
    serialise(record),
  );
  return {
    ...clearMetadata(storeName, record, recordKey),
    __sgsEncrypted: true,
    cryptoSchema: ENCRYPTION_SCHEMA,
    recordKey,
    iv,
    ciphertext,
  } as EncryptedEnvelope;
}

async function decryptRecord(
  key: CryptoKey,
  storeName: string,
  envelope: EncryptedEnvelope,
): Promise<Record<string, unknown>> {
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: envelope.iv,
        additionalData: associatedData(storeName, envelope.recordKey),
        tagLength: 128,
      },
      key,
      envelope.ciphertext,
    );
  } catch (error) {
    throw new SecureStorageError(
      "ciphertext-authentication-failed",
      `Encrypted ${storeName} state failed AES-GCM authentication`,
      error,
    );
  }
  const record = parsePlaintext(plaintext);
  if (recordKeyDigest(storeName, record) !== envelope.recordKey) {
    throw new SecureStorageError(
      "record-binding-mismatch",
      `Encrypted ${storeName} state is bound to a different record key`,
    );
  }
  const path = keyPath(storeName);
  if (storeName === "audit_events") {
    if (
      typeof envelope.sequence !== "number" ||
      !Number.isSafeInteger(envelope.sequence) ||
      envelope.sequence < 1 ||
      record.sequence !== envelope.sequence
    ) {
      throw new SecureStorageError("record-binding-mismatch", "Audit sequence changed");
    }
    if (typeof envelope.eventHash !== "string" || record.eventHash !== envelope.eventHash) {
      throw new SecureStorageError("record-binding-mismatch", "Audit chain head metadata changed");
    }
    return record;
  }
  if (envelope[path] !== physicalPrimaryKey(storeName, logicalPrimaryKey(storeName, record))) {
    throw new SecureStorageError("record-binding-mismatch", `${storeName} primary key changed`);
  }
  if (
    storeName === "deployment_runs" &&
    typeof record.status === "string" &&
    envelope.status !== record.status
  ) {
    throw new SecureStorageError("record-binding-mismatch", "Run status metadata changed");
  }
  if (
    RUN_ID_INDEX_STORES.has(storeName) &&
    typeof record.runId === "string" &&
    envelope.runId !== digestKey("index:runId", record.runId)
  ) {
    throw new SecureStorageError("record-binding-mismatch", `${storeName} run index changed`);
  }
  return record;
}

function requireCachedKey(database: IDBDatabase): CryptoKey {
  const key = cachedKeys.get(database);
  if (key === undefined) {
    throw new SecureStorageError(
      "consent-required",
      "Persistent extension state is unavailable until the 0.2.1 data disclosure is accepted",
    );
  }
  if (!isValidDataKey(key)) {
    throw new SecureStorageError("key-invalid", "The persisted encryption key is invalid");
  }
  return key;
}

export function ensureSecureSchema(
  database: IDBDatabase,
  transaction: IDBTransaction,
  oldVersion: number,
): void {
  if (!database.objectStoreNames.contains(METADATA_STORE)) {
    database.createObjectStore(METADATA_STORE, { keyPath: "key" });
  }
  if (!database.objectStoreNames.contains(KEY_STORE)) {
    database.createObjectStore(KEY_STORE, { keyPath: "name" });
  }
  if (!database.objectStoreNames.contains(LOCAL_STATE_STORE)) {
    database.createObjectStore(LOCAL_STATE_STORE, { keyPath: "keyDigest" });
  }
  // This write records only a schema number. It deliberately does not open or
  // iterate any old product store during onupgradeneeded.
  transaction.objectStore(METADATA_STORE).put({
    key: LEGACY_SCHEMA_METADATA_KEY,
    version: oldVersion,
  });
}

export async function activateAcceptedEncryption(database: IDBDatabase): Promise<void> {
  if (
    !database.objectStoreNames.contains(METADATA_STORE) ||
    !database.objectStoreNames.contains(KEY_STORE)
  ) return;
  const transaction = database.transaction([METADATA_STORE, KEY_STORE], "readonly");
  const done = transactionDone(transaction);
  const consent = await idbRequest(
    transaction.objectStore(METADATA_STORE).get(CONSENT_METADATA_KEY),
  ) as ConsentMetadata | undefined;
  if (consent?.phase !== "accepted" || consent.version !== CONSENT_VERSION) {
    await done;
    return;
  }
  const keyRecord = await idbRequest(
    transaction.objectStore(KEY_STORE).get(DATA_KEY_NAME),
  ) as KeyRecord | undefined;
  await done;
  if (!isValidDataKey(keyRecord?.key)) {
    throw new SecureStorageError("key-missing", "Accepted encrypted state has no valid data key");
  }
  cachedKeys.set(database, keyRecord.key);
}

export async function userDataConsentStatus(
  database: IDBDatabase,
): Promise<UserDataConsentStatus> {
  const transaction = database.transaction([METADATA_STORE], "readonly");
  const done = transactionDone(transaction);
  const consent = await idbRequest(
    transaction.objectStore(METADATA_STORE).get(CONSENT_METADATA_KEY),
  ) as ConsentMetadata | undefined;
  await done;
  return {
    accepted: consent?.phase === "accepted" && consent.version === CONSENT_VERSION,
    migrationPrepared: consent?.phase === "prepared" && consent.version === CONSENT_VERSION,
    version: consent?.version ?? null,
  };
}

function prepareLegacyAcceptanceMigration(
  records: Map<string, Record<string, unknown>[]>,
  legacyVersion: number,
): void {
  if (legacyVersion === 0 || legacyVersion >= 3) return;
  const rows = records.get("acceptance_results") ?? [];
  const events = records.get("audit_events") ?? [];
  let previousHash = events.length === 0
    ? null
    : String((events.at(-1) as Record<string, unknown>).eventHash ?? "") || null;
  let nextSequence = events.reduce(
    (highest, event) => Math.max(highest, Number(event.sequence ?? 0)),
    0,
  ) + 1;
  const migratedRows: Record<string, unknown>[] = [];
  for (const row of rows) {
    const migrated = migrateLegacyAcceptanceRecord(row);
    migratedRows.push(migrated);
    const createdAt = new Date().toISOString();
    const event = buildAuditEvent({
      eventId: crypto.randomUUID(),
      deploymentId: String(migrated.runId ?? "") || null,
      eventType: "acceptance.integrity_migrated",
      actor: "system:migration",
      payload: acceptanceAuditPayload(migrated),
      createdAt,
      previousHash,
    }) as AuditEventRecord & { sequence?: number };
    event.sequence = nextSequence;
    nextSequence += 1;
    events.push(event as unknown as Record<string, unknown>);
    previousHash = event.eventHash;
  }
  records.set("acceptance_results", migratedRows);
  records.set("audit_events", events);
}

function rawRecordPrimaryKey(storeName: string, record: Record<string, unknown>): IDBValidKey {
  const value = record[keyPath(storeName)];
  if (typeof value !== "string" && typeof value !== "number") {
    throw new SecureStorageError("legacy-record-key-invalid", `Legacy ${storeName} key is invalid`);
  }
  return value;
}

async function encryptLocalValue(
  key: CryptoKey,
  logicalKey: string,
  value: unknown,
): Promise<EncryptedLocalRecord> {
  const keyDigest = digestKey("local-state", logicalKey);
  const iv = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(12)));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: associatedData(LOCAL_STATE_STORE, keyDigest),
      tagLength: 128,
    },
    key,
    serialise({ logicalKey, value }),
  );
  return {
    keyDigest,
    __sgsEncrypted: true,
    cryptoSchema: ENCRYPTION_SCHEMA,
    recordKey: keyDigest,
    iv,
    ciphertext,
  };
}

async function decryptLocalValue(
  key: CryptoKey,
  logicalKey: string,
  record: EncryptedLocalRecord,
): Promise<unknown> {
  const expected = digestKey("local-state", logicalKey);
  if (record.keyDigest !== expected || record.recordKey !== expected) {
    throw new SecureStorageError("record-binding-mismatch", "Encrypted local-state key changed");
  }
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: record.iv,
        additionalData: associatedData(LOCAL_STATE_STORE, expected),
        tagLength: 128,
      },
      key,
      record.ciphertext,
    );
  } catch (error) {
    throw new SecureStorageError(
      "ciphertext-authentication-failed",
      "Encrypted local state failed AES-GCM authentication",
      error,
    );
  }
  const payload = parsePlaintext(plaintext);
  if (payload.logicalKey !== logicalKey) {
    throw new SecureStorageError("record-binding-mismatch", "Encrypted local-state AAD changed");
  }
  return structuredClone(payload.value);
}

/**
 * Encrypt every legacy row only after the affirmative disclosure click.
 *
 * The transaction leaves consent at `prepared`. Callers must erase the two
 * legacy cleartext surfaces (chrome.storage.local and window.localStorage)
 * before finalising consent and allowing cold-start reconciliation.
 */
export async function prepareUserDataConsentMigration(options: {
  database: IDBDatabase;
  sensitiveStores: readonly string[];
  legacyLocalState?: Record<string, unknown>;
  legacyClientState?: Record<string, unknown>;
  now?: Date;
}): Promise<void> {
  const stores = [
    METADATA_STORE,
    KEY_STORE,
    LOCAL_STATE_STORE,
    ...options.sensitiveStores,
  ];
  const transaction = options.database.transaction(stores, "readwrite");
  const done = transactionDone(transaction);
  const metadata = transaction.objectStore(METADATA_STORE);
  const keyStore = transaction.objectStore(KEY_STORE);
  const currentConsent = await idbRequest(
    metadata.get(CONSENT_METADATA_KEY),
  ) as ConsentMetadata | undefined;
  if (currentConsent?.phase === "accepted" && currentConsent.version === CONSENT_VERSION) {
    await done;
    return;
  }
  let keyRecord = await idbRequest(keyStore.get(DATA_KEY_NAME)) as KeyRecord | undefined;
  if (keyRecord === undefined) {
    const generated = await waitForActiveTransaction(
      transaction,
      crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      ),
    ) as CryptoKey;
    keyRecord = { name: DATA_KEY_NAME, key: generated };
    await idbRequest(keyStore.add(keyRecord));
  }
  if (!isValidDataKey(keyRecord.key)) {
    transaction.abort();
    throw new SecureStorageError("key-invalid", "The persisted encryption key is invalid");
  }

  const legacySchema = await idbRequest(metadata.get(LEGACY_SCHEMA_METADATA_KEY)) as
    | { version?: unknown }
    | undefined;
  const legacyVersion = Number(legacySchema?.version ?? 0);
  const records = new Map<string, Record<string, unknown>[]>();
  for (const storeName of options.sensitiveStores) {
    const rows = await idbRequest(
      transaction.objectStore(storeName).getAll(),
    ) as Record<string, unknown>[];
    records.set(storeName, rows);
  }

  if (currentConsent?.phase !== "prepared" && currentConsent?.phase !== "accepted") {
    prepareLegacyAcceptanceMigration(records, legacyVersion);
  }

  const encryptedByStore = await waitForActiveTransaction(
    transaction,
    Promise.all(options.sensitiveStores.map(async (storeName) => {
      const encrypted: Array<{
        oldKey: IDBValidKey;
        envelope: EncryptedEnvelope;
      }> = [];
      for (const row of records.get(storeName) ?? []) {
        if (isEnvelope(row)) {
          // A prepared migration may be resumed. Authenticate every prior row
          // before accepting it; a missing/wrong key or tamper fails closed.
          await decryptRecord(keyRecord!.key, storeName, row);
          continue;
        }
        encrypted.push({
          oldKey: rawRecordPrimaryKey(storeName, row),
          envelope: await encryptRecord(keyRecord!.key, storeName, row),
        });
      }
      return { storeName, encrypted };
    })),
  );

  for (const { storeName, encrypted } of encryptedByStore) {
    const store = transaction.objectStore(storeName);
    for (const item of encrypted) {
      const newKey = item.envelope[keyPath(storeName)] as IDBValidKey | undefined;
      if (storeName !== "audit_events" && newKey !== item.oldKey) {
        await idbRequest(store.delete(item.oldKey));
      }
      await idbRequest(store.put(item.envelope));
    }
  }

  const localEntries = currentConsent?.phase === "prepared"
    ? {}
    : {
        ...(options.legacyLocalState ?? {}),
        ...(options.legacyClientState ?? {}),
      };
  const encryptedLocal = await waitForActiveTransaction(
    transaction,
    Promise.all(Object.entries(localEntries).map(async ([logicalKey, value]) =>
      encryptLocalValue(keyRecord!.key, logicalKey, value))),
  );
  const localStore = transaction.objectStore(LOCAL_STATE_STORE);
  for (const entry of encryptedLocal) await idbRequest(localStore.put(entry));

  await idbRequest(metadata.put({
    key: CONSENT_METADATA_KEY,
    phase: "prepared",
    version: CONSENT_VERSION,
    acceptedAt: currentConsent?.acceptedAt ?? (options.now ?? new Date()).toISOString(),
  } satisfies ConsentMetadata));
  await done;
}

export async function finalizeUserDataConsent(database: IDBDatabase): Promise<void> {
  const transaction = database.transaction([METADATA_STORE, KEY_STORE], "readwrite");
  const done = transactionDone(transaction);
  const metadata = transaction.objectStore(METADATA_STORE);
  const current = await idbRequest(metadata.get(CONSENT_METADATA_KEY)) as
    | ConsentMetadata
    | undefined;
  const prepared = current?.phase === "prepared" && current.version === CONSENT_VERSION;
  const alreadyAccepted = current?.phase === "accepted" && current.version === CONSENT_VERSION;
  if (!prepared && !alreadyAccepted) {
    transaction.abort();
    await done.catch(() => undefined);
    throw new SecureStorageError(
      "consent-migration-not-prepared",
      "Encrypted migration must finish before consent can be finalised",
    );
  }
  const keyRecord = await idbRequest(
    transaction.objectStore(KEY_STORE).get(DATA_KEY_NAME),
  ) as KeyRecord | undefined;
  if (!isValidDataKey(keyRecord?.key)) {
    transaction.abort();
    await done.catch(() => undefined);
    throw new SecureStorageError("key-missing", "The migration encryption key is missing");
  }
  if (prepared) {
    await idbRequest(metadata.put({ ...current, phase: "accepted" } satisfies ConsentMetadata));
  }
  await done;
  cachedKeys.set(database, keyRecord.key);
}

function transformRunIndexQuery(query?: IDBValidKey | IDBKeyRange | null): IDBValidKey | IDBKeyRange | null | undefined {
  if (query === undefined || query === null) return query;
  if (typeof query === "string") return digestKey("index:runId", query);
  if (
    typeof IDBKeyRange !== "undefined" &&
    query instanceof IDBKeyRange &&
    query.lower === query.upper &&
    !query.lowerOpen &&
    !query.upperOpen &&
    typeof query.lower === "string"
  ) {
    return IDBKeyRange.only(digestKey("index:runId", query.lower));
  }
  throw new SecureStorageError("index-query-invalid", "Only exact runId index queries are allowed");
}

export interface SecureIndex {
  get(query: IDBValidKey | IDBKeyRange): Promise<unknown>;
  getAll(query?: IDBValidKey | IDBKeyRange | null, count?: number): Promise<unknown[]>;
}

export interface SecureObjectStore {
  get(query: IDBValidKey | IDBKeyRange): Promise<unknown>;
  getAll(query?: IDBValidKey | IDBKeyRange | null, count?: number): Promise<unknown[]>;
  put(value: unknown): Promise<IDBValidKey>;
  add(value: unknown): Promise<IDBValidKey>;
  delete(query: IDBValidKey | IDBKeyRange): Promise<undefined>;
  index(name: string): SecureIndex;
  openCursor(query?: IDBValidKey | IDBKeyRange | null, direction?: IDBCursorDirection): Promise<IDBCursorWithValue | null>;
}

function assertRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SecureStorageError("record-invalid", "Persistent store values must be objects");
  }
  return value as Record<string, unknown>;
}

async function decryptRaw(
  transaction: IDBTransaction,
  storeName: string,
  raw: unknown,
): Promise<Record<string, unknown> | undefined> {
  if (raw === undefined) return undefined;
  if (!isEnvelope(raw)) {
    throw new SecureStorageError(
      "plaintext-record-after-migration",
      `Unencrypted ${storeName} state was found after consent`,
    );
  }
  return waitForActiveTransaction(
    transaction,
    decryptRecord(requireCachedKey(transaction.db), storeName, raw),
  );
}

/** A narrow async facade over an encrypted object store. */
export function secureObjectStore(
  transaction: IDBTransaction,
  storeName: string,
): SecureObjectStore {
  const native = transaction.objectStore(storeName);
  const key = requireCachedKey(transaction.db);
  const primaryQuery = (query: IDBValidKey | IDBKeyRange): IDBValidKey | IDBKeyRange => {
    if (storeName === "audit_events" || (typeof IDBKeyRange !== "undefined" && query instanceof IDBKeyRange)) {
      return query;
    }
    return physicalPrimaryKey(storeName, query as IDBValidKey);
  };
  const decryptMany = async (raw: unknown[]): Promise<Record<string, unknown>[]> =>
    waitForActiveTransaction(
      transaction,
      Promise.all(raw.map(async (value) => {
        if (!isEnvelope(value)) {
          throw new SecureStorageError(
            "plaintext-record-after-migration",
            `Unencrypted ${storeName} state was found after consent`,
          );
        }
        return decryptRecord(key, storeName, value);
      })),
    );

  return {
    async get(query) {
      const raw = await idbRequest(native.get(primaryQuery(query)));
      return decryptRaw(transaction, storeName, raw);
    },
    async getAll(query, count) {
      const raw = await idbRequest(native.getAll(query ?? undefined, count)) as unknown[];
      return decryptMany(raw);
    },
    async put(value) {
      const envelope = await waitForActiveTransaction(
        transaction,
        encryptRecord(key, storeName, assertRecord(value)),
      );
      return idbRequest(native.put(envelope));
    },
    async add(value) {
      let record = assertRecord(value);
      let envelope = await waitForActiveTransaction(
        transaction,
        encryptRecord(key, storeName, record),
      );
      const generatedKey = await idbRequest(native.add(envelope));
      if (storeName === "audit_events" && record.sequence === undefined) {
        if (
          typeof generatedKey !== "number" ||
          !Number.isSafeInteger(generatedKey) ||
          generatedKey < 1
        ) {
          transaction.abort();
          throw new SecureStorageError(
            "record-key-invalid",
            "IndexedDB did not generate a valid audit sequence",
          );
        }
        // Auto-increment chooses the insertion sequence. Re-encrypt inside the
        // same uncommitted transaction so that sequence is authenticated too.
        record = { ...record, sequence: generatedKey };
        envelope = await waitForActiveTransaction(
          transaction,
          encryptRecord(key, storeName, record),
        );
        await idbRequest(native.put(envelope));
      }
      return generatedKey;
    },
    async delete(query) {
      await idbRequest(native.delete(primaryQuery(query)));
      return undefined;
    },
    index(name) {
      const index = native.index(name);
      const transform: (
        value?: IDBValidKey | IDBKeyRange | null,
      ) => IDBValidKey | IDBKeyRange | null | undefined =
        name === "runId" ? transformRunIndexQuery : (value) => value;
      return {
        async get(query) {
          const raw = await idbRequest(index.get(transform(query) as IDBValidKey | IDBKeyRange));
          return decryptRaw(transaction, storeName, raw);
        },
        async getAll(query, count) {
          const raw = await idbRequest(
            index.getAll(transform(query) as IDBValidKey | IDBKeyRange | undefined, count),
          ) as unknown[];
          return decryptMany(raw);
        },
      };
    },
    async openCursor(query, direction) {
      const cursor = await idbRequest(native.openCursor(query, direction));
      if (cursor === null) return null;
      const value = await decryptRaw(transaction, storeName, cursor.value);
      return { value } as IDBCursorWithValue;
    },
  };
}

export async function encryptedLocalGet<T = unknown>(
  database: IDBDatabase,
  logicalKey: string,
): Promise<T | undefined> {
  const key = requireCachedKey(database);
  const transaction = database.transaction([LOCAL_STATE_STORE], "readonly");
  const done = transactionDone(transaction);
  const raw = await idbRequest(
    transaction.objectStore(LOCAL_STATE_STORE).get(digestKey("local-state", logicalKey)),
  );
  if (raw === undefined) {
    await done;
    return undefined;
  }
  if (!isEnvelope(raw)) {
    throw new SecureStorageError("plaintext-record-after-migration", "Local state is not encrypted");
  }
  const value = await waitForActiveTransaction(
    transaction,
    decryptLocalValue(key, logicalKey, raw as EncryptedLocalRecord),
  );
  await done;
  return value as T;
}

export async function encryptedLocalGetMany(
  database: IDBDatabase,
  logicalKeys: readonly string[],
): Promise<Record<string, unknown>> {
  const entries = await Promise.all(
    logicalKeys.map(async (logicalKey) => [logicalKey, await encryptedLocalGet(database, logicalKey)] as const),
  );
  return Object.fromEntries(entries.filter(([, value]) => value !== undefined));
}

export async function encryptedLocalSet(
  database: IDBDatabase,
  entries: Record<string, unknown>,
): Promise<void> {
  const key = requireCachedKey(database);
  const transaction = database.transaction([LOCAL_STATE_STORE], "readwrite");
  const done = transactionDone(transaction);
  const encrypted = await waitForActiveTransaction(
    transaction,
    Promise.all(Object.entries(entries).map(([logicalKey, value]) =>
      encryptLocalValue(key, logicalKey, value))),
  );
  const store = transaction.objectStore(LOCAL_STATE_STORE);
  for (const record of encrypted) await idbRequest(store.put(record));
  await done;
}

export async function encryptedLocalRemove(
  database: IDBDatabase,
  logicalKeys: string | readonly string[],
): Promise<void> {
  requireCachedKey(database);
  const keys = typeof logicalKeys === "string" ? [logicalKeys] : logicalKeys;
  const transaction = database.transaction([LOCAL_STATE_STORE], "readwrite");
  const done = transactionDone(transaction);
  const store = transaction.objectStore(LOCAL_STATE_STORE);
  for (const logicalKey of keys) {
    await idbRequest(store.delete(digestKey("local-state", logicalKey)));
  }
  await done;
}

/** Test/reload hook: the next open must reload the structured-cloned key. */
export function forgetCachedEncryptionKey(database: IDBDatabase): void {
  cachedKeys.delete(database);
}

export function encryptedRecordDigest(value: unknown): string {
  return canonicalDigestSync(value);
}
