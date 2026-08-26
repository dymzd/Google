/**
 * Chrome Enterprise Premium (CEP) PoC provider.
 *
 * Provisions a CEP evaluation baseline into one organizational unit, and takes
 * it back out again. Three properties shape the design:
 *
 *   - **Schemas are discovered, not assumed.** Every policy is checked against
 *     the live `policySchemas` response before it is written: the field must
 *     exist, and enum values are read off the schema rather than spelled out
 *     here. The same reasoning as `executor.ts` -- a policy written into a
 *     field Chrome no longer advertises does nothing, silently. A schema that
 *     does not resolve is reported as skipped, with the reason.
 *
 *   - **One batch per module.** A single `batchModify` carrying every policy
 *     means one rejected schema takes the whole deployment with it, and the
 *     operator cannot see which one. Per-module batches degrade to partial
 *     success and name the module that failed.
 *
 *   - **One table drives provision, rollback, and the exported script.** They
 *     were three separate hardcoded lists and had already drifted; rollback
 *     did not undo the force-installed extension, and the script ignored every
 *     toggle. `CEP_POLICIES` below is now the only place a policy is declared.
 *
 * DLP rules are a second surface entirely: Cloud Identity policies, where the
 * DLP shape is carried in a free-form `setting.value` struct rather than in the
 * discovery document. Only supported `settings/rule.dlp` mutations are sent;
 * unsupported URL-list detector settings are never created.
 *
 * Two things about that API are easy to get wrong and are handled below: it
 * answers HTTP 200 with an error code in the body, and an empty sub-object
 * anywhere in the request is rejected outright.
 */

import { ensureManagedChromeAccessLevelDetailed } from "./catalog.ts";
import type { Transport } from "./executor.ts";
import { validateLicenseAssignment } from "./licensing.ts";
import { canonicalJson } from "../domain/canonical.ts";

const CHROME_POLICY = "https://chromepolicy.googleapis.com/v1";
const DIRECTORY = "https://admin.googleapis.com/admin/directory/v1";
const ACM = "https://accesscontextmanager.googleapis.com/v1";
const CRM = "https://cloudresourcemanager.googleapis.com/v1";
/** DLP rule mutations and reconciliation reads use the v1beta1 Policies API. */
const CLOUD_IDENTITY = "https://cloudidentity.googleapis.com/v1beta1";

/** Display-name prefix used only for reporting candidates; it is not ownership proof. */
const DLP_PREFIX = "CEP PoC - ";

export type CepDlpRuleId =
  | "universal_upload"
  | "universal_download"
  | "payment_card"
  | "national_id"
  | "access_level"
  | "watermark"
  | "genai_block";

/** Chrome actions supported by the Cloud Identity Policy API. `off` omits the rule. */
export type CepDlpAction = "off" | "warnUser" | "blockContent";

export type CepDlpOperation = "upload" | "download" | "paste" | "print" | "watermark";

function selectionToAccessLevelKind(
  selection: string,
): "profile" | "browser" | "any" | null {
  if (selection === "AUTO_CREATE_CHROME_ANY") return "any";
  if (selection === "AUTO_CREATE_PROFILE_MANAGED") return "profile";
  if (selection === "AUTO_CREATE_BROWSER_MANAGED") return "browser";
  return null;
}

export interface CepDlpMatrixRuleConfig {
  upload?: CepDlpAction;
  download?: CepDlpAction;
  paste?: CepDlpAction;
  print?: CepDlpAction;
  watermark?: boolean;
  byodOnly?: boolean;
}

export type CepDlpMatrixState = Partial<Record<CepDlpRuleId, CepDlpMatrixRuleConfig>>;

/**
 * The national identifier to scan for, per region.
 *
 * The starter rules used `US_SOCIAL_SECURITY_NUMBER` unconditionally, which
 * detects nothing in a Japanese tenant and quietly makes the rule look like it
 * works. These are Cloud DLP infoTypes; the full list is at
 * https://cloud.google.com/sensitive-data-protection/docs/infotypes-reference
 */
const NATIONAL_ID_INFOTYPES: Record<string, { label: string; infoTypes: string[] }> = {
  JP: { label: "Japan", infoTypes: ["JAPAN_INDIVIDUAL_NUMBER", "JAPAN_BANK_ACCOUNT"] },
  US: {
    label: "United States",
    infoTypes: ["US_SOCIAL_SECURITY_NUMBER", "US_DRIVERS_LICENSE_NUMBER"],
  },
  GB: { label: "United Kingdom", infoTypes: ["UK_NATIONAL_INSURANCE_NUMBER"] },
  DE: { label: "Germany", infoTypes: ["GERMANY_IDENTITY_CARD_NUMBER"] },
  FR: { label: "France", infoTypes: ["FRANCE_NIR"] },
  CA: { label: "Canada", infoTypes: ["CANADA_SOCIAL_INSURANCE_NUMBER"] },
  AU: { label: "Australia", infoTypes: ["AUSTRALIA_TAX_FILE_NUMBER"] },
  KR: { label: "South Korea", infoTypes: ["KOREA_RRN"] },
  SG: { label: "Singapore", infoTypes: ["SINGAPORE_NATIONAL_REGISTRATION_ID_NUMBER"] },
  IN: { label: "India", infoTypes: ["INDIA_AADHAAR_INDIVIDUAL"] },
};

export const CEP_DLP_REGIONS = Object.entries(NATIONAL_ID_INFOTYPES).map(
  ([value, entry]) => ({ value, label: entry.label, infoTypes: entry.infoTypes }),
);

/** Cloud Identity Policies allows one aggregate query per second per customer/project. */
const POLICY_MIN_INTERVAL_MS = 1100;
const POLICY_MAX_ATTEMPTS = 4;
const DLP_RECONCILIATION_MAX_ATTEMPTS = 8;

interface PolicyRateLimitClock {
  now(): number;
  sleep(milliseconds: number): Promise<void>;
}

const SYSTEM_POLICY_CLOCK: PolicyRateLimitClock = {
  now: () => Date.now(),
  sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
};

class CloudIdentityPolicyRateLimiter {
  private readonly clock: PolicyRateLimitClock;
  private nextAllowedAt = 0;
  private tail: Promise<void> = Promise.resolve();

  constructor(clock: PolicyRateLimitClock) {
    this.clock = clock;
  }

  async run<T>(request: () => Promise<T>, retryDelayMs = 0): Promise<T> {
    const previous = this.tail;
    let release: () => void = () => void 0;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      const now = this.clock.now();
      const target = Math.max(this.nextAllowedAt, now + retryDelayMs);
      if (target > now) await this.clock.sleep(target - now);
      return await request();
    } finally {
      this.nextAllowedAt = this.clock.now() + POLICY_MIN_INTERVAL_MS;
      release();
    }
  }
}

type TransportWithPolicyClock = Transport & {
  cepPolicyRateLimitClock?: PolicyRateLimitClock;
};

const POLICY_LIMITERS = new WeakMap<object, CloudIdentityPolicyRateLimiter>();

function policyRateLimiter(transport: Transport): CloudIdentityPolicyRateLimiter {
  const key = transport as object;
  const existing = POLICY_LIMITERS.get(key);
  if (existing !== undefined) return existing;
  const clock = (transport as TransportWithPolicyClock).cepPolicyRateLimitClock ?? SYSTEM_POLICY_CLOCK;
  const limiter = new CloudIdentityPolicyRateLimiter(clock);
  POLICY_LIMITERS.set(key, limiter);
  return limiter;
}

/** Endpoint Verification, the posture-signal extension CEP reads from. */
const ENDPOINT_VERIFICATION = "callobklhcbilhphinckomhgkigmfocg";

export const CEP_SUB_OU_NAMES = {
  users: "CEP Users",
  browsers: "CEP Browsers",
} as const;

export type CepOu = keyof typeof CEP_SUB_OU_NAMES;

export type CepModule =
  | "core"
  | "extensions"
  | "connectors"
  | "contextAwareAccess"
  | "dataBoundary"
  | "dlpDetectors"
  | "dlpRules";

export type CepDataBoundaryMode = "copy_paste" | "block_non_corp" | "none";

export interface CepProvisionConfig {
  customer_id: string;
  project_id?: string;
  /** Bare org unit id, as `catalog.listOrganizationalUnits` returns it. */
  target_ou_id: string;
  /** `orgUnitPath` of the same unit; required to create sub OUs beneath it. */
  target_ou_path?: string;
  /**
   * Exact current `orgUnitPath` typed by the operator immediately before a
   * write. Provision routes reject an omitted, stale, or root-OU value.
   */
  target_ou_confirmation?: string;
  create_sub_ous?: boolean;
  core_policies?: boolean;
  force_extensions?: boolean;
  connectors?: boolean;
  /**
   * Access level to require: `NONE`, an `AUTO_CREATE_*` sentinel, or the
   * resource name of a level the operator picked from the dropdown. Same
   * vocabulary the deployment wizard uses.
   */
  access_level?: string;
  dlp_detectors?: boolean;
  dlp_rules?: boolean;
  /** ISO country code selecting which national identifier the rules scan for. */
  dlp_region?: string;
  /** Per-rule action; a rule set to `off` is not created. */
  dlp_rule_actions?: Partial<Record<CepDlpRuleId, CepDlpAction>>;
  /** Comprehensive DLP matrix state */
  dlp_matrix?: CepDlpMatrixState;
  data_boundary_mode?: CepDataBoundaryMode;
  internal_urls?: string[];
}

export interface CepCustomRoleConfig {
  project_id: string;
  customer_id: string;
  role_type: "administrator" | "auditor" | "both";
  assigned_user_email?: string;
}

export interface CepLicenseAssignConfig {
  customer_id: string;
  project_id: string;
  target_ou_id: string;
  target_ou_path?: string;
  /** Exact current `orgUnitPath` typed before this licence mutation. */
  target_ou_confirmation?: string;
  product_id?: string;
  sku_id?: string;
}

export interface CepLicenseAssignResult {
  success: boolean;
  message: string;
  total_users: number;
  assigned_count: number;
  already_assigned_count: number;
  failed_count: number;
  assigned_users: string[];
  errors: string[];
  debug_trace: CepTraceItem[];
}

/**
 * License assignment is intentionally a small-OU pilot operation. The bounds
 * below keep one runtime.onMessage event far below Chrome's MV3 event lifetime:
 * one OU read + four Directory pages + at most three Licensing calls for each
 * of ten users, all with a five-second deadline (175 seconds total network
 * wait inside the provider). Route-level identity/target reads are bounded
 * separately before this provider is entered.
 */
export const CEP_LICENSE_PILOT_USER_LIMIT = 10;
export const CEP_LICENSE_DIRECTORY_PAGE_LIMIT = 4;
export const CEP_LICENSE_REQUEST_TIMEOUT_MS = 5_000;
export const CEP_LICENSE_PROVIDER_MAX_NETWORK_WAIT_MS =
  (1 + CEP_LICENSE_DIRECTORY_PAGE_LIMIT + 3 * CEP_LICENSE_PILOT_USER_LIMIT) *
  CEP_LICENSE_REQUEST_TIMEOUT_MS;

export interface CepRollbackConfig {
  customer_id: string;
  target_ou_id: string;
  target_ou_path?: string;
  /** Retained compatibility flag; cleanup is read-only without durable ownership. */
  verify_match?: boolean;
  /** Restrict the rollback to these modules. Empty or absent means all. */
  rollback_modules?: CepModule[];
  /**
   * What provision was given. AUTO_CREATE candidates are resolved for review,
   * but no level is deleted without durable run ownership.
   */
  access_level?: string;
  project_id?: string;
}

export interface CepTraceItem {
  label: string;
  method: string;
  url: string;
  status: number;
  ok: boolean;
  error?: string;
}

export interface CepProvisionResult {
  success: boolean;
  message: string;
  created_items: string[];
  skipped_items: string[];
  debug_trace: CepTraceItem[];
}

export interface CepRoleResult {
  success: boolean;
  message: string;
  roles: string[];
  debug_trace: CepTraceItem[];
}

export class CepApiError extends Error {
  readonly status: number;
  readonly definitelyRejected: boolean;
  constructor(status: number, message: string, definitelyRejected = false) {
    super(message);
    this.name = "CepApiError";
    this.status = status;
    this.definitelyRejected = definitelyRejected;
  }
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

export class CepTargetValidationError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "CepTargetValidationError";
    this.status = status;
    this.code = code;
  }
}

export interface ResolvedCepTargetOu {
  id: string;
  path: string;
  name: string;
}

function errorStatus(error: unknown): number | null {
  if (error instanceof CepApiError) return error.status;
  if (typeof error !== "object" || error === null) return null;
  const status = (error as { status?: unknown }).status;
  return typeof status === "number" && Number.isInteger(status) ? status : null;
}

function isDefiniteCepMutationRejection(error: unknown): boolean {
  if (error instanceof CepApiError && error.definitelyRejected) return true;
  const status = errorStatus(error);
  return status !== null && status >= 400 && status < 500 &&
    status !== 408 && status !== 429;
}

function strictNextPageToken(
  payload: Record<string, unknown>,
  context: string,
): string | null {
  if (!("nextPageToken" in payload) || payload.nextPageToken === "") return null;
  if (typeof payload.nextPageToken !== "string") {
    throw new Error(
      `${context}: nextPageToken must be an omitted field, an empty string, or a string token`,
    );
  }
  return payload.nextPageToken;
}

function normalizedCloudIdentityPolicyQuery(
  value: Record<string, unknown>,
): { query: string; orgUnit: string } | null {
  const allowed = new Set(["query", "orgUnit", "group", "sortOrder"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) return null;
  if (
    typeof value.query !== "string" || value.query === "" ||
    typeof value.orgUnit !== "string" || !/^orgUnits\/[A-Za-z0-9._~-]+$/.test(value.orgUnit)
  ) {
    return null;
  }
  if (value.group !== undefined && value.group !== "") return null;
  if (
    value.sortOrder !== undefined &&
    (typeof value.sortOrder !== "number" || !Number.isSafeInteger(value.sortOrder))
  ) {
    return null;
  }
  return { query: value.query, orgUnit: value.orgUnit };
}

/**
 * A requestId-less CEP mutation may have committed even though its response
 * was lost. The route layer keeps the durable customer/OU lease when this is
 * raised so only the exact same request can later reconcile the outcome.
 */
export class CepMutationOutcomeAmbiguous extends Error {
  readonly code = "cep-mutation-outcome-ambiguous";

  constructor(message: string) {
    super(message);
    this.name = "CepMutationOutcomeAmbiguous";
  }
}

class CepLicenseRequestTimeout extends Error {
  readonly method: string;
  readonly url: string;

  constructor(method: string, url: string, timeoutMs: number) {
    super(`license-request-timeout: ${method} ${url} exceeded ${timeoutMs}ms`);
    this.name = "CepLicenseRequestTimeout";
    this.method = method;
    this.url = url;
  }
}

/** Promise deadline that also observes a late transport rejection. */
function withinCepLicenseDeadline<T>(
  operation: Promise<T>,
  method: string,
  url: string,
  timeoutMs: number,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new CepLicenseRequestTimeout(method, url, timeoutMs));
    }, timeoutMs);
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

/**
 * The policy API returns a bare gRPC code with no message. These are the ones
 * its guide calls out, phrased as what the operator should do about them.
 */
function rpcCodeMeaning(code: number): string {
  switch (code) {
    case 3:
      return "the request was rejected as invalid (code 3) -- usually a missing field, or no access to the organizational unit named in the query";
    case 5:
      return "the policy was not found (code 5)";
    case 7:
      return "the request was refused (code 7) -- most often an empty sub-object in the body";
    default:
      return `the policy API returned error code ${code}`;
  }
}

// -- Policy table -------------------------------------------------------------

/**
 * How to pick an enum constant off the live schema.
 *
 * The Chrome Policy API spells enums differently from the published policy
 * templates (`ENHANCED_PROTECTION` vs the template's integer `2`), and the
 * spelling is not guessable. Matching against what the schema advertises is
 * both correct today and resilient to Google renaming a constant.
 */
interface EnumHint {
  prefer: RegExp;
  avoid?: RegExp;
}

interface CepContext {
  customerId: string;
  /** Canonical Directory customer id required by Cloud Identity Policy create. */
  dlpCustomerId?: string;
  projectId?: string;
  /** Org unit ids the policies target, per scope. */
  ouIds: Record<CepOu, string>;
  primaryDomain?: string;
  internalUrls: string[];
  region: string;
  dlpMatrix: CepDlpMatrixState;
  accessLevelName?: string;
  /** True only when this run created it, which is what rollback may delete. */
  accessLevelIsOurs?: boolean;
}

interface CepFieldSpec {
  /**
   * Field name, or a pattern when the tenant's spelling is not predictable.
   * A live tenant served `onFileAttachedAnalysisConnectorConfiguration` where
   * the published policy list implies `onFileAttachedEnterpriseConnector`.
   */
  name: string | RegExp;
  enumHint?: EnumHint;
  value?: (context: CepContext) => unknown;
  /** Absent from this tenant's schema is fine; write the other fields. */
  optional?: boolean;
}

interface CepPolicyDefinition {
  module: CepModule;
  ou: CepOu;
  label: string;
  schema: string;
  /** Fields written together; the updateMask is built from the resolved names. */
  fields: CepFieldSpec[];
  /**
   * Last-resort match when neither the exact name nor the trailing segment is
   * found. Chrome Policy namespaces the connector policies differently from
   * the published policy templates, and the difference is not derivable.
   */
  schemaMatcher?: RegExp;
  /** App-scoped policies carry an `app_id` target key. */
  appId?: string;
  /** Returns a reason when the policy cannot be applied, otherwise null. */
  requires?: (context: CepContext) => string | null;
  /** Only applies for some configurations, e.g. a data boundary mode. */
  appliesTo?: (config: CepProvisionConfig) => boolean;
}

/** Turn a pipeline on, whatever this tenant calls the switch. */
const TURN_ON: EnumHint = {
  prefer: /ENABLE|SCAN|ALL|UPLOAD|DOWNLOAD|GOOGLE/,
  avoid: /UNSPECIFIED|DISABLE|NONE|OFF|INHERIT/,
};

/**
 * The fields a content-analysis connector shares.
 *
 * Every one is optional because the four connector schemas differ from each
 * other and from the published policy list: upload carries
 * `fileAttachedConfiguration`, paste carries `bulkTextEntryConfiguration`, and
 * the analysis-connector field is named after its own policy. Declaring them
 * as patterns and letting the schema decide is what stops the next rename from
 * turning into another round of skipped modules.
 */
function connectorFields(configurationPattern: RegExp): CepFieldSpec[] {
  return [
    { name: configurationPattern, enumHint: TURN_ON, value: () => true, optional: true },
    { name: /^serviceProvider$/, value: () => "google", optional: true },
    {
      name: /^delayDeliveryUntilVerdict$/,
      enumHint: {
        prefer: /UPLOAD|DOWNLOAD|ALL|ENABLE/,
        avoid: /UNSPECIFIED|NONE|DISABLE|OFF/,
      },
      value: () => true,
      optional: true,
    },
  ];
}

function requiresDomain(context: CepContext): string | null {
  return context.primaryDomain
    ? null
    : "the tenant's primary domain could not be resolved from the Directory API";
}

type ActionableDlpOperation = Exclude<CepDlpOperation, "watermark">;

const DLP_OPERATION_TRIGGERS: Record<ActionableDlpOperation, string> = {
  upload: "google.workspace.chrome.file.v1.upload",
  download: "google.workspace.chrome.file.v1.download",
  paste: "google.workspace.chrome.web_content.v1.upload",
  print: "google.workspace.chrome.page.v1.print",
};

const DLP_OPERATIONS_BY_RULE: Record<
  Exclude<CepDlpRuleId, "watermark">,
  readonly ActionableDlpOperation[]
> = {
  universal_upload: ["upload"],
  universal_download: ["download"],
  payment_card: ["upload", "paste", "print"],
  national_id: ["upload", "paste", "print"],
  access_level: ["upload", "download", "paste", "print"],
  genai_block: ["upload", "paste"],
};

/**
 * The matrix is the authoritative contract for current callers. The legacy
 * per-rule action remains a compatibility input and expands to every operation
 * that rule supports, which preserves old API clients without collapsing mixed
 * actions from the UI.
 */
function resolveDlpMatrix(config: CepProvisionConfig): CepDlpMatrixState {
  if (config.dlp_matrix !== undefined) return config.dlp_matrix;

  const actionFor = (id: CepDlpRuleId): CepDlpAction =>
    config.dlp_rule_actions?.[id] ?? "warnUser";
  const expanded: CepDlpMatrixState = {};
  for (const [id, operations] of Object.entries(DLP_OPERATIONS_BY_RULE) as Array<
    [Exclude<CepDlpRuleId, "watermark">, readonly ActionableDlpOperation[]]
  >) {
    const action = actionFor(id);
    expanded[id] = Object.fromEntries(
      operations.map((operation) => [operation, action]),
    ) as CepDlpMatrixRuleConfig;
  }
  // The public Policy API documentation does not publish a supported CEL
  // function for evaluating an Access Context Manager level in a DLP rule.
  // Legacy callers therefore default this row off instead of emitting guessed
  // CEL that the service rejects.
  expanded.access_level = {
    upload: "off",
    download: "off",
    paste: "off",
    print: "off",
    byodOnly: false,
  };
  expanded.watermark = { watermark: actionFor("watermark") !== "off", byodOnly: false };
  return expanded;
}

function dlpRuleHasAction(
  config: CepProvisionConfig,
  id: CepDlpRuleId,
  action: CepDlpAction,
): boolean {
  const rule = resolveDlpMatrix(config)[id];
  if (rule === undefined) return false;
  return (["upload", "download", "paste", "print"] as const).some(
    (operation) => rule[operation] === action,
  );
}

const CEP_POLICIES: readonly CepPolicyDefinition[] = [
  // -- Core -------------------------------------------------------------------
  {
    module: "core",
    ou: "users",
    label: "Enhanced Safe Browsing",
    schema: "chrome.users.SafeBrowsingProtectionLevel",
    fields: [
      {
        name: /safeBrowsingProtectionLevel/i,
        enumHint: { prefer: /ENHANCED/, avoid: /UNSPECIFIED/ },
      },
    ],
  },
  {
    module: "core",
    ou: "users",
    label: "Password reuse warning",
    schema: "chrome.users.PasswordProtectionWarningTrigger",
    // Deliberately narrow: a looser pattern matched
    // `PasswordDismissCompromisedAlertEnabled`, which is a different setting.
    schemaMatcher: /PasswordProtection/,
    // The previous value was PASSWORD_PROTECTION_OFF, which turned the warning
    // the UI advertises off rather than on.
    fields: [
      {
        name: /passwordProtection/i,
        enumHint: { prefer: /PASSWORD_REUSE/, avoid: /UNSPECIFIED|OFF|PHISHING/ },
      },
    ],
  },
  {
    module: "core",
    ou: "users",
    label: "Chrome cloud reporting",
    schema: "chrome.users.CloudReportingEnabled",
    schemaMatcher: /CloudReporting/i,
    fields: [{ name: /cloudReporting/i, value: () => true }],
  },
  {
    module: "core",
    ou: "users",
    label: "Cloud profile reporting",
    schema: "chrome.users.CloudProfileReportingEnabled",
    fields: [{ name: /cloudProfileReporting/i, value: () => true }],
  },

  // -- Extensions -------------------------------------------------------------
  {
    module: "extensions",
    ou: "browsers",
    label: "Force-install Endpoint Verification",
    schema: "chrome.users.apps.InstallType",
    appId: ENDPOINT_VERIFICATION,
    fields: [{ name: "appInstallType", value: () => "FORCED" }],
  },

  // -- Connectors -------------------------------------------------------------
  {
    module: "connectors",
    ou: "users",
    label: "Real-time URL check",
    schema: "chrome.users.RealtimeUrlCheck",
    schemaMatcher: /Real.?[Tt]ime.?Url.?Check/i,
    // The field is `realtimeUrlCheckEnabled` here and an enum elsewhere, so it
    // is resolved as either: enum by hint, otherwise a plain true.
    fields: [{ name: /realtimeUrlCheck/i, enumHint: TURN_ON, value: () => true }],
  },
  {
    module: "connectors",
    ou: "users",
    label: "File upload inspection",
    schema: "chrome.users.OnFileAttachedConnectorPolicy",
    schemaMatcher: /FileAttached|UploadScanning/i,
    fields: connectorFields(/FileAttached.*Configuration$/i),
  },
  {
    module: "connectors",
    ou: "users",
    label: "File download inspection",
    schema: "chrome.users.OnFileDownloadedConnectorPolicy",
    schemaMatcher: /FileDownloaded|DownloadScanning/i,
    fields: connectorFields(/FileDownloaded.*Configuration$/i),
  },
  {
    module: "connectors",
    ou: "users",
    label: "Security event reporting",
    schema: "chrome.users.OnSecurityEvent",
    schemaMatcher: /SecurityEvent/i,
    fields: [
      { name: /^reportingConnector$/, enumHint: TURN_ON, value: () => true, optional: true },
      {
        name: /^enabledEventNames$/,
        value: () => [
          "passwordChangedEvent",
          "sensitiveDataEvent",
          "unscannedFileEvent",
          "dangerousDownloadEvent",
        ],
        optional: true,
      },
    ],
  },

  // -- Data boundary ----------------------------------------------------------
  {
    module: "dataBoundary",
    ou: "users",
    label: "Paste inspection (bulk text)",
    schema: "chrome.users.OnBulkTextEntryConnectorPolicy",
    schemaMatcher: /BulkTextEntry|BulkDataEntry/i,
    appliesTo: (config) => config.data_boundary_mode === "copy_paste",
    fields: connectorFields(/BulkTextEntry.*Configuration$/i),
  },
  {
    module: "dataBoundary",
    ou: "users",
    label: "Block non-corporate Google accounts in apps",
    schema: "chrome.users.AllowedDomainsForApps",
    // RestrictAccountsToPatterns only applies on Android/iOS. This policy is
    // supported by managed Chrome on desktop and ChromeOS, which are also in
    // this product's advertised platform boundary.
    appliesTo: (config) =>
      config.data_boundary_mode === "copy_paste" ||
      config.data_boundary_mode === "block_non_corp",
    requires: requiresDomain,
    // A comma-separated domain list, per the published policy. The previous
    // value was `*.{customer_id}`, and customer_id is `my_customer` or `C0…`.
    fields: [{ name: /allowedDomainsForApps/i, value: (c) => c.primaryDomain }],
  },
  {
    module: "dlpRules",
    ou: "users",
    label: "Block unapproved consumer GenAI services",
    schema: "chrome.users.URLBlocklist",
    schemaMatcher: /URLBlocklist/i,
    appliesTo: (config) => dlpRuleHasAction(config, "genai_block", "blockContent"),
    fields: [
      {
        name: /urlBlocklist/i,
        value: () => [
          // Chrome's URL-filter grammar does not accept a trailing `*` after
          // the URL. A bare host matches that host and its subdomains.
          "chatgpt.com",
          "claude.ai",
          "deepseek.com",
          "poe.com",
          "perplexity.ai",
          "copilot.microsoft.com",
        ],
      },
    ],
  },
  {
    module: "dlpRules",
    ou: "users",
    label: "Allow corporate GenAI (Gemini)",
    schema: "chrome.users.URLAllowlist",
    schemaMatcher: /URLAllowlist/i,
    appliesTo: (config) => dlpRuleHasAction(config, "genai_block", "blockContent"),
    fields: [
      {
        name: /urlAllowlist/i,
        value: () => [
          "gemini.google.com",
          "workspace.google.com",
        ],
      },
    ],
  },
];

function moduleEnabled(config: CepProvisionConfig, module: CepModule): boolean {
  switch (module) {
    case "core":
      return config.core_policies === true;
    case "extensions":
      return config.force_extensions === true;
    case "connectors":
      return config.connectors === true;
    case "contextAwareAccess":
      return config.access_level !== undefined && config.access_level !== "" &&
        config.access_level !== "NONE";
    case "dlpDetectors":
      return config.dlp_detectors === true;
    case "dlpRules":
      return config.dlp_rules === true;
    case "dataBoundary":
      return config.data_boundary_mode !== undefined && config.data_boundary_mode !== "none";
  }
}

function selectedPolicies(config: CepProvisionConfig): CepPolicyDefinition[] {
  return CEP_POLICIES.filter(
    (policy) =>
      moduleEnabled(config, policy.module) &&
      (policy.appliesTo === undefined || policy.appliesTo(config)),
  );
}

// -- Schema introspection -----------------------------------------------------

interface ProtoEnum {
  name?: string;
  value?: Array<{ name?: string }>;
}

interface ProtoField {
  name?: string;
  /** `TYPE_ENUM`, `TYPE_BOOL`, `TYPE_STRING`, `TYPE_MESSAGE`, … */
  type?: string;
  /** For enums and messages, the fully qualified type it points at. */
  typeName?: string;
  label?: string;
}

interface ProtoMessage {
  name?: string;
  field?: ProtoField[];
  enumType?: ProtoEnum[];
}

interface PolicySchemaShape {
  definition?: {
    messageType?: ProtoMessage[];
    enumType?: ProtoEnum[];
  };
}

function schemaFields(schema: PolicySchemaShape): ProtoField[] {
  return (schema.definition?.messageType ?? []).flatMap((message) => message.field ?? []);
}

function matchesName(field: ProtoField, wanted: string | RegExp): boolean {
  if (typeof field.name !== "string") return false;
  return typeof wanted === "string" ? field.name === wanted : wanted.test(field.name);
}

/**
 * The values a specific field may take.
 *
 * Scoped to the field's own `typeName` rather than every enum in the schema:
 * the connector policies declare several enums each, and flattening them would
 * let a value from the wrong one look like a match.
 */
function enumValuesForField(schema: PolicySchemaShape, field: ProtoField): string[] {
  const declared = [
    ...(schema.definition?.enumType ?? []),
    ...(schema.definition?.messageType ?? []).flatMap((message) => message.enumType ?? []),
  ];
  const leaf = (field.typeName ?? "").split(".").pop();
  const scoped = declared.filter((entry) => entry.name !== undefined && entry.name === leaf);
  const usable = scoped.length > 0 ? scoped : leaf === undefined ? declared : [];
  return usable
    .flatMap((entry) => entry.value ?? [])
    .map((entry) => entry.name)
    .filter((name): name is string => typeof name === "string");
}

function chooseEnumValue(values: string[], hint: EnumHint): string | null {
  const candidates = values.filter(
    (name) => !(hint.avoid !== undefined && hint.avoid.test(name)),
  );
  return candidates.find((name) => hint.prefer.test(name)) ?? null;
}

function findMessageType(
  schema: PolicySchemaShape,
  typeName: string | undefined,
): ProtoMessage | undefined {
  const leaf = (typeName ?? "").split(".").pop();
  if (leaf === undefined || leaf === "") return undefined;
  return (schema.definition?.messageType ?? []).find((message) => message.name === leaf);
}

/**
 * A value for one field, derived from what the schema says the field is.
 *
 * A live tenant rejected the connector batch with "Expect message object but
 * got: true" -- the configuration field is a nested message, not a switch, and
 * writing a scalar into it fails the whole batch. Message fields are therefore
 * built by walking their own definition and applying the same rules one level
 * down, and a field this cannot produce a value for is left unset rather than
 * guessed at.
 */
function buildFieldValue(
  schema: PolicySchemaShape,
  field: ProtoField,
  hint: EnumHint | undefined,
  literal: unknown,
  depth: number,
): unknown {
  const repeated = field.label === "LABEL_REPEATED";

  if (field.type === "TYPE_ENUM") {
    const chosen = chooseEnumValue(enumValuesForField(schema, field), hint ?? TURN_ON);
    if (chosen === null) return undefined;
    return repeated ? [chosen] : chosen;
  }

  if (field.type === "TYPE_MESSAGE") {
    if (literal !== undefined && typeof literal === "object") return literal;
    if (depth <= 0) return undefined;
    const nested = findMessageType(schema, field.typeName);
    if (nested === undefined) return undefined;
    const built: Record<string, unknown> = {};
    for (const inner of nested.field ?? []) {
      if (typeof inner.name !== "string") continue;
      const value = buildFieldValue(schema, inner, undefined, defaultLiteral(inner), depth - 1);
      if (value !== undefined) built[inner.name] = value;
    }
    if (Object.keys(built).length === 0) return undefined;
    return repeated ? [built] : built;
  }

  if (literal !== undefined) return literal;
  if (field.type === "TYPE_BOOL") return repeated ? [true] : true;
  return undefined;
}

/**
 * What an unspecified scalar inside a connector message should say.
 *
 * These policies exist to turn inspection on, so a boolean means yes and the
 * provider is Google. Anything else is left out: a string we cannot name is
 * not something to invent.
 */
function defaultLiteral(field: ProtoField): unknown {
  if (field.name === "serviceProvider") return "google";
  if (field.type === "TYPE_BOOL") return true;
  return undefined;
}

/** A field described the way the next fix would need to read it. */
function describeField(schema: PolicySchemaShape, field: ProtoField): string {
  const kind = (field.type ?? "TYPE_UNKNOWN").replace(/^TYPE_/, "").toLowerCase();
  const list = field.label === "LABEL_REPEATED" ? "[]" : "";
  if (field.type === "TYPE_ENUM") {
    const values = enumValuesForField(schema, field);
    return `${field.name} (${kind}${list}: ${values.join(" | ") || "no values listed"})`;
  }
  if (field.type === "TYPE_MESSAGE") {
    const nested = findMessageType(schema, field.typeName);
    const inner = (nested?.field ?? [])
      .map((entry) => entry.name)
      .filter((name): name is string => typeof name === "string");
    return `${field.name} (${kind}${list}${inner.length > 0 ? `: {${inner.join(", ")}}` : ""})`;
  }
  return `${field.name} (${kind}${list})`;
}

function targetKey(
  context: CepContext,
  policy: CepPolicyDefinition,
): Record<string, unknown> {
  const key: Record<string, unknown> = {
    targetResource: `orgunits/${context.ouIds[policy.ou]}`,
  };
  if (policy.appId !== undefined) {
    key.additionalTargetKeys = { app_id: `chrome:${policy.appId}` };
  }
  return key;
}

/**
 * Chrome Policy batch calls accept only one target resource and one set of
 * additional-target-key names per request. Values (for example app ids) may
 * differ, but mixing an app-scoped request with a normal OU request is a 400.
 */
function groupPolicyRequests<
  T extends { policyTargetKey: Record<string, unknown> },
>(requests: readonly T[]): T[][] {
  const groups = new Map<string, T[]>();
  for (const request of requests) {
    const targetResource = String(request.policyTargetKey.targetResource ?? "");
    const rawAdditionalKeys = request.policyTargetKey.additionalTargetKeys;
    const additionalKeyNames =
      rawAdditionalKeys !== null && typeof rawAdditionalKeys === "object"
        ? Object.keys(rawAdditionalKeys).sort()
        : [];
    const signature = JSON.stringify([targetResource, additionalKeyNames]);
    const group = groups.get(signature) ?? [];
    group.push(request);
    groups.set(signature, group);
  }
  return [...groups.values()];
}

function policyRequestGroupLabel(
  requests: readonly { policyTargetKey: Record<string, unknown> }[],
): string {
  const key = requests[0]?.policyTargetKey ?? {};
  const additional = key.additionalTargetKeys;
  const additionalNames =
    additional !== null && typeof additional === "object"
      ? Object.keys(additional).sort()
      : [];
  return `${String(key.targetResource ?? "unknown target")}` +
    (additionalNames.length > 0 ? ` + ${additionalNames.join(",")}` : "");
}

interface ResolvedPolicy {
  definition: CepPolicyDefinition;
  request: {
    policyTargetKey: Record<string, unknown>;
    policyValue: { policySchema: string; value: Record<string, unknown> };
    updateMask: string;
  };
}

function parseDirectoryOrgUnits(payload: Record<string, unknown>): ResolvedCepTargetOu[] {
  const rawUnits = payload.organizationUnits;
  if (rawUnits !== undefined && !Array.isArray(rawUnits)) {
    throw new Error("directory-orgunits-response-invalid");
  }
  const units = rawUnits ?? [];
  const result: ResolvedCepTargetOu[] = [];
  const ids = new Set<string>();
  const paths = new Set<string>();
  for (const item of units) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error("directory-orgunits-item-invalid");
    }
    const record = item as Record<string, unknown>;
    const rawId = record.orgUnitId;
    const path = record.orgUnitPath;
    const name = record.name;
    if (
      typeof rawId !== "string" || !/^(?:id:)?[A-Za-z0-9_-]+$/.test(rawId) ||
      typeof path !== "string" || path === "" || !path.startsWith("/") ||
      (path !== "/" && (path.endsWith("/") || path.includes("//"))) ||
      typeof name !== "string" || name.trim() === ""
    ) {
      throw new Error("directory-orgunits-item-invalid");
    }
    // Directory returns `id:03abc...`; Chrome policy targets use the bare id.
    const id = rawId.replace(/^id:/, "");
    const normalizedId = id.toLowerCase();
    const normalizedPath = path.toLowerCase();
    if (ids.has(normalizedId) || paths.has(normalizedPath)) {
      throw new Error("directory-orgunits-duplicate-identity");
    }
    ids.add(normalizedId);
    paths.add(normalizedPath);
    result.push({ id, path, name: name.trim() });
  }
  return result;
}

/**
 * Resolve and authorize a CEP write target from a fresh Directory tree read.
 * Browser-supplied labels are display data only: the immutable id, current
 * path, non-root boundary, and separately typed confirmation must all agree.
 */
export async function resolveConfirmedCepTargetOu(
  transport: Transport,
  request: Pick<
    CepProvisionConfig | CepLicenseAssignConfig,
    "customer_id" | "target_ou_id" | "target_ou_path" | "target_ou_confirmation"
  >,
): Promise<ResolvedCepTargetOu> {
  const customerId = typeof request.customer_id === "string"
    ? request.customer_id.trim()
    : "";
  const targetOuId = typeof request.target_ou_id === "string"
    ? request.target_ou_id.trim()
    : "";
  if (!/^C[A-Za-z0-9]+$/.test(customerId) || !/^[A-Za-z0-9_-]+$/.test(targetOuId)) {
    throw new CepTargetValidationError(
      400,
      "cep-target-ou-invalid",
      "A canonical customer_id and bare target_ou_id are required for a CEP mutation.",
    );
  }

  let payload: Record<string, unknown>;
  try {
    const response = await transport.requestJson(
      "GET",
      `${DIRECTORY}/customer/${encodeURIComponent(customerId)}/orgunits?type=all_including_parent`,
    );
    if (response.status < 200 || response.status >= 300) {
      throw new Error(`HTTP ${response.status}`);
    }
    payload = response.payload;
  } catch (error) {
    throw new CepTargetValidationError(
      502,
      "cep-target-ou-unresolved",
      `The current Directory organizational-unit tree could not be resolved: ${errorMessage(error)}`,
    );
  }

  let units: ResolvedCepTargetOu[];
  try {
    units = parseDirectoryOrgUnits(payload);
  } catch (error) {
    throw new CepTargetValidationError(
      502,
      "cep-target-ou-inventory-invalid",
      `Directory returned an invalid organizational-unit tree: ${errorMessage(error)}`,
    );
  }
  const target = units.find((unit) => unit.id === targetOuId);
  if (target === undefined) {
    throw new CepTargetValidationError(
      409,
      "cep-target-ou-not-found",
      "The selected organizational-unit id is no longer present. Reload the OU list.",
    );
  }
  if (target.path === "/") {
    throw new CepTargetValidationError(
      400,
      "cep-root-ou-forbidden",
      "The Workspace root organizational unit cannot be used for CEP provision or licence assignment.",
    );
  }
  if (typeof request.target_ou_path !== "string" || request.target_ou_path !== target.path) {
    throw new CepTargetValidationError(
      409,
      "cep-target-ou-path-stale",
      "The selected OU path no longer matches Directory. Reload the OU list.",
    );
  }
  if (
    typeof request.target_ou_confirmation !== "string" ||
    request.target_ou_confirmation !== target.path
  ) {
    throw new CepTargetValidationError(
      400,
      "cep-target-ou-confirmation-mismatch",
      "Type the exact current OU path shown in the picker before this mutation.",
    );
  }
  return target;
}

export class CepProvider {
  private readonly schemaCache = new Map<string, PolicySchemaShape | null>();
  private schemaCatalogueCache: Map<string, PolicySchemaShape> | null = null;
  /** Directory, Chrome Policy, Cloud Identity: authorized as a Workspace admin. */
  private readonly transport: Transport;
  /** IAM, Resource Manager, Access Context Manager: authorized as the deployer. */
  private readonly cloudTransport: Transport;
  /** Administrator-discovered policy on which the deployer has policyReader. */
  private readonly accessPolicyId: string | undefined;
  private readonly cloudIdentityPolicyRateLimiter: CloudIdentityPolicyRateLimiter;
  private readonly licenseRequestTimeoutMs: number;

  // Assigned rather than declared as parameter properties: node's
  // type-stripping loader, which the verify scripts run under, rejects those.
  constructor(
    transport: Transport,
    cloudTransport?: Transport,
    accessPolicyId?: string,
    options?: { licenseRequestTimeoutMs?: number },
  ) {
    this.transport = transport;
    this.cloudTransport = cloudTransport ?? transport;
    this.accessPolicyId = accessPolicyId;
    this.cloudIdentityPolicyRateLimiter = policyRateLimiter(transport);
    const requestedLicenseTimeout = options?.licenseRequestTimeoutMs;
    this.licenseRequestTimeoutMs =
      typeof requestedLicenseTimeout === "number" &&
        Number.isFinite(requestedLicenseTimeout) && requestedLicenseTimeout > 0
        ? Math.min(requestedLicenseTimeout, CEP_LICENSE_REQUEST_TIMEOUT_MS)
        : CEP_LICENSE_REQUEST_TIMEOUT_MS;
  }

  // -- Transport --------------------------------------------------------------

  /**
   * The shared transport reports HTTP status rather than throwing, so a failed
   * Google call would otherwise read as success. This is where that is turned
   * back into an error.
   *
   * The Cloud Identity policy API adds a second failure mode: it answers 200
   * with `{done: true, error: {code}}`, so status alone is not enough.
   */
  private async request(
    transport: Transport,
    method: "GET" | "POST" | "PATCH" | "DELETE",
    url: string,
    body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const cloudIdentityRequest = url.startsWith(`${CLOUD_IDENTITY}/`);
    const send = () =>
      transport.requestJson(
        method,
        url,
        {
          ...(body === undefined ? {} : { jsonBody: body }),
          ...(cloudIdentityRequest ? { acceptedStatuses: [429] } : {}),
        },
      );
    let response: Awaited<ReturnType<Transport["requestJson"]>>;
    if (cloudIdentityRequest) {
      response = await this.cloudIdentityPolicyRateLimiter.run(send);
      for (let attempt = 1; response.status === 429 && attempt < POLICY_MAX_ATTEMPTS; attempt += 1) {
        const backoff = POLICY_MIN_INTERVAL_MS * 2 ** (attempt - 1);
        response = await this.cloudIdentityPolicyRateLimiter.run(send, backoff);
      }
    } else {
      response = await send();
    }
    const { status, payload } = response;
    if (status < 200 || status >= 300) {
      const detail = payload.error as { message?: string } | undefined;
      throw new CepApiError(status, detail?.message ?? `HTTP ${status}`);
    }
    const embedded = payload.error as { code?: number; message?: string } | undefined;
    if (embedded !== undefined && embedded.code !== undefined) {
      throw new CepApiError(
        status,
        embedded.message ?? rpcCodeMeaning(embedded.code),
        true,
      );
    }
    return payload;
  }

  /** Run a call, record it in the trace either way, and return null on failure. */
  private async call(
    trace: CepTraceItem[],
    label: string,
    method: "GET" | "POST" | "PATCH" | "DELETE",
    url: string,
    body?: Record<string, unknown>,
    transport: Transport = this.transport,
  ): Promise<Record<string, unknown> | null> {
    try {
      const payload = await this.request(transport, method, url, body);
      trace.push({ label, method, url, status: 200, ok: true });
      return payload;
    } catch (error) {
      trace.push({
        label,
        method,
        url,
        status: error instanceof CepApiError ? error.status : 0,
        ok: false,
        error: errorMessage(error),
      });
      return null;
    }
  }

  // -- Discovery --------------------------------------------------------------

  /**
   * Every policy schema this tenant serves, by bare schema name.
   *
   * Fetched as a catalogue rather than one GET per policy because the exact
   * names are not reliably knowable: a live tenant rejected seven of eleven
   * names taken from Google's published policy list, including ones whose
   * sibling policies resolved fine. Reading the catalogue turns "we guessed
   * wrong" into "we looked it up".
   */
  private async schemaCatalogue(customerId: string): Promise<Map<string, PolicySchemaShape>> {
    if (this.schemaCatalogueCache !== null) return this.schemaCatalogueCache;
    const catalogue = new Map<string, PolicySchemaShape>();
    let pageToken = "";
    let complete = false;
    const seenPageTokens = new Set<string>();
    for (let page = 0; page < 40; page += 1) {
      const query = pageToken === "" ? "" : `&pageToken=${encodeURIComponent(pageToken)}`;
      let payload: Record<string, unknown>;
      try {
        payload = await this.request(
          this.transport,
          "GET",
          `${CHROME_POLICY}/customers/${customerId}/policySchemas?pageSize=1000${query}`,
        );
      } catch (error) {
        throw new Error(
          `policy-schema-catalogue-incomplete: page ${page + 1} failed (${errorMessage(error)})`,
        );
      }
      const rawSchemas = payload.policySchemas;
      if (rawSchemas !== undefined && !Array.isArray(rawSchemas)) {
        throw new Error(
          "policy-schema-catalogue-incomplete: policySchemas was present but not an array",
        );
      }
      const schemas = rawSchemas ?? [];
      for (const item of schemas) {
        if (typeof item !== "object" || item === null || Array.isArray(item)) {
          throw new Error(
            "policy-schema-catalogue-incomplete: policySchemas contained a malformed item",
          );
        }
        const record = item as PolicySchemaShape & { schemaName?: string; name?: string };
        // `schemaName` is the bare name; `name` is the full resource path.
        const bare =
          record.schemaName ??
          (typeof record.name === "string"
            ? record.name.replace(/^customers\/[^/]+\/policySchemas\//, "")
            : undefined);
        if (
          typeof bare !== "string" || bare === "" || bare.includes("/") ||
          catalogue.has(bare)
        ) {
          throw new Error(
            "policy-schema-catalogue-incomplete: policySchemas contained an invalid or duplicate identity",
          );
        }
        catalogue.set(bare, record);
      }
      const next = strictNextPageToken(payload, "policy-schema-catalogue-incomplete");
      if (next === null) {
        complete = true;
        break;
      }
      if (seenPageTokens.has(next)) {
        throw new Error(
          `policy-schema-catalogue-incomplete: repeated page token ${JSON.stringify(next)}`,
        );
      }
      seenPageTokens.add(next);
      pageToken = next;
    }
    if (!complete) {
      throw new Error(
        "policy-schema-catalogue-incomplete: a next page remained after 40 pages",
      );
    }
    this.schemaCatalogueCache = catalogue;
    return catalogue;
  }

  /**
   * Find the schema a policy definition means: exact name, then the trailing
   * segment, then its matcher. The trailing segment is the stable part -- what
   * moves between releases is the namespace in front of it.
   */
  private async resolveSchema(
    customerId: string,
    definition: CepPolicyDefinition,
  ): Promise<{ name: string; schema: PolicySchemaShape } | null> {
    const catalogue = await this.schemaCatalogue(customerId);

    // Candidates in order of confidence, filtered to those that can actually
    // carry the policy. Committing to the first name that merely looks right
    // matched `PasswordDismissCompromisedAlertEnabled` for the password-reuse
    // warning, which then failed on its fields.
    const leaf = definition.schema.split(".").pop() ?? "";
    const candidates: Array<[string, PolicySchemaShape]> = [];
    const exact = catalogue.get(definition.schema);
    if (exact !== undefined) candidates.push([definition.schema, exact]);
    for (const entry of catalogue) {
      if (entry[0] === definition.schema) continue;
      if (entry[0].split(".").pop() === leaf) candidates.push(entry);
    }
    if (definition.schemaMatcher !== undefined) {
      for (const entry of catalogue) {
        if (candidates.some(([name]) => name === entry[0])) continue;
        if (definition.schemaMatcher.test(entry[0])) candidates.push(entry);
      }
    }

    const usable = candidates.find(([, schema]) =>
      definition.fields.some(
        (spec) =>
          spec.optional !== true &&
          schemaFields(schema).some((field) => matchesName(field, spec.name)),
      ),
    );
    if (usable !== undefined) return { name: usable[0], schema: usable[1] };
    if (candidates.length > 0) return { name: candidates[0][0], schema: candidates[0][1] };

    // The catalogue may not have loaded at all; fall back to a direct read so a
    // list failure does not look like a missing policy.
    if (catalogue.size === 0) {
      const cached = this.schemaCache.get(definition.schema);
      if (cached !== undefined) {
        return cached === null ? null : { name: definition.schema, schema: cached };
      }
      try {
        const schema = (await this.request(
          this.transport,
          "GET",
          `${CHROME_POLICY}/customers/${customerId}/policySchemas/${definition.schema}`,
        )) as PolicySchemaShape;
        this.schemaCache.set(definition.schema, schema);
        return { name: definition.schema, schema };
      } catch {
        this.schemaCache.set(definition.schema, null);
        return null;
      }
    }
    return null;
  }

  /** Names sharing a word with the one we wanted, to put in the skip message. */
  private async nearbySchemaNames(customerId: string, wanted: string): Promise<string[]> {
    const catalogue = await this.schemaCatalogue(customerId);
    const words = (wanted.split(".").pop() ?? "").match(/[A-Z][a-z]+/g) ?? [];
    const scored: Array<{ name: string; hits: number }> = [];
    for (const name of catalogue.keys()) {
      const hits = words.filter((word) => name.includes(word)).length;
      if (hits > 0) scored.push({ name, hits });
    }
    return scored
      .sort((a, b) => b.hits - a.hits)
      .slice(0, 3)
      .map((entry) => entry.name);
  }

  /** Canonical tenant identity used by domain policies and Cloud Identity DLP. */
  private async customerMetadata(
    customerId: string,
  ): Promise<{ primaryDomain?: string; dlpCustomerId?: string }> {
    try {
      const payload = await this.request(
        this.transport,
        "GET",
        `${DIRECTORY}/customers/${customerId}`,
      );
      const domain = payload.customerDomain;
      const resolvedId = payload.id;
      return {
        primaryDomain:
          typeof domain === "string" && domain !== "" ? domain : undefined,
        dlpCustomerId:
          typeof resolvedId === "string" && /^C[A-Za-z0-9]+$/.test(resolvedId)
            ? resolvedId
            : undefined,
      };
    } catch {
      return {};
    }
  }

  private async listOrgUnits(
    customerId: string,
  ): Promise<Array<{ id: string; path: string; name: string }>> {
    const payload = await this.request(
      this.transport,
      "GET",
      `${DIRECTORY}/customer/${customerId}/orgunits?type=all_including_parent`,
    );
    return parseDirectoryOrgUnits(payload);
  }

  /**
   * Resolve the two sub OUs, creating them when asked to.
   *
   * The returned ids are used for legacy cleanup inventory. Provision creates
   * these children only as optional organization scaffolding: it deliberately
   * keeps policy targets on the selected populated pilot OU, because creating
   * a child does not move users or enrolled browsers into it.
   */
  private async resolveSubOrgUnits(
    trace: CepTraceItem[],
    config: CepProvisionConfig | CepRollbackConfig,
    context: CepContext,
    created: string[],
    skipped: string[],
    create: boolean,
  ): Promise<boolean> {
    let units: Array<{ id: string; path: string; name: string }>;
    try {
      units = await this.listOrgUnits(context.customerId);
      trace.push({
        label: "List organizational units",
        method: "GET",
        url: `${DIRECTORY}/customer/${context.customerId}/orgunits`,
        status: 200,
        ok: true,
      });
    } catch (error) {
      trace.push({
        label: "List organizational units",
        method: "GET",
        url: `${DIRECTORY}/customer/${context.customerId}/orgunits`,
        status: error instanceof CepApiError ? error.status : 0,
        ok: false,
        error: errorMessage(error),
      });
      skipped.push(`Sub OUs: could not read the OU tree (${errorMessage(error)})`);
      return false;
    }

    const parent = units.find((unit) => unit.id === config.target_ou_id);
    if (
      parent === undefined ||
      (config.target_ou_path !== undefined &&
        config.target_ou_path.toLowerCase() !== parent.path.toLowerCase())
    ) {
      skipped.push(
        "Sub OUs: the selected OU identity/path could not be resolved exactly; no policy was applied",
      );
      return false;
    }
    const parentPath = parent.path;

    for (const scope of ["users", "browsers"] as const) {
      const name = CEP_SUB_OU_NAMES[scope];
      const wanted = `${parentPath === "/" ? "" : parentPath}/${name}`;
      const existing = units.find((unit) => unit.path === wanted);
      if (existing !== undefined) {
        context.ouIds[scope] = existing.id;
        skipped.push(`Sub OU "${name}" already exists and was reused`);
        continue;
      }
      if (!create) continue;

      const url = `${DIRECTORY}/customer/${context.customerId}/orgunits`;
      const payload = await this.call(trace, `Create OU "${name}"`, "POST", url, {
        name,
        parentOrgUnitPath: parentPath,
      });
      if (payload === null) {
        skipped.push(`Sub OU "${name}" could not be created; no policy was applied`);
        return false;
      }
      const rawId = payload.orgUnitId;
      if (typeof rawId === "string") {
        created.push(`Organizational unit "${name}"`);
      } else {
        skipped.push(
          `Sub OU "${name}" create response had no organizational-unit id; no policy was applied`,
        );
        return false;
      }
    }
    if (!create) return true;

    // Creation acknowledgements are not sufficient: both exact child paths
    // must be visible in a fresh authoritative OU-tree read before any policy
    // request is allowed to target them.
    let freshUnits: Array<{ id: string; path: string; name: string }>;
    try {
      freshUnits = await this.listOrgUnits(context.customerId);
      trace.push({
        label: "Verify created organizational units",
        method: "GET",
        url: `${DIRECTORY}/customer/${context.customerId}/orgunits`,
        status: 200,
        ok: true,
      });
    } catch (error) {
      trace.push({
        label: "Verify created organizational units",
        method: "GET",
        url: `${DIRECTORY}/customer/${context.customerId}/orgunits`,
        status: error instanceof CepApiError ? error.status : 0,
        ok: false,
        error: errorMessage(error),
      });
      skipped.push(`Sub OUs: fresh verification failed (${errorMessage(error)}); no policy was applied`);
      return false;
    }
    for (const scope of ["users", "browsers"] as const) {
      const name = CEP_SUB_OU_NAMES[scope];
      const wanted = `${parentPath === "/" ? "" : parentPath}/${name}`;
      const exact = freshUnits.filter((unit) => unit.path === wanted);
      if (exact.length !== 1 || exact[0]!.id === "") {
        skipped.push(
          `Sub OU "${name}" was not resolved to exactly one fresh child at ${wanted}; no policy was applied`,
        );
        return false;
      }
      context.ouIds[scope] = exact[0]!.id;
    }
    return true;
  }

  /**
   * Resolve the access level the operator chose.
   *
   * Three cases, and only one of them creates anything: an `AUTO_CREATE_*`
   * sentinel builds a managed-Chrome level, a resource name is used as-is, and
   * anything else means the module is off. Picking an existing level used to be
   * impossible -- the module hard-failed on tenants with no access policy,
   * which is most of them.
   *
   * `ensureManagedChromeAccessLevelDetailed` resolves the ACM policy, writes
   * the CEL expression, and reuses a level it finds, so the auto-create path
   * does not reimplement any of that.
   */
  private async resolveAccessLevel(
    trace: CepTraceItem[],
    context: CepContext,
    created: string[],
    skipped: string[],
    selection: string,
  ): Promise<boolean> {
    if (!selection.startsWith("AUTO_CREATE_")) {
      // A level the operator selected. Nothing to create, nothing to own.
      context.accessLevelName = selection;
      context.accessLevelIsOurs = false;
      return selection !== "" && selection !== "NONE";
    }

    if (!context.projectId) {
      skipped.push(
        "Context-Aware Access: creating a level needs a Google Cloud project. Pick an existing access level instead, or set a project on the setup screen.",
      );
      return false;
    }

    const kind = selection.includes("BROWSER")
      ? "browser"
      : selection.includes("ANY")
      ? "any"
      : "profile";
    try {
      const ensured = await ensureManagedChromeAccessLevelDetailed(
        this.cloudTransport,
        context.projectId,
        kind,
        this.accessPolicyId,
      );
      const name = ensured.name;
      context.accessLevelName = name;
      context.accessLevelIsOurs = ensured.created;
      trace.push({
        label: "Ensure Context-Aware Access level",
        method: "POST",
        url: `${ACM}/${name}`,
        status: 200,
        ok: true,
      });
      if (ensured.created) {
        created.push(`Context-Aware Access level (${name})`);
      } else {
        skipped.push(
          `Context-Aware Access: ${name} already existed and was reused; this CEP operation does not own it`,
        );
      }
      return true;
    } catch (error) {
      trace.push({
        label: "Ensure Context-Aware Access level",
        method: "POST",
        url: `${ACM}/accessPolicies`,
        status: error instanceof CepApiError ? error.status : 0,
        ok: false,
        error: errorMessage(error),
      });
      skipped.push(
        `Context-Aware Access: ${errorMessage(error)} Select an existing access level from the dropdown to use one that already exists.`,
      );
      return false;
    }
  }

  // -- DLP rules and legacy-detector retention --------------------------------

  /**
   * Cloud Identity policies are addressed by a CEL query over the target OU,
   * with the org unit repeated in its own field.
   */
  private policyQuery(context: CepContext): Record<string, unknown> {
    const ouId = context.ouIds.users;
    return {
      query: `entity.org_units.exists(org_unit, org_unit.org_unit_id == orgUnitId('${ouId}'))`,
      orgUnit: `orgUnits/${ouId}`,
    };
  }

  /**
   * Existing `CEP PoC - …` policies, so a second run reuses rather than
   * duplicates. A matching name is deliberately not treated as delete ownership.
   *
   * The shared request path rate-limits every Cloud Identity Policies request,
   * including list pages and create calls. Results are still
   * passed around to avoid unnecessary quota use.
   */
  private lastDlpError = "";

  private async listDlpPolicies(
    trace: CepTraceItem[],
    kind: "rule.dlp" | "detector",
    customerId: string,
  ): Promise<Array<{
    name: string;
    displayName: string;
    type: string;
    value: Record<string, unknown>;
    policyQuery: Record<string, unknown>;
  }> | null> {
    const filter = encodeURIComponent(
      `customer == "customers/${customerId}" && setting.type.matches("${kind}")`,
    );
    const result: Array<{
      name: string;
      displayName: string;
      type: string;
      value: Record<string, unknown>;
      policyQuery: Record<string, unknown>;
    }> = [];
    let pageToken = "";
    let complete = false;
    const seenPageTokens = new Set<string>();
    const seenPolicyNames = new Set<string>();

    // Paged, because the default page is 50 and a tenant with more policies
    // than that would hide ours -- which reads as "not created yet" and makes
    // the next run create a duplicate.
    for (let page = 0; page < 20; page += 1) {
      const query = pageToken === "" ? "" : `&pageToken=${encodeURIComponent(pageToken)}`;
      const url = `${CLOUD_IDENTITY}/policies?pageSize=100&filter=${filter}${query}`;
      const before = trace.length;
      const payload = await this.call(trace, `List ${kind} policies`, "GET", url);
      if (payload === null) {
        this.lastDlpError = trace[before]?.error ?? "the policy API could not be reached";
        return null;
      }

      if (payload.policies !== undefined && !Array.isArray(payload.policies)) {
        this.lastDlpError = `response-invalid: ${kind} policy list omitted a valid policies array`;
        return null;
      }
      const policies = payload.policies ?? [];
      for (const item of policies) {
        if (typeof item !== "object" || item === null || Array.isArray(item)) {
          this.lastDlpError = `response-invalid: ${kind} policy list contains a malformed item`;
          return null;
        }
        const record = item as Record<string, unknown>;
        if (
          typeof record.name !== "string" ||
          !/^policies\/[A-Za-z0-9._~-]+$/.test(record.name) ||
          seenPolicyNames.has(record.name)
        ) {
          this.lastDlpError = `response-invalid: ${kind} policy list contains an invalid identity`;
          return null;
        }
        seenPolicyNames.add(record.name);
        if (typeof record.setting !== "object" || record.setting === null ||
            Array.isArray(record.setting)) {
          this.lastDlpError = `response-invalid: ${kind} policy list contains an invalid setting`;
          return null;
        }
        const setting = record.setting as {
          type?: unknown;
          value?: unknown;
        };
        const settingTypeMatches = kind === "rule.dlp"
          ? setting.type === "settings/rule.dlp"
          : typeof setting.type === "string" && /^settings\/detector(?:\.|$)/.test(setting.type);
        if (
          !settingTypeMatches ||
          typeof setting.value !== "object" || setting.value === null ||
          Array.isArray(setting.value)
        ) {
          this.lastDlpError = `response-invalid: ${kind} policy list contains an invalid setting`;
          return null;
        }
        const settingValue = setting.value as Record<string, unknown>;
        // `setting.value` is a free-form struct, so its keys come back exactly
        // as whoever wrote them spelled them. Reading only camelCase missed
        // every rule and duplicated the whole set on the second run.
        const camel = settingValue.displayName;
        const snake = settingValue.display_name;
        const raw = camel ?? snake;
        if (
          typeof raw !== "string" || raw === "" ||
          (camel !== undefined && typeof camel !== "string") ||
          (snake !== undefined && typeof snake !== "string") ||
          (typeof camel === "string" && typeof snake === "string" && camel !== snake)
        ) {
          this.lastDlpError = `response-invalid: ${kind} policy list contains an invalid display name`;
          return null;
        }
        const value = { ...settingValue };
        // Struct keys are user-defined. Treat the legacy snake-case spelling
        // as the same display-name field, but keep every other field exact.
        if (value.displayName === undefined && typeof value.display_name === "string") {
          value.displayName = value.display_name;
        }
        delete value.display_name;
        if (kind === "rule.dlp") {
          const outputOnlyFields = [
            ["createTime", "create_time", "timestamp"],
            ["updateTime", "update_time", "timestamp"],
          ] as const;
          for (const [camelName, snakeName, outputType] of outputOnlyFields) {
            const camelValue = value[camelName];
            const snakeValue = value[snakeName];
            if (
              camelValue !== undefined && snakeValue !== undefined &&
              canonicalJson(camelValue) !== canonicalJson(snakeValue)
            ) {
              this.lastDlpError =
                `response-invalid: ${kind} policy list contains conflicting ${camelName} fields`;
              return null;
            }
            const outputValue = camelValue ?? snakeValue;
            const validOutput = outputValue === undefined ||
              (outputType === "timestamp" &&
                typeof outputValue === "string" && outputValue !== "" &&
                Number.isFinite(Date.parse(outputValue)));
            if (!validOutput) {
              this.lastDlpError =
                `response-invalid: ${kind} policy list contains invalid ${camelName}`;
              return null;
            }
            // Cloud Identity populates timestamps after create. They are not
            // operator-set rule semantics; every other value key remains exact.
            delete value[camelName];
            delete value[snakeName];
          }

          const normalizeRuleTypeMetadata = (
            raw: unknown,
          ): Record<string, unknown> | null => {
            if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
            const metadata = raw as Record<string, unknown>;
            if (!Object.keys(metadata).every(
              (key) => key === "dlpRuleMetadata" || key === "dlp_rule_metadata"
            )) return null;
            const camelDlp = metadata.dlpRuleMetadata;
            const snakeDlp = metadata.dlp_rule_metadata;
            if (camelDlp === undefined && snakeDlp === undefined) return null;
            const normalizeDlp = (candidate: unknown): Record<string, unknown> | null => {
              if (
                typeof candidate !== "object" || candidate === null ||
                Array.isArray(candidate)
              ) return null;
              const record = candidate as Record<string, unknown>;
              if (!Object.keys(record).every(
                (key) => key === "alertSeverity" || key === "alert_severity"
              )) return null;
              const camelSeverity = record.alertSeverity;
              const snakeSeverity = record.alert_severity;
              if (
                camelSeverity !== undefined && snakeSeverity !== undefined &&
                camelSeverity !== snakeSeverity
              ) return null;
              const severity = camelSeverity ?? snakeSeverity;
              if (
                typeof severity !== "string" ||
                !["LOW", "MEDIUM", "HIGH"].includes(severity)
              ) return null;
              return { alertSeverity: severity };
            };
            const normalizedCamel = camelDlp === undefined ? undefined : normalizeDlp(camelDlp);
            const normalizedSnake = snakeDlp === undefined ? undefined : normalizeDlp(snakeDlp);
            if (
              normalizedCamel === null || normalizedSnake === null ||
              (normalizedCamel !== undefined && normalizedSnake !== undefined &&
                canonicalJson(normalizedCamel) !== canonicalJson(normalizedSnake))
            ) return null;
            return { dlpRuleMetadata: normalizedCamel ?? normalizedSnake };
          };
          const camelMetadata = value.ruleTypeMetadata;
          const snakeMetadata = value.rule_type_metadata;
          if (camelMetadata !== undefined || snakeMetadata !== undefined) {
            const normalizedCamel = camelMetadata === undefined
              ? undefined
              : normalizeRuleTypeMetadata(camelMetadata);
            const normalizedSnake = snakeMetadata === undefined
              ? undefined
              : normalizeRuleTypeMetadata(snakeMetadata);
            if (
              normalizedCamel === null || normalizedSnake === null ||
              (normalizedCamel !== undefined && normalizedSnake !== undefined &&
                canonicalJson(normalizedCamel) !== canonicalJson(normalizedSnake))
            ) {
              this.lastDlpError =
                `response-invalid: ${kind} policy list contains invalid ruleTypeMetadata`;
              return null;
            }
            value.ruleTypeMetadata = normalizedCamel ?? normalizedSnake;
            delete value.rule_type_metadata;
          }
        }
        if (
          typeof record.policyQuery !== "object" || record.policyQuery === null ||
          Array.isArray(record.policyQuery)
        ) {
          this.lastDlpError = `response-invalid: ${kind} policy list contains an invalid policy query`;
          return null;
        }
        const policyQuery = normalizedCloudIdentityPolicyQuery(
          record.policyQuery as Record<string, unknown>,
        );
        if (policyQuery === null) {
          this.lastDlpError = `response-invalid: ${kind} policy list contains an invalid policy query`;
          return null;
        }
        result.push({
          name: record.name,
          displayName: raw,
          type: setting.type as string,
          value,
          policyQuery,
        });
      }

      let next: string | null;
      try {
        next = strictNextPageToken(payload, `${kind} policy list`);
      } catch (error) {
        this.lastDlpError = `pagination-incomplete: ${errorMessage(error)}`;
        return null;
      }
      if (next === null) {
        complete = true;
        break;
      }
      if (seenPageTokens.has(next)) {
        this.lastDlpError =
          `pagination-incomplete: ${kind} policy list repeated page token ${JSON.stringify(next)}`;
        return null;
      }
      seenPageTokens.add(next);
      pageToken = next;
    }
    if (!complete) {
      this.lastDlpError =
        `pagination-incomplete: ${kind} policy list still had a next page after 20 pages`;
      return null;
    }
    return result;
  }

  /**
   * Cloud Identity create is a long-running operation. A 2xx response with
   * `done: false` is only an acknowledgement, so do not let a dependent rule
   * run until the created policy is visible in the authoritative list.
   * Every poll goes through the shared one-QPS request path and the attempt
   * bound turns a stuck operation into an explicit failure.
   */
  private async waitForDlpPolicy(
    trace: CepTraceItem[],
    kind: "rule.dlp" | "detector",
    displayName: string,
    customerId: string,
    expectedValue: Record<string, unknown>,
    expectedQuery: Record<string, unknown>,
  ): Promise<{
    name: string;
    displayName: string;
    type: string;
    value: Record<string, unknown>;
    policyQuery: Record<string, unknown>;
  } | null> {
    for (let attempt = 1; attempt <= DLP_RECONCILIATION_MAX_ATTEMPTS; attempt += 1) {
      const policies = await this.listDlpPolicies(trace, kind, customerId);
      if (policies === null) return null;
      const matches = policies.filter((policy) => policy.displayName === displayName);
      if (matches.length > 1) {
        this.lastDlpError = `reserved-name-conflict: ${matches.length} policies use "${displayName}"`;
        return null;
      }
      const found = matches[0];
      if (found !== undefined) {
        if (
          found.type !== `settings/${kind}` ||
          canonicalJson(found.value) !== canonicalJson(expectedValue) ||
          canonicalJson(found.policyQuery) !== canonicalJson(expectedQuery)
        ) {
          this.lastDlpError =
            `reserved-name-conflict: policy "${displayName}" does not match the requested setting and OU query`;
          return null;
        }
        return found;
      }
    }
    this.lastDlpError =
      `the create operation was still incomplete after ` +
      `${DLP_RECONCILIATION_MAX_ATTEMPTS} rate-limited reconciliation checks`;
    return null;
  }

  /**
   * Starter rules covering the surfaces an evaluation usually wants to show.
   *
   * Two things are the operator's choice rather than ours. The national
   * identifier depends on where the tenant operates -- a US infoType detects
   * nothing in a Japanese tenant, and a rule that never fires looks the same as
   * one that works. And the action is per rule, because an evaluation normally
   * starts with a warning and tightens to blocking once the volume is understood.
   *
   * Watermarking lives here rather than in the Chrome policy table because it
   * is an action parameter on a rule, not a policy of its own.
   */
  private dlpRules(context: CepContext): Array<{
    id: CepDlpRuleId;
    operation: CepDlpOperation;
    displayName: string;
    description: string;
    triggers: string[];
    action: Exclude<CepDlpAction, "off">;
    condition?: Record<string, string>;
    actionParams?: Record<string, unknown>;
    requires?: "internalUrls";
    byodOnly: boolean;
  }> {
    const region = NATIONAL_ID_INFOTYPES[context.region] ?? NATIONAL_ID_INFOTYPES.US;
    const nationalIdCondition = region.infoTypes
      .map(
        (infoType) =>
          `all_content.matches_dlp_detector('${infoType}', google.privacy.dlp.v2.Likelihood.LIKELY, {minimum_match_count: 1, minimum_unique_match_count: 1})`,
      )
      .join(" || ");

    const bases: Array<{
      id: CepDlpRuleId;
      displayName: string;
      description: string;
      operations: readonly CepDlpOperation[];
      condition?: Record<string, string>;
      actionParams?: Record<string, unknown>;
      requires?: "internalUrls";
    }> = [
      {
        id: "universal_upload",
        displayName: `${DLP_PREFIX}Universal file upload protection`,
        description: "Inspects and warns/blocks all file uploads from Chrome.",
        operations: DLP_OPERATIONS_BY_RULE.universal_upload,
      },
      {
        id: "universal_download",
        displayName: `${DLP_PREFIX}Universal file download protection`,
        description: "Inspects and warns/blocks all file downloads in Chrome.",
        operations: DLP_OPERATIONS_BY_RULE.universal_download,
      },
      {
        id: "payment_card",
        displayName: `${DLP_PREFIX}Payment card numbers`,
        description: "Detects payment card numbers in Chrome content.",
        operations: DLP_OPERATIONS_BY_RULE.payment_card,
        condition: {
          contentCondition:
            "all_content.matches_dlp_detector('CREDIT_CARD_NUMBER', google.privacy.dlp.v2.Likelihood.LIKELY, {minimum_match_count: 1, minimum_unique_match_count: 1})",
        },
      },
      {
        id: "national_id",
        displayName: `${DLP_PREFIX}National ID numbers`,
        description: `Detects ${region.infoTypes.join(", ")} in Chrome content (${region.label}).`,
        operations: DLP_OPERATIONS_BY_RULE.national_id,
        condition: { contentCondition: nationalIdCondition },
      },
      {
        id: "watermark",
        displayName: `${DLP_PREFIX}Watermark internal pages`,
        description:
          "Allows navigation with a warning, overlays a watermark, and blocks screenshots on the listed internal sites.",
        operations: ["watermark"],
        condition: {
          contentCondition: context.internalUrls
            .map((url) => `url.starts_with(${JSON.stringify(url)})`)
            .join(" || "),
        },
        actionParams: { watermarkMessage: "Confidential", blockScreenshot: true },
        requires: "internalUrls",
      },
      {
        id: "genai_block",
        displayName: `${DLP_PREFIX}Consumer GenAI data protection`,
        description:
          "Controls uploads and paste to unapproved consumer GenAI services while allowing corporate Gemini.",
        operations: DLP_OPERATIONS_BY_RULE.genai_block,
        condition: {
          contentCondition:
            "url.contains('chatgpt.com') || url.contains('claude.ai') || url.contains('deepseek.com') || url.contains('poe.com') || url.contains('perplexity.ai') || url.contains('copilot.microsoft.com')",
        },
      },
    ];

    const resolved: Array<{
      id: CepDlpRuleId;
      operation: CepDlpOperation;
      displayName: string;
      description: string;
      triggers: string[];
      action: Exclude<CepDlpAction, "off">;
      condition?: Record<string, string>;
      actionParams?: Record<string, unknown>;
      requires?: "internalUrls";
      byodOnly: boolean;
    }> = [];

    for (const base of bases) {
      const matrixRule = context.dlpMatrix[base.id] ?? {};
      // A requested BYOD scope is reported separately by ensureRules. Never
      // broaden it silently into an all-device rule.
      if (matrixRule.byodOnly === true) continue;
      for (const operation of base.operations) {
        const selectedAction =
          operation === "watermark"
            ? matrixRule.watermark === true
              ? "warnUser"
              : "off"
            : matrixRule[operation];
        if (selectedAction === undefined || selectedAction === "off") continue;

        const operationLabel = operation === "watermark" ? "navigation" : operation;
        resolved.push({
          id: base.id,
          operation,
          displayName: `${base.displayName} - ${operationLabel}`,
          description: `${base.description} Operation: ${operationLabel}.`,
          triggers: [
            operation === "watermark"
              ? "google.workspace.chrome.url.v1.navigation"
              : DLP_OPERATION_TRIGGERS[operation],
          ],
          action: selectedAction,
          condition: base.condition,
          actionParams: base.actionParams,
          requires: base.requires,
          byodOnly: false,
        });
      }
    }
    return resolved;
  }

  private async ensureRules(
    trace: CepTraceItem[],
    context: CepContext,
    created: string[],
    skipped: string[],
  ): Promise<boolean> {
    let failed = false;
    if (context.dlpCustomerId === undefined) {
      skipped.push(
        "DLP rules: Directory customers.get did not return a canonical customer id beginning with C; no Cloud Identity policy was listed or created",
      );
      return false;
    }
    const existing = await this.listDlpPolicies(trace, "rule.dlp", context.dlpCustomerId);
    if (existing === null) {
      skipped.push(`DLP rules: ${this.lastDlpError}`);
      return false;
    }

    const operationKeys = ["upload", "download", "paste", "print"] as const;
    for (const [id, rule] of Object.entries(context.dlpMatrix) as Array<
      [CepDlpRuleId, CepDlpMatrixRuleConfig]
    >) {
      const selected =
        rule.watermark === true ||
        operationKeys.some((operation) => {
          const action = rule[operation];
          return action !== undefined && action !== "off";
        });
      if (!selected) continue;
      if (id === "access_level") {
        failed = true;
        skipped.push(
          "DLP unmanaged/BYOD rule: not created because the public Policy API documentation does not define a supported access-level CEL function",
        );
      } else if (rule.byodOnly === true) {
        failed = true;
        skipped.push(
          `DLP ${id} BYOD scope: not created because the public Policy API documentation does not define a supported access-level CEL function`,
        );
      }
    }

    for (const rule of this.dlpRules(context)) {
      if (rule.requires === "internalUrls" && context.internalUrls.length === 0) {
        skipped.push(`Rule "${rule.displayName}": needs at least one internal URL prefix`);
        failed = true;
        continue;
      }
      const value: Record<string, unknown> = {
        displayName: rule.displayName,
        description: rule.description,
        triggers: rule.triggers,
        state: "ACTIVE",
        action: {
          chromeAction:
            rule.actionParams === undefined
              ? { [rule.action]: {} }
              : { [rule.action]: { actionParams: rule.actionParams } },
        },
        ruleTypeMetadata: {
          dlpRuleMetadata: { alertSeverity: "LOW" },
        },
      };
      // Omitted entirely when absent: an empty sub-object is rejected.
      if (rule.condition !== undefined) value.condition = rule.condition;
      const policyQuery = this.policyQuery(context);
      const sameName = existing.filter((policy) => policy.displayName === rule.displayName);
      if (sameName.length > 0) {
        const exact = sameName.length === 1 &&
          sameName[0]!.type === "settings/rule.dlp" &&
          canonicalJson(sameName[0]!.value) === canonicalJson(value) &&
          canonicalJson(sameName[0]!.policyQuery) === canonicalJson(policyQuery);
        if (exact) {
          skipped.push(`Rule "${rule.displayName}" already exists and was reused`);
        } else {
          failed = true;
          skipped.push(
            `Rule "${rule.displayName}": reserved-name-conflict; ` +
              `${sameName.length} existing policy record(s) do not exactly match the requested setting and OU query`,
          );
        }
        continue;
      }

      const createLabel = `Create rule "${rule.displayName}"`;
      const createUrl = `${CLOUD_IDENTITY}/policies`;
      const createBody = {
          customer: `customers/${context.dlpCustomerId}`,
          type: "ADMIN",
          policyQuery,
          setting: { type: "settings/rule.dlp", value },
      };
      let createError: unknown;
      try {
        await this.request(this.transport, "POST", createUrl, createBody);
        trace.push({ label: createLabel, method: "POST", url: createUrl, status: 200, ok: true });
      } catch (error) {
        createError = error;
        trace.push({
          label: createLabel,
          method: "POST",
          url: createUrl,
          status: errorStatus(error) ?? 0,
          ok: false,
          error: errorMessage(error),
        });
      }

      if (createError !== undefined && isDefiniteCepMutationRejection(createError)) {
        failed = true;
        skipped.push(
          `Rule "${rule.displayName}": ${errorMessage(createError)}`,
        );
        continue;
      }

      // policies.create has no requestId and returns an Operation. Its response
      // (including an immediate resource name) is never ownership proof: only
      // the authoritative paged list can establish exactly one full semantic
      // match under the durable CEP lease.
      const confirmed = await this.waitForDlpPolicy(
        trace,
        "rule.dlp",
        rule.displayName,
        context.dlpCustomerId,
        value,
        policyQuery,
      );
      if (confirmed === null) {
        throw new CepMutationOutcomeAmbiguous(
          `Rule "${rule.displayName}" create outcome is ambiguous: ${this.lastDlpError}`,
        );
      }
      created.push(`DLP rule "${rule.displayName}" (${confirmed.name})`);
    }
    return !failed;
  }

  /**
   * Retain DLP resources unless durable ownership can be proven.
   *
   * A display-name prefix is not ownership: an earlier run may have reused a
   * matching policy, and another administrator can create the same prefix.
   * CEP ownership is not currently persisted with a customer/OU/settings
   * digest, so rollback must not issue a destructive DELETE.
   */
  private async retainUnownedDlpPolicies(
    trace: CepTraceItem[],
    skipped: string[],
    kinds: Array<"rule.dlp" | "detector">,
    customerId?: string,
  ): Promise<boolean> {
    if (customerId === undefined) {
      skipped.push(
        "DLP rollback: Directory customers.get did not return a canonical customer id beginning with C; no DLP policy was listed or deleted",
      );
      return true;
    }
    let retained = false;
    for (const kind of kinds) {
      const existing = await this.listDlpPolicies(trace, kind, customerId);
      if (existing === null) {
        retained = true;
        skipped.push(
          `${kind}: ownership could not be verified because the policy API could not be read ` +
            `(${this.lastDlpError}); no DLP policy was deleted`,
        );
        continue;
      }
      for (const policy of existing) {
        if (!policy.displayName.startsWith(DLP_PREFIX)) continue;
        if (!policy.type.includes(kind)) continue;
        retained = true;
        skipped.push(
          `Retained DLP ${kind === "detector" ? "detector" : "rule"} ` +
            `"${policy.displayName}" (${policy.name}): durable ownership metadata is unavailable`,
        );
      }
    }
    return retained;
  }

  /**
   * Turn the selected policy definitions into batchModify requests, dropping
   * any whose schema does not resolve.
   */
  private async resolvePolicies(
    config: CepProvisionConfig,
    context: CepContext,
    skipped: string[],
  ): Promise<ResolvedPolicy[]> {
    const resolved: ResolvedPolicy[] = [];
    for (const definition of selectedPolicies(config)) {
      const blocked = definition.requires?.(context) ?? null;
      if (blocked !== null) {
        skipped.push(`${definition.label}: ${blocked}`);
        continue;
      }

      const match = await this.resolveSchema(context.customerId, definition);
      if (match === null) {
        const nearby = await this.nearbySchemaNames(context.customerId, definition.schema);
        skipped.push(
          `${definition.label}: this tenant serves no policy schema matching ${definition.schema}` +
            (nearby.length > 0 ? `. Closest names available: ${nearby.join(", ")}` : ""),
        );
        continue;
      }

      const { name: schemaName, schema } = match;
      const available = schemaFields(schema);
      const value: Record<string, unknown> = {};
      const paths: string[] = [];
      const problems: string[] = [];

      for (const spec of definition.fields) {
        const field = available.find((entry) => matchesName(entry, spec.name));
        if (field === undefined || typeof field.name !== "string") {
          if (spec.optional !== true) problems.push(`no field matching ${String(spec.name)}`);
          continue;
        }

        // The schema decides the shape: the same setting is a boolean on one
        // tenant, an enum on another, and a nested message on a third.
        const chosen = buildFieldValue(
          schema,
          field,
          spec.enumHint,
          spec.value?.(context),
          3,
        );
        if (chosen === undefined) {
          if (spec.optional !== true) {
            problems.push(`no value could be built for ${describeField(schema, field)}`);
          }
          continue;
        }

        value[field.name] = chosen;
        paths.push(field.name);
      }

      if (paths.length === 0 || problems.length > 0) {
        // Describe what the schema does offer, with types and enum values, so
        // the next correction does not need another run against a live tenant.
        const description = available.map((field) => describeField(schema, field));
        skipped.push(
          `${definition.label}: ${schemaName} ` +
            (paths.length === 0
              ? "has none of the fields this policy sets"
              : problems.join("; ")) +
            (description.length > 0 ? `. It offers ${description.join(", ")}` : ""),
        );
        continue;
      }

      resolved.push({
        definition,
        request: {
          policyTargetKey: targetKey(context, definition),
          policyValue: { policySchema: schemaName, value },
          updateMask: paths.join(","),
        },
      });
    }
    return resolved;
  }

  private async buildContext(
    config: CepProvisionConfig | CepRollbackConfig,
    internalUrls: string[],
  ): Promise<CepContext> {
    const customerId = config.customer_id || "my_customer";
    const provision = config as CepProvisionConfig;
    const region = provision.dlp_region ?? "";
    const customer = await this.customerMetadata(customerId);
    return {
      customerId,
      dlpCustomerId: customer.dlpCustomerId,
      projectId: config.project_id,
      ouIds: { users: config.target_ou_id, browsers: config.target_ou_id },
      primaryDomain: customer.primaryDomain,
      internalUrls,
      region: NATIONAL_ID_INFOTYPES[region] === undefined ? "US" : region,
      dlpMatrix: resolveDlpMatrix(provision),
    };
  }

  // -- Provision --------------------------------------------------------------

  async provision(config: CepProvisionConfig): Promise<CepProvisionResult> {
    const trace: CepTraceItem[] = [];
    const created: string[] = [];
    const skipped: string[] = [];
    const internalUrls = (config.internal_urls ?? []).map((url) => url.trim()).filter(Boolean);
    const context = await this.buildContext(config, internalUrls);
    const failedModules = new Set<string>();

    if (config.create_sub_ous === true) {
      const childContext: CepContext = {
        ...context,
        ouIds: { ...context.ouIds },
      };
      const exactChildren = await this.resolveSubOrgUnits(
        trace,
        config,
        childContext,
        created,
        skipped,
        true,
      );
      if (!exactChildren) {
        return {
          success: false,
          message:
            "No policy was applied because both requested child organizational units could not be resolved exactly.",
          created_items: created,
          skipped_items: skipped,
          debug_trace: trace,
        };
      }
      skipped.push(
        `Sub OUs "${CEP_SUB_OU_NAMES.users}" and "${CEP_SUB_OU_NAMES.browsers}" were created or reused as optional scaffolding. Policies remain on the selected pilot OU so its current users and browsers are covered immediately; the children inherit those policies unless directly overridden, and no occupant was moved automatically.`,
      );
    }

    if (moduleEnabled(config, "contextAwareAccess")) {
      if (!(await this.resolveAccessLevel(
        trace,
        context,
        created,
        skipped,
        config.access_level ?? "",
      ))) {
        failedModules.add("contextAwareAccess");
      }
    }

    if (moduleEnabled(config, "dlpDetectors")) {
      skipped.push(
        "DLP URL-list detectors were not created: settings/detector.url_list is not supported by the Cloud Identity Policy mutation API. Internal URL prefixes are embedded as escaped CEL in supported rules instead.",
      );
      failedModules.add("dlpDetectors");
    }
    if (moduleEnabled(config, "dlpRules")) {
      if (!(await this.ensureRules(trace, context, created, skipped))) {
        failedModules.add("dlpRules");
      }
    }

    const requestedPolicies = selectedPolicies(config);
    let resolved: ResolvedPolicy[] = [];
    try {
      resolved = await this.resolvePolicies(config, context, skipped);
    } catch (error) {
      skipped.push(`Chrome policy schema catalogue: ${errorMessage(error)}; no unresolved Chrome policy was applied`);
    }
    for (const module of new Set(requestedPolicies.map((policy) => policy.module))) {
      const requestedCount = requestedPolicies.filter((policy) => policy.module === module).length;
      const resolvedCount = resolved.filter((item) => item.definition.module === module).length;
      if (resolvedCount !== requestedCount) failedModules.add(module);
    }
    if (resolved.length === 0 && created.length === 0) {
      return {
        success: false,
        message:
          skipped.length > 0
            ? "Nothing was applied. Every selected policy was skipped -- see the details below."
            : "Nothing was applied. Select at least one policy module first.",
        created_items: created,
        skipped_items: skipped,
        debug_trace: trace,
      };
    }

    // One batch per module: a rejected schema then costs that module rather
    // than the whole deployment, and the trace names which one it was.
    const byModule = new Map<CepModule, ResolvedPolicy[]>();
    for (const item of resolved) {
      const bucket = byModule.get(item.definition.module) ?? [];
      bucket.push(item);
      byModule.set(item.definition.module, bucket);
    }

    const url = `${CHROME_POLICY}/customers/${context.customerId}/policies/orgunits:batchModify`;
    for (const [module, items] of byModule) {
      const payload = await this.call(
        trace,
        `Apply ${module} policies (${items.length})`,
        "POST",
        url,
        { requests: items.map((item) => item.request) },
      );
      if (payload !== null) {
        for (const item of items) created.push(item.definition.label);
        continue;
      }

      // The batch names no policy, so "the connectors batch was rejected"
      // convicted all four. Re-send them one at a time: whatever the API
      // objects to belongs to a specific policy, and the others still apply.
      if (items.length === 1) {
        failedModules.add(module);
        skipped.push(`${items[0].definition.label}: ${trace[trace.length - 1]?.error ?? "rejected"}`);
        continue;
      }

      let moduleFailed = false;
      for (const item of items) {
        const before = trace.length;
        const single = await this.call(
          trace,
          `Apply ${item.definition.label}`,
          "POST",
          url,
          { requests: [item.request] },
        );
        if (single === null) {
          moduleFailed = true;
          skipped.push(`${item.definition.label}: ${trace[before]?.error ?? "rejected"}`);
          continue;
        }
        created.push(item.definition.label);
      }
      if (moduleFailed) failedModules.add(module);
    }

    const applied = created.length;
    const failures = failedModules.size;
    return {
      success: failures === 0,
      message:
        failures === 0
          ? `Applied ${applied} CEP setting${applied === 1 ? "" : "s"} to the target OU.`
          : `Applied ${applied} setting${applied === 1 ? "" : "s"}; ${failures} module${failures === 1 ? "" : "s"} failed. See the execution trace.`,
      created_items: created,
      skipped_items: skipped,
      debug_trace: trace,
    };
  }

  // -- Rollback ---------------------------------------------------------------

  /**
   * Inspect rollback candidates without mutating tenant state.
   *
   * CEP provision predates the run inventory and does not durably persist an
   * exact before/managed-after image per OU/schema/app target. Inheriting a
   * policy here could therefore erase a direct value that existed before CEP,
   * or a value another administrator wrote after provision. Until CEP has the
   * same three-way ownership ledger as deployment Apply, rollback is a
   * fail-closed inventory operation: resolve exact targets and retain them for
   * manual review.
   */
  async rollback(config: CepRollbackConfig): Promise<CepProvisionResult> {
    const trace: CepTraceItem[] = [];
    const removed: string[] = [];
    const skipped: string[] = [];
    const context = await this.buildContext(config, []);
    const modules = config.rollback_modules ?? [];
    const wanted = (module: CepModule): boolean =>
      modules.length === 0 || modules.includes(module);

    // New releases apply to the selected populated pilot OU. Older releases
    // could target the two children, so cleanup inventory inspects both without
    // assuming which release wrote a direct value.
    const childContext: CepContext = {
      ...context,
      ouIds: { ...context.ouIds },
    };
    await this.resolveSubOrgUnits(trace, config, childContext, [], [], false);
    const inspectionContexts = [context];
    if (
      childContext.ouIds.users !== context.ouIds.users ||
      childContext.ouIds.browsers !== context.ouIds.browsers
    ) {
      inspectionContexts.push(childContext);
    }

    const targets = CEP_POLICIES.filter((policy) => wanted(policy.module));
    const retainedChrome = targets.length > 0;
    let inspectedChromeTargets = 0;
    if (targets.length > 0) {
      for (const policy of targets) {
        const resolved = await this.resolveSchema(context.customerId, policy);
        const schemaName = resolved?.name ?? policy.schema;
        const seenKeys = new Set<string>();
        for (const targetContext of inspectionContexts) {
          const policyTargetKey = targetKey(targetContext, policy);
          const fingerprint = JSON.stringify(policyTargetKey);
          if (seenKeys.has(fingerprint)) continue;
          seenKeys.add(fingerprint);
          inspectedChromeTargets += 1;
          await this.call(
            trace,
            `Inspect rollback candidate ${policy.label}`,
            "POST",
            `${CHROME_POLICY}/customers/${context.customerId}/policies:resolve`,
            {
              policySchemaFilter: schemaName,
              policyTargetKey,
            },
          );
        }
      }
      skipped.push(
        `${inspectedChromeTargets} Chrome policy target${inspectedChromeTargets === 1 ? " was" : "s were"} retained: durable before/managed-after ownership is unavailable for CEP rollback`,
      );
    }

    // Inventory DLP candidates in dependency order. No DELETE is issued
    // without a durable CEP run ownership record.
    const dlpKinds: Array<"rule.dlp" | "detector"> = [];
    if (wanted("dlpRules")) dlpKinds.push("rule.dlp");
    if (wanted("dlpDetectors")) dlpKinds.push("detector");
    const retainedDlp =
      dlpKinds.length > 0
        ? await this.retainUnownedDlpPolicies(
            trace,
            skipped,
            dlpKinds,
            context.dlpCustomerId,
          )
        : false;

    const selectedLevel = config.access_level ?? "";
    if (wanted("contextAwareAccess") && selectedLevel.startsWith("AUTO_CREATE_")) {
      if (context.projectId === undefined) {
        skipped.push("Context-Aware Access: no project id, so no access level was looked for");
      } else {
        await this.retainSelectedAccessLevel(
          trace,
          context.projectId,
          selectedLevel,
          skipped,
        );
      }
    } else if (wanted("contextAwareAccess") && selectedLevel !== "" && selectedLevel !== "NONE") {
      skipped.push(
        `Context-Aware Access: ${selectedLevel} was selected rather than created here, so it was left in place`,
      );
    }

    // Deleting an OU that still holds users or browsers is refused by Google,
    // and deleting the operator's pilot group is not what rollback means.
    skipped.push(
      `Sub OUs "${CEP_SUB_OU_NAMES.users}" and "${CEP_SUB_OU_NAMES.browsers}" were left in place; remove them in the Admin Console if they are empty`,
    );

    const retained = retainedChrome || retainedDlp ||
      (wanted("contextAwareAccess") && selectedLevel.startsWith("AUTO_CREATE_"));
    return {
      success: !retained,
      message: retained
        ? "CEP rollback made no destructive change where durable ownership or a three-way before/managed-after image was unavailable. Review the retained targets and remove only verified-owned settings in the Admin consoles."
        : "No owned CEP mutation required rollback.",
      created_items: removed,
      skipped_items: skipped,
      debug_trace: trace,
    };
  }

  private async retainSelectedAccessLevel(
    trace: CepTraceItem[],
    projectId: string,
    selection: string,
    skipped: string[],
  ): Promise<void> {
    const kind = selectionToAccessLevelKind(selection);
    if (kind === null) {
      skipped.push(`Context-Aware Access: unknown auto-create selection ${selection}; nothing was deleted`);
      return;
    }

    let parentPayload = await this.call(
      trace,
      "Resolve Access Context Manager organization",
      "GET",
      `${CRM}/projects/${projectId}`,
      undefined,
      this.cloudTransport,
    );
    let parent = parentPayload?.parent;
    for (let depth = 0; depth < 20 && typeof parent === "string" && !parent.startsWith("organizations/"); depth += 1) {
      parentPayload = await this.call(
        trace,
        "Resolve Access Context Manager parent",
        "GET",
        `${CRM}/${parent}`,
        undefined,
        this.cloudTransport,
      );
      parent = parentPayload?.parent;
    }
    if (typeof parent !== "string" || !parent.startsWith("organizations/")) {
      skipped.push("Context-Aware Access: project organization could not be resolved; nothing was deleted");
      return;
    }

    let policyName: string | undefined;
    if (this.accessPolicyId !== undefined) {
      policyName = `accessPolicies/${this.accessPolicyId}`;
      const policy = await this.call(
        trace,
        "Read Access Context Manager policy",
        "GET",
        `${ACM}/${policyName}`,
        undefined,
        this.cloudTransport,
      );
      if (policy?.name !== policyName || policy.parent !== parent) {
        skipped.push("Context-Aware Access: configured policy did not match the project organization; nothing was deleted");
        return;
      }
    } else {
      const policies = await this.call(
        trace,
        "List Access Context Manager policies",
        "GET",
        `${ACM}/accessPolicies?parent=${encodeURIComponent(parent)}`,
        undefined,
        this.cloudTransport,
      );
      policyName = Array.isArray(policies?.accessPolicies) &&
          typeof policies.accessPolicies[0]?.name === "string"
        ? policies.accessPolicies[0].name
        : undefined;
    }
    if (policyName === undefined) {
      skipped.push("Context-Aware Access: no access policy was found; nothing was deleted");
      return;
    }

    const suffix =
      kind === "profile"
        ? "secgw_profile_managed"
        : kind === "browser"
        ? "secgw_browser_managed"
        : "secgw_chrome_managed";
    const name = `${policyName}/accessLevels/${suffix}`;

    const level = await this.call(
      trace,
      "Read auto-created access level",
      "GET",
      `${ACM}/${name}`,
      undefined,
      this.cloudTransport,
    );
    const expectedExpression =
      kind === "profile"
        ? "device.chrome.management_state == ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED"
        : kind === "browser"
        ? "device.chrome.management_state == ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED"
        : "device.chrome.management_state in [ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED, ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]";
    const expression = (((level?.custom as { expr?: { expression?: unknown } } | undefined)?.expr)
      ?.expression ?? "") as string;
    if (
      level?.name !== name ||
      level.description !== "Created automatically by Secure Gateway Studio" ||
      expression !== expectedExpression
    ) {
      skipped.push(
        `Context-Aware Access: ${name} was absent, not created by this tool, or edited; it was left in place`,
      );
      return;
    }

    skipped.push(
      `Context-Aware Access: ${name} matches the CEP template but has no durable run ownership marker; it was left in place`,
    );
  }

  // -- Workspace administrator roles -----------------------------------------

  /**
   * Kept only as a fail-closed response for older clients while the legacy
   * route is retired. Google Cloud custom IAM roles cannot grant Google
   * Workspace Chrome administrator privileges or OAuth scopes, so pretending
   * to provision those roles would report security access that does not exist.
   */
  async createCustomRoles(_config: CepCustomRoleConfig): Promise<CepRoleResult> {
    return {
      success: false,
      message:
        "Unsupported: Google Cloud custom IAM roles cannot grant Chrome Policy administrator access. Assign a scoped administrator role in the Google Admin console (Super Admin is required for Cloud Identity DLP mutations), then verify the real APIs from the CEP deployer.",
      roles: [],
      debug_trace: [],
    };
  }

  // -- License assignment -----------------------------------------------------

  /**
   * Assign Chrome Enterprise Premium licences to a bounded exact-OU pilot.
   */
  async assignLicenses(config: CepLicenseAssignConfig): Promise<CepLicenseAssignResult> {
    const trace: CepTraceItem[] = [];
    const customerId = config.customer_id || "my_customer";
    const productId = config.product_id || "101040";
    const skuId = config.sku_id || "1010400001";
    let targetPath = "";
    const boundedRequest = (
      method: string,
      url: string,
      options?: Parameters<Transport["requestJson"]>[2],
    ) => withinCepLicenseDeadline(
      this.transport.requestJson(method, url, options),
      method,
      url,
      this.licenseRequestTimeoutMs,
    );

    const failedResult = (message: string, errors: string[]): CepLicenseAssignResult => ({
      success: false,
      message,
      total_users: 0,
      assigned_count: 0,
      already_assigned_count: 0,
      failed_count: 0,
      assigned_users: [],
      errors,
      debug_trace: trace,
    });

    if (!config.target_ou_id) {
      return failedResult("ライセンス割り当てを開始できませんでした。", [
        "対象の組織部門IDが指定されていません。",
      ]);
    }

    // Never trust a caller-supplied path as the license-assignment boundary.
    // Resolve the immutable OU id immediately before listing users, and reject
    // a stale/mismatched path instead of silently assigning a different OU.
    try {
      const ouUrl =
        `${DIRECTORY}/customer/${encodeURIComponent(customerId)}` +
        "/orgunits?type=all_including_parent";
      const response = await boundedRequest("GET", ouUrl);
      if (response.status < 200 || response.status >= 300) {
        throw new Error(`HTTP ${response.status}`);
      }
      const units = parseDirectoryOrgUnits(response.payload);
      const found = units.find((u) => u.id === config.target_ou_id);
      if (found === undefined) {
        return failedResult("対象の組織部門を確認できなかったため、割り当てを中止しました。", [
          `組織部門ID ${config.target_ou_id} はDirectory APIの結果にありません。`,
        ]);
      }
      targetPath = found.path;
    } catch (error) {
      return failedResult("対象の組織部門を確認できなかったため、割り当てを中止しました。", [
        errorMessage(error),
      ]);
    }

    if (
      config.target_ou_path !== undefined &&
      config.target_ou_path !== "" &&
      config.target_ou_path !== targetPath
    ) {
      return failedResult("対象の組織部門情報が変更されたため、割り当てを中止しました。", [
        `指定されたOUパス ${config.target_ou_path} はDirectory APIの現在値 ${targetPath} と一致しません。OU一覧を再読み込みしてください。`,
      ]);
    }

    if (!targetPath.startsWith("/")) {
      return failedResult("対象の組織部門パスが不正なため、割り当てを中止しました。", [
        `Directory API形式の絶対OUパスではありません: ${targetPath}`,
      ]);
    }

    const usersByEmail = new Map<string, { primaryEmail: string }>();
    let pageToken = "";
    const seenPageTokens = new Set<string>();
    const query = `orgUnitPath='${targetPath.replace(/'/g, "\\'")}'`;
    let directoryComplete = false;

    for (let page = 0; page < CEP_LICENSE_DIRECTORY_PAGE_LIMIT; page += 1) {
      const queryParam =
        `customer=${encodeURIComponent(customerId)}` +
        `&query=${encodeURIComponent(query)}` +
        "&viewType=admin_view&projection=full&maxResults=500" +
        `${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ""}`;
      const url = `${DIRECTORY}/users?${queryParam}`;
      let payload: Record<string, unknown>;
      try {
        const response = await boundedRequest("GET", url);
        if (response.status < 200 || response.status >= 300) {
          throw new Error(`HTTP ${response.status}`);
        }
        payload = response.payload;
        trace.push({
          label: `List users in OU ${targetPath}`,
          method: "GET",
          url,
          status: response.status,
          ok: true,
        });
      } catch (error) {
        trace.push({
          label: `List users in OU ${targetPath}`,
          method: "GET",
          url,
          status: 0,
          ok: false,
          error: errorMessage(error),
        });
        return failedResult("OU内のユーザー一覧を取得できなかったため、割り当てを中止しました。", [
          errorMessage(error),
        ]);
      }
      if (!Array.isArray(payload.users)) {
        return failedResult("OU内のユーザー一覧が不正なため、割り当てを中止しました。", [
          "Directory APIのusersフィールドが配列ではありません。",
        ]);
      }
      const rawUsers = payload.users;
      for (const u of rawUsers) {
        if (u === null || typeof u !== "object") {
          return failedResult("OU内のユーザー情報が不正なため、割り当てを中止しました。", [
            "Directory APIがオブジェクトではないユーザーを返しました。",
          ]);
        }
        const record = u as { primaryEmail?: unknown; orgUnitPath?: unknown };
        const email = typeof record.primaryEmail === "string"
          ? record.primaryEmail.trim()
          : "";
        const userPath = record.orgUnitPath;
        if (
          !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) ||
          typeof userPath !== "string" ||
          !userPath.startsWith("/")
        ) {
          return failedResult("OU内のユーザー情報が不正なため、割り当てを中止しました。", [
            "Directory APIのprimaryEmailまたはorgUnitPathが欠落・不正です。",
          ]);
        }
        // Directory's orgUnitPath query includes every descendant OU. Licence
        // assignment is intentionally bounded to the exact selected OU.
        if (userPath === targetPath) {
          const key = email.toLowerCase();
          if (!usersByEmail.has(key)) usersByEmail.set(key, { primaryEmail: email });
        }
      }
      if (usersByEmail.size > CEP_LICENSE_PILOT_USER_LIMIT) {
        return {
          success: false,
          message:
            `組織部門「${targetPath}」にはパイロット上限の ` +
            `${CEP_LICENSE_PILOT_USER_LIMIT} 名を超えるユーザーがいるため、` +
            "ライセンスは1件も割り当てませんでした。",
          total_users: usersByEmail.size,
          assigned_count: 0,
          already_assigned_count: 0,
          failed_count: 0,
          assigned_users: [],
          errors: [
            `この操作は正確なOUに所属する最大${CEP_LICENSE_PILOT_USER_LIMIT}名の` +
              "非本番パイロット専用です。対象OUを小さくして再試行してください。",
          ],
          debug_trace: trace,
        };
      }
      let next: string | null;
      try {
        next = strictNextPageToken(payload, "Directory users list");
      } catch (error) {
        return failedResult("OU内のユーザー一覧を最後まで取得できなかったため、割り当てを中止しました。", [
          errorMessage(error),
        ]);
      }
      if (next === null) {
        directoryComplete = true;
        break;
      }
      if (seenPageTokens.has(next)) {
        return failedResult("OU内のユーザー一覧を最後まで取得できなかったため、割り当てを中止しました。", [
          "Directory APIが同じページトークンを繰り返しました。",
        ]);
      }
      seenPageTokens.add(next);
      pageToken = next;
    }
    if (!directoryComplete) {
      return failedResult("OU内のユーザー一覧を最後まで取得できなかったため、割り当てを中止しました。", [
        `Directory APIのユーザー一覧が${CEP_LICENSE_DIRECTORY_PAGE_LIMIT}ページ以内に` +
          "完了しませんでした。部分結果には割り当てません。",
      ]);
    }
    const users = [...usersByEmail.values()];

    if (users.length === 0) {
      return {
        success: false,
        message: `組織部門「${targetPath}」内にユーザーが見つからなかったため、割り当てを行いませんでした。`,
        total_users: 0,
        assigned_count: 0,
        already_assigned_count: 0,
        failed_count: 0,
        assigned_users: [],
        errors: ["対象OUにライセンス割り当て可能なユーザーが存在することを確認してください。"],
        debug_trace: trace,
      };
    }

    let assignedCount = 0;
    let alreadyAssignedCount = 0;
    let failedCount = 0;
    const assignedUsers: string[] = [];
    const errors: string[] = [];

    const LICENSING = "https://licensing.googleapis.com/apps/licensing/v1";

    const exactLicenseAssignment = (
      payload: Record<string, unknown>,
      userEmail: string,
    ): boolean => {
      try {
        validateLicenseAssignment(payload, { productId, skuId, userId: userEmail });
        return true;
      } catch {
        return false;
      }
    };

    for (const user of users) {
      const collectionUrl = `${LICENSING}/product/${productId}/sku/${skuId}/user`;
      const assignmentUrl = `${collectionUrl}/${encodeURIComponent(user.primaryEmail)}`;
      const readAssignment = async (): Promise<"missing" | "exact"> => {
        const current = await boundedRequest("GET", assignmentUrl, {
          acceptedStatuses: [404],
        });
        if (current.status === 404) return "missing";
        if (
          current.status >= 200 && current.status < 300 &&
          exactLicenseAssignment(current.payload, user.primaryEmail)
        ) {
          return "exact";
        }
        throw new Error(
          current.status >= 200 && current.status < 300
            ? "license-assignment-identity-mismatch"
            : `HTTP ${current.status}`,
        );
      };
      try {
        const current = await readAssignment();
        if (current === "exact") {
          alreadyAssignedCount += 1;
          trace.push({
            label: `License for ${user.primaryEmail} already assigned`,
            method: "GET",
            url: assignmentUrl,
            status: 200,
            ok: true,
          });
          continue;
        }

        let status = 0;
        let payload: Record<string, unknown> = {};
        let postError: unknown;
        let postLeaseFence = false;
        try {
          const response = await boundedRequest("POST", collectionUrl, {
            jsonBody: { userId: user.primaryEmail },
            // These statuses do not prove non-application. They are returned
            // to this state machine so it can reconcile with exact GET.
            acceptedStatuses: [408, 412, 429, 500, 502, 503, 504],
          });
          status = response.status;
          payload = response.payload;
        } catch (error) {
          postError = error;
          postLeaseFence =
            (error as { cepMutationLeaseFence?: unknown }).cepMutationLeaseFence === true;
          const errorStatus = (error as { status?: unknown }).status;
          if (
            typeof errorStatus === "number" && errorStatus >= 400 && errorStatus < 500 &&
            ![408, 412, 429].includes(errorStatus)
          ) {
            throw error;
          }
        }
        const postOutcomeAmbiguous =
          !postLeaseFence &&
          (postError instanceof CepLicenseRequestTimeout ||
            postError !== undefined ||
            [408, 500, 502, 503, 504].includes(status));

        if (
          status >= 200 && status < 300 &&
          exactLicenseAssignment(payload, user.primaryEmail)
        ) {
          assignedCount += 1;
          assignedUsers.push(user.primaryEmail);
          trace.push({
            label: `Assign CEP license to ${user.primaryEmail}`,
            method: "POST",
            url: collectionUrl,
            status,
            ok: true,
          });
          continue;
        }

        // A 412, 5xx, timeout, or response loss is ambiguous. Only the exact
        // user/product/SKU read proves success; a missing or mismatched row is
        // a failure and is never relabelled as "already assigned" by message.
        let reconciled: "missing" | "exact";
        try {
          reconciled = await readAssignment();
        } catch (error) {
          if (postOutcomeAmbiguous) {
            throw new CepMutationOutcomeAmbiguous(
              `The CEP licence POST for ${user.primaryEmail} had no confirmed response, ` +
                `and exact reconciliation could not complete (${errorMessage(error)}).`,
            );
          }
          throw error;
        }
        if (reconciled !== "exact") {
          const detail = postError === undefined
            ? ((payload.error as { message?: string } | undefined)?.message ?? `HTTP ${status}`)
            : errorMessage(postError);
          if (postOutcomeAmbiguous) {
            throw new CepMutationOutcomeAmbiguous(
              `The CEP licence POST for ${user.primaryEmail} may have committed, ` +
                `but an exact product/SKU/user assignment is not visible yet (${detail}).`,
            );
          }
          throw new Error(`license-assignment-not-confirmed: ${detail}`);
        }
        assignedCount += 1;
        assignedUsers.push(user.primaryEmail);
        trace.push({
          label: `Reconcile CEP license for ${user.primaryEmail}`,
          method: "GET",
          url: assignmentUrl,
          status: 200,
          ok: true,
        });
      } catch (err) {
        if (err instanceof CepMutationOutcomeAmbiguous) throw err;
        failedCount += 1;
        const msg = errorMessage(err);
        errors.push(`${user.primaryEmail}: ${msg}`);
        trace.push({
          label: `Exception assigning license to ${user.primaryEmail}`,
          method: "GET",
          url: assignmentUrl,
          status: 0,
          ok: false,
          error: msg,
        });
      }
    }

    const message = `組織部門「${targetPath}」内のユーザー ${users.length} 名の処理が完了しました（新規割り当て: ${assignedCount} 名、割り当て済み: ${alreadyAssignedCount} 名${failedCount > 0 ? `、失敗: ${failedCount} 名` : ""}）。`;

    return {
      success:
        failedCount === 0 && assignedCount + alreadyAssignedCount === users.length,
      message,
      total_users: users.length,
      assigned_count: assignedCount,
      already_assigned_count: alreadyAssignedCount,
      failed_count: failedCount,
      assigned_users: assignedUsers,
      errors,
      debug_trace: trace,
    };
  }

  // -- Script export ----------------------------------------------------------

  /**
   * A standalone script for the Chrome Policy portion of the selected setup.
   *
   * Resolved against the live schemas rather than hardcoded, so the exported
   * file and the one-click Chrome Policy path cannot disagree -- the previous
   * version emitted the same four policies no matter what was selected. Cloud
   * Identity DLP, Access Context Manager, OU creation, and licence assignment
   * use different APIs and are deliberately not represented by this export.
   */
  async generatePythonScript(config: CepProvisionConfig): Promise<string> {
    const internalUrls = (config.internal_urls ?? []).map((url) => url.trim()).filter(Boolean);
    const context = await this.buildContext(config, internalUrls);
    const skipped: string[] = [];
    const resolved = await this.resolvePolicies(config, context, skipped);

    const requestGroups = groupPolicyRequests(resolved.map((item) => item.request));
    const notes = skipped.length > 0 ? `\n\nNot included:\n  - ${skipped.join("\n  - ")}` : "";

    return `#!/usr/bin/env python3
"""
Chrome Enterprise Premium configuration for organizational unit ${context.ouIds.users}.
Generated by Secure Gateway Studio from the options selected in the UI.

The policy values below were resolved against this tenant's live Chrome Policy
schemas at export time.${notes}

Usage:
  pip install google-auth google-api-python-client
  gcloud auth application-default login \\
    --scopes=https://www.googleapis.com/auth/chrome.management.policy
  python cep_configure.py
"""

import json

import google.auth
from googleapiclient.discovery import build

CUSTOMER_ID = ${pythonLiteral(context.customerId)}
REQUEST_GROUPS = ${pythonLiteral(requestGroups)}


def main() -> None:
    if not REQUEST_GROUPS:
        print("[!] Nothing to apply: no policy modules were selected.")
        return

    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/chrome.management.policy"]
    )
    service = build("chromepolicy", "v1", credentials=credentials)

    total = sum(len(requests) for requests in REQUEST_GROUPS)
    applied = 0
    print(f"[*] Applying {total} policies to customer {CUSTOMER_ID}...")
    for index, requests in enumerate(REQUEST_GROUPS, start=1):
        try:
            response = (
                service.customers()
                .policies()
                .orgunits()
                .batchModify(customer=f"customers/{CUSTOMER_ID}", body={"requests": requests})
                .execute()
            )
        except Exception as error:
            raise RuntimeError(
                f"Stopped after {applied}/{total} policies: target-compatible "
                f"batch {index}/{len(REQUEST_GROUPS)} failed; later batches were not attempted."
            ) from error
        applied += len(requests)
        print(f"[+] Applied batch {index}/{len(REQUEST_GROUPS)} ({len(requests)} policies).")
        print(json.dumps(response, indent=2))


if __name__ == "__main__":
    main()
`;
  }
}

/**
 * Render a value as a Python literal.
 *
 * Emitted structurally rather than by post-processing JSON text: a URL
 * containing the word "null" is a string, not a literal, and a search-replace
 * over the serialised form cannot tell the difference. String escaping goes
 * through `JSON.stringify`, so an org unit id or domain carrying a quote cannot
 * break out -- the previous version interpolated both straight into the source.
 */
function pythonLiteral(value: unknown, indent = 0): string {
  const pad = " ".repeat(indent + 4);
  const closePad = " ".repeat(indent);
  if (value === null || value === undefined) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    const items = value.map((item) => `${pad}${pythonLiteral(item, indent + 4)}`);
    return `[\n${items.join(",\n")},\n${closePad}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) return "{}";
  const rendered = entries.map(
    ([key, item]) => `${pad}${JSON.stringify(key)}: ${pythonLiteral(item, indent + 4)}`,
  );
  return `{\n${rendered.join(",\n")},\n${closePad}}`;
}
