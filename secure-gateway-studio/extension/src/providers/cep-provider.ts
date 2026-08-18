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
 * DLP detectors and rules are a second surface entirely: Cloud Identity
 * policies, where the DLP shape is carried in a free-form `setting.value`
 * struct rather than in the discovery document -- which is why grepping that
 * document for "dlp" finds nothing and suggests, wrongly, that no API exists.
 *
 * Two things about that API are easy to get wrong and are handled below: it
 * answers HTTP 200 with an error code in the body, and an empty sub-object
 * anywhere in the request is rejected outright.
 */

import { ensureManagedChromeAccessLevel } from "./catalog.ts";
import type { Transport } from "./executor.ts";

const CHROME_POLICY = "https://chromepolicy.googleapis.com/v1";
const DIRECTORY = "https://admin.googleapis.com/admin/directory/v1";
const IAM = "https://iam.googleapis.com/v1";
const CRM = "https://cloudresourcemanager.googleapis.com/v1";
const ACM = "https://accesscontextmanager.googleapis.com/v1";
/** DLP rules and detectors. Mutations are v1beta1; reads are GA on v1. */
const CLOUD_IDENTITY = "https://cloudidentity.googleapis.com/v1beta1";

/** Display-name prefix that marks a rule or detector as ours to roll back. */
const DLP_PREFIX = "CEP PoC - ";

export type CepDlpRuleId =
  | "universal_upload"
  | "universal_download"
  | "payment_card"
  | "national_id"
  | "access_level"
  | "watermark"
  | "genai_block";

/** What a rule does when it matches. `off` means do not create it. */
export type CepDlpAction = "off" | "auditOnly" | "warnUser" | "blockContent";

export type CepDlpOperation = "upload" | "download" | "paste" | "print" | "watermark";

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

/** The policy API allows one list per second per customer. */
const LIST_MIN_INTERVAL_MS = 1100;

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
  target_ou_id: string;
  target_ou_path?: string;
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

export interface CepRollbackConfig {
  customer_id: string;
  target_ou_id: string;
  target_ou_path?: string;
  /** Compare live state before deleting anything we created. Default on. */
  verify_match?: boolean;
  /** Restrict the rollback to these modules. Empty or absent means all. */
  rollback_modules?: CepModule[];
  /**
   * What provision was given. Only an `AUTO_CREATE_*` level is ours to delete;
   * a level the operator selected belongs to them and is left alone.
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
  constructor(status: number, message: string) {
    super(message);
    this.name = "CepApiError";
    this.status = status;
  }
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
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
  projectId?: string;
  /** Org unit ids the policies target, per scope. */
  ouIds: Record<CepOu, string>;
  primaryDomain?: string;
  internalUrls: string[];
  region: string;
  ruleActions: Partial<Record<CepDlpRuleId, CepDlpAction>>;
  accessLevelName?: string;
  /** True only when this run created it, which is what rollback may delete. */
  accessLevelIsOurs?: boolean;
  /** `policies/<id>` of the URL-list detector, once it exists. */
  internalSitesDetector?: string;
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
    label: "Restrict secondary sign-in to the corporate domain",
    schema: "chrome.users.RestrictAccountsToPatterns",
    appliesTo: (config) => config.data_boundary_mode === "copy_paste",
    requires: requiresDomain,
    fields: [{ name: /restrictAccountsToPatterns/i, value: (c) => [`*@${c.primaryDomain}`] }],
  },
  {
    module: "dataBoundary",
    ou: "users",
    label: "Block non-corporate Google accounts in apps",
    schema: "chrome.users.AllowedDomainsForApps",
    appliesTo: (config) => config.data_boundary_mode === "block_non_corp",
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
    appliesTo: (config) =>
      config.dlp_rule_actions?.genai_block !== undefined &&
      config.dlp_rule_actions.genai_block !== "off",
    fields: [
      {
        name: /urlBlocklist/i,
        value: () => [
          "*chatgpt.com*",
          "*claude.ai*",
          "*deepseek.com*",
          "*poe.com*",
          "*perplexity.ai*",
          "*copilot.microsoft.com*",
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
    appliesTo: (config) =>
      config.dlp_rule_actions?.genai_block !== undefined &&
      config.dlp_rule_actions.genai_block !== "off",
    fields: [
      {
        name: /urlAllowlist/i,
        value: () => [
          "*gemini.google.com*",
          "*workspace.google.com*",
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

interface ResolvedPolicy {
  definition: CepPolicyDefinition;
  request: {
    policyTargetKey: Record<string, unknown>;
    policyValue: { policySchema: string; value: Record<string, unknown> };
    updateMask: { paths: string[] };
  };
}

export class CepProvider {
  private readonly schemaCache = new Map<string, PolicySchemaShape | null>();
  private schemaCatalogueCache: Map<string, PolicySchemaShape> | null = null;
  /** Directory, Chrome Policy, Cloud Identity: authorized as a Workspace admin. */
  private readonly transport: Transport;
  /** IAM, Resource Manager, Access Context Manager: authorized as the deployer. */
  private readonly cloudTransport: Transport;
  private lastListAt = 0;

  // Assigned rather than declared as parameter properties: node's
  // type-stripping loader, which the verify scripts run under, rejects those.
  constructor(transport: Transport, cloudTransport?: Transport) {
    this.transport = transport;
    this.cloudTransport = cloudTransport ?? transport;
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
    const { status, payload } = await transport.requestJson(
      method,
      url,
      body === undefined ? {} : { jsonBody: body },
    );
    if (status < 200 || status >= 300) {
      const detail = payload.error as { message?: string } | undefined;
      throw new CepApiError(status, detail?.message ?? `HTTP ${status}`);
    }
    const embedded = payload.error as { code?: number; message?: string } | undefined;
    if (embedded !== undefined && embedded.code !== undefined) {
      throw new CepApiError(status, embedded.message ?? rpcCodeMeaning(embedded.code));
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
    for (let page = 0; page < 40; page += 1) {
      const query = pageToken === "" ? "" : `&pageToken=${encodeURIComponent(pageToken)}`;
      let payload: Record<string, unknown>;
      try {
        payload = await this.request(
          this.transport,
          "GET",
          `${CHROME_POLICY}/customers/${customerId}/policySchemas?pageSize=1000${query}`,
        );
      } catch {
        break;
      }
      const schemas = Array.isArray(payload.policySchemas) ? payload.policySchemas : [];
      for (const item of schemas) {
        const record = item as PolicySchemaShape & { schemaName?: string; name?: string };
        // `schemaName` is the bare name; `name` is the full resource path.
        const bare =
          record.schemaName ??
          (typeof record.name === "string"
            ? record.name.replace(/^customers\/[^/]+\/policySchemas\//, "")
            : undefined);
        if (typeof bare === "string" && bare !== "") catalogue.set(bare, record);
      }
      const next = payload.nextPageToken;
      if (typeof next !== "string" || next === "") break;
      pageToken = next;
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

  /** The tenant's primary domain, which the data-boundary policies are written from. */
  private async primaryDomain(customerId: string): Promise<string | undefined> {
    try {
      const payload = await this.request(
        this.transport,
        "GET",
        `${DIRECTORY}/customers/${customerId}`,
      );
      const domain = payload.customerDomain;
      return typeof domain === "string" && domain !== "" ? domain : undefined;
    } catch {
      return undefined;
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
    const units = Array.isArray(payload.organizationUnits) ? payload.organizationUnits : [];
    const result: Array<{ id: string; path: string; name: string }> = [];
    for (const item of units) {
      const record = item as Record<string, unknown>;
      const rawId = record.orgUnitId;
      const path = record.orgUnitPath;
      if (typeof rawId !== "string" || typeof path !== "string") continue;
      // The Directory API returns `id:03abc…`; policy targets want the bare id.
      result.push({ id: rawId.replace(/^id:/, ""), path, name: String(record.name ?? "") });
    }
    return result;
  }

  /**
   * Resolve the two sub OUs, creating them when asked to.
   *
   * User-scoped and browser-scoped policies want different homes, which is the
   * whole point of the pair. When they are not created, both scopes fall back
   * to the selected OU so the deployment still lands somewhere real.
   */
  private async resolveSubOrgUnits(
    trace: CepTraceItem[],
    config: CepProvisionConfig | CepRollbackConfig,
    context: CepContext,
    created: string[],
    skipped: string[],
    create: boolean,
  ): Promise<void> {
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
      return;
    }

    const parentPath =
      config.target_ou_path ?? units.find((unit) => unit.id === config.target_ou_id)?.path;
    if (parentPath === undefined) {
      skipped.push(
        "Sub OUs: the selected OU's path could not be resolved, so policies target it directly",
      );
      return;
    }

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
        skipped.push(`Sub OU "${name}" could not be created; policies target the selected OU`);
        continue;
      }
      const rawId = payload.orgUnitId;
      if (typeof rawId === "string") {
        context.ouIds[scope] = rawId.replace(/^id:/, "");
        created.push(`Organizational unit "${name}"`);
      }
    }
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
   * `ensureManagedChromeAccessLevel` already resolves the ACM policy, writes
   * the CEL expression, and reuses a level it finds, so the auto-create path
   * does not reimplement any of that.
   */
  private async resolveAccessLevel(
    trace: CepTraceItem[],
    context: CepContext,
    created: string[],
    skipped: string[],
    selection: string,
  ): Promise<void> {
    if (!selection.startsWith("AUTO_CREATE_")) {
      // A level the operator selected. Nothing to create, nothing to own.
      context.accessLevelName = selection;
      context.accessLevelIsOurs = false;
      return;
    }

    if (!context.projectId) {
      skipped.push(
        "Context-Aware Access: creating a level needs a Google Cloud project. Pick an existing access level instead, or set a project on the setup screen.",
      );
      return;
    }

    const kind = selection.includes("BROWSER")
      ? "browser"
      : selection.includes("ANY")
      ? "any"
      : "profile";
    try {
      const name = await ensureManagedChromeAccessLevel(
        this.cloudTransport,
        context.projectId,
        kind,
      );
      context.accessLevelName = name;
      context.accessLevelIsOurs = true;
      trace.push({
        label: "Ensure Context-Aware Access level",
        method: "POST",
        url: `${ACM}/${name}`,
        status: 200,
        ok: true,
      });
      created.push(`Context-Aware Access level (${name})`);
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
    }
  }

  // -- DLP detectors and rules ------------------------------------------------

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
   * duplicates, and rollback knows what is ours to delete.
   *
   * List is rate limited to 1 QPS per customer, so this runs once per kind and
   * the result is passed around rather than re-fetched.
   */
  private lastDlpError = "";

  private async listDlpPolicies(
    trace: CepTraceItem[],
    kind: "rule.dlp" | "detector",
  ): Promise<Array<{ name: string; displayName: string; type: string }> | null> {
    // Documented at 1 QPS per customer, and provision and rollback both list
    // twice in a row. Without this the second call comes back 429.
    const sinceLastList = Date.now() - this.lastListAt;
    if (this.lastListAt !== 0 && sinceLastList < LIST_MIN_INTERVAL_MS) {
      await new Promise((resolve) => setTimeout(resolve, LIST_MIN_INTERVAL_MS - sinceLastList));
    }
    this.lastListAt = Date.now();

    const filter = encodeURIComponent(`setting.type.matches("${kind}")`);
    const result: Array<{ name: string; displayName: string; type: string }> = [];
    let pageToken = "";

    // Paged, because the default page is 50 and a tenant with more policies
    // than that would hide ours -- which reads as "not created yet" and makes
    // the next run create a duplicate.
    for (let page = 0; page < 20; page += 1) {
      const query = pageToken === "" ? "" : `&pageToken=${encodeURIComponent(pageToken)}`;
      const url = `${CLOUD_IDENTITY}/policies?pageSize=200&filter=${filter}${query}`;
      const before = trace.length;
      const payload = await this.call(trace, `List ${kind} policies`, "GET", url);
      if (payload === null) {
        this.lastDlpError = trace[before]?.error ?? "the policy API could not be reached";
        return null;
      }

      const policies = Array.isArray(payload.policies) ? payload.policies : [];
      for (const item of policies) {
        const record = item as Record<string, unknown>;
        const setting = (record.setting ?? {}) as {
          type?: string;
          value?: Record<string, unknown>;
        };
        // `setting.value` is a free-form struct, so its keys come back exactly
        // as whoever wrote them spelled them. Reading only camelCase missed
        // every rule and duplicated the whole set on the second run.
        const raw = setting.value?.displayName ?? setting.value?.display_name;
        if (typeof record.name !== "string" || typeof raw !== "string") continue;
        result.push({ name: record.name, displayName: raw, type: setting.type ?? "" });
      }

      const next = payload.nextPageToken;
      if (typeof next !== "string" || next === "") break;
      pageToken = next;
    }
    return result;
  }

  /**
   * The URL-list detector the rules below exempt, built from the internal
   * sites the operator typed in.
   */
  private async ensureDetectors(
    trace: CepTraceItem[],
    context: CepContext,
    created: string[],
    skipped: string[],
  ): Promise<void> {
    if (context.internalUrls.length === 0) {
      skipped.push(
        "Internal Sites detector: no internal URLs were entered, so there is nothing to match",
      );
      return;
    }

    const existing = await this.listDlpPolicies(trace, "detector");
    if (existing === null) {
      skipped.push(`DLP detectors: ${this.lastDlpError}`);
      return;
    }

    const displayName = `${DLP_PREFIX}Internal Sites`;
    const found = existing.find((policy) => policy.displayName === displayName);
    if (found !== undefined) {
      context.internalSitesDetector = found.name;
      skipped.push(`Detector "${displayName}" already exists and was reused`);
      return;
    }

    const beforeCreate = trace.length;
    const payload = await this.call(
      trace,
      `Create detector "${displayName}"`,
      "POST",
      `${CLOUD_IDENTITY}/policies`,
      {
        customer: `customers/${context.customerId}`,
        type: "ADMIN",
        policyQuery: this.policyQuery(context),
        setting: {
          type: "settings/detector.url_list",
          value: {
            displayName,
            description: "Internal sites exempted from CEP evaluation rules.",
            urlList: { urls: context.internalUrls },
          },
        },
      },
    );
    if (payload === null) {
      skipped.push(
        `Detector "${displayName}": ${trace[beforeCreate]?.error ?? "could not be created"}`,
      );
      return;
    }
    const response = (payload.response ?? payload) as { name?: string };
    if (typeof response.name === "string") context.internalSitesDetector = response.name;
    created.push(`DLP detector "${displayName}"`);
  }

  /**
   * Starter rules covering the surfaces an evaluation usually wants to show.
   *
   * Two things are the operator's choice rather than ours. The national
   * identifier depends on where the tenant operates -- a US infoType detects
   * nothing in a Japanese tenant, and a rule that never fires looks the same as
   * one that works. And the action is per rule, because an evaluation normally
   * starts by auditing and tightens to blocking once the volume is understood.
   *
   * Watermarking lives here rather than in the Chrome policy table because it
   * is an action parameter on a rule, not a policy of its own.
   */
  private dlpRules(context: CepContext): Array<{
    id: CepDlpRuleId;
    displayName: string;
    description: string;
    triggers: string[];
    condition?: Record<string, string>;
    actionParams?: Record<string, unknown>;
    requires?: "internalSites" | "accessLevel";
  }> {
    const region = NATIONAL_ID_INFOTYPES[context.region] ?? NATIONAL_ID_INFOTYPES.US;
    const nationalIdCondition = region.infoTypes
      .map(
        (infoType) =>
          `all_content.matches_dlp_detector('${infoType}', google.privacy.dlp.v2.Likelihood.LIKELY, {minimum_match_count: 1, minimum_unique_match_count: 1})`,
      )
      .join(" || ");

    return [
      {
        id: "universal_upload",
        displayName: `${DLP_PREFIX}Universal file upload protection`,
        description: "Inspects and audits/blocks all file uploads from Chrome.",
        triggers: ["google.workspace.chrome.file.v1.upload"],
      },
      {
        id: "universal_download",
        displayName: `${DLP_PREFIX}Universal file download protection`,
        description: "Inspects and audits/blocks all file downloads in Chrome.",
        triggers: ["google.workspace.chrome.file.v1.download"],
      },
      {
        id: "payment_card",
        displayName: `${DLP_PREFIX}Payment card numbers in uploads and paste`,
        description: "Detects payment card numbers in files uploaded and content pasted from Chrome.",
        triggers: [
          "google.workspace.chrome.file.v1.upload",
          "google.workspace.chrome.web_content.v1.upload",
        ],
        condition: {
          contentCondition:
            "all_content.matches_dlp_detector('CREDIT_CARD_NUMBER', google.privacy.dlp.v2.Likelihood.LIKELY, {minimum_match_count: 1, minimum_unique_match_count: 1})",
        },
      },
      {
        id: "national_id",
        displayName: `${DLP_PREFIX}National ID numbers in pages and uploads`,
        description: `Detects ${region.infoTypes.join(", ")} in content pasted into pages or uploaded (${region.label}).`,
        triggers: [
          "google.workspace.chrome.web_content.v1.upload",
          "google.workspace.chrome.file.v1.upload",
        ],
        condition: { contentCondition: nationalIdCondition },
      },
      {
        id: "access_level",
        displayName: `${DLP_PREFIX}Uploads and paste from unmanaged Chrome / BYOD`,
        description:
          "Enforces controls on sessions that do not meet the selected Context-Aware Access level.",
        triggers: [
          "google.workspace.chrome.file.v1.upload",
          "google.workspace.chrome.web_content.v1.upload",
        ],
        condition: {
          contextCondition: `!access_levels.meets_access_requirements(['${context.accessLevelName ?? ""}'])`,
        },
        requires: "accessLevel",
      },
      {
        id: "watermark",
        displayName: `${DLP_PREFIX}Watermark internal pages`,
        description:
          "Overlays a watermark and blocks screenshots on the internal sites listed above.",
        triggers: ["google.workspace.chrome.url.v1.navigation"],
        condition: {
          contentCondition: `url.matches_url_list('${context.internalSitesDetector ?? ""}')`,
        },
        actionParams: { watermarkMessage: "Confidential", blockScreenshot: true },
        requires: "internalSites",
      },
      {
        id: "genai_block",
        displayName: `${DLP_PREFIX}Prevent data paste to consumer GenAI`,
        description:
          "Prevents pasting sensitive data into unapproved consumer GenAI services while allowing corporate Gemini.",
        triggers: [
          "google.workspace.chrome.web_content.v1.upload",
          "google.workspace.chrome.url.v1.navigation",
        ],
      },
    ];
  }

  private async ensureRules(
    trace: CepTraceItem[],
    context: CepContext,
    created: string[],
    skipped: string[],
  ): Promise<void> {
    const existing = await this.listDlpPolicies(trace, "rule.dlp");
    if (existing === null) {
      skipped.push(`DLP rules: ${this.lastDlpError}`);
      return;
    }

    for (const rule of this.dlpRules(context)) {
      // Audit first is the safe default: a PoC that starts by blocking is a
      // PoC that gets turned off before anyone sees the reports.
      const action = context.ruleActions[rule.id] ?? "auditOnly";
      if (action === "off") {
        skipped.push(`Rule "${rule.displayName}": not selected`);
        continue;
      }
      if (rule.requires === "internalSites" && context.internalSitesDetector === undefined) {
        skipped.push(`Rule "${rule.displayName}": needs the Internal Sites detector`);
        continue;
      }
      if (rule.requires === "accessLevel" && context.accessLevelName === undefined) {
        skipped.push(`Rule "${rule.displayName}": needs a Context-Aware Access level`);
        continue;
      }
      if (existing.some((policy) => policy.displayName === rule.displayName)) {
        skipped.push(`Rule "${rule.displayName}" already exists and was reused`);
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
              ? { [action]: {} }
              : { [action]: { actionParams: rule.actionParams } },
        },
      };
      // Omitted entirely when absent: an empty sub-object is rejected.
      if (rule.condition !== undefined) value.condition = rule.condition;

      const beforeCreate = trace.length;
      const payload = await this.call(
        trace,
        `Create rule "${rule.displayName}"`,
        "POST",
        `${CLOUD_IDENTITY}/policies`,
        {
          customer: `customers/${context.customerId}`,
          type: "ADMIN",
          policyQuery: this.policyQuery(context),
          setting: { type: "settings/rule.dlp", value },
        },
      );
      if (payload === null) {
        skipped.push(
          `Rule "${rule.displayName}": ${trace[beforeCreate]?.error ?? "could not be created"}`,
        );
        continue;
      }
      created.push(`DLP rule "${rule.displayName}"`);
    }
  }

  /**
   * Delete what we created, rules before detectors.
   *
   * A detector cannot go while a rule still references it, so the order is
   * load-bearing rather than incidental.
   */
  private async removeDlpPolicies(
    trace: CepTraceItem[],
    removed: string[],
    skipped: string[],
    kinds: Array<"rule.dlp" | "detector">,
    verifyMatch: boolean,
  ): Promise<void> {
    for (const kind of kinds) {
      const existing = await this.listDlpPolicies(trace, kind);
      if (existing === null) {
        skipped.push(`${kind}: the policy API could not be reached, so nothing was deleted`);
        continue;
      }
      for (const policy of existing) {
        if (!policy.displayName.startsWith(DLP_PREFIX)) continue;
        // The kind is re-checked rather than taken from the server-side filter.
        // Deleting a detector during the rule pass would break the ordering
        // this loop exists to guarantee.
        if (!policy.type.includes(kind)) continue;
        if (verifyMatch && !policy.type.startsWith("settings/")) {
          skipped.push(`"${policy.displayName}" has an unexpected type and was left alone`);
          continue;
        }
        const deleted = await this.call(
          trace,
          `Delete "${policy.displayName}"`,
          "DELETE",
          `${CLOUD_IDENTITY}/${policy.name}`,
        );
        if (deleted === null) {
          skipped.push(`"${policy.displayName}" could not be deleted`);
          continue;
        }
        removed.push(`${kind === "detector" ? "Detector" : "Rule"} "${policy.displayName}"`);
      }
    }
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
          updateMask: { paths },
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
    return {
      customerId,
      projectId: config.project_id,
      ouIds: { users: config.target_ou_id, browsers: config.target_ou_id },
      primaryDomain: await this.primaryDomain(customerId),
      internalUrls,
      region: NATIONAL_ID_INFOTYPES[region] === undefined ? "US" : region,
      ruleActions: provision.dlp_rule_actions ?? {},
    };
  }

  // -- Provision --------------------------------------------------------------

  async provision(config: CepProvisionConfig): Promise<CepProvisionResult> {
    const trace: CepTraceItem[] = [];
    const created: string[] = [];
    const skipped: string[] = [];
    const internalUrls = (config.internal_urls ?? []).map((url) => url.trim()).filter(Boolean);
    const context = await this.buildContext(config, internalUrls);

    if (config.create_sub_ous === true) {
      await this.resolveSubOrgUnits(trace, config, context, created, skipped, true);
    }

    if (moduleEnabled(config, "contextAwareAccess")) {
      await this.resolveAccessLevel(trace, context, created, skipped, config.access_level ?? "");
    }

    // Detectors before rules: a rule that matches the internal-sites list needs
    // that detector's resource name to reference.
    if (moduleEnabled(config, "dlpDetectors")) {
      await this.ensureDetectors(trace, context, created, skipped);
    }
    if (moduleEnabled(config, "dlpRules")) {
      await this.ensureRules(trace, context, created, skipped);
    }

    const resolved = await this.resolvePolicies(config, context, skipped);
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
    let failures = 0;
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
        failures += 1;
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
      if (moduleFailed) failures += 1;
    }

    const applied = created.length;
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
   * Return the OU to its parent's settings.
   *
   * Every policy the table can write is inherited back, including the
   * app-scoped extension entry that the previous implementation left behind --
   * a rollback that leaves a force-installed extension in place is not one.
   */
  async rollback(config: CepRollbackConfig): Promise<CepProvisionResult> {
    const trace: CepTraceItem[] = [];
    const removed: string[] = [];
    const skipped: string[] = [];
    const context = await this.buildContext(config, []);
    const modules = config.rollback_modules ?? [];
    const wanted = (module: CepModule): boolean =>
      modules.length === 0 || modules.includes(module);

    // Find the sub OUs without creating them; policies may live in either place.
    await this.resolveSubOrgUnits(trace, config, context, [], [], false);

    const targets = CEP_POLICIES.filter((policy) => wanted(policy.module));
    if (targets.length > 0) {
      // Resolved the same way provision resolved them, so a policy written
      // under a namespace we did not predict is still inherited back.
      const requests: Array<Record<string, unknown>> = [];
      for (const policy of targets) {
        const resolved = await this.resolveSchema(context.customerId, policy);
        requests.push({
          policyTargetKey: targetKey(context, policy),
          policySchema: resolved?.name ?? policy.schema,
        });
      }
      const url = `${CHROME_POLICY}/customers/${context.customerId}/policies/orgunits:batchInherit`;
      const payload = await this.call(trace, "Inherit CEP policies", "POST", url, {
        requests,
      });
      if (payload === null) {
        return {
          success: false,
          message: "Rollback failed while returning policies to the parent OU.",
          created_items: removed,
          skipped_items: skipped,
          debug_trace: trace,
        };
      }
      removed.push(`${targets.length} Chrome policies returned to the parent OU`);
    }

    // Rules first, then detectors, then the access level a rule may reference:
    // each depends on the one after it, so deleting in the other order fails.
    const dlpKinds: Array<"rule.dlp" | "detector"> = [];
    if (wanted("dlpRules")) dlpKinds.push("rule.dlp");
    if (wanted("dlpDetectors")) dlpKinds.push("detector");
    if (dlpKinds.length > 0) {
      await this.removeDlpPolicies(
        trace,
        removed,
        skipped,
        dlpKinds,
        config.verify_match !== false,
      );
    }

    const selectedLevel = config.access_level ?? "";
    if (wanted("contextAwareAccess") && selectedLevel.startsWith("AUTO_CREATE_")) {
      await this.removeAccessLevel(trace, context, removed, skipped, config.verify_match !== false);
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

    return {
      success: true,
      message: "CEP policies were returned to the parent OU.",
      created_items: removed,
      skipped_items: skipped,
      debug_trace: trace,
    };
  }

  private async removeAccessLevel(
    trace: CepTraceItem[],
    context: CepContext,
    removed: string[],
    skipped: string[],
    verifyMatch: boolean,
  ): Promise<void> {
    if (!context.projectId) {
      skipped.push("Context-Aware Access: no project id, so no access level was looked for");
      return;
    }
    let name: string;
    try {
      name = await ensureManagedChromeAccessLevel(this.cloudTransport, context.projectId, "any");
    } catch (error) {
      skipped.push(`Context-Aware Access: ${errorMessage(error)}`);
      return;
    }

    if (verifyMatch) {
      const level = await this.call(
        trace,
        "Read access level",
        "GET",
        `${ACM}/${name}`,
        undefined,
        this.cloudTransport,
      );
      const description = (level?.description ?? "") as string;
      if (!description.includes("Secure Gateway Studio")) {
        skipped.push(
          `Context-Aware Access: ${name} was not created by this tool (or has been edited) and was left alone`,
        );
        return;
      }
    }

    const deleted = await this.call(
      trace,
      "Delete access level",
      "DELETE",
      `${ACM}/${name}`,
      undefined,
      this.cloudTransport,
    );
    if (deleted === null) {
      skipped.push(`Context-Aware Access: ${name} could not be deleted`);
      return;
    }
    removed.push(`Context-Aware Access level (${name})`);
  }

  // -- IAM custom roles -------------------------------------------------------

  /**
   * The permissions IAM will actually accept in a custom role on this project.
   *
   * Hardcoding a permission list does not survive contact with IAM: a name can
   * be wrong, withdrawn, or -- as with `accesscontextmanager.*` -- real but
   * scoped to the organization, so a project-level custom role rejects the
   * whole request over one entry. Asking first turns that into a role that is
   * created with the permissions that exist, and a note about the ones that do
   * not. Same reasoning as reading Chrome Policy schemas rather than assuming.
   */
  private async testablePermissions(projectId: string): Promise<Set<string> | null> {
    const permissions = new Set<string>();
    let pageToken = "";
    for (let page = 0; page < 20; page += 1) {
      const body: Record<string, unknown> = {
        fullResourceName: `//cloudresourcemanager.googleapis.com/projects/${projectId}`,
        pageSize: 1000,
      };
      if (pageToken !== "") body.pageToken = pageToken;

      let payload: Record<string, unknown>;
      try {
        payload = await this.request(
          this.cloudTransport,
          "POST",
          `${IAM}/permissions:queryTestablePermissions`,
          body,
        );
      } catch {
        // Without the list we cannot filter; the caller falls back to sending
        // the permissions as written rather than refusing to create anything.
        return null;
      }

      const page_ = Array.isArray(payload.permissions) ? payload.permissions : [];
      for (const item of page_) {
        const record = item as { name?: string; customRolesSupportLevel?: string };
        if (typeof record.name !== "string") continue;
        // NOT_SUPPORTED permissions exist but cannot go in a custom role.
        if (record.customRolesSupportLevel === "NOT_SUPPORTED") continue;
        permissions.add(record.name);
      }

      const next = payload.nextPageToken;
      if (typeof next !== "string" || next === "") break;
      pageToken = next;
    }
    return permissions;
  }

  /**
   * Create the two least-privilege roles, and optionally grant them.
   *
   * A failure here used to be reported as "(Existing / Verified)" and the call
   * still returned success, so a permission error looked like a completed
   * provisioning step. Only ALREADY_EXISTS means the role is there.
   */
  async createCustomRoles(config: CepCustomRoleConfig): Promise<CepRoleResult> {
    const trace: CepTraceItem[] = [];
    const roles: string[] = [];
    const failures: string[] = [];
    const projectId = config.project_id;

    if (!projectId) {
      return {
        success: false,
        message: "A Google Cloud project id is required to create IAM custom roles.",
        roles: [],
        debug_trace: trace,
      };
    }

    const definitions: Array<{ id: string; title: string; description: string; permissions: string[] }> = [];
    if (config.role_type === "administrator" || config.role_type === "both") {
      definitions.push({
        id: "cepPolicyAdministrator",
        title: "CEP Policy Administrator",
        description:
          "Least-privilege role to configure Chrome Enterprise Premium policies and access levels.",
        permissions: [
          "chromepolicy.policies.get",
          "chromepolicy.policies.list",
          "chromepolicy.policies.modify",
          "chromepolicy.orgunits.get",
          "accesscontextmanager.accessLevels.get",
          "accesscontextmanager.accessLevels.list",
          "accesscontextmanager.accessLevels.update",
          "serviceusage.services.use",
        ],
      });
    }
    if (config.role_type === "auditor" || config.role_type === "both") {
      definitions.push({
        id: "cepSecurityAuditor",
        title: "CEP Security Auditor (Read-Only)",
        description:
          "Read-only role to inspect Chrome Enterprise Premium policy state and security logs.",
        permissions: [
          "chromepolicy.policies.get",
          "chromepolicy.policies.list",
          "chromepolicy.orgunits.get",
          "logging.logEntries.list",
          "accesscontextmanager.accessLevels.get",
          "accesscontextmanager.accessLevels.list",
          "serviceusage.services.use",
        ],
      });
    }

    const testable = await this.testablePermissions(projectId);
    trace.push({
      label: "Query permissions valid for a project custom role",
      method: "POST",
      url: `${IAM}/permissions:queryTestablePermissions`,
      status: testable === null ? 0 : 200,
      ok: testable !== null,
      error: testable === null ? "could not be read; permissions sent as declared" : undefined,
    });

    const unavailable = new Set<string>();
    const url = `${IAM}/projects/${projectId}/roles`;
    for (const definition of definitions) {
      const roleName = `projects/${projectId}/roles/${definition.id}`;
      const permissions =
        testable === null
          ? definition.permissions
          : definition.permissions.filter((permission) => {
              if (testable.has(permission)) return true;
              unavailable.add(permission);
              return false;
            });

      if (permissions.length === 0) {
        failures.push(
          `${definition.title}: none of its permissions can be granted on project ${projectId}`,
        );
        continue;
      }

      try {
        await this.request(this.cloudTransport, "POST", url, {
          roleId: definition.id,
          role: {
            title: definition.title,
            description: definition.description,
            stage: "GA",
            includedPermissions: permissions,
          },
        });
        trace.push({ label: `Create role ${definition.id}`, method: "POST", url, status: 200, ok: true });
        roles.push(roleName);
      } catch (error) {
        const status = error instanceof CepApiError ? error.status : 0;
        trace.push({
          label: `Create role ${definition.id}`,
          method: "POST",
          url,
          status,
          ok: status === 409,
          error: status === 409 ? undefined : errorMessage(error),
        });
        if (status === 409) {
          roles.push(roleName);
        } else {
          failures.push(`${definition.title}: ${errorMessage(error)}`);
        }
      }
    }

    let omittedNote = "";
    if (unavailable.size > 0) {
      const orgScoped = [...unavailable].filter((permission) =>
        permission.startsWith("accesscontextmanager."),
      );
      omittedNote =
        ` Omitted ${[...unavailable].join(", ")} -- not grantable in a custom role on this project.`;
      if (orgScoped.length > 0) {
        omittedNote +=
          " Access Context Manager permissions are organization-scoped; to let this role manage access levels, create an equivalent role at the organization level.";
      }
    }

    const email = config.assigned_user_email?.trim();
    let grantNote = "";
    if (email && roles.length > 0) {
      const granted = await this.grantRoles(trace, projectId, roles, email);
      grantNote = granted
        ? ` Granted to ${email}.`
        : ` The roles were created but could not be granted to ${email}.`;
      if (!granted) failures.push(`Role binding for ${email} failed`);
    }

    if (failures.length > 0) {
      return {
        success: false,
        message: `${failures.join("; ")}.${omittedNote}${grantNote}`,
        roles,
        debug_trace: trace,
      };
    }
    return {
      success: true,
      message: `Provisioned ${roles.join(", ")}.${omittedNote}${grantNote}`,
      roles,
      debug_trace: trace,
    };
  }

  /** Read-modify-write on the project policy, keeping the etag as elsewhere. */
  private async grantRoles(
    trace: CepTraceItem[],
    projectId: string,
    roles: string[],
    email: string,
  ): Promise<boolean> {
    const base = `${CRM}/projects/${projectId}`;
    const policy = await this.call(
      trace,
      "Read project IAM policy",
      "POST",
      `${base}:getIamPolicy`,
      undefined,
      this.cloudTransport,
    );
    if (policy === null) return false;

    const bindings = (Array.isArray(policy.bindings) ? policy.bindings : []) as Array<{
      role: string;
      members: string[];
      condition?: unknown;
    }>;
    const member = `user:${email}`;
    for (const role of roles) {
      const existing = bindings.find(
        (binding) => binding.role === role && binding.condition === undefined,
      );
      if (existing === undefined) {
        bindings.push({ role, members: [member] });
      } else if (!existing.members.includes(member)) {
        existing.members.push(member);
      }
    }

    const updated = await this.call(
      trace,
      "Set project IAM policy",
      "POST",
      `${base}:setIamPolicy`,
      { policy: { bindings, etag: policy.etag } },
      this.cloudTransport,
    );
    return updated !== null;
  }

  // -- License assignment -----------------------------------------------------

  /**
   * Assign Chrome Enterprise Premium licenses to all users in the target OU.
   */
  async assignLicenses(config: CepLicenseAssignConfig): Promise<CepLicenseAssignResult> {
    const trace: CepTraceItem[] = [];
    const customerId = config.customer_id || "my_customer";
    const productId = config.product_id || "101040";
    const skuId = config.sku_id || "1010400001";
    let targetPath = config.target_ou_path;

    if (!targetPath) {
      try {
        const units = await this.listOrgUnits(customerId);
        const found = units.find((u) => u.id === config.target_ou_id);
        targetPath = found?.path || "/";
      } catch {
        targetPath = "/";
      }
    }

    const users: Array<{ primaryEmail: string }> = [];
    let pageToken = "";
    const query = `orgUnitPath='${targetPath.replace(/'/g, "\\'")}'`;

    for (let page = 0; page < 20; page += 1) {
      const queryParam = `customer=${encodeURIComponent(customerId)}&query=${encodeURIComponent(query)}${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ""}`;
      const url = `${DIRECTORY}/users?${queryParam}`;
      const payload = await this.call(trace, `List users in OU ${targetPath}`, "GET", url);
      if (payload === null) {
        break;
      }
      const rawUsers = Array.isArray(payload.users) ? payload.users : [];
      for (const u of rawUsers) {
        const email = (u as { primaryEmail?: string }).primaryEmail;
        if (typeof email === "string" && email !== "") {
          users.push({ primaryEmail: email });
        }
      }
      const next = payload.nextPageToken;
      if (typeof next !== "string" || next === "") break;
      pageToken = next;
    }

    if (users.length === 0) {
      return {
        success: true,
        message: `組織部門「${targetPath}」内にユーザーは見つかりませんでした。`,
        total_users: 0,
        assigned_count: 0,
        already_assigned_count: 0,
        failed_count: 0,
        assigned_users: [],
        errors: [],
        debug_trace: trace,
      };
    }

    let assignedCount = 0;
    let alreadyAssignedCount = 0;
    let failedCount = 0;
    const assignedUsers: string[] = [];
    const errors: string[] = [];

    const LICENSING = "https://licensing.googleapis.com/apps/licensing/v1";

    for (const user of users) {
      const url = `${LICENSING}/product/${productId}/sku/${skuId}/user`;
      try {
        const { status, payload } = await this.transport.requestJson("POST", url, {
          jsonBody: { userId: user.primaryEmail },
        });
        if (status >= 200 && status < 300) {
          assignedCount += 1;
          assignedUsers.push(user.primaryEmail);
          trace.push({
            label: `Assign CEP license to ${user.primaryEmail}`,
            method: "POST",
            url,
            status,
            ok: true,
          });
        } else {
          const errDetail = (payload.error as { message?: string })?.message || `HTTP ${status}`;
          if (
            errDetail.toLowerCase().includes("already") ||
            errDetail.toLowerCase().includes("duplicate") ||
            status === 400 ||
            status === 409
          ) {
            alreadyAssignedCount += 1;
            trace.push({
              label: `License for ${user.primaryEmail} already assigned (${errDetail})`,
              method: "POST",
              url,
              status,
              ok: true,
            });
          } else {
            failedCount += 1;
            errors.push(`${user.primaryEmail}: ${errDetail}`);
            trace.push({
              label: `Failed to assign license to ${user.primaryEmail}`,
              method: "POST",
              url,
              status,
              ok: false,
              error: errDetail,
            });
          }
        }
      } catch (err) {
        failedCount += 1;
        const msg = errorMessage(err);
        errors.push(`${user.primaryEmail}: ${msg}`);
        trace.push({
          label: `Exception assigning license to ${user.primaryEmail}`,
          method: "POST",
          url,
          status: 0,
          ok: false,
          error: msg,
        });
      }
    }

    const message = `組織部門「${targetPath}」内のユーザー ${users.length} 名の処理が完了しました（新規割り当て: ${assignedCount} 名、割り当て済み: ${alreadyAssignedCount} 名${failedCount > 0 ? `、失敗: ${failedCount} 名` : ""}）。`;

    return {
      success: failedCount === 0 || assignedCount > 0 || alreadyAssignedCount > 0,
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
   * A standalone script for the same configuration the UI would apply.
   *
   * Resolved against the live schemas rather than hardcoded, so the exported
   * file and the one-click path cannot disagree -- the previous version emitted
   * the same four policies no matter what was selected.
   */
  async generatePythonScript(config: CepProvisionConfig): Promise<string> {
    const internalUrls = (config.internal_urls ?? []).map((url) => url.trim()).filter(Boolean);
    const context = await this.buildContext(config, internalUrls);
    const skipped: string[] = [];
    const resolved = await this.resolvePolicies(config, context, skipped);

    const requests = resolved.map((item) => item.request);
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
REQUESTS = ${pythonLiteral(requests)}


def main() -> None:
    if not REQUESTS:
        print("[!] Nothing to apply: no policy modules were selected.")
        return

    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/chrome.management.policy"]
    )
    service = build("chromepolicy", "v1", credentials=credentials)

    print(f"[*] Applying {len(REQUESTS)} policies to customer {CUSTOMER_ID}...")
    response = (
        service.customers()
        .policies()
        .orgunits()
        .batchModify(customer=f"customers/{CUSTOMER_ID}", body={"requests": REQUESTS})
        .execute()
    )
    print("[+] Applied.")
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
