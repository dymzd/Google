/**
 * CEP PoC Deployer: route dispatch and the requests it produces.
 *
 * This check exists because its absence hid a total failure. The CEP routes
 * were declared in `PORTED`, so `verify-routes` matched them; the page's tests
 * mocked `api.ts`, so they never reached the worker; and nothing type-checked
 * the extension. All four handlers referenced an undefined `request` variable
 * and threw `ReferenceError` on the first call, and every check was green.
 *
 * So this one goes through `route()` -- the same entry point the service worker
 * calls -- and asserts on the Google requests that come out the other side.
 * A handler that cannot run fails here before anything reaches a tenant.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-cep.ts
 */

const failures: string[] = [];
let passed = 0;

function check(name: string, condition: boolean, detail = ""): void {
  if (condition) passed += 1;
  else failures.push(`${name}${detail ? `\n      ${detail}` : ""}`);
}

// -- Environment --------------------------------------------------------------

// `router.ts` reaches for extension globals in handlers this file does not
// exercise; they only need to exist for the module to load under node.
(globalThis as Record<string, unknown>).chrome = {
  runtime: { getManifest: () => ({ version: "0.0.0-test" }) },
  storage: { local: { get: async () => ({}), set: async () => undefined } },
  alarms: { create: async () => undefined, clear: async () => undefined },
};

const { route, CEP_LICENSE_ROUTE_MAX_NETWORK_WAIT_MS } =
  await import("../src/background/router.ts");
import type { RouteContext } from "../src/background/router.ts";
import type { Transport, TransportResponse } from "../src/providers/executor.ts";
import {
  CEP_LICENSE_DIRECTORY_PAGE_LIMIT,
  CEP_LICENSE_PILOT_USER_LIMIT,
} from "../src/providers/cep-provider.ts";
import {
  CepMutationLeaseBusy,
  type CepMutationLeaseHandle,
} from "../src/storage/repository.ts";

interface Recorded {
  method: string;
  url: string;
  body?: Record<string, unknown>;
  acceptedStatuses?: readonly number[];
  at: number;
}

interface StubField {
  name: string;
  type: "TYPE_BOOL" | "TYPE_ENUM" | "TYPE_STRING" | "TYPE_MESSAGE";
  /** Enum constants, including ones the provider must not choose. */
  enums?: string[];
  /** Sub-fields, for the message-typed connector configurations. */
  message?: StubField[];
  repeated?: boolean;
}

/**
 * A tenant that answers every discovery call the provider makes.
 *
 * Shapes are taken from what a real tenant actually served, which is not what
 * Google's published policy list implies: the connector policies are named
 * after themselves, carry four fields each, and declare more than one enum.
 */
const SCHEMA_FIELDS: Record<string, StubField[]> = {
  "chrome.users.SafeBrowsingProtectionLevel": [
    {
      name: "safeBrowsingProtectionLevel",
      type: "TYPE_ENUM",
      enums: [
        "SAFE_BROWSING_PROTECTION_LEVEL_UNSPECIFIED",
        "NO_PROTECTION",
        "STANDARD_PROTECTION",
        "ENHANCED_PROTECTION",
      ],
    },
  ],
  "chrome.users.PasswordProtectionWarningTrigger": [
    {
      name: "passwordProtectionWarningTrigger",
      type: "TYPE_ENUM",
      enums: [
        "PASSWORD_PROTECTION_WARNING_TRIGGER_UNSPECIFIED",
        "PASSWORD_PROTECTION_OFF",
        "PASSWORD_REUSE",
        "PHISHING_REUSE",
      ],
    },
  ],
  "chrome.users.CloudReportingEnabled": [
    { name: "cloudReportingEnabled", type: "TYPE_BOOL" },
  ],
  "chrome.users.CloudProfileReportingEnabled": [
    { name: "cloudProfileReportingEnabled", type: "TYPE_BOOL" },
  ],
  "chrome.users.apps.InstallType": [{ name: "appInstallType", type: "TYPE_STRING" }],
  "chrome.users.RealtimeUrlCheck": [
    { name: "realtimeUrlCheckEnabled", type: "TYPE_BOOL" },
  ],
  "chrome.users.OnFileAttachedConnectorPolicy": [
    {
      name: "onFileAttachedAnalysisConnectorConfiguration",
      type: "TYPE_MESSAGE",
      message: [
        { name: "enableScanning", type: "TYPE_BOOL" },
        { name: "serviceProvider", type: "TYPE_STRING" },
      ],
    },
    { name: "fileAttachedConfiguration", type: "TYPE_MESSAGE" },
    { name: "serviceProvider", type: "TYPE_STRING" },
    {
      name: "delayDeliveryUntilVerdict",
      type: "TYPE_ENUM",
      enums: ["DELAY_UNSPECIFIED", "DELAY_NONE", "DELAY_UPLOADS"],
    },
  ],
  "chrome.users.OnFileDownloadedConnectorPolicy": [
    {
      name: "onFileDownloadedAnalysisConnectorConfiguration",
      type: "TYPE_ENUM",
      enums: ["ANALYSIS_CONNECTOR_UNSPECIFIED", "DISABLED", "SCAN_ALL_DOWNLOADS"],
    },
    { name: "fileDownloadedConfiguration", type: "TYPE_MESSAGE" },
    { name: "serviceProvider", type: "TYPE_STRING" },
    {
      name: "delayDeliveryUntilVerdict",
      type: "TYPE_ENUM",
      enums: ["DELAY_UNSPECIFIED", "DELAY_NONE", "DELAY_DOWNLOADS"],
    },
  ],
  "chrome.users.OnSecurityEvent": [
    {
      name: "reportingConnector",
      type: "TYPE_ENUM",
      enums: ["REPORTING_CONNECTOR_UNSPECIFIED", "DISABLED", "GOOGLE"],
    },
    { name: "eventConfiguration", type: "TYPE_MESSAGE" },
    { name: "enabledEventNames", type: "TYPE_STRING", repeated: true },
    { name: "explicitlyEmptyEventNames", type: "TYPE_BOOL" },
  ],
  "chrome.users.OnBulkTextEntryConnectorPolicy": [
    {
      name: "onBulkTextEntryAnalysisConnectorConfiguration",
      type: "TYPE_ENUM",
      enums: ["ANALYSIS_CONNECTOR_UNSPECIFIED", "DISABLED", "SCAN_ALL_TEXT"],
    },
    { name: "bulkTextEntryConfiguration", type: "TYPE_MESSAGE" },
    { name: "serviceProvider", type: "TYPE_STRING" },
    {
      name: "delayDeliveryUntilVerdict",
      type: "TYPE_ENUM",
      enums: ["DELAY_UNSPECIFIED", "DELAY_NONE", "DELAY_UPLOADS"],
    },
  ],
  "chrome.users.AllowedDomainsForApps": [
    { name: "allowedDomainsForApps", type: "TYPE_STRING" },
  ],
  "chrome.users.URLBlocklist": [
    { name: "urlBlocklist", type: "TYPE_STRING", repeated: true },
  ],
  "chrome.users.URLAllowlist": [
    { name: "urlAllowlist", type: "TYPE_STRING", repeated: true },
  ],
};

/** Render a stub schema the way the Chrome Policy API describes one. */
function schemaPayload(fields: StubField[]): Record<string, unknown> {
  const describe = (field: StubField) => ({
    name: field.name,
    type: field.type,
    // Enums and messages are addressed by their own type name, so the provider
    // has to resolve the one belonging to the field it is setting.
    typeName:
      field.enums !== undefined
        ? `.chrome.${field.name}Enum`
        : field.message !== undefined
        ? `.chrome.${field.name}Message`
        : undefined,
    label: field.repeated === true ? "LABEL_REPEATED" : "LABEL_OPTIONAL",
  });

  return {
    definition: {
      messageType: [
        {
          field: fields.map(describe),
          enumType: fields
            .filter((field) => field.enums !== undefined)
            .map((field) => ({
              name: `${field.name}Enum`,
              value: (field.enums ?? []).map((value) => ({ name: value })),
            })),
        },
        // Nested messages are siblings in `messageType`, found by type name.
        ...fields
          .filter((field) => field.message !== undefined)
          .map((field) => ({
            name: `${field.name}Message`,
            field: (field.message ?? []).map(describe),
          })),
      ],
    },
  };
}

interface StubDlpPolicy {
  name: string;
  displayName: string;
  type: string;
  snakeCase?: boolean;
  value?: Record<string, unknown>;
  policyQuery?: Record<string, unknown>;
}

interface StubOptions {
  /** Schema names the tenant does not serve, so the provider must skip them. */
  missingSchemas?: string[];
  /**
   * DLP policies already present. `snakeCase` stores the display name the way
   * the API returns a struct written by something other than this tool.
   */
  existingDlp?: StubDlpPolicy[];
  /** Explicit Policy API pages; used to prove truncated pagination fails closed. */
  dlpPages?: StubDlpPolicy[][];
  /** Number of pages returned by the Chrome Policy schema catalogue. */
  schemaPageCount?: number;
  /** Override the first schema page token, including malformed null/number values. */
  schemaNextPageToken?: unknown;
  /** Reject Directory organizational-unit creation while allowing tree reads. */
  failOrgUnitCreate?: boolean;
  /** Answer policy mutations with HTTP 200 carrying an error code in the body. */
  dlpRpcError?: number;
  /** Number of initial Cloud Identity requests that return HTTP 429. */
  dlp429Count?: number;
  /** Return done:false and delay each created DLP policy by this many list calls. */
  dlpCreatePendingLists?: number;
  /** Let this many creates complete immediately before applying the pending behavior. */
  dlpCreatePendingAfter?: number;
  /** Replace every DLP list payload to exercise strict response validation. */
  dlpListPayloadOverride?: Record<string, unknown>;
  /** Add server timestamps and return configured rule metadata in snake case. */
  dlpServerOutputFields?: boolean;
  /** Override the DLP list token, including malformed null/number values. */
  dlpNextPageToken?: unknown;
  /** Simulate requestId-less create response loss with or without provider commit. */
  dlpCreateMode?: "response-loss-commit" | "503-commit" | "503-no-commit";
  /** Fail this one-based Chrome Policy batchInherit call. */
  failBatchInheritAt?: number;
  /**
   * Permissions the project accepts in a custom role. Defaults to the set a
   * real project returned: Access Context Manager is absent, because those
   * permissions are organization-scoped.
   */
  testablePermissions?: string[];
  /** URL fragments whose calls fail, with the status to answer. */
  failing?: Array<{ match: string; status: number; message: string }>;
  /** Org units already present, as `{path, id}`. */
  existingOus?: Array<{ path: string; id: string }>;
  /** Replace the Directory organizational-unit collection with a malformed shape. */
  orgUnitsPayloadOverride?: unknown;
  existingAccessLevels?: Array<{
    name: string;
    description: string;
    expression: string;
  }>;
  customerDomain?: string | null;
  /** Canonical Directory customer id; null simulates an unresolved alias. */
  customerId?: string | null;
  licenseAlreadyAssigned?: boolean;
  licensePostMode?: "412-commit" | "503-commit" | "response-loss-commit" | "412-no-commit";
  directoryUsers?: Array<{ primaryEmail?: unknown; orgUnitPath?: unknown }>;
  directoryPages?: Array<Array<{ primaryEmail?: unknown; orgUnitPath?: unknown }>>;
  /** Override the Directory user-list token, including malformed null/number values. */
  directoryNextPageToken?: unknown;
}

function stubTransport(options: StubOptions = {}): {
  transport: Transport;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  let policyClock = 0;
  let dlp429Remaining = options.dlp429Count ?? 0;
  let dlpCreateCount = 0;
  let batchInheritCount = 0;
  const createdDlp: StubDlpPolicy[] = [];
  const pendingDlp: Array<{
    policy: StubDlpPolicy;
    remainingLists: number;
  }> = [];
  const createdOus: Array<{ path: string; id: string }> = [];
  const createdAccessLevels = new Map<string, Record<string, unknown>>();
  const assignedLicenses = new Set<string>(
    options.licenseAlreadyAssigned ? ["bob@example.com"] : [],
  );
  const transport: Transport & {
    cepPolicyRateLimitClock: {
      now(): number;
      sleep(milliseconds: number): Promise<void>;
    };
  } = {
    cepPolicyRateLimitClock: {
      now: () => policyClock,
      sleep: async (milliseconds) => {
        policyClock += milliseconds;
      },
    },
    async requestJson(method, url, requestOptions = {}): Promise<TransportResponse> {
      const body = requestOptions.jsonBody;
      calls.push({
        method,
        url,
        body,
        acceptedStatuses: requestOptions.acceptedStatuses,
        at: policyClock,
      });

      if (url.includes("orgunits:batchInherit")) {
        batchInheritCount += 1;
        if (batchInheritCount === options.failBatchInheritAt) {
          return {
            status: 400,
            payload: { error: { message: "target-compatible inherit batch rejected" } },
          };
        }
      }

      if (url.includes("cloudidentity.googleapis.com") && dlp429Remaining > 0) {
        dlp429Remaining -= 1;
        if (!requestOptions.acceptedStatuses?.includes(429)) {
          throw Object.assign(new Error("quota exceeded"), { status: 429 });
        }
        return { status: 429, payload: { error: { message: "quota exceeded" } } };
      }

      for (const failure of options.failing ?? []) {
        if (url.includes(failure.match)) {
          return { status: failure.status, payload: { error: { message: failure.message } } };
        }
      }

      // Access Context Manager reachable through an organization, which is
      // what auto-creating a level requires.
      if (url.includes("cloudresourcemanager") && /\/projects\/[^/:]+$/.test(url)) {
        return {
          status: 200,
          payload: { name: "projects/1111", parent: "organizations/1234" },
        };
      }
      // Query params arrive in `options`, not the URL, so match the path.
      if (url.includes("accesscontextmanager") && /\/accessPolicies(?:\?|$)/.test(url)) {
        return {
          status: 200,
          payload: {
            accessPolicies: [{
              name: "accessPolicies/999",
              parent: "organizations/1234",
            }],
          },
        };
      }
      if (
        method === "GET" &&
        url.includes("accesscontextmanager") &&
        /\/accessPolicies\/999$/.test(url)
      ) {
        return {
          status: 200,
          payload: { name: "accessPolicies/999", parent: "organizations/1234" },
        };
      }
      if (
        method === "GET" &&
        url.includes("accesscontextmanager") &&
        /\/accessPolicies\/[^/]+\/accessLevels\/[^/]+$/.test(url)
      ) {
        const name = url.replace(/^https:\/\/[^/]+\/v1\//, "");
        const existing = options.existingAccessLevels?.find((level) => level.name === name);
        const created = createdAccessLevels.get(name);
        return {
          status: existing !== undefined || created !== undefined ? 200 : 404,
          payload: existing !== undefined
            ? {
                name: existing.name,
                description: existing.description,
                custom: { expr: { expression: existing.expression } },
              }
            : created !== undefined
            ? created
            : { error: { message: "not found" } },
        };
      }
      if (
        method === "POST" &&
        url.includes("accesscontextmanager") &&
        /\/accessPolicies\/[^/]+\/accessLevels$/.test(url)
      ) {
        const level = (body ?? {}) as Record<string, unknown>;
        if (typeof level.name === "string") createdAccessLevels.set(level.name, level);
        return {
          status: 200,
          payload: {
            name: `${String(level.name)}/create/operation-${calls.length}`,
            done: true,
          },
        };
      }

      if (url.includes("permissions:queryTestablePermissions")) {
        const permissions = options.testablePermissions ?? [
          "chromepolicy.policies.get",
          "chromepolicy.policies.list",
          "chromepolicy.policies.modify",
          "chromepolicy.orgunits.get",
          "logging.logEntries.list",
          "serviceusage.services.use",
        ];
        return {
          status: 200,
          payload: { permissions: permissions.map((name) => ({ name })) },
        };
      }

      // The schema catalogue, which the provider prefers over per-name reads.
      if (/\/policySchemas(\?|$)/.test(url)) {
        const token = new URL(url).searchParams.get("pageToken");
        const pageIndex = Number(token?.match(/^schema-page-(\d+)$/)?.[1] ?? "0");
        const pageCount = options.schemaPageCount ?? 1;
        return {
          status: 200,
          payload: {
            policySchemas:
              pageIndex === 0
                ? Object.entries(SCHEMA_FIELDS)
                    .filter(([name]) => !(options.missingSchemas ?? []).includes(name))
                    .map(([name, fields]) => ({ schemaName: name, ...schemaPayload(fields) }))
                : [],
            ...(pageIndex === 0 && "schemaNextPageToken" in options
              ? { nextPageToken: options.schemaNextPageToken }
              : pageIndex + 1 < pageCount
                ? { nextPageToken: `schema-page-${pageIndex + 1}` }
                : {}),
          },
        };
      }

      const schemaMatch = url.match(/policySchemas\/(.+)$/);
      if (schemaMatch !== null) {
        const name = schemaMatch[1];
        if ((options.missingSchemas ?? []).includes(name)) {
          return { status: 404, payload: { error: { message: "not found" } } };
        }
        const fields = SCHEMA_FIELDS[name];
        if (fields === undefined) {
          return { status: 404, payload: { error: { message: "unknown schema" } } };
        }
        return { status: 200, payload: schemaPayload(fields) };
      }

      if (/\/customers\/[^/]+$/.test(url) && url.includes("admin/directory")) {
        const domain = options.customerDomain;
        const customerId = options.customerId;
        return {
          status: 200,
          payload:
            domain === null && customerId === null
              ? {}
              : {
                  ...(domain === null ? {} : { customerDomain: domain ?? "example.com" }),
                  ...(customerId === null ? {} : { id: customerId ?? "C01abcdef" }),
                },
        };
      }

      if (url.includes("cloudidentity.googleapis.com")) {
        if (method === "GET") {
          if (options.dlpListPayloadOverride !== undefined) {
            return {
              status: 200,
              payload: structuredClone(options.dlpListPayloadOverride),
            };
          }
          // The real API filters server-side; honour it so the stub cannot
          // make an unfiltered client look correct.
          const kind = decodeURIComponent(url).match(/matches\("([^"]+)"\)/)?.[1] ?? "";
          for (let index = pendingDlp.length - 1; index >= 0; index -= 1) {
            const pending = pendingDlp[index];
            if (!pending.policy.type.includes(kind)) continue;
            if (pending.remainingLists > 0) {
              pending.remainingLists -= 1;
              continue;
            }
            createdDlp.push(pending.policy);
            pendingDlp.splice(index, 1);
          }
          const pageToken = new URL(url).searchParams.get("pageToken");
          const pageIndex = pageToken?.match(/^page-(\d+)$/)?.[1];
          const explicitPage = pageIndex === undefined ? 0 : Number(pageIndex);
          const source = options.dlpPages === undefined
            ? [...(options.existingDlp ?? []), ...createdDlp]
            : options.dlpPages[explicitPage] ?? [];
          const matching = source.filter((policy) => policy.type.includes(kind));
          const nextPageToken =
            options.dlpPages !== undefined && explicitPage + 1 < options.dlpPages.length
              ? `page-${explicitPage + 1}`
              : undefined;
          return {
            status: 200,
            payload: {
              policies: matching.map((policy) => {
                const value = { ...(policy.value ?? {}) };
                if (policy.snakeCase === true) {
                  delete value.displayName;
                  value.display_name = policy.displayName;
                } else {
                  delete value.display_name;
                  value.displayName = policy.displayName;
                }
                if (options.dlpServerOutputFields === true) {
                  value.createTime = "2026-08-24T12:00:00.000Z";
                  value.update_time = "2026-08-24T12:00:01.000Z";
                  const metadata = value.ruleTypeMetadata as {
                    dlpRuleMetadata?: { alertSeverity?: string };
                  } | undefined;
                  delete value.ruleTypeMetadata;
                  if (metadata?.dlpRuleMetadata?.alertSeverity !== undefined) {
                    value.rule_type_metadata = {
                      dlp_rule_metadata: {
                        alert_severity: metadata.dlpRuleMetadata.alertSeverity,
                      },
                    };
                  }
                }
                return {
                  name: policy.name,
                  setting: { type: policy.type, value },
                  policyQuery: { ...(policy.policyQuery ?? {}) },
                };
              }),
              ...("dlpNextPageToken" in options
                ? { nextPageToken: options.dlpNextPageToken }
                : nextPageToken === undefined ? {} : { nextPageToken }),
            },
          };
        }
        if (options.dlpRpcError !== undefined) {
          // The policy API's second failure mode: 200 with an error body.
          return { status: 200, payload: { done: true, error: { code: options.dlpRpcError } } };
        }
        const setting = (body?.setting ?? {}) as {
          type?: string;
          value?: Record<string, unknown> & { displayName?: string };
        };
        const policy = {
          name: `policies/created-${calls.length}`,
          displayName: setting.value?.displayName ?? "created policy",
          type: setting.type ?? "settings/rule.dlp",
          value: { ...(setting.value ?? {}) },
          policyQuery: {
            ...((body?.policyQuery ?? {}) as Record<string, unknown>),
          },
        };
        dlpCreateCount += 1;
        if (options.dlpCreateMode !== undefined) {
          if (options.dlpCreateMode !== "503-no-commit") createdDlp.push(policy);
          if (options.dlpCreateMode === "response-loss-commit") {
            throw new Error("connection reset after Cloud Identity create commit");
          }
          throw Object.assign(new Error("Cloud Identity create unavailable"), { status: 503 });
        }
        if (
          options.dlpCreatePendingLists !== undefined &&
          dlpCreateCount > (options.dlpCreatePendingAfter ?? 0)
        ) {
          pendingDlp.push({
            policy,
            remainingLists: options.dlpCreatePendingLists,
          });
          return {
            status: 200,
            payload: { done: false, name: `operations/create-${calls.length}` },
          };
        }
        createdDlp.push(policy);
        return {
          status: 200,
          payload: { done: true, response: { name: policy.name } },
        };
      }

      // `/orgunits` exactly -- `/orgunits:batchModify` is a different endpoint.
      const isOrgUnitCollection = /\/orgunits(\?|$)/.test(url);

      if (isOrgUnitCollection && method === "GET") {
        const units = [
          { orgUnitId: "id:root", orgUnitPath: "/", name: "Root" },
          { orgUnitId: "id:03pilot", orgUnitPath: "/Pilot", name: "Pilot" },
          ...(options.existingOus ?? []).map((unit) => ({
            orgUnitId: `id:${unit.id}`,
            orgUnitPath: unit.path,
            name: unit.path.split("/").pop(),
          })),
          ...createdOus.map((unit) => ({
            orgUnitId: `id:${unit.id}`,
            orgUnitPath: unit.path,
            name: unit.path.split("/").pop(),
          })),
        ];
        return {
          status: 200,
          payload: {
            organizationUnits: "orgUnitsPayloadOverride" in options
              ? options.orgUnitsPayloadOverride
              : units,
          },
        };
      }

      if (isOrgUnitCollection && method === "POST") {
        if (options.failOrgUnitCreate === true) {
          return { status: 403, payload: { error: { message: "OU create forbidden" } } };
        }
        const name = String((body as { name?: string } | undefined)?.name ?? "");
        const parent = String(
          (body as { parentOrgUnitPath?: string } | undefined)?.parentOrgUnitPath ?? "/",
        );
        const id = `created-${name.replace(/\s+/g, "-")}`;
        createdOus.push({ path: `${parent === "/" ? "" : parent}/${name}`, id });
        return {
          status: 200,
          payload: { orgUnitId: `id:${id}` },
        };
      }

      if (url.includes("admin/directory") && url.includes("/users")) {
        const token = new URL(url).searchParams.get("pageToken");
        const pageIndex = Number(token?.match(/^directory-page-(\d+)$/)?.[1] ?? "0");
        const pages = options.directoryPages ?? [
          options.directoryUsers ?? [
            { primaryEmail: "alice@example.com", orgUnitPath: "/Pilot" },
            { primaryEmail: "bob@example.com", orgUnitPath: "/Pilot" },
          ],
        ];
        return {
          status: 200,
          payload: {
            users: pages[pageIndex] ?? [],
            ...(pageIndex === 0 && "directoryNextPageToken" in options
              ? { nextPageToken: options.directoryNextPageToken }
              : pageIndex + 1 < pages.length
                ? { nextPageToken: `directory-page-${pageIndex + 1}` }
                : {}),
          },
        };
      }

      if (url.includes("licensing.googleapis.com")) {
        if (method === "GET") {
          const userId = decodeURIComponent(url.split("/").pop() ?? "").toLowerCase();
          if (!assignedLicenses.has(userId)) {
            if (!requestOptions.acceptedStatuses?.includes(404)) {
              throw Object.assign(new Error("not found"), { status: 404 });
            }
            return { status: 404, payload: { error: { message: "not found" } } };
          }
          return {
            status: 200,
            payload: {
              kind: "licensing#licenseAssignment",
              productId: "101040",
              skuId: "1010400001",
              userId,
              selfLink:
                "https://licensing.googleapis.com/apps/licensing/v1/product/101040/" +
                `sku/1010400001/user/${encodeURIComponent(userId)}`,
            },
          };
        }
        const userId = String((body as { userId?: unknown } | undefined)?.userId ?? "");
        const mode = options.licensePostMode;
        if (mode !== "412-no-commit") assignedLicenses.add(userId.toLowerCase());
        if (mode === "response-loss-commit") {
          throw new Error("licensing-response-lost");
        }
        if (mode === "412-commit" || mode === "412-no-commit") {
          if (!requestOptions.acceptedStatuses?.includes(412)) {
            throw Object.assign(new Error("precondition failed"), { status: 412 });
          }
          return { status: 412, payload: { error: { message: "precondition failed" } } };
        }
        if (mode === "503-commit") {
          if (!requestOptions.acceptedStatuses?.includes(503)) {
            throw Object.assign(new Error("unavailable"), { status: 503 });
          }
          return { status: 503, payload: { error: { message: "unavailable" } } };
        }
        return {
          status: 200,
          payload: {
            kind: "licensing#licenseAssignment",
            productId: "101040",
            skuId: "1010400001",
            userId,
            selfLink:
              "https://licensing.googleapis.com/apps/licensing/v1/product/101040/" +
              `sku/1010400001/user/${encodeURIComponent(userId)}`,
          },
        };
      }

      return { status: 200, payload: {} };
    },
  };
  return { transport, calls };
}

const activeCepLeases = new Map<string, CepMutationLeaseHandle>();
let cepLeaseSequence = 0;

function context(transport: Transport, policyId?: string): RouteContext {
  return {
    discoveryTransport: transport,
    transport,
    administratorTransport: transport,
    cloudIdentity: async () => "deployer@example.com",
    operatorEmail: async () => "admin@example.com",
    accessPolicyId: async () => policyId,
    rememberAccessPolicyId: async () => undefined,
    bootstrapOwnershipPin: async () => undefined,
    assertBootstrapOperator: async () => undefined,
    checkpointBootstrapOwnershipPin: async () => undefined,
    clearBootstrapOwnershipPin: async () => undefined,
    legacyDeployerIdentity: async () => undefined,
    rememberDeployer: async () => undefined,
    requireDeployer: async () => ({
      serviceAccountEmail: "deployer@example.com",
      serviceAccountUniqueId: "123456789012345678901",
      projectId: "secgw-project",
      operatorEmail: "admin@example.com",
      operatorSubject: "admin-subject-123",
    }),
    acquireCepMutationLease: async (options) => {
      for (const scopeKey of options.scopeKeys) {
        if (activeCepLeases.has(scopeKey)) {
          throw new CepMutationLeaseBusy("cep-mutation-active", scopeKey);
        }
      }
      const handle: CepMutationLeaseHandle = {
        scopeKeys: [...options.scopeKeys],
        operationId: `cep-operation-${++cepLeaseSequence}`,
        operationKind: options.operationKind,
        requestDigest: options.requestDigest,
        ownerToken: `cep-owner-${cepLeaseSequence}`,
        recovered: false,
        expiresAt: new Date(Date.now() + 90_000).toISOString(),
      };
      for (const scopeKey of handle.scopeKeys) activeCepLeases.set(scopeKey, handle);
      return handle;
    },
    renewCepMutationLease: async (handle) => {
      if (handle.scopeKeys.some((key) => activeCepLeases.get(key)?.ownerToken !== handle.ownerToken)) {
        throw new Error("cep-mutation-lease-lost");
      }
      return { ...handle, expiresAt: new Date(Date.now() + 90_000).toISOString() };
    },
    releaseCepMutationLease: async (handle) => {
      for (const key of handle.scopeKeys) {
        if (activeCepLeases.get(key)?.ownerToken !== handle.ownerToken) {
          throw new Error("cep-mutation-lease-lost");
        }
      }
      for (const key of handle.scopeKeys) activeCepLeases.delete(key);
    },
    startApply: async () => ({ run_id: "run" }),
    resumeApply: async () => ({}),
    runState: async () => ({}),
  };
}

const FULL_CONFIG = {
  customer_id: "C01abcdef",
  project_id: "secgw-project",
  target_ou_id: "03pilot",
  target_ou_path: "/Pilot",
  target_ou_confirmation: "/Pilot",
  create_sub_ous: false,
  core_policies: true,
  force_extensions: true,
  connectors: true,
  access_level: "NONE",
  data_boundary_mode: "copy_paste" as const,
  internal_urls: ["https://intranet.example.com"],
};

interface ProvisionResult {
  success: boolean;
  message: string;
  created_items: string[];
  skipped_items: string[];
  debug_trace: Array<{ label: string; ok: boolean; status: number; error?: string }>;
}

function batchRequests(calls: Recorded[], operation: "batchModify" | "batchInherit"): Array<Record<string, unknown>> {
  return calls
    .filter((call) => call.url.includes(`orgunits:${operation}`))
    .flatMap((call) => (call.body?.requests ?? []) as Array<Record<string, unknown>>);
}

/** Creation calls against the org unit collection, not the policy batch endpoints. */
function orgUnitCreations(calls: Recorded[]): Recorded[] {
  return calls.filter((call) => call.method === "POST" && /\/orgunits(\?|$)/.test(call.url));
}

function schemasIn(requests: Array<Record<string, unknown>>): string[] {
  return requests.map((request) => {
    const value = request.policyValue as { policySchema?: string } | undefined;
    return value?.policySchema ?? (request.policySchema as string);
  });
}

// -- 1. Every route dispatches ------------------------------------------------

for (const [path, payload] of [
  ["/api/v1/cep/provision", FULL_CONFIG],
  [
    "/api/v1/cep/rollback",
    { project_id: "secgw-project", customer_id: "C01abcdef", target_ou_id: "03pilot" },
  ],
  [
    "/api/v1/cep/roles",
    { project_id: "secgw-project", customer_id: "C01abcdef", role_type: "both" },
  ],
  ["/api/v1/cep/script", FULL_CONFIG],
  [
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  ],
] as const) {
  const { transport } = stubTransport();
  try {
    const result = await route(context(transport), "POST", path, payload);
    check(`POST ${path} returns a result`, result !== undefined && result !== null);
  } catch (error) {
    check(`POST ${path} dispatches without throwing`, false, String(error));
  }
}

// -- 2. Module toggles reach the wire -----------------------------------------

{
  const { transport, calls } = stubTransport();
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    FULL_CONFIG,
  )) as ProvisionResult;
  const requests = batchRequests(calls, "batchModify");
  const schemas = schemasIn(requests);

  check("provision succeeds against a healthy tenant", result.success, result.message);
  check(
    "core, extension, connector and data-boundary policies are all written",
    schemas.includes("chrome.users.SafeBrowsingProtectionLevel") &&
      schemas.includes("chrome.users.apps.InstallType") &&
      schemas.includes("chrome.users.OnFileAttachedConnectorPolicy") &&
      schemas.includes("chrome.users.OnBulkTextEntryConnectorPolicy"),
    schemas.join(", "),
  );

  const batches = calls.filter((call) => call.url.includes("orgunits:batchModify"));
  check(
    "policies are split into one batch per module, not one batch for everything",
    batches.length >= 3,
    `${batches.length} batch call(s)`,
  );

  // The enum the schema advertises, not a constant spelled out in our source.
  const safeBrowsing = requests.find(
    (request) =>
      (request.policyValue as { policySchema?: string }).policySchema ===
      "chrome.users.SafeBrowsingProtectionLevel",
  );
  const safeBrowsingValue = (
    (safeBrowsing?.policyValue as { value?: Record<string, unknown> })?.value ?? {}
  ).safeBrowsingProtectionLevel;
  check(
    "the enhanced Safe Browsing constant is read off the schema",
    safeBrowsingValue === "ENHANCED_PROTECTION",
    String(safeBrowsingValue),
  );

  // Regression: this used to be PASSWORD_PROTECTION_OFF, which turned off the
  // warning the UI says it turns on.
  const passwordTrigger = requests.find(
    (request) =>
      (request.policyValue as { policySchema?: string }).policySchema ===
      "chrome.users.PasswordProtectionWarningTrigger",
  );
  const triggerValue = (
    (passwordTrigger?.policyValue as { value?: Record<string, unknown> })?.value ?? {}
  ).passwordProtectionWarningTrigger;
  check(
    "password protection is switched on rather than off",
    triggerValue === "PASSWORD_REUSE",
    String(triggerValue),
  );

  // Regression: RestrictAccountsToPatterns only covers Android/iOS. The
  // advertised desktop and ChromeOS boundary uses AllowedDomainsForApps and
  // its value must be the primary domain, never the Workspace customer id.
  const restrict = requests.find(
    (request) =>
      (request.policyValue as { policySchema?: string }).policySchema ===
      "chrome.users.AllowedDomainsForApps",
  );
  const allowedDomain = (
    (restrict?.policyValue as { value?: Record<string, unknown> })?.value ?? {}
  ).allowedDomainsForApps;
  check(
    "desktop and ChromeOS Google-app restrictions use the tenant's primary domain",
    allowedDomain === "example.com",
    JSON.stringify(allowedDomain),
  );

  // Connector policies carry several fields, and each enum has to come from
  // the field that declares it rather than from anywhere in the schema.
  const upload = requests.find(
    (request) =>
      (request.policyValue as { policySchema?: string }).policySchema ===
      "chrome.users.OnFileAttachedConnectorPolicy",
  );
  const uploadValue =
    (upload?.policyValue as { value?: Record<string, unknown> })?.value ?? {};
  check(
    "a connector policy sets every field the schema offers a value for",
    typeof uploadValue.onFileAttachedAnalysisConnectorConfiguration === "object" &&
      uploadValue.serviceProvider === "google" &&
      uploadValue.delayDeliveryUntilVerdict === "DELAY_UPLOADS",
    JSON.stringify(uploadValue),
  );
  check(
    "the update mask lists exactly the fields written",
    JSON.stringify(String(upload?.updateMask ?? "").split(",").filter(Boolean).sort()) ===
      JSON.stringify(Object.keys(uploadValue).sort()),
    JSON.stringify(upload?.updateMask),
  );

  // Regression: `realtimeUrlCheckEnabled` is a boolean here and an enum on
  // other tenants, so the type decides the value rather than the definition.
  const urlCheck = requests.find(
    (request) =>
      (request.policyValue as { policySchema?: string }).policySchema ===
      "chrome.users.RealtimeUrlCheck",
  );
  const urlCheckValue =
    (urlCheck?.policyValue as { value?: Record<string, unknown> })?.value ?? {};
  check(
    "a boolean field is written as a boolean, not an enum constant",
    urlCheckValue.realtimeUrlCheckEnabled === true,
    JSON.stringify(urlCheckValue),
  );

  const securityEvent = requests.find(
    (request) =>
      (request.policyValue as { policySchema?: string }).policySchema ===
      "chrome.users.OnSecurityEvent",
  );
  const securityValue =
    (securityEvent?.policyValue as { value?: Record<string, unknown> })?.value ?? {};
  check(
    "the reporting connector picks its own enum, not another field's",
    securityValue.reportingConnector === "GOOGLE" &&
      JSON.stringify(securityValue.enabledEventNames ?? "").includes("sensitiveDataEvent"),
    JSON.stringify(securityValue),
  );
}

{
  const { transport, calls } = stubTransport();
  await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...FULL_CONFIG,
    force_extensions: false,
    connectors: false,
    data_boundary_mode: "none" as const,
  });
  const schemas = schemasIn(batchRequests(calls, "batchModify"));
  check(
    "deselected modules are not written",
    !schemas.includes("chrome.users.apps.InstallType") &&
      !schemas.some((schema) => schema.includes("ConnectorPolicy")),
    schemas.join(", "),
  );
}

{
  const { transport, calls } = stubTransport();
  const result = (await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...FULL_CONFIG,
    core_policies: false,
    force_extensions: false,
    connectors: false,
    data_boundary_mode: "none" as const,
  })) as ProvisionResult;
  check(
    "an empty selection is reported as a failure, not as a successful no-op",
    !result.success && batchRequests(calls, "batchModify").length === 0,
    result.message,
  );
}

// -- 3. Sub organizational units ----------------------------------------------

{
  const { transport, calls } = stubTransport();
  const result = (await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...FULL_CONFIG,
    create_sub_ous: true,
  })) as ProvisionResult;

  const created = orgUnitCreations(calls);
  check(
    "both sub OUs are created beneath the selected OU",
    created.length === 2 &&
      created.every((call) => (call.body as { parentOrgUnitPath?: string }).parentOrgUnitPath === "/Pilot"),
    JSON.stringify(created.map((call) => call.body)),
  );

  const targets = batchRequests(calls, "batchModify").map(
    (request) => (request.policyTargetKey as { targetResource?: string }).targetResource,
  );
  check(
    "sub-OU scaffolding keeps policies on the populated pilot OU so current occupants are covered",
    new Set(targets).size === 1 && targets.every((target) => target === "orgunits/03pilot"),
    [...new Set(targets)].join(", "),
  );
  check(
    "sub-OU provisioning discloses inheritance and that occupants are not moved",
    result.skipped_items.some(
      (item) => item.includes("Policies remain on the selected pilot OU") &&
        item.includes("no occupant was moved automatically"),
    ),
    result.skipped_items.join(" | "),
  );
  check(
    "created OUs are reported back",
    result.created_items.some((item) => item.includes("CEP Users")),
    result.created_items.join(", "),
  );
}

{
  const { transport, calls } = stubTransport({
    existingOus: [
      { path: "/Pilot/CEP Users", id: "03users" },
      { path: "/Pilot/CEP Browsers", id: "03browsers" },
    ],
  });
  await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...FULL_CONFIG,
    create_sub_ous: true,
  });
  check("existing sub OUs are reused rather than duplicated", orgUnitCreations(calls).length === 0);
}

{
  const overLimitUsers = Array.from(
    { length: CEP_LICENSE_PILOT_USER_LIMIT + 1 },
    (_, index) => ({
      primaryEmail: `pilot-${index + 1}@example.com`,
      orgUnitPath: "/Pilot",
    }),
  );
  const { transport, calls } = stubTransport({ directoryUsers: overLimitUsers });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  )) as { success: boolean; total_users: number; assigned_count: number };
  check(
    "an exact OU above the ten-user pilot cap is rejected before mutation",
    !result.success &&
      result.total_users === CEP_LICENSE_PILOT_USER_LIMIT + 1 &&
      result.assigned_count === 0 &&
      !calls.some((call) =>
        call.method === "POST" && call.url.includes("licensing.googleapis.com")
      ),
    JSON.stringify({ result, licensing: calls.filter((call) => call.url.includes("licensing")) }),
  );
}

{
  const { transport, calls } = stubTransport();
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    {
      ...FULL_CONFIG,
      dlp_rules: true,
      dlp_matrix: {
        genai_block: { upload: "blockContent", paste: "blockContent" },
      },
    },
  )) as ProvisionResult;
  const requests = batchRequests(calls, "batchModify");
  const valueFor = (schema: string, field: string): unknown => {
    const request = requests.find(
      (candidate) =>
        (candidate.policyValue as { policySchema?: string }).policySchema === schema,
    );
    return ((request?.policyValue as { value?: Record<string, unknown> })?.value ?? {})[
      field
    ];
  };
  const blocked = valueFor("chrome.users.URLBlocklist", "urlBlocklist");
  const allowed = valueFor("chrome.users.URLAllowlist", "urlAllowlist");

  check("GenAI protection provisions successfully", result.success, result.message);
  check(
    "GenAI URL policies use valid host filters without unsupported trailing wildcards",
    JSON.stringify(blocked) ===
        JSON.stringify([
          "chatgpt.com",
          "claude.ai",
          "deepseek.com",
          "poe.com",
          "perplexity.ai",
          "copilot.microsoft.com",
        ]) &&
      JSON.stringify(allowed) ===
        JSON.stringify(["gemini.google.com", "workspace.google.com"]) &&
      !JSON.stringify([blocked, allowed]).includes("*"),
    JSON.stringify({ blocked, allowed }),
  );
}

{
  const pages = Array.from(
    { length: CEP_LICENSE_DIRECTORY_PAGE_LIMIT + 1 },
    (_, index) => [{
      primaryEmail: `child-${index + 1}@example.com`,
      orgUnitPath: `/Pilot/Child-${index + 1}`,
    }],
  );
  const { transport, calls } = stubTransport({ directoryPages: pages });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  )) as { success: boolean };
  check(
    "an incomplete bounded Directory enumeration mutates zero licences",
    !result.success &&
      calls.filter((call) => call.url.includes("/users?")).length ===
        CEP_LICENSE_DIRECTORY_PAGE_LIMIT &&
      !calls.some((call) =>
        call.method === "POST" && call.url.includes("licensing.googleapis.com")
      ),
    JSON.stringify({ result, calls }),
  );
}

{
  const stub = stubTransport({
    directoryUsers: [{ primaryEmail: "timeout@example.com", orgUnitPath: "/Pilot" }],
  });
  const hangingPostTransport: Transport = {
    ...stub.transport,
    requestJson(method, url, options) {
      if (method === "POST" && url.includes("licensing.googleapis.com")) {
        stub.calls.push({
          method,
          url,
          body: options?.jsonBody,
          acceptedStatuses: options?.acceptedStatuses,
          at: 0,
        });
        return new Promise<TransportResponse>(() => undefined);
      }
      return stub.transport.requestJson(method, url, options);
    },
  };
  const timeoutContext = context(hangingPostTransport);
  timeoutContext.cepLicenseRequestTimeoutMs = 10;
  let ambiguous = false;
  const startedAt = Date.now();
  try {
    await route(
      timeoutContext,
      "POST",
      "/api/v1/cep/assign-licenses",
      {
        project_id: "secgw-project",
        customer_id: "C01abcdef",
        target_ou_id: "03pilot",
        target_ou_path: "/Pilot",
        target_ou_confirmation: "/Pilot",
      },
    );
  } catch (error) {
    ambiguous = (error as { status?: unknown; code?: unknown }).status === 503 &&
      (error as { code?: unknown }).code === "cep-mutation-outcome-ambiguous";
  }
  check(
    "a timed-out licence POST performs exact GET reconciliation and retains its durable lease",
    ambiguous &&
      Date.now() - startedAt < 1_000 &&
      stub.calls.filter((call) =>
        call.method === "GET" && call.url.includes("licensing.googleapis.com")
      ).length === 2 &&
      activeCepLeases.size > 0,
    JSON.stringify({ ambiguous, elapsedMs: Date.now() - startedAt, calls: stub.calls }),
  );
  activeCepLeases.clear();
}

{
  const stub = stubTransport();
  const hangingCustomerRead: Transport = {
    ...stub.transport,
    requestJson(method, url, options) {
      if (
        method === "GET" &&
        /admin\/directory\/v1\/customers\//.test(url)
      ) {
        stub.calls.push({
          method,
          url,
          body: options?.jsonBody,
          acceptedStatuses: options?.acceptedStatuses,
          at: 0,
        });
        return new Promise<TransportResponse>(() => undefined);
      }
      return stub.transport.requestJson(method, url, options);
    },
  };
  const timeoutContext = context(hangingCustomerRead);
  timeoutContext.cepLicenseRequestTimeoutMs = 10;
  let timedOutReadOnly = false;
  try {
    await route(
      timeoutContext,
      "POST",
      "/api/v1/cep/assign-licenses",
      {
        project_id: "secgw-project",
        customer_id: "C01abcdef",
        target_ou_id: "03pilot",
        target_ou_path: "/Pilot",
        target_ou_confirmation: "/Pilot",
      },
    );
  } catch (error) {
    timedOutReadOnly = (error as { status?: unknown; code?: unknown }).status === 504 &&
      (error as { code?: unknown }).code === "cep-license-preguard-timeout";
  }
  check(
    "a timed-out customer/OU preguard returns promptly with zero mutation and no lease",
    timedOutReadOnly &&
      !stub.calls.some((call) => call.method !== "GET") &&
      activeCepLeases.size === 0,
    JSON.stringify({ timedOutReadOnly, calls: stub.calls, leases: activeCepLeases.size }),
  );
}

check(
  "the production licence route has a declared worst-case network wait below five minutes",
  CEP_LICENSE_ROUTE_MAX_NETWORK_WAIT_MS === 195_000 &&
    CEP_LICENSE_ROUTE_MAX_NETWORK_WAIT_MS < 5 * 60_000,
  String(CEP_LICENSE_ROUTE_MAX_NETWORK_WAIT_MS),
);

{
  const { transport, calls } = stubTransport({ failOrgUnitCreate: true });
  const result = (await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...FULL_CONFIG,
    create_sub_ous: true,
  })) as ProvisionResult;
  const policyMutations = calls.filter(
    (call) =>
      call.method === "POST" &&
      (call.url.includes("orgunits:batchModify") ||
        call.url.includes("cloudidentity.googleapis.com") ||
        call.url.includes("accesscontextmanager.googleapis.com")),
  );
  check(
    "a requested child-OU failure stops before every policy mutation instead of targeting the parent",
    !result.success &&
      policyMutations.length === 0 &&
      result.skipped_items.some((item) => item.includes("no policy was applied")),
    `${result.message} | ${policyMutations.map((call) => call.url).join(" | ")}`,
  );
}

// -- 4. Degradation is visible, not silent ------------------------------------

{
  const { transport } = stubTransport({
    missingSchemas: ["chrome.users.OnSecurityEvent"],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    FULL_CONFIG,
  )) as ProvisionResult;
  check(
    "a schema this tenant does not serve is reported as skipped, with a reason",
    !result.success &&
      result.skipped_items.some((item) => item.includes("Security event reporting")),
    result.skipped_items.join(" | "),
  );
  check("the rest of the deployment still applies", result.created_items.length > 0);
}

{
  const { transport, calls } = stubTransport({ schemaPageCount: 41 });
  const result = (await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...FULL_CONFIG,
    force_extensions: false,
    connectors: false,
    data_boundary_mode: "none" as const,
  })) as ProvisionResult;
  check(
    "an incomplete schema catalogue fails closed even if selected schemas appeared on an early page",
    !result.success &&
      batchRequests(calls, "batchModify").length === 0 &&
      result.skipped_items.some((item) => item.includes("policy-schema-catalogue-incomplete")),
    `${result.message} | ${result.skipped_items.join(" | ")}`,
  );
}

{
  const { transport } = stubTransport({
    failing: [{ match: "orgunits:batchModify", status: 403, message: "caller lacks permission" }],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    FULL_CONFIG,
  )) as ProvisionResult;
  check("a rejected batch is reported as a failure", !result.success, result.message);
  check(
    "the trace carries Google's reason",
    result.debug_trace.some((item) => !item.ok && (item.error ?? "").includes("caller lacks permission")),
    JSON.stringify(result.debug_trace),
  );
}

for (const organizationUnits of [
  null,
  [{ orgUnitId: "id:03pilot", orgUnitPath: "/Pilot" }],
  [
    { orgUnitId: "id:03pilot", orgUnitPath: "/Pilot", name: "Pilot" },
    { orgUnitId: "03PILOT", orgUnitPath: "/pilot-copy", name: "Duplicate" },
  ],
] as unknown[]) {
  const { transport, calls } = stubTransport({
    orgUnitsPayloadOverride: organizationUnits,
  });
  let rejected = false;
  try {
    await route(
      context(transport),
      "POST",
      "/api/v1/cep/provision",
      { ...FULL_CONFIG, create_sub_ous: true },
    );
  } catch (error) {
    rejected = (error as { status?: unknown; code?: unknown }).status === 502 &&
      (error as { code?: unknown }).code === "cep-target-ou-inventory-invalid";
  }
  const ouCreates = calls.filter(
    (call) => call.method === "POST" && /\/orgunits(?:\?|$)/.test(call.url),
  );
  check(
    "malformed or duplicate Directory OU inventory fails closed before OU/policy mutation",
    rejected && ouCreates.length === 0 &&
      batchRequests(calls, "batchModify").length === 0,
    JSON.stringify({ organizationUnits, rejected, ouCreates }),
  );
}

// -- 5. Rollback is fail-closed without a durable CEP ownership ledger -------

{
  const { transport, calls } = stubTransport({
    existingOus: [
      { path: "/Pilot/CEP Users", id: "cep-users" },
      { path: "/Pilot/CEP Browsers", id: "cep-browsers" },
    ],
  });
  const result = (await route(context(transport), "POST", "/api/v1/cep/rollback", {
    project_id: "secgw-project",
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    target_ou_path: "/Pilot",
  })) as ProvisionResult;

  const resolveCalls = calls.filter((call) => call.url.endsWith("/policies:resolve"));
  const inspected = new Set(
    resolveCalls.map((call) => call.body?.policySchemaFilter as string),
  );
  const writable = new Set(
    schemasIn(
      batchRequests(
        (
          await (async () => {
            const stub = stubTransport();
            await route(context(stub.transport), "POST", "/api/v1/cep/provision", {
              ...FULL_CONFIG,
              data_boundary_mode: "block_non_corp" as const,
            });
            return stub.calls;
          })()
        ),
        "batchModify",
      ),
    ),
  );

  check(
    "rollback reports retained state when three-way ownership images are unavailable",
    !result.success && result.message.includes("made no destructive change"),
    result.message,
  );
  check(
    "rollback resolves exact normal and app-scoped targets without batchInherit",
    resolveCalls.length > 0 &&
      calls.every((call) => !call.url.includes("orgunits:batchInherit")) &&
      resolveCalls.some((call) => {
        const key = call.body?.policyTargetKey as
          | { additionalTargetKeys?: Record<string, string> }
          | undefined;
        return key?.additionalTargetKeys?.app_id ===
          "chrome:callobklhcbilhphinckomhgkigmfocg";
      }),
    JSON.stringify(resolveCalls),
  );
  const inspectedResources = new Set(
    resolveCalls.map(
      (call) =>
        (call.body?.policyTargetKey as { targetResource?: string } | undefined)
          ?.targetResource,
    ),
  );
  check(
    "rollback inventories both the current parent target and legacy child targets",
    inspectedResources.has("orgunits/03pilot") &&
      inspectedResources.has("orgunits/cep-users") &&
      inspectedResources.has("orgunits/cep-browsers"),
    JSON.stringify([...inspectedResources]),
  );
  for (const schema of writable) {
    check(`rollback inventories ${schema} without mutating it`, inspected.has(schema));
  }
  check(
    "rollback performs no Chrome policy mutation",
    calls.every(
      (call) =>
        !call.url.includes("orgunits:batchModify") &&
        !call.url.includes("orgunits:batchInherit"),
    ),
  );
}

{
  const { transport, calls } = stubTransport({
    existingOus: [
      { path: "/Pilot/CEP Users", id: "cep-users" },
      { path: "/Pilot/CEP Browsers", id: "cep-browsers" },
    ],
    failBatchInheritAt: 1,
  });
  const result = (await route(context(transport), "POST", "/api/v1/cep/rollback", {
    project_id: "secgw-project",
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    target_ou_path: "/Pilot",
  })) as ProvisionResult;
  check(
    "rollback never enters a partial-mutation state",
    !result.success &&
      calls.every((call) => !call.url.includes("orgunits:batchInherit")) &&
      result.created_items.length === 0 &&
      result.skipped_items.some((item) => item.includes("retained")),
    `${result.message} | ${result.created_items.join("; ")} | ${result.skipped_items.join("; ")}`,
  );
}

{
  const { transport, calls } = stubTransport();
  await route(context(transport), "POST", "/api/v1/cep/rollback", {
    project_id: "secgw-project",
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    rollback_modules: ["core"],
  });
  const schemas = calls
    .filter((call) => call.url.endsWith("/policies:resolve"))
    .map((call) => call.body?.policySchemaFilter as string);
  check(
    "a scoped rollback inventories only the modules it was given",
    schemas.length > 0 && schemas.every((schema) => schema.includes("chrome.users.")) &&
      !schemas.includes("chrome.users.apps.InstallType") &&
      calls.every((call) => !call.url.includes("orgunits:batchInherit")),
    schemas.join(", "),
  );
}

// -- 6. Workspace administrator roles ----------------------------------------

{
  const { transport, calls } = stubTransport();
  const result = (await route(context(transport), "POST", "/api/v1/cep/roles", {
    project_id: "secgw-project",
    customer_id: "C01abcdef",
    role_type: "both",
    assigned_user_email: "auditor@example.com",
  })) as { success: boolean; message: string; roles: string[] };

  check(
    "legacy custom-role provisioning fails closed with Admin console guidance",
    !result.success &&
      result.roles.length === 0 &&
      result.message.includes("Google Admin console") &&
      result.message.includes("Super Admin"),
    result.message,
  );
  check(
    "legacy custom-role provisioning performs no IAM mutation",
    calls.length === 0,
    calls.map((call) => `${call.method} ${call.url}`).join(", "),
  );
}

// -- 7. The exported script matches the selection -----------------------------

{
  const { transport } = stubTransport();
  const full = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/script",
    FULL_CONFIG,
  )) as { script: string; filename: string };

  const { transport: leanTransport } = stubTransport();
  const lean = (await route(context(leanTransport), "POST", "/api/v1/cep/script", {
    ...FULL_CONFIG,
    force_extensions: false,
    connectors: false,
    data_boundary_mode: "none" as const,
  })) as { script: string };

  let exportedGroups: Array<
    Array<{ policyTargetKey: Record<string, unknown> }>
  > = [];
  try {
    const prefix = "REQUEST_GROUPS = ";
    const start = full.script.indexOf(prefix) + prefix.length;
    const end = full.script.indexOf("\n\n\ndef main()", start);
    const jsonCompatible = full.script
      .slice(start, end)
      .replace(/\bTrue\b/g, "true")
      .replace(/\bFalse\b/g, "false")
      .replace(/\bNone\b/g, "null")
      .replace(/,\s*([}\]])/g, "$1");
    exportedGroups = JSON.parse(jsonCompatible) as typeof exportedGroups;
  } catch {
    exportedGroups = [];
  }

  check("the script is named for download", full.filename === "cep_configure.py");
  check(
    "the script reflects the selected modules",
    full.script.includes("OnFileAttachedConnectorPolicy") &&
      !lean.script.includes("OnFileAttachedConnectorPolicy"),
  );
  check(
    "the script is shorter when fewer modules are selected",
    lean.script.length < full.script.length,
  );
  check(
    "JSON literals are emitted as Python",
    !/[^"]\btrue\b/.test(full.script) && !/\bnull\b/.test(full.script),
  );
  check(
    "interpolated values are quoted rather than pasted in",
    full.script.includes('CUSTOMER_ID = "C01abcdef"'),
  );
  check(
    "the exported script runs one target-compatible batch at a time",
    exportedGroups.length === 2 &&
      exportedGroups.every((group) => {
        const signatures = new Set(
          group.map((request) => {
            const key = request.policyTargetKey;
            const additional = key.additionalTargetKeys;
            const names =
              additional !== null && typeof additional === "object"
                ? Object.keys(additional).sort()
                : [];
            return JSON.stringify([key.targetResource, names]);
          }),
        );
        return signatures.size === 1;
      }) &&
      full.script.includes("REQUEST_GROUPS = [") &&
      full.script.includes("for index, requests in enumerate(REQUEST_GROUPS, start=1)") &&
      full.script.includes('body={"requests": requests}') &&
      !full.script.includes('body={"requests": REQUESTS}'),
    JSON.stringify(exportedGroups),
  );
  check(
    "the exported script stops explicitly after a partial batch failure",
    full.script.includes("later batches were not attempted") &&
      full.script.includes("raise RuntimeError"),
  );
}

// -- 7b. Schema names are looked up, not assumed ------------------------------

{
  // A live tenant served seven of eleven policies under names other than the
  // ones Google's published policy list implies. Resolution walks exact name,
  // then trailing segment, then the definition's matcher.
  const { transport, calls } = stubTransport({
    missingSchemas: ["chrome.users.CloudReportingEnabled"],
  });
  // Serve the same policy under a namespace we did not predict.
  SCHEMA_FIELDS["chrome.users.reporting.CloudReportingEnabled"] =
    SCHEMA_FIELDS["chrome.users.CloudReportingEnabled"];

  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    FULL_CONFIG,
  )) as ProvisionResult;
  delete SCHEMA_FIELDS["chrome.users.reporting.CloudReportingEnabled"];

  const schemas = schemasIn(batchRequests(calls, "batchModify"));
  check(
    "a policy served under a different namespace is still found and written",
    schemas.includes("chrome.users.reporting.CloudReportingEnabled"),
    schemas.join(", "),
  );
  check(
    "it is not reported as missing",
    !result.skipped_items.some((item) => item.includes("Chrome cloud reporting")),
    result.skipped_items.join(" | "),
  );
}

{
  // When nothing matches, the message names what the tenant does serve, so the
  // next fix does not need another live run to discover the real name.
  const { transport } = stubTransport({
    missingSchemas: ["chrome.users.SafeBrowsingProtectionLevel"],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    FULL_CONFIG,
  )) as ProvisionResult;
  check(
    "an unresolvable schema is reported with the closest names available",
    result.skipped_items.some(
      (item) => item.includes("Enhanced Safe Browsing") && item.includes("Closest names"),
    ),
    result.skipped_items.join(" | "),
  );
}

// -- 7c. Context-Aware Access is a selection, not a flag ----------------------

{
  // An AUTO_CREATE sentinel builds a level, and rollback may delete it.
  const { transport, calls } = stubTransport();
  const result = (await route(context(transport, "999"), "POST", "/api/v1/cep/provision", {
    ...FULL_CONFIG,
    access_level: "AUTO_CREATE_CHROME_ANY",
  })) as ProvisionResult;
  check(
    "an auto-create selection provisions an access level",
    result.created_items.some((item) => item.includes("Context-Aware Access level")),
    `${result.created_items.join(", ")} | ${result.skipped_items.join(" | ")}`,
  );
  check(
    "it is created through Access Context Manager",
    calls.some((call) => call.url.includes("accesscontextmanager")),
  );
  check(
    "CEP auto-create uses the persisted policy id without organization-level list",
    calls.some((call) => /\/accessPolicies\/999$/.test(call.url)) &&
      !calls.some((call) => /\/accessPolicies$/.test(call.url)),
    JSON.stringify(calls.filter((call) => call.url.includes("accesscontextmanager"))),
  );
}

{
  // A level the operator picked is used as-is: nothing is created for it.
  const { transport, calls } = stubTransport();
  const result = (await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...FULL_CONFIG,
    access_level: "accessPolicies/123/accessLevels/corp_managed",
  })) as ProvisionResult;
  check(
    "selecting an existing level creates nothing in Access Context Manager",
    !calls.some(
      (call) => call.method === "POST" && call.url.includes("accesscontextmanager"),
    ),
    calls.filter((call) => call.url.includes("accesscontextmanager")).map((c) => c.url).join(", "),
  );
  check(
    "and the deployment still succeeds",
    result.success,
    result.message,
  );
}

for (const rollbackCase of [
  {
    selection: "AUTO_CREATE_PROFILE_MANAGED",
    suffix: "secgw_profile_managed",
    expression:
      "device.chrome.management_state == ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED",
  },
  {
    selection: "AUTO_CREATE_BROWSER_MANAGED",
    suffix: "secgw_browser_managed",
    expression:
      "device.chrome.management_state == ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED",
  },
  {
    selection: "AUTO_CREATE_CHROME_ANY",
    suffix: "secgw_chrome_managed",
    expression:
      "device.chrome.management_state in [ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED, ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]",
  },
] as const) {
  const name = `accessPolicies/999/accessLevels/${rollbackCase.suffix}`;
  const { transport, calls } = stubTransport({
    existingAccessLevels: [
      {
        name,
        description: "Created automatically by Secure Gateway Studio",
        expression: rollbackCase.expression,
      },
    ],
  });
  const result = (await route(context(transport, "999"), "POST", "/api/v1/cep/rollback", {
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    target_ou_path: "/Pilot",
    project_id: "secgw-project",
    access_level: rollbackCase.selection,
    rollback_modules: ["contextAwareAccess"],
  })) as ProvisionResult;
  const accessCalls = calls.filter((call) => call.url.includes("accesscontextmanager"));
  const levelReadIndex = accessCalls.findIndex(
    (call) => call.method === "GET" && call.url.endsWith(name),
  );
  const deleteIndex = accessCalls.findIndex(
    (call) => call.method === "DELETE" && call.url.endsWith(name),
  );
  check(
    `${rollbackCase.selection} rollback reads but retains a template match without run ownership`,
    !result.success &&
      levelReadIndex >= 0 &&
      deleteIndex === -1 &&
      accessCalls.every((call) => call.method !== "POST") &&
      result.skipped_items.some((item) => item.includes("durable run ownership marker")),
    JSON.stringify(accessCalls),
  );
}

{
  const { transport } = stubTransport({
    failing: [
      {
        match: "/accessPolicies/999/accessLevels/secgw_chrome_managed",
        status: 403,
        message: "access-level create forbidden",
      },
    ],
  });
  const result = (await route(context(transport, "999"), "POST", "/api/v1/cep/provision", {
    ...FULL_CONFIG,
    access_level: "AUTO_CREATE_CHROME_ANY",
  })) as ProvisionResult;
  check(
    "a requested access-level failure makes a partially applied deployment fail",
    !result.success &&
      result.created_items.length > 0 &&
      result.skipped_items.some((item) => item.includes("Context-Aware Access:")),
    `${result.message} | ${result.skipped_items.join(" | ")}`,
  );
}

{
  const name = "accessPolicies/999/accessLevels/secgw_chrome_managed";
  const { transport, calls } = stubTransport({
    existingAccessLevels: [
      {
        name,
        description: "Created by another administrator",
        expression:
          "device.chrome.management_state in [ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED, ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]",
      },
    ],
  });
  const result = (await route(context(transport, "999"), "POST", "/api/v1/cep/rollback", {
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    target_ou_path: "/Pilot",
    project_id: "secgw-project",
    access_level: "AUTO_CREATE_CHROME_ANY",
    rollback_modules: ["contextAwareAccess"],
  })) as ProvisionResult;
  const accessCalls = calls.filter((call) => call.url.includes("accesscontextmanager"));
  check(
    "AUTO_CREATE rollback retains a same-name access level without exact ownership markers",
    accessCalls.some((call) => call.method === "GET" && call.url.endsWith(name)) &&
      accessCalls.every((call) => call.method !== "DELETE" && call.method !== "POST") &&
      result.skipped_items.some((item) => item.includes("left in place")),
    `${JSON.stringify(accessCalls)} | ${result.skipped_items.join(" | ")}`,
  );
}

{
  // The safety property the dropdown introduces: a level we did not create is
  // never deleted, however thorough the rollback is.
  const { transport, calls } = stubTransport();
  const result = (await route(context(transport), "POST", "/api/v1/cep/rollback", {
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    target_ou_path: "/Pilot",
    project_id: "secgw-project",
    access_level: "accessPolicies/123/accessLevels/corp_managed",
  })) as ProvisionResult;
  check(
    "rollback does not delete an access level the operator selected",
    !calls.some(
      (call) => call.method === "DELETE" && call.url.includes("accesscontextmanager"),
    ),
    calls.filter((call) => call.method === "DELETE").map((c) => c.url).join(", "),
  );
  check(
    "and says so rather than staying silent",
    result.skipped_items.some((item) => item.includes("was left in place")),
    result.skipped_items.join(" | "),
  );
}

// -- 7d. Message fields and per-policy attribution ----------------------------

{
  // Regression: a scalar written into a message-typed field failed the entire
  // connectors batch with "Expect message object but got: true".
  const { transport, calls } = stubTransport();
  await route(context(transport), "POST", "/api/v1/cep/provision", FULL_CONFIG);
  const upload = batchRequests(calls, "batchModify").find(
    (request) =>
      (request.policyValue as { policySchema?: string }).policySchema ===
      "chrome.users.OnFileAttachedConnectorPolicy",
  );
  const uploadValue =
    (upload?.policyValue as { value?: Record<string, unknown> })?.value ?? {};
  const configuration = uploadValue.onFileAttachedAnalysisConnectorConfiguration;
  check(
    "a message-typed field is written as an object, never as a scalar",
    typeof configuration === "object" && configuration !== null,
    JSON.stringify(configuration),
  );
  check(
    "the object is built from the nested message the schema declares",
    JSON.stringify(configuration).includes("enableScanning") &&
      JSON.stringify(configuration).includes("google"),
    JSON.stringify(configuration),
  );
}

{
  // Regression: "the connectors batch was rejected" convicted all four
  // policies. A failed batch is re-sent one policy at a time.
  const { transport, calls } = stubTransport({
    failing: [
      { match: "orgunits:batchModify", status: 400, message: "Insufficient quota." },
    ],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    FULL_CONFIG,
  )) as ProvisionResult;

  const batches = calls.filter((call) => call.url.includes("orgunits:batchModify"));
  const singles = batches.filter(
    (call) => ((call.body?.requests ?? []) as unknown[]).length === 1,
  );
  check(
    "a rejected batch is retried one policy at a time",
    singles.length > 0,
    `${batches.length} calls, ${singles.length} single-policy`,
  );
  check(
    "each policy is skipped with the API's own reason, not a batch-wide excuse",
    result.skipped_items.some((item) => item.includes("Insufficient quota.")) &&
      !result.skipped_items.some((item) => item.includes("batch was rejected")),
    result.skipped_items.join(" | "),
  );
}

{
  // Regression: a loose matcher resolved the password-reuse warning onto
  // `PasswordDismissCompromisedAlertEnabled`, a different setting entirely.
  const { transport } = stubTransport({
    missingSchemas: ["chrome.users.PasswordProtectionWarningTrigger"],
  });
  SCHEMA_FIELDS["chrome.users.PasswordDismissCompromisedAlertEnabled"] = [
    { name: "passwordDismissCompromisedAlertEnabled", type: "TYPE_BOOL" },
  ];
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    FULL_CONFIG,
  )) as ProvisionResult;
  delete SCHEMA_FIELDS["chrome.users.PasswordDismissCompromisedAlertEnabled"];

  check(
    "a same-word-different-meaning policy is not written to by mistake",
    !JSON.stringify(result.created_items).includes("Password reuse") &&
      !result.skipped_items.some((item) =>
        item.includes("passwordDismissCompromisedAlertEnabled"),
      ),
    result.skipped_items.join(" | "),
  );
}

// -- 8. DLP rules -------------------------------------------------------------

const DLP_CONFIG = {
  ...FULL_CONFIG,
  core_policies: false,
  force_extensions: false,
  connectors: false,
  data_boundary_mode: "none" as const,
  dlp_detectors: false,
  dlp_rules: true,
};

async function generatedDlpPolicy(displayName: string): Promise<{
  value: Record<string, unknown>;
  policyQuery: Record<string, unknown>;
}> {
  const { transport, calls } = stubTransport();
  await route(context(transport), "POST", "/api/v1/cep/provision", DLP_CONFIG);
  const create = calls.find((call) => {
    if (call.method !== "POST" || !call.url.includes("cloudidentity.googleapis.com")) {
      return false;
    }
    const setting = (call.body?.setting ?? {}) as {
      value?: { displayName?: string };
    };
    return setting.value?.displayName === displayName;
  });
  if (create === undefined) throw new Error(`test fixture did not create ${displayName}`);
  const setting = (create.body?.setting ?? {}) as { value?: Record<string, unknown> };
  return {
    value: structuredClone(setting.value ?? {}),
    policyQuery: structuredClone(
      (create.body?.policyQuery ?? {}) as Record<string, unknown>,
    ),
  };
}

const PAYMENT_CARD_UPLOAD_NAME = "CEP PoC - Payment card numbers - upload";
const PAYMENT_CARD_UPLOAD = await generatedDlpPolicy(PAYMENT_CARD_UPLOAD_NAME);

{
  const { transport, calls } = stubTransport();
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;

  const created = calls.filter(
    (call) => call.method === "POST" && call.url.includes("cloudidentity"),
  );
  const settingTypes = created.map(
    (call) => ((call.body?.setting ?? {}) as { type?: string }).type,
  );

  check("DLP provisioning succeeds", result.success, result.message);
  check(
    "only supported DLP rule settings are sent to the Policy API",
    settingTypes.length >= 2 &&
      settingTypes.every((type) => type === "settings/rule.dlp") &&
      !JSON.stringify(created.map((call) => call.body)).includes("urlList") &&
      created.every((call) => call.body?.customer === "customers/C01abcdef"),
    settingTypes.join(", "),
  );
  const policyCalls = calls.filter((call) => call.url.includes("cloudidentity.googleapis.com"));
  check(
    "all Cloud Identity list and create requests share the one-QPS limiter",
    policyCalls.slice(1).every(
      (call, index) => call.at - (policyCalls[index]?.at ?? call.at) >= 1_000,
    ),
    policyCalls.map((call) => `${call.method}@${call.at}`).join(", "),
  );

  // The policy query needs the CEL form and the org unit field together.
  const firstRule = created.find(
    (call) => ((call.body?.setting ?? {}) as { type?: string }).type === "settings/rule.dlp",
  );
  const query = (firstRule?.body?.policyQuery ?? {}) as { query?: string; orgUnit?: string };
  check(
    "policies are scoped to the target OU in both required forms",
    (query.query ?? "").includes("orgUnitId(") && (query.orgUnit ?? "").startsWith("orgUnits/"),
    JSON.stringify(query),
  );

  // Watermarking is a rule action parameter, not a Chrome policy.
  const watermark = created.find((call) =>
    JSON.stringify(call.body ?? {}).includes("watermarkMessage"),
  );
  check(
    "watermarking uses allow-with-warning params instead of blocking navigation",
    watermark !== undefined &&
      JSON.stringify(watermark.body).includes("blockScreenshot") &&
      JSON.stringify(watermark.body).includes("warnUser") &&
      !JSON.stringify(watermark.body).includes("blockContent"),
    JSON.stringify(watermark?.body),
  );

  const watermarkCondition = JSON.stringify(
    ((watermark?.body?.setting as { value?: { condition?: unknown } })?.value ?? {}).condition,
  );
  check(
    "the watermark rule embeds the internal URL as supported escaped CEL",
    watermarkCondition.includes('url.starts_with(\\"https://intranet.example.com\\")') &&
      !watermarkCondition.includes("matches_url_list"),
    watermarkCondition,
  );
}

{
  const { transport, calls } = stubTransport({ customerId: "Ccanonical123" });
  const result = (await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...DLP_CONFIG,
    customer_id: "my_customer",
  })) as ProvisionResult;
  const policyCalls = calls.filter((call) => call.url.includes("cloudidentity.googleapis.com"));
  const creates = policyCalls.filter((call) => call.method === "POST");
  check(
    "the Directory response canonicalizes my_customer before every DLP create",
    result.success &&
      creates.length > 0 &&
      creates.every((call) => call.body?.customer === "customers/Ccanonical123") &&
      policyCalls
        .filter((call) => call.method === "GET")
        .every((call) => decodeURIComponent(call.url).includes('customer == "customers/Ccanonical123"')),
    JSON.stringify(policyCalls),
  );
}

{
  const { transport, calls } = stubTransport({ customerId: null });
  let error: unknown;
  try {
    await route(context(transport), "POST", "/api/v1/cep/provision", {
      ...DLP_CONFIG,
      customer_id: "CcallerProvided",
    });
  } catch (caught) {
    error = caught;
  }
  check(
    "DLP fails closed when Directory does not confirm a canonical C id",
    (error as { status?: unknown; code?: unknown }).status === 502 &&
      (error as { code?: unknown }).code === "cep-customer-identity-invalid" &&
      !calls.some(
        (call) => call.method === "POST" && call.url.includes("cloudidentity.googleapis.com"),
      ),
    `${String(error)} | ${JSON.stringify(calls)}`,
  );
}

{
  const { transport, calls } = stubTransport();
  const result = (await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...DLP_CONFIG,
    dlp_matrix: {
      payment_card: { upload: "warnUser", byodOnly: false },
      universal_upload: { upload: "blockContent", byodOnly: true },
      access_level: { upload: "blockContent", byodOnly: true },
      watermark: { watermark: false, byodOnly: false },
    },
  })) as ProvisionResult;
  const bodies = JSON.stringify(
    calls
      .filter((call) => call.method === "POST" && call.url.includes("cloudidentity"))
      .map((call) => call.body),
  );
  check(
    "unsupported access-level and BYOD conditions fail closed without guessed CEL or scope broadening",
    !result.success &&
      result.created_items.some((item) => item.includes("Payment card numbers")) &&
      result.skipped_items.filter((item) => item.includes("access-level CEL")).length === 2 &&
      !bodies.includes("meets_access_requirements") &&
      !bodies.includes("Universal file upload protection") &&
      !bodies.includes("Unmanaged Chrome / BYOD"),
    `${bodies} | ${result.skipped_items.join(" | ")}`,
  );
}

{
  const hostileUrl = 'https://internal.example/\") || true || (\"';
  const { transport, calls } = stubTransport();
  await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...DLP_CONFIG,
    internal_urls: [hostileUrl],
  });
  const watermark = calls.find(
    (call) =>
      call.method === "POST" &&
      call.url.includes("cloudidentity") &&
      JSON.stringify(call.body ?? {}).includes("watermarkMessage"),
  );
  const condition = (
    (watermark?.body?.setting as {
      value?: { condition?: { contentCondition?: string } };
    })?.value?.condition?.contentCondition ?? ""
  );
  check(
    "an operator-supplied URL cannot escape the generated CEL string literal",
    condition === `url.starts_with(${JSON.stringify(hostileUrl)})`,
    condition,
  );
}

{
  const { transport, calls } = stubTransport({ dlpCreatePendingLists: 1 });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;
  const policyCalls = calls.filter((call) =>
    call.url.includes("cloudidentity.googleapis.com"),
  );
  const mutations = policyCalls
    .map((call, index) => ({ call, index }))
    .filter(({ call }) => call.method === "POST");
  check(
    "done:false DLP creates are reconciled before a dependent mutation runs",
    result.success &&
      mutations.length > 1 &&
      mutations.every(({ index }, mutationIndex) => {
        const nextIndex = mutations[mutationIndex + 1]?.index ?? policyCalls.length;
        return policyCalls
          .slice(index + 1, nextIndex)
          .some((call) => call.method === "GET");
      }),
    policyCalls.map((call) => `${call.method} ${call.url}@${call.at}`).join(" | "),
  );
  check(
    "LRO reconciliation remains on the shared one-QPS limiter",
    policyCalls.slice(1).every(
      (call, index) => call.at - (policyCalls[index]?.at ?? call.at) >= 1_000,
    ),
    policyCalls.map((call) => `${call.method}@${call.at}`).join(", "),
  );
}

{
  const { transport, calls } = stubTransport({
    dlpCreatePendingLists: 1_000,
    dlpCreatePendingAfter: 1,
  });
  let error: unknown;
  try {
    await route(
      context(transport),
      "POST",
      "/api/v1/cep/provision",
      DLP_CONFIG,
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "an unreconciled DLP create fails closed and retains its durable lease",
    (error as { status?: unknown; code?: unknown }).status === 503 &&
      (error as { code?: unknown }).code === "cep-mutation-outcome-ambiguous" &&
      calls.some((call) => call.method === "POST" && call.url.includes("cloudidentity")) &&
      activeCepLeases.size > 0,
    `${String(error)} | leases=${activeCepLeases.size}`,
  );
  activeCepLeases.clear();
}

{
  const malformedPayloads: Record<string, unknown>[] = [
    { policies: {} },
    { policies: [null] },
    {
      policies: [{
        name: "policies/missing-setting",
        policyQuery: {},
      }],
    },
    {
      policies: [{
        name: "policies/wrong-setting-type",
        setting: { type: "settings/detector", value: { displayName: "bad" } },
        policyQuery: {},
      }],
    },
    {
      policies: [{
        name: "policies/missing-display-name",
        setting: { type: "settings/rule.dlp", value: {} },
        policyQuery: {},
      }],
    },
    {
      policies: [{
        name: "policies/missing-query",
        setting: { type: "settings/rule.dlp", value: { displayName: "bad" } },
      }],
    },
    {
      policies: [
        {
          name: "policies/duplicate-id",
          setting: { type: "settings/rule.dlp", value: { displayName: "first" } },
          policyQuery: {},
        },
        {
          name: "policies/duplicate-id",
          setting: { type: "settings/rule.dlp", value: { displayName: "second" } },
          policyQuery: {},
        },
      ],
    },
  ];
  let accepted = 0;
  let mutations = 0;
  for (const payload of malformedPayloads) {
    const stub = stubTransport({ dlpListPayloadOverride: payload });
    const result = await route(
      context(stub.transport),
      "POST",
      "/api/v1/cep/provision",
      DLP_CONFIG,
    ) as ProvisionResult;
    if (result.success) accepted += 1;
    mutations += stub.calls.filter(
      (call) => call.method === "POST" && call.url.includes("cloudidentity.googleapis.com"),
    ).length;
  }
  check(
    "malformed DLP policy collections/items/settings/queries fail closed before create",
    accepted === 0 && mutations === 0,
    JSON.stringify({ accepted, mutations }),
  );
}

{
  const stub = stubTransport({ dlpListPayloadOverride: {} });
  const result = await route(context(stub.transport), "POST", "/api/v1/cep/rollback", {
    project_id: "secgw-project",
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    rollback_modules: ["dlpRules"],
  }) as ProvisionResult;
  check(
    "an omitted policies field is the official empty-list shape, not malformed data",
    !result.skipped_items.some((item) => item.includes("response-invalid")) &&
      !stub.calls.some((call) =>
        ["POST", "DELETE"].includes(call.method) && call.url.includes("cloudidentity.googleapis.com")
      ),
    JSON.stringify(result),
  );
}

{
  const stub = stubTransport({ dlpNextPageToken: null });
  const result = await route(
    context(stub.transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  ) as ProvisionResult;
  check(
    "a present null DLP page token fails closed before create",
    !result.success && !stub.calls.some((call) =>
      call.method === "POST" && call.url.includes("cloudidentity.googleapis.com")
    ),
    JSON.stringify(result),
  );
}

{
  const stub = stubTransport({ schemaNextPageToken: null });
  const result = await route(
    context(stub.transport),
    "POST",
    "/api/v1/cep/provision",
    FULL_CONFIG,
  ) as ProvisionResult;
  check(
    "a present null policy-schema page token blocks every Chrome Policy mutation",
    !result.success &&
      !stub.calls.some((call) => call.method === "POST" && call.url.includes("orgunits:batchModify")) &&
      result.skipped_items.some((item) => item.includes("policy-schema-catalogue-incomplete")),
    JSON.stringify(result),
  );
}

{
  const stub = stubTransport({ directoryNextPageToken: null });
  const result = await route(
    context(stub.transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  ) as { success: boolean };
  check(
    "a present null Directory user page token blocks every licensing mutation",
    !result.success && !stub.calls.some((call) => call.url.includes("licensing.googleapis.com")),
  );
}

{
  const duplicateIdentity = (displayName: string): StubDlpPolicy => ({
    name: "policies/duplicate-across-pages",
    displayName,
    type: "settings/rule.dlp",
    value: { displayName, state: "ACTIVE" },
    policyQuery: {},
  });
  const stub = stubTransport({
    dlpPages: [[duplicateIdentity("unrelated-a")], [duplicateIdentity("unrelated-b")]],
  });
  const result = await route(
    context(stub.transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  ) as ProvisionResult;
  check(
    "DLP list rejects a duplicate policy resource identity across pages before create",
    !result.success && !stub.calls.some((call) =>
      call.method === "POST" && call.url.includes("cloudidentity.googleapis.com")
    ),
    JSON.stringify(result),
  );
}

for (const mode of ["response-loss-commit", "503-commit"] as const) {
  const { transport, calls } = stubTransport({ dlpCreateMode: mode });
  const result = await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  ) as ProvisionResult;
  const creates = calls.filter(
    (call) => call.method === "POST" && call.url.includes("cloudidentity.googleapis.com"),
  );
  check(
    `DLP ${mode} reconciles exactly one full policy from the authoritative list`,
    result.success && creates.length > 0 &&
      result.created_items.filter((item) => item.includes("DLP rule")).length === creates.length &&
      activeCepLeases.size === 0,
    JSON.stringify({ mode, result, creates: creates.length, leases: activeCepLeases.size }),
  );
}

{
  const { transport, calls } = stubTransport({ dlpCreateMode: "503-no-commit" });
  let error: unknown;
  try {
    await route(context(transport), "POST", "/api/v1/cep/provision", DLP_CONFIG);
  } catch (caught) {
    error = caught;
  }
  check(
    "an undecidable DLP 503 retains the lease for exact-request reconciliation",
    (error as { status?: unknown; code?: unknown }).status === 503 &&
      (error as { code?: unknown }).code === "cep-mutation-outcome-ambiguous" &&
      calls.filter((call) =>
        call.method === "POST" && call.url.includes("cloudidentity.googleapis.com")
      ).length === 1 && activeCepLeases.size > 0,
    `${String(error)} | leases=${activeCepLeases.size}`,
  );
  activeCepLeases.clear();
}

{
  const { transport, calls } = stubTransport({ dlp429Count: 1 });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;
  const policyCalls = calls.filter((call) => call.url.includes("cloudidentity.googleapis.com"));
  check(
    "a 429 Cloud Identity response is retried after backoff",
    policyCalls.length > 1 &&
      policyCalls[0]?.url === policyCalls[1]?.url &&
      (policyCalls[1]?.at ?? 0) - (policyCalls[0]?.at ?? 0) >= 1_000,
    policyCalls.slice(0, 2).map((call) => `${call.url}@${call.at}`).join(", "),
  );
  check(
    "a recovered 429 does not leave a partially reported DLP deployment",
    result.success &&
      result.created_items.some((item) => item.includes("DLP rule")) &&
      !result.skipped_items.some((item) => item.includes("quota exceeded")),
    `${result.created_items.join(", ")} | ${result.skipped_items.join(" | ")}`,
  );
}

{
  const { transport, calls } = stubTransport({ dlp429Count: 1_000 });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;
  const policyCalls = calls.filter((call) => call.url.includes("cloudidentity.googleapis.com"));
  const firstUrl = policyCalls[0]?.url;
  check(
    "repeated Cloud Identity 429 stops at the bounded retry limit and fails closed",
    !result.success && firstUrl !== undefined &&
      policyCalls.filter((call) => call.url === firstUrl).length === 4 &&
      policyCalls.every((call) => call.acceptedStatuses?.includes(429) === true),
    policyCalls.map((call) => `${call.url}@${call.at}`).join(", "),
  );
}

{
  const { transport, calls } = stubTransport({
    failing: [{ match: "cloudidentity.googleapis.com", status: 403, message: "forbidden" }],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;
  const policyCalls = calls.filter((call) => call.url.includes("cloudidentity.googleapis.com"));
  const firstUrl = policyCalls[0]?.url;
  check(
    "Cloud Identity 403 is never retried as quota backoff",
    !result.success && firstUrl !== undefined &&
      policyCalls.filter((call) => call.url === firstUrl).length === 1,
    policyCalls.map((call) => call.url).join(", "),
  );
}

{
  // Regression guard for the API's 200-with-error-body shape: HTTP status alone
  // would read this as a success.
  const { transport } = stubTransport({ dlpRpcError: 7 });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;
  check(
    "an error code inside a 200 response is treated as a failure",
    result.created_items.length === 0 && result.skipped_items.length > 0,
    `${result.created_items.join(", ")} | ${result.skipped_items.join(" | ")}`,
  );
  check(
    "the skip message carries the reason rather than a generic sentence",
    result.skipped_items.some((item) => item.includes("empty sub-object")),
    result.skipped_items.join(" | "),
  );
  check(
    "the rpc code is explained rather than shown bare",
    result.debug_trace.some((item) => (item.error ?? "").includes("empty sub-object")),
    JSON.stringify(result.debug_trace.map((item) => item.error)),
  );
}

{
  const { transport, calls } = stubTransport({
    existingDlp: [
      {
        name: "policies/exact-payment-card-upload",
        displayName: PAYMENT_CARD_UPLOAD_NAME,
        type: "settings/rule.dlp",
        ...PAYMENT_CARD_UPLOAD,
      },
    ],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;
  const sameNameCreates = calls.filter((call) => {
    const setting = (call.body?.setting ?? {}) as { value?: { displayName?: string } };
    return call.method === "POST" && setting.value?.displayName === PAYMENT_CARD_UPLOAD_NAME;
  });
  check(
    "one same-name DLP policy is reused only when its full value and OU query match",
    result.success &&
      sameNameCreates.length === 0 &&
      result.skipped_items.some(
        (item) => item.includes(PAYMENT_CARD_UPLOAD_NAME) && item.includes("reused"),
      ),
    `${result.skipped_items.join(" | ")} | creates=${sameNameCreates.length}`,
  );
}

{
  const { transport, calls } = stubTransport({ dlpServerOutputFields: true });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;
  const createCalls = calls.filter(
    (call) => call.method === "POST" && call.url.includes("cloudidentity.googleapis.com"),
  );
  check(
    "new DLP rules reconcile when Cloud Identity adds timestamps and returns exact metadata in snake case",
    result.success && createCalls.length > 0 &&
      result.created_items.some((item) => item.includes("DLP rule")),
    JSON.stringify(result),
  );
}

{
  const mismatchedMetadata = structuredClone(PAYMENT_CARD_UPLOAD.value);
  mismatchedMetadata.ruleTypeMetadata = {
    dlpRuleMetadata: { alertSeverity: "HIGH" },
  };
  const { transport, calls } = stubTransport({
    existingDlp: [{
      name: "policies/high-severity-payment-card-upload",
      displayName: PAYMENT_CARD_UPLOAD_NAME,
      type: "settings/rule.dlp",
      value: mismatchedMetadata,
      policyQuery: PAYMENT_CARD_UPLOAD.policyQuery,
    }],
  });
  const result = await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  ) as ProvisionResult;
  check(
    "a same-name DLP policy with a different alert severity is never reused",
    !result.success &&
      !calls.some((call) => {
        const setting = call.body?.setting as { value?: { displayName?: string } } | undefined;
        return call.method === "POST" &&
          setting?.value?.displayName === PAYMENT_CARD_UPLOAD_NAME;
      }) &&
      result.skipped_items.some((item) =>
        item.includes(PAYMENT_CARD_UPLOAD_NAME) && item.includes("reserved-name-conflict")
      ),
    result.skipped_items.join(" | "),
  );
}

{
  const missingMetadata = structuredClone(PAYMENT_CARD_UPLOAD.value);
  delete missingMetadata.ruleTypeMetadata;
  const { transport } = stubTransport({
    existingDlp: [{
      name: "policies/missing-severity-payment-card-upload",
      displayName: PAYMENT_CARD_UPLOAD_NAME,
      type: "settings/rule.dlp",
      value: missingMetadata,
      policyQuery: PAYMENT_CARD_UPLOAD.policyQuery,
    }],
  });
  const result = await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  ) as ProvisionResult;
  check(
    "a same-name DLP policy without the approved alert severity is never reused",
    !result.success && result.skipped_items.some((item) =>
      item.includes(PAYMENT_CARD_UPLOAD_NAME) && item.includes("reserved-name-conflict")
    ),
    result.skipped_items.join(" | "),
  );
}

{
  const queryWithOutputFields = {
    ...structuredClone(PAYMENT_CARD_UPLOAD.policyQuery),
    group: "",
    sortOrder: 7,
  };
  const { transport, calls } = stubTransport({
    existingDlp: [{
      name: "policies/exact-with-output-fields",
      displayName: PAYMENT_CARD_UPLOAD_NAME,
      type: "settings/rule.dlp",
      value: structuredClone(PAYMENT_CARD_UPLOAD.value),
      policyQuery: queryWithOutputFields,
    }],
  });
  const result = await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  ) as ProvisionResult;
  const sameNameCreates = calls.filter((call) => {
    const setting = (call.body?.setting ?? {}) as { value?: { displayName?: string } };
    return call.method === "POST" && setting.value?.displayName === PAYMENT_CARD_UPLOAD_NAME;
  });
  check(
    "Cloud Identity output-only empty group and numeric sortOrder do not change policy semantics",
    result.success && sameNameCreates.length === 0 &&
      result.skipped_items.some((item) =>
        item.includes(PAYMENT_CARD_UPLOAD_NAME) && item.includes("reused")
      ),
    JSON.stringify(result),
  );
}

{
  const mismatchedValue = structuredClone(PAYMENT_CARD_UPLOAD.value);
  mismatchedValue.state = "INACTIVE";
  const { transport, calls } = stubTransport({
    existingDlp: [
      {
        name: "policies/mismatched-payment-card-upload",
        displayName: PAYMENT_CARD_UPLOAD_NAME,
        type: "settings/rule.dlp",
        value: mismatchedValue,
        policyQuery: PAYMENT_CARD_UPLOAD.policyQuery,
      },
    ],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;
  const sameNameCreates = calls.filter((call) => {
    const setting = (call.body?.setting ?? {}) as { value?: { displayName?: string } };
    return call.method === "POST" && setting.value?.displayName === PAYMENT_CARD_UPLOAD_NAME;
  });
  check(
    "a same-name DLP policy with different semantics fails closed",
    !result.success &&
      sameNameCreates.length === 0 &&
      result.skipped_items.some(
        (item) => item.includes(PAYMENT_CARD_UPLOAD_NAME) && item.includes("reserved-name-conflict"),
      ),
    `${result.skipped_items.join(" | ")} | creates=${sameNameCreates.length}`,
  );
}

{
  const duplicate = (suffix: string): StubDlpPolicy => ({
    name: `policies/duplicate-${suffix}`,
    displayName: PAYMENT_CARD_UPLOAD_NAME,
    type: "settings/rule.dlp",
    value: structuredClone(PAYMENT_CARD_UPLOAD.value),
    policyQuery: structuredClone(PAYMENT_CARD_UPLOAD.policyQuery),
  });
  const { transport, calls } = stubTransport({
    existingDlp: [duplicate("a"), duplicate("b")],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;
  const sameNameCreates = calls.filter((call) => {
    const setting = (call.body?.setting ?? {}) as { value?: { displayName?: string } };
    return call.method === "POST" && setting.value?.displayName === PAYMENT_CARD_UPLOAD_NAME;
  });
  check(
    "duplicate same-name DLP policies fail closed even when both look exact",
    !result.success &&
      sameNameCreates.length === 0 &&
      result.skipped_items.some(
        (item) => item.includes(PAYMENT_CARD_UPLOAD_NAME) && item.includes("reserved-name-conflict"),
      ),
    `${result.skipped_items.join(" | ")} | creates=${sameNameCreates.length}`,
  );
}

{
  const pages: StubDlpPolicy[][] = Array.from({ length: 21 }, () => []);
  pages[20] = [{
    name: "policies/hidden-on-page-21",
    displayName: PAYMENT_CARD_UPLOAD_NAME,
    type: "settings/rule.dlp",
    value: { ...PAYMENT_CARD_UPLOAD.value, state: "INACTIVE" },
    policyQuery: PAYMENT_CARD_UPLOAD.policyQuery,
  }];
  const { transport, calls } = stubTransport({ dlpPages: pages });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;
  const dlpMutations = calls.filter(
    (call) => call.method === "POST" && call.url.includes("cloudidentity.googleapis.com"),
  );
  check(
    "a DLP list with a twenty-first page fails closed before creating a hidden same-name rule",
    !result.success &&
      dlpMutations.length === 0 &&
      result.skipped_items.some((item) => item.includes("pagination-incomplete")),
    `${result.message} | ${result.skipped_items.join(" | ")}`,
  );
}

{
  const pages: StubDlpPolicy[][] = Array.from({ length: 21 }, () => []);
  pages[20] = [{
    name: "policies/hidden-detector-on-page-21",
    displayName: "CEP PoC - Internal Sites",
    type: "settings/detector.url_list",
  }];
  const { transport, calls } = stubTransport({ dlpPages: pages });
  const result = (await route(context(transport), "POST", "/api/v1/cep/rollback", {
    project_id: "secgw-project",
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    target_ou_path: "/Pilot",
    rollback_modules: ["dlpDetectors"],
  })) as ProvisionResult;
  check(
    "detector inventory also fails closed when pagination is incomplete",
    !result.success &&
      !calls.some((call) => call.method === "DELETE" && call.url.includes("cloudidentity")) &&
      result.skipped_items.some((item) => item.includes("pagination-incomplete")),
    `${result.message} | ${result.skipped_items.join(" | ")}`,
  );
}

{
  const { transport, calls } = stubTransport({
    existingDlp: [
      {
        name: "policies/existing1",
        displayName: "CEP PoC - Internal Sites",
        type: "settings/detector.url_list",
        policyQuery: structuredClone(PAYMENT_CARD_UPLOAD.policyQuery),
      },
    ],
  });
  const result = (await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...DLP_CONFIG,
    dlp_detectors: true,
  })) as ProvisionResult;
  const detectorCreations = calls.filter(
    (call) =>
      call.method === "POST" &&
      call.url.includes("cloudidentity") &&
      ((call.body?.setting ?? {}) as { type?: string }).type?.includes("detector"),
  );
  check(
    "the legacy detector toggle is rejected without sending an unsupported detector mutation",
    detectorCreations.length === 0 &&
      result.skipped_items.some((item) => item.includes("settings/detector.url_list")),
    result.skipped_items.join(" | "),
  );
}

{
  // A display name is not ownership. This includes an exact name the deployer
  // can reuse and a different policy that merely shares its prefix.
  const { transport, calls } = stubTransport({
    existingDlp: [
      {
        name: "policies/rule1",
        displayName: "CEP PoC - Payment card numbers - upload",
        type: "settings/rule.dlp",
        policyQuery: structuredClone(PAYMENT_CARD_UPLOAD.policyQuery),
      },
      {
        name: "policies/detector1",
        displayName: "CEP PoC - Internal Sites",
        type: "settings/detector.url_list",
        policyQuery: structuredClone(PAYMENT_CARD_UPLOAD.policyQuery),
      },
      {
        name: "policies/other",
        displayName: "CEP PoC - Another administrator's custom rule",
        type: "settings/rule.dlp",
        policyQuery: structuredClone(PAYMENT_CARD_UPLOAD.policyQuery),
      },
    ],
  });
  const result = (await route(context(transport), "POST", "/api/v1/cep/rollback", {
    project_id: "secgw-project",
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    target_ou_path: "/Pilot",
  })) as ProvisionResult;

  const deletes = calls.filter((call) => call.method === "DELETE" && call.url.includes("cloudidentity"));
  const policyCalls = calls.filter((call) => call.url.includes("cloudidentity.googleapis.com"));
  check(
    "rollback fails closed instead of deleting DLP resources without durable ownership",
    !result.success &&
      deletes.length === 0 &&
      result.message.includes("durable ownership") &&
      result.skipped_items.some((item) => item.includes("policies/rule1")) &&
      result.skipped_items.some((item) => item.includes("policies/detector1")),
    `${result.message} | ${result.skipped_items.join(" | ")}`,
  );
  check(
    "another administrator's same-prefix DLP policy is retained",
    result.skipped_items.some((item) => item.includes("policies/other")),
    result.skipped_items.join(" | "),
  );
  check(
    "rollback ownership checks share the one-QPS limiter",
    policyCalls.slice(1).every(
      (call, index) => call.at - (policyCalls[index]?.at ?? call.at) >= 1_000,
    ),
    policyCalls.map((call) => `${call.method}@${call.at}`).join(", "),
  );
}

// -- 9. Region and per-rule action --------------------------------------------

function ruleBodies(calls: Recorded[]): Array<Record<string, unknown>> {
  return calls
    .filter(
      (call) =>
        call.method === "POST" &&
        call.url.includes("cloudidentity") &&
        ((call.body?.setting ?? {}) as { type?: string }).type === "settings/rule.dlp",
    )
    .map((call) => ((call.body?.setting ?? {}) as { value?: Record<string, unknown> }).value ?? {});
}

{
  // Regression: every tenant got US_SOCIAL_SECURITY_NUMBER, which detects
  // nothing outside the US and looks identical to a working rule.
  const { transport, calls } = stubTransport();
  await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...DLP_CONFIG,
    dlp_region: "JP",
  });
  const conditions = JSON.stringify(ruleBodies(calls).map((rule) => rule.condition));
  check(
    "the national ID rule scans for the selected country's identifier",
    conditions.includes("JAPAN_INDIVIDUAL_NUMBER") &&
      !conditions.includes("US_SOCIAL_SECURITY_NUMBER"),
    conditions,
  );
  check(
    "payment cards stay on the country-independent detector",
    conditions.includes("CREDIT_CARD_NUMBER"),
    conditions,
  );
}

{
  const { transport, calls } = stubTransport();
  await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...DLP_CONFIG,
    dlp_region: "US",
  });
  check(
    "switching country switches the detector",
    JSON.stringify(ruleBodies(calls)).includes("US_SOCIAL_SECURITY_NUMBER"),
  );
}

{
  // Each rule carries the action the operator picked, and `off` is not created.
  const { transport, calls } = stubTransport();
  const result = (await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...DLP_CONFIG,
    dlp_region: "JP",
    dlp_rule_actions: {
      payment_card: "blockContent",
      national_id: "warnUser",
      access_level: "off",
    },
  })) as ProvisionResult;

  const rules = ruleBodies(calls);
  const actionOf = (fragment: string) => {
    const rule = rules.find((entry) => String(entry.displayName ?? "").includes(fragment));
    return Object.keys(
      ((rule?.action ?? {}) as { chromeAction?: Record<string, unknown> }).chromeAction ?? {},
    )[0];
  };

  check("a rule set to block is created blocking", actionOf("Payment card") === "blockContent", actionOf("Payment card"));
  check("a rule set to warn is created warning", actionOf("National ID") === "warnUser", actionOf("National ID"));
  check(
    "a rule set to off is not created at all",
    !rules.some((entry) => String(entry.displayName ?? "").includes("unmanaged Chrome")),
    JSON.stringify(rules.map((entry) => entry.displayName)),
  );
  check(
    "and no access-level rule is sent",
    !rules.some((entry) => String(entry.displayName ?? "").includes("Unmanaged Chrome")),
    JSON.stringify(rules.map((entry) => entry.displayName)),
  );
}

{
  // Matrix cells are independent. A mixed row must become one policy per
  // operation because the Cloud Identity rule has one action for all triggers.
  const { transport, calls } = stubTransport();
  await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...DLP_CONFIG,
    access_level: "accessPolicies/999/accessLevels/corp-managed",
    dlp_matrix: {
      payment_card: {
        upload: "blockContent",
        paste: "warnUser",
        print: "blockContent",
        byodOnly: false,
      },
      universal_download: { download: "off" },
      watermark: { watermark: false },
    },
  });
  const rules = ruleBodies(calls);
  const paymentRules = rules.filter((entry) =>
    String(entry.displayName ?? "").includes("Payment card numbers"),
  );
  const byOperation = new Map(
    paymentRules.map((rule) => {
      const operation = String(rule.displayName ?? "").split(" - ").pop() ?? "";
      const chromeAction =
        ((rule.action ?? {}) as { chromeAction?: Record<string, unknown> }).chromeAction ?? {};
      return [operation, { action: Object.keys(chromeAction)[0], rule }];
    }),
  );
  check("a mixed DLP row creates one rule per selected cell", paymentRules.length === 3);
  check("the upload cell keeps its block action", byOperation.get("upload")?.action === "blockContent");
  check("the paste cell keeps its warning action", byOperation.get("paste")?.action === "warnUser");
  check("the print cell keeps its block action", byOperation.get("print")?.action === "blockContent");
  check(
    "the print cell uses the published Chrome print trigger",
    JSON.stringify(byOperation.get("print")?.rule.triggers).includes(
      "google.workspace.chrome.page.v1.print",
    ),
    JSON.stringify(byOperation.get("print")?.rule.triggers),
  );
  check(
    "supported mixed cells are not decorated with undocumented access-level CEL",
    paymentRules.every(
      (rule) => !JSON.stringify(rule.condition ?? {}).includes("access_levels"),
    ),
    JSON.stringify(paymentRules.map((rule) => rule.condition)),
  );
  check(
    "an off matrix cell creates no rule",
    !rules.some((rule) =>
      String(rule.displayName ?? "").includes("Universal file download protection"),
    ),
  );
}

{
  // Warning is the least disruptive action the Cloud Identity API supports for Chrome.
  const { transport, calls } = stubTransport();
  await route(context(transport), "POST", "/api/v1/cep/provision", DLP_CONFIG);
  const actions = ruleBodies(calls).map(
    (rule) =>
      Object.keys(
        ((rule.action ?? {}) as { chromeAction?: Record<string, unknown> }).chromeAction ?? {},
      )[0],
  );
  check(
    "rules default to warning rather than an unsupported Chrome audit action",
    actions.length > 0 &&
      actions.every((action) => action === "warnUser"),
    actions.join(", "),
  );
}

{
  // Regression: reading only camelCase missed every existing rule, so a second
  // run duplicated the whole set.
  const { transport, calls } = stubTransport({
    existingDlp: [
      {
        name: "policies/existing-snake",
        displayName: PAYMENT_CARD_UPLOAD_NAME,
        type: "settings/rule.dlp",
        snakeCase: true,
        ...PAYMENT_CARD_UPLOAD,
      },
    ],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/provision",
    DLP_CONFIG,
  )) as ProvisionResult;
  check(
    "a rule stored with snake_case keys is recognised, not duplicated",
    result.success &&
      result.skipped_items.some(
        (item) => item.includes(PAYMENT_CARD_UPLOAD_NAME) && item.includes("reused"),
      ) &&
      !ruleBodies(calls).some(
        (rule) => String(rule.displayName ?? "") === PAYMENT_CARD_UPLOAD_NAME,
      ),
    JSON.stringify(ruleBodies(calls).map((rule) => rule.displayName)),
  );
}

// -- License batch assignment -------------------------------------------------

for (const [path, payload] of [
  [
    "/api/v1/cep/provision",
    {
      ...FULL_CONFIG,
      target_ou_id: "root",
      target_ou_path: "/",
      target_ou_confirmation: "/",
    },
  ],
  [
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "root",
      target_ou_path: "/",
      target_ou_confirmation: "/",
    },
  ],
] as const) {
  const { transport, calls } = stubTransport();
  let rejected = false;
  try {
    await route(context(transport), "POST", path, payload);
  } catch (error) {
    rejected = (error as { status?: unknown; code?: unknown }).status === 400 &&
      (error as { code?: unknown }).code === "cep-root-ou-forbidden";
  }
  check(`${path} rejects a freshly resolved Workspace root OU`, rejected);
  check(
    `${path} root rejection occurs before every tenant mutation`,
    !calls.some((call) =>
      call.method !== "GET" &&
      (call.url.includes("orgunits") ||
        call.url.includes("chromepolicy") ||
        call.url.includes("cloudidentity") ||
        call.url.includes("licensing"))
    ),
    JSON.stringify(calls),
  );
}

for (const [path, payload] of [
  [
    "/api/v1/cep/provision",
    Object.fromEntries(
      Object.entries(FULL_CONFIG).filter(([key]) => key !== "target_ou_confirmation"),
    ),
  ],
  [
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
    },
  ],
] as const) {
  const { transport, calls } = stubTransport();
  let rejected = false;
  try {
    await route(context(transport), "POST", path, payload);
  } catch (error) {
    rejected = (error as { status?: unknown; code?: unknown }).status === 400 &&
      (error as { code?: unknown }).code === "cep-target-ou-confirmation-mismatch";
  }
  check(`${path} rejects a hand-made body without exact OU confirmation`, rejected);
  check(
    `${path} missing confirmation issues no tenant mutation`,
    !calls.some((call) => call.method !== "GET"),
    JSON.stringify(calls),
  );
}

{
  const { transport, calls } = stubTransport();
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  )) as { success: boolean; total_users: number; assigned_count: number; already_assigned_count: number };

  check("assign-licenses succeeds", result.success === true);
  check("assign-licenses found 2 users", result.total_users === 2);
  check("assign-licenses assigned 2 users", result.assigned_count === 2);
  const licenseCalls = calls.filter((call) => call.url.includes("licensing.googleapis.com"));
  check(
    "looks up and then assigns exactly two licenses",
    licenseCalls.filter((call) => call.method === "GET").length === 2 &&
      licenseCalls.filter((call) => call.method === "POST").length === 2,
    JSON.stringify(licenseCalls),
  );
}

{
  const stub = stubTransport({
    directoryUsers: [{ primaryEmail: "alice@example.com", orgUnitPath: "/Pilot" }],
  });
  let signalPostStarted!: () => void;
  let releasePost!: () => void;
  const postStarted = new Promise<void>((resolve) => {
    signalPostStarted = resolve;
  });
  const postRelease = new Promise<void>((resolve) => {
    releasePost = resolve;
  });
  const blockingTransport: Transport = {
    ...stub.transport,
    async requestJson(method, url, options) {
      if (method === "POST" && url.includes("licensing.googleapis.com")) {
        signalPostStarted();
        await postRelease;
      }
      return stub.transport.requestJson(method, url, options);
    },
  };
  const request = {
    project_id: "secgw-project",
    customer_id: "my_customer",
    target_ou_id: "03pilot",
    target_ou_path: "/Pilot",
    target_ou_confirmation: "/Pilot",
  };
  const first = route(
    context(blockingTransport),
    "POST",
    "/api/v1/cep/assign-licenses",
    request,
  );
  await postStarted;
  let secondBlocked = false;
  try {
    await route(
      context(blockingTransport),
      "POST",
      "/api/v1/cep/assign-licenses",
      {
        ...request,
        customer_id: "C01abcdef",
        sku_id: "alternate-request-body",
      },
    );
  } catch (error) {
    secondBlocked = (error as { status?: unknown; code?: unknown }).status === 409 &&
      (error as { code?: unknown }).code === "cep-mutation-active";
  }
  releasePost();
  const firstResult = await first as { success: boolean };
  check(
    "my_customer/canonical aliases and optional request changes cannot split one customer+OU lease",
    secondBlocked,
  );
  check(
    "parallel license assignment emits exactly one provider POST",
    firstResult.success &&
      stub.calls.filter((call) =>
        call.method === "POST" && call.url.includes("licensing.googleapis.com")
      ).length === 1,
  );
}

{
  const stub = stubTransport({
    directoryUsers: [{ primaryEmail: "lease@example.com", orgUnitPath: "/Lease" }],
    existingOus: [{ path: "/Lease", id: "03lease" }],
  });
  const leaseContext = context(stub.transport);
  leaseContext.renewCepMutationLease = async () => {
    throw new Error("simulated durable lease renewal failure");
  };
  let failedClosed = false;
  try {
    await route(
      leaseContext,
      "POST",
      "/api/v1/cep/assign-licenses",
      {
        project_id: "secgw-project",
        customer_id: "C01leasefail",
        target_ou_id: "03lease",
        target_ou_path: "/Lease",
        target_ou_confirmation: "/Lease",
      },
    );
  } catch (error) {
    failedClosed = (error as { status?: unknown; code?: unknown }).status === 503 &&
      (error as { code?: unknown }).code === "cep-mutation-lease-lost";
  }
  check("a failed durable lease renewal fails the CEP route closed", failedClosed);
  check(
    "lease loss stops before the provider mutation and retains the interrupted lease",
    !stub.calls.some((call) =>
      call.method === "POST" && call.url.includes("licensing.googleapis.com")
    ) && activeCepLeases.size > 0,
  );
  activeCepLeases.clear();
}

{
  const { transport } = stubTransport({ licenseAlreadyAssigned: true });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  )) as { success: boolean; total_users: number; assigned_count: number; already_assigned_count: number };

  check("assign-licenses handles already-assigned users gracefully", result.success === true);
  check("already_assigned_count is 1", result.already_assigned_count === 1);
  check("assigned_count is 1", result.assigned_count === 1);
}

{
  const { transport, calls } = stubTransport({
    directoryPages: [
      [
        { primaryEmail: "Alice@example.com", orgUnitPath: "/Pilot" },
        { primaryEmail: "child@example.com", orgUnitPath: "/Pilot/Child" },
      ],
      [
        { primaryEmail: "alice@EXAMPLE.com", orgUnitPath: "/Pilot" },
        { primaryEmail: "carol@example.com", orgUnitPath: "/Pilot" },
      ],
    ],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  )) as { success: boolean; total_users: number; assigned_count: number };
  const directoryCalls = calls.filter((call) => call.url.includes("/users?"));
  const assignedBodies = calls
    .filter((call) => call.method === "POST" && call.url.includes("licensing.googleapis.com"))
    .map((call) => String(call.body?.userId ?? "").toLowerCase())
    .sort();
  check(
    "license discovery paginates with admin_view and selects only exact-OU unique users",
    result.success && result.total_users === 2 && result.assigned_count === 2 &&
      directoryCalls.length === 2 &&
      directoryCalls.every((call) =>
        new URL(call.url).searchParams.get("viewType") === "admin_view" &&
        new URL(call.url).searchParams.get("projection") === "full"
      ) &&
      assignedBodies.join(",") === "alice@example.com,carol@example.com",
    JSON.stringify({ result, directoryCalls, assignedBodies }),
  );
}

{
  const { transport, calls } = stubTransport({
    directoryUsers: [{ primaryEmail: "alice@example.com" }],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  )) as { success: boolean };
  check(
    "missing Directory orgUnitPath fails closed before every licensing mutation",
    !result.success && !calls.some((call) => call.url.includes("licensing.googleapis.com")),
  );
}

for (const mode of ["412-commit", "503-commit", "response-loss-commit"] as const) {
  const { transport } = stubTransport({
    directoryUsers: [{ primaryEmail: "alice@example.com", orgUnitPath: "/Pilot" }],
    licensePostMode: mode,
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  )) as { success: boolean; assigned_count: number };
  check(
    `license ${mode} reconciles only an exact product/SKU/user row`,
    result.success && result.assigned_count === 1,
    JSON.stringify(result),
  );
}

{
  const { transport } = stubTransport({
    directoryUsers: [{ primaryEmail: "alice@example.com", orgUnitPath: "/Pilot" }],
    licensePostMode: "412-no-commit",
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  )) as { success: boolean; failed_count: number };
  check(
    "license 412 without an exact assignment remains failed",
    !result.success && result.failed_count === 1,
    JSON.stringify(result),
  );
}

{
  const { transport, calls } = stubTransport({
    failing: [{ match: "orgunits?type=all_including_parent", status: 403, message: "forbidden" }],
  });
  let rejected = false;
  try {
    await route(
      context(transport),
      "POST",
      "/api/v1/cep/assign-licenses",
      {
        project_id: "secgw-project",
        customer_id: "C01abcdef",
        target_ou_id: "03pilot",
        target_ou_path: "/Pilot",
        target_ou_confirmation: "/Pilot",
      },
    );
  } catch (error) {
    rejected = (error as { status?: unknown; code?: unknown }).status === 502 &&
      (error as { code?: unknown }).code === "cep-target-ou-unresolved";
  }
  check("license assignment fails closed when the OU cannot be resolved", rejected);
  check(
    "OU resolution failure issues no licensing mutations",
    !calls.some((call) => call.url.includes("licensing.googleapis.com")),
  );
}

{
  const { transport, calls } = stubTransport();
  let rejected = false;
  try {
    await route(
      context(transport),
      "POST",
      "/api/v1/cep/assign-licenses",
      {
        project_id: "secgw-project",
        customer_id: "C01abcdef",
        target_ou_id: "03pilot",
        target_ou_path: "/Different OU",
        target_ou_confirmation: "/Different OU",
      },
    );
  } catch (error) {
    rejected = (error as { status?: unknown; code?: unknown }).status === 409 &&
      (error as { code?: unknown }).code === "cep-target-ou-path-stale";
  }
  check(
    "license assignment rejects a caller-supplied OU path that differs from Directory",
    rejected,
  );
  check(
    "a mismatched OU path issues no user-list or licensing mutations",
    !calls.some(
      (call) => call.url.includes("/users?") || call.url.includes("licensing.googleapis.com"),
    ),
  );
}

{
  const { transport, calls } = stubTransport({
    failing: [{ match: "/users?", status: 403, message: "cannot list users" }],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  )) as { success: boolean };
  check("license assignment fails closed when users cannot be listed", result.success === false);
  check(
    "user-list failure issues no licensing mutations",
    !calls.some((call) => call.url.includes("licensing.googleapis.com")),
  );
}

{
  const { transport, calls } = stubTransport({ directoryUsers: [] });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  )) as { success: boolean; total_users: number };
  check("an empty OU is not reported as a successful license assignment", result.success === false);
  check("an empty OU reports zero users", result.total_users === 0);
  check(
    "an empty OU issues no licensing mutations",
    !calls.some((call) => call.url.includes("licensing.googleapis.com")),
  );
}

{
  const { transport } = stubTransport({
    failing: [{ match: "licensing.googleapis.com", status: 400, message: "invalid SKU" }],
  });
  const result = (await route(
    context(transport),
    "POST",
    "/api/v1/cep/assign-licenses",
    {
      project_id: "secgw-project",
      customer_id: "C01abcdef",
      target_ou_id: "03pilot",
      target_ou_path: "/Pilot",
      target_ou_confirmation: "/Pilot",
    },
  )) as {
    success: boolean;
    already_assigned_count: number;
    failed_count: number;
  };
  check("a generic licensing 400 fails closed", result.success === false);
  check("a generic licensing 400 is not treated as a duplicate", result.already_assigned_count === 0);
  check("a generic licensing 400 counts every failed user", result.failed_count === 2);
}

// -- Report -------------------------------------------------------------------

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} CEP check(s) failed`);
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} CEP deployer checks passed.`);
