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

const { route } = await import("../src/background/router.ts");
import type { RouteContext } from "../src/background/router.ts";
import type { Transport, TransportResponse } from "../src/providers/executor.ts";

interface Recorded {
  method: string;
  url: string;
  body?: Record<string, unknown>;
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
  "chrome.users.RestrictAccountsToPatterns": [
    { name: "restrictAccountsToPatterns", type: "TYPE_STRING", repeated: true },
  ],
  "chrome.users.AllowedDomainsForApps": [
    { name: "allowedDomainsForApps", type: "TYPE_STRING" },
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

interface StubOptions {
  /** Schema names the tenant does not serve, so the provider must skip them. */
  missingSchemas?: string[];
  /**
   * DLP policies already present. `snakeCase` stores the display name the way
   * the API returns a struct written by something other than this tool.
   */
  existingDlp?: Array<{
    name: string;
    displayName: string;
    type: string;
    snakeCase?: boolean;
  }>;
  /** Answer policy mutations with HTTP 200 carrying an error code in the body. */
  dlpRpcError?: number;
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
  customerDomain?: string | null;
}

function stubTransport(options: StubOptions = {}): {
  transport: Transport;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  const transport: Transport = {
    async requestJson(method, url, requestOptions = {}): Promise<TransportResponse> {
      const body = requestOptions.jsonBody;
      calls.push({ method, url, body });

      for (const failure of options.failing ?? []) {
        if (url.includes(failure.match)) {
          return { status: failure.status, payload: { error: { message: failure.message } } };
        }
      }

      // Access Context Manager reachable through an organization, which is
      // what auto-creating a level requires.
      if (url.includes("cloudresourcemanager") && /\/projects\/[^/:]+$/.test(url)) {
        return { status: 200, payload: { parent: "organizations/1234" } };
      }
      // Query params arrive in `options`, not the URL, so match the path.
      if (url.includes("accesscontextmanager") && /\/accessPolicies$/.test(url)) {
        return { status: 200, payload: { accessPolicies: [{ name: "accessPolicies/999" }] } };
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
        return {
          status: 200,
          payload: {
            policySchemas: Object.entries(SCHEMA_FIELDS)
              .filter(([name]) => !(options.missingSchemas ?? []).includes(name))
              .map(([name, fields]) => ({ schemaName: name, ...schemaPayload(fields) })),
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
        return {
          status: 200,
          payload: domain === null ? {} : { customerDomain: domain ?? "example.com" },
        };
      }

      if (url.includes("cloudidentity.googleapis.com")) {
        if (method === "GET") {
          // The real API filters server-side; honour it so the stub cannot
          // make an unfiltered client look correct.
          const kind = decodeURIComponent(url).match(/matches\("([^"]+)"\)/)?.[1] ?? "";
          const matching = (options.existingDlp ?? []).filter((policy) =>
            policy.type.includes(kind),
          );
          return {
            status: 200,
            payload: {
              policies: matching.map((policy) => ({
                name: policy.name,
                setting: {
                  type: policy.type,
                  value:
                    policy.snakeCase === true
                      ? { display_name: policy.displayName }
                      : { displayName: policy.displayName },
                },
              })),
            },
          };
        }
        if (options.dlpRpcError !== undefined) {
          // The policy API's second failure mode: 200 with an error body.
          return { status: 200, payload: { done: true, error: { code: options.dlpRpcError } } };
        }
        return {
          status: 200,
          payload: { done: true, response: { name: `policies/created-${calls.length}` } },
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
        ];
        return { status: 200, payload: { organizationUnits: units } };
      }

      if (isOrgUnitCollection && method === "POST") {
        const name = String((body as { name?: string } | undefined)?.name ?? "");
        return {
          status: 200,
          payload: { orgUnitId: `id:created-${name.replace(/\s+/g, "-")}` },
        };
      }

      return { status: 200, payload: {} };
    },
  };
  return { transport, calls };
}

function context(transport: Transport): RouteContext {
  return {
    transport,
    administratorTransport: transport,
    cloudIdentity: async () => "deployer@example.com",
    operatorEmail: async () => "admin@example.com",
    accessPolicyId: async () => undefined,
    rememberDeployer: async () => undefined,
    startApply: async () => ({ run_id: "run" }),
    runState: async () => ({}),
  };
}

const FULL_CONFIG = {
  customer_id: "C01abcdef",
  project_id: "secgw-project",
  target_ou_id: "03pilot",
  target_ou_path: "/Pilot",
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
  ["/api/v1/cep/rollback", { customer_id: "C01abcdef", target_ou_id: "03pilot" }],
  [
    "/api/v1/cep/roles",
    { project_id: "secgw-project", customer_id: "C01abcdef", role_type: "both" },
  ],
  ["/api/v1/cep/script", FULL_CONFIG],
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

  // Regression: the value was `*.{customer_id}`, and customer_id is not a domain.
  const restrict = requests.find(
    (request) =>
      (request.policyValue as { policySchema?: string }).policySchema ===
      "chrome.users.RestrictAccountsToPatterns",
  );
  const patterns = (
    (restrict?.policyValue as { value?: Record<string, unknown> })?.value ?? {}
  ).restrictAccountsToPatterns;
  check(
    "account restrictions use the tenant's primary domain",
    JSON.stringify(patterns) === JSON.stringify(["*@example.com"]),
    JSON.stringify(patterns),
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
    JSON.stringify(((upload?.updateMask ?? {}) as { paths?: string[] }).paths?.sort()) ===
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
    "user policies and browser policies land in different OUs",
    new Set(targets).size === 2,
    [...new Set(targets)].join(", "),
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
    result.skipped_items.some((item) => item.includes("Security event reporting")),
    result.skipped_items.join(" | "),
  );
  check("the rest of the deployment still applies", result.created_items.length > 0);
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

// -- 5. Rollback covers everything provision writes ---------------------------

{
  const { transport, calls } = stubTransport();
  const result = (await route(context(transport), "POST", "/api/v1/cep/rollback", {
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    target_ou_path: "/Pilot",
  })) as ProvisionResult;

  const requests = batchRequests(calls, "batchInherit");
  const inherited = new Set(schemasIn(requests));
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

  check("rollback succeeds", result.success, result.message);
  for (const schema of writable) {
    check(`rollback returns ${schema} to the parent OU`, inherited.has(schema));
  }

  // Regression: the force-installed extension used to survive a rollback,
  // because its app-scoped target key was left out of the inherit list.
  const appScoped = requests.find(
    (request) => request.policySchema === "chrome.users.apps.InstallType",
  );
  const key = appScoped?.policyTargetKey as
    | { additionalTargetKeys?: Record<string, string> }
    | undefined;
  check(
    "the force-installed extension is un-installed by rollback",
    key?.additionalTargetKeys?.app_id === "chrome:callobklhcbilhphinckomhgkigmfocg",
    JSON.stringify(key),
  );
}

{
  const { transport, calls } = stubTransport();
  await route(context(transport), "POST", "/api/v1/cep/rollback", {
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    rollback_modules: ["core"],
  });
  const schemas = schemasIn(batchRequests(calls, "batchInherit"));
  check(
    "a scoped rollback touches only the modules it was given",
    schemas.length > 0 && schemas.every((schema) => schema.includes("chrome.users.")) &&
      !schemas.includes("chrome.users.apps.InstallType"),
    schemas.join(", "),
  );
}

// -- 6. Custom roles ----------------------------------------------------------

{
  const { transport, calls } = stubTransport();
  const result = (await route(context(transport), "POST", "/api/v1/cep/roles", {
    project_id: "secgw-project",
    customer_id: "C01abcdef",
    role_type: "both",
    assigned_user_email: "auditor@example.com",
  })) as { success: boolean; message: string; roles: string[] };

  check("both roles are created", result.success && result.roles.length === 2, result.message);

  // Regression: IAM rejected the whole role over one organization-scoped
  // permission, so nothing was created at all.
  const roleCreations = calls.filter(
    (call) => call.method === "POST" && call.url.endsWith("/roles"),
  );
  const sentPermissions = roleCreations.flatMap(
    (call) => ((call.body?.role ?? {}) as { includedPermissions?: string[] }).includedPermissions ?? [],
  );
  check(
    "permissions the project cannot grant are dropped rather than sent",
    !sentPermissions.some((permission) => permission.startsWith("accesscontextmanager.")),
    sentPermissions.join(", "),
  );
  check(
    "the roles still carry the permissions that are valid",
    sentPermissions.includes("chromepolicy.policies.modify") &&
      sentPermissions.includes("logging.logEntries.list"),
    sentPermissions.join(", "),
  );
  check(
    "the omission is reported, and says where those permissions do belong",
    result.message.includes("accesscontextmanager") &&
      result.message.includes("organization"),
    result.message,
  );
  const setIam = calls.find((call) => call.url.includes(":setIamPolicy"));
  check(
    "the assigned email is actually granted the roles",
    JSON.stringify(setIam?.body ?? {}).includes("user:auditor@example.com"),
    JSON.stringify(setIam?.body),
  );
}

{
  // Regression: a permission error used to be relabelled "(Existing / Verified)"
  // and the call still returned success.
  const { transport } = stubTransport({
    failing: [{ match: "iam.googleapis.com", status: 403, message: "permission denied" }],
  });
  const result = (await route(context(transport), "POST", "/api/v1/cep/roles", {
    project_id: "secgw-project",
    customer_id: "C01abcdef",
    role_type: "both",
  })) as { success: boolean; message: string };
  check(
    "a role that could not be created is reported as a failure",
    !result.success && result.message.includes("permission denied"),
    result.message,
  );
}

{
  // A project that grants none of them is a failure, not an empty role.
  const { transport } = stubTransport({ testablePermissions: [] });
  const result = (await route(context(transport), "POST", "/api/v1/cep/roles", {
    project_id: "secgw-project",
    customer_id: "C01abcdef",
    role_type: "both",
  })) as { success: boolean; message: string; roles: string[] };
  check(
    "a role with no grantable permissions is refused rather than created empty",
    !result.success && result.roles.length === 0,
    result.message,
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
  const result = (await route(context(transport), "POST", "/api/v1/cep/provision", {
    ...FULL_CONFIG,
    access_level: "AUTO_CREATE_CHROME_ANY",
  })) as ProvisionResult;
  check(
    "an auto-create selection provisions an access level",
    result.created_items.some((item) => item.includes("Context-Aware Access level")),
    result.created_items.join(", "),
  );
  check(
    "it is created through Access Context Manager",
    calls.some((call) => call.url.includes("accesscontextmanager")),
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

// -- 8. DLP detectors and rules -----------------------------------------------

const DLP_CONFIG = {
  ...FULL_CONFIG,
  core_policies: false,
  force_extensions: false,
  connectors: false,
  data_boundary_mode: "none" as const,
  dlp_detectors: true,
  dlp_rules: true,
};

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
    "a URL-list detector is created from the internal sites",
    settingTypes.includes("settings/detector.url_list"),
    settingTypes.join(", "),
  );
  check(
    "DLP rules are created",
    settingTypes.filter((type) => type === "settings/rule.dlp").length >= 2,
    settingTypes.join(", "),
  );

  const detector = created.find(
    (call) => ((call.body?.setting ?? {}) as { type?: string }).type === "settings/detector.url_list",
  );
  const detectorValue = (
    (detector?.body?.setting as { value?: Record<string, unknown> })?.value ?? {}
  );
  check(
    "the detector carries the internal URLs the operator entered",
    JSON.stringify(detectorValue.urlList ?? "").includes("intranet.example.com"),
    JSON.stringify(detectorValue.urlList),
  );

  // The policy query needs the CEL form and the org unit field together.
  const query = (detector?.body?.policyQuery ?? {}) as { query?: string; orgUnit?: string };
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
    "watermarking and screenshot blocking are applied as rule action params",
    watermark !== undefined &&
      JSON.stringify(watermark.body).includes("blockScreenshot"),
    JSON.stringify(watermark?.body),
  );

  // Ordering is load-bearing: the watermark rule references the detector.
  const detectorIndex = created.indexOf(detector as Recorded);
  check(
    "the detector is created before the rules that reference it",
    detectorIndex === 0,
    `detector at index ${detectorIndex}`,
  );
  const watermarkCondition = JSON.stringify(
    ((watermark?.body?.setting as { value?: { condition?: unknown } })?.value ?? {}).condition,
  );
  check(
    "the watermark rule references the created detector by resource name",
    watermarkCondition.includes("policies/created-"),
    watermarkCondition,
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
        name: "policies/existing1",
        displayName: "CEP PoC - Internal Sites",
        type: "settings/detector.url_list",
      },
    ],
  });
  await route(context(transport), "POST", "/api/v1/cep/provision", DLP_CONFIG);
  const detectorCreations = calls.filter(
    (call) =>
      call.method === "POST" &&
      call.url.includes("cloudidentity") &&
      ((call.body?.setting ?? {}) as { type?: string }).type?.includes("detector"),
  );
  check("an existing detector is reused rather than duplicated", detectorCreations.length === 0);
}

{
  // Rollback deletes rules before detectors; the reverse order is refused.
  const { transport, calls } = stubTransport({
    existingDlp: [
      {
        name: "policies/rule1",
        displayName: "CEP PoC - Block card numbers in uploads",
        type: "settings/rule.dlp",
      },
      {
        name: "policies/detector1",
        displayName: "CEP PoC - Internal Sites",
        type: "settings/detector.url_list",
      },
      {
        name: "policies/other",
        displayName: "Someone else's rule",
        type: "settings/rule.dlp",
      },
    ],
  });
  const result = (await route(context(transport), "POST", "/api/v1/cep/rollback", {
    customer_id: "C01abcdef",
    target_ou_id: "03pilot",
    target_ou_path: "/Pilot",
  })) as ProvisionResult;

  const deletes = calls.filter((call) => call.method === "DELETE" && call.url.includes("cloudidentity"));
  check("rollback succeeds with DLP policies present", result.success, result.message);
  check(
    "rules are deleted before the detectors they reference",
    deletes.length === 2 &&
      deletes[0].url.includes("policies/rule1") &&
      deletes[1].url.includes("policies/detector1"),
    deletes.map((call) => call.url).join(", "),
  );
  check(
    "policies this tool did not create are left alone",
    !deletes.some((call) => call.url.includes("policies/other")),
    deletes.map((call) => call.url).join(", "),
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
    "and the omission is reported rather than silent",
    result.skipped_items.some((item) => item.includes("not selected")),
    result.skipped_items.join(" | "),
  );
}

{
  // Audit-only is the default, so a PoC does not start by blocking people.
  const { transport, calls } = stubTransport();
  await route(context(transport), "POST", "/api/v1/cep/provision", DLP_CONFIG);
  const actions = ruleBodies(calls).map(
    (rule) =>
      Object.keys(
        ((rule.action ?? {}) as { chromeAction?: Record<string, unknown> }).chromeAction ?? {},
      )[0],
  );
  check(
    "rules default to audit only",
    actions.length > 0 && actions.every((action) => action === "auditOnly"),
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
        displayName: "CEP PoC - Payment card numbers in uploads",
        type: "settings/rule.dlp",
        snakeCase: true,
      },
    ],
  });
  await route(context(transport), "POST", "/api/v1/cep/provision", DLP_CONFIG);
  check(
    "a rule stored with snake_case keys is recognised, not duplicated",
    !ruleBodies(calls).some((rule) =>
      String(rule.displayName ?? "").includes("Payment card numbers"),
    ),
    JSON.stringify(ruleBodies(calls).map((rule) => rule.displayName)),
  );
}

// -- Report -------------------------------------------------------------------

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} CEP check(s) failed`);
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} CEP deployer checks passed.`);
