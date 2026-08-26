/** Managed-Chrome Access Level CEL and fail-closed creation. */

import {
  ConnectionError,
  ensureManagedChromeAccessLevel,
  GoogleSetupCatalog,
} from "../src/providers/catalog.ts";
import {
  GoogleApiError,
  type Transport,
} from "../src/providers/executor.ts";
import { InvalidGoogleJsonResponseError } from "../src/background/google-response.ts";
import {
  compensateApplicationIamPolicy,
  humanAuditActor,
  route,
  type RouteContext,
} from "../src/background/router.ts";
import {
  EXTENSION_DEPLOYER_READINESS_PERMISSIONS,
  EXTENSION_DEPLOYER_ROLE,
} from "../src/domain/extension-deployer-role.ts";

const failures: string[] = [];
let passed = 0;
function check(name: string, condition: boolean, detail = ""): void {
  if (condition) passed += 1;
  else failures.push(`${name}${detail ? `\n      ${detail}` : ""}`);
}

{
  const calls: string[] = [];
  const readinessPermissions = [...EXTENSION_DEPLOYER_READINESS_PERMISSIONS];
  const readyTransport: Transport = {
    async requestJson(method, url, options = {}) {
      calls.push(`${method} ${url}`);
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { projectId: "project-1", name: "projects/111" },
        };
      }
      if (url.endsWith("/projects/project-1:testIamPermissions")) {
        return { status: 200, payload: { permissions: readinessPermissions } };
      }
      if (url.endsWith("/projects/project-1/services/dns.googleapis.com")) {
        return { status: 200, payload: { state: "ENABLED" } };
      }
      if (url.endsWith("/managedZones") && options.params?.maxResults === 1) {
        return {
          status: 200,
          payload: { managedZones: [{ name: "existing-private-zone" }] },
        };
      }
      if (url.endsWith("/managedZones/existing-private-zone")) {
        return { status: 200, payload: { name: "existing-private-zone" } };
      }
      throw new Error(`unexpected ${method} ${url} ${JSON.stringify(options.jsonBody)}`);
    },
  };
  const ready = await new GoogleSetupCatalog(readyTransport, {
    principalHint: "secure-gateway-studio-deployer@project-1.iam.gserviceaccount.com",
    credentialKind: "impersonated_service_account",
  }).validateCloud("project-1");
  check(
    "impersonated Cloud validation proves Option B role propagation",
    ready.status === "connected" &&
      calls.some((call) => call.endsWith("/projects/project-1:testIamPermissions")) &&
      calls.some((call) =>
        call.endsWith("/managedZones/existing-private-zone")
      ),
    JSON.stringify({ ready, calls }),
  );

  const falsePositiveTransport: Transport = {
    async requestJson(method, url) {
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { projectId: "project-1", name: "projects/111" },
        };
      }
      if (url.endsWith("/projects/project-1:testIamPermissions")) {
        // Google documents that testIamPermissions can fail open. Reproduce
        // the live symptom: the UI check says yes, but the real DNS GET is 403.
        return { status: 200, payload: { permissions: readinessPermissions } };
      }
      if (url.endsWith("/projects/project-1/services/dns.googleapis.com")) {
        return { status: 200, payload: { state: "ENABLED" } };
      }
      if (url.endsWith("/managedZones")) {
        // Reproduce the live message from 0.2.8: a bodyless/non-JSON 403 was
        // parsed before GoogleApiError existed, so the HTTP status was lost.
        throw new InvalidGoogleJsonResponseError(403);
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let apiReadinessError: unknown;
  try {
    await new GoogleSetupCatalog(falsePositiveTransport, {
      principalHint: "secure-gateway-studio-deployer@project-1.iam.gserviceaccount.com",
      credentialKind: "impersonated_service_account",
    }).validateCloud("project-1");
  } catch (error) {
    apiReadinessError = error;
  }
  check(
    "Cloud validation does not trust a fail-open IAM test over the real DNS API",
    apiReadinessError instanceof ConnectionError &&
      apiReadinessError.code === "deployer-dns-permission-denied" &&
      apiReadinessError.message.includes("HTTP 403") &&
      apiReadinessError.message.includes("IAM propagation"),
    String(apiReadinessError),
  );

  const organizationRestrictedTransport: Transport = {
    async requestJson(method, url) {
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { projectId: "project-1", name: "projects/111" },
        };
      }
      if (url.endsWith("/projects/project-1:testIamPermissions")) {
        return { status: 200, payload: { permissions: readinessPermissions } };
      }
      if (url.endsWith("/projects/project-1/services/dns.googleapis.com")) {
        return { status: 200, payload: { state: "ENABLED" } };
      }
      if (url.endsWith("/managedZones")) {
        throw new GoogleApiError({
          status: 403,
          method,
          url,
          payload: {
            error: {
              code: 403,
              message: "Request is prohibited by organization's policy",
              status: "PERMISSION_DENIED",
              details: [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                reason: "VPC_SERVICE_CONTROLS",
                domain: "googleapis.com",
                metadata: { service: "dns.googleapis.com", uid: "do-not-expose" },
              }],
            },
          },
        });
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let organizationRestrictionError: unknown;
  try {
    await new GoogleSetupCatalog(organizationRestrictedTransport, {
      principalHint: "secure-gateway-studio-deployer@project-1.iam.gserviceaccount.com",
      credentialKind: "impersonated_service_account",
    }).validateCloud("project-1");
  } catch (error) {
    organizationRestrictionError = error;
  }
  check(
    "Cloud validation reports organization restrictions without leaking metadata",
    organizationRestrictionError instanceof ConnectionError &&
      organizationRestrictionError.code === "deployer-dns-organization-restricted" &&
      organizationRestrictionError.message.includes("VPC_SERVICE_CONTROLS") &&
      !organizationRestrictionError.message.includes("do-not-expose"),
    String(organizationRestrictionError),
  );

  const emptyDnsProjectTransport: Transport = {
    async requestJson(method, url, options = {}) {
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { projectId: "project-1", name: "projects/111" },
        };
      }
      if (url.endsWith("/projects/project-1:testIamPermissions")) {
        return { status: 200, payload: { permissions: readinessPermissions } };
      }
      if (url.endsWith("/projects/project-1/services/dns.googleapis.com")) {
        return { status: 200, payload: { state: "ENABLED" } };
      }
      if (url.endsWith("/managedZones") && options.params?.maxResults === 1) {
        return { status: 200, payload: { managedZones: [] } };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  const emptyDnsProject = await new GoogleSetupCatalog(emptyDnsProjectTransport, {
    principalHint: "secure-gateway-studio-deployer@project-1.iam.gserviceaccount.com",
    credentialKind: "impersonated_service_account",
  }).validateCloud("project-1");
  check(
    "Cloud validation accepts a successful managed-zone list for an empty project",
    emptyDnsProject.status === "connected",
    JSON.stringify(emptyDnsProject),
  );

  const disabledApiTransport: Transport = {
    async requestJson(method, url) {
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { projectId: "project-1", name: "projects/111" },
        };
      }
      if (url.endsWith("/projects/project-1:testIamPermissions")) {
        return { status: 200, payload: { permissions: readinessPermissions } };
      }
      if (url.endsWith("/projects/project-1/services/dns.googleapis.com")) {
        return { status: 200, payload: { state: "DISABLED" } };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let disabledApiError: unknown;
  try {
    await new GoogleSetupCatalog(disabledApiTransport, {
      principalHint: "secure-gateway-studio-deployer@project-1.iam.gserviceaccount.com",
      credentialKind: "impersonated_service_account",
    }).validateCloud("project-1");
  } catch (error) {
    disabledApiError = error;
  }
  check(
    "Cloud validation distinguishes a disabled DNS API from an IAM failure",
    disabledApiError instanceof ConnectionError &&
      disabledApiError.code === "deployer-required-api-disabled" &&
      disabledApiError.message.includes("dns.googleapis.com"),
    String(disabledApiError),
  );

  const missingTransport: Transport = {
    async requestJson(method, url) {
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { projectId: "project-1", name: "projects/111" },
        };
      }
      if (url.endsWith("/projects/project-1:testIamPermissions")) {
        return {
          status: 200,
          payload: { permissions: readinessPermissions.filter((permission) =>
            permission !== "dns.managedZones.get"
          ) },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let readinessError: unknown;
  try {
    await new GoogleSetupCatalog(missingTransport, {
      principalHint: "secure-gateway-studio-deployer@project-1.iam.gserviceaccount.com",
      credentialKind: "impersonated_service_account",
    }).validateCloud("project-1");
  } catch (error) {
    readinessError = error;
  }
  check(
    "Cloud validation fails explicitly while deployer role propagation is incomplete",
    readinessError instanceof ConnectionError &&
      readinessError.code === "deployer-permissions-not-ready" &&
      readinessError.message.includes("dns.managedZones.get"),
    String(readinessError),
  );
}

{
  const actor: string = await humanAuditActor({
    operatorEmail: async () => "Admin@Example.com",
  });
  check(
    "human approvals and confirmations retain the administrator identity",
    actor === "admin@example.com",
    actor,
  );
  let rejected = false;
  try {
    await humanAuditActor({ operatorEmail: async () => "" });
  } catch (error) {
    rejected = error instanceof Error && error.message.includes("signed-in administrator");
  }
  check("human actions fail closed when the operator identity is unavailable", rejected);
}

class CatalogTransport implements Transport {
  created = false;
  expression = "";
  failCreate = false;
  confirmedPayloadOverride: Record<string, unknown> | null = null;

  async requestJson(
    method: string,
    url: string,
    options?: { jsonBody?: Record<string, unknown> },
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    if (url.endsWith("/projects/project-1")) {
      return {
        status: 200,
        payload: { name: "projects/111", parent: "organizations/123" },
      };
    }
    if (url.endsWith("/accessPolicies")) {
      return {
        status: 200,
        payload: {
          accessPolicies: [{
            name: "accessPolicies/456",
            parent: "organizations/123",
          }],
        },
      };
    }
    if (url.endsWith("/accessPolicies/456")) {
      return {
        status: 200,
        payload: { name: "accessPolicies/456", parent: "organizations/123" },
      };
    }
    if (url.endsWith("/accessLevels/secgw_chrome_managed") && method === "GET") {
      if (!this.created) {
        return { status: 404, payload: { error: { status: "NOT_FOUND" } } };
      }
      return {
        status: 200,
        payload: this.confirmedPayloadOverride ?? {
          name: "accessPolicies/456/accessLevels/secgw_chrome_managed",
          title: "Managed Chrome Profile or Browser (SGS)",
          description: "Created automatically by Secure Gateway Studio",
          custom: {
            expr: {
              expression:
                "device.chrome.management_state in [ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED, ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]",
            },
          },
        },
      };
    }
    if (url.endsWith("/accessPolicies/456/accessLevels") && method === "POST") {
      if (this.failCreate) throw new Error("permission-denied");
      const custom = options?.jsonBody?.custom as Record<string, unknown>;
      const expr = custom.expr as Record<string, unknown>;
      this.expression = String(expr.expression ?? "");
      this.created = true;
      return {
        status: 200,
        payload: {
          name:
            "accessPolicies/456/accessLevels/secgw_chrome_managed/create/create-level-1",
          done: true,
        },
      };
    }
    throw new Error(`unexpected ${method} ${url}`);
  }
}

// A reserved name is ownership only when its complete management predicate and
// operator-facing shape match. Reusing a permissive lookalike would weaken the
// IAM condition that relies on this Access Level.
{
  const calls: string[] = [];
  const reserved =
    "https://accesscontextmanager.googleapis.com/v1/accessPolicies/456/accessLevels/secgw_profile_managed";
  const expectedExpression =
    "device.chrome.management_state == ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED";
  const exactTransport = (expression: string): Transport => ({
    async requestJson(method, url) {
      calls.push(`${method} ${url}`);
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { name: "projects/111", parent: "organizations/123" },
        };
      }
      if (url.endsWith("/accessPolicies/456")) {
        return {
          status: 200,
          payload: { name: "accessPolicies/456", parent: "organizations/123" },
        };
      }
      if (url === reserved && method === "GET") {
        return {
          status: 200,
          payload: {
            name: "accessPolicies/456/accessLevels/secgw_profile_managed",
            title: "Managed Chrome Profile (SGS)",
            description: "Created automatically by Secure Gateway Studio",
            custom: { expr: { expression } },
          },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  });
  const reused = await ensureManagedChromeAccessLevel(
    exactTransport(expectedExpression),
    "project-1",
    "profile",
    "456",
  );
  check(
    "an exact reserved Access Level definition is safely reused",
    reused.endsWith("/secgw_profile_managed") &&
      calls.every((call) => !call.startsWith("POST ")),
    calls.join(","),
  );

  calls.length = 0;
  let conflict: unknown;
  try {
    await ensureManagedChromeAccessLevel(
      exactTransport("true"),
      "project-1",
      "profile",
      "456",
    );
  } catch (error) {
    conflict = error;
  }
  check(
    "a permissive Access Level occupying the reserved name fails closed",
    conflict instanceof ConnectionError &&
      conflict.code === "access-level-reserved-name-conflict" &&
      calls.every((call) => !call.startsWith("POST ")),
    `${String(conflict)} | ${calls.join(",")}`,
  );
}

// A configured numeric policy id is not proof that it belongs to this project.
// Project organization discovery and an exact policy parent read are mandatory.
{
  const noOrganizationCalls: string[] = [];
  const noOrganization: Transport = {
    async requestJson(method, url) {
      noOrganizationCalls.push(`${method} ${url}`);
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { name: "projects/111", projectId: "project-1" },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let noOrganizationError: unknown;
  try {
    await ensureManagedChromeAccessLevel(
      noOrganization,
      "project-1",
      "profile",
      "456",
    );
  } catch (error) {
    noOrganizationError = error;
  }
  check(
    "configured Access Policy id fails closed when project organization is unresolved",
    noOrganizationError instanceof ConnectionError &&
      noOrganizationError.code === "project-not-in-organization" &&
      noOrganizationCalls.length === 1,
    `${String(noOrganizationError)} | ${noOrganizationCalls.join(",")}`,
  );

  const wrongParent: Transport = {
    async requestJson(method, url) {
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { name: "projects/111", parent: "organizations/123" },
        };
      }
      if (url.endsWith("/accessPolicies/456")) {
        return {
          status: 200,
          payload: { name: "accessPolicies/456", parent: "organizations/999" },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let wrongParentError: unknown;
  try {
    await ensureManagedChromeAccessLevel(
      wrongParent,
      "project-1",
      "profile",
      "456",
    );
  } catch (error) {
    wrongParentError = error;
  }
  check(
    "configured Access Policy id requires an exact project organization parent",
    wrongParentError instanceof ConnectionError &&
      wrongParentError.code === "access-policy-organization-mismatch",
    String(wrongParentError),
  );

  const wrongScope: Transport = {
    async requestJson(method, url) {
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { name: "projects/111", parent: "organizations/123" },
        };
      }
      if (url.endsWith("/accessPolicies/456")) {
        return {
          status: 200,
          payload: {
            name: "accessPolicies/456",
            parent: "organizations/123",
            scopes: ["projects/999"],
          },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let wrongScopeError: unknown;
  try {
    await ensureManagedChromeAccessLevel(
      wrongScope,
      "project-1",
      "profile",
      "456",
    );
  } catch (error) {
    wrongScopeError = error;
  }
  check(
    "configured scoped Access Policy must apply to the target project hierarchy",
    wrongScopeError instanceof ConnectionError &&
      wrongScopeError.code === "access-policy-scope-mismatch",
    String(wrongScopeError),
  );
}

// Auto-discovery considers the project number and every ancestor folder. It
// must not select the first organization policy when that policy is scoped to
// some other resource, and ambiguous applicable policies require an explicit
// operator choice.
{
  const scopedTransport: Transport = {
    async requestJson(method, url) {
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { name: "projects/111", parent: "folders/222" },
        };
      }
      if (url.endsWith("/folders/222")) {
        return { status: 200, payload: { parent: "organizations/123" } };
      }
      if (url.endsWith("/accessPolicies")) {
        return {
          status: 200,
          payload: {
            accessPolicies: [
              {
                name: "accessPolicies/400",
                parent: "organizations/123",
                scopes: ["projects/999"],
              },
              {
                name: "accessPolicies/456",
                parent: "organizations/123",
                scopes: ["folders/222"],
              },
            ],
          },
        };
      }
      if (url.endsWith("/accessPolicies/456")) {
        return {
          status: 200,
          payload: {
            name: "accessPolicies/456",
            parent: "organizations/123",
            scopes: ["folders/222"],
          },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  const discovered = await new GoogleSetupCatalog(scopedTransport, {
    principalHint: "admin@example.com",
    credentialKind: "administrator",
  }).discoverAccessPolicyId("project-1");
  check(
    "Access Policy discovery selects an applicable ancestor-folder scope",
    discovered === "456",
    String(discovered),
  );

  const ambiguous: Transport = {
    async requestJson(method, url) {
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { name: "projects/111", parent: "organizations/123" },
        };
      }
      if (url.endsWith("/accessPolicies")) {
        return {
          status: 200,
          payload: {
            accessPolicies: [
              {
                name: "accessPolicies/400",
                parent: "organizations/123",
              },
              {
                name: "accessPolicies/456",
                parent: "organizations/123",
                scopes: ["projects/111"],
              },
            ],
          },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let ambiguousError: unknown;
  try {
    await new GoogleSetupCatalog(ambiguous, {
      principalHint: "admin@example.com",
      credentialKind: "administrator",
    }).discoverAccessPolicyId("project-1");
  } catch (error) {
    ambiguousError = error;
  }
  check(
    "multiple applicable Access Policies require an explicit policy id",
    ambiguousError instanceof ConnectionError &&
      ambiguousError.code === "access-policy-selection-required",
    String(ambiguousError),
  );
}

// Resource Manager allows ten nested folders. The organization reached from
// the tenth folder must still be accepted; an eleventh folder or a cycle must
// stop before policy data is trusted.
{
  const hierarchyTransport = (
    depth: number,
    cycle = false,
  ): { transport: Transport; calls: string[] } => {
    const calls: string[] = [];
    return {
      calls,
      transport: {
        async requestJson(method, url) {
          calls.push(`${method} ${url}`);
          if (url.endsWith("/projects/project-1")) {
            return {
              status: 200,
              payload: { name: "projects/111", parent: `folders/${depth}` },
            };
          }
          const folder = /\/folders\/(\d+)$/.exec(url);
          if (folder !== null) {
            const id = Number(folder[1]);
            return {
              status: 200,
              payload: {
                parent: cycle && id === depth - 1
                  ? `folders/${depth}`
                  : id === 1
                    ? "organizations/123"
                    : `folders/${id - 1}`,
              },
            };
          }
          if (url.endsWith("/accessPolicies/456")) {
            return {
              status: 200,
              payload: {
                name: "accessPolicies/456",
                parent: "organizations/123",
                scopes: ["folders/1"],
              },
            };
          }
          if (url.endsWith("/accessPolicies/456/accessLevels")) {
            return { status: 200, payload: { accessLevels: [] } };
          }
          throw new Error(`unexpected ${method} ${url}`);
        },
      },
    };
  };

  const ten = hierarchyTransport(10);
  await new GoogleSetupCatalog(ten.transport, {
    principalHint: "admin@example.com",
    credentialKind: "administrator",
    accessPolicyId: "456",
  }).listAccessLevels("project-1");
  check(
    "a legal ten-folder project hierarchy reaches its organization",
    ten.calls.filter((call) => call.includes("/folders/")).length === 10 &&
      ten.calls.some((call) => call.includes("/accessPolicies/456")),
    ten.calls.join(","),
  );

  for (const [name, candidate] of [
    ["an eleven-folder project hierarchy fails closed", hierarchyTransport(11)],
    ["a cyclic project hierarchy fails closed", hierarchyTransport(3, true)],
  ] as const) {
    let hierarchyError: unknown;
    try {
      await new GoogleSetupCatalog(candidate.transport, {
        principalHint: "admin@example.com",
        credentialKind: "administrator",
        accessPolicyId: "456",
      }).listAccessLevels("project-1");
    } catch (error) {
      hierarchyError = error;
    }
    check(
      name,
      hierarchyError instanceof ConnectionError &&
        hierarchyError.code === "project-hierarchy-invalid" &&
        candidate.calls.every((call) => !call.includes("/accessPolicies/")),
      `${String(hierarchyError)} | ${candidate.calls.join(",")}`,
    );
  }
}

{
  const transport = new CatalogTransport();
  const name = await ensureManagedChromeAccessLevel(transport, "project-1", "any");
  check("created level is confirmed before return", name === "accessPolicies/456/accessLevels/secgw_chrome_managed");
  check("CEL uses the supported management_state field", transport.expression.includes("device.chrome.management_state"));
  check("CEL includes browser-managed enum", transport.expression.includes("CHROME_MANAGEMENT_STATE_BROWSER_MANAGED"));
  check("CEL includes profile-managed enum", transport.expression.includes("CHROME_MANAGEMENT_STATE_PROFILE_MANAGED"));
  check("legacy undocumented CEL fields are absent", !/chrome_profile_managed|device\.is_managed|origin\.access_levels/.test(transport.expression));
}

for (const postCreateCase of [
  {
    name: "permissive expression",
    payload: {
      name: "accessPolicies/456/accessLevels/secgw_chrome_managed",
      title: "Managed Chrome Profile or Browser (SGS)",
      description: "Created automatically by Secure Gateway Studio",
      custom: { expr: { expression: "true" } },
    },
  },
  {
    name: "basic/custom union drift",
    payload: {
      name: "accessPolicies/456/accessLevels/secgw_chrome_managed",
      title: "Managed Chrome Profile or Browser (SGS)",
      description: "Created automatically by Secure Gateway Studio",
      basic: { conditions: [] },
      custom: {
        expr: {
          expression:
            "device.chrome.management_state in [ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED, ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]",
        },
      },
    },
  },
  {
    name: "operator-facing metadata drift",
    payload: {
      name: "accessPolicies/456/accessLevels/secgw_chrome_managed",
      title: "Managed Chrome (changed)",
      description: "Created automatically by Secure Gateway Studio",
      custom: {
        expr: {
          expression:
            "device.chrome.management_state in [ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED, ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]",
        },
      },
    },
  },
] as const) {
  const transport = new CatalogTransport();
  transport.confirmedPayloadOverride = structuredClone(postCreateCase.payload);
  let error: unknown;
  try {
    await ensureManagedChromeAccessLevel(transport, "project-1", "any");
  } catch (caught) {
    error = caught;
  }
  check(
    `post-create Access Level confirmation rejects ${postCreateCase.name}`,
    error instanceof ConnectionError && error.code === "access-level-verification-failed",
    String(error),
  );
}

// Access Context Manager's documented create operation is nested below the
// exact Access Level rather than under a generic operations/ collection.
{
  const calls: string[] = [];
  let created = false;
  const operationName =
    "accessPolicies/456/accessLevels/secgw_chrome_managed/create/create-level-42";
  const transport: Transport = {
    async requestJson(method, url, options) {
      calls.push(`${method} ${url}`);
      if (url.endsWith("/projects/project-1")) {
        return { status: 200, payload: { name: "projects/111", parent: "organizations/123" } };
      }
      if (url.endsWith("/accessPolicies")) {
        return {
          status: 200,
          payload: { accessPolicies: [{ name: "accessPolicies/456", parent: "organizations/123" }] },
        };
      }
      if (url.endsWith("/accessPolicies/456")) {
        return { status: 200, payload: { name: "accessPolicies/456", parent: "organizations/123" } };
      }
      if (url.endsWith("/accessLevels/secgw_chrome_managed") && method === "GET") {
        return created
          ? {
            status: 200,
            payload: {
              name: "accessPolicies/456/accessLevels/secgw_chrome_managed",
              title: "Managed Chrome Profile or Browser (SGS)",
              description: "Created automatically by Secure Gateway Studio",
              custom: {
                expr: {
                  expression:
                    "device.chrome.management_state in [ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED, ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]",
                },
              },
            },
          }
          : { status: 404, payload: { error: { status: "NOT_FOUND" } } };
      }
      if (url.endsWith("/accessPolicies/456/accessLevels") && method === "POST") {
        check("documented operation test sends the access level body", options?.jsonBody !== undefined);
        return { status: 200, payload: { name: operationName } };
      }
      if (url.endsWith(`/${operationName}`) && method === "GET") {
        created = true;
        return { status: 200, payload: { name: operationName, done: true } };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  const name = await ensureManagedChromeAccessLevel(transport, "project-1", "any");
  check(
    "documented Access Level create operation is polled before confirmation",
    name === "accessPolicies/456/accessLevels/secgw_chrome_managed" &&
      calls.includes(
        `GET https://accesscontextmanager.googleapis.com/v1/${operationName}`,
      ),
    calls.join(","),
  );
}

for (const invalidName of [
  "accessPolicies/999/accessLevels/secgw_chrome_managed/create/1",
  "accessPolicies/456/accessLevels/other/create/1",
  "accessPolicies/456/accessLevels/secgw_chrome_managed/create/../1",
  "https://accesscontextmanager.googleapis.com/v1/accessPolicies/456/accessLevels/secgw_chrome_managed/create/1",
]) {
  const transport = new CatalogTransport();
  const original = transport.requestJson.bind(transport);
  transport.requestJson = async (method, url, options) => {
    const response = await original(method, url, options);
    if (method === "POST" && url.endsWith("/accessPolicies/456/accessLevels")) {
      return { status: 200, payload: { name: invalidName } };
    }
    return response;
  };
  let error: unknown;
  try {
    await ensureManagedChromeAccessLevel(transport, "project-1", "any");
  } catch (caught) {
    error = caught;
  }
  check(
    `Access Level create rejects unbound operation ${invalidName}`,
    error instanceof ConnectionError &&
      error.code === "access-level-create-operation-invalid",
    String(error),
  );
}

// Directory canonicalizes the convenient `my_customer` alias. Cloud Identity
// Policy mutations accept only the returned C-prefixed customer resource id,
// so setup must persist that identity rather than echoing the alias.
{
  const calls: string[] = [];
  const transport: Transport = {
    async requestJson(method, url) {
      calls.push(`${method} ${url}`);
      if (url.endsWith("/customers/my_customer")) {
        return { status: 200, payload: { id: "C012345" } };
      }
      if (url.endsWith("/customers/C012345/policySchemas")) {
        return { status: 200, payload: { policySchemas: [] } };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  const validation = await new GoogleSetupCatalog(transport, {
    principalHint: "admin@example.com",
    credentialKind: "administrator",
  }).validateWorkspace("my_customer");
  check(
    "Workspace validation persists Directory's canonical customer ID",
    validation.resource_id === "C012345" &&
      calls.includes("GET https://admin.googleapis.com/admin/directory/v1/customers/my_customer") &&
      calls.includes(
        "GET https://chromepolicy.googleapis.com/v1/customers/C012345/policySchemas",
      ),
    JSON.stringify({ validation, calls }),
  );
}

{
  const transport: Transport = {
    async requestJson(_method, url) {
      if (url.includes("/customers/")) return { status: 200, payload: { id: "my_customer" } };
      return { status: 200, payload: {} };
    },
  };
  let rejected = false;
  try {
    await new GoogleSetupCatalog(transport, {
      principalHint: "admin@example.com",
      credentialKind: "administrator",
    }).validateWorkspace("my_customer");
  } catch {
    rejected = true;
  }
  check("Workspace validation fails closed without a canonical C-ID", rejected);
}

{
  const transport = new CatalogTransport();
  transport.failCreate = true;
  let rejected = false;
  try {
    await ensureManagedChromeAccessLevel(transport, "project-1", "any");
  } catch {
    rejected = true;
  }
  check("creation failure propagates instead of returning a nonexistent name", rejected);
}

// Permission failures are not an empty catalogue. Returning [] on 403 tells
// the operator that no Access Levels exist and can lead them to deploy without
// the intended condition, even though the real state was never observed.
{
  const forbidden: Transport = {
    async requestJson(method, url) {
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { name: "projects/111", parent: "organizations/123" },
        };
      }
      throw new GoogleApiError({
        status: 403,
        method,
        url,
        payload: { error: { status: "PERMISSION_DENIED" } },
      });
    },
  };
  let error: unknown;
  try {
    await new GoogleSetupCatalog(forbidden, {
      principalHint: "deployer@example.iam.gserviceaccount.com",
      credentialKind: "impersonated_service_account",
    }).listAccessLevels("project-1");
  } catch (caught) {
    error = caught;
  }
  check(
    "Access Level catalogue propagates 403 instead of returning an empty list",
    error instanceof GoogleApiError && error.status === 403,
    String(error),
  );
}

function routeContext(
  cloudTransport: Transport,
  administratorTransport: Transport,
  overrides: Partial<RouteContext> = {},
): RouteContext {
  let bootstrapPin: unknown;
  return {
    discoveryTransport: cloudTransport,
    transport: cloudTransport,
    administratorTransport,
    cloudIdentity: async () => "secure-gateway-deployer@project-1.iam.gserviceaccount.com",
    cloudCredentialKind: async () => "impersonated_service_account",
    operatorEmail: async () => "admin@example.com",
    accessPolicyId: async () => "456",
    rememberAccessPolicyId: async () => undefined,
    bootstrapOwnershipPin: async () => bootstrapPin,
    assertBootstrapOperator: async () => undefined,
    checkpointBootstrapOwnershipPin: async (pin) => {
      bootstrapPin = structuredClone(pin);
    },
    clearBootstrapOwnershipPin: async () => {
      bootstrapPin = undefined;
    },
    legacyDeployerIdentity: async () => undefined,
    rememberDeployer: async () => undefined,
    requireDeployer: async () => ({
      serviceAccountEmail: "secure-gateway-deployer@project-1.iam.gserviceaccount.com",
      serviceAccountUniqueId: "123456789012345678901",
      projectId: "project-1",
      operatorEmail: "admin@example.com",
      operatorSubject: "admin-subject-123",
    }),
    startApply: async () => ({ run_id: crypto.randomUUID() }),
    resumeApply: async () => ({}),
    runState: async () => ({}),
    ...overrides,
  } as RouteContext;
}

// The post-bootstrap Cloud catalogue must use the deployer transport. Only
// Directory/Chrome Policy/Cloud Identity catalogue calls stay on the signed-in
// Workspace administrator transport.
{
  const cloudCalls: string[] = [];
  const administratorCalls: string[] = [];
  const cloud: Transport = {
    async requestJson(_method, url) {
      cloudCalls.push(url);
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: {
            name: "projects/111",
            projectId: "project-1",
            parent: "organizations/123",
          },
        };
      }
      if (url.endsWith("/accessPolicies/456")) {
        return { status: 200, payload: { name: "accessPolicies/456", parent: "organizations/123" } };
      }
      if (url.endsWith("/accessPolicies/456/accessLevels")) {
        return { status: 200, payload: { accessLevels: [] } };
      }
      throw new Error(`unexpected cloud request ${url}`);
    },
  };
  const administrator: Transport = {
    async requestJson(_method, url) {
      administratorCalls.push(url);
      if (url.includes("/orgunits")) {
        return { status: 200, payload: { organizationUnits: [] } };
      }
      throw new Error(`unexpected administrator request ${url}`);
    },
  };
  const context = routeContext(cloud, administrator);
  await route(context, "POST", "/api/v1/setup-options/access-levels", {
    project_id: "project-1",
  });
  await route(context, "POST", "/api/v1/setup-options/organizational-units", {
    customer_id: "C012345",
  });
  check(
    "Cloud and Workspace setup catalogues use separate credential transports",
    cloudCalls.some((url) => url.includes("accesscontextmanager.googleapis.com")) &&
      cloudCalls.every((url) => !url.includes("admin.googleapis.com")) &&
      administratorCalls.some((url) => url.includes("admin.googleapis.com")) &&
      administratorCalls.every((url) => !url.includes("accesscontextmanager.googleapis.com")),
    JSON.stringify({ cloudCalls, administratorCalls }),
  );
}

// A policy discovered during the administrator's first Cloud validation is
// carried explicitly into bootstrap, where Policy Editor is granted before
// later Access Level reads and CEP AUTO_CREATE writes use the deployer account.
{
  const calls: string[] = [];
  let accessPolicyGetBody: Record<string, unknown> | undefined;
  let accessPolicySetBody: Record<string, unknown> | undefined;
  let rememberedPolicy: string | null | undefined;
  const accountEmail = "secure-gateway-deployer@project-1.iam.gserviceaccount.com";
  const roleName = "projects/project-1/roles/secureGatewayPocDeployer";
  let accountPolicy: Record<string, unknown> = {
    etag: "account-before",
    version: 3,
    bindings: [],
  };
  const administrator: Transport = {
    async requestJson(method, url, options = {}) {
      calls.push(`${method} ${url}`);
      if (method === "GET" && url.endsWith(`/serviceAccounts/${accountEmail}`)) {
        return {
          status: 200,
          payload: {
            email: accountEmail,
            uniqueId: "123456789012345678901",
            displayName: "Secure Gateway Studio deployer",
          },
        };
      }
      if (method === "GET" && url.endsWith(roleName)) {
        return {
          status: 200,
          payload: {
            name: roleName,
            etag: "role-etag",
            title: EXTENSION_DEPLOYER_ROLE.title,
            description: EXTENSION_DEPLOYER_ROLE.description,
            includedPermissions: [...EXTENSION_DEPLOYER_ROLE.includedPermissions],
            stage: EXTENSION_DEPLOYER_ROLE.stage,
          },
        };
      }
      if (method === "GET" && url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: {
            name: "projects/111",
            projectId: "project-1",
            parent: "organizations/123",
          },
        };
      }
      if (method === "GET" && url.endsWith("/accessPolicies/456")) {
        return { status: 200, payload: { name: "accessPolicies/456", parent: "organizations/123" } };
      }
      if (url.endsWith(":getIamPolicy")) {
        if (url.includes("accessPolicies/456")) {
          accessPolicyGetBody = options.jsonBody;
        }
        if (url.includes("/serviceAccounts/")) {
          return { status: 200, payload: structuredClone(accountPolicy) };
        }
        return { status: 200, payload: { etag: "before", version: 3, bindings: [] } };
      }
      if (url.includes("/serviceAccounts/") && url.endsWith(":setIamPolicy")) {
        accountPolicy = {
          ...structuredClone(options.jsonBody?.policy ?? {}),
          etag: "account-after",
        };
      }
      if (url.includes("accessPolicies/456:setIamPolicy")) {
        accessPolicySetBody = options.jsonBody;
      }
      return { status: 200, payload: {} };
    },
  };
  await route(
    routeContext(administrator, administrator, {
      accessPolicyId: async () => undefined,
      bootstrapOwnershipPin: async () => ({
        version: 1,
        project_id: "project-1",
        service_account_email: accountEmail,
        service_account_unique_id: "123456789012345678901",
        operator_email: "admin@example.com",
        service_account_iam_bindings: [],
        custom_role: roleName,
        custom_role_etag: "role-etag",
      }),
      checkpointBootstrapOwnershipPin: async () => undefined,
      rememberDeployer: async (_email, _projectId, _uniqueId, policyId) => {
        rememberedPolicy = policyId;
      },
    }),
    "POST",
    "/api/v1/bootstrap/google-cloud/deployer",
    { project_id: "project-1", confirmation: "BOOTSTRAP", access_policy_id: "456" },
  );
  check(
    "bootstrap request grants Policy Editor for catalogue and AUTO_CREATE lifecycle",
    calls.includes(
      "POST https://accesscontextmanager.googleapis.com/v1/accessPolicies/456:getIamPolicy",
    ) &&
      JSON.stringify(accessPolicyGetBody) ===
        JSON.stringify({ options: { requestedPolicyVersion: 3 } }) &&
      (accessPolicySetBody?.policy as { bindings?: Array<{ role?: unknown }> } | undefined)
        ?.bindings?.some(
          (binding) => binding.role === "roles/accesscontextmanager.policyEditor",
        ) === true &&
      rememberedPolicy === "456",
    JSON.stringify({ calls, accessPolicyGetBody, accessPolicySetBody, rememberedPolicy }),
  );
}

// Live access-level update writes Application IAM before Gateway IAM. If the
// second write fails, compensation must not reuse the pre-update etag: the
// Application SET itself has already invalidated it.
{
  const beforePolicy = {
    etag: "before-etag",
    version: 3,
    bindings: [{ role: "roles/viewer", members: ["user:owner@example.com"] }],
  };
  const afterPolicy = {
    ...beforePolicy,
    etag: "after-etag",
    bindings: [
      ...beforePolicy.bindings,
      {
        role: "roles/beyondcorp.sgApplicationUser",
        members: ["group:managed@example.com"],
      },
    ],
  };
  const restoredEtags: unknown[] = [];
  const restoredPolicies: Array<Record<string, unknown>> = [];
  let reads = 0;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        reads += 1;
        return {
          status: 200,
          payload: {
            ...afterPolicy,
            etag: `fresh-${reads}`,
            bindings: [
              ...afterPolicy.bindings,
              { role: "roles/editor", members: ["user:concurrent@example.com"] },
            ],
          },
        };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        restoredEtags.push(
          (options.jsonBody?.policy as { etag?: unknown } | undefined)?.etag,
        );
        restoredPolicies.push(
          structuredClone((options.jsonBody?.policy ?? {}) as Record<string, unknown>),
        );
        return restoredEtags.length === 1
          ? { status: 409, payload: { error: { status: "ABORTED" } } }
          : { status: 200, payload: {} };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  await compensateApplicationIamPolicy(
    transport,
    "https://beyondcorp.googleapis.com/v1/projects/project-1/locations/global/" +
      "securityGateways/default/applications/demo-app",
    beforePolicy,
    afterPolicy,
  );
  check(
    "live access-level compensation refreshes etag and retries 409",
    JSON.stringify(restoredEtags) === JSON.stringify(["fresh-1", "fresh-2"]) &&
      (restoredPolicies.at(-1)?.bindings as Array<{ role?: string }> | undefined)?.some(
        (binding) => binding.role === "roles/editor",
      ) === true &&
      (restoredPolicies.at(-1)?.bindings as Array<{ role?: string }> | undefined)?.some(
        (binding) => binding.role === "roles/beyondcorp.sgApplicationUser",
      ) === false,
    JSON.stringify({ restoredEtags, restoredPolicies }),
  );
}

// Catalogue pagination is a trust boundary: a repeated token must not hang the
// service worker, and a partial list must never be presented as complete.
{
  let groupCalls = 0;
  const repeatedGroups: Transport = {
    async requestJson() {
      groupCalls += 1;
      return {
        status: 200,
        payload: {
          groups: [{ email: "partial@example.com", name: "Partial" }],
          nextPageToken: "repeated",
        },
      };
    },
  };
  let groupError: unknown;
  try {
    await new GoogleSetupCatalog(repeatedGroups, {
      principalHint: "admin@example.com",
      credentialKind: "administrator",
    }).listGroups("C012345");
  } catch (error) {
    groupError = error;
  }
  check(
    "Directory group catalogue rejects a repeated page token",
    groupCalls === 2 &&
      groupError instanceof ConnectionError &&
      groupError.code === "catalog-pagination-invalid",
    `${String(groupError)} | calls=${groupCalls}`,
  );

  let accessLevelCalls = 0;
  const repeatedAccessLevels: Transport = {
    async requestJson(_method, url) {
      if (url.endsWith("/projects/project-1")) {
        return {
          status: 200,
          payload: { name: "projects/111", parent: "organizations/123" },
        };
      }
      if (url.endsWith("/accessPolicies/456")) {
        return {
          status: 200,
          payload: { name: "accessPolicies/456", parent: "organizations/123" },
        };
      }
      if (url.endsWith("/accessPolicies/456/accessLevels")) {
        accessLevelCalls += 1;
        return {
          status: 200,
          payload: { accessLevels: [], nextPageToken: "repeated" },
        };
      }
      throw new Error(`unexpected request ${url}`);
    },
  };
  let accessLevelError: unknown;
  try {
    await new GoogleSetupCatalog(repeatedAccessLevels, {
      principalHint: "deployer@example.iam.gserviceaccount.com",
      credentialKind: "impersonated_service_account",
      accessPolicyId: "456",
    }).listAccessLevels("project-1");
  } catch (error) {
    accessLevelError = error;
  }
  check(
    "Access Level catalogue rejects a repeated page token",
    accessLevelCalls === 2 &&
      accessLevelError instanceof ConnectionError &&
      accessLevelError.code === "catalog-pagination-invalid",
    `${String(accessLevelError)} | calls=${accessLevelCalls}`,
  );
}

{
  const transport: Transport = {
    async requestJson() {
      return {
        status: 200,
        payload: {
          organizationUnits: [
            { orgUnitId: "id:root", orgUnitPath: "/", name: "Root" },
            { orgUnitId: "id:pilot", orgUnitPath: "/Pilot", name: "Pilot" },
          ],
        },
      };
    },
  };
  const options = await new GoogleSetupCatalog(transport, {
    principalHint: "admin@example.com",
    credentialKind: "administrator",
  }).listOrganizationalUnits("C012345");
  check(
    "main deployment catalogue excludes the Workspace Root OU",
    options.length === 1 && options[0].value === "pilot" && options[0].label === "/Pilot",
    JSON.stringify(options),
  );
}

{
  const calls: Array<{ url: string; params?: Record<string, string | number> }> = [];
  const transport: Transport = {
    async requestJson(_method, url, options) {
      calls.push({ url, params: options?.params });
      return {
        status: 200,
        payload: {
          items: [
            {
              name: "z-auto-vpc",
              selfLink:
                "https://www.googleapis.com/compute/v1/projects/project-1/global/networks/z-auto-vpc",
              autoCreateSubnetworks: true,
            },
            {
              name: "a-custom-vpc",
              selfLink:
                "https://www.googleapis.com/compute/v1/projects/project-1/global/networks/a-custom-vpc",
              autoCreateSubnetworks: false,
            },
          ],
        },
      };
    },
  };
  const options = await new GoogleSetupCatalog(transport, {
    principalHint: "deployer@example.iam.gserviceaccount.com",
    credentialKind: "impersonated_service_account",
  }).listVpcNetworks("project-1");
  check(
    "deployment-project VPC catalogue is read-only, validated, and sorted for Step 3",
    calls.length === 1 &&
      calls[0].url.endsWith("/projects/project-1/global/networks") &&
      calls[0].params?.maxResults === 500 &&
      options.map((item) => item.value).join(",") === "a-custom-vpc,z-auto-vpc" &&
      options[0].description === "Custom mode VPC" &&
      options[1].description === "Auto mode VPC",
    JSON.stringify({ calls, options }),
  );
  check(
    "extension deployer role can list deployment-project VPC networks",
    EXTENSION_DEPLOYER_ROLE.includedPermissions.includes("compute.networks.list"),
    JSON.stringify(EXTENSION_DEPLOYER_ROLE.includedPermissions),
  );
  check(
    "extension deployer role covers Option B regional health-check and private-DNS inspection",
    [
      "compute.regionHealthChecks.create",
      "compute.regionHealthChecks.delete",
      "compute.regionHealthChecks.get",
      "compute.regionHealthChecks.useReadOnly",
      "dns.managedZones.get",
      "dns.managedZones.list",
      "dns.resourceRecordSets.get",
    ].every((permission) =>
      (EXTENSION_DEPLOYER_ROLE.includedPermissions as readonly string[]).includes(permission)
    ),
    JSON.stringify(EXTENSION_DEPLOYER_ROLE.includedPermissions),
  );
}

{
  const calls: string[] = [];
  const transport: Transport = {
    async requestJson(method, url) {
      calls.push(`${method} ${url}`);
      return {
        status: 200,
        payload: {
          id: "1234567890123456789",
          name: "debian-12-bookworm-v20260801",
          selfLink:
            "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-12-bookworm-v20260801",
          status: "READY",
        },
      };
    },
  };
  const option = await new GoogleSetupCatalog(transport, {
    principalHint: "deployer@example.iam.gserviceaccount.com",
    credentialKind: "impersonated_service_account",
  }).recommendedPocSourceImage();
  check(
    "PoC sample VM resolves a public image family to an immutable image name",
    calls.length === 1 &&
      calls[0].endsWith("/projects/debian-cloud/global/images/family/debian-12") &&
      option.value ===
        "projects/debian-cloud/global/images/debian-12-bookworm-v20260801" &&
      option.description.includes("1234567890123456789"),
    JSON.stringify({ calls, option }),
  );
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} checks`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} catalog checks passed.`);
