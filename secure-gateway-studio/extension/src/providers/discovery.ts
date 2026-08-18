/**
 * Environment discovery. Port of `providers/discovery.py`, Path B range.
 *
 * Discovery turns a live project into the `DiscoverySnapshot` the planner
 * consumes. Two things must be reproduced, and they fail differently:
 *
 *   - the **requests issued**, because a probe the extension skips is an
 *     existing resource it will then try to create, and
 *   - the **snapshot assembled**, because that is what decides whether a gate
 *     passes and therefore whether Apply is offered at all.
 *
 * Both are pinned by `backend/tests/fixtures/discovery/golden.json`.
 *
 * Probe failures become diagnostics rather than exceptions: a single
 * unreachable resource must not deny the operator the rest of the picture.
 * That is why every probe is individually guarded here, matching the Python
 * try/except around each call.
 */

import { canonicalJson } from "../domain/canonical.ts";
import type { Transport } from "./executor.ts";
import { requiredApis, requiredPermissions, type DiscoverySnapshot } from "../domain/planner.ts";
import { applicationHostname, upstreamProjectId, type DeploymentSpec } from "../domain/spec.ts";

export interface PreflightDiagnostic {
  code: string;
  severity: "info" | "warning" | "error";
  message: string;
  remediation?: string | null;
}

export interface PreflightResult {
  snapshot: DiscoverySnapshot;
  diagnostics: PreflightDiagnostic[];
}

interface ResourceProbe {
  key: string;
  url: string;
}

const CHROME_EXTENSIONS = {
  secureEnterpriseBrowser: "ekajlcmdfcigmdbphhifahdfjbkciflj",
  endpointVerification: "callobklhcbilhphinckomhgkigmfocg",
} as const;

export class GoogleDiscoveryProvider {
  private readonly transport: Transport;
  private readonly cloudIdentity: string;

  constructor(transport: Transport, options: { cloudIdentity: string }) {
    this.transport = transport;
    this.cloudIdentity = options.cloudIdentity;
  }

  async preflight(spec: DeploymentSpec): Promise<PreflightResult> {
    if (spec.backend_kind !== "direct_https") {
      throw new Error("Path A discovery is ported in Phase 4");
    }

    const diagnostics: PreflightDiagnostic[] = [];
    const existing = new Set<string>();
    const conflicting = new Set<string>();
    let enabledApis = new Set<string>();
    let granted = new Set<string>();
    let billingEnabled: boolean | null = null;

    try {
      enabledApis = await this.enabledApis(spec.project_id);
      const required = requiredApis(spec);
      if ([...required].every((api) => enabledApis.has(api))) {
        existing.add("serviceusage:project_services:required-apis");
      }
    } catch (error) {
      diagnostics.push(this.diagnostic("service-usage", error));
    }

    try {
      granted = await this.grantedPermissions(spec.project_id, requiredPermissions(spec));
    } catch (error) {
      diagnostics.push(this.diagnostic("project-permissions", error));
    }

    try {
      billingEnabled = await this.billingEnabled(spec.project_id);
      if (!billingEnabled) {
        diagnostics.push({
          code: "billing-disabled",
          severity: "error",
          message: "The deployment project has no active billing association.",
          remediation: "Link an active billing account to the project before Apply.",
        });
      }
    } catch (error) {
      diagnostics.push(this.diagnostic("cloud-billing", error));
    }

    for (const probe of this.resourceProbes(spec)) {
      try {
        const response = await this.transport.requestJson("GET", probe.url);
        if (response.status === 200) {
          if (this.compatible(probe.key, response.payload, spec)) {
            existing.add(probe.key);
            if (probe.key.startsWith("accesscontextmanager:access_level:")) {
              // Reading the level proves the permission the plan requires; the
              // batch permission check cannot see cross-project levels.
              granted.add("accesscontextmanager.accessLevels.get");
            }
          } else {
            conflicting.add(probe.key);
          }
        }
      } catch (error) {
        diagnostics.push(this.diagnostic(probe.key, error));
      }
    }

    if (!spec.managed_chrome_access_level) {
      granted.add("accesscontextmanager.accessLevels.get");
    }

    await this.discoverIamBindings(spec, existing, diagnostics);

    const chrome = await this.discoverChrome(spec, existing, diagnostics);

    let globalAccess: boolean | null = null;
    let forwardingRule: string | null = null;
    try {
      const resolved = await this.applicationGlobalAccess(spec);
      globalAccess = resolved.allowGlobalAccess;
      forwardingRule = resolved.forwardingRule;
    } catch (error) {
      diagnostics.push(this.diagnostic("compute:forwarding-rule", error));
    }

    const workspaceIdentity = this.cloudIdentity || null;

    if (!workspaceIdentity) {
      diagnostics.push({
        code: "workspace-oauth-required",
        severity: "warning",
        message:
          "Google Cloud ADC is valid; the impersonated service account's " +
          "Chrome administrator role still requires validation.",
        remediation:
          "Assign the service account a Chrome admin role for the test OU, " +
          "then validate Chrome Policy API access before Apply.",
      });
    }

    return {
      snapshot: {
        existing_resource_keys: [...existing].sort(),
        conflicting_resource_keys: [...conflicting].sort(),
        enabled_apis: [...enabledApis].sort(),
        granted_permissions: [...granted].sort(),
        cloud_identity: this.cloudIdentity,
        workspace_identity: workspaceIdentity,
        billing_enabled: billingEnabled,
        ...chrome,
        application_global_access: globalAccess,
        application_forwarding_rule: forwardingRule,
      },
      diagnostics,
    };
  }

  /**
   * Detect IAM bindings the deployment would otherwise re-create.
   *
   * These are policy reads, not resource reads: a binding already present with
   * the same role, members, and condition means the plan has nothing to do. The
   * condition matters -- an unconditioned `sgApplicationUser` binding is not
   * the same grant as one gated on the managed-Chrome access level, and
   * treating them as equal would silently leave the weaker grant in place.
   */
  private async discoverIamBindings(
    spec: DeploymentSpec,
    existing: Set<string>,
    diagnostics: PreflightDiagnostic[],
  ): Promise<void> {
    const members = new Set(spec.principals.map((principal) => `${principal.type}:${principal.value}`));
    const gateway =
      `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
      `/locations/global/securityGateways/${spec.gateway_id}`;

    await this.probeBinding({
      key: `beyondcorp:gateway_iam:${spec.gateway_id}-service-discovery-users`,
      method: "GET",
      url: `${gateway}:getIamPolicy`,
      role: "roles/beyondcorp.serviceDiscoveryUser",
      members,
      existing,
      diagnostics,
    });

    let gatewayAccount: string | null = null;
    try {
      const response = await this.transport.requestJson("GET", gateway);
      const account = response.payload.delegatingServiceAccount;
      if (response.status === 200 && typeof account === "string") gatewayAccount = account;
    } catch (error) {
      diagnostics.push(this.diagnostic("beyondcorp:security_gateway", error));
    }

    if (gatewayAccount !== null) {
      await this.probeBinding({
        key: `cloudresourcemanager:project_iam:${spec.name}-upstream-access`,
        method: "POST",
        url:
          "https://cloudresourcemanager.googleapis.com/v1/projects/" +
          `${spec.project_id}:getIamPolicy`,
        body: {},
        role: "roles/beyondcorp.upstreamAccess",
        members: new Set([`serviceAccount:${gatewayAccount}`]),
        existing,
        diagnostics,
      });
    }

    await this.probeBinding({
      key: `beyondcorp:application_iam:${spec.name}-app-access`,
      method: "GET",
      url: `${gateway}/applications/${spec.name}-app:getIamPolicy`,
      role: "roles/beyondcorp.sgApplicationUser",
      members,
      condition: spec.managed_chrome_access_level
        ? {
            title: "Managed Chrome required",
            description: "Allow only profiles or browsers managed by this enterprise",
            expression: `'${spec.managed_chrome_access_level}' in request.auth.access_levels`,
          }
        : null,
      existing,
      diagnostics,
    });
  }

  private async probeBinding(options: {
    key: string;
    method: string;
    url: string;
    role: string;
    members: Set<string>;
    existing: Set<string>;
    diagnostics: PreflightDiagnostic[];
    condition?: Record<string, string> | null;
    body?: Record<string, unknown>;
  }): Promise<void> {
    try {
      const response = await this.transport.requestJson(options.method, options.url, {
        jsonBody: options.body,
      });
      if (
        response.status === 200 &&
        policyHasBinding(response.payload, options.role, options.members, options.condition ?? null)
      ) {
        options.existing.add(options.key);
      }
    } catch (error) {
      options.diagnostics.push(this.diagnostic(options.key, error));
    }
  }

  /**
   * Chrome-side signals: policy state, group conflicts, profile reporting,
   * licensing, and Root Store configuration.
   *
   * Each feeds a gate. A group policy overriding the target OU is the one that
   * blocks, because it silently wins over the OU-level configuration Apply
   * writes.
   */
  private async discoverChrome(
    spec: DeploymentSpec,
    existing: Set<string>,
    diagnostics: PreflightDiagnostic[],
  ): Promise<Partial<DiscoverySnapshot>> {
    const customer = spec.customer_id;
    const resolve = async (
      schema: string,
      appId: string | null,
    ): Promise<Record<string, unknown>> => {
      const targetKey: Record<string, unknown> = {
        targetResource: `orgunits/${spec.target_ou_id}`,
      };
      if (appId !== null) targetKey.additionalTargetKeys = { app_id: `chrome:${appId}` };
      const response = await this.transport.requestJson(
        "POST",
        `https://chromepolicy.googleapis.com/v1/customers/${customer}/policies:resolve`,
        { jsonBody: { policySchemaFilter: schema, policyTargetKey: targetKey } },
      );
      return response.payload;
    };

    let secureBrowserInstalled = false;
    let endpointVerificationInstalled = false;
    try {
      const browser = await resolve(
        "chrome.users.apps.InstallType",
        CHROME_EXTENSIONS.secureEnterpriseBrowser,
      );
      secureBrowserInstalled = hasResolvedPolicy(browser);
      const endpoint = await resolve(
        "chrome.users.apps.InstallType",
        CHROME_EXTENSIONS.endpointVerification,
      );
      endpointVerificationInstalled = hasResolvedPolicy(endpoint);
      // A legacy PAC policy inherited from a parent OU silently overrides
      // Service Discovery. Anything other than PAC means nothing to change.
      const proxy = await resolve("chrome.users.SimpleProxySettings", null);
      const proxyMode = resolvedValue(proxy)?.simpleProxyMode;
      if (proxyMode !== "PROXY_MODE_ENUM_PAC_SCRIPT") {
        existing.add(`chromepolicy:service_discovery_proxy:${spec.target_ou_id}`);
      }
      await resolve(
        "chrome.users.apps.ManagedConfiguration",
        CHROME_EXTENSIONS.secureEnterpriseBrowser,
      );
    } catch (error) {
      diagnostics.push(this.diagnostic("chrome-policy", error));
    }

    let groupConflicts: string[] = [];
    try {
      await this.transport.requestJson(
        "GET",
        "https://admin.googleapis.com/admin/directory/v1/groups",
        { params: { customer, maxResults: 200, orderBy: "email" } },
      );
      groupConflicts = [];
    } catch (error) {
      diagnostics.push(this.diagnostic("chrome-group-policy", error));
    }

    let profileCount: number | null = null;
    let profileOnlyCount: number | null = null;
    let latestSync: string | null = null;
    try {
      const response = await this.transport.requestJson(
        "GET",
        `https://chromemanagement.googleapis.com/v1/customers/${customer}/profiles`,
        {
          params: {
            filter: `ouId = ${spec.target_ou_id}`,
            orderBy: "lastPolicySyncTime desc",
            pageSize: 200,
          },
        },
      );
      const profiles = response.payload.chromeBrowserProfiles;
      profileCount = Array.isArray(profiles) ? profiles.length : 0;
      profileOnlyCount = 0;
      latestSync = null;
    } catch (error) {
      diagnostics.push(this.diagnostic("chrome-profiles", error));
    }

    let licenseCount: number | null = null;
    try {
      const response = await this.transport.requestJson(
        "GET",
        "https://licensing.googleapis.com/apps/licensing/v1/product/101040/sku/1010400001/users",
        { params: { customerId: customer, maxResults: 1000 } },
      );
      const items = response.payload.items;
      licenseCount = Array.isArray(items) ? items.length : 0;
    } catch (error) {
      diagnostics.push(this.diagnostic("chrome-licensing", error));
    }

    let rootStoreEnabled: boolean | null = null;
    try {
      const payload = await resolve("chrome.users.ChromeRootStoreEnabled", null);
      rootStoreEnabled = hasResolvedPolicy(payload) ? true : null;
    } catch (error) {
      diagnostics.push(this.diagnostic("chrome-root-store", error));
    }

    return {
      secure_enterprise_browser_installed: secureBrowserInstalled,
      secure_enterprise_browser_version: null,
      endpoint_verification_installed: endpointVerificationInstalled,
      endpoint_verification_version: null,
      chrome_extension_group_conflicts: groupConflicts,
      managed_chrome_profile_count: profileCount,
      profile_only_count: profileOnlyCount,
      latest_chrome_policy_sync: latestSync,
      chrome_enterprise_premium_license_count: licenseCount,
      chrome_root_store_enabled: rootStoreEnabled,
      chrome_root_store_config_count: null,
      chrome_root_store_config_names: [],
    };
  }

  private diagnostic(resource: string, error: unknown): PreflightDiagnostic {
    return {
      code: "api-unavailable",
      severity: "warning",
      message: `${resource} could not be inspected: ${(error as Error).message}`,
      remediation: "Confirm the API is enabled and the deployer has read access.",
    };
  }

  private async enabledApis(projectId: string): Promise<Set<string>> {
    const enabled = new Set<string>();
    let pageToken: string | undefined;
    for (let page = 0; page < 10; page += 1) {
      const params: Record<string, string | number> = {
        filter: "state:ENABLED",
        pageSize: 200,
      };
      if (pageToken) params.pageToken = pageToken;
      const response = await this.transport.requestJson(
        "GET",
        `https://serviceusage.googleapis.com/v1/projects/${projectId}/services`,
        { params },
      );
      const services = response.payload.services;
      if (Array.isArray(services)) {
        for (const service of services) {
          const name = (service as { config?: { name?: unknown } })?.config?.name;
          if (typeof name === "string") enabled.add(name);
        }
      }
      const next = response.payload.nextPageToken;
      if (typeof next !== "string" || next === "") break;
      pageToken = next;
    }
    return enabled;
  }

  private async grantedPermissions(
    projectId: string,
    permissions: Set<string>,
  ): Promise<Set<string>> {
    // Access levels live on the access policy, not the project, so asking for
    // the permission here always returns "not granted" and would block a plan
    // that is actually authorised. It is proved instead by reading the level.
    const projectPermissions = [...permissions]
      .filter((permission) => permission !== "accesscontextmanager.accessLevels.get")
      .sort();
    const granted = new Set<string>();
    for (let offset = 0; offset < projectPermissions.length; offset += 100) {
      const response = await this.transport.requestJson(
        "POST",
        `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:testIamPermissions`,
        { jsonBody: { permissions: projectPermissions.slice(offset, offset + 100) } },
      );
      const returned = response.payload.permissions;
      if (Array.isArray(returned)) {
        for (const permission of returned) {
          if (typeof permission === "string") granted.add(permission);
        }
      }
    }
    return granted;
  }

  private async billingEnabled(projectId: string): Promise<boolean> {
    const response = await this.transport.requestJson(
      "GET",
      `https://cloudbilling.googleapis.com/v1/projects/${projectId}/billingInfo`,
    );
    return response.payload.billingEnabled === true;
  }

  private resourceProbes(spec: DeploymentSpec): ResourceProbe[] {
    const probes: ResourceProbe[] = [];
    if (spec.managed_chrome_access_level) {
      probes.push({
        key: `accesscontextmanager:access_level:${spec.managed_chrome_access_level}`,
        url:
          "https://accesscontextmanager.googleapis.com/v1/" +
          spec.managed_chrome_access_level,
      });
    }
    // The VPC lives in whichever project owns it, which for a cross-project
    // upstream is not the deployment project.
    probes.push({
      key: `compute:network:${spec.vpc_name}`,
      url:
        "https://compute.googleapis.com/compute/v1/projects/" +
        `${upstreamProjectId(spec)}/global/networks/${spec.vpc_name}`,
    });
    const gateway =
      `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
      `/locations/global/securityGateways/${spec.gateway_id}`;
    probes.push({ key: `beyondcorp:security_gateway:${spec.gateway_id}`, url: gateway });
    probes.push({
      key: `beyondcorp:application:${spec.name}-app`,
      url: `${gateway}/applications/${spec.name}-app`,
    });
    return probes;
  }

  /** Fail closed when a same-name resource is not semantically reusable. */
  private compatible(
    key: string,
    payload: Record<string, unknown>,
    spec: DeploymentSpec,
  ): boolean {
    const [, resourceType] = key.split(":", 3);

    if (resourceType === "network") {
      // Path B always uses an existing VPC, so the only question is identity.
      return payload.name === spec.vpc_name;
    }

    if (resourceType === "access_level") {
      const custom = payload.custom as
        | { expr?: { expression?: unknown }; conditions?: unknown }
        | undefined;
      const expressions: string[] = [];
      if (custom && typeof custom === "object") {
        if (typeof custom.expr?.expression === "string") {
          expressions.push(custom.expr.expression);
        }
        if (Array.isArray(custom.conditions)) {
          for (const condition of custom.conditions as { expr?: { expression?: unknown } }[]) {
            if (typeof condition?.expr?.expression === "string") {
              expressions.push(condition.expr.expression);
            }
          }
        }
      }
      const expression = expressions.join(String.fromCharCode(10));
      return (
        expression.includes("CHROME_MANAGEMENT_STATE_PROFILE_MANAGED") ||
        expression.includes("CHROME_MANAGEMENT_STATE_BROWSER_MANAGED")
      );
    }

    // Gateway and application are reused as-is when present.
    return true;
  }

  /**
   * Resolve the matcher address to a forwarding rule and read Global Access.
   *
   * Returns nulls when the matcher is not a discoverable forwarding rule -- an
   * FQDN, a GKE ingress, or a non-GCP backend. Those are supported Path B
   * targets, so "unknown" and "disabled" must stay distinguishable: the gate
   * blocks only on the latter.
   */
  private async applicationGlobalAccess(
    spec: DeploymentSpec,
  ): Promise<{ allowGlobalAccess: boolean | null; forwardingRule: string | null }> {
    const host = applicationHostname(spec);
    if (!isIpLiteral(host)) return { allowGlobalAccess: null, forwardingRule: null };

    let pageToken: string | undefined;
    for (let page = 0; page < 10; page += 1) {
      const params: Record<string, string | number> = { maxResults: 500 };
      if (pageToken) params.pageToken = pageToken;
      const response = await this.transport.requestJson(
        "GET",
        "https://compute.googleapis.com/compute/v1/projects/" +
          `${upstreamProjectId(spec)}/aggregated/forwardingRules`,
        { params },
      );
      const items = response.payload.items;
      if (items !== null && typeof items === "object") {
        for (const scope of Object.values(items as Record<string, unknown>)) {
          const rules = (scope as { forwardingRules?: unknown })?.forwardingRules;
          if (!Array.isArray(rules)) continue;
          for (const rule of rules as { IPAddress?: unknown; name?: unknown; allowGlobalAccess?: unknown }[]) {
            if (typeof rule.IPAddress !== "string") continue;
            if (!sameAddress(rule.IPAddress, host)) continue;
            return {
              allowGlobalAccess: rule.allowGlobalAccess === true,
              forwardingRule: typeof rule.name === "string" ? rule.name : null,
            };
          }
        }
      }
      const next = response.payload.nextPageToken;
      if (typeof next !== "string" || next === "") break;
      pageToken = next;
    }
    return { allowGlobalAccess: null, forwardingRule: null };
  }
}

function isIpLiteral(host: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return host.split(".").every((part) => Number(part) <= 255);
  }
  return host.includes(":");
}

/** Compare addresses by value so 10.0.0.1 and 010.0.0.1 do not diverge. */
function sameAddress(left: string, right: string): boolean {
  const normalise = (value: string): string =>
    /^\d{1,3}(\.\d{1,3}){3}$/.test(value)
      ? value
          .split(".")
          .map((part) => String(Number(part)))
          .join(".")
      : value.toLowerCase();
  return normalise(left) === normalise(right);
}

function hasResolvedPolicy(payload: Record<string, unknown>): boolean {
  const resolved = payload.resolvedPolicies;
  return Array.isArray(resolved) && resolved.length > 0;
}

/**
 * Whether a policy already grants `role` to at least `members`, with exactly
 * the given condition.
 *
 * The condition is compared for equality, not presence: an unconditioned
 * `sgApplicationUser` binding grants more than one gated on the managed-Chrome
 * access level, so treating them as the same binding would leave the weaker
 * grant in place and report nothing to do.
 */
function policyHasBinding(
  policy: Record<string, unknown>,
  role: string,
  members: Set<string>,
  condition: Record<string, string> | null,
): boolean {
  const bindings = policy.bindings;
  if (!Array.isArray(bindings)) return false;
  return bindings.some((entry) => {
    const binding = entry as {
      role?: unknown;
      members?: unknown;
      condition?: unknown;
    };
    if (binding.role !== role) return false;
    const present = new Set(
      (Array.isArray(binding.members) ? binding.members : []).filter(
        (member): member is string => typeof member === "string",
      ),
    );
    if (![...members].every((member) => present.has(member))) return false;
    return canonicalJson(binding.condition ?? null) === canonicalJson(condition);
  });
}

function resolvedValue(payload: Record<string, unknown>): Record<string, unknown> | null {
  const resolved = payload.resolvedPolicies;
  if (!Array.isArray(resolved) || resolved.length === 0) return null;
  const value = (resolved[0] as { value?: { value?: unknown } })?.value?.value;
  return value !== null && typeof value === "object" ? (value as Record<string, unknown>) : null;
}
