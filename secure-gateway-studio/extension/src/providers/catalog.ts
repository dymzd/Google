/**
 * Setup catalogues and connection validation. Port of `providers/catalog.py`
 * and `providers/connections.py`.
 *
 * These feed the first three steps of the wizard: confirm the project, confirm
 * Workspace access, then pick an OU, a group, and an access level. Nothing
 * downstream can be configured until they answer, which is why their absence
 * made the whole product look broken rather than partly built.
 */

import type { Transport } from "./executor.ts";

export interface SetupOption {
  value: string;
  label: string;
  description: string;
}

export interface ConnectionValidation {
  provider: "google_cloud" | "workspace";
  status: "connected";
  principal_hint: string;
  resource_id: string;
  credential_kind: string;
}

export class ConnectionError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ConnectionError";
    this.code = code;
  }
}

const ADMIN = "https://admin.googleapis.com/admin/directory/v1";
const ACM = "https://accesscontextmanager.googleapis.com/v1";
const CRM = "https://cloudresourcemanager.googleapis.com/v3";

interface CatalogOptions {
  principalHint: string;
  credentialKind: string;
  accessPolicyId?: string;
}

export class GoogleSetupCatalog {
  private readonly transport: Transport;
  private readonly options: CatalogOptions;

  constructor(transport: Transport, options: CatalogOptions) {
    this.transport = transport;
    this.options = options;
  }

  /** Confirm the credential can see the project, and that it is the right one. */
  async validateCloud(projectId: string): Promise<ConnectionValidation> {
    const { payload } = await this.transport.requestJson("GET", `${CRM}/projects/${projectId}`);
    if (payload.projectId !== projectId) {
      throw new ConnectionError(
        "project-identity-mismatch",
        "Google Cloud returned an unexpected project identity",
      );
    }
    return {
      provider: "google_cloud",
      status: "connected",
      principal_hint: this.options.principalHint,
      resource_id: projectId,
      credential_kind: this.options.credentialKind,
    };
  }

  /**
   * Confirm Chrome Policy access for the customer, and for the target OU when
   * one is chosen.
   *
   * Reading a single policy schema proves the API is enabled and the
   * impersonated account holds a Chrome administrator role. Resolving one
   * policy against the OU proves the OU exists and is addressable, which is
   * the failure an operator otherwise meets much later during Apply.
   */
  async validateWorkspace(
    customerId: string,
    targetOuId?: string,
  ): Promise<ConnectionValidation> {
    await this.transport.requestJson(
      "GET",
      `https://chromepolicy.googleapis.com/v1/customers/${customerId}/policySchemas`,
      { params: { pageSize: 1 } },
    );
    if (targetOuId) {
      await this.transport.requestJson(
        "POST",
        `https://chromepolicy.googleapis.com/v1/customers/${customerId}/policies:resolve`,
        {
          jsonBody: {
            policySchemaFilter: "chrome.users.*",
            policyTargetKey: { targetResource: `orgunits/${targetOuId}` },
            pageSize: 1,
          },
        },
      );
    }
    return {
      provider: "workspace",
      status: "connected",
      principal_hint: this.options.principalHint,
      resource_id: customerId,
      credential_kind: this.options.credentialKind,
    };
  }

  async listOrganizationalUnits(customerId: string): Promise<SetupOption[]> {
    const { payload } = await this.transport.requestJson(
      "GET",
      `${ADMIN}/customer/${customerId}/orgunits`,
      { params: { type: "all_including_parent" } },
    );
    const units = Array.isArray(payload.organizationUnits) ? payload.organizationUnits : [];
    const options: SetupOption[] = [];
    for (const item of units) {
      const record = item as Record<string, unknown>;
      const rawId = record.orgUnitId;
      const path = record.orgUnitPath;
      if (typeof rawId !== "string" || typeof path !== "string") continue;
      options.push({
        // The API returns `id:03abc...`; the policy target wants the bare id.
        value: rawId.replace(/^id:/, ""),
        label: path,
        description: String(record.name ?? ""),
      });
    }
    return options.sort((a, b) =>
      a.label.toLowerCase().localeCompare(b.label.toLowerCase()),
    );
  }

  async listGroups(customerId: string): Promise<SetupOption[]> {
    const options: SetupOption[] = [];
    let pageToken = "";
    while (options.length < 2000) {
      const params: Record<string, string | number> = {
        customer: customerId,
        maxResults: 200,
        orderBy: "email",
      };
      if (pageToken) params.pageToken = pageToken;
      const { payload } = await this.transport.requestJson("GET", `${ADMIN}/groups`, {
        params,
      });
      const groups = Array.isArray(payload.groups) ? payload.groups : [];
      for (const item of groups) {
        const record = item as Record<string, unknown>;
        const email = record.email;
        if (typeof email !== "string" || email === "") continue;
        options.push({
          value: email.toLowerCase(),
          label: String(record.name ?? email),
          description: email.toLowerCase(),
        });
      }
      const next = payload.nextPageToken;
      if (typeof next !== "string" || next === "") break;
      pageToken = next;
    }
    return options;
  }

  /**
   * Access levels from the configured policy.
   *
   * The policy is checked to belong to the project's organization first. A
   * level from another organization would bind as an IAM condition and then
   * never match, producing an application nobody can reach.
   */
  async listAccessLevels(projectId: string): Promise<SetupOption[]> {
    let accessPolicyId = this.options.accessPolicyId;
    let organization: string | null = null;
    try {
      organization = await this.projectOrganization(projectId);
    } catch {
      // Standalone project without organization in PoC
      return [];
    }

    if (!accessPolicyId && organization) {
      try {
        const { payload } = await this.transport.requestJson(
          "GET",
          `${ACM}/accessPolicies`,
          { params: { parent: organization } },
        );
        const policies = Array.isArray(payload.accessPolicies) ? payload.accessPolicies : [];
        if (policies.length > 0 && typeof policies[0]?.name === "string") {
          accessPolicyId = policies[0].name.replace(/^accessPolicies\//, "");
        }
      } catch {
        // Access Context Manager API disabled or no permission
        return [];
      }
    }

    if (!accessPolicyId) {
      return [];
    }

    const policyName = `accessPolicies/${accessPolicyId}`;
    try {
      const { payload: policy } = await this.transport.requestJson(
        "GET",
        `${ACM}/${policyName}`,
      );
      if (organization && policy.parent !== organization) {
        return [];
      }

      const levels = await this.listCollection(
        `${ACM}/${policyName}/accessLevels`,
        "accessLevels",
        { pageSize: 100 },
      );
      const options: SetupOption[] = [];
      for (const level of levels) {
        const name = level.name;
        const title = level.title;
        if (typeof name !== "string" || typeof title !== "string") continue;
        options.push({ value: name, label: title, description: String(level.description ?? "") });
      }
      return options.sort((a, b) =>
        a.label.toLowerCase().localeCompare(b.label.toLowerCase()),
      );
    } catch {
      return [];
    }
  }

  /** Walk up through folders to the organization the project belongs to. */
  private async projectOrganization(projectId: string): Promise<string> {
    const { payload } = await this.transport.requestJson("GET", `${CRM}/projects/${projectId}`);
    let parent = payload.parent;
    for (let depth = 0; depth < 10; depth += 1) {
      if (typeof parent !== "string") break;
      if (parent.startsWith("organizations/")) return parent;
      if (!parent.startsWith("folders/")) break;
      const folder = await this.transport.requestJson("GET", `${CRM}/${parent}`);
      parent = folder.payload.parent;
    }
    throw new ConnectionError(
      "project-not-in-organization",
      "The Google Cloud project is not attached to an organization",
    );
  }

  private async listCollection(
    url: string,
    collection: string,
    params: Record<string, string | number>,
  ): Promise<Record<string, unknown>[]> {
    const items: Record<string, unknown>[] = [];
    let pageToken = "";
    while (items.length < 2000) {
      const request = { ...params };
      if (pageToken) request.pageToken = pageToken;
      const { payload } = await this.transport.requestJson("GET", url, { params: request });
      const page = payload[collection];
      if (Array.isArray(page)) {
        for (const item of page) {
          if (item !== null && typeof item === "object") {
            items.push(item as Record<string, unknown>);
          }
        }
      }
      const next = payload.nextPageToken;
      if (typeof next !== "string" || next === "") break;
      pageToken = next;
    }
    return items;
  }
}

export async function ensureManagedChromeAccessLevel(
  transport: Transport,
  projectId: string,
  kind: "profile" | "browser" | "any",
): Promise<string> {
  const ACM = "https://accesscontextmanager.googleapis.com/v1";
  const CRM = "https://cloudresourcemanager.googleapis.com/v1";

  let organization: string | undefined;
  try {
    const { payload } = await transport.requestJson("GET", `${CRM}/projects/${projectId}`);
    let parent = payload.parent;
    while (parent && typeof parent === "string" && !parent.startsWith("organizations/")) {
      const res = await transport.requestJson("GET", `${CRM}/${parent}`);
      parent = res.payload?.parent;
    }
    if (typeof parent === "string" && parent.startsWith("organizations/")) {
      organization = parent;
    }
  } catch {}

  let accessPolicyId: string | undefined;
  if (organization) {
    try {
      const { payload } = await transport.requestJson("GET", `${ACM}/accessPolicies`, {
        params: { parent: organization },
      });
      const policies = Array.isArray(payload.accessPolicies) ? payload.accessPolicies : [];
      if (policies.length > 0 && typeof policies[0]?.name === "string") {
        accessPolicyId = policies[0].name.replace(/^accessPolicies\//, "");
      }
    } catch {}
  }
  if (!accessPolicyId) {
    // Previously fell back to a hardcoded policy id from a development tenant,
    // which would write an access level into somebody else's organization or
    // fail with a confusing 403. Callers wrap this and report the reason.
    throw new ConnectionError(
      "access-policy-not-found",
      `No Access Context Manager policy was found for project ${projectId}. Create one, or set the access policy id in the extension's settings.`,
    );
  }

  const policyName = `accessPolicies/${accessPolicyId}`;
  const levelNameSuffix =
    kind === "profile"
      ? "secgw_profile_managed"
      : kind === "browser"
      ? "secgw_browser_managed"
      : "secgw_chrome_managed";
  const fullName = `${policyName}/accessLevels/${levelNameSuffix}`;

  // Check if it already exists
  try {
    const res = await transport.requestJson("GET", `${ACM}/${fullName}`);
    if (res.payload?.name) return fullName;
  } catch {}

  // Create it with the standard CEL expression
  const title =
    kind === "profile"
      ? "Managed Chrome Profile (SGS)"
      : kind === "browser"
      ? "Managed Chrome Browser (SGS)"
      : "Managed Chrome Profile or Browser (SGS)";

  const expression =
    kind === "profile"
      ? 'device.chrome_profile_managed == true || origin.access_levels.exists(lvl, lvl == "CHROME_MANAGEMENT_STATE_PROFILE_MANAGED")'
      : kind === "browser"
      ? 'device.is_managed == true || origin.access_levels.exists(lvl, lvl == "CHROME_MANAGEMENT_STATE_BROWSER_MANAGED")'
      : 'device.chrome_profile_managed == true || device.is_managed == true || origin.access_levels.exists(lvl, lvl == "CHROME_MANAGEMENT_STATE_PROFILE_MANAGED") || origin.access_levels.exists(lvl, lvl == "CHROME_MANAGEMENT_STATE_BROWSER_MANAGED")';

  try {
    await transport.requestJson("POST", `${ACM}/${policyName}/accessLevels`, {
      jsonBody: {
        name: fullName,
        title,
        description: "Created automatically by Secure Gateway Studio",
        custom: {
          expr: {
            expression,
          },
        },
      },
    });
    console.log("[SGS Catalog] Created custom CEL Access Level:", fullName);
  } catch (err) {
    console.warn("[SGS Catalog] Note creating Access Level:", err);
  }

  return fullName;
}
