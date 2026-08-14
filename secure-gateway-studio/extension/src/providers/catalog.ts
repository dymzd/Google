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
    const accessPolicyId = this.options.accessPolicyId;
    if (!accessPolicyId) {
      throw new ConnectionError(
        "access-policy-not-configured",
        "Set the Access Context Manager policy ID before choosing an access level.",
      );
    }
    const organization = await this.projectOrganization(projectId);
    const policyName = `accessPolicies/${accessPolicyId}`;
    const { payload: policy } = await this.transport.requestJson(
      "GET",
      `${ACM}/${policyName}`,
    );
    if (policy.parent !== organization) {
      throw new ConnectionError(
        "access-policy-organization-mismatch",
        "The access policy does not belong to the project organization",
      );
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
