/**
 * Setup catalogues and connection validation. Port of `providers/catalog.py`
 * and `providers/connections.py`.
 *
 * These feed the first three steps of the wizard: confirm the project, confirm
 * Workspace access, then pick an OU, a group, and an access level. Nothing
 * downstream can be configured until they answer, which is why their absence
 * made the whole product look broken rather than partly built.
 */

import { GoogleApiError, type Transport } from "./executor.ts";
import {
  EXTENSION_DEPLOYER_READINESS_PERMISSIONS,
} from "../domain/extension-deployer-role.ts";

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
  access_policy_id: string | null;
  read_only: true;
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
const COMPUTE = "https://compute.googleapis.com/compute/v1";
const MAX_CATALOG_ITEMS = 2_000;
const MAX_CATALOG_PAGES = 20;

const DNS_ORGANIZATION_RESTRICTION_REASONS = new Set([
  "ORGANIZATION_POLICY_VIOLATION",
  "ORG_RESTRICTION",
  "SECURITY_POLICY_VIOLATED",
  "VPC_SERVICE_CONTROLS",
]);
const DNS_API_DISABLED_REASONS = new Set([
  "API_DISABLED",
  "SERVICE_DISABLED",
]);

interface SanitizedGoogleFailure {
  httpStatus: number | null;
  status: string | null;
  reasons: string[];
}

function sanitizedGoogleFailure(error: unknown): SanitizedGoogleFailure | null {
  const candidateStatus = typeof error === "object" && error !== null
    ? (error as { status?: unknown }).status
    : null;
  const httpStatus = typeof candidateStatus === "number" &&
      Number.isInteger(candidateStatus) && candidateStatus >= 100 && candidateStatus <= 599
    ? candidateStatus
    : null;
  if (!(error instanceof GoogleApiError)) {
    return httpStatus === null ? null : { httpStatus, status: null, reasons: [] };
  }
  const googleError = error.payload.error;
  if (typeof googleError !== "object" || googleError === null || Array.isArray(googleError)) {
    return { httpStatus, status: null, reasons: [] };
  }
  const errorRecord = googleError as Record<string, unknown>;
  const status = typeof errorRecord.status === "string" &&
      /^[A-Z][A-Z0-9_]{1,80}$/.test(errorRecord.status)
    ? errorRecord.status
    : null;
  const details = Array.isArray(errorRecord.details) ? errorRecord.details : [];
  const reasons = details.flatMap((detail) => {
    if (typeof detail !== "object" || detail === null || Array.isArray(detail)) return [];
    const reason = (detail as Record<string, unknown>).reason;
    return typeof reason === "string" && /^[A-Z][A-Z0-9_]{1,80}$/.test(reason)
      ? [reason]
      : [];
  });
  return { httpStatus, status, reasons: [...new Set(reasons)] };
}

function dnsReadinessError(error: unknown): ConnectionError {
  if (error instanceof ConnectionError) return error;
  const googleFailure = sanitizedGoogleFailure(error);
  const reason = googleFailure?.reasons.find((item) =>
    DNS_ORGANIZATION_RESTRICTION_REASONS.has(item)
  );
  if (reason) {
    return new ConnectionError(
      "deployer-dns-organization-restricted",
      `Cloud DNS rejected the impersonated deployer because of an organization restriction (${reason}). ` +
        "Review VPC Service Controls, organization policy, and IAM deny policies for dns.googleapis.com.",
    );
  }
  const apiDisabledReason = googleFailure?.reasons.find((item) =>
    DNS_API_DISABLED_REASONS.has(item)
  );
  if (apiDisabledReason) {
    return new ConnectionError(
      "deployer-required-api-disabled",
      `Cloud DNS API rejected the readiness check because the service is disabled (${apiDisabledReason}). ` +
        "Enable dns.googleapis.com, then retry automatic deployer setup.",
    );
  }
  if (googleFailure?.httpStatus === 403) {
    const statusSuffix = googleFailure.status ? ` Google status: ${googleFailure.status}.` : "";
    return new ConnectionError(
      "deployer-dns-permission-denied",
      "Cloud DNS returned HTTP 403 for the impersonated deployer." + statusSuffix +
        " IAM propagation for the exact role or binding may still be incomplete; " +
        "automatic setup will retry. " +
        "If it persists, inspect inherited deny policies and service perimeters.",
    );
  }
  if (error instanceof TypeError) {
    return new ConnectionError(
      "deployer-dns-network-failed",
      "The extension could not reach dns.googleapis.com. Check the browser network, proxy, " +
        "and organization URL restrictions, then retry.",
    );
  }
  const httpSuffix = googleFailure?.httpStatus ? ` HTTP ${googleFailure.httpStatus}.` : "";
  const statusSuffix = googleFailure?.status ? ` Google status: ${googleFailure.status}.` : "";
  return new ConnectionError(
    "deployer-dns-readiness-failed",
    "The impersonated deployer has not yet completed the Cloud DNS read check for " +
      "dns.managedZones.get." + httpSuffix + statusSuffix +
      " IAM propagation commonly takes several minutes; " +
      "automatic setup will retry for up to two minutes. If it still fails, wait and validate again.",
  );
}

function nextCatalogPageToken(
  payload: Record<string, unknown>,
  seen: Set<string>,
  catalogue: string,
): string | null {
  const next = payload.nextPageToken;
  if (next === undefined || next === "") return null;
  if (typeof next !== "string" || seen.has(next)) {
    throw new ConnectionError(
      "catalog-pagination-invalid",
      `Google returned an invalid ${catalogue} page token`,
    );
  }
  seen.add(next);
  return next;
}

function assertCatalogLimit(count: number, hasNextPage: boolean, catalogue: string): void {
  if (count > MAX_CATALOG_ITEMS || (count >= MAX_CATALOG_ITEMS && hasNextPage)) {
    throw new ConnectionError(
      "catalog-result-limit-exceeded",
      `Google ${catalogue} catalogue exceeded the ${MAX_CATALOG_ITEMS}-item safety limit`,
    );
  }
}

interface ProjectPolicyContext {
  organization: string;
  /** Project number plus every ancestor folder resource name. */
  applicableScopes: Set<string>;
}

function accessPolicyScopes(policy: Record<string, unknown>): string[] {
  if (policy.scopes === undefined) return [];
  if (
    !Array.isArray(policy.scopes) ||
    policy.scopes.some(
      (scope) =>
        typeof scope !== "string" ||
        !/^(?:projects|folders)\/\d+$/.test(scope),
    )
  ) {
    throw new ConnectionError(
      "access-policy-response-invalid",
      "Google returned malformed Access Context Manager policy scopes",
    );
  }
  return [...new Set(policy.scopes as string[])];
}

function assertApplicableAccessPolicy(
  policy: Record<string, unknown>,
  name: string,
  context: ProjectPolicyContext,
): void {
  if (policy.name !== name) {
    throw new ConnectionError(
      "access-policy-identity-mismatch",
      "Google returned an unexpected Access Context Manager policy identity",
    );
  }
  if (policy.parent !== context.organization) {
    throw new ConnectionError(
      "access-policy-organization-mismatch",
      "The Access Context Manager policy belongs to another organization",
    );
  }
  const scopes = accessPolicyScopes(policy);
  if (
    scopes.length > 0 &&
    !scopes.some((scope) => context.applicableScopes.has(scope))
  ) {
    throw new ConnectionError(
      "access-policy-scope-mismatch",
      "The Access Context Manager policy is not scoped to this project or one of its ancestor folders",
    );
  }
}

async function projectPolicyContext(
  transport: Transport,
  projectId: string,
): Promise<ProjectPolicyContext> {
  const { payload } = await transport.requestJson(
    "GET",
    `${CRM}/projects/${projectId}`,
  );
  const projectName = payload.name;
  if (typeof projectName !== "string" || !/^projects\/\d+$/.test(projectName)) {
    throw new ConnectionError(
      "project-number-invalid",
      "Google Cloud did not return the project's immutable numeric resource name",
    );
  }
  const applicableScopes = new Set<string>([projectName]);
  let parent = payload.parent;
  if (parent === undefined || parent === null || parent === "") {
    throw new ConnectionError(
      "project-not-in-organization",
      "The Google Cloud project is not attached to an organization",
    );
  }
  const seenFolders = new Set<string>();
  let folderCount = 0;
  while (true) {
    if (typeof parent !== "string") {
      throw new ConnectionError(
        "project-hierarchy-invalid",
        "Google Cloud returned a malformed project folder hierarchy",
      );
    }
    if (/^organizations\/\d+$/.test(parent)) {
      return { organization: parent, applicableScopes };
    }
    if (!/^folders\/\d+$/.test(parent)) {
      throw new ConnectionError(
        "project-hierarchy-invalid",
        "Google Cloud returned a malformed project folder hierarchy",
      );
    }
    // Resource Manager permits at most ten nested folders. Check the parent
    // reached *after* the tenth GET before enforcing that limit, otherwise a
    // legal project -> folder x10 -> organization chain is rejected.
    if (folderCount >= 10 || seenFolders.has(parent)) {
      throw new ConnectionError(
        "project-hierarchy-invalid",
        "The Google Cloud project folder hierarchy exceeded ten levels or contained a cycle",
      );
    }
    seenFolders.add(parent);
    folderCount += 1;
    applicableScopes.add(parent);
    const folder = await transport.requestJson("GET", `${CRM}/${parent}`);
    parent = folder.payload.parent;
  }
}

async function listAccessPolicies(
  transport: Transport,
  organization: string,
): Promise<Record<string, unknown>[]> {
  const policies: Record<string, unknown>[] = [];
  let pageToken = "";
  const seenPageTokens = new Set<string>();
  let complete = false;
  for (let pageIndex = 0; pageIndex < MAX_CATALOG_PAGES; pageIndex += 1) {
    const params: Record<string, string | number> = {
      parent: organization,
      pageSize: 100,
    };
    if (pageToken) params.pageToken = pageToken;
    const { payload } = await transport.requestJson(
      "GET",
      `${ACM}/accessPolicies`,
      { params },
    );
    const page = payload.accessPolicies;
    if (page !== undefined && !Array.isArray(page)) {
      throw new ConnectionError(
        "access-policy-response-invalid",
        "Google returned an invalid Access Context Manager policy list",
      );
    }
    for (const policy of page ?? []) {
      if (typeof policy !== "object" || policy === null || Array.isArray(policy)) {
        throw new ConnectionError(
          "access-policy-response-invalid",
          "Google returned an invalid Access Context Manager policy",
        );
      }
      policies.push(policy as Record<string, unknown>);
    }
    const next = nextCatalogPageToken(payload, seenPageTokens, "Access Policy");
    assertCatalogLimit(policies.length, next !== null, "Access Policy");
    if (next === null) {
      complete = true;
      break;
    }
    pageToken = next;
  }
  if (!complete) {
    throw new ConnectionError(
      "catalog-pagination-incomplete",
      "Google Access Policy catalogue pagination did not complete",
    );
  }
  return policies;
}

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
    if (this.options.credentialKind === "impersonated_service_account") {
      const { payload: permissionResult } = await this.transport.requestJson(
        "POST",
        `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:testIamPermissions`,
        {
          jsonBody: {
            permissions: [...EXTENSION_DEPLOYER_READINESS_PERMISSIONS],
          },
        },
      );
      const granted = new Set(
        Array.isArray(permissionResult.permissions)
          ? permissionResult.permissions.filter(
            (permission): permission is string => typeof permission === "string",
          )
          : [],
      );
      const missing = EXTENSION_DEPLOYER_READINESS_PERMISSIONS.filter(
        (permission) => !granted.has(permission),
      );
      if (missing.length > 0) {
        throw new ConnectionError(
          "deployer-permissions-not-ready",
          `The deployer custom role is not yet effective for: ${missing.join(", ")}. ` +
            "Run automatic deployer setup again or retry connection validation after IAM propagation.",
        );
      }

      const { payload: dnsService } = await this.transport.requestJson(
        "GET",
        `https://serviceusage.googleapis.com/v1/projects/${projectId}` +
          "/services/dns.googleapis.com",
      );
      if (dnsService.state !== "ENABLED") {
        throw new ConnectionError(
          "deployer-required-api-disabled",
          "Cloud DNS API (dns.googleapis.com) is not enabled for the deployment project. " +
            "Enable it, then retry automatic deployer setup.",
        );
      }

      // testIamPermissions is useful for UI hints but Google documents that it
      // can fail open. Prove Cloud DNS against a real project collection and,
      // when one exists, a real managed zone. A fabricated resource name can
      // produce an authorization-shaped false negative before Google resolves
      // resource existence, which blocked a correctly configured live project.
      try {
        const zones = await this.transport.requestJson(
          "GET",
          `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones`,
          { params: { maxResults: 1 } },
        );
        const listed = zones.payload.managedZones;
        if (listed !== undefined && !Array.isArray(listed)) {
          throw new ConnectionError(
            "deployer-dns-response-invalid",
            "Cloud DNS returned a malformed managed-zone list.",
          );
        }
        const first = Array.isArray(listed) ? listed[0] : undefined;
        if (first !== undefined) {
          if (typeof first !== "object" || first === null || Array.isArray(first)) {
            throw new ConnectionError(
              "deployer-dns-response-invalid",
              "Cloud DNS returned a malformed managed-zone entry.",
            );
          }
          const zoneName = (first as Record<string, unknown>).name;
          if (
            typeof zoneName !== "string" ||
            !/^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$/.test(zoneName)
          ) {
            throw new ConnectionError(
              "deployer-dns-response-invalid",
              "Cloud DNS returned an invalid managed-zone identity.",
            );
          }
          const zone = await this.transport.requestJson(
            "GET",
            `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones/` +
              encodeURIComponent(zoneName),
          );
          if (zone.payload.name !== zoneName) {
            throw new ConnectionError(
              "deployer-dns-response-invalid",
              "Cloud DNS returned an unexpected managed-zone identity.",
            );
          }
        }
      } catch (error) {
        throw dnsReadinessError(error);
      }
    }
    return {
      provider: "google_cloud",
      status: "connected",
      principal_hint: this.options.principalHint,
      resource_id: projectId,
      credential_kind: this.options.credentialKind,
      access_policy_id: await this.discoverAccessPolicyId(projectId),
      read_only: true,
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
    const customerKey = customerId.trim();
    if (customerKey === "" || /[/?#]/.test(customerKey)) {
      throw new ConnectionError(
        "workspace-customer-invalid",
        "The Workspace customer key is invalid",
      );
    }
    const { payload: customer } = await this.transport.requestJson(
      "GET",
      `${ADMIN}/customers/${encodeURIComponent(customerKey)}`,
    );
    const canonicalCustomerId = customer.id;
    if (
      typeof canonicalCustomerId !== "string" ||
      !/^C[0-9A-Za-z]+$/.test(canonicalCustomerId)
    ) {
      throw new ConnectionError(
        "workspace-customer-identity-invalid",
        "Google Directory did not return a canonical Workspace customer ID",
      );
    }
    if (targetOuId && !/^[0-9A-Za-z_-]+$/.test(targetOuId)) {
      throw new ConnectionError(
        "workspace-ou-invalid",
        "The Workspace organizational unit ID is invalid",
      );
    }
    await this.transport.requestJson(
      "GET",
      `https://chromepolicy.googleapis.com/v1/customers/${canonicalCustomerId}/policySchemas`,
      { params: { pageSize: 1 } },
    );
    if (targetOuId) {
      await this.transport.requestJson(
        "POST",
        `https://chromepolicy.googleapis.com/v1/customers/${canonicalCustomerId}/policies:resolve`,
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
      resource_id: canonicalCustomerId,
      credential_kind: this.options.credentialKind,
      access_policy_id: null,
      read_only: true,
    };
  }

  async listOrganizationalUnits(customerId: string): Promise<SetupOption[]> {
    const { payload } = await this.transport.requestJson(
      "GET",
      `${ADMIN}/customer/${customerId}/orgunits`,
      { params: { type: "all_including_parent" } },
    );
    if (payload.organizationUnits !== undefined && !Array.isArray(payload.organizationUnits)) {
      throw new ConnectionError(
        "catalog-response-invalid",
        "Google returned an invalid organizational-unit catalogue",
      );
    }
    const units = (payload.organizationUnits ?? []) as unknown[];
    const options: SetupOption[] = [];
    for (const item of units) {
      if (item === null || typeof item !== "object" || Array.isArray(item)) {
        throw new ConnectionError(
          "catalog-response-invalid",
          "Google returned a malformed organizational-unit item",
        );
      }
      const record = item as Record<string, unknown>;
      const rawId = record.orgUnitId;
      const path = record.orgUnitPath;
      if (typeof rawId !== "string" || rawId === "" || typeof path !== "string" || path === "") {
        throw new ConnectionError(
          "catalog-response-invalid",
          "Google returned an invalid organizational-unit identity",
        );
      }
      // Root-scoped Chrome policies affect the entire Workspace domain.
      if (path === "/") continue;
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
    const seenPageTokens = new Set<string>();
    let complete = false;
    for (let pageIndex = 0; pageIndex < MAX_CATALOG_PAGES; pageIndex += 1) {
      const params: Record<string, string | number> = {
        customer: customerId,
        maxResults: 200,
        orderBy: "email",
      };
      if (pageToken) params.pageToken = pageToken;
      const { payload } = await this.transport.requestJson("GET", `${ADMIN}/groups`, {
        params,
      });
      if (payload.groups !== undefined && !Array.isArray(payload.groups)) {
        throw new ConnectionError(
          "catalog-response-invalid",
          "Google returned an invalid Directory group catalogue",
        );
      }
      const groups = (payload.groups ?? []) as unknown[];
      for (const item of groups) {
        if (item === null || typeof item !== "object" || Array.isArray(item)) {
          throw new ConnectionError(
            "catalog-response-invalid",
            "Google returned a malformed Directory group item",
          );
        }
        const record = item as Record<string, unknown>;
        const email = record.email;
        if (typeof email !== "string" || email === "") {
          throw new ConnectionError(
            "catalog-response-invalid",
            "Google returned an invalid Directory group identity",
          );
        }
        options.push({
          value: email.toLowerCase(),
          label: String(record.name ?? email),
          description: email.toLowerCase(),
        });
      }
      const next = nextCatalogPageToken(payload, seenPageTokens, "Directory group");
      assertCatalogLimit(options.length, next !== null, "Directory group");
      if (next === null) {
        complete = true;
        break;
      }
      pageToken = next;
    }
    if (!complete) {
      throw new ConnectionError(
        "catalog-pagination-incomplete",
        "Google Directory group catalogue pagination did not complete",
      );
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
    const resolved = await this.resolveAccessPolicy(projectId);
    if (resolved === null) return [];

    const levels = await this.listCollection(
      `${ACM}/${resolved.name}/accessLevels`,
      "accessLevels",
      { pageSize: 100 },
    );
    const options: SetupOption[] = [];
    for (const level of levels) {
      const name = level.name;
      const title = level.title;
      if (typeof name !== "string" || name === "" || typeof title !== "string" || title === "") {
        throw new ConnectionError(
          "catalog-response-invalid",
          "Google returned an invalid Access Context Manager level",
        );
      }
      options.push({ value: name, label: title, description: String(level.description ?? "") });
    }
    return options.sort((a, b) =>
      a.label.toLowerCase().localeCompare(b.label.toLowerCase()),
    );
  }

  /** List VPCs owned by the selected deployment project for Step 3. */
  async listVpcNetworks(projectId: string): Promise<SetupOption[]> {
    if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) {
      throw new ConnectionError(
        "project-id-invalid",
        "The Google Cloud project id is invalid",
      );
    }
    const networks = await this.listCollection(
      `${COMPUTE}/projects/${encodeURIComponent(projectId)}/global/networks`,
      "items",
      { maxResults: 500 },
    );
    const options: SetupOption[] = [];
    for (const network of networks) {
      const name = network.name;
      const selfLink = network.selfLink;
      if (
        typeof name !== "string" ||
        !/^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$/.test(name) ||
        typeof selfLink !== "string" ||
        !selfLink.endsWith(`/projects/${projectId}/global/networks/${name}`)
      ) {
        throw new ConnectionError(
          "catalog-response-invalid",
          "Google returned an invalid VPC network catalogue item",
        );
      }
      options.push({
        value: name,
        label: name,
        description: network.autoCreateSubnetworks === true
          ? "Auto mode VPC"
          : "Custom mode VPC",
      });
    }
    return options.sort((left, right) => left.label.localeCompare(right.label));
  }

  /** Resolve the public Debian 12 family to the immutable image used by PoC sample VMs. */
  async recommendedPocSourceImage(): Promise<SetupOption> {
    const { payload } = await this.transport.requestJson(
      "GET",
      `${COMPUTE}/projects/debian-cloud/global/images/family/debian-12`,
    );
    const id = payload.id;
    const name = payload.name;
    const selfLink = payload.selfLink;
    if (
      typeof id !== "string" || !/^[1-9][0-9]*$/.test(id) ||
      typeof name !== "string" || !/^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$/.test(name) ||
      selfLink !==
        `https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/${name}` ||
      payload.status !== "READY" ||
      payload.deprecated !== undefined
    ) {
      throw new ConnectionError(
        "poc-source-image-invalid",
        "Google did not return a ready immutable Debian 12 image for the PoC sample VM",
      );
    }
    return {
      value: `projects/debian-cloud/global/images/${name}`,
      label: `Google Debian 12 — ${name}`,
      description: `Immutable public PoC image · numeric ID ${id}`,
    };
  }

  /**
   * Resolve and validate the project's Access Context Manager policy.
   *
   * Before bootstrap the administrator discovers the id. Afterwards the
   * persisted id lets the deployer use its policy-scoped Reader grant without
   * needing organization-level `accessPolicies.list`.
   */
  async discoverAccessPolicyId(projectId: string): Promise<string | null> {
    return (await this.resolveAccessPolicy(projectId))?.id ?? null;
  }

  private async resolveAccessPolicy(
    projectId: string,
  ): Promise<{ id: string; name: string; organization: string } | null> {
    let context: ProjectPolicyContext;
    try {
      context = await projectPolicyContext(this.transport, projectId);
    } catch (error) {
      if (
        error instanceof ConnectionError &&
        error.code === "project-not-in-organization"
      ) {
        return null;
      }
      throw error;
    }

    let accessPolicyId = this.options.accessPolicyId?.trim();
    if (accessPolicyId !== undefined && !/^\d+$/.test(accessPolicyId)) {
      throw new ConnectionError(
        "access-policy-id-invalid",
        "The Access Context Manager policy id must contain digits only",
      );
    }
    if (!accessPolicyId) {
      const policies = await this.listCollection(
        `${ACM}/accessPolicies`,
        "accessPolicies",
        { parent: context.organization, pageSize: 100 },
      );
      if (policies.length === 0) return null;
      const applicable: Array<{ id: string; name: string }> = [];
      for (const policy of policies) {
        const rawName = policy.name;
        const match = typeof rawName === "string"
          ? /^accessPolicies\/(\d+)$/.exec(rawName)
          : null;
        if (match === null || policy.parent !== context.organization) {
          throw new ConnectionError(
            "access-policy-response-invalid",
            "Google returned an invalid Access Context Manager policy",
          );
        }
        const scopes = accessPolicyScopes(policy);
        if (
          scopes.length === 0 ||
          scopes.some((scope) => context.applicableScopes.has(scope))
        ) {
          applicable.push({ id: match[1], name: rawName as string });
        }
      }
      if (applicable.length === 0) {
        throw new ConnectionError(
          "access-policy-scope-mismatch",
          "No Access Context Manager policy in the organization applies to this project",
        );
      }
      if (applicable.length > 1) {
        throw new ConnectionError(
          "access-policy-selection-required",
          "More than one Access Context Manager policy applies to this project; configure the intended policy id explicitly",
        );
      }
      accessPolicyId = applicable[0].id;
    }

    const name = `accessPolicies/${accessPolicyId}`;
    const { payload: policy } = await this.transport.requestJson(
      "GET",
      `${ACM}/${name}`,
    );
    assertApplicableAccessPolicy(policy, name, context);
    return { id: accessPolicyId, name, organization: context.organization };
  }

  private async listCollection(
    url: string,
    collection: string,
    params: Record<string, string | number>,
  ): Promise<Record<string, unknown>[]> {
    const items: Record<string, unknown>[] = [];
    let pageToken = "";
    const seenPageTokens = new Set<string>();
    let complete = false;
    for (let pageIndex = 0; pageIndex < MAX_CATALOG_PAGES; pageIndex += 1) {
      const request = { ...params };
      if (pageToken) request.pageToken = pageToken;
      const { payload } = await this.transport.requestJson("GET", url, { params: request });
      const page = payload[collection];
      if (page !== undefined && !Array.isArray(page)) {
        throw new ConnectionError(
          "catalog-response-invalid",
          `Google returned an invalid ${collection} catalogue`,
        );
      }
      if (Array.isArray(page)) {
        for (const item of page) {
          if (item === null || typeof item !== "object" || Array.isArray(item)) {
            throw new ConnectionError(
              "catalog-response-invalid",
              `Google returned a malformed ${collection} item`,
            );
          }
          items.push(item as Record<string, unknown>);
        }
      }
      const next = nextCatalogPageToken(payload, seenPageTokens, collection);
      assertCatalogLimit(items.length, next !== null, collection);
      if (next === null) {
        complete = true;
        break;
      }
      pageToken = next;
    }
    if (!complete) {
      throw new ConnectionError(
        "catalog-pagination-incomplete",
        `Google ${collection} catalogue pagination did not complete`,
      );
    }
    return items;
  }
}

export async function ensureManagedChromeAccessLevel(
  transport: Transport,
  projectId: string,
  kind: "profile" | "browser" | "any",
  configuredAccessPolicyId?: string,
): Promise<string> {
  return (
    await ensureManagedChromeAccessLevelDetailed(
      transport,
      projectId,
      kind,
      configuredAccessPolicyId,
    )
  ).name;
}

export interface ManagedChromeAccessLevelResult {
  name: string;
  created: boolean;
}

function isExactManagedChromeAccessLevel(
  payload: Record<string, unknown>,
  expected: {
    name: string;
    title: string;
    description: string;
    expression: string;
  },
): boolean {
  const custom = payload.custom;
  const customRecord = typeof custom === "object" && custom !== null && !Array.isArray(custom)
    ? custom as Record<string, unknown>
    : undefined;
  const expr = customRecord?.expr;
  const exprRecord = typeof expr === "object" && expr !== null && !Array.isArray(expr)
    ? expr as Record<string, unknown>
    : undefined;
  return payload.name === expected.name &&
    payload.title === expected.title &&
    payload.description === expected.description &&
    payload.basic === undefined &&
    customRecord !== undefined &&
    Object.keys(customRecord).length === 1 &&
    Object.hasOwn(customRecord, "expr") &&
    exprRecord !== undefined &&
    Object.keys(exprRecord).length === 1 &&
    Object.hasOwn(exprRecord, "expression") &&
    exprRecord.expression === expected.expression;
}

export async function ensureManagedChromeAccessLevelDetailed(
  transport: Transport,
  projectId: string,
  kind: "profile" | "browser" | "any",
  configuredAccessPolicyId?: string,
): Promise<ManagedChromeAccessLevelResult> {
  const ACM = "https://accesscontextmanager.googleapis.com/v1";
  const context = await projectPolicyContext(transport, projectId);

  let accessPolicyId = configuredAccessPolicyId?.trim() || undefined;
  if (accessPolicyId !== undefined && !/^\d+$/.test(accessPolicyId)) {
    throw new ConnectionError(
      "access-policy-id-invalid",
      "The Access Context Manager policy id must contain digits only",
    );
  }
  if (accessPolicyId === undefined) {
    const policies = await listAccessPolicies(transport, context.organization);
    const applicable: string[] = [];
    for (const policy of policies) {
      const name = policy.name;
      const match = typeof name === "string"
        ? /^accessPolicies\/(\d+)$/.exec(name)
        : null;
      if (match === null || policy.parent !== context.organization) {
        throw new ConnectionError(
          "access-policy-response-invalid",
          "Google returned an invalid Access Context Manager policy",
        );
      }
      const scopes = accessPolicyScopes(policy);
      if (
        scopes.length === 0 ||
        scopes.some((scope) => context.applicableScopes.has(scope))
      ) {
        applicable.push(match[1]);
      }
    }
    if (applicable.length === 1) {
      accessPolicyId = applicable[0];
    } else if (applicable.length > 1) {
      throw new ConnectionError(
        "access-policy-selection-required",
        "More than one Access Context Manager policy applies to this project; configure the intended policy id explicitly",
      );
    } else if (policies.length > 0) {
      throw new ConnectionError(
        "access-policy-scope-mismatch",
        "No Access Context Manager policy in the organization applies to this project",
      );
    }
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
  const { payload: policy } = await transport.requestJson(
    "GET",
    `${ACM}/${policyName}`,
  );
  assertApplicableAccessPolicy(policy, policyName, context);
  const levelNameSuffix =
    kind === "profile"
      ? "secgw_profile_managed"
      : kind === "browser"
      ? "secgw_browser_managed"
      : "secgw_chrome_managed";
  const fullName = `${policyName}/accessLevels/${levelNameSuffix}`;

  const title =
    kind === "profile"
      ? "Managed Chrome Profile (SGS)"
      : kind === "browser"
      ? "Managed Chrome Browser (SGS)"
      : "Managed Chrome Profile or Browser (SGS)";
  const description = "Created automatically by Secure Gateway Studio";
  const expression =
    kind === "profile"
      ? "device.chrome.management_state == ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED"
      : kind === "browser"
      ? "device.chrome.management_state == ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED"
      : "device.chrome.management_state in [ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED, ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]";

  // Check if it already exists. Only exact NOT_FOUND permits creation; a 403
  // or disabled API must remain visible to the caller.
  const existing = await transport.requestJson("GET", `${ACM}/${fullName}`, {
    acceptedStatuses: [404],
  });
  if (existing.status !== 404) {
    if (!isExactManagedChromeAccessLevel(existing.payload, {
      name: fullName,
      title,
      description,
      expression,
    })) {
      throw new ConnectionError(
        "access-level-reserved-name-conflict",
        `Reserved managed Chrome Access Level ${fullName} exists with an unexpected definition`,
      );
    }
    return { name: fullName, created: false };
  }

  // Create it with the standard CEL expression.

  const { payload: operation } = await transport.requestJson(
    "POST",
    `${ACM}/${policyName}/accessLevels`,
    {
      jsonBody: {
        name: fullName,
        title,
        description,
        custom: {
          expr: { expression },
        },
      },
    },
  );

  // Access Context Manager creates return a long-running Operation. Do not
  // bind a level into IAM until the operation and a confirming GET succeed.
  const operationName = operation.name;
  const expectedOperation = new RegExp(
    `^${fullName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/create/[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`,
  );
  if (typeof operationName !== "string" || !expectedOperation.test(operationName)) {
    throw new ConnectionError(
      "access-level-create-operation-invalid",
      `Google returned an invalid create operation for ${fullName}`,
    );
  }
  let current = operation;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (
      current.name !== operationName ||
      (current.done !== undefined && typeof current.done !== "boolean") ||
      (current.error !== undefined &&
        (typeof current.error !== "object" || current.error === null || Array.isArray(current.error)))
    ) {
      throw new ConnectionError(
        "access-level-create-operation-invalid",
        `Google returned an invalid create operation for ${fullName}`,
      );
    }
    if (current.done === true) {
      if (current.error !== undefined) {
        throw new ConnectionError(
          "access-level-create-failed",
          `Google rejected managed Chrome Access Level ${fullName}`,
        );
      }
      break;
    }
    if (attempt === 59) {
      throw new ConnectionError(
        "access-level-create-timeout",
        `Timed out creating managed Chrome Access Level ${fullName}`,
      );
    }
    if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, 1_000));
    const polled = await transport.requestJson("GET", `${ACM}/${operationName}`);
    current = polled.payload;
  }

  const confirmed = await transport.requestJson("GET", `${ACM}/${fullName}`);
  if (!isExactManagedChromeAccessLevel(confirmed.payload, {
    name: fullName,
    title,
    description,
    expression,
  })) {
    throw new ConnectionError(
      "access-level-verification-failed",
      `Managed Chrome Access Level ${fullName} did not match the approved definition after creation`,
    );
  }

  return { name: fullName, created: true };
}
