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

import { canonicalDigestSync, canonicalJson } from "../domain/canonical.ts";
import {
  GoogleApiError,
  isCompatibleBeyondCorpApplicationPayload,
  isCompatibleSecurityGatewayPayload,
  resourceUrlForChange,
  type Transport,
} from "./executor.ts";
import { networkName, subnetName } from "./executor-path-a.ts";
import { validateLicenseAssignment } from "./licensing.ts";
import {
  configurationHash,
  requiredApis,
  requiredPermissions,
  type DiscoverySnapshot,
  type SourceImageBinding,
} from "../domain/planner.ts";
import { serviceAccountEmail, serviceAccountId } from "../domain/naming.ts";
import { isCreatedSharedDefaultGateway } from "../domain/teardown.ts";
import {
  applicationHostname,
  applicationPort,
  upstreamProjectId,
  type DeploymentSpec,
} from "../domain/spec.ts";
import {
  CertificateError,
  crc32c,
  validatePublicCertificateAccessResponse,
  type ValidatedPublicCertificateSecret,
} from "./certificates.ts";
import { offloadStartupScript, sampleBackendStartupScript } from "./startup-scripts.ts";
export { crc32c } from "./certificates.ts";

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

const COMPUTE = "https://compute.googleapis.com/compute/v1";
const SECURE_GATEWAY_SOURCE_RANGE = "136.124.16.0/20";
const GOOGLE_HEALTH_CHECK_SOURCE_RANGES = ["35.191.0.0/16", "130.211.0.0/22"] as const;
const OWNERSHIP_DESCRIPTION_PREFIX = "Secure Gateway Studio ownership-token=";
const MANAGED_CHROME_ACCESS_LEVEL_EXPRESSIONS = new Set([
  "device.chrome.management_state == ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED",
  "device.chrome.management_state == ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED",
  "device.chrome.management_state in [ChromeManagementState.CHROME_MANAGEMENT_STATE_BROWSER_MANAGED, ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED]",
]);
const MAX_CHROME_POLICY_RESOLVE_PAGES = 20;
const MAX_CHROME_POLICY_RESOLVE_ITEMS = 2_000;

function isChromePolicyUnmanagedAppInternalError(error: unknown): boolean {
  if (!(error instanceof GoogleApiError) || error.status < 500 || error.status >= 600) {
    return false;
  }
  const detail = error.payload.error;
  const googleStatus = typeof detail === "object" && detail !== null && !Array.isArray(detail)
    ? (detail as Record<string, unknown>).status
    : null;
  return googleStatus === "INTERNAL" || /internal error encountered/i.test(error.message);
}

async function listChromeResolvedPolicies(
  transport: Transport,
  customer: string,
  request: {
    policySchemaFilter: string;
    policyTargetKey: Record<string, unknown>;
  },
): Promise<Record<string, unknown>[]> {
  const policies: Record<string, unknown>[] = [];
  const seenPageTokens = new Set<string>();
  let pageToken: string | undefined;
  for (let page = 0; page < MAX_CHROME_POLICY_RESOLVE_PAGES; page += 1) {
    const { payload } = await transport.requestJson(
      "POST",
      `https://chromepolicy.googleapis.com/v1/customers/${customer}/policies:resolve`,
      {
        jsonBody: {
          ...request,
          pageSize: 1_000,
          ...(pageToken === undefined ? {} : { pageToken }),
        },
      },
    );
    const resolvedPolicies = payload.resolvedPolicies === undefined
      ? []
      : payload.resolvedPolicies;
    if (!Array.isArray(resolvedPolicies)) {
      throw new Error("Chrome Policy resolve response is missing resolvedPolicies");
    }
    for (const item of resolvedPolicies) {
      if (item === null || typeof item !== "object" || Array.isArray(item)) {
        throw new Error("Chrome Policy resolve response contains a malformed policy");
      }
      policies.push(item as Record<string, unknown>);
    }
    if (policies.length > MAX_CHROME_POLICY_RESOLVE_ITEMS) {
      throw new Error("Chrome Policy resolve response exceeded the item safety limit");
    }
    const next = payload.nextPageToken;
    if (next === undefined || next === "") return policies;
    if (typeof next !== "string" || seenPageTokens.has(next)) {
      throw new Error("Chrome Policy resolve returned an invalid page token");
    }
    seenPageTokens.add(next);
    if (page + 1 >= MAX_CHROME_POLICY_RESOLVE_PAGES) {
      throw new Error("Chrome Policy resolve pagination did not complete");
    }
    pageToken = next;
  }
  throw new Error("Chrome Policy resolve pagination did not complete");
}

function chromePolicySourceResource(value: unknown, label: string): string | null {
  if (value === undefined) return null;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} is malformed`);
  }
  const key = value as Record<string, unknown>;
  // Empty protobuf message fields can be serialized as `{}`. For output-only
  // provenance keys this has the same meaning as an omitted key: no explicit
  // source was reported. Non-empty malformed keys still fail closed below.
  if (Object.keys(key).length === 0) return null;
  if (!Object.keys(key).every((name) => name === "targetResource" || name === "additionalTargetKeys")) {
    throw new Error(`${label} contains unexpected fields`);
  }
  const targetResource = key.targetResource;
  if (
    typeof targetResource !== "string" ||
    !/^(?:orgunits|groups)\/[A-Za-z0-9_-]+$/.test(targetResource)
  ) {
    throw new Error(`${label} has an invalid targetResource`);
  }
  if ("additionalTargetKeys" in key) {
    const additional = key.additionalTargetKeys;
    if (
      typeof additional !== "object" || additional === null || Array.isArray(additional) ||
      Object.keys(additional as Record<string, unknown>).length !== 0
    ) {
      throw new Error(`${label} has unexpected additionalTargetKeys`);
    }
  }
  return targetResource;
}
function validateChromePolicyTargetKey(
  value: unknown,
  expected: Record<string, unknown>,
  label: string,
): void {
  if (
    typeof value !== "object" || value === null || Array.isArray(value) ||
    canonicalJson(value) !== canonicalJson(expected)
  ) {
    throw new Error(`${label} does not match the requested policy target`);
  }
}

/**
 * Chrome Policy may return an internal error when an app-specific resolve
 * names an app that has not yet been added for management. Google's supported
 * aggregate form omits additionalTargetKeys and returns every entity for the
 * schema. Validate that response strictly, then keep only the requested app.
 */
function chromePoliciesForApp(
  policies: Record<string, unknown>[],
  targetResource: string,
  appId: string,
  label: string,
): Record<string, unknown>[] {
  const expectedAppId = `chrome:${appId}`;
  return policies.filter((policy) => {
    const rawTarget = policy.targetKey;
    if (typeof rawTarget !== "object" || rawTarget === null || Array.isArray(rawTarget)) {
      throw new Error(`${label} has a malformed targetKey`);
    }
    const target = rawTarget as Record<string, unknown>;
    if (
      !Object.keys(target).every(
        (name) => name === "targetResource" || name === "additionalTargetKeys",
      ) ||
      target.targetResource !== targetResource
    ) {
      throw new Error(`${label} has an unexpected target resource`);
    }
    const rawAdditional = target.additionalTargetKeys;
    if (
      typeof rawAdditional !== "object" || rawAdditional === null ||
      Array.isArray(rawAdditional)
    ) {
      throw new Error(`${label} is missing app_id`);
    }
    const additional = rawAdditional as Record<string, unknown>;
    if (
      Object.keys(additional).length !== 1 ||
      typeof additional.app_id !== "string" ||
      additional.app_id.trim() === ""
    ) {
      throw new Error(`${label} has an invalid app_id`);
    }
    return additional.app_id === expectedAppId;
  });
}

function compatibleRoutingConfig(value: unknown): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const config = value as Record<string, unknown>;
  const allowed = new Set([
    "routingMode",
    "bgpBestPathSelectionMode",
    "bgpInterRegionCost",
    "bgpAlwaysCompareMed",
    "effectiveBgpInterRegionCost",
    "effectiveBgpAlwaysCompareMed",
  ]);
  return Object.keys(config).every((key) => allowed.has(key)) &&
    config.routingMode === "REGIONAL" &&
    (config.bgpBestPathSelectionMode === undefined ||
      config.bgpBestPathSelectionMode === "LEGACY") &&
    (config.bgpInterRegionCost === undefined || config.bgpInterRegionCost === "DEFAULT") &&
    (config.effectiveBgpInterRegionCost === undefined ||
      config.effectiveBgpInterRegionCost === "DEFAULT") &&
    (config.bgpAlwaysCompareMed === undefined || config.bgpAlwaysCompareMed === false) &&
    (config.effectiveBgpAlwaysCompareMed === undefined ||
      config.effectiveBgpAlwaysCompareMed === false);
}

function compatibleFixedOrPercent(
  value: unknown,
  expectedFixed: number,
): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const setting = value as Record<string, unknown>;
  return Object.keys(setting).every((key) => key === "fixed" || key === "calculated") &&
    setting.fixed === expectedFixed &&
    (setting.calculated === undefined || setting.calculated === expectedFixed);
}

function compatibleMigUpdatePolicy(value: unknown): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const policy = value as Record<string, unknown>;
  const allowed = new Set([
    "type",
    "minimalAction",
    "maxSurge",
    "maxUnavailable",
    "replacementMethod",
    "mostDisruptiveAllowedAction",
    "instanceRedistributionType",
    "minReadySec",
  ]);
  return Object.keys(policy).every((key) => allowed.has(key)) &&
    policy.type === "PROACTIVE" && policy.minimalAction === "REPLACE" &&
    compatibleFixedOrPercent(policy.maxSurge, 2) &&
    compatibleFixedOrPercent(policy.maxUnavailable, 0) &&
    (policy.replacementMethod === undefined || policy.replacementMethod === "SUBSTITUTE") &&
    (policy.mostDisruptiveAllowedAction === undefined ||
      policy.mostDisruptiveAllowedAction === "REPLACE") &&
    (policy.instanceRedistributionType === undefined ||
      policy.instanceRedistributionType === "PROACTIVE") &&
    (policy.minReadySec === undefined || policy.minReadySec === 0);
}

export function isCanonicalManagedChromeAccessLevel(
  payload: Record<string, unknown>,
): boolean {
  if (payload.basic !== undefined) return false;
  const custom = payload.custom;
  if (typeof custom !== "object" || custom === null || Array.isArray(custom)) return false;
  const customRecord = custom as Record<string, unknown>;
  if (Object.keys(customRecord).length !== 1 || !("expr" in customRecord)) return false;
  const expr = customRecord.expr;
  if (typeof expr !== "object" || expr === null || Array.isArray(expr)) return false;
  const exprRecord = expr as Record<string, unknown>;
  const allowed = new Set(["expression", "title", "description", "location"]);
  return Object.keys(exprRecord).every((field) => allowed.has(field)) &&
    typeof exprRecord.expression === "string" &&
    ["title", "description", "location"].every(
      (field) => exprRecord[field] === undefined || typeof exprRecord[field] === "string",
    ) &&
    MANAGED_CHROME_ACCESS_LEVEL_EXPRESSIONS.has(exprRecord.expression);
}
export interface DiscoveryOwnershipProof {
  marker: string | null;
  providerIdentityField?: string;
  providerIdentity?: string;
}

export type DiscoveryOwnershipProofs = Readonly<Record<string, DiscoveryOwnershipProof>>;

function validGenericOwnershipCheckpoint(
  record: Record<string, unknown>,
  checkpoint: Record<string, unknown>,
  spec: DeploymentSpec,
): boolean {
  const resourceKey = record.resourceKey;
  const provider = record.provider;
  const resourceType = record.resourceType;
  const resourceName = record.resourceName;
  const requestId = record.requestId;
  if (
    typeof resourceKey !== "string" || typeof provider !== "string" ||
    typeof resourceType !== "string" || typeof resourceName !== "string" ||
    typeof requestId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      .test(requestId) ||
    checkpoint.kind !== "generic_created_resource" || checkpoint.protocolVersion !== 2 ||
    checkpoint.phase !== "applied" || checkpoint.resourceKey !== resourceKey ||
    checkpoint.createRequestId !== requestId ||
    typeof checkpoint.expectedParamsDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(checkpoint.expectedParamsDigest) ||
    typeof checkpoint.expectedPayloadDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(checkpoint.expectedPayloadDigest)
  ) return false;
  const expectedUrl = provider === "beyondcorp" && resourceType === "security_gateway"
    ? `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
      `/locations/global/securityGateways/${spec.gateway_id}`
    : resourceUrlForChange(
      { provider, resource_type: resourceType, resource_name: resourceName },
      spec,
    );
  if (
    expectedUrl === null || checkpoint.resourceUrl !== expectedUrl ||
    checkpoint.createUrl !== expectedUrl.slice(0, expectedUrl.lastIndexOf("/"))
  ) return false;
  const expectedParams: Record<string, string> = { requestId };
  if (provider === "beyondcorp" && resourceType === "security_gateway") {
    expectedParams.securityGatewayId = resourceName;
  } else if (provider === "beyondcorp" && resourceType === "application") {
    expectedParams.applicationId = resourceName;
  }
  if (checkpoint.expectedParamsDigest !== canonicalDigestSync(expectedParams)) return false;
  if (provider === "compute") {
    return typeof checkpoint.ownershipMarker === "string" &&
      checkpoint.ownershipMarker.startsWith(
        `Secure Gateway Studio ownership-token=${requestId}`,
      );
  }
  if (provider !== "beyondcorp" || checkpoint.ownershipMarker !== null) return false;
  const expectedBody = resourceType === "security_gateway"
    ? { displayName: resourceName, serviceDiscovery: {}, logging: {} }
    : resourceType === "application"
    ? {
      displayName: resourceName,
      endpointMatchers: [{
        hostname: applicationHostname(spec),
        ports: [applicationPort(spec)],
      }],
      upstreams: [{
        network: {
          name: `projects/${upstreamProjectId(spec)}/global/networks/${networkName(spec)}`,
        },
        ...(spec.application_egress_region === null
          ? {}
          : { egressPolicy: { regions: [spec.application_egress_region] } }),
      }],
    }
    : null;
  return expectedBody !== null &&
    checkpoint.expectedPayloadDigest === canonicalDigestSync(expectedBody) &&
    checkpoint.providerIdentityField === "createTime" &&
    typeof checkpoint.providerIdentity === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/
      .test(checkpoint.providerIdentity);
}

/** Reduce encrypted durable inventory rows to the provider proof discovery needs. */
export function discoveryOwnershipProofs(
  records: readonly Record<string, unknown>[],
  spec: DeploymentSpec,
): Record<string, DiscoveryOwnershipProof> {
  const proofs: Record<string, DiscoveryOwnershipProof> = {};
  const ambiguous = new Set<string>();
  const addProof = (key: string, proof: DiscoveryOwnershipProof): void => {
    if (ambiguous.has(key)) return;
    const current = proofs[key];
    if (current !== undefined && canonicalJson(current) !== canonicalJson(proof)) {
      delete proofs[key];
      ambiguous.add(key);
      return;
    }
    proofs[key] = proof;
  };
  for (const record of records) {
    if (typeof record.resourceKey !== "string") continue;
    const before = record.beforeImage;
    if (typeof before !== "object" || before === null || Array.isArray(before)) continue;
    const checkpoint = before as Record<string, unknown>;
    const createdSharedGateway = isCreatedSharedDefaultGateway({
      resourceKey: record.resourceKey,
      provider: String(record.provider ?? ""),
      resourceType: String(record.resourceType ?? ""),
      resourceName: String(record.resourceName ?? ""),
      owned: record.owned === true,
      shared: record.shared === true,
      beforeImage: checkpoint,
      requestId: typeof record.requestId === "string" ? record.requestId : undefined,
    });
    if (record.owned !== true && !createdSharedGateway) continue;
    if (
      checkpoint.kind === "generic_created_resource" && checkpoint.phase === "applied" &&
      validGenericOwnershipCheckpoint(record, checkpoint, spec) &&
      (checkpoint.ownershipMarker === null || typeof checkpoint.ownershipMarker === "string") &&
      typeof checkpoint.providerIdentityField === "string" &&
      typeof checkpoint.providerIdentity === "string"
    ) {
      if (
        record.resourceKey.startsWith("beyondcorp:") &&
        checkpoint.providerIdentityField !== "createTime"
      ) continue;
      addProof(record.resourceKey, {
        marker: checkpoint.ownershipMarker,
        providerIdentityField: checkpoint.providerIdentityField,
        providerIdentity: checkpoint.providerIdentity,
      });
      continue;
    }
    if (
      checkpoint.kind === "named_resource_ownership" &&
      checkpoint.protocolVersion === 1 && checkpoint.phase === "applied" &&
      typeof checkpoint.marker === "string"
    ) {
      addProof(record.resourceKey, { marker: checkpoint.marker });
      continue;
    }
    if (
      checkpoint.kind === "router_nats" ||
      (checkpoint.kind === "secret_iam" && checkpoint.phase === "applied")
    ) {
      addProof(record.resourceKey, { marker: null });
      continue;
    }
    if (
      checkpoint.kind === "secret_version" && checkpoint.phase === "applied" &&
      typeof checkpoint.ownershipToken === "string" &&
      typeof checkpoint.versionName === "string"
    ) {
      addProof(record.resourceKey, {
        marker: checkpoint.ownershipToken,
        providerIdentityField: "versionName",
        providerIdentity: checkpoint.versionName,
      });
    }
  }
  return proofs;
}

// These permissions are exercised against the project that owns an existing
// upstream VPC.  Testing only the deployment project can produce a green
// preflight followed by a guaranteed failure while reading the network or
// granting the gateway's delegating account access to it.
const UPSTREAM_PROJECT_PERMISSIONS = new Set([
  "compute.networks.get",
  "compute.networks.use",
  "resourcemanager.projects.get",
  "resourcemanager.projects.getIamPolicy",
  "resourcemanager.projects.setIamPolicy",
]);

export class GoogleDiscoveryProvider {
  private readonly transport: Transport;
  private readonly workspaceTransport: Transport;
  private readonly cloudIdentity: string;
  private readonly ownershipProofs: DiscoveryOwnershipProofs;
  private readonly discoveredAddresses = new Map<string, string>();
  private publicCertificateVersionName: string | undefined;
  private sourceImageBinding: SourceImageBinding | undefined;

  constructor(
    transport: Transport,
    options: {
      cloudIdentity: string;
      workspaceTransport?: Transport;
      ownershipProofs?: DiscoveryOwnershipProofs;
    },
  ) {
    this.transport = transport;
    this.workspaceTransport = options.workspaceTransport ?? transport;
    this.cloudIdentity = options.cloudIdentity;
    this.ownershipProofs = options.ownershipProofs ?? {};
  }

  private ownsManagedResource(
    key: string,
    payload: Record<string, unknown>,
  ): boolean {
    const proof = this.ownershipProofs[key];
    if (proof === undefined) return false;
    if (
      proof.providerIdentityField !== undefined || proof.providerIdentity !== undefined
    ) {
      if (
        typeof proof.providerIdentityField !== "string" ||
        typeof proof.providerIdentity !== "string" ||
        payload[proof.providerIdentityField] !== proof.providerIdentity
      ) return false;
    }
    if (proof.marker === null) return true;
    if (payload.description === proof.marker) return true;
    const labels = stringMap(payload.labels);
    return labels?.["sgs-owner-token"] === proof.marker;
  }

  async preflight(spec: DeploymentSpec): Promise<PreflightResult> {
    this.discoveredAddresses.clear();
    this.publicCertificateVersionName = undefined;
    this.sourceImageBinding = undefined;
    const diagnostics: PreflightDiagnostic[] = [];
    const existing = new Set<string>();
    const conflicting = new Set<string>();
    let enabledApis = new Set<string>();
    let granted = new Set<string>();
    let billingEnabled: boolean | null = null;
    const publicSecretName =
      spec.backend_kind !== "direct_https" &&
      spec.certificate_strategy === "public_trusted" &&
      spec.public_certificate_secret
        ? spec.public_certificate_secret.split("/").pop() ?? null
        : null;
    const publicSecretKey = publicSecretName === null
      ? null
      : `secretmanager:secret:${publicSecretName}`;
    let publicCertificateBinding: ValidatedPublicCertificateSecret | null = null;

    try {
      await this.assertTargetOuIsNonRoot(spec);
    } catch (error) {
      for (const key of [
        `chromepolicy:extension_install:${CHROME_EXTENSIONS.secureEnterpriseBrowser}`,
        `chromepolicy:extension_install:${CHROME_EXTENSIONS.endpointVerification}`,
        `chromepolicy:extension_configuration:${CHROME_EXTENSIONS.secureEnterpriseBrowser}`,
        `chromepolicy:service_discovery_proxy:${spec.target_ou_id}`,
      ]) conflicting.add(key);
      diagnostics.push(this.diagnostic("target-ou-invalid", error));
    }

    try {
      enabledApis = await this.enabledApis(spec.project_id);
      const required = requiredApis(spec);
      if ([...required].every((api) => enabledApis.has(api))) {
        existing.add("serviceusage:project_services:required-apis");
      }
    } catch (error) {
      diagnostics.push(this.diagnostic("service-usage", error));
    }

    const required = requiredPermissions(spec);
    try {
      granted = await this.grantedPermissions(spec.project_id, required);
    } catch (error) {
      diagnostics.push(this.diagnostic("project-permissions", error));
    }

    const upstreamProject = upstreamProjectId(spec);
    if (upstreamProject !== spec.project_id) {
      const upstreamRequired = new Set(
        [...required].filter((permission) => UPSTREAM_PROJECT_PERMISSIONS.has(permission)),
      );
      try {
        const upstreamGranted = await this.grantedPermissions(upstreamProject, upstreamRequired);
        for (const permission of upstreamRequired) {
          if (!upstreamGranted.has(permission)) granted.delete(permission);
        }
      } catch (error) {
        // Fail closed: the flat snapshot cannot express permission scope, so a
        // permission is considered granted only when every project on which it
        // is required confirms it.
        for (const permission of upstreamRequired) granted.delete(permission);
        diagnostics.push(this.diagnostic("upstream-project-permissions", error));
      }
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
        const response = await this.transport.requestJson("GET", probe.url, {
          acceptedStatuses: [404],
        });
        if (response.status === 404) continue;
        if (response.status === 200) {
          if (await this.compatible(probe.key, response.payload, spec)) {
            if (probe.key === publicSecretKey) {
              // Validate and bind the immutable numeric version before later
              // VM/template probes compare their exact startup script.
              if (publicSecretName === null) throw new Error("Public secret identity missing");
              publicCertificateBinding = await this.validatePublicCertificateSecret(
                spec,
                publicSecretName,
              );
              this.publicCertificateVersionName = publicCertificateBinding.versionName;
              existing.add(probe.key);
            } else {
              existing.add(probe.key);
            }
            if (
              probe.key.startsWith("compute:internal_address:") &&
              typeof response.payload.address === "string"
            ) {
              this.discoveredAddresses.set(probe.key, response.payload.address);
            }
            if (probe.key.startsWith("accesscontextmanager:access_level:")) {
              // Reading the level proves the permission the plan requires; the
              // batch permission check cannot see cross-project levels.
              granted.add("accesscontextmanager.accessLevels.get");
            }
          } else {
            conflicting.add(probe.key);
          }
        } else {
          throw new Error(`Unexpected discovery status ${response.status}`);
        }
      } catch (error) {
        // 404 is the only safe proof of absence.  Any unreadable or ambiguous
        // same-name resource must block planning; treating 403/5xx/transport
        // loss as absence would turn the next Apply into a blind CREATE.
        existing.delete(probe.key);
        conflicting.add(probe.key);
        diagnostics.push(this.diagnostic(probe.key, error));
      }
    }

    if (spec.backend_kind !== "direct_https") {
      await this.discoverCloudNat(spec, existing, conflicting, diagnostics);
      await this.discoverManagedSecretVersion(spec, existing, conflicting, diagnostics);
      await this.discoverDnsRecord(spec, existing, conflicting, diagnostics);
    }

    if (!spec.managed_chrome_access_level) {
      granted.add("accesscontextmanager.accessLevels.get");
    }

    await this.discoverIamBindings(spec, existing, conflicting, diagnostics);

    const chrome = await this.discoverChrome(spec, existing, conflicting, diagnostics);

    let privateEgressAvailable: boolean | null = null;
    if (spec.network_strategy === "existing" && spec.backend_kind !== "direct_https") {
      try {
        privateEgressAvailable = await this.existingPrivateEgressAvailable(spec);
      } catch (error) {
        diagnostics.push(this.diagnostic("compute:private-egress", error));
      }
    }

    let globalAccess: boolean | null = null;
    let forwardingRule: string | null = null;
    let globalAccessDiscoveryComplete = true;
    try {
      const resolved = await this.applicationGlobalAccess(spec);
      globalAccess = resolved.allowGlobalAccess;
      forwardingRule = resolved.forwardingRule;
    } catch (error) {
      diagnostics.push(this.diagnostic("compute:forwarding-rule", error));
      globalAccessDiscoveryComplete = false;
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
        private_egress_available: privateEgressAvailable,
        ...chrome,
        application_global_access: globalAccess,
        application_forwarding_rule: forwardingRule,
        application_global_access_discovery_complete: globalAccessDiscoveryComplete,
        public_certificate_binding: publicCertificateBinding === null
          ? null
          : {
              secret_version_name: publicCertificateBinding.versionName,
              payload_sha256: publicCertificateBinding.payloadSha256,
            },
        source_image_binding: this.sourceImageBinding ?? null,
      },
      diagnostics,
    };
  }

  private async assertTargetOuIsNonRoot(spec: DeploymentSpec): Promise<void> {
    const expectedId = spec.target_ou_id;
    const identity = encodeURIComponent(`id:${expectedId}`);
    const { payload } = await this.workspaceTransport.requestJson(
      "GET",
      `https://admin.googleapis.com/admin/directory/v1/customer/${spec.customer_id}` +
        `/orgunits/${identity}`,
    );
    const rawId = payload.orgUnitId;
    const path = payload.orgUnitPath;
    if (
      typeof rawId !== "string" || rawId.replace(/^id:/, "") !== expectedId ||
      typeof path !== "string" || !path.startsWith("/") || path === "/"
    ) {
      throw new Error("The selected organizational unit is missing, stale, or is the Root OU");
    }
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
    conflicting: Set<string>,
    diagnostics: PreflightDiagnostic[],
  ): Promise<void> {
    const members = new Set(spec.principals.map((principal) => `${principal.type}:${principal.value}`));
    const gateway =
      `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
      `/locations/global/securityGateways/${spec.gateway_id}`;

    if (spec.backend_kind !== "direct_https") {
      const secretName =
        spec.certificate_strategy === "public_trusted" && spec.public_certificate_secret
          ? spec.public_certificate_secret.split("/").pop() as string
          : `${spec.name}-tls`;
      await this.probeBinding({
        key: `secretmanager:secret_iam:${spec.name}-tls-accessor`,
        method: "GET",
        url:
          `https://secretmanager.googleapis.com/v1/projects/${spec.project_id}` +
          `/secrets/${secretName}:getIamPolicy`,
        role: "roles/secretmanager.secretAccessor",
        members: new Set([
          `serviceAccount:${serviceAccountEmail(spec.name, spec.project_id, "offload")}`,
        ]),
        existing,
        conflicting,
        diagnostics,
      });
    }

    await this.probeBinding({
      key: `beyondcorp:gateway_iam:${spec.gateway_id}-service-discovery-users`,
      method: "GET",
      url: `${gateway}:getIamPolicy`,
      role: "roles/beyondcorp.serviceDiscoveryUser",
      members,
      existing,
      conflicting,
      diagnostics,
    });

    let gatewayAccount: string | null = null;
    try {
      const response = await this.transport.requestJson("GET", gateway, {
        acceptedStatuses: [404],
      });
      const account = response.payload.delegatingServiceAccount;
      if (response.status === 200) {
        if (typeof account !== "string" || account === "") {
          throw new Error("Gateway response omitted its delegating service-account identity");
        }
        gatewayAccount = account;
      }
    } catch (error) {
      conflicting.add(`beyondcorp:security_gateway:${spec.gateway_id}`);
      conflicting.add(`cloudresourcemanager:project_iam:${spec.name}-upstream-access`);
      diagnostics.push(this.diagnostic("beyondcorp:security_gateway", error));
    }

    if (gatewayAccount !== null) {
      await this.probeBinding({
        key: `cloudresourcemanager:project_iam:${spec.name}-upstream-access`,
        method: "POST",
        url:
          "https://cloudresourcemanager.googleapis.com/v1/projects/" +
          `${upstreamProjectId(spec)}:getIamPolicy`,
        body: {},
        role: "roles/beyondcorp.upstreamAccess",
        members: new Set([`serviceAccount:${gatewayAccount}`]),
        existing,
        conflicting,
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
      conflicting,
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
    conflicting: Set<string>;
    diagnostics: PreflightDiagnostic[];
    condition?: Record<string, string> | null;
    body?: Record<string, unknown>;
  }): Promise<void> {
    try {
      const isPost = options.method === "POST";
      const response = await this.transport.requestJson(options.method, options.url, {
        params: isPost ? undefined : { "options.requestedPolicyVersion": 3 },
        jsonBody: isPost
          ? {
              ...(options.body ?? {}),
              options: { requestedPolicyVersion: 3 },
            }
          : undefined,
        acceptedStatuses: [404],
      });
      if (response.status === 404) return;
      if (response.status !== 200) {
        throw new Error(`Unexpected IAM discovery status ${response.status}`);
      }
      if (typeof response.payload.etag !== "string" || response.payload.etag === "") {
        throw new Error("IAM policy is missing its concurrency etag");
      }
      if (policyHasBinding(response.payload, options.role, options.members, options.condition ?? null)) {
        options.existing.add(options.key);
      }
    } catch (error) {
      options.existing.delete(options.key);
      options.conflicting.add(options.key);
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
    conflicting: Set<string>,
    diagnostics: PreflightDiagnostic[],
  ): Promise<Partial<DiscoverySnapshot>> {
    const workspace = this.workspaceTransport;
    const customer = spec.customer_id;
    const appPolicyCache = new Map<string, Promise<Record<string, unknown>[]>>();
    const resolve = async (
      schema: string,
      appId: string | null,
    ): Promise<{ value: Record<string, unknown> | null; source: string | null }> => {
      const targetKey: Record<string, unknown> = {
        targetResource: `orgunits/${spec.target_ou_id}`,
      };
      if (appId !== null) targetKey.additionalTargetKeys = { app_id: `chrome:${appId}` };
      let policies: Record<string, unknown>[];
      if (appId === null) {
        policies = await listChromeResolvedPolicies(
          workspace,
          customer,
          { policySchemaFilter: schema, policyTargetKey: targetKey },
        );
      } else {
        const cachedAggregate = appPolicyCache.get(schema);
        if (cachedAggregate !== undefined) {
          policies = chromePoliciesForApp(
            await cachedAggregate,
            `orgunits/${spec.target_ou_id}`,
            appId,
            "Chrome Policy aggregate resolve response",
          );
        } else {
          try {
            policies = await listChromeResolvedPolicies(
              workspace,
              customer,
              { policySchemaFilter: schema, policyTargetKey: targetKey },
            );
          } catch (error) {
            if (!isChromePolicyUnmanagedAppInternalError(error)) throw error;
            const aggregate = listChromeResolvedPolicies(
              workspace,
              customer,
              {
                policySchemaFilter: schema,
                policyTargetKey: { targetResource: `orgunits/${spec.target_ou_id}` },
              },
            );
            appPolicyCache.set(schema, aggregate);
            policies = chromePoliciesForApp(
              await aggregate,
              `orgunits/${spec.target_ou_id}`,
              appId,
              "Chrome Policy aggregate resolve response",
            );
          }
        }
      }
      if (policies.length === 0) return { value: null, source: null };
      if (policies.length !== 1) {
        throw new Error("Chrome Policy resolve response contains duplicate policies");
      }
      const item = policies[0];
      if (typeof item !== "object" || item === null || Array.isArray(item)) {
        throw new Error("Chrome Policy resolve response contains a malformed policy");
      }
      const policy = item as Record<string, unknown>;
      validateChromePolicyTargetKey(
        policy.targetKey,
        targetKey,
        "Chrome Policy resolve targetKey",
      );
      const source = chromePolicySourceResource(
        policy.sourceKey,
        "Chrome Policy resolve sourceKey",
      );
      const addedSource = chromePolicySourceResource(
        policy.addedSourceKey,
        "Chrome Policy resolve addedSourceKey",
      );
      if (
        (source !== null && !source.startsWith("orgunits/")) ||
        (addedSource !== null && !addedSource.startsWith("orgunits/"))
      ) {
        throw new Error("Chrome Policy resolve response has an invalid source kind");
      }
      const policyValue = policy.value;
      if (typeof policyValue !== "object" || policyValue === null || Array.isArray(policyValue)) {
        throw new Error("Chrome Policy resolve response has a malformed value");
      }
      const typedPolicyValue = policyValue as Record<string, unknown>;
      if (typedPolicyValue.policySchema !== schema) {
        throw new Error("Chrome Policy resolve response has the wrong policy schema");
      }
      const value = typedPolicyValue.value;
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error("Chrome Policy resolve response has a malformed policy payload");
      }
      return { value: value as Record<string, unknown>, source };
    };

    let secureBrowserInstalled: boolean | null = null;
    let endpointVerificationInstalled: boolean | null = null;
    let secureBrowserVersion: string | null = null;
    let endpointVerificationVersion: string | null = null;
    try {
      const secureInstall = await resolve(
        "chrome.users.apps.InstallType",
        CHROME_EXTENSIONS.secureEnterpriseBrowser,
      );
      if (
        secureInstall.source === `orgunits/${spec.target_ou_id}` &&
        secureInstall.value?.appInstallType === "FORCED"
      ) {
        existing.add(
          `chromepolicy:extension_install:${CHROME_EXTENSIONS.secureEnterpriseBrowser}`,
        );
      }
      const endpointInstall = await resolve(
        "chrome.users.apps.InstallType",
        CHROME_EXTENSIONS.endpointVerification,
      );
      if (
        endpointInstall.source === `orgunits/${spec.target_ou_id}` &&
        endpointInstall.value?.appInstallType === "FORCED"
      ) {
        existing.add(`chromepolicy:extension_install:${CHROME_EXTENSIONS.endpointVerification}`);
      }
      // A legacy PAC policy inherited from a parent OU silently overrides
      // Service Discovery. Anything other than PAC means nothing to change.
      const proxy = await resolve("chrome.users.SimpleProxySettings", null);
      const proxyMode = proxy.value?.simpleProxyMode;
      if (proxy.value !== null && typeof proxyMode !== "string") {
        throw new Error("Chrome proxy policy is missing simpleProxyMode");
      }
      if (proxyMode !== "PROXY_MODE_ENUM_PAC_SCRIPT") {
        existing.add(`chromepolicy:service_discovery_proxy:${spec.target_ou_id}`);
      }
      const configuration = await resolve(
        "chrome.users.apps.ManagedConfiguration",
        CHROME_EXTENSIONS.secureEnterpriseBrowser,
      );
      if (configuration.value !== null) {
        const encoded = configuration.value.managedConfiguration;
        if (typeof encoded !== "string") {
          throw new Error("Chrome managed configuration is missing managedConfiguration");
        }
        let decoded: unknown;
        try {
          decoded = JSON.parse(encoded);
        } catch {
          throw new Error("Chrome managed configuration is not valid JSON");
        }
        if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
          throw new Error("Chrome managed configuration is not a JSON object");
        }
        const securityGateway = (decoded as Record<string, unknown>).securityGateway;
        const wrapped = typeof securityGateway === "object" && securityGateway !== null &&
            !Array.isArray(securityGateway)
          ? (securityGateway as Record<string, unknown>).Value
          : null;
        const context = typeof wrapped === "object" && wrapped !== null && !Array.isArray(wrapped)
          ? (wrapped as Record<string, unknown>).context
          : null;
        const resource = typeof context === "object" && context !== null && !Array.isArray(context)
          ? (context as Record<string, unknown>).resource
          : null;
        if (
          configuration.source === `orgunits/${spec.target_ou_id}` &&
          resource ===
            `projects/${spec.project_id}/locations/global/securityGateways/${spec.gateway_id}`
        ) {
          existing.add(
            `chromepolicy:extension_configuration:${CHROME_EXTENSIONS.secureEnterpriseBrowser}`,
          );
        }
      }
    } catch (error) {
      for (const key of [
        `chromepolicy:extension_install:${CHROME_EXTENSIONS.secureEnterpriseBrowser}`,
        `chromepolicy:extension_install:${CHROME_EXTENSIONS.endpointVerification}`,
        `chromepolicy:extension_configuration:${CHROME_EXTENSIONS.secureEnterpriseBrowser}`,
        `chromepolicy:service_discovery_proxy:${spec.target_ou_id}`,
      ]) {
        existing.delete(key);
        conflicting.add(key);
      }
      diagnostics.push(this.diagnostic("chrome-policy", error));
    }

    const groupPrincipals = new Set(
      spec.principals
        .filter((principal) => principal.type === "group")
        .map((principal) => principal.value.toLowerCase()),
    );
    const userPrincipals = new Set(
      spec.principals
        .filter((principal) => principal.type === "user")
        .map((principal) => principal.value.toLowerCase()),
    );
    const groupConflicts: string[] = [];
    let groupPolicyDiscoveryComplete = true;
    if (groupPrincipals.size > 0 || userPrincipals.size > 0) {
      const groups: Record<string, unknown>[] = [];
      let pageToken = "";
      const seenPageTokens = new Set<string>();
      try {
        for (let page = 0; page < 10 && groups.length <= 2_000; page += 1) {
          const params: Record<string, string | number> = {
            customer,
            maxResults: 200,
            orderBy: "email",
          };
          if (pageToken) params.pageToken = pageToken;
          const { payload } = await workspace.requestJson(
            "GET",
            "https://admin.googleapis.com/admin/directory/v1/groups",
            { params },
          );
          if (payload.groups !== undefined && !Array.isArray(payload.groups)) {
            throw new Error("Directory groups response is not an array");
          }
          if (Array.isArray(payload.groups)) {
            for (const item of payload.groups) {
              if (item === null || typeof item !== "object" || Array.isArray(item)) {
                throw new Error("Directory groups response contains a malformed item");
              }
              const group = item as Record<string, unknown>;
              if (
                typeof group.email !== "string" || group.email.trim() === "" ||
                typeof group.id !== "string" || group.id.trim() === ""
              ) {
                throw new Error("Directory groups response contains an invalid group identity");
              }
              groups.push(group);
            }
          }
          if (groups.length > 2_000) {
            pageToken = "item-limit-exceeded";
            break;
          }
          const next = payload.nextPageToken;
          if (next === undefined || next === "") {
            pageToken = "";
            break;
          }
          if (typeof next !== "string") {
            throw new Error("Directory groups pagination returned an invalid page token");
          }
          if (seenPageTokens.has(next)) {
            throw new Error("Directory groups pagination repeated a page token");
          }
          seenPageTokens.add(next);
          pageToken = next;
        }
        if (pageToken !== "") {
          diagnostics.push({
            code: "chrome-group-policy-discovery-truncated",
            severity: "error",
            message: "Group policy discovery exceeded the 2,000-group safety limit.",
            remediation:
              "Narrow the approved principals or review group-scoped Chrome policies manually before Apply.",
          });
          groupPolicyDiscoveryComplete = false;
        }
      } catch (error) {
        diagnostics.push(this.diagnostic("chrome-group-policy-membership", error));
        groupPolicyDiscoveryComplete = false;
      }

      const candidates = new Map<string, string>();
      if (groupPolicyDiscoveryComplete) {
        for (const group of groups) {
          const email = (group.email as string).toLowerCase();
          const groupId = group.id as string;
          if (groupPrincipals.has(email)) {
            candidates.set(email, groupId);
            continue;
          }
          for (const user of userPrincipals) {
            try {
              const { payload } = await workspace.requestJson(
                "GET",
                "https://admin.googleapis.com/admin/directory/v1/groups/" +
                  `${encodeURIComponent(email)}/hasMember/${encodeURIComponent(user)}`,
              );
              if (typeof payload.isMember !== "boolean") {
                throw new Error("Directory hasMember response is missing boolean isMember");
              }
              if (payload.isMember === true) {
                candidates.set(email, groupId);
                break;
              }
            } catch (error) {
              diagnostics.push(this.diagnostic("chrome-group-policy-membership", error));
              groupPolicyDiscoveryComplete = false;
            }
          }
        }

        const expectedResource =
          `projects/${spec.project_id}/locations/global/securityGateways/${spec.gateway_id}`;
        for (const [email, groupId] of [...candidates.entries()].sort()) {
          try {
            const targetResource = `groups/${groupId}`;
            const exactTargetKey = {
              targetResource,
              additionalTargetKeys: {
                app_id: `chrome:${CHROME_EXTENSIONS.secureEnterpriseBrowser}`,
              },
            };
            let resolvedPolicies: Record<string, unknown>[];
            try {
              resolvedPolicies = await listChromeResolvedPolicies(
                workspace,
                customer,
                {
                  policyTargetKey: exactTargetKey,
                  policySchemaFilter: "chrome.users.apps.ManagedConfiguration",
                },
              );
            } catch (error) {
              if (!isChromePolicyUnmanagedAppInternalError(error)) throw error;
              resolvedPolicies = chromePoliciesForApp(
                await listChromeResolvedPolicies(
                  workspace,
                  customer,
                  {
                    policyTargetKey: { targetResource },
                    policySchemaFilter: "chrome.users.apps.ManagedConfiguration",
                  },
                ),
                targetResource,
                CHROME_EXTENSIONS.secureEnterpriseBrowser,
                "Chrome Policy group aggregate resolve response",
              );
            }
            if (resolvedPolicies.length === 0) continue;
            if (resolvedPolicies.length !== 1) {
              throw new Error("Chrome Policy group resolve returned duplicate policies");
            }
            const exact = resolvedPolicies[0];
            if (typeof exact !== "object" || exact === null || Array.isArray(exact)) {
              throw new Error("Chrome Policy group resolve returned a malformed policy");
            }
            const policy = exact as Record<string, unknown>;
            const expectedTarget = {
              targetResource: `groups/${groupId}`,
              additionalTargetKeys: {
                app_id: `chrome:${CHROME_EXTENSIONS.secureEnterpriseBrowser}`,
              },
            };
            validateChromePolicyTargetKey(
              policy.targetKey,
              expectedTarget,
              "Chrome Policy group resolve targetKey",
            );
            const source = chromePolicySourceResource(
              policy.sourceKey,
              "Chrome Policy group resolve sourceKey",
            );
            const addedSource = chromePolicySourceResource(
              policy.addedSourceKey,
              "Chrome Policy group resolve addedSourceKey",
            );
            if (
              (source !== null && !source.startsWith("groups/")) ||
              (addedSource !== null && !addedSource.startsWith("groups/"))
            ) {
              throw new Error("Chrome Policy group resolve returned an invalid source kind");
            }
            const policyValue = policy.value;
            if (typeof policyValue !== "object" || policyValue === null || Array.isArray(policyValue)) {
              throw new Error("Chrome Policy group resolve returned a malformed value");
            }
            const typedPolicyValue = policyValue as Record<string, unknown>;
            if (typedPolicyValue.policySchema !== "chrome.users.apps.ManagedConfiguration") {
              throw new Error("Chrome Policy group resolve returned the wrong schema");
            }
            const value = typedPolicyValue.value;
            if (typeof value !== "object" || value === null || Array.isArray(value)) {
              throw new Error("Chrome Policy group resolve returned a malformed payload");
            }
            const encoded = (value as Record<string, unknown>).managedConfiguration;
            if (typeof encoded !== "string") {
              throw new Error("Chrome Policy group resolve omitted managedConfiguration");
            }
            // Inherited/default policies are not group-scoped overrides. Only
            // the exact queried group may block the target OU.
            if (source !== `groups/${groupId}`) continue;
            let resource: unknown = null;
            try {
              const parsed = JSON.parse(encoded) as unknown;
              if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
                throw new Error("managedConfiguration is not a JSON object");
              }
              const decoded = parsed as Record<string, unknown>;
              const securityGateway = decoded.securityGateway as Record<string, unknown> | undefined;
              const wrapped = securityGateway?.Value as Record<string, unknown> | undefined;
              const context = wrapped?.context as Record<string, unknown> | undefined;
              resource = context?.resource;
            } catch (error) {
              throw new Error("Chrome Policy group managedConfiguration is invalid", {
                cause: error,
              });
            }
            if (resource === expectedResource) continue;
            groupConflicts.push(email);
            conflicting.add(`chromepolicy:group_extension_configuration:${email}`);
            diagnostics.push({
              code: "chrome-extension-group-policy-conflict",
              severity: "error",
              message:
                `Group ${email} overrides Secure Enterprise Browser managed configuration ` +
                "for an approved principal.",
              remediation:
                "Remove the incompatible group override or configure it for the same Secure Gateway before Apply.",
            });
          } catch (error) {
            diagnostics.push(this.diagnostic("chrome-group-policy", error));
            groupPolicyDiscoveryComplete = false;
          }
        }
      }
    }

    let profileCount: number | null = null;
    let profileOnlyCount: number | null = null;
    let latestSync: string | null = null;
    const profiles: Record<string, unknown>[] = [];
    try {
      let pageToken = "";
      const seenPageTokens = new Set<string>();
      for (let page = 0; page < 20; page += 1) {
        const params: Record<string, string | number> = {
            filter: `ouId = ${spec.target_ou_id}`,
            orderBy: "lastPolicySyncTime desc",
            pageSize: 200,
        };
        if (pageToken) params.pageToken = pageToken;
        const response = await workspace.requestJson(
          "GET",
          `https://chromemanagement.googleapis.com/v1/customers/${customer}/profiles`,
          { params },
        );
        const pageProfiles = response.payload.chromeBrowserProfiles;
        if (pageProfiles !== undefined && !Array.isArray(pageProfiles)) {
          throw new Error("Chrome profile response is not an array");
        }
        if (Array.isArray(pageProfiles)) {
          for (const profile of pageProfiles) {
            if (profile === null || typeof profile !== "object" || Array.isArray(profile)) {
              throw new Error("Chrome profile response contains a malformed item");
            }
            const item = profile as Record<string, unknown>;
            if (typeof item.affiliationState !== "string" || item.affiliationState === "") {
              throw new Error("Chrome profile affiliationState is invalid");
            }
            if (
              item.lastPolicySyncTime !== undefined &&
              (typeof item.lastPolicySyncTime !== "string" || item.lastPolicySyncTime === "")
            ) {
              throw new Error("Chrome profile lastPolicySyncTime is invalid");
            }
            profiles.push(item);
          }
        }
        const next = response.payload.nextPageToken;
        if (next === undefined || next === "") {
          pageToken = "";
          break;
        }
        if (typeof next !== "string") {
          throw new Error("Chrome profile pagination returned an invalid page token");
        }
        if (seenPageTokens.has(next)) {
          throw new Error("Chrome profile pagination repeated a page token");
        }
        seenPageTokens.add(next);
        pageToken = next;
      }
      if (pageToken !== "" || profiles.length > 4_000) {
        diagnostics.push({
          code: "chrome-profile-readiness-truncated",
          severity: "error",
          message: "Chrome profile discovery exceeded the 4,000-profile safety limit.",
          remediation: "Narrow the target OU or review its profile readiness manually before Apply.",
        });
        profiles.length = 0;
      } else {
        profileCount = profiles.length;
        profileOnlyCount = profiles.filter(
          (profile) => profile.affiliationState === "PROFILE_ONLY",
        ).length;
        const syncTimes = profiles
          .map((profile) => profile.lastPolicySyncTime)
          .filter((value): value is string => typeof value === "string" && value !== "");
        latestSync = syncTimes.length > 0 ? syncTimes.sort().at(-1) ?? null : null;

        const extensionVersions = new Map<string, string>();
        for (const profile of profiles) {
          const reportingRaw = profile.reportingData;
          if (
            reportingRaw !== undefined &&
            (typeof reportingRaw !== "object" || reportingRaw === null || Array.isArray(reportingRaw))
          ) throw new Error("Chrome profile reportingData is malformed");
          const reporting = reportingRaw as Record<string, unknown> | undefined;
          const extensionData = reporting?.extensionData;
          if (extensionData === undefined) continue;
          if (!Array.isArray(extensionData)) {
            throw new Error("Chrome profile extensionData is malformed");
          }
          for (const item of extensionData) {
            if (item === null || typeof item !== "object" || Array.isArray(item)) {
              throw new Error("Chrome profile extensionData contains a malformed item");
            }
            const extension = item as Record<string, unknown>;
            if (
              typeof extension.extensionId !== "string" || extension.extensionId === "" ||
              (extension.isDisabled !== undefined && typeof extension.isDisabled !== "boolean") ||
              (extension.version !== undefined &&
                (typeof extension.version !== "string" || extension.version === ""))
            ) {
              throw new Error("Chrome profile extensionData contains an invalid identity");
            }
            if (extension.isDisabled === true) continue;
            const candidate = typeof extension.version === "string"
              ? extension.version
              : "installed";
            const current = extensionVersions.get(extension.extensionId);
            if (current === undefined || compareVersions(candidate, current) > 0) {
              extensionVersions.set(extension.extensionId, candidate);
            }
          }
        }
        secureBrowserInstalled = extensionVersions.has(CHROME_EXTENSIONS.secureEnterpriseBrowser);
        endpointVerificationInstalled = extensionVersions.has(CHROME_EXTENSIONS.endpointVerification);
        secureBrowserVersion = extensionVersions.get(CHROME_EXTENSIONS.secureEnterpriseBrowser) ?? null;
        endpointVerificationVersion = extensionVersions.get(CHROME_EXTENSIONS.endpointVerification) ?? null;
      }
    } catch (error) {
      profiles.length = 0;
      profileCount = null;
      profileOnlyCount = null;
      latestSync = null;
      secureBrowserInstalled = null;
      endpointVerificationInstalled = null;
      secureBrowserVersion = null;
      endpointVerificationVersion = null;
      diagnostics.push({
        code: "chrome-profile-readiness-pagination-invalid",
        severity: "error",
        message: "Chrome profile pagination could not be completed safely.",
        remediation: (error as Error).message,
      });
    }

    let licenseCount: number | null = null;
    try {
      let count = 0;
      let pageToken = "";
      const seenPageTokens = new Set<string>();
      const seenLicenseUsers = new Set<string>();
      for (let page = 0; page < 20; page += 1) {
        const params: Record<string, string | number> = {
          customerId: customer,
          maxResults: 1000,
        };
        if (pageToken) params.pageToken = pageToken;
        const response = await workspace.requestJson(
          "GET",
          "https://licensing.googleapis.com/apps/licensing/v1/product/101040/sku/1010400001/users",
          { params, acceptedStatuses: [404] },
        );
        if (response.status === 404) {
          pageToken = "";
          break;
        }
        const items = response.payload.items;
        if (items !== undefined && !Array.isArray(items)) {
          throw new Error("License response items is not an array");
        }
        if (Array.isArray(items)) {
          for (const item of items) {
            if (item === null || typeof item !== "object" || Array.isArray(item)) {
              throw new Error("License response contains a malformed item");
            }
            const assignment = validateLicenseAssignment(item as Record<string, unknown>, {
              productId: "101040",
              skuId: "1010400001",
            });
            const userId = assignment.userId.toLowerCase();
            if (seenLicenseUsers.has(userId)) {
              throw new Error("License response contains a duplicate user assignment");
            }
            seenLicenseUsers.add(userId);
            count += 1;
          }
        }
        const next = response.payload.nextPageToken;
        if (next === undefined || next === "") {
          pageToken = "";
          break;
        }
        if (typeof next !== "string") {
          throw new Error("License pagination returned an invalid page token");
        }
        if (seenPageTokens.has(next)) throw new Error("License pagination repeated a page token");
        seenPageTokens.add(next);
        pageToken = next;
      }
      if (pageToken !== "") throw new Error("License pagination exceeded the 20-page safety limit");
      licenseCount = count;
      if (count === 0) {
        diagnostics.push({
          code: "chrome-enterprise-premium-license-not-detected",
          severity: "warning",
          message: "No Chrome Enterprise Premium user assignment was returned by the Enterprise License Manager API.",
          remediation:
            "Assign Chrome Enterprise Premium SKU 1010400001 to at least one target user, or verify a domain-wide entitlement in Admin console.",
        });
      }
    } catch (error) {
      licenseCount = null;
      diagnostics.push({
        code: "chrome-enterprise-premium-manual-confirmation",
        severity: "info",
        message:
          "Chrome Enterprise Premium entitlement could not be reliably verified through the Enterprise License Manager API.",
        remediation: "Confirm the target users' license or domain-wide entitlement in Google Admin console.",
      });
    }

    let rootStoreEnabled: boolean | null = null;
    try {
      const rootStore = await resolve("chrome.users.ChromeRootStoreEnabled", null);
      const selection = rootStore.value?.chromeRootStoreEnabled;
      if (rootStore.value !== null && typeof selection !== "string") {
        throw new Error("Chrome Root Store policy has an invalid value");
      }
      rootStoreEnabled = selection === "TRUE" ? true : selection === "FALSE" ? false : null;
    } catch (error) {
      diagnostics.push(this.diagnostic("chrome-root-store", error));
    }

    return {
      secure_enterprise_browser_installed: secureBrowserInstalled,
      secure_enterprise_browser_version: secureBrowserVersion,
      endpoint_verification_installed: endpointVerificationInstalled,
      endpoint_verification_version: endpointVerificationVersion,
      chrome_extension_group_conflicts: groupConflicts,
      chrome_group_policy_discovery_complete: groupPolicyDiscoveryComplete,
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
    const workspaceResource = resource.startsWith("chrome-");
    return {
      code: "api-unavailable",
      severity: "warning",
      message: `${resource} could not be inspected: ${(error as Error).message}`,
      remediation: workspaceResource
        ? "Confirm the Chrome Policy API is enabled and the signed-in Workspace administrator " +
          "has Chrome Policy read access to the selected organizational unit and groups."
        : "Confirm the API is enabled and the deployer has read access.",
    };
  }

  private async enabledApis(projectId: string): Promise<Set<string>> {
    const enabled = new Set<string>();
    let pageToken: string | undefined;
    const seenPageTokens = new Set<string>();
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
      if (services !== undefined && !Array.isArray(services)) {
        throw new Error("Enabled-API response services is not an array");
      }
      if (Array.isArray(services)) {
        for (const service of services) {
          if (typeof service !== "object" || service === null || Array.isArray(service)) {
            throw new Error("Enabled-API response contains a malformed service");
          }
          const name = (service as { config?: { name?: unknown } })?.config?.name;
          if (typeof name !== "string" || name === "") {
            throw new Error("Enabled-API response contains an invalid service name");
          }
          enabled.add(name);
        }
      }
      const next = response.payload.nextPageToken;
      if (next === undefined || next === "") return enabled;
      if (typeof next !== "string") {
        throw new Error("Enabled-API pagination returned an invalid page token");
      }
      if (seenPageTokens.has(next)) {
        throw new Error("Enabled-API pagination repeated a page token");
      }
      seenPageTokens.add(next);
      pageToken = next;
    }
    throw new Error("Enabled-API pagination exceeded the 10-page safety limit");
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

  private async validatePublicCertificateSecret(
    spec: DeploymentSpec,
    secretName: string,
  ): Promise<ValidatedPublicCertificateSecret> {
    const response = await this.transport.requestJson(
      "GET",
      `https://secretmanager.googleapis.com/v1/projects/${spec.project_id}` +
        `/secrets/${secretName}/versions/latest:access`,
    );
    if (response.status !== 200) throw new Error("The latest secret version is not accessible");
    return validatePublicCertificateAccessResponse(response.payload, {
      projectId: spec.project_id,
      secretName,
      hostname: spec.private_hostname,
      minimumValidityDays: spec.mode === "production" ? 30 : 1,
    });
  }

  private async discoverCloudNat(
    spec: DeploymentSpec,
    existing: Set<string>,
    conflicting: Set<string>,
    diagnostics: PreflightDiagnostic[],
  ): Promise<void> {
    if (spec.network_strategy !== "dedicated") return;
    const key = `compute:cloud_nat:${spec.name}-nat`;
    const routerUrl =
      `${COMPUTE}/projects/${spec.project_id}/regions/${spec.region}` +
      `/routers/${spec.name}-router`;
    try {
      const response = await this.transport.requestJson("GET", routerUrl, {
        acceptedStatuses: [404],
      });
      if (response.status === 404) return;
      if (
        !hasSgsOwnershipDescription(response.payload) ||
        !this.ownsManagedResource(`compute:router:${spec.name}-router`, response.payload) ||
        this.ownershipProofs[key] === undefined
      ) {
        conflicting.add(key);
        return;
      }
      const nats = response.payload.nats;
      if (nats === undefined) return;
      if (!Array.isArray(nats)) throw new Error("Cloud Router nats is not an array");
      const matches: Record<string, unknown>[] = [];
      for (const item of nats) {
        if (typeof item !== "object" || item === null || Array.isArray(item)) {
          throw new Error("Cloud Router nats contains a malformed item");
        }
        const nat = item as Record<string, unknown>;
        if (typeof nat.name !== "string" || nat.name === "") {
          throw new Error("Cloud Router nats contains an invalid name");
        }
        if (nat.name === `${spec.name}-nat`) matches.push(nat);
      }
      if (matches.length === 0) return;
      const expectedSubnet =
        `${COMPUTE}/projects/${spec.project_id}/regions/${spec.region}` +
        `/subnetworks/${subnetName(spec)}`;
      const nat = matches.length === 1 ? matches[0] : null;
      const subnetworks = nat?.subnetworks;
      const exact = nat !== null && nat.natIpAllocateOption === "AUTO_ONLY" &&
        nat.sourceSubnetworkIpRangesToNat === "LIST_OF_SUBNETWORKS" &&
        Array.isArray(subnetworks) && subnetworks.length === 1 &&
        typeof subnetworks[0] === "object" && subnetworks[0] !== null &&
        !Array.isArray(subnetworks[0]) &&
        (subnetworks[0] as Record<string, unknown>).name === expectedSubnet &&
        canonicalJson((subnetworks[0] as Record<string, unknown>).sourceIpRangesToNat) ===
          canonicalJson(["ALL_IP_RANGES"]);
      if (exact) existing.add(key);
      else conflicting.add(key);
    } catch (error) {
      existing.delete(key);
      conflicting.add(key);
      diagnostics.push(this.diagnostic(key, error));
    }
  }

  private async existingPrivateEgressAvailable(spec: DeploymentSpec): Promise<boolean> {
    if (spec.vpc_name === null || spec.subnet_name === null) {
      throw new Error("Existing private egress requires an exact network and subnetwork");
    }
    const expectedNetworkPath =
      `/compute/v1/projects/${spec.project_id}/global/networks/${spec.vpc_name}`;
    const expectedSubnetPath =
      `/compute/v1/projects/${spec.project_id}/regions/${spec.region}` +
      `/subnetworks/${spec.subnet_name}`;
    const exactComputeResource = (value: unknown, expectedPath: string): boolean => {
      if (typeof value !== "string") return false;
      try {
        const parsed = new URL(value);
        return (parsed.origin === "https://compute.googleapis.com" ||
            parsed.origin === "https://www.googleapis.com") &&
          parsed.username === "" && parsed.password === "" && parsed.port === "" &&
          parsed.search === "" && parsed.hash === "" && parsed.pathname === expectedPath;
      } catch {
        return false;
      }
    };

    let found = false;
    let pageToken: string | undefined;
    const seenTokens = new Set<string>();
    for (let page = 0; page < 10; page += 1) {
      const response = await this.transport.requestJson(
        "GET",
        `${COMPUTE}/projects/${spec.project_id}/aggregated/routers`,
        {
          params: {
            maxResults: 500,
            returnPartialSuccess: "true",
            ...(pageToken === undefined ? {} : { pageToken }),
          },
        },
      );
      const unreachables = response.payload.unreachables;
      if (
        unreachables !== undefined &&
        (!Array.isArray(unreachables) ||
          !unreachables.every((item) => typeof item === "string" && item !== ""))
      ) {
        throw new Error("Router response unreachables is malformed");
      }
      if (Array.isArray(unreachables) && unreachables.length > 0) {
        throw new Error("Router discovery returned unreachable scopes");
      }
      const items = response.payload.items;
      if (
        items !== undefined &&
        (typeof items !== "object" || items === null || Array.isArray(items))
      ) {
        throw new Error("Router response items is malformed");
      }
      for (const [scopeName, rawScope] of Object.entries(
        (items ?? {}) as Record<string, unknown>,
      )) {
        if (
          !/^regions\/[a-z0-9-]+$/.test(scopeName) ||
          typeof rawScope !== "object" || rawScope === null || Array.isArray(rawScope)
        ) {
          throw new Error("Router response contains an invalid scope");
        }
        if (scopeName !== `regions/${spec.region}`) continue;
        const scope = rawScope as Record<string, unknown>;
        if (scope.routers === undefined) {
          const warning = scope.warning;
          if (
            typeof warning !== "object" || warning === null || Array.isArray(warning) ||
            typeof (warning as Record<string, unknown>).code !== "string"
          ) {
            throw new Error("Router scope has neither routers nor a warning");
          }
          throw new Error("Target-region router discovery returned a warning");
        }
        if (!Array.isArray(scope.routers)) {
          throw new Error("Router scope contains an invalid routers collection");
        }
        for (const rawRouter of scope.routers) {
          if (typeof rawRouter !== "object" || rawRouter === null || Array.isArray(rawRouter)) {
            throw new Error("Router response contains a malformed router");
          }
          const router = rawRouter as Record<string, unknown>;
          if (typeof router.network !== "string") {
            throw new Error("Router response contains an invalid network");
          }
          const nats = router.nats;
          if (nats !== undefined && !Array.isArray(nats)) {
            throw new Error("Router response contains invalid NAT state");
          }
          if (!exactComputeResource(router.network, expectedNetworkPath)) continue;
          for (const rawNat of nats ?? []) {
            if (typeof rawNat !== "object" || rawNat === null || Array.isArray(rawNat)) {
              throw new Error("Router response contains a malformed NAT");
            }
            const nat = rawNat as Record<string, unknown>;
            if (
              typeof nat.name !== "string" || nat.name === "" ||
              typeof nat.sourceSubnetworkIpRangesToNat !== "string"
            ) {
              throw new Error("Router response contains an invalid NAT identity");
            }
            if (nat.type !== undefined && nat.type !== "PUBLIC") continue;
            const endpointTypes = nat.endpointTypes;
            if (
              endpointTypes !== undefined &&
              (!Array.isArray(endpointTypes) ||
                !endpointTypes.every((item) => typeof item === "string") ||
                new Set(endpointTypes).size !== endpointTypes.length ||
                !(endpointTypes.length === 0 ||
                  (endpointTypes.length === 1 && endpointTypes[0] === "ENDPOINT_TYPE_VM")))
            ) {
              throw new Error("Router response contains invalid NAT endpoint types");
            }
            if (nat.natIpAllocateOption === "MANUAL_ONLY") {
              if (
                !Array.isArray(nat.natIps) || nat.natIps.length === 0 ||
                !nat.natIps.every((item) => {
                  if (typeof item !== "string") return false;
                  const name = item.split("/").pop() ?? "";
                  return /^[a-z]([-a-z0-9]*[a-z0-9])?$/.test(name) &&
                    exactComputeResource(
                      item,
                      `/compute/v1/projects/${spec.project_id}/regions/${spec.region}` +
                        `/addresses/${name}`,
                    );
                })
              ) {
                throw new Error("Manual Public NAT has invalid address bindings");
              }
            } else if (
              nat.natIpAllocateOption !== "AUTO_ONLY"
            ) {
              throw new Error("Router response contains an invalid NAT allocation");
            }
            const mode = nat.sourceSubnetworkIpRangesToNat;
            if (
              mode === "ALL_SUBNETWORKS_ALL_IP_RANGES" ||
              mode === "ALL_SUBNETWORKS_ALL_PRIMARY_IP_RANGES"
            ) {
              found = true;
              continue;
            }
            if (mode !== "LIST_OF_SUBNETWORKS") continue;
            if (!Array.isArray(nat.subnetworks)) {
              throw new Error("NAT subnetwork coverage is malformed");
            }
            for (const rawSubnet of nat.subnetworks) {
              if (typeof rawSubnet !== "object" || rawSubnet === null || Array.isArray(rawSubnet)) {
                throw new Error("NAT subnetwork coverage is malformed");
              }
              const subnet = rawSubnet as Record<string, unknown>;
              if (
                !Array.isArray(subnet.sourceIpRangesToNat) ||
                !subnet.sourceIpRangesToNat.every(
                  (item) => typeof item === "string" && item !== "",
                )
              ) {
                throw new Error("NAT subnetwork coverage is malformed");
              }
              const ranges = new Set(subnet.sourceIpRangesToNat as string[]);
              if (
                exactComputeResource(subnet.name, expectedSubnetPath) &&
                ranges.size === 1 &&
                (ranges.has("ALL_IP_RANGES") || ranges.has("PRIMARY_IP_RANGE"))
              ) found = true;
            }
          }
        }
      }
      const next = response.payload.nextPageToken;
      if (next === undefined || next === "") {
        return found && await this.defaultInternetRouteAvailable(spec);
      }
      if (typeof next !== "string" || seenTokens.has(next)) {
        throw new Error("Router pagination returned an invalid/repeated token");
      }
      seenTokens.add(next);
      pageToken = next;
    }
    throw new Error("Router pagination exceeded the 10-page safety limit");
  }

  private async defaultInternetRouteAvailable(spec: DeploymentSpec): Promise<boolean> {
    if (spec.vpc_name === null) return false;
    const exactComputeResource = (value: unknown, expectedPath: string): boolean => {
      if (typeof value !== "string") return false;
      try {
        const parsed = new URL(value);
        return (parsed.origin === "https://compute.googleapis.com" ||
            parsed.origin === "https://www.googleapis.com") &&
          parsed.username === "" && parsed.password === "" && parsed.port === "" &&
          parsed.search === "" && parsed.hash === "" && parsed.pathname === expectedPath;
      } catch {
        return false;
      }
    };
    const networkPath =
      `/compute/v1/projects/${spec.project_id}/global/networks/${spec.vpc_name}`;
    const gatewayPath =
      `/compute/v1/projects/${spec.project_id}/global/gateways/default-internet-gateway`;
    const candidates: Array<{ priority: number; defaultGateway: boolean }> = [];
    let pageToken: string | undefined;
    const seenTokens = new Set<string>();
    for (let page = 0; page < 10; page += 1) {
      const response = await this.transport.requestJson(
        "GET",
        `${COMPUTE}/projects/${spec.project_id}/global/routes`,
        {
          params: {
            maxResults: 500,
            ...(pageToken === undefined ? {} : { pageToken }),
          },
        },
      );
      const items = response.payload.items;
      if (items !== undefined && !Array.isArray(items)) {
        throw new Error("Route response items is not an array");
      }
      if (items === undefined && "warning" in response.payload) {
        const warning = response.payload.warning;
        if (
          typeof warning !== "object" || warning === null || Array.isArray(warning) ||
          typeof (warning as Record<string, unknown>).code !== "string"
        ) throw new Error("Route response warning is malformed");
      }
      for (const rawRoute of items ?? []) {
        if (typeof rawRoute !== "object" || rawRoute === null || Array.isArray(rawRoute)) {
          throw new Error("Route response contains a malformed item");
        }
        const route = rawRoute as Record<string, unknown>;
        if (
          typeof route.name !== "string" || route.name === "" ||
          typeof route.network !== "string" || typeof route.destRange !== "string"
        ) throw new Error("Route response contains an invalid identity");
        if (!exactComputeResource(route.network, networkPath) || route.destRange !== "0.0.0.0/0") {
          continue;
        }
        if (
          route.tags !== undefined &&
          (!Array.isArray(route.tags) ||
            !route.tags.every((item) => typeof item === "string" && item !== ""))
        ) throw new Error("Route response contains invalid tags");
        if (
          Array.isArray(route.tags) && route.tags.length > 0 &&
          !route.tags.some(
            (tag) => tag === `${spec.name}-backend` || tag === `${spec.name}-offload`,
          )
        ) continue;
        if (
          typeof route.priority !== "number" || !Number.isInteger(route.priority) ||
          route.priority < 0
        ) throw new Error("Route response contains an invalid priority");
        if (route.status !== undefined && route.status !== "ACTIVE") {
          throw new Error("Applicable default route is not active");
        }
        candidates.push({
          priority: route.priority,
          defaultGateway:
            (route.routeType === undefined || route.routeType === "STATIC") &&
            exactComputeResource(route.nextHopGateway, gatewayPath),
        });
      }
      const next = response.payload.nextPageToken;
      if (next === undefined || next === "") {
        if (candidates.length === 0) return false;
        const winningPriority = Math.min(...candidates.map((item) => item.priority));
        const winners = candidates.filter((item) => item.priority === winningPriority);
        return winners.length === 1 && winners[0]!.defaultGateway;
      }
      if (typeof next !== "string" || next === "" || seenTokens.has(next)) {
        throw new Error("Route pagination returned an invalid/repeated token");
      }
      seenTokens.add(next);
      pageToken = next;
    }
    throw new Error("Route pagination exceeded the 10-page safety limit");
  }

  private async discoverManagedSecretVersion(
    spec: DeploymentSpec,
    existing: Set<string>,
    conflicting: Set<string>,
    diagnostics: PreflightDiagnostic[],
  ): Promise<void> {
    if (spec.certificate_strategy === "public_trusted") return;
    const secretName = `${spec.name}-tls`;
    const secretKey = `secretmanager:secret:${secretName}`;
    const versionKey = `secretmanager:secret_version:${secretName}`;
    if (!existing.has(secretKey)) return;
    const secretUrl =
      `https://secretmanager.googleapis.com/v1/projects/${spec.project_id}` +
      `/secrets/${secretName}`;
    try {
      const metadata = (await this.transport.requestJson("GET", secretUrl)).payload;
      const aliases = stringMap(metadata.versionAliases);
      const labels = stringMap(metadata.labels);
      if (aliases === null || labels === null) {
        throw new Error("Managed secret aliases or labels are malformed");
      }
      const active = aliases.active;
      if (active === undefined || active === "") return;
      if (!/^[1-9][0-9]*$/.test(active)) {
        throw new Error("Managed secret active alias is not a numeric version");
      }
      const expectedCertificateHash = canonicalDigestSync({
        ca_name: spec.ca_name ?? null,
        ca_pool: spec.ca_pool ?? null,
        certificate_lifetime_days: spec.certificate_lifetime_days,
        certificate_strategy: spec.certificate_strategy,
        private_hostname: spec.private_hostname,
        public_certificate_secret: spec.public_certificate_secret ?? null,
      }).slice(0, 32);
      if (
        labels["managed-by"] !== "secure-gateway-studio" ||
        typeof labels["sgs-owner-token"] !== "string" || labels["sgs-owner-token"] === ""
      ) {
        conflicting.add(versionKey);
        return;
      }
      const versionProof = this.ownershipProofs[versionKey];
      if (
        versionProof === undefined || typeof versionProof.marker !== "string" ||
        versionProof.providerIdentityField !== "versionName" ||
        versionProof.providerIdentity !==
          `projects/${spec.project_id}/secrets/${secretName}/versions/${active}`
      ) {
        conflicting.add(versionKey);
        return;
      }
      // A legitimate SGS secret with an old configuration is a rotation, not
      // a name collision.  Only mark the version reusable when both durable
      // configuration labels match this exact plan.
      if (
        labels["certificate-spec-hash"] !== expectedCertificateHash ||
        labels["configuration-hash"] !== configurationHash(spec).slice(0, 32)
      ) return;
      const response = await this.transport.requestJson(
        "GET",
        `${secretUrl}/versions/${active}:access`,
      );
      const validated = await validatePublicCertificateAccessResponse(response.payload, {
        projectId: spec.project_id,
        secretName,
        hostname: spec.private_hostname,
        // Prove the entire CRC/JSON/key/SAN/chain/ownership contract first.
        // Expiry inside the rotation window is then the one non-conflict case.
        minimumValidityDays: 0,
      });
      if (validated.versionName !== `projects/${spec.project_id}/secrets/${secretName}/versions/${active}`) {
        throw new Error("Managed secret version response identity changed");
      }
      try {
        await validatePublicCertificateAccessResponse(response.payload, {
          projectId: spec.project_id,
          secretName,
          hostname: spec.private_hostname,
          minimumValidityDays: spec.mode === "production" ? 30 : 1,
        });
      } catch (error) {
        if (
          error instanceof CertificateError &&
          error.message === "The TLS secret certificate expires too soon"
        ) {
          diagnostics.push({
            code: "managed-certificate-rotation-required",
            severity: "warning",
            message: "The existing managed TLS certificate is inside its rotation window.",
            remediation: "Approve the planned certificate issuance and Secret Manager rotation.",
          });
          return;
        }
        throw error;
      }
      existing.add(versionKey);
    } catch (error) {
      existing.delete(versionKey);
      conflicting.add(versionKey);
      diagnostics.push(this.diagnostic(versionKey, error));
    }
  }

  private async discoverDnsRecord(
    spec: DeploymentSpec,
    existing: Set<string>,
    conflicting: Set<string>,
    diagnostics: PreflightDiagnostic[],
  ): Promise<void> {
    const key = `dns:record_set:${spec.private_hostname}`;
    if (!existing.has(`dns:private_zone:${spec.name}-zone`)) return;
    const fqdn = `${spec.private_hostname}.`;
    const markerName = `_sgs-owner.${fqdn}`;
    const zone =
      `https://dns.googleapis.com/dns/v1/projects/${spec.project_id}` +
      `/managedZones/${spec.name}-zone`;
    try {
      const [address, record, marker] = await Promise.all([
        this.transport.requestJson(
          "GET",
          `${COMPUTE}/projects/${spec.project_id}/regions/${spec.region}` +
            `/addresses/${spec.name}-offload-ip`,
          { acceptedStatuses: [404] },
        ),
        this.transport.requestJson(
          "GET",
          `${zone}/rrsets/${encodeURIComponent(fqdn)}/A`,
          { acceptedStatuses: [404] },
        ),
        this.transport.requestJson(
          "GET",
          `${zone}/rrsets/${encodeURIComponent(markerName)}/TXT`,
          { acceptedStatuses: [404] },
        ),
      ]);
      if (record.status === 404 && marker.status === 404) return;
      const token = Array.isArray(marker.payload.rrdatas) && marker.payload.rrdatas.length === 1
        ? marker.payload.rrdatas[0]
        : null;
      const proof = this.ownershipProofs[key];
      const exact = proof !== undefined && typeof proof.marker === "string" &&
        token === proof.marker &&
        address.status === 200 && record.status === 200 && marker.status === 200 &&
        typeof address.payload.address === "string" &&
        record.payload.name === fqdn && record.payload.type === "A" && record.payload.ttl === 60 &&
        canonicalJson(record.payload.rrdatas) === canonicalJson([address.payload.address]) &&
        marker.payload.name === markerName && marker.payload.type === "TXT" &&
        marker.payload.ttl === 60 && typeof token === "string" &&
        /^"sgs-owner=[0-9a-f]{8}-[0-9a-f-]{27}"$/i.test(token);
      if (exact) existing.add(key);
      else conflicting.add(key);
    } catch (error) {
      existing.delete(key);
      conflicting.add(key);
      diagnostics.push(this.diagnostic(key, error));
    }
  }

  private resourceProbes(spec: DeploymentSpec): ResourceProbe[] {
    const probes: ResourceProbe[] = [];
    const project = spec.project_id;
    const prefix = spec.name;
    const network = networkName(spec);
    if (spec.managed_chrome_access_level) {
      probes.push({
        key: `accesscontextmanager:access_level:${spec.managed_chrome_access_level}`,
        url:
          "https://accesscontextmanager.googleapis.com/v1/" +
          spec.managed_chrome_access_level,
      });
    }
    if (spec.source_image) {
      probes.push({
        key: `compute:source_image:${spec.source_image}`,
        url: `https://compute.googleapis.com/compute/v1/${spec.source_image}`,
      });
    }
    // A dedicated Path-A VPC is created in the deployment project. An
    // administrator-managed Path-B/existing VPC can live in the upstream
    // project instead.
    const networkProject = spec.network_strategy === "dedicated"
      ? project
      : upstreamProjectId(spec);
    probes.push({
      key: `compute:network:${network}`,
      url:
        "https://compute.googleapis.com/compute/v1/projects/" +
        `${networkProject}/global/networks/${network}`,
    });

    const gateway =
      `https://beyondcorp.googleapis.com/v1/projects/${project}` +
      `/locations/global/securityGateways/${spec.gateway_id}`;
    if (spec.backend_kind === "direct_https") {
      probes.push({ key: `beyondcorp:security_gateway:${spec.gateway_id}`, url: gateway });
      probes.push({
        key: `beyondcorp:application:${prefix}-app`,
        url: `${gateway}/applications/${prefix}-app`,
      });
      return probes;
    }

    if (spec.network_strategy === "dedicated") {
      probes.push(
        {
          key: `compute:subnetwork:${prefix}-subnet`,
          url:
            `${COMPUTE}/projects/${project}/regions/${spec.region}` +
            `/subnetworks/${prefix}-subnet`,
        },
        {
          key: `compute:router:${prefix}-router`,
          url:
            `${COMPUTE}/projects/${project}/regions/${spec.region}` +
            `/routers/${prefix}-router`,
        },
      );
    } else if (spec.subnet_name) {
      probes.push({
        key: `compute:subnetwork:${spec.subnet_name}`,
        url:
          `${COMPUTE}/projects/${project}` +
          `/regions/${spec.region}/subnetworks/${spec.subnet_name}`,
      });
    }
    if (spec.backend_kind === "internal_https_lb") {
      probes.push({
        key: `compute:subnetwork:${prefix}-proxy-subnet`,
        url: `${COMPUTE}/projects/${project}/regions/${spec.region}` +
          `/subnetworks/${prefix}-proxy-subnet`,
      });
    }

    const accountRoles = spec.backend_kind === "managed_sample"
      ? ["offload", "backend"]
      : spec.backend_kind === "internal_https_lb"
        ? ["backend"]
        : ["offload"];
    for (const role of accountRoles) {
      const accountId = serviceAccountId(prefix, role);
      const email = encodeURIComponent(`${accountId}@${project}.iam.gserviceaccount.com`);
      probes.push({
        key: `iam:service_account:${accountId}`,
        url: `https://iam.googleapis.com/v1/projects/${project}/serviceAccounts/${email}`,
      });
    }
    if (spec.backend_kind === "internal_https_lb") {
      probes.push({
        key: `compute:internal_address:${prefix}-offload-ip`,
        url: `${COMPUTE}/projects/${project}/regions/${spec.region}` +
          `/addresses/${prefix}-offload-ip`,
      });
    }

    const secretName =
      spec.certificate_strategy === "public_trusted" && spec.public_certificate_secret
        ? spec.public_certificate_secret.split("/").pop() as string
        : `${prefix}-tls`;
    probes.push({
      key: `secretmanager:secret:${secretName}`,
      url:
        `https://secretmanager.googleapis.com/v1/projects/${project}` +
        `/secrets/${secretName}`,
    });

    for (const role of accountRoles) {
      probes.push({
        key: `compute:internal_address:${prefix}-${role}-ip`,
        url:
          `${COMPUTE}/projects/${project}/regions/${spec.region}` +
          `/addresses/${prefix}-${role}-ip`,
      });
    }

    if (spec.backend_kind === "internal_https_lb") {
      for (const [resourceType, collection, name] of [
        ["instance", `zones/${spec.zone}/instances`, `${prefix}-backend`],
        ["instance_group", `zones/${spec.zone}/instanceGroups`, `${prefix}-backend-ig`],
        ["health_check", `regions/${spec.region}/healthChecks`, `${prefix}-ilb-hc`],
        ["backend_service", `regions/${spec.region}/backendServices`, `${prefix}-ilb-bs`],
        ["ssl_certificate", `regions/${spec.region}/sslCertificates`, `${prefix}-ilb-cert`],
        ["url_map", `regions/${spec.region}/urlMaps`, `${prefix}-ilb-map`],
        ["target_https_proxy", `regions/${spec.region}/targetHttpsProxies`, `${prefix}-ilb-proxy`],
        ["forwarding_rule", `regions/${spec.region}/forwardingRules`, `${prefix}-ilb-fr`],
      ] as const) {
        probes.push({
          key: `compute:${resourceType}:${name}`,
          url: `${COMPUTE}/projects/${project}/${collection}/${name}`,
        });
      }
    } else if (spec.mode === "production") {
      for (const [resourceType, collection, name] of [
        ["instance_template", "global/instanceTemplates", `${prefix}-offload-template`],
        ["health_check", `regions/${spec.region}/healthChecks`, `${prefix}-offload-hc`],
        ["instance_group_manager", `regions/${spec.region}/instanceGroupManagers`, `${prefix}-offload-mig`],
        ["autoscaler", `regions/${spec.region}/autoscalers`, `${prefix}-offload-autoscaler`],
        ["backend_service", `regions/${spec.region}/backendServices`, `${prefix}-offload-bs`],
        ["forwarding_rule", `regions/${spec.region}/forwardingRules`, `${prefix}-offload-fr`],
      ] as const) {
        probes.push({
          key: `compute:${resourceType}:${name}`,
          url: `${COMPUTE}/projects/${project}/${collection}/${name}`,
        });
      }
    } else {
      probes.push({
        key: `compute:instance:${prefix}-offload`,
        url: `${COMPUTE}/projects/${project}/zones/${spec.zone}/instances/${prefix}-offload`,
      });
    }
    if (spec.backend_kind === "managed_sample") {
      probes.push({
        key: `compute:instance:${prefix}-backend`,
        url: `${COMPUTE}/projects/${project}/zones/${spec.zone}/instances/${prefix}-backend`,
      });
    }

    const firewallSuffixes = spec.backend_kind === "internal_https_lb"
      ? ["ilb-proxy-ingress", "ilb-health-ingress"]
      : ["gateway-ingress"];
    if (spec.mode === "production") firewallSuffixes.push("health-check-ingress");
    if (spec.backend_kind === "managed_sample") firewallSuffixes.push("backend-ingress");
    for (const suffix of firewallSuffixes) {
      probes.push({
        key: `compute:firewall_rule:${prefix}-${suffix}`,
        url: `${COMPUTE}/projects/${project}/global/firewalls/${prefix}-${suffix}`,
      });
    }

    probes.push({
      key: `dns:private_zone:${prefix}-zone`,
      url: `https://dns.googleapis.com/dns/v1/projects/${project}/managedZones/${prefix}-zone`,
    });
    probes.push({ key: `beyondcorp:security_gateway:${spec.gateway_id}`, url: gateway });
    probes.push({
      key: `beyondcorp:application:${prefix}-app`,
      url: `${gateway}/applications/${prefix}-app`,
    });
    return probes;
  }

  /** Fail closed when a same-name resource is not semantically reusable. */
  private async compatible(
    key: string,
    payload: Record<string, unknown>,
    spec: DeploymentSpec,
  ): Promise<boolean> {
    const [, resourceType, resourceName] = key.split(":", 3);
    const managedCompute = (): boolean =>
      hasSgsOwnershipDescription(payload) && this.ownsManagedResource(key, payload);
    const expectedNetwork = networkName(spec);
    const expectedSubnet = subnetName(spec);
    const networkSuffix = `/projects/${spec.project_id}/global/networks/${expectedNetwork}`;
    const subnetSuffix = `/regions/${spec.region}/subnetworks/${expectedSubnet}`;

    if (resourceType === "network") {
      const selfLink = payload.selfLink;
      const project = spec.network_strategy === "dedicated"
        ? spec.project_id
        : upstreamProjectId(spec);
      const expectedPath = `/compute/v1/projects/${project}/global/networks/${expectedNetwork}`;
      const identity = payload.name === expectedNetwork &&
        (typeof selfLink !== "string" || selfLink.endsWith(expectedPath));
      if (spec.network_strategy === "existing") return identity;
      return identity && payload.autoCreateSubnetworks === false &&
        compatibleRoutingConfig(payload.routingConfig) &&
        managedCompute();
    }

    if (resourceType === "source_image") {
      const deprecated = payload.deprecated as Record<string, unknown> | undefined;
      const state = deprecated?.state;
      const selfLink = payload.selfLink;
      const identifier = payload.id;
      const id = typeof identifier === "string"
        ? identifier
        : typeof identifier === "number" && Number.isSafeInteger(identifier)
          ? String(identifier)
          : "";
      const canonicalSelfLink = `https://www.googleapis.com/compute/v1/${resourceName}`;
      const compatible = payload.name === resourceName.split("/").pop() &&
        selfLink === canonicalSelfLink && /^[1-9][0-9]*$/.test(id) &&
        state !== "OBSOLETE" && state !== "DELETED";
      if (compatible) {
        this.sourceImageBinding = {
          name: resourceName,
          id,
          self_link: canonicalSelfLink,
        };
      }
      return compatible;
    }

    if (resourceType === "subnetwork") {
      const network = payload.network;
      const selfLink = payload.selfLink;
      const proxyOnly = resourceName.endsWith("-proxy-subnet");
      const managed = spec.network_strategy === "dedicated" || proxyOnly;
      return typeof network === "string" &&
        network.endsWith(networkSuffix) &&
        payload.name === resourceName &&
        // subnet_cidr is a creation input for a run-owned dedicated subnet.
        // Existing subnets are selected by name and discovered from Compute;
        // the UI has no CIDR field for them, so the hidden creation default
        // must not reject an otherwise-compatible administrator resource.
        (!managed || payload.ipCidrRange === (proxyOnly ? spec.proxy_subnet_cidr : spec.subnet_cidr)) &&
        payload.privateIpGoogleAccess === !proxyOnly && payload.stackType === "IPV4_ONLY" &&
        (!proxyOnly || (payload.purpose === "REGIONAL_MANAGED_PROXY" && payload.role === "ACTIVE")) &&
        (!managed || managedCompute()) &&
        (typeof selfLink !== "string" || selfLink.endsWith(
          `/compute/v1/projects/${spec.project_id}/regions/${spec.region}` +
            `/subnetworks/${resourceName}`,
        ));
    }

    if (resourceType === "router") {
      return payload.name === resourceName && typeof payload.network === "string" &&
        payload.network.endsWith(networkSuffix) && managedCompute();
    }

    if (resourceType === "service_account") {
      return payload.email === `${resourceName}@${spec.project_id}.iam.gserviceaccount.com` &&
        typeof payload.uniqueId === "string" && payload.uniqueId !== "" &&
        hasSgsOwnershipDescription(payload) && this.ownsManagedResource(key, payload);
    }

    if (resourceType === "secret") {
      if (payload.name !== `projects/${spec.project_id}/secrets/${resourceName}`) return false;
      if (spec.certificate_strategy === "public_trusted") return true;
      const labels = stringMap(payload.labels);
      const replication = payload.replication;
      return labels !== null && labels["managed-by"] === "secure-gateway-studio" &&
        typeof labels["sgs-owner-token"] === "string" && labels["sgs-owner-token"] !== "" &&
        this.ownsManagedResource(key, payload) &&
        typeof replication === "object" && replication !== null && !Array.isArray(replication) &&
        typeof (replication as Record<string, unknown>).automatic === "object";
    }

    if (resourceType === "internal_address") {
      return payload.name === resourceName && payload.addressType === "INTERNAL" &&
        typeof payload.address === "string" && payload.address !== "" &&
        typeof payload.subnetwork === "string" && payload.subnetwork.endsWith(subnetSuffix) &&
        managedCompute();
    }

    if (resourceType === "instance") {
      return managedCompute() && await privateManagedVm(payload, spec, resourceName, {
        template: false,
        transport: this.transport,
        sourceImageBinding: this.sourceImageBinding,
        expectedAddress: this.discoveredAddresses.get(
          `compute:internal_address:${resourceName}-ip`,
        ),
        publicCertificateVersionName: this.publicCertificateVersionName,
        backendAddress: this.discoveredAddresses.get(
          `compute:internal_address:${spec.name}-backend-ip`,
        ),
      });
    }

    if (resourceType === "instance_template") {
      const properties = payload.properties;
      return managedCompute() && typeof properties === "object" && properties !== null &&
        !Array.isArray(properties) &&
        await privateManagedVm(properties as Record<string, unknown>, spec, resourceName, {
          template: true,
          transport: this.transport,
          sourceImageBinding: this.sourceImageBinding,
          publicCertificateVersionName: this.publicCertificateVersionName,
          backendAddress: this.discoveredAddresses.get(
            `compute:internal_address:${spec.name}-backend-ip`,
          ),
        });
    }

    if (resourceType === "health_check") {
      if (spec.backend_kind === "internal_https_lb") {
        const http = payload.httpHealthCheck as Record<string, unknown> | undefined;
        return this.ownsManagedResource(key, payload) && payload.name === resourceName &&
          payload.type === "HTTP" && payload.checkIntervalSec === 10 &&
          payload.timeoutSec === 5 && payload.healthyThreshold === 2 &&
          payload.unhealthyThreshold === 3 && http?.portSpecification === "USE_SERVING_PORT" &&
          http.requestPath === "/";
      }
      const ssl = payload.sslHealthCheck;
      return managedCompute() && payload.name === resourceName && payload.type === "SSL" &&
        payload.checkIntervalSec === 10 && payload.timeoutSec === 5 &&
        payload.healthyThreshold === 2 && payload.unhealthyThreshold === 3 &&
        compatibleSslHealthCheck(ssl);
    }

    if (resourceType === "instance_group") {
      if (!this.ownsManagedResource(key, payload) || payload.name !== resourceName ||
        canonicalJson(payload.namedPorts) !== canonicalJson([{ name: "http", port: 80 }])) {
        return false;
      }
      const members = await this.transport.requestJson(
        "POST",
        `${COMPUTE}/projects/${spec.project_id}/zones/${spec.zone}` +
          `/instanceGroups/${resourceName}/listInstances`,
        { params: { maxResults: 2 }, jsonBody: { instanceState: "ALL" } },
      );
      const items = members.payload.items;
      return Array.isArray(items) && items.length === 1 &&
        typeof items[0] === "object" && items[0] !== null &&
        typeof (items[0] as Record<string, unknown>).instance === "string" &&
        String((items[0] as Record<string, unknown>).instance).endsWith(
          `/projects/${spec.project_id}/zones/${spec.zone}/instances/${spec.name}-backend`,
        );
    }

    if (resourceType === "instance_group_manager") {
      const policy = payload.distributionPolicy;
      const zones = typeof policy === "object" && policy !== null && !Array.isArray(policy)
        ? (policy as Record<string, unknown>).zones
        : null;
      if (!Array.isArray(zones)) return false;
      const zoneNames = new Set(zones.map((zone) =>
        typeof zone === "object" && zone !== null && !Array.isArray(zone) &&
          typeof (zone as Record<string, unknown>).zone === "string"
          ? ((zone as Record<string, string>).zone.split("/").pop() ?? "")
          : ""
      ));
      const versions = payload.versions;
      const namedPorts = payload.namedPorts;
      const updatePolicy = payload.updatePolicy;
      return managedCompute() && payload.name === resourceName &&
        payload.baseInstanceName === `${spec.name}-offload` &&
        payload.targetSize === spec.offload_min_replicas &&
        zoneNames.size === 2 && zoneNames.has(spec.zone) && zoneNames.has(spec.secondary_zone) &&
        typeof policy === "object" && policy !== null && !Array.isArray(policy) &&
        (policy as Record<string, unknown>).targetShape === "EVEN" &&
        Array.isArray(versions) && versions.length === 1 &&
        typeof versions[0] === "object" && versions[0] !== null &&
        (versions[0] as Record<string, unknown>).name === "primary" &&
        typeof (versions[0] as Record<string, unknown>).instanceTemplate === "string" &&
        String((versions[0] as Record<string, unknown>).instanceTemplate).endsWith(
          `/global/instanceTemplates/${spec.name}-offload-template`,
        ) && canonicalJson(namedPorts) === canonicalJson([{ name: "https", port: 443 }]) &&
        compatibleMigUpdatePolicy(updatePolicy);
    }

    if (resourceType === "autoscaler") {
      const policy = payload.autoscalingPolicy;
      const cpu = typeof policy === "object" && policy !== null && !Array.isArray(policy)
        ? (policy as Record<string, unknown>).cpuUtilization
        : null;
      return managedCompute() && payload.name === resourceName &&
        typeof payload.target === "string" && payload.target.endsWith(
          `/regions/${spec.region}/instanceGroupManagers/${spec.name}-offload-mig`,
        ) && typeof policy === "object" && policy !== null &&
        !Array.isArray(policy) &&
        (policy as Record<string, unknown>).minNumReplicas === spec.offload_min_replicas &&
        (policy as Record<string, unknown>).maxNumReplicas === spec.offload_max_replicas &&
        (policy as Record<string, unknown>).coolDownPeriodSec === 90 &&
        (policy as Record<string, unknown>).mode === "ON" &&
        typeof cpu === "object" && cpu !== null && !Array.isArray(cpu) &&
        (cpu as Record<string, unknown>).utilizationTarget === spec.offload_cpu_target;
    }

    if (resourceType === "backend_service") {
      const backends = payload.backends;
      const healthChecks = payload.healthChecks;
      if (spec.backend_kind === "internal_https_lb") {
        return this.ownsManagedResource(key, payload) && payload.name === resourceName &&
          payload.protocol === "HTTP" && payload.portName === "http" &&
          payload.loadBalancingScheme === "INTERNAL_MANAGED" && payload.timeoutSec === 10 &&
          Array.isArray(backends) && backends.length === 1 &&
          typeof backends[0] === "object" && backends[0] !== null &&
          (backends[0] as Record<string, unknown>).balancingMode === "UTILIZATION" &&
          String((backends[0] as Record<string, unknown>).group).endsWith(
            `/zones/${spec.zone}/instanceGroups/${spec.name}-backend-ig`,
          ) && Array.isArray(healthChecks) && healthChecks.length === 1 &&
          String(healthChecks[0]).endsWith(`/regions/${spec.region}/healthChecks/${spec.name}-ilb-hc`);
      }
      return managedCompute() && payload.name === resourceName && payload.protocol === "TCP" &&
        payload.loadBalancingScheme === "INTERNAL" &&
        payload.timeoutSec === 10 &&
        Array.isArray(backends) && backends.length === 1 &&
        typeof backends[0] === "object" && backends[0] !== null &&
        typeof (backends[0] as Record<string, unknown>).group === "string" &&
        ((backends[0] as Record<string, string>).group).endsWith(
          `/regions/${spec.region}/instanceGroups/${spec.name}-offload-mig`,
        ) && Array.isArray(healthChecks) && healthChecks.length === 1 &&
        typeof healthChecks[0] === "string" &&
        healthChecks[0].endsWith(`/regions/${spec.region}/healthChecks/${spec.name}-offload-hc`);
    }

    if (resourceType === "forwarding_rule") {
      const expectedAddress = this.discoveredAddresses.get(
        `compute:internal_address:${spec.name}-offload-ip`,
      );
      if (spec.backend_kind === "internal_https_lb") {
        return this.ownsManagedResource(key, payload) && payload.name === resourceName &&
          typeof expectedAddress === "string" && payload.IPAddress === expectedAddress &&
          payload.IPProtocol === "TCP" && payload.loadBalancingScheme === "INTERNAL_MANAGED" &&
          payload.allowGlobalAccess === true && canonicalJson(payload.ports) === canonicalJson(["443"]) &&
          payload.networkTier === "PREMIUM" && typeof payload.target === "string" &&
          payload.target.endsWith(`/regions/${spec.region}/targetHttpsProxies/${spec.name}-ilb-proxy`);
      }
      return managedCompute() && payload.name === resourceName &&
        typeof expectedAddress === "string" && payload.IPAddress === expectedAddress &&
        payload.IPProtocol === "TCP" &&
        payload.loadBalancingScheme === "INTERNAL" && payload.allowGlobalAccess === true &&
        Array.isArray(payload.ports) && payload.ports.length === 1 &&
        String(payload.ports[0]) === "443" &&
        typeof payload.network === "string" && payload.network.endsWith(networkSuffix) &&
        typeof payload.subnetwork === "string" && payload.subnetwork.endsWith(subnetSuffix) &&
        typeof payload.backendService === "string" && payload.backendService.endsWith(
          `/regions/${spec.region}/backendServices/${spec.name}-offload-bs`,
        );
    }

    if (resourceType === "ssl_certificate") {
      return this.ownsManagedResource(key, payload) && payload.name === resourceName &&
        typeof payload.description === "string" && payload.description.endsWith(
          `; Managed by Secure Gateway Studio; configuration ${configurationHash(spec)}`,
        ) &&
        typeof payload.certificate === "string";
    }

    if (resourceType === "url_map") {
      return this.ownsManagedResource(key, payload) && payload.name === resourceName &&
        typeof payload.defaultService === "string" && payload.defaultService.endsWith(
          `/regions/${spec.region}/backendServices/${spec.name}-ilb-bs`,
        );
    }

    if (resourceType === "target_https_proxy") {
      return this.ownsManagedResource(key, payload) && payload.name === resourceName &&
        typeof payload.urlMap === "string" && payload.urlMap.endsWith(
          `/regions/${spec.region}/urlMaps/${spec.name}-ilb-map`,
        ) && Array.isArray(payload.sslCertificates) && payload.sslCertificates.length === 1 &&
        String(payload.sslCertificates[0]).endsWith(
          `/regions/${spec.region}/sslCertificates/${spec.name}-ilb-cert`,
        );
    }

    if (resourceType === "firewall_rule") {
      return managedCompute() && compatibleFirewall(resourceName, payload, spec);
    }

    if (resourceType === "private_zone") {
      const networks = typeof payload.privateVisibilityConfig === "object" &&
          payload.privateVisibilityConfig !== null && !Array.isArray(payload.privateVisibilityConfig)
        ? (payload.privateVisibilityConfig as Record<string, unknown>).networks
        : null;
      return hasSgsOwnershipDescription(payload) && this.ownsManagedResource(key, payload) &&
        payload.visibility === "private" &&
        payload.dnsName === `${spec.private_hostname}.` && Array.isArray(networks) &&
        networks.length === 1 && typeof networks[0] === "object" && networks[0] !== null &&
        (networks[0] as Record<string, unknown>).networkUrl ===
          `https://www.googleapis.com/compute/v1/projects/${spec.project_id}` +
            `/global/networks/${expectedNetwork}`;
    }

    if (resourceType === "access_level") {
      return payload.name === resourceName && isCanonicalManagedChromeAccessLevel(payload);
    }

    if (resourceType === "security_gateway") {
      return this.ownsManagedResource(key, payload) &&
        isCompatibleSecurityGatewayPayload(payload, spec);
    }

    if (resourceType === "application") {
      return this.ownsManagedResource(key, payload) &&
        isCompatibleBeyondCorpApplicationPayload(payload, spec, resourceName);
    }

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
    const seenPageTokens = new Set<string>();
    const matches: Array<{ allowGlobalAccess: boolean; forwardingRule: string }> = [];
    for (let page = 0; page < 10; page += 1) {
      const params: Record<string, string | number> = {
        maxResults: 500,
        returnPartialSuccess: "true",
      };
      if (pageToken) params.pageToken = pageToken;
      const response = await this.transport.requestJson(
        "GET",
        "https://compute.googleapis.com/compute/v1/projects/" +
          `${upstreamProjectId(spec)}/aggregated/forwardingRules`,
        { params },
      );
      const unreachables = response.payload.unreachables;
      if (
        unreachables !== undefined &&
        (!Array.isArray(unreachables) ||
          !unreachables.every((item) => typeof item === "string" && item !== ""))
      ) {
        throw new Error("Forwarding-rule response unreachables is malformed");
      }
      if (Array.isArray(unreachables) && unreachables.length > 0) {
        throw new Error("Forwarding-rule discovery returned unreachable scopes");
      }
      const items = response.payload.items;
      if (
        items !== undefined &&
        (items === null || typeof items !== "object" || Array.isArray(items))
      ) {
        throw new Error("Forwarding-rule response items is malformed");
      }
      if (items !== undefined) {
        for (const [scopeName, scope] of Object.entries(items as Record<string, unknown>)) {
          if (scopeName !== "global" && !scopeName.startsWith("regions/")) {
            throw new Error("Forwarding-rule response contains an invalid scope identity");
          }
          if (typeof scope !== "object" || scope === null || Array.isArray(scope)) {
            throw new Error("Forwarding-rule response contains a malformed scope");
          }
          const rules = (scope as { forwardingRules?: unknown }).forwardingRules;
          if (rules === undefined) continue;
          if (!Array.isArray(rules)) {
            throw new Error("Forwarding-rule response contains a malformed collection");
          }
          for (const rawRule of rules) {
            if (typeof rawRule !== "object" || rawRule === null || Array.isArray(rawRule)) {
              throw new Error("Forwarding-rule response contains a malformed rule");
            }
            const rule = rawRule as {
              IPAddress?: unknown;
              name?: unknown;
              allowGlobalAccess?: unknown;
              loadBalancingScheme?: unknown;
              IPProtocol?: unknown;
              ports?: unknown;
              portRange?: unknown;
            };
            if (typeof rule.IPAddress !== "string" || !isIpLiteral(rule.IPAddress)) {
              throw new Error("Forwarding-rule response contains an invalid IPAddress");
            }
            if (typeof rule.name !== "string" || rule.name === "") {
              throw new Error("Forwarding-rule response contains an invalid identity");
            }
            if (!sameAddress(rule.IPAddress, host)) continue;
            const expectedPort = String(applicationPort(spec));
            const portMatches =
              (Array.isArray(rule.ports) && rule.ports.length === 1 &&
                rule.ports[0] === expectedPort) ||
              rule.portRange === expectedPort ||
              rule.portRange === `${expectedPort}-${expectedPort}`;
            const allowGlobalAccess = rule.allowGlobalAccess ?? false;
            if (
              !scopeName.startsWith("regions/") ||
              !["INTERNAL", "INTERNAL_MANAGED"].includes(
                String(rule.loadBalancingScheme),
              ) ||
              rule.IPProtocol !== "TCP" || !portMatches ||
              typeof allowGlobalAccess !== "boolean"
            ) {
              throw new Error(
                "The application forwarding rule does not have exact internal TCP semantics",
              );
            }
            matches.push({
              allowGlobalAccess,
              forwardingRule: rule.name,
            });
          }
        }
      }
      const next = response.payload.nextPageToken;
      if (next === undefined || next === "") {
        if (matches.length === 0) {
          return { allowGlobalAccess: null, forwardingRule: null };
        }
        if (matches.length !== 1) {
          throw new Error("Multiple forwarding rules use the application address");
        }
        return matches[0]!;
      }
      if (typeof next !== "string") {
        throw new Error("Forwarding-rule pagination returned an invalid page token");
      }
      if (seenPageTokens.has(next)) {
        throw new Error("Forwarding-rule pagination repeated a page token");
      }
      seenPageTokens.add(next);
      pageToken = next;
    }
    throw new Error("Forwarding-rule pagination exceeded the 10-page safety limit");
  }
}

function compareVersions(left: string, right: string): number {
  const parts = (value: string): Array<number | string> =>
    value.replace(/-/g, ".").split(".").map((part) =>
      /^\d+$/.test(part) ? Number(part) : part
    );
  const leftParts = parts(left);
  const rightParts = parts(right);
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const a = leftParts[index] ?? 0;
    const b = rightParts[index] ?? 0;
    if (a === b) continue;
    if (typeof a === "number" && typeof b === "number") return a < b ? -1 : 1;
    return String(a).localeCompare(String(b));
  }
  return 0;
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

function stringMap(value: unknown): Record<string, string> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const entries = Object.entries(value);
  if (entries.some(([, item]) => typeof item !== "string")) return null;
  return Object.fromEntries(entries) as Record<string, string>;
}

function hasSgsOwnershipDescription(payload: Record<string, unknown>): boolean {
  const description = payload.description;
  if (typeof description !== "string" || !description.startsWith(OWNERSHIP_DESCRIPTION_PREFIX)) {
    return false;
  }
  const token = description.slice(OWNERSHIP_DESCRIPTION_PREFIX.length).split(";", 1)[0];
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    .test(token);
}

async function privateManagedVm(
  payload: Record<string, unknown>,
  spec: DeploymentSpec,
  resourceName: string,
  options: {
    template: boolean;
    transport: Transport;
    sourceImageBinding?: SourceImageBinding;
    expectedAddress?: string;
    backendAddress?: string;
    publicCertificateVersionName?: string;
  },
): Promise<boolean> {
  const labels = stringMap(payload.labels);
  const interfaces = payload.networkInterfaces;
  const accounts = payload.serviceAccounts;
  const role = resourceName.endsWith("-backend") ? "backend" : "offload";
  if (
    labels === null || canonicalJson(labels) !== canonicalJson({
      "managed-by": "secure-gateway-studio",
      role,
    }) || !Array.isArray(interfaces) || interfaces.length !== 1 ||
    !Array.isArray(accounts) || accounts.length !== 1
  ) return false;
  if (!options.template && payload.name !== resourceName) return false;
  const expectedMachine = options.template
    ? "e2-small"
    : `zones/${spec.zone}/machineTypes/e2-small`;
  if (
    typeof payload.machineType !== "string" ||
    !(payload.machineType === expectedMachine || payload.machineType.endsWith(`/${expectedMachine}`))
  ) return false;

  const disks = payload.disks;
  if (!Array.isArray(disks) || disks.length !== 1) return false;
  const disk = disks[0];
  if (typeof disk !== "object" || disk === null || Array.isArray(disk)) return false;
  const typedDisk = disk as Record<string, unknown>;
  const binding = options.sourceImageBinding;
  if (
    !spec.source_image || !binding || binding.name !== spec.source_image ||
    typedDisk.autoDelete !== true || typedDisk.boot !== true
  ) return false;
  if (options.template) {
    const initialize = typedDisk.initializeParams;
    if (typeof initialize !== "object" || initialize === null || Array.isArray(initialize)) {
      return false;
    }
    const init = initialize as Record<string, unknown>;
    if (
      init.diskSizeGb !== "20" || typeof init.diskType !== "string" ||
      !(init.diskType === "pd-balanced" || init.diskType.endsWith("/pd-balanced")) ||
      init.sourceImage !== spec.source_image
    ) return false;
  } else {
    const diskPath =
      `/projects/${spec.project_id}/zones/${spec.zone}/disks/${resourceName}`;
    if (
      (typedDisk.type !== undefined && typedDisk.type !== "PERSISTENT") ||
      (typedDisk.mode !== undefined && typedDisk.mode !== "READ_WRITE") ||
      typeof typedDisk.source !== "string" || !typedDisk.source.endsWith(diskPath)
    ) return false;
    const diskResponse = await options.transport.requestJson(
      "GET",
      `${COMPUTE}${diskPath}`,
      { acceptedStatuses: [404] },
    );
    if (diskResponse.status !== 200) return false;
    const current = diskResponse.payload;
    if (
      current.name !== resourceName ||
      typeof current.selfLink !== "string" || !current.selfLink.endsWith(diskPath) ||
      typeof current.zone !== "string" ||
      !current.zone.endsWith(`/projects/${spec.project_id}/zones/${spec.zone}`) ||
      current.status !== "READY" || String(current.sizeGb) !== "20" ||
      typeof current.type !== "string" ||
      !current.type.endsWith(
        `/projects/${spec.project_id}/zones/${spec.zone}/diskTypes/pd-balanced`,
      ) ||
      typeof current.sourceImage !== "string" ||
      !current.sourceImage.endsWith(`/${spec.source_image}`) ||
      String(current.sourceImageId) !== binding.id
    ) return false;
  }

  const networkInterface = interfaces[0];
  if (
    typeof networkInterface !== "object" || networkInterface === null ||
    Array.isArray(networkInterface)
  ) return false;
  const typedInterface = networkInterface as Record<string, unknown>;
  if (
    typedInterface.accessConfigs !== undefined &&
    (!Array.isArray(typedInterface.accessConfigs) || typedInterface.accessConfigs.length !== 0)
  ) return false;
  if (
    typeof typedInterface.network !== "string" ||
    !typedInterface.network.endsWith(`/global/networks/${networkName(spec)}`) ||
    typeof typedInterface.subnetwork !== "string" ||
    !typedInterface.subnetwork.endsWith(`/regions/${spec.region}/subnetworks/${subnetName(spec)}`)
  ) return false;
  if (typedInterface.stackType !== "IPV4_ONLY") return false;
  if (options.template) {
    if (typedInterface.networkIP !== undefined) return false;
  } else if (
    typeof options.expectedAddress !== "string" || options.expectedAddress === "" ||
    typedInterface.networkIP !== options.expectedAddress
  ) return false;

  const account = accounts[0];
  if (typeof account !== "object" || account === null || Array.isArray(account)) return false;
  const typedAccount = account as Record<string, unknown>;
  if (
    typedAccount.email !== serviceAccountEmail(spec.name, spec.project_id, role) ||
    canonicalJson(typedAccount.scopes) !==
      canonicalJson(["https://www.googleapis.com/auth/cloud-platform"])
  ) return false;

  const shielded = payload.shieldedInstanceConfig;
  if (
    canonicalJson(shielded) !== canonicalJson({
      enableIntegrityMonitoring: true,
      enableSecureBoot: true,
      enableVtpm: true,
    })
  ) return false;
  const tags = payload.tags;
  if (typeof tags !== "object" || tags === null || Array.isArray(tags)) return false;
  const typedTags = tags as Record<string, unknown>;
  if (
    !Object.keys(typedTags).every((key) => key === "items" || key === "fingerprint") ||
    canonicalJson(typedTags.items) !== canonicalJson([`${spec.name}-${role}`]) ||
    (typedTags.fingerprint !== undefined &&
      (typeof typedTags.fingerprint !== "string" || typedTags.fingerprint === ""))
  ) {
    return false;
  }
  if (!options.template && payload.deletionProtection !== false) return false;

  const metadata = payload.metadata;
  if (typeof metadata !== "object" || metadata === null || Array.isArray(metadata)) return false;
  const items = (metadata as Record<string, unknown>).items;
  if (!Array.isArray(items) || items.length !== 2) return false;
  const metadataMap = new Map<string, string>();
  for (const item of items) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) return false;
    const key = (item as Record<string, unknown>).key;
    const value = (item as Record<string, unknown>).value;
    if (typeof key !== "string" || typeof value !== "string" || metadataMap.has(key)) {
      return false;
    }
    metadataMap.set(key, value);
  }
  if (
    metadataMap.size !== 2 || metadataMap.get("enable-guest-attributes") !== "TRUE"
  ) return false;
  let expectedScript: string;
  if (role === "backend") {
    expectedScript = sampleBackendStartupScript(spec);
  } else {
    if (spec.backend_kind === "managed_sample" && !options.backendAddress) return false;
    if (
      spec.certificate_strategy === "public_trusted" &&
      !options.publicCertificateVersionName
    ) return false;
    expectedScript = offloadStartupScript(spec, {
      backendAddress: options.backendAddress,
      publicCertificateVersionName: options.publicCertificateVersionName,
    });
  }
  return metadataMap.get("startup-script") === expectedScript;
}

function compatibleSslHealthCheck(value: unknown): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const detail = value as Record<string, unknown>;
  const allowed = new Set([
    "port",
    "portName",
    "portSpecification",
    "proxyHeader",
    "request",
    "response",
  ]);
  return Object.keys(detail).every((key) => allowed.has(key)) &&
    (detail.port === undefined || detail.port === 443) &&
    (detail.portName === undefined || detail.portName === "") &&
    (detail.portSpecification === undefined || detail.portSpecification === "USE_FIXED_PORT") &&
    (detail.proxyHeader === undefined || detail.proxyHeader === "NONE") &&
    (detail.request === undefined || detail.request === "") &&
    (detail.response === undefined || detail.response === "");
}

function compatibleFirewall(
  resourceName: string,
  payload: Record<string, unknown>,
  spec: DeploymentSpec,
): boolean {
  if (
    payload.name !== resourceName || payload.direction !== "INGRESS" ||
    payload.priority !== 1000 || payload.disabled !== false ||
    typeof payload.network !== "string" ||
    !payload.network.endsWith(`/projects/${spec.project_id}/global/networks/${networkName(spec)}`) ||
    canonicalJson(payload.logConfig) !== canonicalJson({
      enable: true,
      metadata: "INCLUDE_ALL_METADATA",
    }) ||
    (payload.denied !== undefined &&
      (!Array.isArray(payload.denied) || payload.denied.length !== 0))
  ) return false;
  const allowed = payload.allowed;
  if (!Array.isArray(allowed) || allowed.length !== 1) return false;
  const entry = allowed[0];
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return false;
  const typedEntry = entry as Record<string, unknown>;
  if (typedEntry.IPProtocol !== "tcp" || !Array.isArray(typedEntry.ports)) return false;
  if (typedEntry.ports.some((item) => typeof item !== "string")) return false;
  const ports = typedEntry.ports;
  const strictStrings = (value: unknown): string[] | null => {
    if (value === undefined) return [];
    if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) return null;
    return value as string[];
  };
  const sourceRanges = strictStrings(payload.sourceRanges);
  const sourceAccounts = strictStrings(payload.sourceServiceAccounts);
  const targetAccounts = strictStrings(payload.targetServiceAccounts);
  if (sourceRanges === null || sourceAccounts === null || targetAccounts === null) return false;
  if (resourceName.endsWith("-gateway-ingress")) {
    return canonicalJson(ports) === canonicalJson(["443"]) &&
      canonicalJson(sourceRanges) === canonicalJson([SECURE_GATEWAY_SOURCE_RANGE]) &&
      sourceAccounts.length === 0 &&
      canonicalJson(targetAccounts) === canonicalJson([
        serviceAccountEmail(spec.name, spec.project_id, "offload"),
      ]);
  }
  if (resourceName.endsWith("-health-check-ingress")) {
    return canonicalJson(ports) === canonicalJson(["443"]) &&
      canonicalJson([...sourceRanges].sort()) ===
        canonicalJson([...GOOGLE_HEALTH_CHECK_SOURCE_RANGES].sort()) &&
      sourceAccounts.length === 0 &&
      canonicalJson(targetAccounts) === canonicalJson([
        serviceAccountEmail(spec.name, spec.project_id, "offload"),
      ]);
  }
  if (resourceName.endsWith("-backend-ingress")) {
    return canonicalJson(ports) === canonicalJson(["80"]) &&
      sourceRanges.length === 0 &&
      canonicalJson(sourceAccounts) === canonicalJson([
        serviceAccountEmail(spec.name, spec.project_id, "offload"),
      ]) && canonicalJson(targetAccounts) === canonicalJson([
        serviceAccountEmail(spec.name, spec.project_id, "backend"),
      ]);
  }
  return false;
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
  const bindings = policy.bindings ?? [];
  if (!Array.isArray(bindings)) throw new Error("IAM policy bindings is malformed");
  for (const entry of bindings) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new Error("IAM policy contains a malformed binding");
    }
    const binding = entry as Record<string, unknown>;
    if (
      typeof binding.role !== "string" || binding.role === "" ||
      !Array.isArray(binding.members) ||
      !binding.members.every((member) => typeof member === "string" && member !== "") ||
      (binding.condition !== undefined &&
        (typeof binding.condition !== "object" || binding.condition === null ||
          Array.isArray(binding.condition)))
    ) {
      throw new Error("IAM policy contains a malformed binding");
    }
  }
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
