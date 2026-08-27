/**
 * Path A resource handlers: the network and offload tier.
 *
 * Split from `executor.ts` because Path A roughly doubles the provider surface
 * and the two paths share nothing below the transport. Keeping them apart makes
 * it obvious which handlers a given deployment can reach.
 *
 * Two Path A types are deliberately absent and throw rather than silently doing
 * nothing:
 *
 *   - `compute:instance` and `compute:instance_template` embed the Nginx
 *     startup script, a large verbatim asset that must be shared with the
 *     Python implementation rather than retyped. Duplicating it would create
 *     two subtly different offload configurations with no test able to see the
 *     difference.
 *   - `secretmanager:secret_version` and `local:root_certificate_artifact`
 *     depend on the WebCrypto certificate work.
 *
 * Both are tracked in the migration plan. An explicit refusal keeps the gap
 * visible; a stub would let Apply report success having built nothing.
 */

import {
  GoogleApiError,
  ProviderExecutionError,
  isConfirmedIamEtagConflict,
  isDefiniteMutationRejection,
  type Transport,
} from "./executor.ts";
import { canonicalJson } from "../domain/canonical.ts";
import { validatedIamPolicy } from "../domain/iam-policy.ts";
import {
  configurationHash,
  type PublicCertificateBinding,
  type ResourceChange,
  type SourceImageBinding,
} from "../domain/planner.ts";
import { serviceAccountEmail, serviceAccountId } from "../domain/naming.ts";
import type { DeploymentSpec } from "../domain/spec.ts";
import type { CertificateBundle } from "./certificates.ts";
import { validatePublicCertificateAccessResponse } from "./certificates.ts";
import { offloadStartupScript, sampleBackendStartupScript } from "./startup-scripts.ts";
import { applyProduction } from "./executor-production.ts";

const COMPUTE = "https://compute.googleapis.com/compute/v1";
const SECURE_GATEWAY_SOURCE_RANGE = "136.124.16.0/20";
const GOOGLE_HEALTH_CHECK_SOURCE_RANGES = ["35.191.0.0/16", "130.211.0.0/22"];
const MANAGED_BY = "Managed by Secure Gateway Studio";

export async function revalidatePublicCertificateBinding(
  transport: Transport,
  spec: DeploymentSpec,
  binding: PublicCertificateBinding | null | undefined,
): Promise<string | undefined> {
  if (spec.certificate_strategy !== "public_trusted") return undefined;
  const secretName = spec.public_certificate_secret?.split("/").pop();
  const expectedPrefix =
    `projects/${spec.project_id}/secrets/${secretName ?? ""}/versions/`;
  if (
    secretName === undefined || secretName === "" || binding === undefined ||
    binding === null ||
    !binding.secret_version_name.startsWith(expectedPrefix) ||
    !/^[1-9][0-9]*$/.test(
      binding.secret_version_name.slice(expectedPrefix.length),
    ) || !/^[0-9a-f]{64}$/.test(binding.payload_sha256)
  ) {
    throw new ProviderExecutionError("public-certificate-plan-binding-invalid");
  }
  const response = await transport.requestJson(
    "GET",
    `https://secretmanager.googleapis.com/v1/projects/${spec.project_id}` +
      `/secrets/${secretName}/versions/latest:access`,
  );
  // The alias response itself carries the immutable numeric resource name.
  // Validate that name and the exact approved bytes, then embed only the
  // numeric name in VM startup so boot never consumes the mutable alias.
  await validatePublicCertificateAccessResponse(response.payload, {
    projectId: spec.project_id,
    secretName,
    hostname: spec.private_hostname,
    minimumValidityDays: spec.mode === "production" ? 30 : 1,
    expectedVersionName: binding.secret_version_name,
    expectedPayloadSha256: binding.payload_sha256,
  });
  return binding.secret_version_name;
}

/**
 * Scope one durable step UUID to a distinct Compute mutation.
 *
 * Compute requires a unique requestId for each request. Changing only the last
 * byte preserves the UUID version/variant bits while producing stable,
 * different tokens for the stop and start calls on every worker retry.
 */
export function computeRefreshRequestId(
  requestId: string,
  phase: "stop" | "start",
): string {
  const compact = requestId.replaceAll("-", "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(compact)) {
    throw new ProviderExecutionError("compute-request-id-invalid");
  }
  const mask = phase === "stop" ? 0xa5 : 0x5a;
  const lastByte = (Number.parseInt(compact.slice(-2), 16) ^ mask)
    .toString(16)
    .padStart(2, "0");
  const scoped = `${compact.slice(0, -2)}${lastByte}`;
  return `${scoped.slice(0, 8)}-${scoped.slice(8, 12)}-${scoped.slice(12, 16)}-` +
    `${scoped.slice(16, 20)}-${scoped.slice(20)}`;
}

export type OffloadRefreshPhase =
  | "prepared"
  | "stop_sending"
  | "restart_rejected"
  | "stopped"
  | "start_sending"
  | "applied";

/** Durable state for the PoC VM stop/start certificate refresh saga. */
export interface OffloadRefreshCheckpoint {
  kind: "offload_refresh";
  phase: OffloadRefreshPhase;
  instanceUrl: string;
  stopRequestId: string;
  startRequestId: string;
}

const OFFLOAD_REFRESH_PHASES = new Set<OffloadRefreshPhase>([
  "prepared",
  "stop_sending",
  "stopped",
  "start_sending",
  "applied",
]);

const COMPUTE_INSTANCE_STATUSES = new Set([
  "PROVISIONING",
  "STAGING",
  "RUNNING",
  "STOPPING",
  "SUSPENDING",
  "SUSPENDED",
  "REPAIRING",
  "TERMINATED",
]);

function offloadInstanceUrl(spec: DeploymentSpec): string {
  return `${COMPUTE}/projects/${spec.project_id}/zones/${spec.zone}/instances/` +
    `${spec.name}-offload`;
}

function expectedOffloadRefreshCheckpoint(
  spec: DeploymentSpec,
  requestId: string,
): OffloadRefreshCheckpoint {
  return {
    kind: "offload_refresh",
    phase: "prepared",
    instanceUrl: offloadInstanceUrl(spec),
    stopRequestId: computeRefreshRequestId(requestId, "stop"),
    startRequestId: computeRefreshRequestId(requestId, "start"),
  };
}

function validateOffloadRefreshCheckpoint(
  value: unknown,
  spec: DeploymentSpec,
  requestId: string,
): OffloadRefreshCheckpoint {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProviderExecutionError("offload-refresh-checkpoint-invalid");
  }
  const checkpoint = value as Partial<OffloadRefreshCheckpoint>;
  const expected = expectedOffloadRefreshCheckpoint(spec, requestId);
  if (
    checkpoint.kind !== "offload_refresh" ||
    typeof checkpoint.phase !== "string" ||
    !OFFLOAD_REFRESH_PHASES.has(checkpoint.phase as OffloadRefreshPhase) ||
    checkpoint.instanceUrl !== expected.instanceUrl ||
    checkpoint.stopRequestId !== expected.stopRequestId ||
    checkpoint.startRequestId !== expected.startRequestId
  ) {
    throw new ProviderExecutionError("offload-refresh-checkpoint-invalid");
  }
  return structuredClone(checkpoint as OffloadRefreshCheckpoint);
}

async function readOffloadInstanceStatus(
  transport: Transport,
  instanceUrl: string,
): Promise<string> {
  const status = (await transport.requestJson("GET", instanceUrl)).payload.status;
  if (typeof status !== "string" || !COMPUTE_INSTANCE_STATUSES.has(status)) {
    throw new ProviderExecutionError("offload-refresh-instance-status-invalid");
  }
  return status;
}

function isOffloadTransition(status: string): boolean {
  return status === "PROVISIONING" || status === "STAGING" ||
    status === "STOPPING" || status === "REPAIRING";
}

async function startOffloadInstance(
  transport: Transport,
  checkpoint: OffloadRefreshCheckpoint,
): Promise<void> {
  await transport.requestJson("POST", `${checkpoint.instanceUrl}/start`, {
    params: { requestId: checkpoint.startRequestId },
  });
}

/**
 * Compensation for every refresh phase is the same invariant: the PoC VM is
 * RUNNING. In particular, a failed start must not be treated as an ordinary
 * shared-resource rollback and silently leave the VM TERMINATED.
 */
export async function ensureOffloadRefreshRunning(
  transport: Transport,
  checkpointValue: unknown,
  spec: DeploymentSpec,
  requestId: string,
): Promise<void> {
  const checkpoint = validateOffloadRefreshCheckpoint(
    checkpointValue,
    spec,
    requestId,
  );
  let status = await readOffloadInstanceStatus(transport, checkpoint.instanceUrl);
  if (checkpoint.phase === "prepared" && status === "RUNNING") return;

  if (checkpoint.phase === "stop_sending") {
    // A RUNNING read can be the stale pre-stop state after an accepted request
    // whose response was lost. Re-submit the exact dedupe token and only then
    // repair from the confirmed stop boundary.
    try {
      await transport.requestJson("POST", `${checkpoint.instanceUrl}/stop`, {
        params: { discardLocalSsd: "false", requestId: checkpoint.stopRequestId },
      });
    } catch (error) {
      status = await readOffloadInstanceStatus(transport, checkpoint.instanceUrl)
        .catch(() => "UNKNOWN");
      if (status !== "TERMINATED") throw error;
    }
    status = await readOffloadInstanceStatus(transport, checkpoint.instanceUrl);
  }

  if (status === "RUNNING") return;
  if (status !== "TERMINATED") {
    if (isOffloadTransition(status)) {
      throw new ProviderExecutionError("offload-refresh-instance-state-pending");
    }
    throw new ProviderExecutionError("offload-refresh-instance-state-unsupported");
  }

  try {
    await startOffloadInstance(transport, checkpoint);
  } catch (error) {
    // A lost start response is successful compensation if the instance is
    // already RUNNING. Otherwise retain the rollback failure for manual retry.
    const reconciled = await readOffloadInstanceStatus(
      transport,
      checkpoint.instanceUrl,
    ).catch(() => null);
    if (reconciled === "RUNNING") return;
    throw error;
  }
  const running = await readOffloadInstanceStatus(transport, checkpoint.instanceUrl);
  if (running !== "RUNNING") {
    throw new ProviderExecutionError("offload-refresh-instance-state-pending");
  }
}

export interface PathAContext {
  transport: Transport;
  /** Immutable public TLS input copied from the approval-hashed plan. */
  publicCertificateBinding?: PublicCertificateBinding | null;
  /** Approval-bound immutable Compute image identity for every VM-backed path. */
  sourceImageBinding?: SourceImageBinding | null;
  /** Durable compensation/operation state restored when a step is resumed. */
  beforeImage?: unknown;
  /**
   * Idempotency token for this change.
   *
   * Google deduplicates a create by `requestId`, so a retry after a crash must
   * present the same value or it creates a second resource. The Python
   * implementation derives it from a per-process UUID, which cannot survive a
   * service-worker restart; here it is persisted with the run step instead, so
   * the retry path -- the normal path under Manifest V3 -- stays idempotent.
   */
  requestId: (change: ResourceChange) => string;
  /** Bundle issued earlier in the run, when the plan issues one. */
  certificate?: CertificateBundle;
  /**
   * Hand an artefact to the operator.
   *
   * The local application wrote it to disk at `0600`. An extension has no
   * filesystem, so this is a download the operator saves deliberately -- which
   * also makes the Root Store handoff a visible step rather than a file that
   * silently appeared.
   */
  exportArtifact: (filename: string, contents: string) => Promise<void>;
  /** Persist a compensation image with the run step before mutating shared state. */
  captureBefore?: (change: ResourceChange, beforeImage: unknown) => Promise<void>;
  maxOperationPolls?: number;
  operationPollIntervalMs?: number;
}

export type NamedResourceMutationPhase = "prepared" | "sending" | "rejected" | "applied";

type NamedResourceOwnershipProtocol = {
  /** Missing on legacy checkpoints, whose send outcome must remain ambiguous. */
  protocolVersion?: 1;
  phase?: NamedResourceMutationPhase;
};

export type NamedResourceOwnershipCheckpoint = NamedResourceOwnershipProtocol & (
  | {
      kind: "named_resource_ownership";
      resourceKind: "iam_service_account" | "dns_private_zone" | "secretmanager_secret";
      resourceUrl: string;
      ownershipToken: string;
      marker: string;
    }
  | {
      kind: "named_resource_ownership";
      resourceKind: "dns_record_set";
      resourceUrl: string;
      ownershipToken: string;
      marker: string;
      recordName: string;
      recordAddress: string;
      markerName: string;
    }
);

function namedResourcePhase(
  checkpoint: NamedResourceOwnershipCheckpoint,
): NamedResourceMutationPhase {
  if (
    checkpoint.protocolVersion === 1 &&
    (checkpoint.phase === "prepared" || checkpoint.phase === "sending" ||
      checkpoint.phase === "rejected" || checkpoint.phase === "applied")
  ) return checkpoint.phase;
  // A phase-less 0.2.0 checkpoint may have crossed the external mutation
  // boundary. Never reinterpret it as a proven pre-send record.
  return "sending";
}

function namedResourceIdentity(checkpoint: NamedResourceOwnershipCheckpoint): string {
  const { protocolVersion: _protocol, phase: _phase, ...identity } = checkpoint;
  return canonicalJson(identity);
}

/**
 * Persist an ownership predicate before a requestId-less named create.
 *
 * A 409 is only a safe retry when the resource carries this exact run-scoped
 * marker. Configuration equality alone is not ownership: another admin can
 * create an identical resource between Plan and Apply.
 */
export async function checkpointNamedResourceOwnership(
  context: PathAContext,
  change: ResourceChange,
  checkpoint: NamedResourceOwnershipCheckpoint,
): Promise<void> {
  if (context.captureBefore === undefined) {
    throw new ProviderExecutionError("named-resource-ownership-checkpoint-unavailable");
  }
  if (
    context.beforeImage !== undefined &&
    (
      typeof context.beforeImage !== "object" || context.beforeImage === null ||
      (context.beforeImage as { kind?: unknown }).kind !== "named_resource_ownership"
    )
  ) {
    throw new ProviderExecutionError("named-resource-ownership-checkpoint-mismatch");
  }
  if (context.beforeImage !== undefined) {
    const current = context.beforeImage as NamedResourceOwnershipCheckpoint;
    const transitions: Record<NamedResourceMutationPhase, readonly NamedResourceMutationPhase[]> = {
      prepared: ["prepared", "sending", "rejected"],
      sending: ["sending", "rejected", "applied"],
      rejected: ["rejected"],
      applied: ["applied"],
    };
    if (
      namedResourceIdentity(current) !== namedResourceIdentity(checkpoint) ||
      !transitions[namedResourcePhase(current)].includes(namedResourcePhase(checkpoint))
    ) {
      throw new ProviderExecutionError("named-resource-ownership-checkpoint-mismatch");
    }
  }
  await context.captureBefore(change, checkpoint);
}

export async function applyNamedResourceCreate(
  context: PathAContext,
  change: ResourceChange,
  identity: Omit<NamedResourceOwnershipCheckpoint, "protocolVersion" | "phase">,
  send: () => Promise<void>,
  reconcile: () => Promise<boolean>,
): Promise<void> {
  let checkpoint: NamedResourceOwnershipCheckpoint = {
    ...identity,
    protocolVersion: 1,
    phase: "prepared",
  } as NamedResourceOwnershipCheckpoint;
  if (context.beforeImage !== undefined) {
    const current = context.beforeImage;
    if (
      typeof current !== "object" || current === null ||
      (current as { kind?: unknown }).kind !== "named_resource_ownership" ||
      namedResourceIdentity(current as NamedResourceOwnershipCheckpoint) !==
        namedResourceIdentity(checkpoint)
    ) {
      throw new ProviderExecutionError("named-resource-ownership-checkpoint-mismatch");
    }
    checkpoint = current as NamedResourceOwnershipCheckpoint;
  } else {
    await checkpointNamedResourceOwnership(context, change, checkpoint);
  }

  const advance = async (phase: NamedResourceMutationPhase): Promise<void> => {
    checkpoint = { ...checkpoint, protocolVersion: 1, phase };
    await checkpointNamedResourceOwnership(context, change, checkpoint);
  };
  const phase = namedResourcePhase(checkpoint);
  if (phase === "applied") {
    if (!(await reconcile())) {
      throw new ProviderExecutionError("named-resource-managed-state-changed");
    }
    return;
  }
  if (phase === "sending") {
    if (await reconcile()) {
      await advance("applied");
      return;
    }
    throw new ProviderExecutionError("named-resource-provider-response-ambiguous");
  }
  if (phase === "rejected") {
    throw new ProviderExecutionError("named-resource-create-definitively-rejected");
  }

  await advance("sending");
  try {
    await send();
  } catch (error) {
    if (isDefiniteMutationRejection(error)) {
      await advance("rejected");
    } else if (await reconcile().catch(() => false)) {
      await advance("applied");
    }
    throw error;
  }
  await advance("applied");
}

function ownershipMarker(token: string): string {
  return `Secure Gateway Studio ownership-token=${token}`;
}

function networkUrl(spec: DeploymentSpec, name: string): string {
  return `${COMPUTE}/projects/${spec.project_id}/global/networks/${name}`;
}

function dnsPrivateNetworkUrl(spec: DeploymentSpec, name: string): string {
  return `https://www.googleapis.com/compute/v1/projects/${spec.project_id}` +
    `/global/networks/${name}`;
}

function subnetUrl(spec: DeploymentSpec, name: string): string {
  return `${COMPUTE}/projects/${spec.project_id}/regions/${spec.region}/subnetworks/${name}`;
}

export interface CloudNatConfig {
  logConfig: { enable: boolean; filter: string };
  name: string;
  natIpAllocateOption: string;
  sourceSubnetworkIpRangesToNat: string;
  subnetworks: Array<{ name: string; sourceIpRangesToNat: string[] }>;
}

function cloudNatConfig(change: ResourceChange, spec: DeploymentSpec): CloudNatConfig {
  return {
    logConfig: { enable: true, filter: "ERRORS_ONLY" },
    name: change.resource_name,
    natIpAllocateOption: "AUTO_ONLY",
    sourceSubnetworkIpRangesToNat: "LIST_OF_SUBNETWORKS",
    subnetworks: [
      {
        name: subnetUrl(spec, subnetName(spec)),
        sourceIpRangesToNat: ["ALL_IP_RANGES"],
      },
    ],
  };
}

export function isCompatibleCloudNat(value: unknown, expected: CloudNatConfig): boolean {
  if (
    typeof value !== "object" || value === null ||
    typeof expected !== "object" || expected === null ||
    typeof expected.logConfig !== "object" || expected.logConfig === null ||
    !Array.isArray(expected.subnetworks) || expected.subnetworks.length !== 1
  ) return false;
  const nat = value as Partial<CloudNatConfig>;
  const subnetworks = nat.subnetworks;
  const actualSubnet = subnetworks?.[0]?.name;
  const expectedSubnet = expected.subnetworks[0]?.name;
  const subnetsMatch = typeof actualSubnet === "string" && typeof expectedSubnet === "string" &&
    (actualSubnet === expectedSubnet || actualSubnet.split("/").pop() === expectedSubnet.split("/").pop());

  return nat.name === expected.name &&
    nat.natIpAllocateOption === expected.natIpAllocateOption &&
    nat.sourceSubnetworkIpRangesToNat === expected.sourceSubnetworkIpRangesToNat &&
    nat.logConfig?.enable === true &&
    nat.logConfig.filter === expected.logConfig.filter &&
    Array.isArray(subnetworks) && subnetworks.length === 1 &&
    subnetsMatch &&
    Array.isArray(subnetworks[0]?.sourceIpRangesToNat) &&
    subnetworks[0]?.sourceIpRangesToNat.length === 1 &&
    subnetworks[0]?.sourceIpRangesToNat[0] === "ALL_IP_RANGES";
}

function isCloudNatRetry(
  beforeImage: unknown,
  routerUrl: string,
  natName: string,
  expected: CloudNatConfig,
): boolean {
  if (typeof beforeImage !== "object" || beforeImage === null) return false;
  const image = beforeImage as {
    kind?: unknown;
    routerUrl?: unknown;
    nats?: unknown;
    managedNat?: unknown;
  };
  return image.kind === "router_nats" && image.routerUrl === routerUrl &&
    Array.isArray(image.nats) &&
    isCompatibleCloudNat(image.managedNat, expected) &&
    !image.nats.some(
      (nat) =>
        typeof nat === "object" && nat !== null &&
        (nat as { name?: unknown }).name === natName,
    );
}

export function networkName(spec: DeploymentSpec): string {
  return spec.network_strategy === "existing" && spec.vpc_name
    ? spec.vpc_name
    : `${spec.name}-vpc`;
}

export function subnetName(spec: DeploymentSpec): string {
  return spec.network_strategy === "existing" && spec.subnet_name
    ? spec.subnet_name
    : `${spec.name}-subnet`;
}

type InstanceRole = "backend" | "offload";

/**
 * Decode only unambiguous, object-shaped Secure Gateway Studio guest evidence.
 *
 * Compute returns guest attributes as JSON strings nested below `queryValue`.
 * Missing, malformed, or duplicate test records are deliberately treated as
 * not ready. In particular, a string-valued SAN must not satisfy the array
 * membership check merely because it contains the expected hostname.
 */
function guestAttributeEvidence(payload: unknown): Map<string, Record<string, unknown>> | null {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return null;
  const queryValue = (payload as { queryValue?: unknown }).queryValue;
  if (typeof queryValue !== "object" || queryValue === null || Array.isArray(queryValue)) {
    return null;
  }
  const items = (queryValue as { items?: unknown }).items;
  if (!Array.isArray(items)) return null;

  const evidence = new Map<string, Record<string, unknown>>();
  for (const item of items) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) continue;
    const record = item as { namespace?: unknown; key?: unknown; value?: unknown };
    if (
      record.namespace !== "sgstudio" || typeof record.key !== "string" ||
      typeof record.value !== "string" || evidence.has(record.key)
    ) {
      if (
        record.namespace === "sgstudio" && typeof record.key === "string" &&
        evidence.has(record.key)
      ) return null;
      continue;
    }
    try {
      const decoded: unknown = JSON.parse(record.value);
      if (typeof decoded === "object" && decoded !== null && !Array.isArray(decoded)) {
        evidence.set(record.key, decoded as Record<string, unknown>);
      }
    } catch {
      // A VM can publish while a read is in flight. The durable step retries a
      // malformed/partial value instead of accepting or spinning on it here.
    }
  }
  return evidence;
}

/** Strict runtime readiness predicate shared by Apply and its regression gate. */
export function isInstanceRuntimeReady(
  payload: unknown,
  spec: DeploymentSpec,
  role: InstanceRole,
): boolean {
  const evidence = guestAttributeEvidence(payload);
  if (evidence === null) return false;
  const expectedHash = configurationHash(spec);

  if (role === "backend") {
    const t01 = evidence.get("T01");
    return t01?.status === 200 && t01.configuration_hash === expectedHash;
  }

  const t02 = evidence.get("T02");
  const t03 = evidence.get("T03");
  const sans = t03?.subject_alt_names;
  const expectedTrustMode = spec.certificate_strategy === "public_trusted"
    ? "public_system_roots"
    : "presented_chain_pinned";
  return t02?.status === 200 && t02.configuration_hash === expectedHash &&
    t03?.http_status === 200 && t03.configuration_hash === expectedHash &&
    t03.hostname === spec.private_hostname &&
    t03.trust_mode === expectedTrustMode &&
    (t03.tls_version === "TLSv1.2" || t03.tls_version === "TLSv1.3") &&
    Array.isArray(sans) && sans.every((value) => typeof value === "string") &&
    sans.includes(spec.private_hostname);
}

function firewallRuleBody(
  change: ResourceChange,
  spec: DeploymentSpec,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    allowed: [{ IPProtocol: "tcp", ports: ["443"] }],
    direction: "INGRESS",
    logConfig: { enable: true, metadata: "INCLUDE_ALL_METADATA" },
    name: change.resource_name,
    network: networkUrl(spec, networkName(spec)),
    priority: 1000,
  };

  if (change.resource_name.endsWith("-backend-ingress")) {
    body.allowed = [{ IPProtocol: "tcp", ports: ["80"] }];
    body.sourceServiceAccounts = [
      serviceAccountEmail(spec.name, spec.project_id, "offload"),
    ];
    body.targetServiceAccounts = [
      serviceAccountEmail(spec.name, spec.project_id, "backend"),
    ];
  } else if (change.resource_name.endsWith("-health-check-ingress")) {
    body.sourceRanges = [...GOOGLE_HEALTH_CHECK_SOURCE_RANGES];
    body.targetServiceAccounts = [
      serviceAccountEmail(spec.name, spec.project_id, "offload"),
    ];
  } else if (change.resource_name.endsWith("-gateway-ingress")) {
    body.sourceRanges = [SECURE_GATEWAY_SOURCE_RANGE];
    if (spec.backend_kind !== "internal_https_lb") {
      body.targetServiceAccounts = [
        serviceAccountEmail(spec.name, spec.project_id, "offload"),
      ];
    }
  } else if (change.resource_name.endsWith("-ilb-proxy-ingress")) {
    body.allowed = [{ IPProtocol: "tcp", ports: ["80"] }];
    body.sourceRanges = [spec.proxy_subnet_cidr];
    body.targetServiceAccounts = [
      serviceAccountEmail(spec.name, spec.project_id, "backend"),
    ];
  } else if (change.resource_name.endsWith("-ilb-health-ingress")) {
    body.allowed = [{ IPProtocol: "tcp", ports: ["80"] }];
    body.sourceRanges = [...GOOGLE_HEALTH_CHECK_SOURCE_RANGES];
    body.targetServiceAccounts = [
      serviceAccountEmail(spec.name, spec.project_id, "backend"),
    ];
  } else {
    throw new ProviderExecutionError("firewall-rule-kind-invalid");
  }
  return body;
}

export async function applyPathA(
  context: PathAContext,
  change: ResourceChange,
  spec: DeploymentSpec,
): Promise<void> {
  const { transport } = context;
  const project = spec.project_id;
  const kind = `${change.provider}:${change.resource_type}`;

  const post = async (
    url: string,
    body: Record<string, unknown>,
    withRequestId = true,
    reconcileAlreadyExists?: () => Promise<boolean>,
    customParams?: Record<string, string | number>,
  ): Promise<Record<string, unknown>> => {
    const response = await transport.requestJson("POST", url, {
      params: customParams ??
        (withRequestId ? { requestId: context.requestId(change) } : undefined),
      jsonBody: body,
      // A caller may opt into ALREADY_EXISTS only when it also supplies an
      // exact-resource semantic reconciliation below.
      acceptedStatuses: reconcileAlreadyExists ? [409] : undefined,
    });
    if (response.status === 409) {
      if (reconcileAlreadyExists === undefined || !(await reconcileAlreadyExists())) {
        throw new ProviderExecutionError("named-resource-reconciliation-failed");
      }
    }
    return response.payload;
  };

  // Production replaces the single VM with a managed group behind an internal
  // load balancer; those types are handled there and fall through here.
  if (await applyProduction(context, change, spec)) return;

  switch (kind) {
    case "compute:network":
      // Custom mode: automatic subnets would create a subnet in every region,
      // widening the private surface far beyond the one region in the plan.
      await post(`${COMPUTE}/projects/${project}/global/networks`, {
        autoCreateSubnetworks: false,
        description: MANAGED_BY,
        name: change.resource_name,
        routingConfig: { routingMode: "REGIONAL" },
      });
      return;

    case "compute:subnetwork":
      {
        const proxyOnly = change.resource_name.endsWith("-proxy-subnet");
        await post(`${COMPUTE}/projects/${project}/regions/${spec.region}/subnetworks`, {
          ipCidrRange: proxyOnly ? spec.proxy_subnet_cidr : spec.subnet_cidr,
          name: change.resource_name,
          network: networkUrl(spec, networkName(spec)),
          stackType: "IPV4_ONLY",
          ...(proxyOnly
            ? { purpose: "REGIONAL_MANAGED_PROXY", role: "ACTIVE" }
            : { privateIpGoogleAccess: true }),
        });
      }
      return;

    case "compute:router":
      await post(`${COMPUTE}/projects/${project}/regions/${spec.region}/routers`, {
        name: change.resource_name,
        network: networkUrl(spec, networkName(spec)),
      });
      return;

    case "compute:cloud_nat": {
      // NAT is a field on the router, not a resource: read the router, add the
      // config, and patch it back so any other NAT on it survives.
      const routerUrl =
        `${COMPUTE}/projects/${project}/regions/${spec.region}/routers/${spec.name}-router`;
      const router = (await transport.requestJson("GET", routerUrl)).payload;
      if (router.nats !== undefined && !Array.isArray(router.nats)) {
        throw new ProviderExecutionError("cloud-nat-router-nats-invalid");
      }
      const nats = [...((router.nats ?? []) as unknown[])];
      if (nats.some((nat) =>
        typeof nat !== "object" || nat === null || Array.isArray(nat) ||
        typeof (nat as { name?: unknown }).name !== "string" ||
        (nat as { name: string }).name === ""
      )) {
        throw new ProviderExecutionError("cloud-nat-router-nats-invalid");
      }
      const expected = cloudNatConfig(change, spec);
      await context.captureBefore?.(change, {
        kind: "router_nats",
        routerUrl,
        nats: structuredClone(nats),
        managedNat: structuredClone(expected),
      });
      const existing = nats.filter(
        (nat) =>
          typeof nat === "object" && nat !== null &&
          (nat as { name?: unknown }).name === change.resource_name,
      );
      if (existing.length > 0) {
        if (
          existing.length !== 1 ||
          !isCloudNatRetry(context.beforeImage, routerUrl, change.resource_name, expected) ||
          !isCompatibleCloudNat(existing[0], expected)
        ) {
          throw new ProviderExecutionError("cloud-nat-reconciliation-failed");
        }
        return;
      }
      nats.push(expected);
      await transport.requestJson("PATCH", routerUrl, {
        params: { requestId: context.requestId(change) },
        jsonBody: { nats },
      });
      return;
    }

    case "iam:service_account":
      {
        const collection = `https://iam.googleapis.com/v1/projects/${project}/serviceAccounts`;
        const email = `${change.resource_name}@${project}.iam.gserviceaccount.com`;
        const displayName = `Secure Gateway Studio ${change.resource_name}`;
        const resourceUrl = `${collection}/${encodeURIComponent(email)}`;
        const ownershipToken = context.requestId(change);
        const marker = ownershipMarker(ownershipToken);
        const identity = {
          kind: "named_resource_ownership",
          resourceKind: "iam_service_account",
          resourceUrl,
          ownershipToken,
          marker,
        } as const;
        const reconcile = async (): Promise<boolean> => {
          const existing = await transport.requestJson("GET", resourceUrl, {
            acceptedStatuses: [404],
          });
          return existing.status !== 404 && existing.payload.email === email &&
            existing.payload.displayName === displayName &&
            existing.payload.description === marker;
        };
        await applyNamedResourceCreate(
          context,
          change,
          identity,
          async () => {
            const response = await transport.requestJson("POST", collection, {
              jsonBody: {
                accountId: change.resource_name,
                serviceAccount: { description: marker, displayName },
              },
              acceptedStatuses: [409],
            });
            if (response.status === 409 && !(await reconcile())) {
              throw new ProviderExecutionError("named-resource-reconciliation-failed");
            }
          },
          reconcile,
        );
      }
      return;

    case "compute:internal_address":
      await post(`${COMPUTE}/projects/${project}/regions/${spec.region}/addresses`, {
        addressType: "INTERNAL",
        name: change.resource_name,
        subnetwork: subnetUrl(spec, subnetName(spec)),
      });
      return;

    case "compute:firewall_rule": {
      await post(
        `${COMPUTE}/projects/${project}/global/firewalls`,
        firewallRuleBody(change, spec),
      );
      return;
    }

    case "dns:private_zone":
      {
        const collection = `https://dns.googleapis.com/dns/v1/projects/${project}/managedZones`;
        const expectedNetwork = dnsPrivateNetworkUrl(spec, networkName(spec));
        const resourceUrl = `${collection}/${change.resource_name}`;
        const ownershipToken = context.requestId(change);
        const marker = ownershipMarker(ownershipToken);
        const identity = {
          kind: "named_resource_ownership",
          resourceKind: "dns_private_zone",
          resourceUrl,
          ownershipToken,
          marker,
        } as const;
        const reconcile = async (): Promise<boolean> => {
          const existing = await transport.requestJson("GET", resourceUrl, {
            acceptedStatuses: [404],
          });
          if (existing.status === 404) return false;
          const networks = (
            existing.payload.privateVisibilityConfig as
              | { networks?: Array<{ networkUrl?: unknown }> }
              | undefined
          )?.networks;
          return existing.payload.name === change.resource_name &&
            existing.payload.description === marker &&
            existing.payload.dnsName === `${spec.private_hostname}.` &&
            existing.payload.visibility === "private" &&
            Array.isArray(networks) &&
            networks.length === 1 &&
            networks[0]?.networkUrl === expectedNetwork;
        };
        await applyNamedResourceCreate(
          context,
          change,
          identity,
          async () => {
            const response = await transport.requestJson("POST", collection, {
              jsonBody: {
                description: marker,
                dnsName: `${spec.private_hostname}.`,
                name: change.resource_name,
                privateVisibilityConfig: {
                  networks: [{ networkUrl: expectedNetwork }],
                },
                visibility: "private",
              },
              acceptedStatuses: [409],
            });
            if (response.status === 409 && !(await reconcile())) {
              throw new ProviderExecutionError("named-resource-reconciliation-failed");
            }
          },
          reconcile,
        );
      }
      return;

    case "dns:record_set": {
      const address = (await reservedAddress(
        context,
        spec,
        `${spec.name}-offload-ip`,
      )) as string;
      const fqdn = `${spec.private_hostname}.`;
      const resourceUrl =
        `https://dns.googleapis.com/dns/v1/projects/${project}/managedZones/` +
        `${spec.name}-zone`;
      const ownershipToken = context.requestId(change);
      const marker = `"sgs-owner=${ownershipToken}"`;
      const markerName = `_sgs-owner.${fqdn}`;
      const identity = {
        kind: "named_resource_ownership",
        resourceKind: "dns_record_set",
        resourceUrl,
        ownershipToken,
        marker,
        recordName: fqdn,
        recordAddress: address,
        markerName,
      } as const;
      const reconcile = async (): Promise<boolean> => {
          const existing = await transport.requestJson(
            "GET",
            `${resourceUrl}/rrsets/${encodeURIComponent(fqdn)}/A`,
            { acceptedStatuses: [404] },
          );
          const ownership = await transport.requestJson(
            "GET",
            `${resourceUrl}/rrsets/${encodeURIComponent(markerName)}/TXT`,
            { acceptedStatuses: [404] },
          );
          return existing.status !== 404 && ownership.status !== 404 &&
            existing.payload.name === fqdn &&
            existing.payload.type === "A" &&
            existing.payload.ttl === 60 &&
            Array.isArray(existing.payload.rrdatas) &&
            existing.payload.rrdatas.length === 1 &&
            existing.payload.rrdatas[0] === address &&
            ownership.payload.name === markerName &&
            ownership.payload.type === "TXT" &&
            ownership.payload.ttl === 60 &&
            Array.isArray(ownership.payload.rrdatas) &&
            ownership.payload.rrdatas.length === 1 &&
            ownership.payload.rrdatas[0] === marker;
      };
      await applyNamedResourceCreate(
        context,
        change,
        identity,
        async () => {
          const response = await transport.requestJson("POST", `${resourceUrl}/changes`, {
            params: { clientOperationId: ownershipToken },
            jsonBody: {
              additions: [
                {
                  name: fqdn,
                  rrdatas: [address],
                  ttl: 60,
                  type: "A",
                },
                {
                  name: markerName,
                  rrdatas: [marker],
                  ttl: 60,
                  type: "TXT",
                },
              ],
            },
            acceptedStatuses: [409],
          });
          if (response.status === 409 && !(await reconcile())) {
            throw new ProviderExecutionError("named-resource-reconciliation-failed");
          }
        },
        reconcile,
      );
      return;
    }

    case "secretmanager:secret_iam": {
      // The TLS bundle must be readable by the offload VM's identity and by
      // nothing else, so this grants one role to one service account and
      // preserves every binding already on the secret.
      const secretName =
        spec.certificate_strategy === "public_trusted" && spec.public_certificate_secret
          ? (spec.public_certificate_secret.split("/").pop() as string)
          : `${spec.name}-tls`;
      const resource =
        `https://secretmanager.googleapis.com/v1/projects/${project}/secrets/${secretName}`;
      const getUrl = `${resource}:getIamPolicy`;
      const setUrl = `${resource}:setIamPolicy`;
      type SecretIamCheckpoint = {
        kind: "secret_iam";
        phase?: "prepared" | "sending" | "rejected" | "applied";
        rejectionStatus?: number;
        rejectionReason?: "ABORTED";
        getUrl: string;
        getMethod: "GET";
        setUrl: string;
        policy: Record<string, unknown>;
        afterPolicy: Record<string, unknown>;
      };
      const resumed = context.beforeImage as SecretIamCheckpoint | undefined;
      if (resumed !== undefined) {
        if (
          resumed.kind !== "secret_iam" || resumed.getUrl !== getUrl ||
          resumed.getMethod !== "GET" || resumed.setUrl !== setUrl ||
          !["prepared", "sending", "rejected", "applied"].includes(resumed.phase ?? "")
        ) {
          throw new ProviderExecutionError("secret-iam-checkpoint-invalid");
        }
        if (resumed.phase === "sending") {
          throw new ProviderExecutionError("secret-iam-mutation-outcome-ambiguous");
        }
        if (
          resumed.phase === "rejected" &&
          (resumed.rejectionStatus !== 409 || resumed.rejectionReason !== "ABORTED")
        ) {
          throw new ProviderExecutionError("secret-iam-mutation-definitively-rejected");
        }
        if (resumed.phase === "applied") return;
      }
      const member =
        `serviceAccount:${serviceAccountEmail(spec.name, project, "offload")}`;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const rawPolicy = (await transport.requestJson("GET", getUrl, {
          params: { "options.requestedPolicyVersion": 3 },
        })).payload as {
          etag?: unknown;
          bindings?: Array<{
            role?: string;
            members?: string[];
            condition?: unknown;
            [key: string]: unknown;
          }>;
          [key: string]: unknown;
        };
        let policy: Record<string, unknown>;
        try {
          policy = validatedIamPolicy(rawPolicy) as Record<string, unknown>;
        } catch {
          throw new ProviderExecutionError("secret-iam-policy-invalid");
        }
        const currentBindings = policy.bindings as Array<{
          role?: string;
          members?: string[];
          condition?: unknown;
          [key: string]: unknown;
        }>;
        const targetBindings = currentBindings.filter(
          (binding) =>
            binding.role === "roles/secretmanager.secretAccessor" &&
            (binding.condition === undefined || binding.condition === null),
        );
        const bindings = currentBindings.filter(
          (binding) =>
            binding.role !== "roles/secretmanager.secretAccessor" ||
            (binding.condition !== undefined && binding.condition !== null),
        );
        bindings.push({
          role: "roles/secretmanager.secretAccessor",
          members: [
            ...new Set([
              ...targetBindings.flatMap((binding) => binding.members ?? []),
              member,
            ]),
          ],
        });
        let updatedPolicy: Record<string, unknown>;
        try {
          updatedPolicy = validatedIamPolicy({
            ...policy,
            bindings,
            version: 3,
          }) as Record<string, unknown>;
        } catch {
          throw new ProviderExecutionError("secret-iam-policy-invalid");
        }
        const checkpoint: SecretIamCheckpoint = {
          kind: "secret_iam",
          phase: "prepared",
          getUrl,
          getMethod: "GET",
          setUrl,
          policy: structuredClone(policy),
          afterPolicy: structuredClone(updatedPolicy),
        };
        await context.captureBefore?.(change, checkpoint);
        await context.captureBefore?.(change, { ...checkpoint, phase: "sending" });
        try {
          await transport.requestJson("POST", setUrl, {
            jsonBody: { policy: updatedPolicy },
          });
        } catch (error) {
          if (isConfirmedIamEtagConflict(error)) {
            await context.captureBefore?.(change, {
              ...checkpoint,
              phase: "rejected",
              rejectionStatus: error.status,
              rejectionReason: "ABORTED",
            });
            if (attempt < 2) {
              await new Promise((resolve) => setTimeout(resolve, 25 * (2 ** attempt)));
              continue;
            }
          } else if (isDefiniteMutationRejection(error) && error.status !== 409) {
            await context.captureBefore?.(change, {
              ...checkpoint,
              phase: "rejected",
              rejectionStatus: error.status,
            });
          }
          throw error;
        }
        await context.captureBefore?.(change, { ...checkpoint, phase: "applied" });
        return;
      }
      throw new ProviderExecutionError("secret-iam-concurrent-update-limit");
    }

    case "compute:offload_refresh": {
      const requestId = context.requestId(change);
      const capture = context.captureBefore;
      if (capture === undefined) {
        throw new ProviderExecutionError("offload-refresh-checkpoint-unavailable");
      }
      let checkpoint: OffloadRefreshCheckpoint;
      if (context.beforeImage === undefined) {
        checkpoint = expectedOffloadRefreshCheckpoint(spec, requestId);
        await capture(change, checkpoint);
      } else {
        checkpoint = validateOffloadRefreshCheckpoint(
          context.beforeImage,
          spec,
          requestId,
        );
      }

      const advance = async (phase: OffloadRefreshPhase): Promise<void> => {
        checkpoint = { ...checkpoint, phase };
        await capture(change, checkpoint);
      };
      const reconcileAfterError = async (
        expectedStatus: "RUNNING" | "TERMINATED",
      ): Promise<boolean> => {
        const status = await readOffloadInstanceStatus(
          transport,
          checkpoint.instanceUrl,
        ).catch(() => null);
        return status === expectedStatus;
      };
      const requireActionableStatus = (status: string): void => {
        if (isOffloadTransition(status)) {
          throw new ProviderExecutionError("offload-refresh-instance-state-pending");
        }
        if (status === "SUSPENDING" || status === "SUSPENDED") {
          throw new ProviderExecutionError("offload-refresh-instance-state-unsupported");
        }
      };

      // Each iteration either advances the durable phase or returns. The cap
      // is defensive; normal execution takes at most four transitions.
      for (let transition = 0; transition < 8; transition += 1) {
        const status = await readOffloadInstanceStatus(
          transport,
          checkpoint.instanceUrl,
        );
        if (checkpoint.phase === "prepared") {
          if (status === "TERMINATED") {
            await advance("stopped");
            continue;
          }
          if (status !== "RUNNING") {
            requireActionableStatus(status);
            throw new ProviderExecutionError("offload-refresh-instance-state-invalid");
          }
          await advance("stop_sending");
          try {
            await transport.requestJson("POST", `${checkpoint.instanceUrl}/stop`, {
              params: {
                discardLocalSsd: "false",
                requestId: checkpoint.stopRequestId,
              },
            });
          } catch (error) {
            if (await reconcileAfterError("TERMINATED")) {
              await advance("stopped");
              continue;
            }
            throw error;
          }
          await advance("stopped");
          continue;
        }

        if (checkpoint.phase === "stop_sending") {
          if (status === "TERMINATED") {
            await advance("stopped");
            continue;
          }
          if (status !== "RUNNING") {
            requireActionableStatus(status);
            throw new ProviderExecutionError("offload-refresh-instance-state-invalid");
          }
          try {
            await transport.requestJson("POST", `${checkpoint.instanceUrl}/stop`, {
              params: {
                discardLocalSsd: "false",
                requestId: checkpoint.stopRequestId,
              },
            });
          } catch (error) {
            if (await reconcileAfterError("TERMINATED")) {
              await advance("stopped");
              continue;
            }
            throw error;
          }
          await advance("stopped");
          continue;
        }

        if (checkpoint.phase === "stopped") {
          if (status === "RUNNING") {
            await advance("applied");
            return;
          }
          if (status !== "TERMINATED") {
            if (
              status === "PROVISIONING" || status === "STAGING" ||
              status === "REPAIRING"
            ) {
              // Another invocation may have sent start immediately before its
              // checkpoint write was interrupted. Persist the conservative
              // phase and let the next worker reconcile RUNNING.
              await advance("start_sending");
            }
            requireActionableStatus(status);
            throw new ProviderExecutionError("offload-refresh-instance-state-invalid");
          }
          await advance("start_sending");
          try {
            await startOffloadInstance(transport, checkpoint);
          } catch (error) {
            if (await reconcileAfterError("RUNNING")) {
              await advance("applied");
              return;
            }
            throw error;
          }
          await advance("applied");
          return;
        }

        if (checkpoint.phase === "start_sending") {
          if (status === "RUNNING") {
            await advance("applied");
            return;
          }
          if (status !== "TERMINATED") {
            requireActionableStatus(status);
            throw new ProviderExecutionError("offload-refresh-instance-state-invalid");
          }
          try {
            await startOffloadInstance(transport, checkpoint);
          } catch (error) {
            if (await reconcileAfterError("RUNNING")) {
              await advance("applied");
              return;
            }
            throw error;
          }
          await advance("applied");
          return;
        }

        if (checkpoint.phase === "applied") {
          if (status !== "RUNNING") {
            requireActionableStatus(status);
            throw new ProviderExecutionError("offload-refresh-managed-state-changed");
          }
          return;
        }
      }
      throw new ProviderExecutionError("offload-refresh-transition-limit");
    }

    case "compute:instance": {
      if (spec.source_image === null) {
        throw new ProviderExecutionError("source-image-binding-invalid");
      }
      const role = change.resource_name.endsWith("-backend") ? "backend" : "offload";
      // Only a managed sample has a reserved backend address. Existing HTTP
      // deployments embed `existing_backend_url` directly and must never probe
      // a `${name}-backend-ip` resource that their plan does not create.
      const backendAddress = role === "offload" && spec.backend_kind === "managed_sample"
        ? await reservedAddress(context, spec, `${spec.name}-backend-ip`)
        : null;
      const address = await reservedAddress(context, spec, `${spec.name}-${role}-ip`);
      const publicCertificateVersionName = role === "offload"
        ? await revalidatePublicCertificateBinding(
            transport,
            spec,
            context.publicCertificateBinding,
          )
        : undefined;
      const script =
        role === "backend"
          ? sampleBackendStartupScript(spec)
          : offloadStartupScript(spec, {
              backendAddress: backendAddress ?? undefined,
              publicCertificateVersionName,
            });

      await post(`${COMPUTE}/projects/${project}/zones/${spec.zone}/instances`, {
        deletionProtection: false,
        disks: [
          {
            autoDelete: true,
            boot: true,
            initializeParams: {
              diskSizeGb: "20",
              diskType: `zones/${spec.zone}/diskTypes/pd-balanced`,
              sourceImage: spec.source_image,
            },
          },
        ],
        labels: { "managed-by": "secure-gateway-studio", role },
        machineType: `zones/${spec.zone}/machineTypes/e2-small`,
        metadata: {
          items: [
            { key: "startup-script", value: script },
            // The VM writes its own T01-T03 self-test results here; Apply reads
            // them back rather than trusting that the boot succeeded.
            { key: "enable-guest-attributes", value: "TRUE" },
          ],
        },
        name: change.resource_name,
        networkInterfaces: [
          {
            network: networkUrl(spec, networkName(spec)),
            networkIP: address,
            stackType: "IPV4_ONLY",
            subnetwork: subnetUrl(spec, subnetName(spec)),
          },
        ],
        serviceAccounts: [
          {
            email: serviceAccountEmail(spec.name, project, role),
            scopes: ["https://www.googleapis.com/auth/cloud-platform"],
          },
        ],
        shieldedInstanceConfig: {
          enableIntegrityMonitoring: true,
          enableSecureBoot: true,
          enableVtpm: true,
        },
        tags: { items: [change.resource_name] },
      });

      const maxPolls = context.maxOperationPolls ?? 40;
      const interval = context.operationPollIntervalMs ?? 3000;
      for (let poll = 0; poll < maxPolls; poll += 1) {
        const readiness = await transport.requestJson(
          "GET",
          `${COMPUTE}/projects/${project}/zones/${spec.zone}/instances/` +
            `${change.resource_name}/getGuestAttributes`,
          { params: { queryPath: "sgstudio/" }, acceptedStatuses: [400, 404] },
        );
        if (readiness.status === 200 && isInstanceRuntimeReady(readiness.payload, spec, role)) {
          return;
        }
        if (poll < maxPolls - 1 && interval > 0) {
          await new Promise((resolve) => setTimeout(resolve, interval));
        }
      }
      throw new ProviderExecutionError("instance-readiness-pending");
    }

    default:
      throw new ProviderExecutionError("unsupported-resource-type");
  }
}

/** The allocated internal address, needed by the VM and the DNS record. */
async function reservedAddress(
  context: PathAContext,
  spec: DeploymentSpec,
  name: string,
  options: { optional?: boolean } = {},
): Promise<string | null> {
  const response = await context.transport.requestJson(
    "GET",
    `${COMPUTE}/projects/${spec.project_id}/regions/${spec.region}/addresses/${name}`,
  );
  const address = response.payload.address;
  if (typeof address !== "string") {
    if (options.optional === true) return null;
    throw new ProviderExecutionError("reserved-address-missing");
  }
  return address;
}

export { serviceAccountId };
