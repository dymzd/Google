/**
 * Teardown planning. Port of `domain/teardown.py`.
 *
 * Teardown deletes only what this deployment created, in reverse dependency
 * order, and never touches a shared resource. That constraint is the whole
 * design: a PoC that removed the caller's existing VPC, or a gateway another
 * application still uses, would be far worse than one that leaves something
 * behind.
 *
 * The plan is hash-bound like an Apply plan. The operator confirms a phrase
 * derived from that hash, so a teardown approved against one inventory cannot
 * execute against another.
 */

import { canonicalDigestSync } from "./canonical.ts";

export type TeardownAction = "delete" | "delete_if_empty" | "restore" | "retain";

export interface DeploymentResource {
  resourceKey: string;
  provider: string;
  resourceType: string;
  resourceName: string;
  owned: boolean;
  /** True when the resource is shared and may still be in use elsewhere. */
  shared: boolean;
  /** Persisted policy/configuration state from before this run's mutation. */
  beforeImage?: unknown;
  /** Stable request token used by the original Apply operation. */
  requestId?: string;
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const GOOGLE_CREATE_TIME_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

/**
 * Prove that this shared `default` gateway was created by the finalized run.
 *
 * Shared does not mean pre-existing: the default gateway is deliberately
 * reused across applications. Its exact v2 checkpoint is creation provenance,
 * but never turns it into an exclusively owned resource.
 */
export function isCreatedSharedDefaultGateway(
  resource: Pick<
    DeploymentResource,
    | "resourceKey"
    | "provider"
    | "resourceType"
    | "resourceName"
    | "owned"
    | "shared"
    | "beforeImage"
    | "requestId"
  >,
): boolean {
  if (
    resource.resourceKey !== "beyondcorp:security_gateway:default" ||
    resource.provider !== "beyondcorp" ||
    resource.resourceType !== "security_gateway" ||
    resource.resourceName !== "default" ||
    resource.owned !== false || resource.shared !== true ||
    typeof resource.requestId !== "string" || !UUID_PATTERN.test(resource.requestId) ||
    resource.beforeImage === null || typeof resource.beforeImage !== "object" ||
    Array.isArray(resource.beforeImage)
  ) return false;
  const checkpoint = resource.beforeImage as Record<string, unknown>;
  const resourceUrl = checkpoint.resourceUrl;
  const createUrl = checkpoint.createUrl;
  const createRequestId = checkpoint.createRequestId;
  const providerIdentity = checkpoint.providerIdentity;
  if (
    checkpoint.kind !== "generic_created_resource" || checkpoint.protocolVersion !== 2 ||
    checkpoint.phase !== "applied" || checkpoint.resourceKey !== resource.resourceKey ||
    checkpoint.ownershipMarker !== null || checkpoint.providerIdentityField !== "createTime" ||
    typeof providerIdentity !== "string" || !GOOGLE_CREATE_TIME_PATTERN.test(providerIdentity) ||
    createRequestId !== resource.requestId || typeof createRequestId !== "string" ||
    !UUID_PATTERN.test(createRequestId) ||
    typeof resourceUrl !== "string" || typeof createUrl !== "string" ||
    !SHA256_PATTERN.test(String(checkpoint.expectedParamsDigest ?? "")) ||
    !SHA256_PATTERN.test(String(checkpoint.expectedPayloadDigest ?? ""))
  ) return false;
  const match = resourceUrl.match(
    /^https:\/\/beyondcorp\.googleapis\.com\/v1\/projects\/([^/?#]+)\/locations\/global\/securityGateways\/default$/,
  );
  if (match === null) return false;
  try {
    if (decodeURIComponent(match[1]!) !== match[1]) return false;
  } catch {
    return false;
  }
  if (createUrl !== resourceUrl.slice(0, resourceUrl.lastIndexOf("/"))) return false;
  return checkpoint.expectedParamsDigest === canonicalDigestSync({
    securityGatewayId: "default",
    requestId: createRequestId,
  }) && checkpoint.expectedPayloadDigest === canonicalDigestSync({
    displayName: "default",
    serviceDiscovery: {},
    logging: {},
  });
}

export interface TeardownResource {
  resource_key: string;
  provider: string;
  resource_type: string;
  resource_name: string;
  owned: boolean;
  shared: boolean;
  teardown_action: TeardownAction;
  /** Stable UUID sent with the destructive provider request. */
  request_id: string;
  /** Original Apply token, when the resource came from an executed step. */
  apply_request_id: string | null;
  before_image_present: boolean;
  before_image_sha256: string;
}

/**
 * Complete immutable instruction stored when teardown starts.
 *
 * The public plan exposes only the before-image digest. The durable snapshot
 * also carries the canonical content, so every provider input can be checked
 * against the operator-approved plan immediately before it is executed.
 */
export interface TeardownInstruction {
  resourceKey: string;
  provider: string;
  resourceType: string;
  resourceName: string;
  owned: boolean;
  shared: boolean;
  action: TeardownAction;
  requestId: string;
  applyRequestId: string | null;
  beforeImagePresent: boolean;
  beforeImage: unknown;
  beforeImageDigest: string;
}

export interface TeardownPlan {
  run_id: string;
  plan_hash: string;
  confirmation: string;
  resources: TeardownResource[];
  retained_resources: TeardownResource[];
  can_destroy: boolean;
}

function action(resource: DeploymentResource): TeardownAction {
  // Shared resources are never deleted, but a setting this run changed must be
  // restored from its persisted before-image. Merely reused resources have no
  // before-image and remain untouched.
  if (isCreatedSharedDefaultGateway(resource)) return "delete_if_empty";
  if (!resource.owned) return resource.beforeImage == null ? "retain" : "restore";
  // The extension only exports this trust anchor for the operator to install.
  // It has no authority to remove a certificate from OS/browser trust stores,
  // so claiming a delete would make every local-PoC teardown fail (or, worse,
  // imply that endpoint trust was revoked when it was not).
  if (resource.provider === "local" && resource.resourceType === "root_certificate_artifact") {
    return "retain";
  }
  // A gateway is removed only once no application remains under it; anything
  // else this deployment owns outright is deleted.
  if (resource.resourceType === "security_gateway") return "delete_if_empty";
  return "delete";
}

function uuidFromDigest(digest: string): string {
  // Google requestId fields accept UUIDs. Set the RFC 4122 version/variant
  // bits while retaining deterministic input so retries use the same token.
  const hex = digest.slice(0, 32).split("");
  hex[12] = "4";
  hex[16] = ((Number.parseInt(hex[16]!, 16) & 0x3) | 0x8).toString(16);
  const joined = hex.join("");
  return `${joined.slice(0, 8)}-${joined.slice(8, 12)}-${joined.slice(12, 16)}-` +
    `${joined.slice(16, 20)}-${joined.slice(20, 32)}`;
}

function canonicalInstruction(instruction: TeardownInstruction): Record<string, unknown> {
  return {
    action: instruction.action,
    apply_request_id: instruction.applyRequestId,
    before_image: instruction.beforeImage,
    before_image_present: instruction.beforeImagePresent,
    before_image_sha256: instruction.beforeImageDigest,
    owned: instruction.owned,
    provider: instruction.provider,
    request_id: instruction.requestId,
    resource_key: instruction.resourceKey,
    resource_name: instruction.resourceName,
    resource_type: instruction.resourceType,
    shared: instruction.shared,
  };
}

/** Build the exact executable instruction list in dependency-safe order. */
export function buildTeardownExecutionSnapshot(
  runId: string,
  configurationHash: string,
  inventory: readonly DeploymentResource[],
): TeardownInstruction[] {
  const described = inventory.map((resource) => {
    const beforeImagePresent = resource.beforeImage != null;
    const beforeImage = beforeImagePresent ? structuredClone(resource.beforeImage) : null;
    const beforeImageDigest = canonicalDigestSync(beforeImage);
    const targetAction = action(resource);
    const requestSeed = canonicalDigestSync({
      run_id: runId,
      configuration_hash: configurationHash,
      resource_key: resource.resourceKey,
      provider: resource.provider,
      resource_type: resource.resourceType,
      resource_name: resource.resourceName,
      owned: resource.owned,
      shared: resource.shared,
      action: targetAction,
      apply_request_id: resource.requestId ?? null,
      before_image_present: beforeImagePresent,
      before_image: beforeImage,
      before_image_sha256: beforeImageDigest,
    });
    return {
      resourceKey: resource.resourceKey,
      provider: resource.provider,
      resourceType: resource.resourceType,
      resourceName: resource.resourceName,
      owned: resource.owned,
      shared: resource.shared,
      action: targetAction,
      requestId: uuidFromDigest(requestSeed),
      applyRequestId: resource.requestId ?? null,
      beforeImagePresent,
      beforeImage,
      beforeImageDigest,
    } satisfies TeardownInstruction;
  });
  return described.filter((item) => item.action !== "retain").reverse();
}

export function teardownInstructionHash(
  runId: string,
  configurationHash: string,
  instructions: readonly TeardownInstruction[],
): string {
  return canonicalDigestSync({
    schema_version: 2,
    run_id: runId,
    configuration_hash: configurationHash,
    instructions: instructions.map(canonicalInstruction),
  });
}

/** Fail closed if any stored provider input differs from the approved bytes. */
export function assertTeardownSnapshotIntegrity(options: {
  runId: string;
  configurationHash: string;
  planHash: string;
  instructions: readonly TeardownInstruction[];
}): void {
  for (const instruction of options.instructions) {
    if (
      canonicalDigestSync(instruction.beforeImage) !== instruction.beforeImageDigest
    ) {
      throw new Error("teardown-before-image-integrity-failed");
    }
  }
  if (
    teardownInstructionHash(
      options.runId,
      options.configurationHash,
      options.instructions,
    ) !== options.planHash
  ) {
    throw new Error("teardown-instruction-integrity-failed");
  }
}

function publicResource(instruction: TeardownInstruction): TeardownResource {
  return {
    resource_key: instruction.resourceKey,
    provider: instruction.provider,
    resource_type: instruction.resourceType,
    resource_name: instruction.resourceName,
    owned: instruction.owned,
    shared: instruction.shared,
    teardown_action: instruction.action,
    request_id: instruction.requestId,
    apply_request_id: instruction.applyRequestId,
    before_image_present: instruction.beforeImagePresent,
    before_image_sha256: instruction.beforeImageDigest,
  };
}

export function buildTeardownPlan(
  runId: string,
  configurationHash: string,
  deploymentName: string,
  inventory: readonly DeploymentResource[],
): TeardownPlan {
  const instructions = buildTeardownExecutionSnapshot(runId, configurationHash, inventory);
  const executableKeys = new Set(instructions.map((item) => item.resourceKey));
  const deletions = instructions.map(publicResource);
  const retained = inventory
    .filter((item) => !executableKeys.has(item.resourceKey))
    .map((resource) => {
      const beforeImagePresent = resource.beforeImage != null;
      const beforeImage = beforeImagePresent ? structuredClone(resource.beforeImage) : null;
      const instruction: TeardownInstruction = {
        resourceKey: resource.resourceKey,
        provider: resource.provider,
        resourceType: resource.resourceType,
        resourceName: resource.resourceName,
        owned: resource.owned,
        shared: resource.shared,
        action: "retain",
        requestId: uuidFromDigest(canonicalDigestSync({
          run_id: runId,
          configuration_hash: configurationHash,
          resource_key: resource.resourceKey,
          action: "retain",
        })),
        applyRequestId: resource.requestId ?? null,
        beforeImagePresent,
        beforeImage,
        beforeImageDigest: canonicalDigestSync(beforeImage),
      };
      return publicResource(instruction);
    });

  const planHash = teardownInstructionHash(runId, configurationHash, instructions);

  return {
    run_id: runId,
    plan_hash: planHash,
    // Bound to the hash: a confirmation typed for one inventory will not match
    // a plan rebuilt from a different one.
    confirmation: `DELETE ${deploymentName} ${planHash.slice(0, 12)}`,
    resources: deletions,
    retained_resources: retained,
    can_destroy: deletions.length > 0,
  };
}
