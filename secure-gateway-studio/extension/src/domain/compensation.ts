import type { ResourceChange } from "./planner.ts";

export type CompensationCapability =
  | { available: true }
  | { available: false; errorCode: string };

const AVAILABLE: CompensationCapability = { available: true };
const SHARED_PHASES = new Set(["prepared", "sending", "rejected", "applied"]);
const SECRET_VERSION_PHASES = new Set([
  "prepared",
  "sending",
  "rejected",
  "version_added",
  "alias_sending",
  "applied",
]);
const OFFLOAD_REFRESH_PHASES = new Set([
  "prepared",
  "stop_sending",
  "restart_rejected",
  "stopped",
  "start_sending",
  "applied",
]);

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function objectField(value: unknown): boolean {
  return record(value) !== null;
}

function stringField(value: unknown): boolean {
  return typeof value === "string" && value !== "";
}

/**
 * Validate that a persisted checkpoint has the current compensation protocol.
 * This is deliberately pure: legacy adoption can classify every residual step
 * before a Google transport or an executor-local cache exists.
 */
export function validCompensationCheckpoint(value: unknown): boolean {
  const checkpoint = record(value);
  if (checkpoint === null || typeof checkpoint.kind !== "string") return false;
  switch (checkpoint.kind) {
    case "iam":
    case "secret_iam":
      return SHARED_PHASES.has(String(checkpoint.phase)) &&
        stringField(checkpoint.setUrl) && objectField(checkpoint.policy) &&
        objectField(checkpoint.afterPolicy);
    case "chrome_policy":
      return SHARED_PHASES.has(String(checkpoint.phase)) &&
        stringField(checkpoint.schemaName) && objectField(checkpoint.previous) &&
        (checkpoint.phase !== "applied" || objectField(checkpoint.managedAfter));
    case "router_nats":
      return stringField(checkpoint.routerUrl) && Array.isArray(checkpoint.nats) &&
        objectField(checkpoint.managedNat);
    case "generic_created_resource":
      return checkpoint.protocolVersion === 2 && SHARED_PHASES.has(String(checkpoint.phase)) &&
        stringField(checkpoint.resourceKey) && stringField(checkpoint.createUrl) &&
        stringField(checkpoint.resourceUrl) && stringField(checkpoint.createRequestId) &&
        stringField(checkpoint.expectedParamsDigest) &&
        stringField(checkpoint.expectedPayloadDigest) &&
        (checkpoint.ownershipMarker === null || stringField(checkpoint.ownershipMarker));
    case "named_resource_ownership":
      return checkpoint.protocolVersion === 1 && SHARED_PHASES.has(String(checkpoint.phase)) &&
        stringField(checkpoint.resourceKind) && stringField(checkpoint.resourceUrl) &&
        stringField(checkpoint.ownershipToken) && stringField(checkpoint.marker);
    case "offload_refresh":
      return OFFLOAD_REFRESH_PHASES.has(String(checkpoint.phase)) &&
        stringField(checkpoint.instanceUrl) && stringField(checkpoint.stopRequestId) &&
        stringField(checkpoint.startRequestId);
    case "privateca_certificate":
      return checkpoint.protocolVersion === 1 && SHARED_PHASES.has(String(checkpoint.phase)) &&
        stringField(checkpoint.certificateName) && stringField(checkpoint.authorityName) &&
        stringField(checkpoint.csrDigest) &&
        (checkpoint.phase !== "sending" || stringField(checkpoint.csrPem));
    case "secret_version":
      return SECRET_VERSION_PHASES.has(String(checkpoint.phase)) &&
        stringField(checkpoint.secretUrl) &&
        (checkpoint.versionName === null || stringField(checkpoint.versionName)) &&
        objectField(checkpoint.previousAliases) && objectField(checkpoint.previousLabels) &&
        (checkpoint.phase !== "sending" ||
          (stringField(checkpoint.payloadDigest) &&
            Array.isArray(checkpoint.existingVersionNames) &&
            stringField(checkpoint.ownershipToken))) &&
        ((checkpoint.phase !== "version_added" && checkpoint.phase !== "alias_sending" &&
            checkpoint.phase !== "applied") || stringField(checkpoint.versionName)) &&
        (checkpoint.phase !== "applied" ||
          (objectField(checkpoint.managedAfterAliases) &&
            objectField(checkpoint.managedAfterLabels)));
    default:
      return false;
  }
}

function checkpointMatchesChange(
  change: Pick<ResourceChange, "provider" | "resource_type">,
  value: unknown,
): boolean {
  const checkpoint = record(value);
  if (checkpoint === null) return false;
  const kind = `${change.provider}:${change.resource_type}`;
  if (
    kind === "beyondcorp:gateway_iam" || kind === "beyondcorp:application_iam" ||
    kind === "cloudresourcemanager:project_iam"
  ) return checkpoint.kind === "iam";
  if (kind === "secretmanager:secret_iam") return checkpoint.kind === "secret_iam";
  if (kind.startsWith("chromepolicy:")) return checkpoint.kind === "chrome_policy";
  if (kind === "compute:cloud_nat") return checkpoint.kind === "router_nats";
  if (kind === "compute:offload_refresh") return checkpoint.kind === "offload_refresh";
  if (
    change.provider === "compute" || kind === "beyondcorp:security_gateway" ||
    kind === "beyondcorp:application"
  ) return checkpoint.kind === "generic_created_resource";
  if (
    kind === "iam:service_account" || kind === "dns:private_zone" ||
    kind === "dns:record_set" || kind === "secretmanager:secret"
  ) return checkpoint.kind === "named_resource_ownership";
  if (kind === "privateca:certificate") return checkpoint.kind === "privateca_certificate";
  if (kind === "secretmanager:secret_version") return checkpoint.kind === "secret_version";
  return false;
}

/**
 * Determine whether one step can be compensated using durable state alone.
 * No resource lookup is permitted here; live names are not ownership proof.
 */
export function compensationCapability(
  change: Pick<ResourceChange, "provider" | "resource_type" | "owned_after_apply">,
  beforeImage: unknown,
): CompensationCapability {
  if (beforeImage !== undefined) {
    if (!validCompensationCheckpoint(beforeImage) ||
        !checkpointMatchesChange(change, beforeImage)) {
      return { available: false, errorCode: "compensation-checkpoint-invalid" };
    }
    const checkpoint = record(beforeImage) as Record<string, unknown>;
    if ((checkpoint.kind === "iam" || checkpoint.kind === "secret_iam") &&
        checkpoint.phase === "sending") {
      return { available: false, errorCode: "iam-rollback-outcome-ambiguous" };
    }
    if (checkpoint.kind === "chrome_policy" && checkpoint.phase === "sending") {
      return { available: false, errorCode: "chrome-policy-rollback-outcome-ambiguous" };
    }
    if (checkpoint.kind === "generic_created_resource" &&
        checkpoint.phase === "sending" && checkpoint.ownershipMarker === null) {
      return { available: false, errorCode: "generic-resource-provider-response-ambiguous" };
    }
    return AVAILABLE;
  }
  if (!change.owned_after_apply) return AVAILABLE;

  const kind = `${change.provider}:${change.resource_type}`;
  if (
    kind === "serviceusage:project_services" ||
    kind === "accesscontextmanager:access_level" ||
    kind === "compute:source_image" ||
    kind === "compute:offload_refresh" ||
    kind === "local:root_certificate_artifact"
  ) {
    return AVAILABLE;
  }
  if (kind === "compute:cloud_nat") {
    return { available: false, errorCode: "cloud-nat-ownership-checkpoint-missing" };
  }
  if (
    change.provider === "compute" || kind === "beyondcorp:security_gateway" ||
    kind === "beyondcorp:application"
  ) {
    return { available: false, errorCode: "generic-resource-ownership-checkpoint-missing" };
  }
  if (kind === "dns:record_set") {
    return { available: false, errorCode: "dns-record-ownership-checkpoint-missing" };
  }
  if (
    kind === "iam:service_account" || kind === "dns:private_zone" ||
    kind === "secretmanager:secret"
  ) {
    return { available: false, errorCode: "named-resource-ownership-checkpoint-missing" };
  }
  if (
    kind === "beyondcorp:gateway_iam" || kind === "beyondcorp:application_iam" ||
    kind === "cloudresourcemanager:project_iam" || kind === "secretmanager:secret_iam"
  ) {
    return { available: false, errorCode: "iam-ownership-checkpoint-missing" };
  }
  if (kind.startsWith("chromepolicy:")) {
    return { available: false, errorCode: "chrome-policy-before-image-missing" };
  }
  if (kind === "secretmanager:secret_version") {
    return { available: false, errorCode: "secret-version-ownership-checkpoint-missing" };
  }
  return AVAILABLE;
}
