/**
 * Production offload tier: managed instance group and internal load balancer.
 *
 * The PoC path runs a single VM. Production replaces it with a two-zone
 * regional managed instance group behind an internal TCP load balancer, so a
 * zone outage or an instance replacement does not take the gateway down. That
 * is the whole difference, and it is why these handlers exist separately.
 *
 * Two waits here are not optional. The group must report stable with the
 * configured baseline running before the load balancer is pointed at it, and
 * the backend must report healthy before the forwarding rule is considered
 * done -- otherwise Apply reports success while Secure Gateway is still
 * connecting to nothing.
 */

import {
  canonicalSecretVersionUrl,
  GoogleApiError,
  isDefiniteMutationRejection,
  ProviderExecutionError,
  secretPayloadDigest,
  secretPayloadOwnershipToken,
  type Transport,
} from "./executor.ts";
import { secretPayload, validatePublicCertificateAccessResponse } from "./certificates.ts";
import { canonicalDigestSync, canonicalJson } from "../domain/canonical.ts";
import { configurationHash } from "../domain/planner.ts";
import type { ResourceChange, SourceImageBinding } from "../domain/planner.ts";
import { serviceAccountEmail } from "../domain/naming.ts";
import type { DeploymentSpec } from "../domain/spec.ts";
import { offloadStartupScript } from "./startup-scripts.ts";
import {
  applyNamedResourceCreate,
  networkName,
  revalidatePublicCertificateBinding,
  subnetName,
  type PathAContext,
} from "./executor-path-a.ts";

const COMPUTE = "https://compute.googleapis.com/compute/v1";
const COMPUTE_RESOURCE = "https://www.googleapis.com/compute/v1";
const SECRETS = "https://secretmanager.googleapis.com/v1";
const MANAGED_BY = "Managed by Secure Gateway Studio";

function base(spec: DeploymentSpec): string {
  return `${COMPUTE}/projects/${spec.project_id}`;
}

function regional(spec: DeploymentSpec, collection: string): string {
  return `${base(spec)}/regions/${spec.region}/${collection}`;
}

function scopedRequestId(value: string, discriminator: number): string {
  const compact = value.replaceAll("-", "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(compact)) throw new ProviderExecutionError("request-id-invalid");
  const last = (Number.parseInt(compact.slice(-2), 16) ^ discriminator)
    .toString(16).padStart(2, "0");
  const next = `${compact.slice(0, -2)}${last}`;
  return `${next.slice(0, 8)}-${next.slice(8, 12)}-${next.slice(12, 16)}-${next.slice(16, 20)}-${next.slice(20)}`;
}

/**
 * Labels that let an operator see, from the Google console alone, which
 * deployment a secret belongs to and whether it is current.
 */
function secretLabels(
  spec: DeploymentSpec,
  ownershipToken?: string,
): Record<string, string> {
  const certificateInputs = {
    ca_name: spec.ca_name ?? null,
    ca_pool: spec.ca_pool ?? null,
    certificate_lifetime_days: spec.certificate_lifetime_days,
    certificate_strategy: spec.certificate_strategy,
    private_hostname: spec.private_hostname,
    public_certificate_secret: spec.public_certificate_secret ?? null,
  };
  const labels: Record<string, string> = {
    "certificate-spec-hash": canonicalDigestSync(certificateInputs).slice(0, 32),
    "configuration-hash": configurationHash(spec).slice(0, 32),
    "managed-by": "secure-gateway-studio",
  };
  if (ownershipToken !== undefined) labels["sgs-owner-token"] = ownershipToken;
  return labels;
}

async function ilbTlsMaterial(
  context: PathAContext,
  spec: DeploymentSpec,
): Promise<{ certificate: string; privateKey: string }> {
  let bundle = context.certificate;
  if (spec.certificate_strategy === "public_trusted") {
    const binding = context.publicCertificateBinding;
    const secretName = spec.public_certificate_secret?.split("/").pop();
    if (!binding || !secretName) {
      throw new ProviderExecutionError("public-certificate-plan-binding-invalid");
    }
    await revalidatePublicCertificateBinding(context.transport, spec, binding);
    const access = await context.transport.requestJson(
      "GET",
      `https://secretmanager.googleapis.com/v1/${binding.secret_version_name}:access`,
    );
    bundle = (await validatePublicCertificateAccessResponse(access.payload, {
      projectId: spec.project_id,
      secretName,
      hostname: spec.private_hostname,
      minimumValidityDays: spec.mode === "production" ? 30 : 1,
      expectedVersionName: binding.secret_version_name,
      expectedPayloadSha256: binding.payload_sha256,
    })).bundle;
  }
  if (!bundle) {
    const secretName = `${spec.name}-tls`;
    const access = await context.transport.requestJson(
      "GET",
      `${SECRETS}/projects/${spec.project_id}/secrets/${secretName}/versions/active:access`,
    );
    bundle = (await validatePublicCertificateAccessResponse(access.payload, {
      projectId: spec.project_id,
      secretName,
      hostname: spec.private_hostname,
      minimumValidityDays: spec.mode === "production" ? 30 : 1,
    })).bundle;
  }
  return {
    certificate: bundle.certificatePem + bundle.certificateChainPem.join(""),
    privateKey: bundle.privateKeyPem,
  };
}

function runOwnedSecretPayload(
  bundle: NonNullable<PathAContext["certificate"]>,
  ownershipToken: string,
): string {
  const decoded: unknown = JSON.parse(secretPayload(bundle));
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new ProviderExecutionError("secret-version-payload-invalid");
  }
  return canonicalJson({
    ...(decoded as Record<string, unknown>),
    sgs_ownership_token: ownershipToken,
  });
}

interface SecretVersionBeforeImage {
  kind: "secret_version";
  phase?: SecretVersionPhase;
  secretUrl: string;
  versionName: string | null;
  previousAliases: Record<string, string>;
  previousLabels: Record<string, string>;
  managedAfterAliases?: Record<string, string>;
  managedAfterLabels?: Record<string, string>;
  /** Present on 0.2.1+ checkpoints created before addVersion. */
  payloadDigest?: string;
  /** Exact version names that existed before addVersion. */
  existingVersionNames?: string[];
  ownershipToken?: string;
}

type SecretVersionPhase =
  | "prepared"
  | "sending"
  | "rejected"
  | "version_added"
  | "alias_sending"
  | "applied";

const SECRET_VERSION_PHASES = new Set<SecretVersionPhase>([
  "prepared",
  "sending",
  "rejected",
  "version_added",
  "alias_sending",
  "applied",
]);

function secretVersionPhase(before: SecretVersionBeforeImage): SecretVersionPhase {
  if (before.phase !== undefined) return before.phase;
  if (before.versionName === null) return "sending";
  if (
    before.managedAfterAliases !== undefined &&
    before.managedAfterLabels !== undefined
  ) return "alias_sending";
  return "version_added";
}

function secretVersionBeforeImage(value: unknown): SecretVersionBeforeImage | null {
  if (typeof value !== "object" || value === null) return null;
  const image = value as Partial<SecretVersionBeforeImage>;
  const stringMap = (candidate: unknown): boolean =>
    typeof candidate === "object" && candidate !== null && !Array.isArray(candidate) &&
    Object.values(candidate).every((item) => typeof item === "string");
  const valid = image.kind === "secret_version" &&
      (image.phase === undefined || SECRET_VERSION_PHASES.has(image.phase)) &&
      typeof image.secretUrl === "string" &&
      (typeof image.versionName === "string" || image.versionName === null) &&
      stringMap(image.previousAliases) && stringMap(image.previousLabels) &&
      (image.managedAfterAliases === undefined || stringMap(image.managedAfterAliases)) &&
      (image.managedAfterLabels === undefined || stringMap(image.managedAfterLabels)) &&
      (image.payloadDigest === undefined || typeof image.payloadDigest === "string") &&
      (image.existingVersionNames === undefined ||
        (Array.isArray(image.existingVersionNames) &&
          image.existingVersionNames.every((item) => typeof item === "string"))) &&
      (image.ownershipToken === undefined || typeof image.ownershipToken === "string");
  if (!valid) return null;
  const typed = image as SecretVersionBeforeImage;
  if (typed.phase === undefined) return typed;
  const beforeAdd =
    typed.phase === "prepared" || typed.phase === "sending" || typed.phase === "rejected";
  if (beforeAdd !== (typed.versionName === null)) return null;
  if (
    typeof typed.payloadDigest !== "string" || typed.payloadDigest === "" ||
    !Array.isArray(typed.existingVersionNames) ||
    typeof typed.ownershipToken !== "string" || typed.ownershipToken === ""
  ) return null;
  const hasManagedAliases = typed.managedAfterAliases !== undefined;
  const hasManagedLabels = typed.managedAfterLabels !== undefined;
  if (hasManagedAliases !== hasManagedLabels) return null;
  if (
    (typed.phase === "alias_sending" || typed.phase === "applied") !==
      (hasManagedAliases && hasManagedLabels)
  ) return null;
  return typed;
}

function secretStringMap(value: unknown, field: string): Record<string, string> {
  if (value === undefined) return {};
  if (
    typeof value !== "object" || value === null || Array.isArray(value) ||
    Object.values(value).some((item) => typeof item !== "string")
  ) {
    throw new ProviderExecutionError(`secret-${field}-invalid`);
  }
  return structuredClone(value as Record<string, string>);
}

function mapEntryEquals(
  left: Record<string, string>,
  right: Record<string, string>,
  key: string,
): boolean {
  return Object.hasOwn(left, key) === Object.hasOwn(right, key) && left[key] === right[key];
}

function changedMapKeys(
  before: Record<string, string>,
  after: Record<string, string>,
): string[] {
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter((key) => !mapEntryEquals(before, after, key));
}

function promotionState(
  beforeAliases: Record<string, string>,
  afterAliases: Record<string, string>,
  beforeLabels: Record<string, string>,
  afterLabels: Record<string, string>,
  currentAliases: Record<string, string>,
  currentLabels: Record<string, string>,
): "before" | "after" | "conflict" {
  const aliasKeys = changedMapKeys(beforeAliases, afterAliases);
  const labelKeys = changedMapKeys(beforeLabels, afterLabels);
  const matches = (
    aliases: Record<string, string>,
    labels: Record<string, string>,
  ): boolean =>
    aliasKeys.every((key) => mapEntryEquals(currentAliases, aliases, key)) &&
    labelKeys.every((key) => mapEntryEquals(currentLabels, labels, key));
  if (matches(afterAliases, afterLabels)) return "after";
  if (matches(beforeAliases, beforeLabels)) return "before";
  return "conflict";
}

function applyMapDelta(
  current: Record<string, string>,
  before: Record<string, string>,
  after: Record<string, string>,
): Record<string, string> {
  const result = { ...current };
  for (const key of changedMapKeys(before, after)) {
    if (Object.hasOwn(after, key)) result[key] = after[key]!;
    else delete result[key];
  }
  return result;
}

function isSecretEtagPrecondition(error: unknown): error is GoogleApiError {
  if (!(error instanceof GoogleApiError) || error.status !== 400) return false;
  const detail = error.payload.error;
  return typeof detail === "object" && detail !== null && !Array.isArray(detail) &&
    (detail as { status?: unknown }).status === "FAILED_PRECONDITION";
}

async function listSecretVersions(
  context: PathAContext,
  secretUrl: string,
  projectId: string,
  secretName: string,
): Promise<Array<{ name: string; state: string }>> {
  const versions: Array<{ name: string; state: string }> = [];
  let pageToken: string | undefined;
  const seenTokens = new Set<string>();
  for (let page = 0; page < 100; page += 1) {
    const response = await context.transport.requestJson("GET", `${secretUrl}/versions`, {
      params: {
        pageSize: 100,
        ...(pageToken === undefined ? {} : { pageToken }),
      },
    });
    const pageVersions = response.payload.versions;
    if (pageVersions !== undefined && !Array.isArray(pageVersions)) {
      throw new ProviderExecutionError("secret-version-list-invalid");
    }
    for (const value of pageVersions ?? []) {
      if (typeof value !== "object" || value === null) {
        throw new ProviderExecutionError("secret-version-list-invalid");
      }
      const item = value as { name?: unknown; state?: unknown };
      if (typeof item.name !== "string" || typeof item.state !== "string") {
        throw new ProviderExecutionError("secret-version-list-invalid");
      }
      versions.push({
        name: canonicalSecretVersionUrl(item.name, projectId, secretName),
        state: item.state,
      });
    }
    const next = response.payload.nextPageToken;
    if (next === undefined || next === "") return versions;
    if (typeof next !== "string" || seenTokens.has(next)) {
      throw new ProviderExecutionError("secret-version-pagination-invalid");
    }
    seenTokens.add(next);
    pageToken = next;
  }
  throw new ProviderExecutionError("secret-version-pagination-exhausted");
}

async function recoverCreatedSecretVersion(
  context: PathAContext,
  change: ResourceChange,
  spec: DeploymentSpec,
  before: SecretVersionBeforeImage,
): Promise<SecretVersionBeforeImage> {
  if (
    typeof before.payloadDigest !== "string" || before.payloadDigest === "" ||
    !Array.isArray(before.existingVersionNames) ||
    typeof before.ownershipToken !== "string" || before.ownershipToken === ""
  ) {
    throw new ProviderExecutionError("secret-version-recovery-metadata-missing");
  }
  const baseline = new Set(before.existingVersionNames.map((name) =>
    canonicalSecretVersionUrl(name, spec.project_id, change.resource_name)
  ));
  const candidates = (await listSecretVersions(
    context,
    before.secretUrl,
    spec.project_id,
    change.resource_name,
  )).filter(
    (version) => version.state === "ENABLED" && !baseline.has(version.name),
  );
  const matching: string[] = [];
  for (const candidate of candidates) {
    const accessed = await context.transport.requestJson(
      "GET",
      `${candidate.name}:access`,
    );
    const data = (accessed.payload.payload as { data?: unknown } | undefined)?.data;
    if (typeof data !== "string") {
      throw new ProviderExecutionError("secret-version-access-payload-invalid");
    }
    if (
      secretPayloadDigest(data) === before.payloadDigest &&
      secretPayloadOwnershipToken(data) === before.ownershipToken
    ) matching.push(candidate.name);
  }
  if (matching.length === 0) {
    throw new ProviderExecutionError("secret-version-recovery-not-found");
  }
  if (matching.length > 1) {
    throw new ProviderExecutionError("secret-version-recovery-ambiguous");
  }
  const recovered = {
    ...before,
    phase: "version_added" as const,
    versionName: matching[0]!,
  };
  await context.captureBefore?.(change, recovered);
  return recovered;
}

async function resumeSecretVersionPromotion(
  context: PathAContext,
  change: ResourceChange,
  spec: DeploymentSpec,
  secretUrl: string,
  before: SecretVersionBeforeImage,
  payloadData?: string,
): Promise<void> {
  if (before.secretUrl !== secretUrl) {
    throw new ProviderExecutionError("secret-version-resume-metadata-invalid");
  }
  let recovered = before;
  let phase = secretVersionPhase(recovered);
  let versionAcknowledgedNow = false;
  if (phase === "rejected") {
    throw new ProviderExecutionError("secret-version-add-rejected");
  }
  if (phase === "prepared") {
    if (
      payloadData === undefined || typeof recovered.payloadDigest !== "string" ||
      recovered.payloadDigest !== secretPayloadDigest(payloadData)
    ) {
      throw new ProviderExecutionError("secret-version-prepared-payload-unavailable");
    }
    recovered = { ...recovered, phase: "sending" };
    await context.captureBefore?.(change, recovered);
    try {
      const payload = (
        await context.transport.requestJson("POST", `${secretUrl}:addVersion`, {
          jsonBody: { payload: { data: payloadData } },
        })
      ).payload;
      if (typeof payload.name !== "string" || payload.name === "") {
        throw new ProviderExecutionError("secret-version-name-missing");
      }
      recovered = {
        ...recovered,
        phase: "version_added",
        versionName: canonicalSecretVersionUrl(
          payload.name,
          spec.project_id,
          change.resource_name,
        ),
      };
      await context.captureBefore?.(change, recovered);
      versionAcknowledgedNow = true;
    } catch (error) {
      if (
        error instanceof GoogleApiError &&
        [400, 401, 403, 404, 409, 412].includes(error.status)
      ) {
        const rejected: SecretVersionBeforeImage = {
          ...recovered,
          phase: "rejected",
          versionName: null,
        };
        await context.captureBefore?.(change, rejected);
      }
      throw error;
    }
    phase = secretVersionPhase(recovered);
  } else if (phase === "sending") {
    recovered = await recoverCreatedSecretVersion(context, change, spec, recovered);
    phase = "version_added";
  }

  const rawVersionName = recovered.versionName;
  if (rawVersionName === null) {
    throw new ProviderExecutionError("secret-version-resume-metadata-invalid");
  }
  const versionName = canonicalSecretVersionUrl(
    rawVersionName,
    spec.project_id,
    change.resource_name,
  );
  recovered = { ...recovered, versionName };
  const version = versionName.slice(versionName.lastIndexOf("/") + 1);
  if (!versionAcknowledgedNow) {
    const existingVersion = await context.transport.requestJson("GET", versionName);
    if (existingVersion.payload.state !== "ENABLED") {
      throw new ProviderExecutionError("secret-version-resume-state-invalid");
    }
  }
  const secret = (await context.transport.requestJson("GET", secretUrl)).payload as {
    etag?: unknown;
    versionAliases?: unknown;
    labels?: unknown;
  };
  if (typeof secret.etag !== "string" || secret.etag === "") {
    throw new ProviderExecutionError("secret-etag-missing");
  }
  const currentAliases = secretStringMap(secret.versionAliases, "version-aliases");
  const currentLabels = secretStringMap(secret.labels, "labels");
  const hasManagedAliases = recovered.managedAfterAliases !== undefined;
  const hasManagedLabels = recovered.managedAfterLabels !== undefined;
  if (hasManagedAliases !== hasManagedLabels) {
    throw new ProviderExecutionError("secret-version-managed-state-invalid");
  }
  if (
    (phase === "alias_sending" || phase === "applied") &&
    (!hasManagedAliases || !hasManagedLabels)
  ) {
    throw new ProviderExecutionError("secret-version-managed-state-invalid");
  }

  // A new-format checkpoint without managed-after was durably written before
  // addVersion and therefore before any metadata PATCH. Rebase its compensation
  // baseline onto this fresh, etag-bearing snapshot so an administrator change
  // between the original GET and this GET is not later rolled back. A legacy
  // checkpoint cannot prove that the PATCH was never sent, so it keeps its
  // original baseline and is reconciled below without overwriting a conflict.
  const mayRebasePrePatch =
    !hasManagedAliases && recovered.phase === "version_added" &&
    typeof recovered.payloadDigest === "string" &&
    Array.isArray(recovered.existingVersionNames);
  const previousAliases = mayRebasePrePatch
    ? currentAliases
    : structuredClone(recovered.previousAliases);
  const previousLabels = mayRebasePrePatch
    ? currentLabels
    : structuredClone(recovered.previousLabels);
  const managedAfterAliases = hasManagedAliases
    ? structuredClone(recovered.managedAfterAliases!)
    : { ...previousAliases, active: version };
  const managedAfterLabels = hasManagedLabels
    ? structuredClone(recovered.managedAfterLabels!)
    : {
      ...previousLabels,
      ...secretLabels(spec),
      "sgs-active-version": version,
      "sgs-previous-active": previousAliases.active ?? "none",
    };
  const checkpoint = {
    ...recovered,
    phase: phase === "applied" ? "applied" as const : "alias_sending" as const,
    previousAliases,
    previousLabels,
    managedAfterAliases,
    managedAfterLabels,
  };
  await context.captureBefore?.(change, checkpoint);

  let liveEtag = secret.etag;
  let liveAliases = currentAliases;
  let liveLabels = currentLabels;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const state = promotionState(
      previousAliases,
      managedAfterAliases,
      previousLabels,
      managedAfterLabels,
      liveAliases,
      liveLabels,
    );
    if (state === "after") {
      if (phase !== "applied") {
        await context.captureBefore?.(change, { ...checkpoint, phase: "applied" });
      }
      return;
    }
    if (state === "conflict" || phase === "applied") {
      throw new ProviderExecutionError("secret-version-current-state-changed");
    }
    try {
      await context.transport.requestJson("PATCH", secretUrl, {
        params: { updateMask: "versionAliases,labels" },
        jsonBody: {
          etag: liveEtag,
          labels: applyMapDelta(liveLabels, previousLabels, managedAfterLabels),
          versionAliases: applyMapDelta(
            liveAliases,
            previousAliases,
            managedAfterAliases,
          ),
        },
      });
      await context.captureBefore?.(change, { ...checkpoint, phase: "applied" });
      return;
    } catch (error) {
      if (!isSecretEtagPrecondition(error) || attempt === 2) throw error;
      const fresh = (await context.transport.requestJson("GET", secretUrl)).payload;
      if (typeof fresh.etag !== "string" || fresh.etag === "") {
        throw new ProviderExecutionError("secret-etag-missing");
      }
      liveEtag = fresh.etag;
      liveAliases = secretStringMap(fresh.versionAliases, "version-aliases");
      liveLabels = secretStringMap(fresh.labels, "labels");
      await new Promise((resolve) => setTimeout(resolve, 25 * (2 ** attempt)));
    }
  }
  throw new ProviderExecutionError("secret-version-etag-retry-exhausted");
}

export async function applyProduction(
  context: PathAContext,
  change: ResourceChange,
  spec: DeploymentSpec,
): Promise<boolean> {
  const { transport } = context;
  const kind = `${change.provider}:${change.resource_type}`;

  const post = async (
    url: string,
    body: Record<string, unknown>,
    params?: Record<string, string | number>,
  ): Promise<Record<string, unknown>> =>
    (await transport.requestJson("POST", url, { params, jsonBody: body })).payload;

  switch (kind) {
    case "secretmanager:secret": {
      const collection = `${SECRETS}/projects/${spec.project_id}/secrets`;
      const resourceUrl = `${collection}/${change.resource_name}`;
      const ownershipToken = context.requestId(change);
      const labels = secretLabels(spec, ownershipToken);
      const identity = {
        kind: "named_resource_ownership",
        resourceKind: "secretmanager_secret",
        resourceUrl,
        ownershipToken,
        marker: ownershipToken,
      } as const;
      const reconcile = async (): Promise<boolean> => {
        const existing = await transport.requestJson("GET", resourceUrl, {
          acceptedStatuses: [404],
        });
        if (existing.status === 404) return false;
        const existingLabels = existing.payload.labels;
        const automatic = (
          existing.payload.replication as { automatic?: unknown } | undefined
        )?.automatic;
        return !(
          typeof existingLabels !== "object" || existingLabels === null ||
          Object.entries(labels).some(
            ([key, value]) => (existingLabels as Record<string, unknown>)[key] !== value,
          ) ||
          typeof automatic !== "object" || automatic === null
        );
      };
      await applyNamedResourceCreate(
        context,
        change,
        identity,
        async () => {
          const response = await transport.requestJson("POST", collection, {
            params: { secretId: change.resource_name },
            jsonBody: { labels, replication: { automatic: {} } },
            acceptedStatuses: [409],
          });
          if (response.status === 409 && !(await reconcile())) {
            throw new ProviderExecutionError("secret-reconciliation-failed");
          }
        },
        reconcile,
      );
      return true;
    }

    case "secretmanager:secret_version": {
      // Promotion is deliberately three steps: add the version, then move the
      // `active` alias onto it. The offload VM reads `active`, so the alias
      // move is the moment the rotation takes effect -- and it is atomic, so a
      // half-written rotation cannot leave the VM reading a version that does
      // not exist.
      const secretUrl =
        `${SECRETS}/projects/${spec.project_id}/secrets/${change.resource_name}`;
      const resumed = secretVersionBeforeImage(context.beforeImage);
      if (resumed !== null) {
        const resumedPayload = context.certificate === undefined
          ? undefined
          : typeof resumed.ownershipToken === "string"
          ? base64Utf8(runOwnedSecretPayload(context.certificate, resumed.ownershipToken))
          : undefined;
        await resumeSecretVersionPromotion(
          context,
          change,
          spec,
          secretUrl,
          resumed,
          resumedPayload,
        );
        return true;
      }
      if (context.beforeImage !== undefined) {
        throw new ProviderExecutionError("secret-version-checkpoint-invalid");
      }
      const bundle = context.certificate;
      if (bundle === undefined) {
        throw new ProviderExecutionError("certificate-not-issued");
      }

      const original = (await transport.requestJson("GET", secretUrl)).payload as {
        versionAliases?: unknown;
        labels?: unknown;
      };
      const ownershipToken = context.requestId(change);
      const payloadData = base64Utf8(runOwnedSecretPayload(bundle, ownershipToken));
      const previousAliases = secretStringMap(original.versionAliases, "version-aliases");
      const previousLabels = secretStringMap(original.labels, "labels");
      const existingVersionNames = (await listSecretVersions(
        context,
        secretUrl,
        spec.project_id,
        change.resource_name,
      ))
        .map((version) => version.name)
        .sort();
      const prepared: SecretVersionBeforeImage = {
        kind: "secret_version",
        phase: "prepared",
        secretUrl,
        versionName: null,
        previousAliases,
        previousLabels,
        payloadDigest: secretPayloadDigest(payloadData),
        existingVersionNames,
        ownershipToken,
      };
      await context.captureBefore?.(change, prepared);
      await resumeSecretVersionPromotion(
        context,
        change,
        spec,
        secretUrl,
        prepared,
        payloadData,
      );
      return true;
    }

    case "local:root_certificate_artifact": {
      // The PoC root is handed to the operator for Chrome Root Store upload;
      // no public API can attest that handoff, which is why T07 verifies it.
      const bundle = context.certificate;
      if (bundle === undefined) {
        throw new ProviderExecutionError("certificate-not-issued");
      }
      if (bundle.certificateChainPem.length !== 1) {
        throw new ProviderExecutionError("local-poc-chain-missing-root");
      }
      await context.exportArtifact(
        `${spec.name}-poc-root.pem`,
        bundle.certificateChainPem[0],
      );
      return true;
    }

    case "compute:instance_template": {
      if (spec.source_image === null) {
        throw new ProviderExecutionError("source-image-binding-invalid");
      }
      // The Nginx upstream is the sample backend's reserved address, so it has
      // to be resolved before the template that embeds it.
      const publicCertificateVersionName = await revalidatePublicCertificateBinding(
        transport,
        spec,
        context.publicCertificateBinding,
      );
      const script = offloadStartupScript(spec, {
        backendAddress: await sampleBackendAddress(transport, spec),
        publicCertificateVersionName,
      });
      await post(
        `${base(spec)}/global/instanceTemplates`,
        {
          description: MANAGED_BY,
          name: change.resource_name,
          properties: {
            disks: [
              {
                autoDelete: true,
                boot: true,
                initializeParams: {
                  diskSizeGb: "20",
                  // Templates take bare types; only zonal resources are URLs.
                  diskType: "pd-balanced",
                  sourceImage: spec.source_image,
                },
              },
            ],
            labels: { "managed-by": "secure-gateway-studio", role: "offload" },
            machineType: "e2-small",
            metadata: {
              items: [
                { key: "startup-script", value: script },
                { key: "enable-guest-attributes", value: "TRUE" },
              ],
            },
            networkInterfaces: [
              {
                network: `${base(spec)}/global/networks/${networkName(spec)}`,
                stackType: "IPV4_ONLY",
                subnetwork: `${regional(spec, "subnetworks")}/${subnetName(spec)}`,
              },
            ],
            serviceAccounts: [
              {
                email: serviceAccountEmail(spec.name, spec.project_id, "offload"),
                scopes: ["https://www.googleapis.com/auth/cloud-platform"],
              },
            ],
            shieldedInstanceConfig: {
              enableIntegrityMonitoring: true,
              enableSecureBoot: true,
              enableVtpm: true,
            },
            tags: { items: [`${spec.name}-offload`] },
          },
        },
        { requestId: context.requestId(change) },
      );
      return true;
    }

    case "compute:instance_group": {
      const groupUrl = `${base(spec)}/zones/${spec.zone}/instanceGroups/${change.resource_name}`;
      await post(`${base(spec)}/zones/${spec.zone}/instanceGroups`, {
        name: change.resource_name,
        description: MANAGED_BY,
        namedPorts: [{ name: "http", port: 80 }],
      }, { requestId: context.requestId(change) });
      await transport.requestJson("POST", `${groupUrl}/addInstances`, {
        params: { requestId: scopedRequestId(context.requestId(change), 1) },
        jsonBody: { instances: [{ instance: `${base(spec)}/zones/${spec.zone}/instances/${spec.name}-backend` }] },
      });
      const membership = await transport.requestJson("POST", `${groupUrl}/listInstances`, {
        params: { maxResults: 2 },
        jsonBody: { instanceState: "ALL" },
      });
      const members = membership.payload.items;
      if (
        !Array.isArray(members) || members.length !== 1 ||
        typeof members[0] !== "object" || members[0] === null ||
        typeof (members[0] as Record<string, unknown>).instance !== "string" ||
        !String((members[0] as Record<string, unknown>).instance).endsWith(
          `/projects/${spec.project_id}/zones/${spec.zone}/instances/${spec.name}-backend`,
        )
      ) {
        throw new ProviderExecutionError("instance-group-membership-reconciliation-failed");
      }
      return true;
    }

    case "compute:health_check":
      await post(
        regional(spec, "healthChecks"),
        {
          checkIntervalSec: 10,
          healthyThreshold: 2,
          name: change.resource_name,
          ...(spec.backend_kind === "internal_https_lb"
            ? { httpHealthCheck: { portSpecification: "USE_SERVING_PORT", requestPath: "/" } }
            : { sslHealthCheck: { port: 443 } }),
          timeoutSec: 5,
          type: spec.backend_kind === "internal_https_lb" ? "HTTP" : "SSL",
          unhealthyThreshold: 3,
        },
        { requestId: context.requestId(change) },
      );
      return true;

    case "compute:instance_group_manager": {
      await post(
        regional(spec, "instanceGroupManagers"),
        {
          baseInstanceName: `${spec.name}-offload`,
          distributionPolicy: {
            targetShape: "EVEN",
            zones: [{ zone: `zones/${spec.zone}` }, { zone: `zones/${spec.secondary_zone}` }],
          },
          name: change.resource_name,
          namedPorts: [{ name: "https", port: 443 }],
          targetSize: spec.offload_min_replicas,
          updatePolicy: {
            // Never drop below the baseline while replacing instances.
            maxSurge: { fixed: 2 },
            maxUnavailable: { fixed: 0 },
            minimalAction: "REPLACE",
            type: "PROACTIVE",
          },
          versions: [
            {
              instanceTemplate:
                `${base(spec)}/global/instanceTemplates/${spec.name}-offload-template`,
              name: "primary",
            },
          ],
        },
        { requestId: context.requestId(change) },
      );
      await waitForStableGroup(transport, spec);
      await assertProductionManagedInstanceBootDisks(
        transport,
        spec,
        context.sourceImageBinding,
      );
      return true;
    }

    case "compute:autoscaler":
      await post(
        regional(spec, "autoscalers"),
        {
          autoscalingPolicy: {
            coolDownPeriodSec: 90,
            cpuUtilization: { utilizationTarget: spec.offload_cpu_target },
            maxNumReplicas: spec.offload_max_replicas,
            minNumReplicas: spec.offload_min_replicas,
            mode: "ON",
          },
          name: change.resource_name,
          target: `${regional(spec, "instanceGroupManagers")}/${spec.name}-offload-mig`,
        },
        { requestId: context.requestId(change) },
      );
      return true;

    case "compute:backend_service":
      await post(
        regional(spec, "backendServices"),
        {
          backends: [
            {
              group: spec.backend_kind === "internal_https_lb"
                ? `${COMPUTE_RESOURCE}/projects/${spec.project_id}/zones/${spec.zone}/instanceGroups/${spec.name}-backend-ig`
                : `${COMPUTE_RESOURCE}/projects/${spec.project_id}/regions/${spec.region}/instanceGroups/${spec.name}-offload-mig`,
              ...(spec.backend_kind === "internal_https_lb" ? { balancingMode: "UTILIZATION" } : {}),
            },
          ],
          healthChecks: [`${regional(spec, "healthChecks")}/${spec.name}-${spec.backend_kind === "internal_https_lb" ? "ilb" : "offload"}-hc`],
          loadBalancingScheme: spec.backend_kind === "internal_https_lb" ? "INTERNAL_MANAGED" : "INTERNAL",
          name: change.resource_name,
          protocol: spec.backend_kind === "internal_https_lb" ? "HTTP" : "TCP",
          ...(spec.backend_kind === "internal_https_lb" ? { portName: "http" } : {}),
          timeoutSec: 10,
        },
        { requestId: context.requestId(change) },
      );
      return true;

    case "compute:forwarding_rule": {
      const addressResponse = await transport.requestJson(
        "GET",
        `${regional(spec, "addresses")}/${spec.name}-offload-ip`,
      );
      const address = addressResponse.payload.address;
      if (typeof address !== "string") {
        throw new ProviderExecutionError("reserved-address-missing");
      }
      await post(
        regional(spec, "forwardingRules"),
        {
          IPAddress: address,
          IPProtocol: "TCP",
          // Secure Gateway connects from Google's own range, which is not in
          // this region. Without Global Access the rule refuses that traffic --
          // the failure the Path B gate exists to catch, here by construction.
          allowGlobalAccess: true,
          ...(spec.backend_kind === "internal_https_lb"
            ? {
              target: `${regional(spec, "targetHttpsProxies")}/${spec.name}-ilb-proxy`,
              networkTier: "PREMIUM",
            }
            : {
              backendService:
                `${regional(spec, "backendServices")}/${spec.name}-offload-bs`,
            }),
          loadBalancingScheme:
            spec.backend_kind === "internal_https_lb" ? "INTERNAL_MANAGED" : "INTERNAL",
          name: change.resource_name,
          network: `${base(spec)}/global/networks/${networkName(spec)}`,
          ports: ["443"],
          subnetwork: `${regional(spec, "subnetworks")}/${subnetName(spec)}`,
        },
        { requestId: context.requestId(change) },
      );
      await waitForHealthyBackend(transport, spec);
      return true;
    }

    case "compute:offload_refresh": {
      if (spec.mode !== "production") return false;
      const managerUrl =
        `${regional(spec, "instanceGroupManagers")}/${spec.name}-offload-mig`;
      const requestId = context.requestId(change);
      const expected = {
        kind: "offload_refresh" as const,
        phase: "prepared" as const,
        // Reuse the durable refresh checkpoint schema. For production these
        // UUID fields bind the local claim to this approved step only. Compute
        // does not support requestId on applyUpdatesToInstances, so they must
        // never be sent as undocumented query parameters.
        instanceUrl: managerUrl,
        stopRequestId: requestId,
        startRequestId: requestId,
      };
      let checkpoint = expected as {
        kind: "offload_refresh";
        phase: "prepared" | "stop_sending" | "restart_rejected" | "applied";
        instanceUrl: string;
        stopRequestId: string;
        startRequestId: string;
      };
      if (context.beforeImage === undefined) {
        if (context.captureBefore === undefined) {
          throw new ProviderExecutionError("offload-refresh-checkpoint-unavailable");
        }
        await context.captureBefore(change, checkpoint);
      } else {
        const value = context.beforeImage;
        if (
          typeof value !== "object" || value === null || Array.isArray(value) ||
          (value as { kind?: unknown }).kind !== "offload_refresh"
        ) throw new ProviderExecutionError("offload-refresh-checkpoint-invalid");
        const candidate = value as typeof checkpoint;
        if (
          !["prepared", "stop_sending", "restart_rejected", "applied"].includes(
            candidate.phase,
          ) ||
          candidate.instanceUrl !== managerUrl ||
          candidate.stopRequestId !== requestId || candidate.startRequestId !== requestId
        ) throw new ProviderExecutionError("offload-refresh-checkpoint-invalid");
        checkpoint = structuredClone(candidate);
      }
      const advance = async (phase: typeof checkpoint.phase): Promise<void> => {
        checkpoint = { ...checkpoint, phase };
        await context.captureBefore?.(change, checkpoint);
      };
      if (checkpoint.phase === "applied") {
        await ensureProductionOffloadRefreshHealthy(
          transport,
          spec,
          checkpoint,
          context.sourceImageBinding,
        );
        return true;
      }
      if (checkpoint.phase === "stop_sending") {
        // There is no provider idempotency token or immutable observation that
        // can distinguish an accepted restart from the old healthy state.
        // Replaying here could restart the whole group twice.
        throw new ProviderExecutionError("offload-refresh-restart-outcome-ambiguous");
      }
      if (
        checkpoint.phase === "prepared" || checkpoint.phase === "restart_rejected"
      ) await advance("stop_sending");
      try {
        await transport.requestJson("POST", `${managerUrl}/applyUpdatesToInstances`, {
          jsonBody: {
            allInstances: true,
            minimalAction: "RESTART",
            mostDisruptiveAllowedAction: "RESTART",
          },
        });
      } catch (error) {
        if (isDefiniteMutationRejection(error)) {
          // A received provider rejection proves that the restart was not
          // accepted, so a future explicit retry is safe. If persisting this
          // checkpoint is interrupted, stop_sending remains fail-closed.
          await advance("restart_rejected");
        }
        // A transport/response-loss failure leaves stop_sending durable. A
        // healthy/stable MIG may be the old state and is not commit evidence.
        throw error;
      }
      await advance("applied");
      await ensureProductionOffloadRefreshHealthy(
        transport,
        spec,
        checkpoint,
        context.sourceImageBinding,
      );
      return true;
    }

    case "compute:ssl_certificate": {
      const material = await ilbTlsMaterial(context, spec);
      await post(regional(spec, "sslCertificates"), {
        name: change.resource_name,
        description: `${MANAGED_BY}; configuration ${configurationHash(spec)}`,
        certificate: material.certificate,
        privateKey: material.privateKey,
      }, { requestId: context.requestId(change) });
      return true;
    }

    case "compute:url_map":
      await post(regional(spec, "urlMaps"), {
        name: change.resource_name,
        defaultService: `${regional(spec, "backendServices")}/${spec.name}-ilb-bs`,
      }, { requestId: context.requestId(change) });
      return true;

    case "compute:target_https_proxy":
      await post(regional(spec, "targetHttpsProxies"), {
        name: change.resource_name,
        urlMap: `${regional(spec, "urlMaps")}/${spec.name}-ilb-map`,
        sslCertificates: [`${regional(spec, "sslCertificates")}/${spec.name}-ilb-cert`],
      }, { requestId: context.requestId(change) });
      return true;

    default:
      return false;
  }
}

export async function ensureProductionOffloadRefreshHealthy(
  transport: Transport,
  spec: DeploymentSpec,
  checkpoint: unknown,
  sourceImageBinding?: SourceImageBinding | null,
): Promise<void> {
  const managerUrl = `${regional(spec, "instanceGroupManagers")}/${spec.name}-offload-mig`;
  if (
    typeof checkpoint !== "object" || checkpoint === null || Array.isArray(checkpoint) ||
    (checkpoint as { kind?: unknown }).kind !== "offload_refresh" ||
    (checkpoint as { instanceUrl?: unknown }).instanceUrl !== managerUrl
  ) throw new ProviderExecutionError("offload-refresh-checkpoint-invalid");
  const phase = (checkpoint as { phase?: unknown }).phase;
  if (phase === "prepared") return;
  if (phase === "stop_sending") {
    throw new ProviderExecutionError("offload-refresh-restart-outcome-ambiguous");
  }
  if (phase !== "restart_rejected" && phase !== "applied") {
    throw new ProviderExecutionError("offload-refresh-checkpoint-invalid");
  }
  await waitForStableGroup(transport, spec);
  await assertProductionManagedInstanceBootDisks(
    transport,
    spec,
    sourceImageBinding,
  );
  await waitForHealthyBackend(transport, spec);
}

function exactComputeResource(value: unknown, expectedPath: string): boolean {
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
}

async function assertProductionManagedInstanceBootDisks(
  transport: Transport,
  spec: DeploymentSpec,
  binding: SourceImageBinding | null | undefined,
): Promise<void> {
  if (
    spec.source_image === null || binding === null || binding === undefined ||
    binding.name !== spec.source_image || !/^[1-9][0-9]*$/.test(binding.id) ||
    binding.self_link !== `https://www.googleapis.com/compute/v1/${spec.source_image}`
  ) {
    throw new ProviderExecutionError("source-image-binding-invalid");
  }
  const managerUrl = `${regional(spec, "instanceGroupManagers")}/${spec.name}-offload-mig`;
  const instances: Array<{ zone: string; name: string }> = [];
  const seenTokens = new Set<string>();
  let pageToken: string | undefined;
  for (let page = 0; page < 100; page += 1) {
    const response = await transport.requestJson(
      "POST",
      `${managerUrl}/listManagedInstances`,
      { params: { maxResults: 500, ...(pageToken === undefined ? {} : { pageToken }) } },
    );
    const items = response.payload.managedInstances;
    if (items !== undefined && !Array.isArray(items)) {
      throw new ProviderExecutionError("managed-instance-list-invalid");
    }
    for (const item of items ?? []) {
      if (
        typeof item !== "object" || item === null || Array.isArray(item) ||
        (item as Record<string, unknown>).instanceStatus !== "RUNNING"
      ) {
        throw new ProviderExecutionError("managed-instance-list-invalid");
      }
      const instance = (item as Record<string, unknown>).instance;
      if (typeof instance !== "string") {
        throw new ProviderExecutionError("managed-instance-list-invalid");
      }
      let parsed: URL;
      try {
        parsed = new URL(instance);
      } catch {
        throw new ProviderExecutionError("managed-instance-list-invalid");
      }
      const match = new RegExp(
        `^/compute/v1/projects/${spec.project_id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}` +
          `/zones/(${spec.region.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-[a-z])` +
          `/instances/(${spec.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}` +
          `-offload-[a-z0-9-]+)$`,
      ).exec(parsed.pathname);
      if (
        (parsed.origin !== "https://compute.googleapis.com" &&
          parsed.origin !== "https://www.googleapis.com") ||
        parsed.username !== "" || parsed.password !== "" || parsed.port !== "" ||
        parsed.search !== "" || parsed.hash !== "" || match === null
      ) {
        throw new ProviderExecutionError("managed-instance-list-invalid");
      }
      const [, zone, name] = match;
      if (
        (zone !== spec.zone && zone !== spec.secondary_zone) ||
        instances.some((value) => value.zone === zone && value.name === name)
      ) {
        throw new ProviderExecutionError("managed-instance-list-invalid");
      }
      instances.push({ zone, name });
      if (instances.length > spec.offload_max_replicas) {
        throw new ProviderExecutionError("managed-instance-list-invalid");
      }
    }
    if (!("nextPageToken" in response.payload) || response.payload.nextPageToken === "") {
      pageToken = undefined;
      break;
    }
    const token = response.payload.nextPageToken;
    if (typeof token !== "string" || token === "" || seenTokens.has(token)) {
      throw new ProviderExecutionError("managed-instance-list-invalid");
    }
    seenTokens.add(token);
    pageToken = token;
    if (page === 99) {
      throw new ProviderExecutionError("managed-instance-list-pagination-limit-exceeded");
    }
  }
  if (pageToken !== undefined || instances.length < spec.offload_min_replicas) {
    throw new ProviderExecutionError("managed-instance-count-invalid");
  }
  for (const { zone, name } of instances) {
    const instancePath =
      `/compute/v1/projects/${spec.project_id}/zones/${zone}/instances/${name}`;
    const instance = (await transport.requestJson(
      "GET",
      `https://compute.googleapis.com${instancePath}`,
    )).payload;
    const disks = instance.disks;
    if (
      !Array.isArray(disks) || disks.length !== 1 ||
      typeof disks[0] !== "object" || disks[0] === null || Array.isArray(disks[0])
    ) {
      throw new ProviderExecutionError("instance-boot-disk-identity-invalid");
    }
    const diskPath =
      `/compute/v1/projects/${spec.project_id}/zones/${zone}/disks/${name}`;
    const attached = disks[0] as Record<string, unknown>;
    if (attached.boot !== true || !exactComputeResource(attached.source, diskPath)) {
      throw new ProviderExecutionError("instance-boot-disk-identity-invalid");
    }
    const disk = (await transport.requestJson(
      "GET",
      `https://compute.googleapis.com${diskPath}`,
    )).payload;
    if (
      disk.name !== name || disk.status !== "READY" ||
      !exactComputeResource(disk.selfLink, diskPath) ||
      !exactComputeResource(
        disk.zone,
        `/compute/v1/projects/${spec.project_id}/zones/${zone}`,
      ) ||
      String(disk.sizeGb) !== "20" ||
      !exactComputeResource(
        disk.type,
        `/compute/v1/projects/${spec.project_id}/zones/${zone}/diskTypes/pd-balanced`,
      ) ||
      !exactComputeResource(disk.sourceImage, `/compute/v1/${spec.source_image}`) ||
      String(disk.sourceImageId) !== binding.id
    ) {
      throw new ProviderExecutionError("instance-boot-disk-identity-invalid");
    }
  }
}

/** The sample backend's reserved address, when the deployment creates one. */
async function sampleBackendAddress(
  transport: Transport,
  spec: DeploymentSpec,
): Promise<string | undefined> {
  if (spec.backend_kind !== "managed_sample") return undefined;
  const response = await transport.requestJson(
    "GET",
    `${regional(spec, "addresses")}/${spec.name}-backend-ip`,
  );
  const address = response.payload.address;
  return typeof address === "string" ? address : undefined;
}

/**
 * Wait until the group is stable with the baseline running.
 *
 * Pointing the load balancer at a group that has not finished creating
 * instances produces a deployment that looks applied and serves nothing.
 */
async function waitForStableGroup(transport: Transport, spec: DeploymentSpec): Promise<void> {
  const response = await transport.requestJson(
    "GET",
    `${regional(spec, "instanceGroupManagers")}/${spec.name}-offload-mig`,
  );
  const status = response.payload.status as
    | { isStable?: unknown; currentInstanceStatuses?: { running?: unknown } }
    | undefined;
  const running = Number(status?.currentInstanceStatuses?.running ?? 0);
  if (status?.isStable !== true || running < spec.offload_min_replicas) {
    // The caller reschedules; under Manifest V3 waiting is an alarm, not a loop.
    throw new ProviderExecutionError("managed-instance-group-not-stable");
  }
}

async function waitForHealthyBackend(
  transport: Transport,
  spec: DeploymentSpec,
): Promise<void> {
  const response = await transport.requestJson(
    "POST",
    `${regional(spec, "backendServices")}/${spec.name}-${spec.backend_kind === "internal_https_lb" ? "ilb" : "offload"}-bs/getHealth`,
    {
      jsonBody: {
        group: spec.backend_kind === "internal_https_lb"
          ? `${COMPUTE_RESOURCE}/projects/${spec.project_id}/zones/${spec.zone}/instanceGroups/${spec.name}-backend-ig`
          : `${COMPUTE_RESOURCE}/projects/${spec.project_id}/regions/${spec.region}/instanceGroups/${spec.name}-offload-mig`,
      },
    },
  );
  const states = response.payload.healthStatus;
  const healthy = Array.isArray(states)
    ? states.filter((entry) => (entry as { healthState?: unknown }).healthState === "HEALTHY")
        .length
    : 0;
  const required = spec.backend_kind === "internal_https_lb" ? 1 : spec.offload_min_replicas;
  if (healthy < required) {
    throw new ProviderExecutionError("offload-backend-not-healthy");
  }
}

/** UTF-8 aware base64, since btoa alone mangles non-ASCII. */
function base64Utf8(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
