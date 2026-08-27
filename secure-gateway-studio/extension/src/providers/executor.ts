/**
 * Resource executor. Port of `providers/google_executor.py`, Path B range.
 *
 * What this module produces is a sequence of HTTP requests, so that is what the
 * golden set pins: for a given change and specification, the same requests, in
 * the same order, with the same bodies. Comparing plans alone would not catch a
 * reordered IAM read/write, a missing egress policy, or the wrong project in an
 * upstream network path -- each of which is a materially different deployment.
 *
 * Two behaviours are load-bearing and easy to lose in a port:
 *
 *   - **IAM is read-modify-write with the returned etag.** Dropping the etag
 *     turns a concurrent policy edit into a silent overwrite of someone else's
 *     binding. The before-image is retained for rollback.
 *   - **Chrome Policy schemas are discovered, not assumed.** The Python
 *     implementation fetches the schema and asserts the field exists before
 *     writing. A schema change then surfaces as a refusal rather than a policy
 *     written into the wrong field.
 *
 * Path A resource types are not handled; they land in Phase 4 and reaching one
 * throws rather than silently doing nothing.
 */

import { canonicalDigestSync, canonicalJson } from "../domain/canonical.ts";
import { compensationCapability } from "../domain/compensation.ts";
import {
  applyPathA,
  ensureOffloadRefreshRunning,
  isCompatibleCloudNat,
  networkName,
  type CloudNatConfig,
  type NamedResourceOwnershipCheckpoint,
  type OffloadRefreshCheckpoint,
} from "./executor-path-a.ts";
import { ensureProductionOffloadRefreshHealthy } from "./executor-production.ts";
import {
  enterpriseCertificateId,
  type CertificateBundle,
} from "./certificates.ts";
import { DIRECT_HTTPS_APIS, REQUIRED_APIS } from "../domain/constants.generated.ts";
import {
  configurationHash,
  type PublicCertificateBinding,
  type ResourceChange,
  type SourceImageBinding,
} from "../domain/planner.ts";
import {
  applicationHostname,
  applicationPort,
  iamMember,
  upstreamProjectId,
  type DeploymentSpec,
} from "../domain/spec.ts";
import { ensureManagedChromeAccessLevel } from "./catalog.ts";
import type { StepApplyResult, StepExecutionContext } from "../runtime/run-engine.ts";
import { serviceAccountEmail } from "../domain/naming.ts";
import {
  revertIamPolicyDelta,
  validatedIamPolicy,
} from "../domain/iam-policy.ts";

const SECURE_ENTERPRISE_BROWSER = "ekajlcmdfcigmdbphhifahdfjbkciflj";
const SECRET_MANAGER_API = "https://secretmanager.googleapis.com/v1";

export class ProviderExecutionError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "ProviderExecutionError";
    this.code = code;
  }
}

/**
 * Convert Secret Manager's resource-name response into the absolute URL our
 * transport requires. SecretVersion.name is documented as a relative resource
 * name; accepting an arbitrary URL here would let a malformed response redirect
 * a later access/disable/destroy request away from the intended secret.
 */
export function canonicalSecretVersionUrl(
  value: string,
  expectedProjectId: string,
  expectedSecretName: string,
): string {
  if (
    expectedProjectId === "" || expectedSecretName === "" ||
    /[/?#]/.test(expectedProjectId) || /[/?#]/.test(expectedSecretName)
  ) {
    throw new ProviderExecutionError("secret-version-expected-resource-invalid");
  }
  const relative = value.startsWith(`${SECRET_MANAGER_API}/`)
    ? value.slice(SECRET_MANAGER_API.length + 1)
    : value;
  const match = relative.match(/^projects\/([^/]+)\/secrets\/([^/]+)\/versions\/([1-9][0-9]*)$/);
  if (!match) {
    throw new ProviderExecutionError("secret-version-name-invalid");
  }
  const project = match[1]!;
  const secret = match[2]!;
  if (secret !== expectedSecretName) {
    throw new ProviderExecutionError("secret-version-name-invalid");
  }
  if (project !== expectedProjectId && !/^[0-9]+$/.test(project)) {
    throw new ProviderExecutionError("secret-version-name-invalid");
  }
  return `${SECRET_MANAGER_API}/${relative}`;
}

/** Digest used to match an addVersion response-loss candidate without keeping plaintext. */
export function secretPayloadDigest(encoded: string): string {
  try {
    const binary = atob(encoded);
    const hexadecimal = Array.from(
      binary,
      (character) => character.charCodeAt(0).toString(16).padStart(2, "0"),
    ).join("");
    return canonicalDigestSync(hexadecimal);
  } catch {
    throw new ProviderExecutionError("secret-version-payload-invalid");
  }
}

/** Exact unguessable marker embedded in a run-owned SecretVersion payload. */
export function secretPayloadOwnershipToken(encoded: string): string | null {
  try {
    const binary = atob(encoded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    const decoded: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) return null;
    const token = (decoded as Record<string, unknown>).sgs_ownership_token;
    return typeof token === "string" &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
          .test(token)
      ? token
      : null;
  } catch {
    return null;
  }
}

/** A non-success response returned by a Google REST endpoint. */
export class GoogleApiError extends Error {
  readonly status: number;
  readonly method: string;
  readonly url: string;
  readonly payload: Record<string, unknown>;

  constructor(options: {
    status: number;
    method: string;
    url: string;
    payload: Record<string, unknown>;
  }) {
    const detail = googleErrorDetail(options.payload) ?? `HTTP ${options.status}`;
    super(`${options.method} ${options.url}: ${detail}`);
    this.name = "GoogleApiError";
    this.status = options.status;
    this.method = options.method;
    this.url = options.url;
    this.payload = options.payload;
  }
}

export interface TransportResponse {
  status: number;
  payload: Record<string, unknown>;
}

export interface Transport {
  requestJson(
    method: string,
    url: string,
    options?: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
      /** Non-2xx statuses the individual call deliberately reconciles. */
      acceptedStatuses?: readonly number[];
    },
  ): Promise<TransportResponse>;
}

/**
 * Validate a Google response at the provider boundary.
 *
 * Callers must opt into every expected non-2xx status. This keeps 404/409
 * reconciliation paths visible instead of allowing an arbitrary API failure
 * to look like a successful mutation.
 */
export async function requestJsonChecked(
  transport: Transport,
  method: string,
  url: string,
  options: {
    params?: Record<string, string | number>;
    jsonBody?: Record<string, unknown>;
    acceptedStatuses?: readonly number[];
  } = {},
): Promise<TransportResponse> {
  const response = await transport.requestJson(method, url, {
    params: options.params,
    jsonBody: options.jsonBody,
    acceptedStatuses: options.acceptedStatuses,
  });
  const accepted = options.acceptedStatuses ?? [];
  if ((response.status < 200 || response.status >= 300) && !accepted.includes(response.status)) {
    throw new GoogleApiError({ status: response.status, method, url, payload: response.payload });
  }
  return response;
}

/**
 * Restore an IAM before-image with a fresh concurrency token.
 *
 * A persisted etag describes the policy before Apply and is necessarily stale
 * after Apply's own SET. Each compensation attempt therefore reads policy v3,
 * reverses only this run's persisted before/after delta against that fresh
 * policy, and retries a bounded number of ABORTED/409 races.
 */
export async function restoreIamPolicyWithFreshEtag(
  transport: Transport,
  options: {
    getUrl: string;
    setUrl: string;
    getMethod?: "GET" | "POST";
    beforePolicy: Record<string, unknown>;
    afterPolicy: Record<string, unknown>;
    maxAttempts?: number;
  },
): Promise<void> {
  const getMethod = options.getMethod ?? "GET";
  const maxAttempts = options.maxAttempts ?? 3;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const current = await requestJsonChecked(transport, getMethod, options.getUrl, {
      params:
        getMethod === "GET"
          ? { "options.requestedPolicyVersion": 3 }
          : undefined,
      jsonBody:
        getMethod === "POST"
          ? { options: { requestedPolicyVersion: 3 } }
          : undefined,
    });
    const etag = current.payload.etag;
    if (typeof etag !== "string" || etag === "") {
      throw new ProviderExecutionError("iam-restore-etag-missing");
    }
    const reverted = revertIamPolicyDelta({
      beforePolicy: options.beforePolicy,
      afterPolicy: options.afterPolicy,
      currentPolicy: current.payload,
    });
    const restored = await requestJsonChecked(transport, "POST", options.setUrl, {
      jsonBody: {
        policy: {
          ...reverted,
          etag,
          version: 3,
        },
      },
      acceptedStatuses: [409],
    });
    if (restored.status !== 409) return;
    if (!isConfirmedIamEtagConflictResponse(restored)) {
      throw new GoogleApiError({
        status: restored.status,
        method: "POST",
        url: options.setUrl,
        payload: restored.payload,
      });
    }
    // Every other read-modify-write race in this file backs off before
    // re-reading. Without it three attempts are spent in milliseconds and a
    // rollback that only needed a moment reports as unrecoverable.
    if (attempt < maxAttempts - 1) {
      await new Promise((resolve) => setTimeout(resolve, 25 * (2 ** attempt)));
    }
  }
  throw new ProviderExecutionError("iam-restore-conflict");
}

function googleErrorDetail(payload: Record<string, unknown>): string | null {
  const error = payload.error;
  if (typeof error === "string") return error;
  if (typeof error !== "object" || error === null) return null;
  const message = (error as { message?: unknown }).message;
  return typeof message === "string" && message !== "" ? message : null;
}

function googleStatusCode(payload: Record<string, unknown>): string | null {
  const error = payload.error;
  if (typeof error !== "object" || error === null) return null;
  const status = (error as { status?: unknown }).status;
  return typeof status === "string" && /^[A-Z][A-Z0-9_]+$/.test(status)
    ? status.toLowerCase().replaceAll("_", "-")
    : null;
}

function validatedChromePolicySourceResource(value: unknown): string | null {
  if (value === undefined) return null;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
  }
  const key = value as Record<string, unknown>;
  // Google protobuf JSON may encode an unset output-only message as `{}`.
  // Treat that exact empty shape as no reported source while rejecting every
  // non-empty malformed source key below.
  if (Object.keys(key).length === 0) return null;
  if (!Object.keys(key).every((name) => name === "targetResource" || name === "additionalTargetKeys")) {
    throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
  }
  const targetResource = key.targetResource;
  if (
    typeof targetResource !== "string" ||
    !/^(?:orgunits|groups)\/[A-Za-z0-9_-]+$/.test(targetResource)
  ) {
    throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
  }
  if ("additionalTargetKeys" in key) {
    const additional = key.additionalTargetKeys;
    if (
      typeof additional !== "object" || additional === null || Array.isArray(additional) ||
      Object.keys(additional as Record<string, unknown>).length !== 0
    ) {
      throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
    }
  }
  return targetResource;
}

function operationDone(payload: Record<string, unknown>): boolean {
  return payload.done === true ||
    (typeof payload.status === "string" && payload.status.toUpperCase() === "DONE");
}

function isGoogleOperation(payload: Record<string, unknown>): boolean {
  if ("done" in payload) {
    if (typeof payload.done !== "boolean") {
      throw new ProviderExecutionError("provider-operation-done-invalid");
    }
    return true;
  }
  if ("status" in payload) {
    if (
      typeof payload.status !== "string" ||
      !["PENDING", "RUNNING", "DONE"].includes(payload.status.toUpperCase())
    ) {
      throw new ProviderExecutionError("provider-operation-status-invalid");
    }
    return true;
  }
  const name = payload.name;
  const selfLink = payload.selfLink;
  return (
    (typeof name === "string" &&
      (name.startsWith("operations/") || name.includes("/operations/"))) ||
    (typeof selfLink === "string" && selfLink.includes("/operations/"))
  );
}

function ensureOperationSucceeded(payload: Record<string, unknown>): void {
  if (payload.error !== undefined && payload.error !== null) {
    throw new ProviderExecutionError("provider-operation-failed");
  }
}

function googleOperationUrl(
  payload: Record<string, unknown>,
  requestUrl: string,
): string | null {
  const request = new URL(requestUrl);
  const validate = (candidateValue: string): string => {
    const legacyCompute = "https://www.googleapis.com/compute/";
    const normalized = candidateValue.startsWith(legacyCompute)
      ? `https://compute.googleapis.com/compute/${candidateValue.slice(legacyCompute.length)}`
      : candidateValue;
    if (/(?:^|\/)(?:\.{1,2}|%2e(?:%2e)?)(?:\/|$)/i.test(candidateValue)) {
      throw new ProviderExecutionError("provider-operation-poll-url-invalid");
    }
    let candidate: URL;
    try {
      candidate = new URL(normalized);
    } catch {
      throw new ProviderExecutionError("provider-operation-poll-url-invalid");
    }
    const computeRequest = request.pathname.match(
      /^\/compute\/v1\/projects\/([^/]+)\/(global|regions\/[^/]+|zones\/[^/]+)(?:\/|$)/,
    );
    const computePrefix = computeRequest === null
      ? null
      : `/compute/v1/projects/${computeRequest[1]}/${computeRequest[2]}/operations/`;
    const locationRequest = request.pathname.match(
      /^\/v1\/(projects\/[^/]+\/locations\/[^/]+)(?:\/|$)/,
    );
    const locationPrefix = locationRequest === null
      ? null
      : `/v1/${locationRequest[1]}/operations/`;
    if (
      candidate.protocol !== "https:" || candidate.username !== "" ||
      candidate.password !== "" || candidate.port !== "" ||
      candidate.origin !== request.origin || candidate.search !== "" ||
      candidate.hash !== "" ||
      !/(?:^|\/)operations\/[A-Za-z0-9._~%-]+$/.test(candidate.pathname) ||
      (computePrefix !== null && !candidate.pathname.startsWith(computePrefix)) ||
      (locationPrefix !== null && !candidate.pathname.startsWith(locationPrefix))
    ) {
      // Polling uses the same bearer token as the mutation. Never follow an
      // operation selfLink to a different origin or an arbitrary API path.
      throw new ProviderExecutionError("provider-operation-poll-url-invalid");
    }
    return candidate.toString();
  };
  const selfLink = payload.selfLink;
  if (typeof selfLink === "string" && selfLink !== "") {
    return validate(selfLink);
  }
  const name = payload.name;
  if (typeof name !== "string" || name === "") return null;
  if (name.startsWith("https://")) return validate(name);
  if (/[?#]/.test(name) || name.split("/").some((part) => part === "..")) {
    throw new ProviderExecutionError("provider-operation-poll-url-invalid");
  }
  return validate(`${request.origin}/v1/${name.replace(/^\/+/, "")}`);
}

export function resourceUrlForChange(
  change: Pick<ResourceChange, "provider" | "resource_type" | "resource_name">,
  spec: DeploymentSpec,
): string | null {
  const compute = `https://compute.googleapis.com/compute/v1/projects/${spec.project_id}`;
  const regional = `${compute}/regions/${spec.region}`;
  const key = `${change.provider}:${change.resource_type}`;
  const urls: Record<string, string> = {
    "compute:network": `${compute}/global/networks/${change.resource_name}`,
    "compute:subnetwork": `${regional}/subnetworks/${change.resource_name}`,
    "compute:router": `${regional}/routers/${change.resource_name}`,
    "compute:internal_address": `${regional}/addresses/${change.resource_name}`,
    "compute:instance": `${compute}/zones/${spec.zone}/instances/${change.resource_name}`,
    "compute:instance_group": spec.backend_kind === "internal_https_lb"
      ? `${compute}/zones/${spec.zone}/instanceGroups/${change.resource_name}`
      : `${regional}/instanceGroups/${change.resource_name}`,
    "compute:instance_template": `${compute}/global/instanceTemplates/${change.resource_name}`,
    "compute:health_check": `${regional}/healthChecks/${change.resource_name}`,
    "compute:instance_group_manager": `${regional}/instanceGroupManagers/${change.resource_name}`,
    "compute:autoscaler": `${regional}/autoscalers/${change.resource_name}`,
    "compute:backend_service": `${regional}/backendServices/${change.resource_name}`,
    "compute:forwarding_rule": `${regional}/forwardingRules/${change.resource_name}`,
    "compute:ssl_certificate": `${regional}/sslCertificates/${change.resource_name}`,
    "compute:url_map": `${regional}/urlMaps/${change.resource_name}`,
    "compute:target_https_proxy": `${regional}/targetHttpsProxies/${change.resource_name}`,
    "compute:firewall_rule": `${compute}/global/firewalls/${change.resource_name}`,
    "dns:private_zone":
      `https://dns.googleapis.com/dns/v1/projects/${spec.project_id}` +
      `/managedZones/${change.resource_name}`,
    "iam:service_account":
      `https://iam.googleapis.com/v1/projects/${spec.project_id}/serviceAccounts/` +
      encodeURIComponent(
        `${change.resource_name}@${spec.project_id}.iam.gserviceaccount.com`,
      ),
    "secretmanager:secret":
      `https://secretmanager.googleapis.com/v1/projects/${spec.project_id}` +
      `/secrets/${change.resource_name}`,
    "beyondcorp:application":
      `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
      `/locations/global/securityGateways/${spec.gateway_id}` +
      `/applications/${change.resource_name}`,
  };
  return urls[key] ?? null;
}

function expectedSecretLabels(spec: DeploymentSpec): Record<string, string> {
  return {
    "certificate-spec-hash": canonicalDigestSync({
      ca_name: spec.ca_name ?? null,
      ca_pool: spec.ca_pool ?? null,
      certificate_lifetime_days: spec.certificate_lifetime_days,
      certificate_strategy: spec.certificate_strategy,
      private_hostname: spec.private_hostname,
      public_certificate_secret: spec.public_certificate_secret ?? null,
    }).slice(0, 32),
    "configuration-hash": configurationHash(spec).slice(0, 32),
    "managed-by": "secure-gateway-studio",
  };
}

interface IamPolicy {
  version?: number;
  etag?: string;
  bindings?: IamBinding[];
  [key: string]: unknown;
}

interface IamBinding {
  role: string;
  members: string[];
  condition?: { title: string; description: string; expression: string };
}

function sameIamCondition(
  left: IamBinding["condition"] | undefined,
  right: IamBinding["condition"] | undefined,
): boolean {
  return canonicalJson(left ?? null) === canonicalJson(right ?? null);
}

type PersistedBeforeImage =
  | {
      kind: "iam";
      /** Missing means a legacy checkpoint whose send outcome is ambiguous. */
      phase?: SharedMutationPhase;
      /** Present only when Google definitively rejected the SET. */
      rejectionStatus?: number;
      /** Required proof that a 409 was IAM's concurrency rejection. */
      rejectionReason?: "ABORTED";
      getUrl?: string;
      getMethod?: "GET" | "POST";
      setUrl: string;
      policy: Record<string, unknown>;
      afterPolicy: Record<string, unknown>;
    }
  | {
      kind: "chrome_policy";
      /** Missing means a legacy checkpoint whose send outcome is ambiguous. */
      phase?: SharedMutationPhase;
      schemaName: string;
      appId: string | null;
      previous: Record<string, unknown>;
      /** Exact direct policy value written by this run. */
      managedAfter?: Record<string, unknown>;
    }
  | {
      kind: "router_nats";
      routerUrl: string;
      nats: unknown[];
      managedNat: CloudNatConfig;
    }
  | GenericCreatedResourceCheckpoint
  | NamedResourceOwnershipCheckpoint
  | OffloadRefreshCheckpoint
  | {
      kind: "secret_iam";
      /** Missing means a legacy requestId-less SET with ambiguous outcome. */
      phase?: SharedMutationPhase;
      /** Present only when Google definitively rejected the SET. */
      rejectionStatus?: number;
      /** Required proof that a 409 was IAM's concurrency rejection. */
      rejectionReason?: "ABORTED";
      getUrl?: string;
      getMethod?: "GET" | "POST";
      setUrl: string;
      policy: Record<string, unknown>;
      afterPolicy: Record<string, unknown>;
    }
  | {
      kind: "privateca_certificate";
      /** Versioned send protocol; missing legacy records are ambiguous. */
      protocolVersion?: 1;
      phase?: PrivateCaMutationPhase;
      certificateName: string;
      authorityName: string;
      /** Digest of the exact CSR checkpointed before the create POST. */
      csrDigest: string;
      /** CSR material is public and is retained for exact crash reconciliation. */
      csrPem?: string;
    }
  | {
      kind: "secret_version";
      phase?: SecretVersionPhase;
      secretUrl: string;
      versionName: string | null;
      previousAliases: Record<string, string>;
      previousLabels: Record<string, string>;
      /** Run-owned map state; absent on unsafe legacy checkpoints. */
      managedAfterAliases?: Record<string, string>;
      managedAfterLabels?: Record<string, string>;
      payloadDigest?: string;
      existingVersionNames?: string[];
      /** Run/step token embedded before addVersion for ownership recovery. */
      ownershipToken?: string;
    };

interface GenericCreatedResourceCheckpoint {
  kind: "generic_created_resource";
  protocolVersion: 2;
  phase: SharedMutationPhase;
  resourceKey: string;
  createUrl: string;
  resourceUrl: string;
  createRequestId: string;
  expectedParamsDigest: string;
  expectedPayloadDigest: string;
  ownershipMarker: string | null;
  providerIdentityField?: string;
  providerIdentity?: string;
}

type SecretVersionPhase =
  | "prepared"
  | "sending"
  | "rejected"
  | "version_added"
  | "alias_sending"
  | "applied";

type SharedMutationPhase = "prepared" | "sending" | "rejected" | "applied";
export type PrivateCaMutationPhase = "prepared" | "sending" | "rejected" | "applied";

const SHARED_MUTATION_TRANSITIONS: Record<
  SharedMutationPhase,
  readonly SharedMutationPhase[]
> = {
  prepared: ["prepared", "sending", "rejected"],
  sending: ["sending", "rejected", "applied"],
  rejected: ["rejected"],
  applied: ["applied"],
};

function sharedMutationPhase(value: { phase?: SharedMutationPhase }): SharedMutationPhase {
  if (
    value.phase !== "prepared" && value.phase !== "sending" &&
    value.phase !== "rejected" && value.phase !== "applied"
  ) {
    throw new ProviderExecutionError("shared-mutation-phase-missing-or-invalid");
  }
  return value.phase;
}

export function isDefiniteMutationRejection(error: unknown): error is GoogleApiError {
  return error instanceof GoogleApiError &&
    [400, 401, 403, 404, 409, 412].includes(error.status);
}

export function isConfirmedIamEtagConflict(error: unknown): error is GoogleApiError {
  return error instanceof GoogleApiError && error.status === 409 &&
    googleStatusCode(error.payload) === "aborted";
}

function isConfirmedIamEtagConflictResponse(response: TransportResponse): boolean {
  return response.status === 409 && googleStatusCode(response.payload) === "aborted";
}

function genericProviderIdentity(
  payload: Record<string, unknown>,
  provider: string,
  operationResponse = false,
): { field: string; value: string } | null {
  const fields: Array<{ source: string; canonical: string }> = provider === "compute"
    ? operationResponse
      ? [
        // Operation.id identifies the operation, never the created object.
        // If targetId is absent, keep the durable create ambiguous until the
        // exact resource GET becomes visible.
        { source: "targetId", canonical: "id" },
      ]
      : [
      // A Compute Operation has both id (the operation) and targetId (the
      // created resource). Normalize targetId to the resource's live `id` so
      // teardown can compare the same immutable identity after a transient
      // post-operation GET miss.
      { source: "targetId", canonical: "id" },
      { source: "id", canonical: "id" },
      { source: "selfLink", canonical: "selfLink" },
      { source: "creationTimestamp", canonical: "creationTimestamp" },
    ]
    : [
      { source: "createTime", canonical: "createTime" },
    ];
  for (const field of fields) {
    const value = payload[field.source];
    if (
      field.source === "createTime" &&
      (typeof value !== "string" ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value))
    ) continue;
    if (
      (typeof value === "string" && value !== "") ||
      (typeof value === "number" && Number.isSafeInteger(value) && value >= 0)
    ) {
      return { field: field.canonical, value: String(value) };
    }
  }
  return null;
}

const GOOGLE_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const DELEGATING_SERVICE_ACCOUNT_PATTERN =
  /^[a-z0-9][a-z0-9._-]*@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.iam\.gserviceaccount\.com$/i;

function emptyMessage(value: unknown): boolean {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    Object.keys(value as Record<string, unknown>).length === 0;
}

function canonicalIpAddress(value: unknown): string | null {
  if (typeof value !== "string" || value === "" || value.trim() !== value) return null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    const parts = value.split(".");
    if (parts.some((part) => Number(part) > 255 || String(Number(part)) !== part)) return null;
    return parts.join(".");
  }
  if (!value.includes(":")) return null;
  try {
    const hostname = new URL(`http://[${value}]/`).hostname;
    if (!hostname.startsWith("[") || !hostname.endsWith("]")) return null;
    return hostname.slice(1, -1).toLowerCase();
  } catch {
    return null;
  }
}

function validExternalIps(value: unknown): boolean {
  if (value === undefined) return true;
  if (!Array.isArray(value)) return false;
  const canonical = value.map(canonicalIpAddress);
  return canonical.every((item): item is string => item !== null) &&
    new Set(canonical).size === canonical.length;
}

function validBeyondCorpTimes(payload: Record<string, unknown>): boolean {
  return typeof payload.createTime === "string" &&
    GOOGLE_TIMESTAMP_PATTERN.test(payload.createTime) &&
    (payload.updateTime === undefined ||
      (typeof payload.updateTime === "string" &&
        GOOGLE_TIMESTAMP_PATTERN.test(payload.updateTime)));
}

/** Exact current SecurityGateway semantics used by discovery and crash recovery. */
export function isCompatibleSecurityGatewayPayload(
  payload: Record<string, unknown>,
  spec: DeploymentSpec,
): boolean {
  const hasCamel = payload.serviceDiscovery !== undefined;
  const hasSnake = payload.service_discovery !== undefined;
  if (hasCamel === hasSnake) return false;
  const serviceDiscovery = hasCamel ? payload.serviceDiscovery : payload.service_discovery;
  const allowed = new Set([
    "name",
    "displayName",
    hasCamel ? "serviceDiscovery" : "service_discovery",
    "logging",
    "createTime",
    "updateTime",
    "state",
    "delegatingServiceAccount",
    "externalIps",
  ]);
  return payload.name ===
      `projects/${spec.project_id}/locations/global/securityGateways/${spec.gateway_id}` &&
    payload.displayName === spec.gateway_id &&
    Object.keys(payload).every((field) => allowed.has(field)) &&
    emptyMessage(serviceDiscovery) && emptyMessage(payload.logging) &&
    validBeyondCorpTimes(payload) && payload.state === "RUNNING" &&
    typeof payload.delegatingServiceAccount === "string" &&
    payload.delegatingServiceAccount.trim() === payload.delegatingServiceAccount &&
    DELEGATING_SERVICE_ACCOUNT_PATTERN.test(payload.delegatingServiceAccount) &&
    validExternalIps(payload.externalIps);
}

/** Exact current Application semantics; gateway-only outputs are forbidden. */
export function isCompatibleBeyondCorpApplicationPayload(
  payload: Record<string, unknown>,
  spec: DeploymentSpec,
  resourceName: string,
): boolean {
  const hasCamelMatchers = payload.endpointMatchers !== undefined;
  const hasSnakeMatchers = payload.endpoint_matchers !== undefined;
  if (hasCamelMatchers === hasSnakeMatchers) return false;
  const matchers = hasCamelMatchers ? payload.endpointMatchers : payload.endpoint_matchers;
  const matcher = Array.isArray(matchers) && matchers.length === 1 &&
      typeof matchers[0] === "object" && matchers[0] !== null && !Array.isArray(matchers[0])
    ? matchers[0] as Record<string, unknown>
    : null;
  const matcherOk = matcher !== null &&
    Object.keys(matcher).every((field) => field === "hostname" || field === "ports") &&
    matcher.hostname === applicationHostname(spec) && Array.isArray(matcher.ports) &&
    matcher.ports.length === 1 && matcher.ports[0] === applicationPort(spec);

  const upstreams = payload.upstreams;
  const upstream = Array.isArray(upstreams) && upstreams.length === 1 &&
      typeof upstreams[0] === "object" && upstreams[0] !== null && !Array.isArray(upstreams[0])
    ? upstreams[0] as Record<string, unknown>
    : null;
  const network = upstream?.network;
  const networkOk = typeof network === "object" && network !== null && !Array.isArray(network) &&
    Object.keys(network as Record<string, unknown>).length === 1 &&
    (network as Record<string, unknown>).name ===
      `projects/${upstreamProjectId(spec)}/global/networks/${networkName(spec)}`;
  const hasCamelPolicy = upstream?.egressPolicy !== undefined;
  const hasSnakePolicy = upstream?.egress_policy !== undefined;
  const policy = hasCamelPolicy ? upstream?.egressPolicy : upstream?.egress_policy;
  const egressOk = spec.application_egress_region === null
    ? !hasCamelPolicy && !hasSnakePolicy
    : hasCamelPolicy !== hasSnakePolicy && typeof policy === "object" && policy !== null &&
      !Array.isArray(policy) && Object.keys(policy as Record<string, unknown>).length === 1 &&
      Array.isArray((policy as Record<string, unknown>).regions) &&
      canonicalJson((policy as Record<string, unknown>).regions) ===
        canonicalJson([spec.application_egress_region]);
  const upstreamAllowed = spec.application_egress_region === null
    ? new Set(["network"])
    : new Set(["network", hasCamelPolicy ? "egressPolicy" : "egress_policy"]);
  const topLevelAllowed = new Set([
    "name",
    "displayName",
    hasCamelMatchers ? "endpointMatchers" : "endpoint_matchers",
    "upstreams",
    "schema",
    "createTime",
    "updateTime",
  ]);
  return payload.name ===
      `projects/${spec.project_id}/locations/global/securityGateways/${spec.gateway_id}` +
        `/applications/${resourceName}` &&
    payload.displayName === resourceName && validBeyondCorpTimes(payload) &&
    (payload.schema === undefined || payload.schema === "SCHEMA_UNSPECIFIED") &&
    Object.keys(payload).every((field) => topLevelAllowed.has(field)) &&
    upstream !== null && Object.keys(upstream).every((field) => upstreamAllowed.has(field)) &&
    matcherOk && networkOk && egressOk;
}

const SECRET_VERSION_PHASES = new Set<SecretVersionPhase>([
  "prepared",
  "sending",
  "rejected",
  "version_added",
  "alias_sending",
  "applied",
]);

function secretVersionPhase(
  before: Extract<PersistedBeforeImage, { kind: "secret_version" }>,
): SecretVersionPhase {
  if (before.phase !== undefined) {
    if (!SECRET_VERSION_PHASES.has(before.phase)) {
      throw new ProviderExecutionError("secret-version-phase-invalid");
    }
    return before.phase;
  }
  // Compatibility for checkpoints written before the explicit phase field.
  if (before.versionName === null) return "sending";
  if (
    before.managedAfterAliases !== undefined &&
    before.managedAfterLabels !== undefined
  ) return "alias_sending";
  return "version_added";
}

function secretVersionIdentityFromUrl(
  secretUrl: string,
): { projectId: string; secretName: string } | null {
  const prefix = `${SECRET_MANAGER_API}/projects/`;
  if (!secretUrl.startsWith(prefix)) return null;
  const parts = secretUrl.slice(prefix.length).split("/");
  if (
    parts.length !== 3 || parts[1] !== "secrets" ||
    parts[0] === "" || parts[2] === ""
  ) return null;
  return { projectId: parts[0]!, secretName: parts[2]! };
}

function canonicalCheckpointSecretVersion(
  versionName: string,
  secretUrl: string,
): string {
  const identity = secretVersionIdentityFromUrl(secretUrl);
  if (identity === null) {
    throw new ProviderExecutionError("secret-version-secret-url-invalid");
  }
  return canonicalSecretVersionUrl(
    versionName,
    identity.projectId,
    identity.secretName,
  );
}

function isBeforeImage<K extends PersistedBeforeImage["kind"]>(
  value: unknown,
  kind: K,
): value is Extract<PersistedBeforeImage, { kind: K }> {
  return typeof value === "object" && value !== null &&
    (value as { kind?: unknown }).kind === kind;
}

function isSecretEtagPrecondition(error: unknown): error is GoogleApiError {
  if (!(error instanceof GoogleApiError) || error.status !== 400) return false;
  const detail = error.payload.error;
  return typeof detail === "object" && detail !== null && !Array.isArray(detail) &&
    (detail as { status?: unknown }).status === "FAILED_PRECONDITION";
}

function strictSecretStringMap(value: unknown): Record<string, string> {
  if (value === undefined) return {};
  if (
    typeof value !== "object" || value === null ||
    Array.isArray(value) || Object.values(value).some((item) => typeof item !== "string")
  ) {
    throw new ProviderExecutionError("secret-version-current-metadata-invalid");
  }
  return structuredClone(value as Record<string, string>);
}

function restoreManagedStringMapStrict(
  before: Record<string, string>,
  managedAfter: Record<string, string>,
  current: Record<string, string>,
  options: { allowMissingManagedAfterKey?: string } = {},
): Record<string, string> {
  const restored = { ...current };
  const keys = new Set([...Object.keys(before), ...Object.keys(managedAfter)]);
  for (const key of keys) {
    const beforeHas = Object.hasOwn(before, key);
    const afterHas = Object.hasOwn(managedAfter, key);
    if (beforeHas === afterHas && (!beforeHas || before[key] === managedAfter[key])) continue;
    const currentHas = Object.hasOwn(current, key);
    const matchesBefore = currentHas === beforeHas &&
      (!beforeHas || current[key] === before[key]);
    const matchesAfter = currentHas === afterHas &&
      (!afterHas || current[key] === managedAfter[key]);
    const managedAliasRemovedByDestroy = key === options.allowMissingManagedAfterKey &&
      afterHas && !currentHas;
    if (matchesBefore) continue;
    if (!matchesAfter && !managedAliasRemovedByDestroy) {
      throw new ProviderExecutionError("secret-version-current-state-changed");
    }
    if (beforeHas) restored[key] = before[key]!;
    else delete restored[key];
  }
  return restored;
}

export class GoogleResourceExecutor {
  private readonly transport: Transport;
  private readonly workspaceTransport: Transport;
  private readonly before = new Map<string, unknown>();
  private gatewayServiceAccount: string | null = null;

  private readonly requestIds: (change: ResourceChange) => string;
  private readonly exportArtifact: (filename: string, contents: string) => Promise<void>;
  private readonly operationPollIntervalMs: number;
  private readonly maxOperationPolls: number;
  /**
   * How long a Secure Gateway / application IAM write needs before the Service
   * Discovery control plane serves it. The Chrome managed configuration hands
   * the gateway resource to the browser extension, which fetches routes at
   * once; publishing it before the binding is live earns a 403 that the
   * extension answers with a two-hour backoff, so Apply waits this out first.
   */
  private readonly iamSettleMs: number;
  /** Wall clock of the last gateway or application IAM write in this run. */
  private iamMutatedAt: number | undefined;
  private readonly accessPolicyId: string | undefined;
  private readonly publicCertificateBinding: PublicCertificateBinding | null;
  private readonly sourceImageBinding: SourceImageBinding | null;
  private sourceImageValidated = false;
  private readonly issueEnterpriseCertificate:
    | ((
        runId: string,
        spec: DeploymentSpec,
        requestId: string,
        checkpointCsr: (
          csrPem: string,
          phase?: PrivateCaMutationPhase,
        ) => Promise<void>,
      ) => Promise<CertificateBundle>)
    | undefined;
  private checkpointBeforeImage: ((beforeImage: unknown) => Promise<void>) | undefined;
  private preservePersistedBeforeImage = false;
  /** Set once the run issues a certificate; reused by every step that needs it. */
  certificate: CertificateBundle | undefined;

  constructor(
    transport: Transport,
    options: {
      requestId?: (change: ResourceChange) => string;
      exportArtifact?: (filename: string, contents: string) => Promise<void>;
      certificate?: CertificateBundle;
      operationPollIntervalMs?: number;
      maxOperationPolls?: number;
      iamSettleMs?: number;
      workspaceTransport?: Transport;
      accessPolicyId?: string;
      publicCertificateBinding?: PublicCertificateBinding | null;
      sourceImageBinding?: SourceImageBinding | null;
      issueEnterpriseCertificate?: (
        runId: string,
        spec: DeploymentSpec,
        requestId: string,
        checkpointCsr: (
          csrPem: string,
          phase?: PrivateCaMutationPhase,
        ) => Promise<void>,
      ) => Promise<CertificateBundle>;
    } = {},
  ) {
    this.operationPollIntervalMs = options.operationPollIntervalMs ?? 2_000;
    this.maxOperationPolls = options.maxOperationPolls ?? 150;
    this.iamSettleMs = options.iamSettleMs ?? 45_000;
    // Every handler, including Path A/Production modules, receives the checked
    // view. Raw non-2xx responses therefore cannot be mistaken for payloads,
    // and mutations do not return until any Google operation has completed.
    this.transport = this.checkedTransport(transport);
    this.workspaceTransport = options.workspaceTransport === undefined
      ? this.transport
      : this.checkedTransport(options.workspaceTransport);
    // Google deduplicates creates by requestId, so a retry must present the
    // same token. The run engine supplies one persisted with the step; the
    // fallback only covers callers that never retry.
    this.requestIds = options.requestId ?? (() => crypto.randomUUID());
    this.exportArtifact = options.exportArtifact ?? defaultExportArtifact;
    this.accessPolicyId = options.accessPolicyId;
    this.publicCertificateBinding = options.publicCertificateBinding ?? null;
    this.sourceImageBinding = options.sourceImageBinding ?? null;
    this.issueEnterpriseCertificate = options.issueEnterpriseCertificate;
    this.certificate = options.certificate;
  }

  private async ensureSourceImageBinding(
    spec: DeploymentSpec,
    force = false,
  ): Promise<void> {
    if (spec.backend_kind === "direct_https") {
      if (this.sourceImageBinding !== null) {
        throw new ProviderExecutionError("source-image-binding-invalid");
      }
      this.sourceImageValidated = true;
      return;
    }
    const binding = this.sourceImageBinding;
    const expectedName = spec.source_image;
    if (
      !binding || !expectedName || binding.name !== expectedName ||
      !/^[1-9][0-9]*$/.test(binding.id) ||
      binding.self_link !== `https://www.googleapis.com/compute/v1/${expectedName}`
    ) {
      throw new ProviderExecutionError("source-image-binding-invalid");
    }
    if (this.sourceImageValidated && !force) return;
    const response = await this.transport.requestJson(
      "GET",
      `https://compute.googleapis.com/compute/v1/${expectedName}`,
    );
    const image = response.payload;
    const identifier = typeof image.id === "string"
      ? image.id
      : typeof image.id === "number" && Number.isSafeInteger(image.id)
        ? String(image.id)
        : "";
    const deprecated = image.deprecated;
    if (
      image.name !== expectedName.split("/").pop() || identifier !== binding.id ||
      image.selfLink !== binding.self_link ||
      (deprecated !== undefined &&
        (typeof deprecated !== "object" || deprecated === null || Array.isArray(deprecated))) ||
      (typeof deprecated === "object" && deprecated !== null &&
        ["OBSOLETE", "DELETED"].includes(
          String((deprecated as Record<string, unknown>).state ?? ""),
        ))
    ) {
      throw new ProviderExecutionError("source-image-binding-invalid");
    }
    this.sourceImageValidated = true;
  }

  /** Revalidate approval-bound immutable inputs before the first provider mutation. */
  async prepareApply(spec: DeploymentSpec): Promise<void> {
    if (spec.mode === "production" && spec.backend_kind === "internal_https_lb") {
      throw new ProviderExecutionError("production-ilb-unsupported-in-0.2.1");
    }
    await this.ensureSourceImageBinding(spec);
  }

  private checkedTransport(rawTransport: Transport): Transport {
    return {
      requestJson: async (method, url, requestOptions) => {
        const response = await requestJsonChecked(
          rawTransport,
          method,
          url,
          requestOptions,
        );
        if (method === "GET") return response;
        if (this.dnsChangeCollectionUrl(url) !== null) {
          return this.waitForDnsChange(rawTransport, response, url);
        }
        return this.waitForOperation(rawTransport, response, url);
      },
    };
  }

  private dnsChangeCollectionUrl(value: string): URL | null {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      return null;
    }
    return url.origin === "https://dns.googleapis.com" &&
        url.username === "" && url.password === "" && url.search === "" &&
        url.hash === "" &&
        /^\/dns\/v1\/projects\/[^/]+\/managedZones\/[^/]+\/changes$/.test(url.pathname)
      ? url
      : null;
  }

  private async waitForDnsChange(
    rawTransport: Transport,
    initial: TransportResponse,
    requestUrl: string,
  ): Promise<TransportResponse> {
    const collection = this.dnsChangeCollectionUrl(requestUrl);
    if (collection === null) {
      throw new ProviderExecutionError("dns-change-url-invalid");
    }
    const parse = (payload: Record<string, unknown>): { id: string; done: boolean } => {
      if (
        payload.kind !== "dns#change" || typeof payload.id !== "string" ||
        !/^[A-Za-z0-9_-]+$/.test(payload.id) ||
        (payload.status !== "pending" && payload.status !== "done")
      ) {
        throw new ProviderExecutionError("dns-change-response-invalid");
      }
      return { id: payload.id, done: payload.status === "done" };
    };
    const first = parse(initial.payload);
    if (first.done) return initial;
    const pollUrl = `${collection.toString()}/${encodeURIComponent(first.id)}`;
    for (let poll = 0; poll < this.maxOperationPolls; poll += 1) {
      if (this.operationPollIntervalMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, this.operationPollIntervalMs));
      }
      const response = await requestJsonChecked(rawTransport, "GET", pollUrl);
      const current = parse(response.payload);
      if (current.id !== first.id) {
        throw new ProviderExecutionError("dns-change-identity-mismatch");
      }
      if (current.done) return response;
    }
    throw new ProviderExecutionError("dns-change-timeout");
  }

  private async waitForOperation(
    rawTransport: Transport,
    initial: TransportResponse,
    requestUrl: string,
  ): Promise<TransportResponse> {
    const completedResponse = (response: TransportResponse): TransportResponse => {
      const value = response.payload.response;
      return typeof value === "object" && value !== null && !Array.isArray(value)
        ? { ...response, payload: value as Record<string, unknown> }
        : response;
    };
    if (!isGoogleOperation(initial.payload)) return initial;
    ensureOperationSucceeded(initial.payload);
    if (operationDone(initial.payload)) return completedResponse(initial);

    const operationUrl = googleOperationUrl(initial.payload, requestUrl);
    if (operationUrl === null) {
      throw new ProviderExecutionError("provider-operation-missing-name");
    }
    for (let poll = 0; poll < this.maxOperationPolls; poll += 1) {
      if (this.operationPollIntervalMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, this.operationPollIntervalMs));
      }
      const response = await requestJsonChecked(rawTransport, "GET", operationUrl);
      ensureOperationSucceeded(response.payload);
      if (operationDone(response.payload)) return completedResponse(response);
    }
    throw new ProviderExecutionError("provider-operation-timeout");
  }

  private pathAContext(
    requestId: string,
    beforeImage?: unknown,
    transport: Transport = this.transport,
  ) {
    return {
      transport,
      requestId: () => requestId,
      beforeImage,
      publicCertificateBinding: this.publicCertificateBinding,
      sourceImageBinding: this.sourceImageBinding,
      certificate: this.certificate,
      exportArtifact: this.exportArtifact,
      captureBefore: (change: ResourceChange, beforeImage: unknown) =>
        this.captureBefore(change, beforeImage),
      maxOperationPolls: this.maxOperationPolls,
      operationPollIntervalMs: this.operationPollIntervalMs,
      iamSettleMs: this.iamSettleMs,
    };
  }

  private genericCreatedResourceUrl(
    change: ResourceChange,
    spec: DeploymentSpec,
  ): string | null {
    if (change.provider === "compute") {
      if (
        change.resource_type === "cloud_nat" ||
        change.resource_type === "offload_refresh" ||
        change.resource_type === "source_image"
      ) return null;
      return resourceUrlForChange(change, spec);
    }
    if (change.provider === "beyondcorp") {
      if (change.resource_type === "security_gateway") return this.gatewayResource(spec);
      if (change.resource_type === "application") return resourceUrlForChange(change, spec);
    }
    return null;
  }

  private async readGenericCreatedResource(
    change: ResourceChange,
    resourceUrl: string,
    marker: string | null,
  ): Promise<{
    status: number;
    payload: Record<string, unknown>;
    identity: { field: string; value: string } | null;
  }> {
    const response = await this.requestWithStatus("GET", resourceUrl, {
      acceptedStatuses: [404],
    });
    if (response.status === 404) {
      return { status: 404, payload: response.payload, identity: null };
    }
    if (marker !== null && response.payload.description !== marker) {
      return { status: response.status, payload: response.payload, identity: null };
    }
    return {
      status: response.status,
      payload: response.payload,
      identity: genericProviderIdentity(response.payload, change.provider),
    };
  }

  private async assertInstanceBootDiskImage(
    spec: DeploymentSpec,
    instanceName: string,
  ): Promise<void> {
    const binding = this.sourceImageBinding;
    if (!binding || !spec.source_image || binding.name !== spec.source_image) {
      throw new ProviderExecutionError("source-image-binding-invalid");
    }
    const instancePath =
      `/projects/${spec.project_id}/zones/${spec.zone}/instances/${instanceName}`;
    const instance = await this.requestWithStatus(
      "GET",
      `https://compute.googleapis.com/compute/v1${instancePath}`,
      { acceptedStatuses: [404] },
    );
    const disks = instance.payload.disks;
    if (
      instance.status !== 200 || !Array.isArray(disks) || disks.length !== 1 ||
      typeof disks[0] !== "object" || disks[0] === null || Array.isArray(disks[0])
    ) {
      throw new ProviderExecutionError("instance-boot-disk-identity-invalid");
    }
    const attached = disks[0] as Record<string, unknown>;
    const diskPath =
      `/projects/${spec.project_id}/zones/${spec.zone}/disks/${instanceName}`;
    if (
      attached.boot !== true || typeof attached.source !== "string" ||
      !attached.source.endsWith(diskPath)
    ) {
      throw new ProviderExecutionError("instance-boot-disk-identity-invalid");
    }
    const disk = await this.requestWithStatus(
      "GET",
      `https://compute.googleapis.com/compute/v1${diskPath}`,
      { acceptedStatuses: [404] },
    );
    const current = disk.payload;
    if (
      disk.status !== 200 || current.name !== instanceName || current.status !== "READY" ||
      typeof current.selfLink !== "string" || !current.selfLink.endsWith(diskPath) ||
      typeof current.zone !== "string" ||
      !current.zone.endsWith(`/projects/${spec.project_id}/zones/${spec.zone}`) ||
      String(current.sizeGb) !== "20" || typeof current.type !== "string" ||
      !current.type.endsWith(
        `/projects/${spec.project_id}/zones/${spec.zone}/diskTypes/pd-balanced`,
      ) ||
      typeof current.sourceImage !== "string" ||
      !current.sourceImage.endsWith(`/${spec.source_image}`) ||
      String(current.sourceImageId) !== binding.id
    ) {
      throw new ProviderExecutionError("instance-boot-disk-identity-invalid");
    }
  }

  /**
   * Wrap one create so its exact intent and provider identity are durable
   * before the rest of the resource handler (readiness checks included) runs.
   */
  private async applyGenericCreatedResource(
    change: ResourceChange,
    spec: DeploymentSpec,
    requestId: string,
    beforeImage?: unknown,
  ): Promise<void> {
    const resourceUrl = this.genericCreatedResourceUrl(change, spec);
    if (resourceUrl === null) {
      throw new ProviderExecutionError("generic-resource-url-missing");
    }
    const createUrl = resourceUrl.slice(0, resourceUrl.lastIndexOf("/"));
    const resourceKey = this.key(change);
    const postCreate = change.provider === "compute" && change.resource_type === "instance"
      ? () => this.assertInstanceBootDiskImage(spec, change.resource_name)
      : null;
    let intercepted = false;
    const createTransport: Transport = {
      requestJson: async (method, url, options = {}) => {
        if (method !== "POST" || url !== createUrl) {
          return this.transport.requestJson(method, url, options);
        }
        if (intercepted) {
          throw new ProviderExecutionError("generic-resource-create-repeated-in-step");
        }
        intercepted = true;
        const body = options.jsonBody;
        if (typeof body !== "object" || body === null || Array.isArray(body)) {
          throw new ProviderExecutionError("generic-resource-create-body-invalid");
        }
        const requestBody = structuredClone(body);
        if (options.params?.requestId !== requestId) {
          throw new ProviderExecutionError("generic-resource-request-id-mismatch");
        }
        let ownershipMarker: string | null = null;
        if (change.provider === "compute") {
          const prefix = `Secure Gateway Studio ownership-token=${requestId}`;
          const description = requestBody.description;
          ownershipMarker = typeof description === "string" && description !== ""
            ? `${prefix}; ${description}`
            : prefix;
          requestBody.description = ownershipMarker;
        }
        const expected: GenericCreatedResourceCheckpoint = {
          kind: "generic_created_resource",
          protocolVersion: 2,
          phase: "prepared",
          resourceKey,
          createUrl,
          resourceUrl,
          createRequestId: requestId,
          expectedParamsDigest: canonicalDigestSync(options.params ?? {}),
          expectedPayloadDigest: canonicalDigestSync(requestBody),
          ownershipMarker,
        };
        const current = this.before.get(resourceKey);
        let checkpoint = expected;
        if (current !== undefined) {
          if (!isBeforeImage(current, "generic_created_resource")) {
            throw new ProviderExecutionError("generic-resource-ownership-checkpoint-mismatch");
          }
          const {
            phase: _currentPhase,
            providerIdentityField: _currentIdentityField,
            providerIdentity: _currentIdentity,
            ...currentBase
          } = current;
          const {
            phase: _expectedPhase,
            providerIdentityField: _expectedIdentityField,
            providerIdentity: _expectedIdentity,
            ...expectedBase
          } = expected;
          if (canonicalJson(currentBase) !== canonicalJson(expectedBase)) {
            throw new ProviderExecutionError("generic-resource-ownership-checkpoint-mismatch");
          }
          checkpoint = current;
        } else {
          await this.captureBefore(change, expected);
        }

        const reconcile = async (
          allowMarkerOnly: boolean,
        ): Promise<TransportResponse | null> => {
          const live = await this.readGenericCreatedResource(
            change,
            resourceUrl,
            ownershipMarker,
          );
          if (live.status !== 200 || live.identity === null) return null;
          if (
            change.provider === "beyondcorp" &&
            !(change.resource_type === "security_gateway"
              ? isCompatibleSecurityGatewayPayload(live.payload, spec)
              : change.resource_type === "application" &&
                isCompatibleBeyondCorpApplicationPayload(
                  live.payload,
                  spec,
                  change.resource_name,
                ))
          ) {
            throw new ProviderExecutionError("generic-resource-managed-state-changed");
          }
          if (postCreate !== null) await postCreate();
          if (checkpoint.phase === "applied") {
            if (
              checkpoint.providerIdentityField !== live.identity.field ||
              checkpoint.providerIdentity !== live.identity.value
            ) {
              throw new ProviderExecutionError("generic-resource-managed-state-changed");
            }
          } else if (!allowMarkerOnly || ownershipMarker === null) {
            return null;
          } else {
            checkpoint = {
              ...checkpoint,
              phase: "applied",
              providerIdentityField: live.identity.field,
              providerIdentity: live.identity.value,
            };
            await this.captureBefore(change, checkpoint);
          }
          return { status: 200, payload: structuredClone(live.payload) };
        };

        if (checkpoint.phase === "applied") {
          const response = await reconcile(false);
          if (response === null) {
            throw new ProviderExecutionError("generic-resource-managed-state-changed");
          }
          return response;
        }
        if (checkpoint.phase === "sending") {
          if (ownershipMarker !== null) {
            const response = await reconcile(true);
            if (response !== null) return response;
          }
          // BeyondCorp has no ownership marker. Replay the exact request with
          // the same durable requestId; equality from a GET alone is never
          // treated as proof that the first ambiguous send was ours.
        }
        if (checkpoint.phase === "rejected") {
          throw new ProviderExecutionError("generic-resource-create-definitively-rejected");
        }
        const replayingAmbiguousSend = checkpoint.phase === "sending";
        if (checkpoint.phase !== "prepared" && !replayingAmbiguousSend) {
          throw new ProviderExecutionError("generic-resource-ownership-checkpoint-invalid");
        }

        if (!replayingAmbiguousSend) {
          checkpoint = { ...checkpoint, phase: "sending" };
          await this.captureBefore(change, checkpoint);
        }
        let response: TransportResponse;
        try {
          response = await this.transport.requestJson(method, url, {
            ...options,
            jsonBody: requestBody,
          });
        } catch (error) {
          if (!replayingAmbiguousSend && isDefiniteMutationRejection(error)) {
            checkpoint = { ...checkpoint, phase: "rejected" };
            await this.captureBefore(change, checkpoint);
            throw error;
          }
          // A Compute description marker proves which same-name object our
          // request created. BeyondCorp has no marker, so equality is never
          // treated as ownership after an ambiguous response.
          const recovered = await reconcile(true).catch(() => null);
          if (recovered !== null) return recovered;
          throw error;
        }

        const live = await this.readGenericCreatedResource(
          change,
          resourceUrl,
          ownershipMarker,
        );
        if (
          change.provider === "beyondcorp" &&
          (live.status !== 200 || live.identity === null ||
            !(change.resource_type === "security_gateway"
              ? isCompatibleSecurityGatewayPayload(live.payload, spec)
              : change.resource_type === "application" &&
                isCompatibleBeyondCorpApplicationPayload(
                  live.payload,
                  spec,
                  change.resource_name,
                )))
        ) {
          throw new ProviderExecutionError("generic-resource-provider-identity-missing");
        }
        const identity = live.status === 200 && live.identity !== null
          ? live.identity
          : genericProviderIdentity(response.payload, change.provider, true);
        if (identity === null) {
          throw new ProviderExecutionError("generic-resource-provider-identity-missing");
        }
        if (postCreate !== null) await postCreate();
        checkpoint = {
          ...checkpoint,
          phase: "applied",
          providerIdentityField: identity.field,
          providerIdentity: identity.value,
        };
        await this.captureBefore(change, checkpoint);
        return response;
      },
    };

    const context = this.pathAContext(requestId, beforeImage, createTransport);
    const kind = `${change.provider}:${change.resource_type}`;
    if (kind === "beyondcorp:security_gateway") {
      await this.createGateway(change, spec, requestId, createTransport);
    } else if (kind === "beyondcorp:application") {
      await this.createApplication(change, spec, requestId, createTransport);
    } else {
      await applyPathA(context, change, spec);
    }
    if (!intercepted) {
      throw new ProviderExecutionError("generic-resource-create-not-intercepted");
    }
  }

  async apply(
    change: ResourceChange,
    spec: DeploymentSpec,
    context?: StepExecutionContext,
  ): Promise<StepApplyResult> {
    await this.ensureSourceImageBinding(
      spec,
      change.resource_type === "instance" || change.resource_type === "instance_template",
    );
    const requestId = context?.requestId ?? this.requestIds(change);
    const key = this.key(change);
    if (context?.beforeImage !== undefined) {
      this.before.set(key, structuredClone(context.beforeImage));
    } else {
      this.before.delete(key);
    }
    this.checkpointBeforeImage = context?.checkpointBeforeImage;
    this.preservePersistedBeforeImage = context?.beforeImage !== undefined;
    try {
      await this.applyUnchecked(
        change,
        spec,
        requestId,
        context?.runId,
        context?.beforeImage,
      );
      return { beforeImage: this.before.get(this.key(change)) };
    } catch (error) {
      throw this.providerError(error, change.provider);
    } finally {
      this.checkpointBeforeImage = undefined;
      this.preservePersistedBeforeImage = false;
    }
  }

  private async captureBefore(change: ResourceChange, beforeImage: unknown): Promise<void> {
    const key = this.key(change);
    // A retry must never replace the original persisted image with a read of
    // state already mutated by this run. During the first attempt, however,
    // multi-phase mutations may enrich the checkpoint (for example addVersion
    // first records the old aliases, then records the exact created version).
    if (this.preservePersistedBeforeImage && this.before.has(key)) {
      const current = this.before.get(key);
      if (isBeforeImage(current, "iam") && isBeforeImage(beforeImage, "iam")) {
        const {
          phase: _currentPhase,
          rejectionStatus: _currentRejection,
          rejectionReason: _currentRejectionReason,
          policy: _currentPolicy,
          afterPolicy: _currentAfter,
          ...currentTarget
        } = current;
        const {
          phase: _candidatePhase,
          rejectionStatus: _candidateRejection,
          rejectionReason: _candidateRejectionReason,
          policy: _candidatePolicy,
          afterPolicy: _candidateAfter,
          ...candidateTarget
        } = beforeImage;
        const currentPhase = sharedMutationPhase(current);
        const candidatePhase = sharedMutationPhase(beforeImage);
        const sameTarget = canonicalJson(currentTarget) === canonicalJson(candidateTarget);
        const safeRebase = sameTarget && candidatePhase === "prepared" &&
          (currentPhase === "prepared" ||
            (currentPhase === "rejected" && current.rejectionStatus === 409 &&
              current.rejectionReason === "ABORTED"));
        if (
          safeRebase ||
          (sameTarget && canonicalJson(_currentPolicy) === canonicalJson(_candidatePolicy) &&
            canonicalJson(_currentAfter) === canonicalJson(_candidateAfter) &&
            SHARED_MUTATION_TRANSITIONS[currentPhase].includes(candidatePhase))
        ) {
          const advanced = structuredClone(beforeImage);
          this.before.set(key, advanced);
          await this.checkpointBeforeImage?.(advanced);
        }
        return;
      }
      if (
        isBeforeImage(current, "chrome_policy") &&
        isBeforeImage(beforeImage, "chrome_policy")
      ) {
        const { phase: _currentPhase, ...currentIdentity } = current;
        const { phase: _candidatePhase, ...candidateIdentity } = beforeImage;
        const currentPhase = sharedMutationPhase(current);
        const candidatePhase = sharedMutationPhase(beforeImage);
        if (
          canonicalJson(currentIdentity) === canonicalJson(candidateIdentity) &&
          SHARED_MUTATION_TRANSITIONS[currentPhase].includes(candidatePhase)
        ) {
          const advanced = structuredClone(beforeImage);
          this.before.set(key, advanced);
          await this.checkpointBeforeImage?.(advanced);
        }
        return;
      }
      if (
        isBeforeImage(current, "secret_iam") &&
        isBeforeImage(beforeImage, "secret_iam")
      ) {
        const {
          phase: _currentPhase,
          rejectionStatus: _currentRejection,
          rejectionReason: _currentRejectionReason,
          policy: _currentPolicy,
          afterPolicy: _currentAfter,
          ...currentTarget
        } = current;
        const {
          phase: _candidatePhase,
          rejectionStatus: _candidateRejection,
          rejectionReason: _candidateRejectionReason,
          policy: _candidatePolicy,
          afterPolicy: _candidateAfter,
          ...candidateTarget
        } = beforeImage;
        const currentPhase = sharedMutationPhase(current);
        const candidatePhase = sharedMutationPhase(beforeImage);
        const sameTarget = canonicalJson(currentTarget) === canonicalJson(candidateTarget);
        const safeRebase = sameTarget && candidatePhase === "prepared" &&
          (currentPhase === "prepared" ||
            (currentPhase === "rejected" && current.rejectionStatus === 409 &&
              current.rejectionReason === "ABORTED"));
        if (
          safeRebase ||
          (sameTarget && canonicalJson(_currentPolicy) === canonicalJson(_candidatePolicy) &&
            canonicalJson(_currentAfter) === canonicalJson(_candidateAfter) &&
            SHARED_MUTATION_TRANSITIONS[currentPhase].includes(candidatePhase))
        ) {
          const advanced = structuredClone(beforeImage);
          this.before.set(key, advanced);
          await this.checkpointBeforeImage?.(advanced);
        }
        return;
      }
      if (
        isBeforeImage(current, "generic_created_resource") &&
        isBeforeImage(beforeImage, "generic_created_resource")
      ) {
        const {
          phase: _currentPhase,
          providerIdentityField: currentIdentityField,
          providerIdentity: currentIdentity,
          ...currentBase
        } = current;
        const {
          phase: _candidatePhase,
          providerIdentityField: candidateIdentityField,
          providerIdentity: candidateIdentity,
          ...candidateBase
        } = beforeImage;
        const identityCompatible =
          (currentIdentityField === candidateIdentityField &&
            currentIdentity === candidateIdentity) ||
          (currentIdentityField === undefined && currentIdentity === undefined &&
            typeof candidateIdentityField === "string" &&
            typeof candidateIdentity === "string" &&
            beforeImage.phase === "applied");
        if (
          canonicalJson(currentBase) === canonicalJson(candidateBase) &&
          SHARED_MUTATION_TRANSITIONS[current.phase].includes(beforeImage.phase) &&
          identityCompatible
        ) {
          const advanced = structuredClone(beforeImage);
          this.before.set(key, advanced);
          await this.checkpointBeforeImage?.(advanced);
        }
        return;
      }
      if (
        isBeforeImage(current, "named_resource_ownership") &&
        isBeforeImage(beforeImage, "named_resource_ownership")
      ) {
        const {
          protocolVersion: _currentProtocol,
          phase: _currentPhase,
          ...currentIdentity
        } = current;
        const {
          protocolVersion: _candidateProtocol,
          phase: _candidatePhase,
          ...candidateIdentity
        } = beforeImage;
        const phase = (
          value: NamedResourceOwnershipCheckpoint,
        ): SharedMutationPhase =>
          value.protocolVersion === 1 &&
            (value.phase === "prepared" || value.phase === "sending" ||
              value.phase === "rejected" || value.phase === "applied")
            ? value.phase
            : "sending";
        if (
          canonicalJson(currentIdentity) === canonicalJson(candidateIdentity) &&
          SHARED_MUTATION_TRANSITIONS[phase(current)].includes(phase(beforeImage))
        ) {
          const advanced = structuredClone(beforeImage);
          this.before.set(key, advanced);
          await this.checkpointBeforeImage?.(advanced);
        }
        return;
      }
      if (
        isBeforeImage(current, "offload_refresh") &&
        isBeforeImage(beforeImage, "offload_refresh")
      ) {
        const { phase: _currentPhase, ...currentIdentity } = current;
        const { phase: _candidatePhase, ...candidateIdentity } = beforeImage;
        const allowedNext: Record<
          OffloadRefreshCheckpoint["phase"],
          readonly OffloadRefreshCheckpoint["phase"][]
        > = {
          prepared: ["prepared", "stop_sending", "stopped"],
          // Production uses one MIG restart request rather than PoC's
          // stop/start pair. The API has no idempotency token: an ambiguous
          // send can never advance, while a definite provider rejection may
          // be checkpointed and retried safely.
          stop_sending: ["stop_sending", "restart_rejected", "stopped", "applied"],
          restart_rejected: ["restart_rejected", "stop_sending"],
          stopped: ["stopped", "start_sending", "applied"],
          start_sending: ["start_sending", "applied"],
          applied: ["applied"],
        };
        if (
          allowedNext[current.phase].includes(beforeImage.phase) &&
          canonicalJson(currentIdentity) === canonicalJson(candidateIdentity)
        ) {
          const advanced = structuredClone(beforeImage);
          this.before.set(key, advanced);
          await this.checkpointBeforeImage?.(advanced);
        }
        return;
      }
      if (
        isBeforeImage(current, "privateca_certificate") &&
        isBeforeImage(beforeImage, "privateca_certificate")
      ) {
        const {
          phase: _currentPhase,
          protocolVersion: _currentProtocol,
          ...currentIdentity
        } = current;
        const {
          phase: _candidatePhase,
          protocolVersion: _candidateProtocol,
          ...candidateIdentity
        } = beforeImage;
        const phase = (
          value: Extract<PersistedBeforeImage, { kind: "privateca_certificate" }>,
        ): PrivateCaMutationPhase =>
          value.protocolVersion === 1 &&
            (value.phase === "prepared" || value.phase === "sending" ||
              value.phase === "rejected" || value.phase === "applied")
            ? value.phase
            : "sending";
        const allowedNext: Record<
          PrivateCaMutationPhase,
          readonly PrivateCaMutationPhase[]
        > = {
          prepared: ["prepared", "sending", "rejected"],
          sending: ["sending", "rejected", "applied"],
          rejected: ["rejected"],
          applied: ["applied"],
        };
        if (
          canonicalJson(currentIdentity) === canonicalJson(candidateIdentity) &&
          allowedNext[phase(current)].includes(phase(beforeImage))
        ) {
          const advanced = structuredClone(beforeImage);
          this.before.set(key, advanced);
          await this.checkpointBeforeImage?.(advanced);
        }
        return;
      }
      // addVersion has no requestId. Recovery may identify the one new version
      // by the pre-checkpointed payload digest and baseline, then durably enrich
      // only the previously-null result field before moving the active alias.
      if (isBeforeImage(current, "secret_version") && isBeforeImage(beforeImage, "secret_version")) {
        const {
          phase: _currentPhase,
          versionName: _currentVersion,
          previousAliases: _currentPreviousAliases,
          previousLabels: _currentPreviousLabels,
          managedAfterAliases: _currentManagedAliases,
          managedAfterLabels: _currentManagedLabels,
          ...currentPromotionIdentity
        } = current;
        const {
          phase: _candidatePhase,
          versionName: _candidateVersion,
          previousAliases: _candidatePreviousAliases,
          previousLabels: _candidatePreviousLabels,
          managedAfterAliases: _candidateManagedAliases,
          managedAfterLabels: _candidateManagedLabels,
          ...candidatePromotionIdentity
        } = beforeImage;
        const currentPhase = secretVersionPhase(current);
        const candidatePhase = secretVersionPhase(beforeImage);
        const allowedNext: Record<SecretVersionPhase, readonly SecretVersionPhase[]> = {
          prepared: ["prepared", "sending", "rejected"],
          sending: ["sending", "rejected", "version_added"],
          rejected: ["rejected"],
          version_added: ["version_added", "alias_sending"],
          alias_sending: ["alias_sending", "applied"],
          applied: ["applied"],
        };
        let versionCompatible = current.versionName === beforeImage.versionName ||
          (current.versionName === null && typeof beforeImage.versionName === "string");
        if (
          !versionCompatible && typeof current.versionName === "string" &&
          typeof beforeImage.versionName === "string" &&
          current.secretUrl === beforeImage.secretUrl
        ) {
          try {
            versionCompatible =
              canonicalCheckpointSecretVersion(current.versionName, current.secretUrl) ===
              canonicalCheckpointSecretVersion(beforeImage.versionName, beforeImage.secretUrl);
          } catch {
            versionCompatible = false;
          }
        }
        const promotesMetadata =
          currentPhase === "version_added" && candidatePhase === "alias_sending";
        const previousCompatible = promotesMetadata || (
          canonicalJson(current.previousAliases) === canonicalJson(beforeImage.previousAliases) &&
          canonicalJson(current.previousLabels) === canonicalJson(beforeImage.previousLabels)
        );
        const managedCompatible = promotesMetadata || (
          canonicalJson(current.managedAfterAliases ?? null) ===
            canonicalJson(beforeImage.managedAfterAliases ?? null) &&
          canonicalJson(current.managedAfterLabels ?? null) ===
            canonicalJson(beforeImage.managedAfterLabels ?? null)
        );
        if (
          canonicalJson(currentPromotionIdentity) === canonicalJson(candidatePromotionIdentity) &&
          allowedNext[currentPhase].includes(candidatePhase) &&
          versionCompatible && previousCompatible && managedCompatible
        ) {
          const advanced = structuredClone(beforeImage);
          this.before.set(key, advanced);
          await this.checkpointBeforeImage?.(advanced);
        }
      }
      return;
    }
    const snapshot = structuredClone(beforeImage);
    this.before.set(key, snapshot);
    await this.checkpointBeforeImage?.(snapshot);
  }

  /** Restore a modified shared resource or delete a resource this run created. */
  async rollback(
    change: ResourceChange,
    spec: DeploymentSpec,
    context: StepExecutionContext,
  ): Promise<void> {
    try {
      if (change.provider === "chromepolicy") {
        await this.assertTargetOuIsNonRoot(spec);
      }
      const before = context.beforeImage;
      if (isBeforeImage(before, "iam")) {
        await this.restorePersistedIam(before);
        return;
      }
      if (isBeforeImage(before, "chrome_policy")) {
        await this.restoreChromePolicy(spec, before);
        return;
      }
      if (isBeforeImage(before, "router_nats")) {
        await this.restoreManagedCloudNat(before, context.requestId);
        return;
      }
      if (isBeforeImage(before, "offload_refresh")) {
        if (spec.mode === "production") {
          await ensureProductionOffloadRefreshHealthy(
            this.transport,
            spec,
            before,
            this.sourceImageBinding,
          );
        } else {
          await ensureOffloadRefreshRunning(
            this.transport,
            before,
            spec,
            context.requestId,
          );
        }
        return;
      }
      if (isBeforeImage(before, "generic_created_resource")) {
        const outcome = await this.destroyGenericCreatedResource(
          change,
          spec,
          before,
          context.requestId,
        );
        if (outcome !== "deleted") {
          throw new ProviderExecutionError("generic-resource-managed-state-changed");
        }
        return;
      }
      if (isBeforeImage(before, "named_resource_ownership")) {
        const outcome = await this.destroyNamedOwnedResource(change, spec, before);
        if (outcome !== "deleted") {
          throw new ProviderExecutionError("named-resource-managed-state-changed");
        }
        return;
      }
      if (isBeforeImage(before, "secret_iam")) {
        await this.restorePersistedIam(before);
        return;
      }
      if (isBeforeImage(before, "secret_version")) {
        await this.restoreSecretVersion(
          before,
          "disable",
          spec.project_id,
          change.resource_name,
        );
        return;
      }
      if (isBeforeImage(before, "privateca_certificate")) {
        await this.revokePrivateCaCertificate(before, context.requestId);
        return;
      }
      if (change.owned_after_apply) {
        await this.destroy(change, spec, context.requestId);
      }
    } catch (error) {
      throw this.providerError(error, change.provider, "rollback");
    }
  }

  private restorePersistedIam(
    before: Extract<PersistedBeforeImage, { kind: "iam" | "secret_iam" }>,
  ): Promise<void> {
    const phase = sharedMutationPhase(before);
    if (phase === "prepared" || phase === "rejected") {
      // The durable protocol proves no IAM SET was accepted.
      return Promise.resolve();
    }
    if (phase === "sending") {
      // Removing a coincidental matching member would destroy an external
      // administrator's change. Retain the ownership record for review.
      throw new ProviderExecutionError("iam-rollback-outcome-ambiguous");
    }
    if (
      before.afterPolicy === null ||
      typeof before.afterPolicy !== "object" ||
      Array.isArray(before.afterPolicy)
    ) {
      // Older records contain only a before-image. Replacing a live policy from
      // that snapshot could erase unrelated post-Apply edits, so fail closed.
      throw new ProviderExecutionError("iam-restore-after-policy-missing");
    }
    const derivedGetUrl = before.setUrl.replace(/:setIamPolicy$/, ":getIamPolicy");
    if (derivedGetUrl === before.setUrl && before.getUrl === undefined) {
      throw new ProviderExecutionError("iam-restore-get-url-missing");
    }
    const getUrl = before.getUrl ?? derivedGetUrl;
    const getMethod = before.getMethod ??
      (getUrl.startsWith("https://cloudresourcemanager.googleapis.com/")
        ? "POST"
        : "GET");
    return restoreIamPolicyWithFreshEtag(this.transport, {
      getUrl,
      setUrl: before.setUrl,
      getMethod,
      beforePolicy: before.policy,
      afterPolicy: before.afterPolicy,
    });
  }

  private providerError(
    error: unknown,
    provider: string,
    prefix = "google-api",
  ): unknown {
    if (!(error instanceof GoogleApiError)) return error;
    const status = googleStatusCode(error.payload);
    return new ProviderExecutionError(
      `${prefix}-${error.status}-${provider}${status ? `-${status}` : ""}`,
    );
  }

  /**
   * Delete exactly one server-recorded resource.
   *
   * The caller decides ownership; this method never lists broadly and then
   * deletes everything it finds. NOT_FOUND is accepted only on the exact
   * resource URL, which makes retries idempotent without hiding permission or
   * validation failures.
   */
  async destroy(
    change: ResourceChange,
    spec: DeploymentSpec,
    requestId: string = crypto.randomUUID(),
    beforeImage?: unknown,
  ): Promise<"deleted" | "restored" | "skipped"> {
    try {
      beforeImage ??= this.before.get(this.key(change));
      if (beforeImage !== undefined) {
        if (isBeforeImage(beforeImage, "secret_version")) {
          await this.restoreSecretVersion(
            beforeImage,
            "destroy",
            spec.project_id,
            change.resource_name,
          );
          return "deleted";
        }
        if (isBeforeImage(beforeImage, "privateca_certificate")) {
          const outcome = await this.revokePrivateCaCertificate(beforeImage, requestId);
          return outcome === "not_owned" ? "skipped" : "deleted";
        }
        if (isBeforeImage(beforeImage, "named_resource_ownership")) {
          return this.destroyNamedOwnedResource(change, spec, beforeImage);
        }
        if (isBeforeImage(beforeImage, "generic_created_resource")) {
          return this.destroyGenericCreatedResource(
            change,
            spec,
            beforeImage,
            requestId,
          );
        }
        const capability = compensationCapability(change, beforeImage);
        if (!capability.available) {
          throw new ProviderExecutionError(capability.errorCode);
        }
        await this.rollback(change, spec, {
          runId: "teardown",
          stepIndex: 0,
          requestId,
          beforeImage,
        });
        return "restored";
      }

      const kind = `${change.provider}:${change.resource_type}`;
      const capability = compensationCapability(change, beforeImage);
      if (!capability.available) {
        throw new ProviderExecutionError(capability.errorCode);
      }
      if (kind === "serviceusage:project_services" ||
          kind === "accesscontextmanager:access_level" ||
          kind === "compute:source_image" ||
          kind === "compute:offload_refresh" ||
          kind === "local:root_certificate_artifact") {
        return "skipped";
      }
      const url = resourceUrlForChange(change, spec);
      if (url === null) {
        throw new ProviderExecutionError(`teardown-unsupported-${change.resource_type}`);
      }
      await this.deleteExact(url, {
        requestId:
          url.startsWith("https://compute.googleapis.com/") ||
          url.startsWith("https://beyondcorp.googleapis.com/")
            ? requestId
            : undefined,
      });
      return "deleted";
    } catch (error) {
      throw this.providerError(error, change.provider, "teardown");
    }
  }

  private async deleteExact(
    url: string,
    options: { requestId?: string } = {},
  ): Promise<void> {
    await this.request("DELETE", url, {
      params: options.requestId ? { requestId: options.requestId } : undefined,
      acceptedStatuses: [404],
    });
  }

  private async destroyGenericCreatedResource(
    change: ResourceChange,
    spec: DeploymentSpec,
    before: GenericCreatedResourceCheckpoint,
    requestId: string,
  ): Promise<"deleted" | "skipped"> {
    const expectedUrl = this.genericCreatedResourceUrl(change, spec);
    if (
      expectedUrl === null || before.protocolVersion !== 2 ||
      before.resourceKey !== this.key(change) || before.resourceUrl !== expectedUrl ||
      before.createUrl !== expectedUrl.slice(0, expectedUrl.lastIndexOf("/")) ||
      typeof before.createRequestId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
        .test(before.createRequestId) ||
      !/^[0-9a-f]{64}$/.test(before.expectedParamsDigest) ||
      !/^[0-9a-f]{64}$/.test(before.expectedPayloadDigest) ||
      (change.provider === "compute" &&
        (typeof before.ownershipMarker !== "string" ||
          !before.ownershipMarker.startsWith("Secure Gateway Studio ownership-token="))) ||
      (change.provider === "beyondcorp" && before.ownershipMarker !== null)
    ) {
      throw new ProviderExecutionError("generic-resource-ownership-checkpoint-invalid");
    }
    const expectedCreateParams: Record<string, string> = {
      requestId: before.createRequestId,
    };
    if (change.provider === "beyondcorp" && change.resource_type === "security_gateway") {
      expectedCreateParams.securityGatewayId = change.resource_name;
    } else if (change.provider === "beyondcorp" && change.resource_type === "application") {
      expectedCreateParams.applicationId = change.resource_name;
    }
    if (before.expectedParamsDigest !== canonicalDigestSync(expectedCreateParams)) {
      throw new ProviderExecutionError("generic-resource-ownership-checkpoint-invalid");
    }
    if (change.provider === "beyondcorp") {
      const expectedPayload = change.resource_type === "security_gateway"
        ? {
          displayName: change.resource_name,
          serviceDiscovery: {},
          logging: {},
        }
        : change.resource_type === "application"
        ? {
          displayName: change.resource_name,
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
      if (
        expectedPayload === null ||
        before.expectedPayloadDigest !== canonicalDigestSync(expectedPayload) ||
        before.providerIdentityField !== "createTime" ||
        typeof before.providerIdentity !== "string" ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/
          .test(before.providerIdentity)
      ) {
        throw new ProviderExecutionError("generic-resource-ownership-checkpoint-invalid");
      }
    }
    if (before.phase === "prepared" || before.phase === "rejected") return "deleted";
    if (before.phase !== "sending" && before.phase !== "applied") {
      throw new ProviderExecutionError("generic-resource-ownership-checkpoint-invalid");
    }
    const live = await this.readGenericCreatedResource(
      change,
      expectedUrl,
      before.ownershipMarker,
    );
    if (live.status === 404) {
      if (before.phase === "sending") {
        // A request with an unknown outcome can become visible later. Keep its
        // durable claim until an operator resolves the ambiguity.
        throw new ProviderExecutionError("generic-resource-provider-response-ambiguous");
      }
      return "deleted";
    }
    const appliedIdentityMatches = before.phase === "applied" &&
      live.identity !== null &&
      before.providerIdentityField === live.identity.field &&
      before.providerIdentity === live.identity.value;
    const markerProvesInflightCreate = before.phase === "sending" &&
      before.ownershipMarker !== null && live.identity !== null;
    if (!appliedIdentityMatches && !markerProvesInflightCreate) return "skipped";

    if (`${change.provider}:${change.resource_type}` === "beyondcorp:security_gateway") {
      const inventory = await this.gatewayApplicationInventory(expectedUrl);
      if (inventory === "missing") return "deleted";
      if (inventory === "nonempty") return "skipped";
    }
    await this.deleteExact(expectedUrl, { requestId });
    return "deleted";
  }

  private async restoreManagedCloudNat(
    before: Extract<PersistedBeforeImage, { kind: "router_nats" }>,
    requestId: string,
  ): Promise<void> {
    if (!isCompatibleCloudNat(before.managedNat, before.managedNat)) {
      // 0.2.0 checkpoints did not record managed-after. Replacing the whole
      // Router NAT array would erase changes made by another administrator.
      throw new ProviderExecutionError("cloud-nat-managed-state-missing");
    }
    const current = await this.requestWithStatus("GET", before.routerUrl, {
      acceptedStatuses: [404],
    });
    if (current.status === 404) return;
    if (!Array.isArray(current.payload.nats)) {
      throw new ProviderExecutionError("cloud-nat-current-state-invalid");
    }
    const currentNats = current.payload.nats as unknown[];
    const named = currentNats.filter(
      (nat) =>
        typeof nat === "object" && nat !== null &&
        (nat as { name?: unknown }).name === before.managedNat.name,
    );
    if (named.length === 0) return;
    if (
      named.length !== 1 ||
      !isCompatibleCloudNat(named[0], before.managedNat)
    ) {
      throw new ProviderExecutionError("cloud-nat-managed-state-changed");
    }
    await this.request("PATCH", before.routerUrl, {
      params: { requestId },
      body: {
        nats: currentNats.filter((nat) => nat !== named[0]),
      },
    });
  }

  private async destroyNamedOwnedResource(
    change: ResourceChange,
    spec: DeploymentSpec,
    before: NamedResourceOwnershipCheckpoint,
  ): Promise<"deleted" | "skipped"> {
    const phase: SharedMutationPhase = before.protocolVersion === 1 &&
        (before.phase === "prepared" || before.phase === "sending" ||
          before.phase === "rejected" || before.phase === "applied")
      ? before.phase
      : "sending";
    if (phase === "prepared" || phase === "rejected") return "deleted";
    const token = before.ownershipToken;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(token)) {
      throw new ProviderExecutionError("named-resource-ownership-token-invalid");
    }

    const kind = `${change.provider}:${change.resource_type}`;
    const expectedUrls: Record<NamedResourceOwnershipCheckpoint["resourceKind"], string> = {
      iam_service_account:
        `https://iam.googleapis.com/v1/projects/${spec.project_id}/serviceAccounts/` +
        encodeURIComponent(
          `${change.resource_name}@${spec.project_id}.iam.gserviceaccount.com`,
        ),
      dns_private_zone:
        `https://dns.googleapis.com/dns/v1/projects/${spec.project_id}` +
        `/managedZones/${change.resource_name}`,
      dns_record_set:
        `https://dns.googleapis.com/dns/v1/projects/${spec.project_id}` +
        `/managedZones/${spec.name}-zone`,
      secretmanager_secret:
        `https://secretmanager.googleapis.com/v1/projects/${spec.project_id}` +
        `/secrets/${change.resource_name}`,
    };
    const expectedKinds: Record<NamedResourceOwnershipCheckpoint["resourceKind"], string> = {
      iam_service_account: "iam:service_account",
      dns_private_zone: "dns:private_zone",
      dns_record_set: "dns:record_set",
      secretmanager_secret: "secretmanager:secret",
    };
    if (
      before.resourceUrl !== expectedUrls[before.resourceKind] ||
      kind !== expectedKinds[before.resourceKind]
    ) {
      throw new ProviderExecutionError("named-resource-ownership-target-mismatch");
    }

    if (before.resourceKind === "dns_record_set") {
      const fqdn = `${spec.private_hostname}.`;
      const markerName = `_sgs-owner.${fqdn}`;
      const marker = `"sgs-owner=${token}"`;
      if (
        before.recordName !== fqdn || before.markerName !== markerName ||
        before.marker !== marker || before.recordAddress === ""
      ) {
        throw new ProviderExecutionError("dns-record-ownership-checkpoint-invalid");
      }
      const record = await this.requestWithStatus(
        "GET",
        `${before.resourceUrl}/rrsets/${encodeURIComponent(fqdn)}/A`,
        { acceptedStatuses: [404] },
      );
      const owner = await this.requestWithStatus(
        "GET",
        `${before.resourceUrl}/rrsets/${encodeURIComponent(markerName)}/TXT`,
        { acceptedStatuses: [404] },
      );
      if (record.status === 404 && owner.status === 404) {
        if (phase === "sending") {
          throw new ProviderExecutionError("named-resource-provider-response-ambiguous");
        }
        return "deleted";
      }
      const ownerMatches = owner.status !== 404 &&
        owner.payload.name === markerName && owner.payload.type === "TXT" &&
        owner.payload.ttl === 60 && Array.isArray(owner.payload.rrdatas) &&
        owner.payload.rrdatas.length === 1 && owner.payload.rrdatas[0] === marker;
      if (!ownerMatches) return "skipped";
      if (record.status === 404) {
        await this.request("POST", `${before.resourceUrl}/changes`, {
          body: {
            deletions: [{ name: markerName, type: "TXT", ttl: 60, rrdatas: [marker] }],
          },
        });
        return "deleted";
      }
      const recordMatches = record.payload.name === fqdn && record.payload.type === "A" &&
        record.payload.ttl === 60 && Array.isArray(record.payload.rrdatas) &&
        record.payload.rrdatas.length === 1 &&
        record.payload.rrdatas[0] === before.recordAddress;
      if (!recordMatches) return "skipped";
      await this.request("POST", `${before.resourceUrl}/changes`, {
        body: {
          deletions: [
            { name: fqdn, type: "A", ttl: 60, rrdatas: [before.recordAddress] },
            { name: markerName, type: "TXT", ttl: 60, rrdatas: [marker] },
          ],
        },
      });
      return "deleted";
    }

    const current = await this.requestWithStatus("GET", before.resourceUrl, {
      acceptedStatuses: [404],
    });
    if (current.status === 404) {
      if (phase === "sending") {
        throw new ProviderExecutionError("named-resource-provider-response-ambiguous");
      }
      return "deleted";
    }
    let owned = false;
    if (before.resourceKind === "secretmanager_secret") {
      const labels = current.payload.labels;
      owned = before.marker === token && typeof labels === "object" && labels !== null &&
        !Array.isArray(labels) &&
        (labels as Record<string, unknown>)["sgs-owner-token"] === token;
    } else {
      const expectedMarker = `Secure Gateway Studio ownership-token=${token}`;
      owned = before.marker === expectedMarker && current.payload.description === expectedMarker;
    }
    if (!owned) return "skipped";
    await this.deleteExact(before.resourceUrl);
    return "deleted";
  }

  private async recoverSecretVersionForCompensation(
    before: Extract<PersistedBeforeImage, { kind: "secret_version" }>,
    projectId: string,
    secretName: string,
  ): Promise<string | null> {
    if (
      typeof before.payloadDigest !== "string" || before.payloadDigest === "" ||
      !Array.isArray(before.existingVersionNames) ||
      before.existingVersionNames.some((name) => typeof name !== "string") ||
      typeof before.ownershipToken !== "string" || before.ownershipToken === ""
    ) {
      throw new ProviderExecutionError("secret-version-recovery-metadata-missing");
    }
    const baseline = new Set(before.existingVersionNames.map((name) =>
      canonicalSecretVersionUrl(name, projectId, secretName)
    ));
    const candidates: string[] = [];
    let pageToken: string | undefined;
    const seenTokens = new Set<string>();
    for (let page = 0; page < 100; page += 1) {
      const response = await this.requestWithStatus("GET", `${before.secretUrl}/versions`, {
        params: {
          pageSize: 100,
          ...(pageToken === undefined ? {} : { pageToken }),
        },
        acceptedStatuses: [404],
      });
      if (response.status === 404) return null;
      const versions = response.payload.versions;
      if (versions !== undefined && !Array.isArray(versions)) {
        throw new ProviderExecutionError("secret-version-list-invalid");
      }
      for (const value of versions ?? []) {
        if (typeof value !== "object" || value === null) {
          throw new ProviderExecutionError("secret-version-list-invalid");
        }
        const item = value as { name?: unknown; state?: unknown };
        if (typeof item.name !== "string" || typeof item.state !== "string") {
          throw new ProviderExecutionError("secret-version-list-invalid");
        }
        const name = canonicalSecretVersionUrl(item.name, projectId, secretName);
        if (item.state !== "ENABLED" || baseline.has(name)) continue;
        const accessed = await this.requestWithStatus("GET", `${name}:access`);
        const data = (accessed.payload.payload as { data?: unknown } | undefined)?.data;
        if (typeof data !== "string") {
          throw new ProviderExecutionError("secret-version-access-payload-invalid");
        }
        if (
          secretPayloadDigest(data) === before.payloadDigest &&
          secretPayloadOwnershipToken(data) === before.ownershipToken
        ) candidates.push(name);
      }
      const next = response.payload.nextPageToken;
      if (next === undefined || next === "") break;
      if (typeof next !== "string" || seenTokens.has(next)) {
        throw new ProviderExecutionError("secret-version-pagination-invalid");
      }
      seenTokens.add(next);
      pageToken = next;
      if (page === 99) {
        throw new ProviderExecutionError("secret-version-pagination-exhausted");
      }
    }
    // SecretVersion list is eventually consistent. An empty page immediately
    // after a lost addVersion response is not proof that no version exists.
    // Retain the durable claim and retry; never release it as a successful
    // no-op while the private key may become visible later.
    if (candidates.length === 0) {
      throw new ProviderExecutionError("secret-version-recovery-not-found");
    }
    if (candidates.length > 1) {
      throw new ProviderExecutionError("secret-version-recovery-ambiguous");
    }
    return candidates[0]!;
  }

  private async restoreSecretVersion(
    before: Extract<PersistedBeforeImage, { kind: "secret_version" }>,
    finalAction: "disable" | "destroy" = "disable",
    expectedProjectId?: string,
    expectedSecretName?: string,
  ): Promise<void> {
    const identity = secretVersionIdentityFromUrl(before.secretUrl);
    const projectId = expectedProjectId ?? identity?.projectId;
    const secretName = expectedSecretName ?? identity?.secretName;
    if (
      identity === null || projectId === undefined || secretName === undefined ||
      identity.projectId !== projectId || identity.secretName !== secretName ||
      before.secretUrl !==
        `${SECRET_MANAGER_API}/projects/${projectId}/secrets/${secretName}`
    ) {
      throw new ProviderExecutionError("secret-version-secret-url-invalid");
    }
    const phase = secretVersionPhase(before);
    if (phase === "prepared" || phase === "rejected") return;

    let versionName: unknown = before.versionName;
    if (phase === "sending") {
      versionName = await this.recoverSecretVersionForCompensation(
        before,
        projectId,
        secretName,
      );
      if (versionName === null) return;
    }
    if (typeof versionName !== "string" || versionName === "") {
      throw new ProviderExecutionError("secret-version-name-missing-for-rollback");
    }
    const versionUrl = canonicalSecretVersionUrl(versionName, projectId, secretName);
    let version = await this.requestWithStatus("GET", versionUrl, {
      acceptedStatuses: [404],
    });
    const finalizeVersion = async (): Promise<void> => {
      if (
        version.status === 404 || version.payload.state === "DESTROYED" ||
        (finalAction === "disable" && version.payload.state === "DISABLED")
      ) return;
      const action = await this.requestWithStatus(
        "POST",
        `${versionUrl}:${finalAction}`,
        { body: {}, acceptedStatuses: [404, 409] },
      );
      if (action.status === 409) {
        version = await this.requestWithStatus("GET", versionUrl, {
          acceptedStatuses: [404],
        });
        const expectedState = finalAction === "destroy" ? "DESTROYED" : "DISABLED";
        if (version.status !== 404 && version.payload.state !== expectedState) {
          throw new ProviderExecutionError(`secret-version-${finalAction}-reconciliation-failed`);
        }
      }
    };

    if (phase === "sending" || phase === "version_added") {
      await finalizeVersion();
      return;
    }
    if (
      before.phase === undefined &&
      (before.managedAfterAliases === undefined || before.managedAfterLabels === undefined)
    ) {
      throw new ProviderExecutionError("secret-version-managed-state-missing");
    }

    if (
      before.managedAfterAliases === undefined ||
      before.managedAfterLabels === undefined
    ) {
      throw new ProviderExecutionError("secret-version-managed-state-missing");
    }
    // Restore aliases/labels before disabling or destroying the version. This
    // keeps `active` from ever pointing at a terminal version. A retry after
    // an older destroy-first worker is also safe: Secret Manager may have
    // removed `active`, which is treated as our managed-after value only when
    // the exact recorded version is already DESTROYED.
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const currentSecret = await this.requestWithStatus("GET", before.secretUrl, {
        acceptedStatuses: [404],
      });
      if (currentSecret.status === 404) return;
      if (typeof currentSecret.payload.etag !== "string" || currentSecret.payload.etag === "") {
        throw new ProviderExecutionError("secret-version-current-etag-missing");
      }
      const aliases = strictSecretStringMap(currentSecret.payload.versionAliases);
      const labels = strictSecretStringMap(currentSecret.payload.labels);
      const restoredAliases = restoreManagedStringMapStrict(
        before.previousAliases,
        before.managedAfterAliases,
        aliases,
        {
          allowMissingManagedAfterKey:
            version.status !== 404 && version.payload.state === "DESTROYED"
              ? "active"
              : undefined,
        },
      );
      const restoredLabels = restoreManagedStringMapStrict(
        before.previousLabels,
        before.managedAfterLabels,
        labels,
      );
      if (
        canonicalJson(restoredAliases) === canonicalJson(aliases) &&
        canonicalJson(restoredLabels) === canonicalJson(labels)
      ) break;
      try {
        await this.request("PATCH", before.secretUrl, {
          params: { updateMask: "versionAliases,labels" },
          body: {
            etag: currentSecret.payload.etag,
            labels: restoredLabels,
            versionAliases: restoredAliases,
          },
        });
        break;
      } catch (error) {
        if (!isSecretEtagPrecondition(error) || attempt === 2) throw error;
        await new Promise((resolve) => setTimeout(resolve, 25 * (2 ** attempt)));
      }
    }
    await finalizeVersion();
  }

  private async revokePrivateCaCertificate(
    before: Extract<PersistedBeforeImage, { kind: "privateca_certificate" }>,
    requestId: string,
  ): Promise<"revoked" | "absent" | "not_owned"> {
    const url = `https://privateca.googleapis.com/v1/${before.certificateName}`;
    const current = await this.requestWithStatus("GET", url, {
      acceptedStatuses: [404],
    });
    const phase: PrivateCaMutationPhase = before.protocolVersion === 1 &&
        (before.phase === "prepared" || before.phase === "sending" ||
          before.phase === "rejected" || before.phase === "applied")
      ? before.phase
      : "sending";
    if (current.status === 404) {
      if (phase === "sending") {
        // Certificate Authority Service visibility is not immediate. A create
        // accepted before response loss can still return 404 here, so the
        // ownership claim must survive until a later exact reconciliation.
        throw new ProviderExecutionError("privateca-certificate-outcome-ambiguous");
      }
      return "absent";
    }
    if (phase === "prepared" || phase === "rejected") {
      // The durable protocol proves no create send was attempted. A live
      // deterministic-name certificate therefore belongs to somebody else.
      return "not_owned";
    }
    if (current.payload.name !== before.certificateName) {
      throw new ProviderExecutionError("privateca-certificate-identity-mismatch");
    }
    if (
      typeof before.csrDigest !== "string" || before.csrDigest === "" ||
      typeof before.authorityName !== "string" || before.authorityName === "" ||
      typeof current.payload.pemCsr !== "string" || current.payload.pemCsr === "" ||
      typeof current.payload.issuerCertificateAuthority !== "string"
    ) {
      throw new ProviderExecutionError("privateca-certificate-ownership-unverified");
    }
    if (
      canonicalDigestSync(current.payload.pemCsr) !== before.csrDigest ||
      current.payload.issuerCertificateAuthority !== before.authorityName
    ) {
      // The deterministic name is occupied by somebody else's certificate.
      // This is a proven non-owned conflict, not a resource to compensate.
      return "not_owned";
    }
    if (current.payload.revocationDetails !== undefined) return "revoked";
    const response = await this.requestWithStatus("POST", `${url}:revoke`, {
      body: { reason: "CESSATION_OF_OPERATION", requestId },
      acceptedStatuses: [404, 409],
    });
    if (response.status === 409) {
      const reconciled = await this.requestWithStatus("GET", url, {
        acceptedStatuses: [404],
      });
      if (reconciled.status !== 404 && reconciled.payload.revocationDetails === undefined) {
        throw new ProviderExecutionError("privateca-certificate-revoke-reconciliation-failed");
      }
    }
    return "revoked";
  }

  private async applyUnchecked(
    change: ResourceChange,
    spec: DeploymentSpec,
    requestId: string,
    runId: string | undefined,
    beforeImage?: unknown,
  ): Promise<void> {
    const kind = `${change.provider}:${change.resource_type}`;
    if (change.provider === "chromepolicy") {
      await this.assertTargetOuIsNonRoot(spec);
    }
    if (this.genericCreatedResourceUrl(change, spec) !== null) {
      return this.applyGenericCreatedResource(
        change,
        spec,
        requestId,
        beforeImage,
      );
    }
    switch (kind) {
      case "serviceusage:project_services":
        return this.enableServices(spec);
      case "compute:network":
        return applyPathA(this.pathAContext(requestId, beforeImage), change, spec);
      case "compute:subnetwork":
      case "compute:router":
      case "compute:cloud_nat":
      case "iam:service_account":
      case "compute:internal_address":
      case "compute:firewall_rule":
      case "dns:private_zone":
      case "dns:record_set":
      case "secretmanager:secret_iam":
      case "compute:instance":
      case "compute:instance_template":
      case "secretmanager:secret":
      case "secretmanager:secret_version":
      case "local:root_certificate_artifact":
        return applyPathA(this.pathAContext(requestId, beforeImage), change, spec);
      case "privateca:certificate":
        return this.applyPrivateCaCertificate(change, spec, runId, requestId);
      case "accesscontextmanager:access_level":
        // Reused, never created. The planner marks it must-exist, so a missing
        // one is a conflict at plan time rather than an apply failure.
        return;
      case "beyondcorp:security_gateway":
        return this.createGateway(change, spec, requestId);
      case "beyondcorp:gateway_iam":
        return this.setGatewayIam(change, spec);
      case "cloudresourcemanager:project_iam":
        return this.setUpstreamAccess(change, spec);
      case "beyondcorp:application":
        return this.createApplication(change, spec, requestId);
      case "beyondcorp:application_iam":
        return this.setApplicationIam(change, spec);
      case "chromepolicy:extension_install":
        return this.setChromeInstall(change, spec);
      case "chromepolicy:extension_configuration":
        return this.setChromeConfiguration(change, spec);
      case "chromepolicy:service_discovery_proxy":
        return this.setServiceDiscoveryProxy(change, spec);
      default:
        // Everything else belongs to the Nginx offload path.
        return applyPathA(this.pathAContext(requestId, beforeImage), change, spec);
    }
  }

  private async request(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      body?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<Record<string, unknown>> {
    return (await this.requestWithStatus(method, url, options)).payload;
  }

  private async applyPrivateCaCertificate(
    change: ResourceChange,
    spec: DeploymentSpec,
    runId: string | undefined,
    requestId: string,
  ): Promise<void> {
    if (
      runId === undefined ||
      spec.certificate_strategy !== "enterprise_ca" ||
      !spec.ca_pool ||
      !spec.ca_name
    ) {
      throw new ProviderExecutionError("privateca-certificate-context-invalid");
    }
    const certificateName =
      `${spec.ca_pool}/certificates/${enterpriseCertificateId(spec.name, runId)}`;
    const checkpoint = async (
      csrPem: string,
      phase: PrivateCaMutationPhase = "prepared",
    ): Promise<void> => {
      if (typeof csrPem !== "string" || csrPem === "") {
        throw new ProviderExecutionError("privateca-csr-checkpoint-invalid");
      }
      await this.captureBefore(change, {
        kind: "privateca_certificate",
        protocolVersion: 1,
        phase,
        certificateName,
        authorityName: spec.ca_name as string,
        csrDigest: canonicalDigestSync(csrPem),
        csrPem,
      } satisfies PersistedBeforeImage);
    };

    const persisted = this.before.get(this.key(change));
    const ownership = isBeforeImage(persisted, "privateca_certificate")
      ? persisted
      : undefined;

    if (this.certificate !== undefined) {
      if (this.certificate.issuerResourceName !== certificateName) {
        throw new ProviderExecutionError("privateca-certificate-session-mismatch");
      }
      if (
        ownership === undefined || ownership.certificateName !== certificateName ||
        ownership.authorityName !== spec.ca_name ||
        typeof ownership.csrDigest !== "string" || ownership.csrDigest === "" ||
        ownership.phase !== "applied"
      ) {
        throw new ProviderExecutionError("privateca-certificate-ownership-checkpoint-missing");
      }
      const existing = await this.requestWithStatus(
        "GET",
        `https://privateca.googleapis.com/v1/${certificateName}`,
        { acceptedStatuses: [404] },
      );
      if (existing.status === 404 || existing.payload.revocationDetails !== undefined) {
        throw new ProviderExecutionError("privateca-certificate-unavailable");
      }
      if (
        existing.payload.name !== certificateName ||
        typeof existing.payload.pemCsr !== "string" ||
        canonicalDigestSync(existing.payload.pemCsr) !== ownership.csrDigest ||
        existing.payload.issuerCertificateAuthority !== ownership.authorityName
      ) {
        throw new ProviderExecutionError("privateca-certificate-session-ownership-mismatch");
      }
      return;
    }

    if (this.issueEnterpriseCertificate === undefined) {
      throw new ProviderExecutionError("privateca-certificate-issuer-unavailable");
    }
    const issued = await this.issueEnterpriseCertificate(runId, spec, requestId, checkpoint);
    if (issued.issuerResourceName !== certificateName) {
      throw new ProviderExecutionError("privateca-certificate-identity-mismatch");
    }
    const sent = this.before.get(this.key(change));
    if (
      !isBeforeImage(sent, "privateca_certificate") ||
      sent.protocolVersion !== 1 || sent.phase !== "sending" ||
      typeof sent.csrPem !== "string" || sent.csrPem === ""
    ) {
      throw new ProviderExecutionError("privateca-certificate-sending-checkpoint-missing");
    }
    await checkpoint(sent.csrPem, "applied");
    const captured = this.before.get(this.key(change));
    if (
      !isBeforeImage(captured, "privateca_certificate") ||
      captured.certificateName !== certificateName ||
      captured.authorityName !== spec.ca_name ||
      typeof captured.csrDigest !== "string" || captured.csrDigest === "" ||
      captured.protocolVersion !== 1 || captured.phase !== "applied"
    ) {
      throw new ProviderExecutionError("privateca-certificate-ownership-checkpoint-missing");
    }
    this.certificate = issued;
  }

  private async requestWithStatus(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      body?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<TransportResponse> {
    return this.transport.requestJson(method, url, {
      params: options.params,
      jsonBody: options.body,
      acceptedStatuses: options.acceptedStatuses,
    });
  }

  private async gatewayApplicationInventory(
    gatewayUrl: string,
  ): Promise<"missing" | "empty" | "nonempty"> {
    const apiPrefix = "https://beyondcorp.googleapis.com/v1/";
    if (!gatewayUrl.startsWith(apiPrefix)) {
      throw new ProviderExecutionError("teardown-gateway-applications-url-invalid");
    }
    const applicationNamePrefix =
      `${gatewayUrl.slice(apiPrefix.length)}/applications/`;
    const collectionUrl = `${gatewayUrl}/applications`;
    let pageToken: string | undefined;
    const seenTokens = new Set<string>();
    for (let page = 0; page < 100; page += 1) {
      const response = await this.requestWithStatus("GET", collectionUrl, {
        params: {
          pageSize: 100,
          ...(pageToken === undefined ? {} : { pageToken }),
        },
        acceptedStatuses: [404],
      });
      if (response.status === 404) return "missing";
      const unreachable = response.payload.unreachable ?? [];
      if (
        !Array.isArray(unreachable) ||
        unreachable.some((location) => typeof location !== "string" || location === "")
      ) {
        throw new ProviderExecutionError("teardown-gateway-applications-invalid");
      }
      if (unreachable.length > 0) {
        throw new ProviderExecutionError("teardown-gateway-applications-unreachable");
      }
      const applications = response.payload.applications ?? [];
      if (!Array.isArray(applications)) {
        throw new ProviderExecutionError("teardown-gateway-applications-invalid");
      }
      for (const application of applications) {
        const name = typeof application === "object" && application !== null
          ? (application as { name?: unknown }).name
          : undefined;
        const suffix = typeof name === "string" && name.startsWith(applicationNamePrefix)
          ? name.slice(applicationNamePrefix.length)
          : "";
        if (suffix === "" || suffix.includes("/")) {
          throw new ProviderExecutionError("teardown-gateway-applications-invalid");
        }
      }
      if (applications.length > 0) return "nonempty";

      if (!("nextPageToken" in response.payload) || response.payload.nextPageToken === "") {
        return "empty";
      }
      const nextToken = response.payload.nextPageToken;
      if (
        typeof nextToken !== "string" || nextToken.trim() === "" ||
        seenTokens.has(nextToken)
      ) {
        throw new ProviderExecutionError(
          "teardown-gateway-applications-pagination-invalid",
        );
      }
      seenTokens.add(nextToken);
      pageToken = nextToken;
    }
    throw new ProviderExecutionError(
      "teardown-gateway-applications-pagination-limit-exceeded",
    );
  }

  private async workspaceRequest(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      body?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<Record<string, unknown>> {
    return (
      await this.workspaceTransport.requestJson(method, url, {
        params: options.params,
        jsonBody: options.body,
        acceptedStatuses: options.acceptedStatuses,
      })
    ).payload;
  }

  private async assertTargetOuIsNonRoot(spec: DeploymentSpec): Promise<void> {
    const payload = await this.workspaceRequest(
      "GET",
      `https://admin.googleapis.com/admin/directory/v1/customer/${spec.customer_id}` +
        `/orgunits/${encodeURIComponent(`id:${spec.target_ou_id}`)}`,
    );
    const rawId = payload.orgUnitId;
    const path = payload.orgUnitPath;
    if (
      typeof rawId !== "string" || rawId.replace(/^id:/, "") !== spec.target_ou_id ||
      typeof path !== "string" || !path.startsWith("/") || path === "/"
    ) {
      throw new ProviderExecutionError("chrome-policy-target-ou-invalid");
    }
  }

  private gatewayResource(spec: DeploymentSpec): string {
    return (
      `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
      `/locations/global/securityGateways/${spec.gateway_id}`
    );
  }

  private key(change: ResourceChange): string {
    return `${change.provider}:${change.resource_type}:${change.resource_name}`;
  }

  private async enableServices(spec: DeploymentSpec): Promise<void> {
    const services =
      spec.backend_kind === "direct_https" ? DIRECT_HTTPS_APIS : REQUIRED_APIS;
    await this.request(
      "POST",
      `https://serviceusage.googleapis.com/v1/projects/${spec.project_id}/services:batchEnable`,
      { body: { serviceIds: [...services].sort() } },
    );
  }

  private async waitForDelegatingServiceAccount(
    spec: DeploymentSpec,
    transport: Transport = this.transport,
  ): Promise<string> {
    const parent =
      `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
      "/locations/global/securityGateways";
    const url = `${parent}/${spec.gateway_id}`;
    for (let attempt = 0; attempt < 30; attempt++) {
      const response = await transport.requestJson("GET", url, {
        // BeyondCorp can be briefly eventually-consistent after create.
        acceptedStatuses: [404],
      });
      const account = response.payload.delegatingServiceAccount;
      if (response.status !== 404 && typeof account === "string" && account.length > 0) {
        this.gatewayServiceAccount = account;
        return account;
      }
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
    throw new ProviderExecutionError("gateway-missing-delegating-account");
  }

  private async createGateway(
    change: ResourceChange,
    spec: DeploymentSpec,
    requestId: string,
    transport: Transport = this.transport,
  ): Promise<void> {
    const parent =
      `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
      "/locations/global/securityGateways";
    await transport.requestJson("POST", parent, {
      params: { securityGatewayId: change.resource_name, requestId },
      // The official Private Web Apps task guide prescribes this empty message
      // as the Service Discovery enablement marker for both REST and gcloud.
      jsonBody: {
        displayName: change.resource_name,
        serviceDiscovery: {},
        // Current SecurityGateway LoggingConfig is an empty enablement marker.
        logging: {},
      },
    });
    // Wait until the delegating service account is assigned by the service
    await this.waitForDelegatingServiceAccount(spec, transport);
  }

  /**
   * Read-modify-write an IAM policy, preserving the etag and every binding the
   * deployment does not own.
   */
  private async setIam(
    change: ResourceChange,
    options: {
      getUrl: string;
      setUrl: string;
      role: string;
      members: string[];
      condition?: IamBinding["condition"];
      getMethod?: "GET" | "POST";
    },
  ): Promise<void> {
    const persisted = this.before.get(this.key(change));
    let persistedIam: Extract<PersistedBeforeImage, { kind: "iam" }> | undefined;
    if (persisted !== undefined) {
      if (!isBeforeImage(persisted, "iam")) {
        throw new ProviderExecutionError("iam-retry-state-invalid");
      }
      persistedIam = persisted;
      if (
        persistedIam.getUrl !== options.getUrl ||
        persistedIam.getMethod !== (options.getMethod ?? "GET") ||
        persistedIam.setUrl !== options.setUrl
      ) {
        throw new ProviderExecutionError("iam-retry-identity-mismatch");
      }
      const phase = sharedMutationPhase(persistedIam);
      if (phase === "sending") {
        // There is no provider requestId for IAM SET. Equality with the target
        // after a restart could be a coincidental administrator write, so it
        // is never evidence that SGS owns the delta.
        throw new ProviderExecutionError("iam-mutation-outcome-ambiguous");
      }
      if (
        phase === "rejected" &&
        (persistedIam.rejectionStatus !== 409 || persistedIam.rejectionReason !== "ABORTED")
      ) {
        throw new ProviderExecutionError("iam-mutation-definitively-rejected");
      }
      if (phase === "applied") return;
    }

    const getMethod = options.getMethod ?? "GET";
    // IAM SET has no provider requestId. A confirmed 409/ABORTED proves the
    // write was not applied, so it is the only safe retry: fetch the fresh v3
    // policy, merge again, and durably replace the prepared delta before the
    // next send. 5xx/timeout/transport loss leave `sending` untouched.
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const rawPolicy = (await this.request(getMethod, options.getUrl, {
        params:
          getMethod === "GET"
            ? { "options.requestedPolicyVersion": 3 }
            : undefined,
        body:
          getMethod === "POST"
            ? { options: { requestedPolicyVersion: 3 } }
            : undefined,
      })) as IamPolicy;
      if (typeof rawPolicy.etag !== "string" || rawPolicy.etag.trim() === "") {
        throw new ProviderExecutionError("iam-policy-etag-missing");
      }
      let policy: IamPolicy;
      try {
        policy = validatedIamPolicy(rawPolicy) as IamPolicy;
      } catch {
        throw new ProviderExecutionError("iam-policy-bindings-invalid");
      }
      const targetBindings = (policy.bindings ?? []).filter(
        (existing) =>
          existing.role === options.role &&
          sameIamCondition(existing.condition, options.condition),
      );
      const bindings: IamBinding[] = (policy.bindings ?? []).filter(
        (existing) =>
          existing.role !== options.role ||
          !sameIamCondition(existing.condition, options.condition),
      );
      const members = [
        ...new Set([
          ...targetBindings.flatMap((binding) => binding.members),
          ...options.members,
        ]),
      ];
      const binding: IamBinding = { role: options.role, members };
      if (options.condition) binding.condition = options.condition;
      bindings.push(binding);
      let updated: IamPolicy;
      try {
        updated = validatedIamPolicy({ ...policy, bindings, version: 3 }) as IamPolicy;
      } catch {
        throw new ProviderExecutionError("iam-policy-bindings-invalid");
      }
      const checkpoint: Extract<PersistedBeforeImage, { kind: "iam" }> = {
        kind: "iam",
        phase: "prepared",
        getUrl: options.getUrl,
        getMethod,
        setUrl: options.setUrl,
        policy: structuredClone(policy),
        afterPolicy: structuredClone(updated),
      };
      await this.captureBefore(change, checkpoint);
      await this.captureBefore(change, { ...checkpoint, phase: "sending" });
      try {
        await this.request("POST", options.setUrl, { body: { policy: updated } });
      } catch (error) {
        if (isConfirmedIamEtagConflict(error)) {
          await this.captureBefore(change, {
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
          await this.captureBefore(change, {
            ...checkpoint,
            phase: "rejected",
            rejectionStatus: error.status,
          });
        }
        throw error;
      }
      await this.captureBefore(change, { ...checkpoint, phase: "applied" });
      return;
    }
    throw new ProviderExecutionError("iam-concurrent-update-limit");
  }

  private principalMembers(spec: DeploymentSpec): string[] {
    return spec.principals.map(iamMember);
  }

  private async setGatewayIam(change: ResourceChange, spec: DeploymentSpec): Promise<void> {
    const resource = this.gatewayResource(spec);
    await this.setIam(change, {
      getUrl: `${resource}:getIamPolicy`,
      setUrl: `${resource}:setIamPolicy`,
      role: "roles/beyondcorp.serviceDiscoveryUser",
      members: this.principalMembers(spec),
    });
    this.iamMutatedAt = Date.now();
  }

  private async setUpstreamAccess(
    change: ResourceChange,
    spec: DeploymentSpec,
  ): Promise<void> {
    if (this.gatewayServiceAccount === null) {
      await this.waitForDelegatingServiceAccount(spec);
    }
    // The binding belongs to the project owning the upstream VPC, which for a
    // cross-project upstream is not the deployment project.
    const resource =
      "https://cloudresourcemanager.googleapis.com/v1/projects/" +
      upstreamProjectId(spec);
    await this.setIam(change, {
      getUrl: `${resource}:getIamPolicy`,
      setUrl: `${resource}:setIamPolicy`,
      getMethod: "POST",
      role: "roles/beyondcorp.upstreamAccess",
      members: [`serviceAccount:${this.gatewayServiceAccount}`],
    });
  }

  private async createApplication(
    change: ResourceChange,
    spec: DeploymentSpec,
    requestId: string,
    transport: Transport = this.transport,
  ): Promise<void> {
    const parent = `${this.gatewayResource(spec)}/applications`;
    const upstream: Record<string, unknown> = {
      network: {
        name: `projects/${upstreamProjectId(spec)}/global/networks/${networkName(spec)}`,
      },
    };
    if (spec.backend_kind === "direct_https" && spec.application_egress_region) {
      upstream.egressPolicy = { regions: [spec.application_egress_region] };
    }
    await transport.requestJson("POST", parent, {
      params: { applicationId: change.resource_name, requestId },
      jsonBody: {
        displayName: change.resource_name,
        endpointMatchers: [
          { hostname: applicationHostname(spec), ports: [applicationPort(spec)] },
        ],
        upstreams: [upstream],
      },
    });
  }

  private async setApplicationIam(
    change: ResourceChange,
    spec: DeploymentSpec,
  ): Promise<void> {
    const resource = `${this.gatewayResource(spec)}/applications/${spec.name}-app`;
    const condition = await this.applicationIamCondition(spec);
    await this.setIam(change, {
      getUrl: `${resource}:getIamPolicy`,
      setUrl: `${resource}:setIamPolicy`,
      role: "roles/beyondcorp.sgApplicationUser",
      members: this.principalMembers(spec),
      condition,
    });
    this.iamMutatedAt = Date.now();
  }

  private async applicationIamCondition(
    spec: DeploymentSpec,
  ): Promise<IamBinding["condition"] | undefined> {
    let level = spec.managed_chrome_access_level;
    if (level && level.startsWith("AUTO_CREATE_")) {
      const kind = level.includes("BROWSER") ? "browser" : level.includes("ANY") ? "any" : "profile";
      level = await ensureManagedChromeAccessLevel(
        this.transport,
        spec.project_id,
        kind,
        this.accessPolicyId,
      );
    }
    return level && level !== "NONE"
      ? {
          title: "Managed Chrome required",
          description: "Allow only profiles or browsers managed by this enterprise",
          expression: `'${level}' in request.auth.access_levels`,
        }
      : undefined;
  }

  // -- Chrome Policy ----------------------------------------------------------

  private async chromeSchema(
    spec: DeploymentSpec,
    schemaName: string,
  ): Promise<Record<string, unknown>> {
    return this.workspaceRequest(
      "GET",
      `https://chromepolicy.googleapis.com/v1/customers/${spec.customer_id}` +
        `/policySchemas/${schemaName}`,
    );
  }

  /**
   * Refuse to write a field the live schema does not advertise.
   *
   * Chrome Policy schemas change. Assuming a field would write a policy that
   * silently does nothing; this turns that into a refusal.
   */
  private assertSchemaField(schema: Record<string, unknown>, field: string): void {
    const definition = schema.definition as
      | { messageType?: { field?: { name?: string }[] }[] }
      | undefined;
    const fields = (definition?.messageType ?? []).flatMap(
      (message) => message.field ?? [],
    );
    if (!fields.some((entry) => entry.name === field)) {
      throw new ProviderExecutionError(`chrome-policy-schema-missing-${field}`);
    }
  }

  private async resolveChromePolicy(
    spec: DeploymentSpec,
    schemaName: string,
    appId: string | null,
  ): Promise<Record<string, unknown>> {
    const targetKey: Record<string, unknown> = {
      targetResource: `orgunits/${spec.target_ou_id}`,
    };
    if (appId !== null) targetKey.additionalTargetKeys = { app_id: `chrome:${appId}` };
    const policies: Record<string, unknown>[] = [];
    const seenPageTokens = new Set<string>();
    let pageToken: string | undefined;
    for (let page = 0; page < 20; page += 1) {
      const payload = await this.workspaceRequest(
        "POST",
        `https://chromepolicy.googleapis.com/v1/customers/${spec.customer_id}/policies:resolve`,
        {
          body: {
            policySchemaFilter: schemaName,
            policyTargetKey: targetKey,
            pageSize: 1_000,
            ...(pageToken === undefined ? {} : { pageToken }),
          },
        },
      );
      const resolvedPolicies = payload.resolvedPolicies === undefined
        ? []
        : payload.resolvedPolicies;
      if (!Array.isArray(resolvedPolicies)) {
        throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
      }
      for (const item of resolvedPolicies) {
        if (item === null || typeof item !== "object" || Array.isArray(item)) {
          throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
        }
        policies.push(item as Record<string, unknown>);
      }
      if (policies.length > 2_000) {
        throw new ProviderExecutionError("chrome-policy-resolve-item-limit");
      }
      const next = payload.nextPageToken;
      if (next === undefined || next === "") return { resolvedPolicies: policies };
      if (typeof next !== "string" || seenPageTokens.has(next)) {
        throw new ProviderExecutionError("chrome-policy-resolve-page-token-invalid");
      }
      seenPageTokens.add(next);
      if (page + 1 >= 20) {
        throw new ProviderExecutionError("chrome-policy-resolve-pagination-incomplete");
      }
      pageToken = next;
    }
    throw new ProviderExecutionError("chrome-policy-resolve-pagination-incomplete");
  }

  private directChromePolicyValues(
    spec: DeploymentSpec,
    resolved: Record<string, unknown>,
    schemaName: string,
    appId: string | null,
  ): Record<string, unknown> | null {
    const policies = resolved.resolvedPolicies;
    if (!Array.isArray(policies)) {
      throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
    }
    const expectedTarget: Record<string, unknown> = {
      targetResource: `orgunits/${spec.target_ou_id}`,
    };
    if (appId !== null) {
      expectedTarget.additionalTargetKeys = { app_id: `chrome:${appId}` };
    }
    const direct: Record<string, unknown>[] = [];
    for (const item of policies) {
      if (typeof item !== "object" || item === null || Array.isArray(item)) {
        throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
      }
      const policy = item as Record<string, unknown>;
      if (
        typeof policy.targetKey !== "object" || policy.targetKey === null ||
        Array.isArray(policy.targetKey) ||
        canonicalJson(policy.targetKey) !== canonicalJson(expectedTarget)
      ) {
        throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
      }
      const sourceResource = validatedChromePolicySourceResource(policy.sourceKey);
      const addedSourceResource = validatedChromePolicySourceResource(policy.addedSourceKey);
      if (
        (sourceResource !== null && !sourceResource.startsWith("orgunits/")) ||
        (addedSourceResource !== null && !addedSourceResource.startsWith("orgunits/"))
      ) {
        throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
      }
      const value = policy.value;
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
      }
      const typedValue = value as Record<string, unknown>;
      const fields = typedValue.value;
      if (
        typedValue.policySchema !== schemaName ||
        typeof fields !== "object" || fields === null || Array.isArray(fields)
      ) {
        throw new ProviderExecutionError("chrome-policy-resolve-response-invalid");
      }
      if (sourceResource === `orgunits/${spec.target_ou_id}`) {
        direct.push(structuredClone(fields as Record<string, unknown>));
      }
    }
    if (direct.length > 1) {
      throw new ProviderExecutionError("chrome-policy-direct-policy-duplicate");
    }
    return direct[0] ?? null;
  }

  private async batchModify(
    spec: DeploymentSpec,
    schemaName: string,
    field: string,
    value: unknown,
    appId: string | null,
  ): Promise<void> {
    const targetKey: Record<string, unknown> = {
      targetResource: `orgunits/${spec.target_ou_id}`,
    };
    if (appId !== null) targetKey.additionalTargetKeys = { app_id: `chrome:${appId}` };
    await this.workspaceRequest(
      "POST",
      `https://chromepolicy.googleapis.com/v1/customers/${spec.customer_id}` +
        "/policies/orgunits:batchModify",
      {
        body: {
          requests: [
            {
              policyTargetKey: targetKey,
              policyValue: { policySchema: schemaName, value: { [field]: value } },
              updateMask: field,
            },
          ],
        },
      },
    );
  }

  private async restoreChromePolicy(
    spec: DeploymentSpec,
    before: Extract<PersistedBeforeImage, { kind: "chrome_policy" }>,
  ): Promise<void> {
    const phase = sharedMutationPhase(before);
    if (phase === "prepared" || phase === "rejected") return;
    if (phase === "sending") {
      throw new ProviderExecutionError("chrome-policy-rollback-outcome-ambiguous");
    }
    if (
      before.managedAfter === undefined ||
      typeof before.managedAfter !== "object" ||
      before.managedAfter === null ||
      Array.isArray(before.managedAfter)
    ) {
      throw new ProviderExecutionError("chrome-policy-managed-state-missing");
    }
    const current = await this.resolveChromePolicy(spec, before.schemaName, before.appId);
    const currentDirect = this.directChromePolicyValues(
      spec,
      current,
      before.schemaName,
      before.appId,
    );
    if (canonicalJson(currentDirect) !== canonicalJson(before.managedAfter)) {
      // A different direct value means another administrator changed or
      // inherited this policy after Apply. Never erase that change.
      throw new ProviderExecutionError("chrome-policy-current-state-changed");
    }
    const targetKey: Record<string, unknown> = {
      targetResource: `orgunits/${spec.target_ou_id}`,
    };
    if (before.appId !== null) {
      targetKey.additionalTargetKeys = { app_id: `chrome:${before.appId}` };
    }
    const values = this.directChromePolicyValues(
      spec,
      before.previous,
      before.schemaName,
      before.appId,
    );
    const base =
      `https://chromepolicy.googleapis.com/v1/customers/${spec.customer_id}` +
      "/policies/orgunits";
    if (values !== null) {
      await this.workspaceRequest("POST", `${base}:batchModify`, {
        body: {
          requests: [
            {
              policyTargetKey: targetKey,
              policyValue: { policySchema: before.schemaName, value: values },
              updateMask: Object.keys(values).sort().join(","),
            },
          ],
        },
      });
      return;
    }
    await this.workspaceRequest("POST", `${base}:batchInherit`, {
      body: {
        requests: [{ policyTargetKey: targetKey, policySchema: before.schemaName }],
      },
    });
  }

  private async chromePolicy(
    change: ResourceChange,
    spec: DeploymentSpec,
    options: { schemaName: string; field: string; value: unknown; appId: string | null },
  ): Promise<void> {
    const schema = await this.chromeSchema(spec, options.schemaName);
    this.assertSchemaField(schema, options.field);
    const persisted = this.before.get(this.key(change));
    let persistedPolicy:
      | Extract<PersistedBeforeImage, { kind: "chrome_policy" }>
      | undefined;
    if (persisted !== undefined) {
      if (!isBeforeImage(persisted, "chrome_policy")) {
        throw new ProviderExecutionError("chrome-policy-retry-state-invalid");
      }
      persistedPolicy = persisted;
      if (
        persistedPolicy.schemaName !== options.schemaName ||
        persistedPolicy.appId !== options.appId ||
        persistedPolicy.managedAfter === undefined
      ) {
        throw new ProviderExecutionError("chrome-policy-retry-state-invalid");
      }
      const phase = sharedMutationPhase(persistedPolicy);
      if (phase === "sending") {
        // Chrome Policy has no requestId. A matching live value after restart
        // could have been written independently and is not SGS ownership proof.
        throw new ProviderExecutionError("chrome-policy-mutation-outcome-ambiguous");
      }
      if (phase === "rejected") {
        throw new ProviderExecutionError("chrome-policy-mutation-definitively-rejected");
      }
      if (phase === "applied") return;
    }
    const previous = await this.resolveChromePolicy(spec, options.schemaName, options.appId);
    const directBefore = this.directChromePolicyValues(
      spec,
      previous,
      options.schemaName,
      options.appId,
    );
    let managedAfter: Record<string, unknown>;
    if (persistedPolicy !== undefined) {
      const originalDirect = this.directChromePolicyValues(
        spec,
        persistedPolicy.previous,
        options.schemaName,
        options.appId,
      );
      if (canonicalJson(directBefore) !== canonicalJson(originalDirect)) {
        throw new ProviderExecutionError("chrome-policy-current-state-changed");
      }
      managedAfter = structuredClone(persistedPolicy.managedAfter!);
    } else {
      managedAfter = { ...(directBefore ?? {}), [options.field]: options.value };
    }
    const checkpoint = persistedPolicy ?? {
      kind: "chrome_policy",
      phase: "prepared" as const,
      schemaName: options.schemaName,
      appId: options.appId,
      previous,
      managedAfter,
    };
    if (persistedPolicy === undefined) {
      await this.captureBefore(change, checkpoint);
    }
    await this.captureBefore(change, { ...checkpoint, phase: "sending" });
    try {
      await this.batchModify(spec, options.schemaName, options.field, options.value, options.appId);
    } catch (error) {
      if (isDefiniteMutationRejection(error)) {
        await this.captureBefore(change, { ...checkpoint, phase: "rejected" });
      }
      throw error;
    }
    await this.captureBefore(change, { ...checkpoint, phase: "applied" });
  }

  private setChromeInstall(change: ResourceChange, spec: DeploymentSpec): Promise<void> {
    return this.chromePolicy(change, spec, {
      schemaName: "chrome.users.apps.InstallType",
      field: "appInstallType",
      value: "FORCED",
      appId: change.resource_name,
    });
  }

  /**
   * Hold until `iamSettleMs` has passed since the last Secure Gateway or
   * application IAM write. Nothing to wait for when this run wrote no
   * binding, and time already spent counts, so a long Apply pays nothing
   * extra.
   */
  private async settleIamPropagation(): Promise<void> {
    if (this.iamMutatedAt === undefined) return;
    const remaining = this.iamMutatedAt + this.iamSettleMs - Date.now();
    if (remaining <= 0) return;
    await new Promise((resolve) => setTimeout(resolve, remaining));
  }

  private async setChromeConfiguration(
    change: ResourceChange,
    spec: DeploymentSpec,
  ): Promise<void> {
    // Publishing the gateway resource is what makes the extension fetch routes.
    await this.settleIamPropagation();
    const configuration = canonicalJson({
      securityGateway: {
        Value: {
          authentication: {},
          context: {
            resource:
              `projects/${spec.project_id}/locations/global/` +
              `securityGateways/${spec.gateway_id}`,
          },
          serviceDiscovery: { routes: {} },
        },
      },
    });
    return this.chromePolicy(change, spec, {
      schemaName: "chrome.users.apps.ManagedConfiguration",
      field: "managedConfiguration",
      value: configuration,
      appId: SECURE_ENTERPRISE_BROWSER,
    });
  }

  private setServiceDiscoveryProxy(
    change: ResourceChange,
    spec: DeploymentSpec,
  ): Promise<void> {
    return this.chromePolicy(change, spec, {
      schemaName: "chrome.users.SimpleProxySettings",
      field: "simpleProxyMode",
      value: "PROXY_MODE_ENUM_USER_CONFIGURED",
      appId: null,
    });
  }
}

/**
 * Hand an artefact to the operator as a download.
 *
 * The local application wrote it to disk at `0600`. An extension has no
 * filesystem, so the operator saves it deliberately -- which also makes the
 * Root Store handoff a visible step rather than a file that silently appeared.
 */
async function defaultExportArtifact(filename: string, contents: string): Promise<void> {
  const url = `data:application/x-pem-file;base64,${btoa(contents)}`;
  await chrome.downloads.download({ url, filename, saveAs: true });
}
