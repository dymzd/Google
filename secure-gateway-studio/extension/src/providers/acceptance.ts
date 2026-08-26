/**
 * Acceptance verification shared with the canonical T01-T09 matrix.
 *
 * Machine checks are deliberately fail-closed. Browser observations remain
 * operator evidence; the extension never turns a successful API fixture into
 * a claim that a managed browser actually reached the application.
 */

import { configurationHash } from "../domain/planner.ts";
import {
  applicationHostname,
  applicationPort,
  upstreamProjectId,
  type ChromePlatform,
  type DeploymentSpec,
} from "../domain/spec.ts";
import type { Transport } from "./executor.ts";

export type AcceptanceStatus =
  | "passed"
  | "failed"
  | "pending"
  | "skipped"
  | "user_confirmed";
export type EvidenceSource = "system_verified" | "operator_confirmed";

export interface AcceptanceRequirement {
  test_id: string;
  case_key: string;
  title: string;
  source: EvidenceSource;
  operator_confirmable: boolean;
  applicable: true;
  /** Only the T06 regression control may be skipped by a greenfield PoC. */
  allow_poc_skip: boolean;
  detail: string;
}

export interface AcceptanceFinding {
  test_id: string;
  status: AcceptanceStatus;
  summary: string;
  evidence: string;
}

const TITLES: Record<string, string> = {
  T01: "HTTP backend local response",
  T02: "Offload-to-backend response",
  T03: "TLS termination",
  T04: "Private DNS",
  T05: "Secure Gateway route",
  T06: "Existing HTTPS regression control",
  T07: "Managed Chrome end to end",
  T08: "Log correlation",
  T09: "Unauthorized or unmanaged denial",
};

const MANAGED_INSTANCE_PAGE_SIZE = 500;
const MAX_MANAGED_INSTANCE_PAGES = 100;
const MAX_MANAGED_INSTANCE_ITEMS =
  MANAGED_INSTANCE_PAGE_SIZE * MAX_MANAGED_INSTANCE_PAGES;
const COMPUTE_SELF_LINK_HOSTS = new Set([
  "compute.googleapis.com",
  "www.googleapis.com",
]);

function requirement(
  testId: string,
  source: EvidenceSource,
  caseKey = "default",
  detail = "",
  allowPocSkip = false,
): AcceptanceRequirement {
  return {
    test_id: testId,
    case_key: caseKey,
    title: TITLES[testId],
    source,
    operator_confirmable: source === "operator_confirmed",
    applicable: true,
    allow_poc_skip: allowPocSkip,
    detail,
  };
}

/** Return the exact required cases defined by docs/TEST_MATRIX.md. */
export function acceptanceRequirements(spec: DeploymentSpec): AcceptanceRequirement[] {
  const system = "system_verified" as const;
  const operator = "operator_confirmed" as const;
  const requirements: AcceptanceRequirement[] = [];

  if (spec.backend_kind === "direct_https") {
    requirements.push(requirement("T05", system));
  } else if (spec.backend_kind === "internal_https_lb") {
    requirements.push(
      requirement("T01", system),
      requirement("T03", operator, "default", "Verify TLS at the ILB endpoint."),
      requirement("T04", system),
      requirement("T05", system),
    );
  } else {
    requirements.push(
      requirement(
        "T01",
        spec.backend_kind === "existing_http" ? operator : system,
        "default",
        spec.backend_kind === "existing_http"
          ? "Record the existing backend's known-good local response."
          : "Read the managed backend runtime probe.",
      ),
      requirement("T02", system),
      requirement("T03", system),
      requirement("T04", system),
      requirement("T05", system),
    );
  }

  requirements.push(
    requirement(
      "T06",
      operator,
      "default",
      "Verify an already-known-good HTTPS control application; a greenfield PoC may skip with a reason.",
      true,
    ),
  );

  const platformOrder: ChromePlatform[] = ["macos", "windows", "linux", "chromeos"];
  for (const platform of platformOrder) {
    if (spec.platforms.has(platform)) {
      requirements.push(
        requirement("T07", operator, platform, `Verify managed Chrome on ${platform}.`),
      );
    }
  }

  if (spec.mode === "production") {
    requirements.push(
      requirement("T08", operator),
      requirement("T09", operator, "unauthorized-principal"),
      requirement("T09", operator, "unmanaged-browser"),
    );
  }
  return requirements;
}

const BEYONDCORP = "https://beyondcorp.googleapis.com/v1";
const COMPUTE = "https://compute.googleapis.com/compute/v1";
const DNS = "https://dns.googleapis.com/dns/v1";

function jsonEvidence(runId: string, value: Record<string, unknown>): string {
  return JSON.stringify({ run_id: runId, ...value });
}

function hasSha256(value: unknown): boolean {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function passedConfiguration(evidence: Record<string, unknown>, spec: DeploymentSpec): boolean {
  return evidence.configuration_hash === configurationHash(spec);
}

export class GoogleAcceptanceVerifier {
  private readonly transport: Transport;

  constructor(transport: Transport) {
    this.transport = transport;
  }

  /** Run every applicable system-verifiable check, never T06-T09. */
  async verify(spec: DeploymentSpec, runId: string): Promise<AcceptanceFinding[]> {
    const findings: AcceptanceFinding[] = [];
    if (spec.backend_kind === "managed_sample" || spec.backend_kind === "internal_https_lb") {
      findings.push(await this.verifyBackend(spec, runId));
    }
    if (spec.backend_kind !== "direct_https" && spec.backend_kind !== "internal_https_lb") {
      findings.push(...(await this.verifyOffload(spec, runId)));
    }
    if (spec.backend_kind !== "direct_https") {
      findings.push(await this.verifyDns(spec, runId));
    }
    findings.push(await this.verifyApplication(spec, runId));
    return findings;
  }

  private async guestAttribute(
    spec: DeploymentSpec,
    zone: string,
    instance: string,
    testId: string,
  ): Promise<Record<string, unknown>> {
    const { payload } = await this.transport.requestJson(
      "GET",
      `${COMPUTE}/projects/${spec.project_id}/zones/${zone}/instances/${instance}/getGuestAttributes`,
      { params: { queryPath: `sgstudio/${testId}` } },
    );
    let value = payload.variableValue;
    const queryValue = payload.queryValue as Record<string, unknown> | undefined;
    if (typeof value !== "string" && queryValue && Array.isArray(queryValue.items)) {
      const item = queryValue.items.find((entry) => {
        const record = entry as Record<string, unknown>;
        return record.namespace === "sgstudio" && record.key === testId;
      }) as Record<string, unknown> | undefined;
      value = item?.value;
    }
    if (typeof value !== "string") throw new Error("guest-attribute-value-missing");
    const decoded = JSON.parse(value) as unknown;
    if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
      throw new Error("guest-attribute-value-invalid");
    }
    return decoded as Record<string, unknown>;
  }

  private async verifyBackend(spec: DeploymentSpec, runId: string): Promise<AcceptanceFinding> {
    try {
      const evidence = await this.guestAttribute(
        spec,
        spec.zone,
        `${spec.name}-backend`,
        "T01",
      );
      const passed =
        evidence.status === 200 &&
        hasSha256(evidence.body_sha256) &&
        passedConfiguration(evidence, spec);
      return {
        test_id: "T01",
        status: passed ? "passed" : "failed",
        summary: passed
          ? "Managed backend returned HTTP 200 to its local runtime probe."
          : "Managed backend runtime probe is missing or invalid.",
        evidence: jsonEvidence(runId, evidence),
      };
    } catch (error) {
      return this.failed("T01", runId, "Managed backend runtime probe could not be verified.", error);
    }
  }

  private async offloadInstances(spec: DeploymentSpec): Promise<Array<[string, string]>> {
    if (spec.mode === "poc") return [[spec.zone, `${spec.name}-offload`]];
    const url =
      `${COMPUTE}/projects/${spec.project_id}/regions/${spec.region}/instanceGroupManagers/` +
      `${spec.name}-offload-mig/listManagedInstances`;
    const managed: unknown[] = [];
    const seenTokens = new Set<string>();
    let pageToken: string | undefined;
    let complete = false;
    for (let page = 0; page < MAX_MANAGED_INSTANCE_PAGES; page += 1) {
      const jsonBody: Record<string, unknown> = { maxResults: MANAGED_INSTANCE_PAGE_SIZE };
      if (pageToken !== undefined) jsonBody.pageToken = pageToken;
      const { payload } = await this.transport.requestJson("POST", url, { jsonBody });
      if (!Array.isArray(payload.managedInstances)) {
        throw new Error("invalid-managed-instance-response");
      }
      if (payload.managedInstances.length > MANAGED_INSTANCE_PAGE_SIZE) {
        throw new Error("managed-instance-page-limit");
      }
      managed.push(...payload.managedInstances);
      if (managed.length > MAX_MANAGED_INSTANCE_ITEMS) {
        throw new Error("managed-instance-item-limit");
      }
      if (!("nextPageToken" in payload) || payload.nextPageToken === "") {
        complete = true;
        break;
      }
      if (
        typeof payload.nextPageToken !== "string" ||
        seenTokens.has(payload.nextPageToken)
      ) {
        throw new Error("invalid-managed-instance-page-token");
      }
      seenTokens.add(payload.nextPageToken);
      pageToken = payload.nextPageToken;
    }
    if (!complete) throw new Error("managed-instance-pagination-incomplete");

    const instances = new Map<string, [string, string]>();
    for (const entry of managed) {
      if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
        throw new Error("invalid-managed-instance-response");
      }
      const record = entry as Record<string, unknown>;
      if (record.instanceStatus !== "RUNNING" || typeof record.instance !== "string") {
        throw new Error("managed-instance-not-running");
      }
      let parsed: URL;
      try {
        parsed = new URL(record.instance);
      } catch {
        throw new Error("invalid-managed-instance-name");
      }
      const parts = parsed.pathname.split("/");
      if (
        parsed.protocol !== "https:" ||
        !COMPUTE_SELF_LINK_HOSTS.has(parsed.hostname) ||
        parsed.port !== "" || parsed.username !== "" || parsed.password !== "" ||
        parsed.search !== "" || parsed.hash !== "" ||
        parts.length !== 9 || parts[1] !== "compute" || parts[2] !== "v1" ||
        parts[3] !== "projects" || parts[4] !== spec.project_id ||
        parts[5] !== "zones" || parts[7] !== "instances" ||
        !parts[6] || !parts[8] ||
        decodeURIComponent(parts[6]) !== parts[6] || decodeURIComponent(parts[8]) !== parts[8]
      ) {
        throw new Error("invalid-managed-instance-name");
      }
      const zone = parts[6];
      const instance = parts[8];
      const key = `${zone}/${instance}`;
      if (instances.has(key)) throw new Error("duplicate-managed-instance");
      instances.set(key, [zone, instance]);
    }
    return [...instances.values()].sort((left, right) => left.join("/").localeCompare(right.join("/")));
  }

  private async verifyOffload(
    spec: DeploymentSpec,
    runId: string,
  ): Promise<AcceptanceFinding[]> {
    try {
      const instances = await this.offloadInstances(spec);
      if (instances.length === 0) throw new Error("no-offload-instances");
      const t02: Record<string, unknown>[] = await Promise.all(
        instances.map(async ([zone, instance]) => ({
          instance,
          ...(await this.guestAttribute(spec, zone, instance, "T02")),
        })),
      );
      const t03: Record<string, unknown>[] = await Promise.all(
        instances.map(async ([zone, instance]) => ({
          instance,
          ...(await this.guestAttribute(spec, zone, instance, "T03")),
        })),
      );
      const expectedCount = spec.mode === "production" ? spec.offload_min_replicas : 1;
      const expectedTrustMode = spec.certificate_strategy === "public_trusted"
        ? "public_system_roots"
        : "presented_chain_pinned";
      const t02Passed =
        t02.length >= expectedCount &&
        t02.every(
          (item) =>
            item.status === 200 &&
            hasSha256(item.body_sha256) &&
            passedConfiguration(item, spec),
        );
      const t03Passed =
        t03.length >= expectedCount &&
        t03.every(
          (item) =>
            item.http_status === 200 &&
            item.hostname === spec.private_hostname &&
            item.trust_mode === expectedTrustMode &&
            (item.tls_version === "TLSv1.2" || item.tls_version === "TLSv1.3") &&
            Array.isArray(item.subject_alt_names) &&
            item.subject_alt_names.every((name) => typeof name === "string") &&
            item.subject_alt_names.includes(spec.private_hostname) &&
            hasSha256(item.body_sha256) &&
            passedConfiguration(item, spec),
        );
      return [
        {
          test_id: "T02",
          status: t02Passed ? "passed" : "failed",
          summary: t02Passed
            ? "Every offload instance reached the HTTP backend."
            : "One or more offload-to-backend runtime probes failed.",
          evidence: jsonEvidence(runId, { instances: t02 }),
        },
        {
          test_id: "T03",
          status: t03Passed ? "passed" : "failed",
          summary: t03Passed
            ? "Every offload instance passed the configured trust-mode, hostname-validating TLS, and HTTP checks."
            : "One or more TLS termination runtime probes failed.",
          evidence: jsonEvidence(runId, { instances: t03 }),
        },
      ];
    } catch (error) {
      return [
        this.failed("T02", runId, "Offload-to-backend probes could not be verified.", error),
        this.failed("T03", runId, "TLS termination probes could not be verified.", error),
      ];
    }
  }

  private async verifyDns(spec: DeploymentSpec, runId: string): Promise<AcceptanceFinding> {
    try {
      const { payload: address } = await this.transport.requestJson(
        "GET",
        `${COMPUTE}/projects/${spec.project_id}/regions/${spec.region}/addresses/${spec.name}-offload-ip`,
      );
      if (typeof address.address !== "string") throw new Error("internal-address-missing");
      const recordName = encodeURIComponent(`${spec.private_hostname}.`);
      const { payload: record } = await this.transport.requestJson(
        "GET",
        `${DNS}/projects/${spec.project_id}/managedZones/${spec.name}-zone/rrsets/${recordName}/A`,
      );
      const passed =
        record.name === `${spec.private_hostname}.` &&
        record.type === "A" &&
        Array.isArray(record.rrdatas) &&
        record.rrdatas.length === 1 &&
        record.rrdatas[0] === address.address;
      return {
        test_id: "T04",
        status: passed ? "passed" : "failed",
        summary: passed
          ? "Private DNS exactly matches the reserved internal address."
          : "Private DNS does not exactly match the reserved internal address.",
        evidence: jsonEvidence(runId, {
          hostname: spec.private_hostname,
          expected_address: address.address,
          rrdatas: Array.isArray(record.rrdatas) ? record.rrdatas : [],
        }),
      };
    } catch (error) {
      return this.failed("T04", runId, "Private DNS could not be verified.", error);
    }
  }

  private async verifyApplication(
    spec: DeploymentSpec,
    runId: string,
  ): Promise<AcceptanceFinding> {
    try {
      const applicationUrl =
        `${BEYONDCORP}/projects/${spec.project_id}/locations/global` +
        `/securityGateways/${spec.gateway_id}/applications/${spec.name}-app`;
      const { payload } = await this.transport.requestJson("GET", applicationUrl);
      const matchers = payload.endpointMatchers ?? payload.endpoint_matchers;
      const expectedHost = applicationHostname(spec);
      const expectedPort = applicationPort(spec);
      const matcherExact =
        Array.isArray(matchers) &&
        matchers.length === 1 &&
        (() => {
          const record = matchers[0] as Record<string, unknown>;
          return record.hostname === expectedHost &&
            Array.isArray(record.ports) &&
            record.ports.length === 1 &&
            Number(record.ports[0]) === expectedPort;
        })();
      const networkName =
        spec.network_strategy === "existing" ? spec.vpc_name : `${spec.name}-vpc`;
      const expectedNetwork =
        `projects/${upstreamProjectId(spec)}/global/networks/${networkName}`;
      const upstreams = Array.isArray(payload.upstreams) ? payload.upstreams : [];
      const upstreamExact = upstreams.length === 1 && (() => {
        const upstream = upstreams[0] as Record<string, unknown>;
        const network = upstream.network as Record<string, unknown> | undefined;
        if (network?.name !== expectedNetwork) return false;
        const policy = (upstream.egressPolicy ?? upstream.egress_policy) as
          | Record<string, unknown>
          | undefined;
        if (!spec.application_egress_region) return policy === undefined;
        return (
          Array.isArray(policy?.regions) &&
          policy.regions.length === 1 &&
          policy.regions[0] === spec.application_egress_region
        );
      })();
      const passed = matcherExact && upstreamExact;
      return {
        test_id: "T05",
        status: passed ? "passed" : "failed",
        summary: passed
          ? "Secure Gateway application exactly matches the intended route."
          : "Secure Gateway matcher or upstream network does not match exactly.",
        evidence: jsonEvidence(runId, {
          application: `${spec.name}-app`,
          hostname: expectedHost,
          port: expectedPort,
          network: expectedNetwork,
          egress_region: spec.application_egress_region,
          exact_match: passed,
        }),
      };
    } catch (error) {
      return this.failed("T05", runId, "Secure Gateway application could not be verified.", error);
    }
  }

  private failed(
    testId: string,
    runId: string,
    summary: string,
    error: unknown,
  ): AcceptanceFinding {
    return {
      test_id: testId,
      status: "failed",
      summary,
      evidence: jsonEvidence(runId, {
        error: error instanceof Error ? error.message : String(error),
      }),
    };
  }
}
