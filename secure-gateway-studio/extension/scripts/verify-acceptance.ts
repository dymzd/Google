/** Canonical T01-T09 applicability and system-verification contract. */

import { configurationHash } from "../src/domain/planner.ts";
import { parseDeploymentSpec, type DeploymentSpec } from "../src/domain/spec.ts";
import {
  GoogleAcceptanceVerifier,
  acceptanceRequirements,
} from "../src/providers/acceptance.ts";
import type { Transport } from "../src/providers/executor.ts";

const failures: string[] = [];
let passed = 0;
const HASH = "a".repeat(64);

function check(name: string, condition: boolean, detail = ""): void {
  if (condition) passed += 1;
  else failures.push(`${name}${detail ? `: ${detail}` : ""}`);
}

const direct = parseDeploymentSpec({
  project_id: "gateway-project",
  mode: "poc",
  target_ou_id: "03-test-ou",
  managed_chrome_access_level: "accessPolicies/123/accessLevels/managed",
  test_ou_confirmed: true,
  chrome_enterprise_premium_license_confirmed: true,
  workspace_services_confirmed: true,
  endpoint_verification_confirmed: true,
  principals: [{ type: "group", value: "secure@example.com" }],
  platforms: ["macos", "windows"],
  backend_kind: "direct_https",
  network_strategy: "existing",
  vpc_name: "private-vpc",
  subnet_name: null,
  source_image: null,
  certificate_strategy: "public_trusted",
  existing_backend_url: "https://10.20.0.10:8443",
  existing_backend_location: "gcp",
  existing_backend_connectivity_confirmed: true,
  upstream_vpc_project_id: "upstream-project",
});

{
  const poc = acceptanceRequirements(direct);
  const t06 = poc.find((item) => item.test_id === "T06");
  check("T06 is operator evidence", t06?.source === "operator_confirmed");
  check("greenfield PoC may explicitly skip T06", t06?.allow_poc_skip === true);
  check("direct HTTPS has no VM checks", !poc.some((item) => /^T0[1-4]$/.test(item.test_id)));

  const production = acceptanceRequirements({ ...direct, mode: "production" });
  const t09Cases = production
    .filter((item) => item.test_id === "T09")
    .map((item) => item.case_key)
    .sort();
  check(
    "production requires separate T09 denial cases",
    t09Cases.join(",") === "unauthorized-principal,unmanaged-browser",
    t09Cases.join(","),
  );
  check("production direct HTTPS still requires T08", production.some((item) => item.test_id === "T08"));
}

class DirectTransport implements Transport {
  private readonly network: string;
  private readonly extraMatcher: boolean;
  private readonly extraUpstream: boolean;
  constructor(network: string, options: { extraMatcher?: boolean; extraUpstream?: boolean } = {}) {
    this.network = network;
    this.extraMatcher = options.extraMatcher === true;
    this.extraUpstream = options.extraUpstream === true;
  }
  async requestJson(): Promise<{ status: number; payload: Record<string, unknown> }> {
    return {
      status: 200,
      payload: {
        endpointMatchers: [
          { hostname: "10.20.0.10", ports: [8443] },
          ...(this.extraMatcher ? [{ hostname: "foreign.internal", ports: [443] }] : []),
        ],
        upstreams: [
          { network: { name: this.network } },
          ...(this.extraUpstream
            ? [{ network: { name: "projects/foreign/global/networks/foreign" } }]
            : []),
        ],
      },
    };
  }
}

{
  const result = await new GoogleAcceptanceVerifier(
    new DirectTransport("projects/upstream-project/global/networks/private-vpc"),
  ).verify(direct, "run-direct");
  check("direct T05 verifies the cross-project upstream", result[0]?.status === "passed");

  const mismatch = await new GoogleAcceptanceVerifier(
    new DirectTransport("projects/gateway-project/global/networks/private-vpc"),
  ).verify(direct, "run-direct");
  check("direct T05 fails closed on the wrong project", mismatch[0]?.status === "failed");

  const extraMatcher = await new GoogleAcceptanceVerifier(
    new DirectTransport("projects/upstream-project/global/networks/private-vpc", {
      extraMatcher: true,
    }),
  ).verify(direct, "run-direct");
  const extraUpstream = await new GoogleAcceptanceVerifier(
    new DirectTransport("projects/upstream-project/global/networks/private-vpc", {
      extraUpstream: true,
    }),
  ).verify(direct, "run-direct");
  check(
    "direct T05 rejects extra matchers and upstreams",
    extraMatcher[0]?.status === "failed" && extraUpstream[0]?.status === "failed",
  );
}

const managed = {
  ...direct,
  name: "secure-gateway-test",
  backend_kind: "managed_sample",
  network_strategy: "dedicated",
  vpc_name: null,
  subnet_name: "secure-gateway-test-subnet",
  source_image: "projects/example/global/images/secure-gateway-image",
  certificate_strategy: "local_poc",
  existing_backend_url: null,
  existing_backend_location: null,
  existing_backend_connectivity_confirmed: false,
  upstream_vpc_project_id: null,
  private_hostname: "backend.internal",
} as DeploymentSpec;

class ManagedTransport implements Transport {
  private readonly managedInstances?: Array<Record<string, unknown>>;
  private readonly sanShape?: unknown;
  private readonly trustMode: string;

  constructor(
    managedInstances?: Array<Record<string, unknown>>,
    sanShape?: unknown,
    trustMode = "presented_chain_pinned",
  ) {
    this.managedInstances = managedInstances;
    this.sanShape = sanShape;
    this.trustMode = trustMode;
  }

  async requestJson(
    _method: string,
    url: string,
    options?: { params?: Record<string, string | number> },
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    const hash = configurationHash(managed);
    const query = options?.params?.queryPath;
    if (url.endsWith("/listManagedInstances")) {
      return {
        status: 200,
        payload: { managedInstances: structuredClone(this.managedInstances ?? []) },
      };
    }
    if (url.endsWith("/getGuestAttributes") && query === "sgstudio/T01") {
      return { status: 200, payload: { variableValue: JSON.stringify({ status: 200, body_sha256: HASH, configuration_hash: hash }) } };
    }
    if (url.endsWith("/getGuestAttributes") && query === "sgstudio/T02") {
      return { status: 200, payload: { variableValue: JSON.stringify({ status: 200, body_sha256: HASH, configuration_hash: hash }) } };
    }
    if (url.endsWith("/getGuestAttributes") && query === "sgstudio/T03") {
      return { status: 200, payload: { variableValue: JSON.stringify({ http_status: 200, hostname: managed.private_hostname, trust_mode: this.trustMode, tls_version: "TLSv1.3", subject_alt_names: this.sanShape ?? [managed.private_hostname], body_sha256: HASH, configuration_hash: hash }) } };
    }
    if (url.includes("/addresses/")) return { status: 200, payload: { address: "10.42.0.9" } };
    if (url.includes("/rrsets/")) return { status: 200, payload: { name: `${managed.private_hostname}.`, type: "A", rrdatas: ["10.42.0.9"] } };
    if (url.includes("securityGateways")) {
      return {
        status: 200,
        payload: {
          endpointMatchers: [{ hostname: managed.private_hostname, ports: [443] }],
          upstreams: [{ network: { name: `projects/${managed.project_id}/global/networks/${managed.name}-vpc` } }],
        },
      };
    }
    throw new Error(`Unexpected request ${url}`);
  }
}

{
  const results = await new GoogleAcceptanceVerifier(new ManagedTransport()).verify(
    managed,
    "run-managed",
  );
  check("managed sample verifies exactly T01-T05", results.map((item) => item.test_id).join(",") === "T01,T02,T03,T04,T05", results.map((item) => item.test_id).join(","));
  check("all managed sample checks pass with exact evidence", results.every((item) => item.status === "passed"), JSON.stringify(results));
}

function managedEntries(count: number, options: { nonRunning?: boolean; duplicate?: boolean } = {}) {
  const entries = Array.from({ length: count }, (_, index) => ({
    instanceStatus: options.nonRunning && index === 0 ? "STAGING" : "RUNNING",
    instance:
      `https://compute.googleapis.com/compute/v1/projects/${managed.project_id}` +
      `/zones/${managed.zone}/instances/${managed.name}-offload-${index}`,
  }));
  if (options.duplicate && entries.length > 1) entries[entries.length - 1] = { ...entries[0] };
  return entries;
}

{
  const productionManaged = {
    ...managed,
    mode: "production",
    offload_min_replicas: 5,
    offload_max_replicas: 10,
  } as DeploymentSpec;
  // The transport evidence hash must match the production spec used by the
  // verifier, so reuse a local subclass with that canonical hash.
  class ProductionTransport extends ManagedTransport {
    override async requestJson(
      method: string,
      url: string,
      options?: { params?: Record<string, string | number> },
    ) {
      const response = await super.requestJson(method, url, options);
      if (url.endsWith("/getGuestAttributes")) {
        const raw = response.payload.variableValue;
        if (typeof raw === "string") {
          const evidence = JSON.parse(raw) as Record<string, unknown>;
          evidence.configuration_hash = configurationHash(productionManaged);
          response.payload.variableValue = JSON.stringify(evidence);
        }
      }
      return response;
    }
  }

  type PaginationVariant =
    | "valid"
    | "later-malformed"
    | "null-token"
    | "repeat-token"
    | "page-cap"
    | "item-cap";

  class PaginatedProductionTransport extends ProductionTransport {
    readonly listBodies: Record<string, unknown>[] = [];
    readonly probePaths: string[] = [];
    private readonly variant: PaginationVariant;

    constructor(variant: PaginationVariant) {
      super(managedEntries(5));
      this.variant = variant;
    }

    override async requestJson(
      method: string,
      url: string,
      options?: {
        params?: Record<string, string | number>;
        jsonBody?: Record<string, unknown>;
      },
    ) {
      if (url.endsWith("/listManagedInstances")) {
        const body = structuredClone(options?.jsonBody ?? {});
        this.listBodies.push(body);
        const token = body.pageToken;
        if (this.variant === "null-token") {
          return { status: 200, payload: { managedInstances: [], nextPageToken: null } };
        }
        if (this.variant === "repeat-token") {
          return { status: 200, payload: { managedInstances: [], nextPageToken: "repeat" } };
        }
        if (this.variant === "page-cap") {
          return {
            status: 200,
            payload: {
              managedInstances: [],
              nextPageToken: `page-${this.listBodies.length + 1}`,
            },
          };
        }
        if (this.variant === "item-cap") {
          return {
            status: 200,
            payload: { managedInstances: Array.from({ length: 501 }, () => ({})) },
          };
        }
        if (token === undefined) {
          return {
            status: 200,
            payload: { managedInstances: [], nextPageToken: "page-2" },
          };
        }
        if (this.variant === "later-malformed") {
          return { status: 200, payload: { managedInstances: [null] } };
        }
        return { status: 200, payload: { managedInstances: managedEntries(5) } };
      }
      if (url.endsWith("/getGuestAttributes")) {
        this.probePaths.push(String(options?.params?.queryPath ?? ""));
      }
      return super.requestJson(method, url, options);
    }
  }
  const insufficient = await new GoogleAcceptanceVerifier(
    new ProductionTransport(managedEntries(2)),
  ).verify(productionManaged, "run-production-2");
  const complete = await new GoogleAcceptanceVerifier(
    new ProductionTransport(managedEntries(5)),
  ).verify(productionManaged, "run-production-5");
  check(
    "production T02/T03 require all five configured minimum replicas",
    insufficient.filter((item) => item.test_id === "T02" || item.test_id === "T03")
      .every((item) => item.status === "failed") &&
      complete.filter((item) => item.test_id === "T02" || item.test_id === "T03")
        .every((item) => item.status === "passed"),
    JSON.stringify({ insufficient, complete }),
  );
  for (const entries of [
    managedEntries(5, { nonRunning: true }),
    managedEntries(5, { duplicate: true }),
    managedEntries(6, { duplicate: true }),
  ]) {
    const result = await new GoogleAcceptanceVerifier(
      new ProductionTransport(entries),
    ).verify(productionManaged, "run-production-invalid");
    check(
      "production T02/T03 reject non-running or duplicate managed entries",
      result.filter((item) => item.test_id === "T02" || item.test_id === "T03")
        .every((item) => item.status === "failed"),
      JSON.stringify(result),
    );
  }
  {
    const transport = new PaginatedProductionTransport("valid");
    const result = await new GoogleAcceptanceVerifier(transport).verify(
      productionManaged,
      "run-production-paged",
    );
    check(
      "production managed-instance discovery follows an empty first page",
      result.filter((item) => item.test_id === "T02" || item.test_id === "T03")
        .every((item) => item.status === "passed") &&
        transport.listBodies.length === 2 &&
        transport.listBodies[0]?.maxResults === 500 &&
        transport.listBodies[1]?.pageToken === "page-2",
      JSON.stringify({ result, bodies: transport.listBodies }),
    );
  }
  for (const variant of [
    "later-malformed",
    "null-token",
    "repeat-token",
    "page-cap",
    "item-cap",
  ] as const) {
    const transport = new PaginatedProductionTransport(variant);
    const result = await new GoogleAcceptanceVerifier(transport).verify(
      productionManaged,
      `run-production-${variant}`,
    );
    check(
      `production managed-instance pagination rejects ${variant} before instance probes`,
      result.filter((item) => item.test_id === "T02" || item.test_id === "T03")
        .every((item) => item.status === "failed") &&
        !transport.probePaths.some((path) => path === "sgstudio/T02" || path === "sgstudio/T03"),
      JSON.stringify({ result, bodies: transport.listBodies.length, probes: transport.probePaths }),
    );
  }
  const stringSan = await new GoogleAcceptanceVerifier(
    new ProductionTransport(managedEntries(5), managed.private_hostname),
  ).verify(productionManaged, "run-production-string-san");
  check(
    "T03 rejects a string-shaped SAN field even when it contains the hostname",
    stringSan.find((item) => item.test_id === "T03")?.status === "failed",
  );
  const malformedSanItem = await new GoogleAcceptanceVerifier(
    new ProductionTransport(managedEntries(5), [managed.private_hostname, 7]),
  ).verify(productionManaged, "run-production-malformed-san-item");
  check(
    "T03 requires every SAN entry to be a string",
    malformedSanItem.find((item) => item.test_id === "T03")?.status === "failed",
  );
  const wrongTrustMode = await new GoogleAcceptanceVerifier(
    new ProductionTransport(managedEntries(5), undefined, "public_system_roots"),
  ).verify(productionManaged, "run-production-wrong-trust");
  check(
    "T03 requires the evidence trust mode to match the certificate strategy",
    wrongTrustMode.find((item) => item.test_id === "T03")?.status === "failed",
  );
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} checks`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} acceptance checks passed.`);
