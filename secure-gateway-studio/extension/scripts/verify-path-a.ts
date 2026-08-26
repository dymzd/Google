/** Path A request-shape and durable VM-readiness regression checks. */

import { canonicalJson } from "../src/domain/canonical.ts";
import { configurationHash, type ResourceChange } from "../src/domain/planner.ts";
import { serviceAccountEmail } from "../src/domain/naming.ts";
import { parseDeploymentSpec, type DeploymentSpec } from "../src/domain/spec.ts";
import {
  applyPathA,
  isInstanceRuntimeReady,
  type PathAContext,
} from "../src/providers/executor-path-a.ts";
import { GoogleResourceExecutor, type Transport } from "../src/providers/executor.ts";
import { sampleBackendStartupScript } from "../src/providers/startup-scripts.ts";
import {
  planRun,
  RunEngine,
  type RunRecord,
  type RunStore,
  type Scheduler,
} from "../src/runtime/run-engine.ts";

interface Call {
  method: string;
  url: string;
  params: Record<string, string | number> | null;
  body: Record<string, unknown> | null;
}

const failures: string[] = [];
let passed = 0;

function check(name: string, condition: boolean, detail = ""): void {
  if (condition) passed += 1;
  else failures.push(`${name}${detail ? `\n      ${detail}` : ""}`);
}

function change(resourceType: string, resourceName: string): ResourceChange {
  return {
    provider: "compute",
    resource_type: resourceType,
    resource_name: resourceName,
    action: "create",
    risk: "high",
    summary: resourceName,
    owned_after_apply: true,
    dependencies: [],
  };
}

const MANAGED_SPEC = parseDeploymentSpec({
  project_id: "enterprise-secgw-01",
  mode: "poc",
  target_ou_id: "03-test-ou",
  managed_chrome_access_level: "accessPolicies/123456789/accessLevels/managed_chrome",
  test_ou_confirmed: true,
  principals: [{ type: "group", value: "secure-access@example.com" }],
  backend_kind: "managed_sample",
  network_strategy: "dedicated",
  certificate_strategy: "local_poc",
  source_image: "projects/enterprise-secgw-01/global/images/sgs-nginx-20260824",
});

const EXISTING_SPEC = parseDeploymentSpec({
  project_id: "enterprise-secgw-01",
  mode: "poc",
  target_ou_id: "03-test-ou",
  managed_chrome_access_level: "accessPolicies/123456789/accessLevels/managed_chrome",
  test_ou_confirmed: true,
  principals: [{ type: "group", value: "secure-access@example.com" }],
  backend_kind: "existing_http",
  network_strategy: "existing",
  vpc_name: "private-app-vpc",
  subnet_name: "private-app-subnet",
  certificate_strategy: "local_poc",
  source_image: "projects/enterprise-secgw-01/global/images/sgs-nginx-20260824",
  existing_backend_url: "http://10.20.0.10:8080",
  existing_backend_location: "gcp",
  existing_backend_connectivity_confirmed: true,
});

const ILB_SPEC = parseDeploymentSpec({
  project_id: "enterprise-secgw-01",
  mode: "poc",
  target_ou_id: "03-test-ou",
  test_ou_confirmed: true,
  principals: [{ type: "group", value: "secure-access@example.com" }],
  backend_kind: "internal_https_lb",
  network_strategy: "dedicated",
  certificate_strategy: "local_poc",
  source_image: "projects/enterprise-secgw-01/global/images/sgs-nginx-20260824",
  proxy_subnet_cidr: "10.42.1.0/24",
});

const PRODUCTION_MANAGED_SPEC = parseDeploymentSpec({
  project_id: "enterprise-secgw-01",
  mode: "production",
  target_ou_id: "03-test-ou",
  test_ou_confirmed: true,
  principals: [{ type: "group", value: "secure-access@example.com" }],
  backend_kind: "managed_sample",
  network_strategy: "dedicated",
  certificate_strategy: "public_trusted",
  private_hostname: "gateway.customer.dev",
  public_certificate_secret: "projects/enterprise-secgw-01/secrets/tls",
  source_image: "projects/enterprise-secgw-01/global/images/sgs-nginx-20260824",
  secondary_zone: "asia-east1-a",
  managed_chrome_access_level: "accessPolicies/123456789/accessLevels/managed_chrome",
  chrome_enterprise_premium_license_confirmed: true,
  workspace_services_confirmed: true,
  endpoint_verification_confirmed: true,
});

const productionBackendScript = sampleBackendStartupScript(PRODUCTION_MANAGED_SPEC);
check(
  "Production sample backend uses only the approval-bound hardened image packages",
  !productionBackendScript.includes("apt-get") &&
    productionBackendScript.includes("command -v python3") &&
    productionBackendScript.includes("command -v nginx"),
);

const REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000";
const SOURCE_IMAGE_BINDING = {
  name: "projects/enterprise-secgw-01/global/images/sgs-nginx-20260824",
  id: "987654321",
  self_link: (
    "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
    "global/images/sgs-nginx-20260824"
  ),
};

class RecordingTransport implements Transport {
  readonly calls: Call[] = [];
  readonly respond: (
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
    },
  ) => { status: number; payload: Record<string, unknown> };

  constructor(
    respond: RecordingTransport["respond"] = () => ({ status: 200, payload: {} }),
  ) {
    this.respond = respond;
  }

  async requestJson(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
    } = {},
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    this.calls.push({
      method,
      url,
      params: options.params ?? null,
      body: options.jsonBody ?? null,
    });
    return this.respond(method, url, options);
  }
}

function context(transport: Transport): PathAContext {
  return {
    transport,
    requestId: () => REQUEST_ID,
    exportArtifact: async () => undefined,
    captureBefore: async () => undefined,
  };
}

function evidencePayload(
  spec: DeploymentSpec,
  role: "backend" | "offload",
  mutations: {
    hash?: string;
    san?: unknown;
    status?: number;
    tls?: string;
    trustMode?: string;
  } = {},
): Record<string, unknown> {
  const hash = mutations.hash ?? configurationHash(spec);
  const status = mutations.status ?? 200;
  const records = role === "backend"
    ? [{ key: "T01", value: { status, configuration_hash: hash } }]
    : [
        { key: "T02", value: { status, configuration_hash: hash } },
        {
          key: "T03",
          value: {
            http_status: status,
            configuration_hash: hash,
            hostname: spec.private_hostname,
            trust_mode: mutations.trustMode ?? (
              spec.certificate_strategy === "public_trusted"
                ? "public_system_roots"
                : "presented_chain_pinned"
            ),
            tls_version: mutations.tls ?? "TLSv1.3",
            subject_alt_names: mutations.san ?? [spec.private_hostname],
          },
        },
      ];
  return {
    queryValue: {
      items: records.map((record) => ({
        namespace: "sgstudio",
        key: record.key,
        value: JSON.stringify(record.value),
      })),
    },
  };
}

// Every firewall suffix has a distinct trust boundary. Compare the entire body
// so a port, source identity/range, or target identity regression is visible.
{
  const cases = [
    {
      suffix: "backend-ingress",
      expected: {
        allowed: [{ IPProtocol: "tcp", ports: ["80"] }],
        direction: "INGRESS",
        logConfig: { enable: true, metadata: "INCLUDE_ALL_METADATA" },
        name: `${MANAGED_SPEC.name}-backend-ingress`,
        network:
          "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
          `global/networks/${MANAGED_SPEC.name}-vpc`,
        priority: 1000,
        sourceServiceAccounts: [
          serviceAccountEmail(MANAGED_SPEC.name, MANAGED_SPEC.project_id, "offload"),
        ],
        targetServiceAccounts: [
          serviceAccountEmail(MANAGED_SPEC.name, MANAGED_SPEC.project_id, "backend"),
        ],
      },
    },
    {
      suffix: "health-check-ingress",
      expected: {
        allowed: [{ IPProtocol: "tcp", ports: ["443"] }],
        direction: "INGRESS",
        logConfig: { enable: true, metadata: "INCLUDE_ALL_METADATA" },
        name: `${MANAGED_SPEC.name}-health-check-ingress`,
        network:
          "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
          `global/networks/${MANAGED_SPEC.name}-vpc`,
        priority: 1000,
        sourceRanges: ["35.191.0.0/16", "130.211.0.0/22"],
        targetServiceAccounts: [
          serviceAccountEmail(MANAGED_SPEC.name, MANAGED_SPEC.project_id, "offload"),
        ],
      },
    },
    {
      suffix: "gateway-ingress",
      expected: {
        allowed: [{ IPProtocol: "tcp", ports: ["443"] }],
        direction: "INGRESS",
        logConfig: { enable: true, metadata: "INCLUDE_ALL_METADATA" },
        name: `${MANAGED_SPEC.name}-gateway-ingress`,
        network:
          "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
          `global/networks/${MANAGED_SPEC.name}-vpc`,
        priority: 1000,
        sourceRanges: ["136.124.16.0/20"],
        targetServiceAccounts: [
          serviceAccountEmail(MANAGED_SPEC.name, MANAGED_SPEC.project_id, "offload"),
        ],
      },
    },
  ] as const;

  for (const fixture of cases) {
    const transport = new RecordingTransport();
    await applyPathA(
      context(transport),
      change("firewall_rule", `${MANAGED_SPEC.name}-${fixture.suffix}`),
      MANAGED_SPEC,
    );
    const call = transport.calls[0];
    check(
      `Path A ${fixture.suffix} firewall request is exact`,
      transport.calls.length === 1 && call?.method === "POST" &&
        call.url.endsWith("/global/firewalls") &&
        canonicalJson(call.params) === canonicalJson({ requestId: REQUEST_ID }) &&
        canonicalJson(call.body) === canonicalJson(fixture.expected),
      canonicalJson(call ?? null),
    );
  }
}

// The readiness predicate rejects every shape that previously let a Compute
// insert be reported as a successful application without usable Nginx/TLS.
{
  const validBackend = evidencePayload(MANAGED_SPEC, "backend");
  const validOffload = evidencePayload(MANAGED_SPEC, "offload");
  check(
    "backend T01 requires status 200 and the exact configuration hash",
    isInstanceRuntimeReady(validBackend, MANAGED_SPEC, "backend") &&
      !isInstanceRuntimeReady({}, MANAGED_SPEC, "backend") &&
      !isInstanceRuntimeReady(
        evidencePayload(MANAGED_SPEC, "backend", { hash: "0".repeat(64) }),
        MANAGED_SPEC,
        "backend",
      ) &&
      !isInstanceRuntimeReady(
        evidencePayload(MANAGED_SPEC, "backend", { status: 503 }),
        MANAGED_SPEC,
        "backend",
      ),
  );
  check(
    "offload T02/T03 require exact hash, hostname, TLS, and an array SAN",
    isInstanceRuntimeReady(validOffload, MANAGED_SPEC, "offload") &&
      !isInstanceRuntimeReady({}, MANAGED_SPEC, "offload") &&
      !isInstanceRuntimeReady(
        evidencePayload(MANAGED_SPEC, "offload", { hash: "0".repeat(64) }),
        MANAGED_SPEC,
        "offload",
      ) &&
      !isInstanceRuntimeReady(
        evidencePayload(MANAGED_SPEC, "offload", { san: MANAGED_SPEC.private_hostname }),
        MANAGED_SPEC,
        "offload",
      ) &&
      !isInstanceRuntimeReady(
        evidencePayload(MANAGED_SPEC, "offload", { san: ["other.internal"] }),
        MANAGED_SPEC,
        "offload",
      ) &&
      !isInstanceRuntimeReady(
        evidencePayload(MANAGED_SPEC, "offload", { tls: "TLSv1.1" }),
        MANAGED_SPEC,
        "offload",
      ) &&
      !isInstanceRuntimeReady(
        evidencePayload(MANAGED_SPEC, "offload", { trustMode: "public_system_roots" }),
        MANAGED_SPEC,
        "offload",
      ),
  );
}

// Managed sample address reads are role-specific: the backend VM reads its own
// address once, while the offload VM additionally reads it as its upstream.
for (const fixture of [
  { role: "backend" as const, addressSuffixes: ["backend-ip"] },
  { role: "offload" as const, addressSuffixes: ["backend-ip", "offload-ip"] },
]) {
  const transport = new RecordingTransport((method, url) => {
    if (method === "GET" && url.includes("/addresses/")) {
      return {
        status: 200,
        payload: { address: url.endsWith("backend-ip") ? "10.42.0.20" : "10.42.0.10" },
      };
    }
    if (method === "GET" && url.endsWith("/getGuestAttributes")) {
      return { status: 200, payload: evidencePayload(MANAGED_SPEC, fixture.role) };
    }
    return { status: 200, payload: {} };
  });
  await applyPathA(
    context(transport),
    change("instance", `${MANAGED_SPEC.name}-${fixture.role}`),
    MANAGED_SPEC,
  );
  const addresses = transport.calls
    .filter((call) => call.method === "GET" && call.url.includes("/addresses/"))
    .map((call) => call.url.split("/").pop());
  const expectedAddresses = fixture.addressSuffixes.map(
    (suffix) => `${MANAGED_SPEC.name}-${suffix}`,
  );
  check(
    `managed ${fixture.role} reads only its required addresses`,
    canonicalJson(addresses) === canonicalJson(expectedAddresses),
    canonicalJson(addresses),
  );
}

// Cloud Router's v1 Router schema has no top-level fingerprint field. A
// Cloud NAT update is a Router PATCH whose body contains the complete NAT
// array; requiring or sending an obsolete fingerprint makes the live request
// fail before the sample VM path can become reachable.
{
  const routerUrl =
    "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
    `regions/${MANAGED_SPEC.region}/routers/${MANAGED_SPEC.name}-router`;
  const transport = new RecordingTransport((method, url) => {
    if (method === "GET" && url === routerUrl) {
      return {
        status: 200,
        payload: {
          nats: [{ name: "administrator-nat", natIpAllocateOption: "AUTO_ONLY" }],
        },
      };
    }
    return { status: 200, payload: {} };
  });
  await applyPathA(
    context(transport),
    change("cloud_nat", `${MANAGED_SPEC.name}-nat`),
    MANAGED_SPEC,
  );
  const patch = transport.calls.find((call) => call.method === "PATCH");
  check(
    "Cloud NAT Router PATCH uses only fields in the official Router schema",
    patch?.url === routerUrl &&
      canonicalJson(patch.params) === canonicalJson({ requestId: REQUEST_ID }) &&
      Array.isArray(patch.body?.nats) &&
      patch.body?.nats.length === 2 &&
      !("fingerprint" in (patch.body ?? {})),
    canonicalJson(patch ?? null),
  );
}

class MemoryStore implements RunStore {
  private readonly values = new Map<string, string>();
  async load(runId: string): Promise<RunRecord | null> {
    const value = this.values.get(runId);
    return value === undefined ? null : JSON.parse(value) as RunRecord;
  }
  async save(record: RunRecord): Promise<void> {
    this.values.set(record.runId, JSON.stringify(record));
  }
}

class NullScheduler implements Scheduler {
  async schedule(): Promise<void> {}
  async cancel(): Promise<void> {}
}

// Simulate a fresh MV3 worker on every tick. Empty and wrong-hash evidence keep
// the exact step pending; the third valid result completes with the same
// requestId, and no nonexistent backend address is ever queried.
{
  let readinessPolls = 0;
  let instanceLive: Record<string, unknown> | null = null;
  const instanceUrl =
    `https://compute.googleapis.com/compute/v1/projects/${EXISTING_SPEC.project_id}` +
    `/zones/${EXISTING_SPEC.zone}/instances/${EXISTING_SPEC.name}-offload`;
  const diskPath =
    `/projects/${EXISTING_SPEC.project_id}/zones/${EXISTING_SPEC.zone}/disks/` +
    `${EXISTING_SPEC.name}-offload`;
  const diskUrl = `https://compute.googleapis.com/compute/v1${diskPath}`;
  const transport = new RecordingTransport((method, url, options) => {
    if (method === "GET" && url.endsWith("/global/images/sgs-nginx-20260824")) {
      return {
        status: 200,
        payload: {
          name: "sgs-nginx-20260824",
          id: SOURCE_IMAGE_BINDING.id,
          selfLink: SOURCE_IMAGE_BINDING.self_link,
        },
      };
    }
    if (method === "POST" && url.endsWith("/instances")) {
      instanceLive = {
        ...structuredClone(options.jsonBody ?? {}),
        id: "instance-1001",
        disks: [{ boot: true, source: diskUrl }],
      };
      return { status: 200, payload: {} };
    }
    if (method === "GET" && url === instanceUrl) {
      return instanceLive === null
        ? { status: 404, payload: {} }
        : { status: 200, payload: structuredClone(instanceLive) };
    }
    if (method === "GET" && url === diskUrl) {
      return {
        status: 200,
        payload: {
          name: `${EXISTING_SPEC.name}-offload`,
          status: "READY",
          selfLink: diskUrl,
          zone: `https://compute.googleapis.com/compute/v1/projects/${EXISTING_SPEC.project_id}/zones/${EXISTING_SPEC.zone}`,
          sizeGb: "20",
          type: `https://compute.googleapis.com/compute/v1/projects/${EXISTING_SPEC.project_id}/zones/${EXISTING_SPEC.zone}/diskTypes/pd-balanced`,
          sourceImage: `https://www.googleapis.com/compute/v1/${EXISTING_SPEC.source_image}`,
          sourceImageId: SOURCE_IMAGE_BINDING.id,
        },
      };
    }
    if (method === "GET" && url.includes("/addresses/")) {
      return { status: 200, payload: { address: "10.42.0.10" } };
    }
    if (method === "GET" && url.endsWith("/getGuestAttributes")) {
      readinessPolls += 1;
      if (readinessPolls === 1) return { status: 200, payload: {} };
      if (readinessPolls === 2) {
        return {
          status: 200,
          payload: evidencePayload(EXISTING_SPEC, "offload", { hash: "0".repeat(64) }),
        };
      }
      return { status: 200, payload: evidencePayload(EXISTING_SPEC, "offload") };
    }
    return { status: 200, payload: {} };
  });
  const store = new MemoryStore();
  const scheduler = new NullScheduler();
  const instance = change("instance", `${EXISTING_SPEC.name}-offload`);
  const initial = planRun({
    runId: "path-a-readiness",
    approvalId: "approval-path-a",
    configurationHash: configurationHash(EXISTING_SPEC),
    changes: [instance],
  });
  await store.save(initial);

  const snapshots: RunRecord[] = [];
  for (let attempt = 0; attempt < 3; attempt += 1) {
    // A new executor/engine represents a completely restarted service worker.
    const engine = new RunEngine(
      store,
      new GoogleResourceExecutor(transport, {
        operationPollIntervalMs: 0,
        maxOperationPolls: 1,
        sourceImageBinding: SOURCE_IMAGE_BINDING,
      }),
      scheduler,
    );
    snapshots.push(await engine.tick(initial.runId, EXISTING_SPEC));
  }
  const terminal = await new RunEngine(
    store,
    new GoogleResourceExecutor(transport, { sourceImageBinding: SOURCE_IMAGE_BINDING }),
    scheduler,
  ).tick(initial.runId, EXISTING_SPEC);

  const creates = transport.calls.filter(
    (call) => call.method === "POST" && call.url.endsWith("/instances"),
  );
  const addressCalls = transport.calls.filter(
    (call) => call.method === "GET" && call.url.includes("/addresses/"),
  );
  const scripts = creates.map((call) => {
    const metadata = (call.body?.metadata as { items?: Array<{ key?: string; value?: string }> })
      ?.items;
    return metadata?.find((item) => item.key === "startup-script")?.value ?? "";
  });
  check(
    "VM readiness resumes across worker restarts and accepts only the third valid poll",
    snapshots[0]?.steps[0]?.status === "pending" && snapshots[0]?.steps[0]?.attempts === 1 &&
      snapshots[1]?.steps[0]?.status === "pending" && snapshots[1]?.steps[0]?.attempts === 2 &&
      snapshots[2]?.steps[0]?.status === "done" && snapshots[2]?.steps[0]?.attempts === 3 &&
      terminal.state === "succeeded" && readinessPolls === 3,
    canonicalJson({ snapshots: snapshots.map((record) => record.steps[0]), terminal }),
  );
  check(
    "VM retries reuse the immutable created instance and never duplicate its POST",
    creates.length === 1 &&
      new Set(creates.map((call) => call.params?.requestId)).size === 1 &&
      creates.every((call) => call.params?.requestId === initial.steps[0]?.requestId),
    canonicalJson(creates.map((call) => call.params)),
  );
  check(
    "existing HTTP embeds existing_backend_url and never reads a backend-ip address",
    addressCalls.length === 3 &&
      addressCalls.every((call) => call.url.endsWith(`${EXISTING_SPEC.name}-offload-ip`)) &&
      scripts.every((script) => script.includes("proxy_pass http://10.20.0.10:8080;")) &&
      scripts.every((script) => !script.includes("10.42.0.20")),
    canonicalJson(addressCalls),
  );
}

// Dedicated Path A intentionally leaves vpc_name null; the application must
// point at the deterministic network the plan creates, never a literal
// `networks/null` path inherited from the Path B-only field.
{
  let applicationBody: Record<string, unknown> | undefined;
  const transport = new RecordingTransport((method, url, options) => {
    if (method === "GET" && url.endsWith("/global/images/sgs-nginx-20260824")) {
      return {
        status: 200,
        payload: {
          name: "sgs-nginx-20260824",
          id: SOURCE_IMAGE_BINDING.id,
          selfLink: SOURCE_IMAGE_BINDING.self_link,
        },
      };
    }
    if (method === "POST" && url.endsWith("/applications")) {
      applicationBody = structuredClone(options.jsonBody ?? {});
      return { status: 200, payload: { createTime: "2026-08-24T00:00:02Z" } };
    }
    if (method === "GET" && url.includes("/applications/")) {
      return {
        status: 200,
        payload: {
          ...(applicationBody ?? {}),
          name:
            `projects/${MANAGED_SPEC.project_id}/locations/global/securityGateways/` +
            `${MANAGED_SPEC.gateway_id}/applications/${MANAGED_SPEC.name}-app`,
          createTime: "2026-08-24T00:00:02Z",
        },
      };
    }
    return { status: 200, payload: {} };
  });
  await new GoogleResourceExecutor(transport, {
    sourceImageBinding: SOURCE_IMAGE_BINDING,
  }).apply(
    {
      provider: "beyondcorp",
      resource_type: "application",
      resource_name: `${MANAGED_SPEC.name}-app`,
      action: "create",
      risk: "high",
      summary: "Path A application",
      owned_after_apply: true,
      dependencies: [],
    },
    MANAGED_SPEC,
    { runId: "path-a-application", stepIndex: 0, requestId: REQUEST_ID },
  );
  const network = (
    (applicationBody?.upstreams as Array<{ network?: { name?: unknown } }> | undefined)?.[0]
      ?.network
  )?.name;
  check(
    "dedicated Path A application targets the deterministic created VPC",
    network ===
      `projects/${MANAGED_SPEC.project_id}/global/networks/${MANAGED_SPEC.name}-vpc`,
    canonicalJson({ network, applicationBody }),
  );
}

// Option B is a real extension path: verify its provider request shapes rather
// than only checking that the UI exposes the card.
{
  const cases = [
    { type: "subnetwork", name: `${ILB_SPEC.name}-proxy-subnet` },
    { type: "instance_group", name: `${ILB_SPEC.name}-backend-ig` },
    { type: "health_check", name: `${ILB_SPEC.name}-ilb-hc` },
    { type: "backend_service", name: `${ILB_SPEC.name}-ilb-bs` },
  ];
  const transport = new RecordingTransport((method, url) => {
    if (method === "POST" && url.endsWith("/listInstances")) {
      return {
        status: 200,
        payload: {
          items: [{
            instance: `https://www.googleapis.com/compute/v1/projects/${ILB_SPEC.project_id}` +
              `/zones/${ILB_SPEC.zone}/instances/${ILB_SPEC.name}-backend`,
          }],
        },
      };
    }
    return { status: 200, payload: {} };
  });
  for (const fixture of cases) {
    await applyPathA(context(transport), change(fixture.type, fixture.name), ILB_SPEC);
  }
  const bodies = transport.calls.map((call) => call.body ?? {});
  check(
    "Option B emits proxy-only subnet semantics",
    bodies.some((body) => body.purpose === "REGIONAL_MANAGED_PROXY" &&
      body.role === "ACTIVE" && body.ipCidrRange === "10.42.1.0/24" &&
      body.privateIpGoogleAccess === false),
    canonicalJson(transport.calls),
  );
  check(
    "Option B creates and populates a zonal HTTP instance group",
    transport.calls.some((call) => call.url.endsWith(`/zones/${ILB_SPEC.zone}/instanceGroups`)) &&
      transport.calls.some((call) => call.url.endsWith("/addInstances") &&
        call.params?.requestId !== REQUEST_ID),
    canonicalJson(transport.calls),
  );
  check(
    "Option B uses HTTP health and INTERNAL_MANAGED backend semantics",
    bodies.some((body) => body.type === "HTTP" &&
      canonicalJson(body.httpHealthCheck) === canonicalJson({
        portSpecification: "USE_SERVING_PORT", requestPath: "/",
      })) &&
      bodies.some((body) => body.loadBalancingScheme === "INTERNAL_MANAGED" &&
        body.protocol === "HTTP" && body.portName === "http"),
    canonicalJson(transport.calls),
  );
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} Path A check(s)\n`);
  for (const failure of failures) console.error(`  ${failure}\n`);
  process.exit(1);
}
console.log(`OK ${passed} Path A request/readiness checks.`);
