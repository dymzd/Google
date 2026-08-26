/**
 * Executor parity against the Python reference.
 *
 * Replays every recorded scenario through the ported executor and compares the
 * request sequence -- method, URL, params, and body -- against
 * `backend/tests/fixtures/executor/golden.json`.
 *
 * This is the check that catches what plan comparison cannot: a reordered IAM
 * read/write, a dropped etag, a missing egress policy, or the wrong project in
 * an upstream network path.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-executor.ts
 */

import { readFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { canonicalJson } from "../src/domain/canonical.ts";
import { GoogleResourceExecutor, type Transport } from "../src/providers/executor.ts";
import { parseDeploymentSpec } from "../src/domain/spec.ts";
import { configurationHash, type ResourceChange } from "../src/domain/planner.ts";
import {
  crc32c,
  issueLocalPoc,
  secretPayload,
} from "../src/providers/certificates.ts";
import { sha256Hex } from "../src/domain/sha256.ts";

interface RecordedRequest {
  method: string;
  url: string;
  params: Record<string, string | number> | null;
  body: Record<string, unknown> | null;
}

interface Operation {
  change: { provider: string; resource_type: string; resource_name: string };
  requests: RecordedRequest[];
}

interface Scenario {
  name: string;
  spec: Record<string, unknown>;
  operations: Operation[];
}

const goldenPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../backend/tests/fixtures/executor/golden.json",
);

/** Replays the responses the Python recording transport returned. */
class ReplayTransport implements Transport {
  readonly calls: RecordedRequest[] = [];
  private readonly expectedConfigurationHash: string;
  private readonly expectedHostname: string;
  private readonly publicCertificatePayload: Uint8Array | null;
  private readonly genericResources = new Map<string, Record<string, unknown>>();
  private genericIdentity = 1000;

  constructor(
    expectedConfigurationHash: string,
    expectedHostname: string,
    publicCertificatePayload: Uint8Array | null = null,
  ) {
    this.expectedConfigurationHash = expectedConfigurationHash;
    this.expectedHostname = expectedHostname;
    this.publicCertificatePayload = publicCertificatePayload;
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

    if (method === "GET" && url.includes("/orgunits/id%3A")) {
      return {
        status: 200,
        payload: { orgUnitId: "id:03-test-ou", orgUnitPath: "/Secure Gateway Test" },
      };
    }
    if (method === "GET" && url.endsWith("/global/images/sgs-nginx-20260730")) {
      return {
        status: 200,
        payload: {
          name: "sgs-nginx-20260730",
          id: "987654321",
          selfLink: (
            "https://www.googleapis.com/compute/v1/projects/" +
            "enterprise-secgw-01/global/images/sgs-nginx-20260730"
          ),
        },
      };
    }
    if (method === "POST" && url.endsWith("/listManagedInstances")) {
      return {
        status: 200,
        payload: {
          managedInstances: [
            {
              instance: (
                "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
                "zones/asia-east1-c/instances/secure-gateway-http-offload-offload-a1"
              ),
              instanceStatus: "RUNNING",
            },
            {
              instance: (
                "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
                "zones/asia-east1-a/instances/secure-gateway-http-offload-offload-a2"
              ),
              instanceStatus: "RUNNING",
            },
          ],
        },
      };
    }
    if (
      method === "GET" && url.includes("/zones/") &&
      url.includes("/instances/secure-gateway-http-offload-offload-")
    ) {
      const zone = url.split("/zones/")[1]?.split("/")[0] ?? "";
      const instanceName = url.split("/").pop() ?? "";
      return {
        status: 200,
        payload: {
          name: instanceName,
          disks: [{
            boot: true,
            source: (
              "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
              `zones/${zone}/disks/${instanceName}`
            ),
          }],
        },
      };
    }
    if (method === "POST" && /\/managedZones\/[^/]+\/changes$/.test(url)) {
      return {
        status: 200,
        payload: { kind: "dns#change", id: "42", status: "done" },
      };
    }

    const stored = this.genericResources.get(url);
    if (method === "GET" && stored !== undefined) {
      const payload = structuredClone(stored);
      if (url.includes("/instances/")) {
        const instanceName = url.split("/").pop()!;
        payload.disks = [{
          boot: true,
          source: (
            "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
            `zones/asia-east1-c/disks/${instanceName}`
          ),
        }];
      }
      if (url.includes("/addresses/")) {
        payload.address = url.includes("-backend-ip") ? "10.42.0.20" : "10.42.0.10";
      }
      if (url.includes("/instanceGroupManagers/")) {
        payload.status = { isStable: true, currentInstanceStatuses: { running: 2 } };
        payload.targetSize = 2;
      }
      if (url.includes("/securityGateways/") && !url.includes("/applications/")) {
        payload.state = "RUNNING";
        payload.delegatingServiceAccount =
          "sg-delegate@enterprise-secgw-01.iam.gserviceaccount.com";
      }
      return { status: 200, payload };
    }

    if (method === "GET" && url.includes("/zones/") && url.includes("/disks/")) {
      const zone = url.split("/zones/")[1]?.split("/")[0] ?? "";
      const diskName = url.split("/").pop()!;
      const diskPath =
        `projects/enterprise-secgw-01/zones/${zone}/disks/${diskName}`;
      return {
        status: 200,
        payload: {
          name: diskName,
          selfLink: `https://www.googleapis.com/compute/v1/${diskPath}`,
          zone: (
            "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
            `zones/${zone}`
          ),
          status: "READY",
          sizeGb: "20",
          type: (
            "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
            `zones/${zone}/diskTypes/pd-balanced`
          ),
          sourceImage: (
            "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
            "global/images/sgs-nginx-20260730"
          ),
          sourceImageId: "987654321",
        },
      };
    }

    if (
      method === "POST" &&
      (url.includes("compute.googleapis.com") || url.includes("beyondcorp.googleapis.com")) &&
      !url.endsWith(":setIamPolicy")
    ) {
      const resourceName = options.jsonBody?.name ?? options.params?.securityGatewayId ??
        options.params?.applicationId;
      if (typeof resourceName === "string") {
        const resourceUrl = `${url.replace(/\/$/, "")}/${resourceName}`;
        this.genericIdentity += 1;
        const payload = structuredClone(options.jsonBody ?? {});
        if (url.includes("compute.googleapis.com")) {
          Object.assign(payload, {
            id: String(this.genericIdentity),
            selfLink: resourceUrl,
            creationTimestamp: "2026-08-24T00:00:00.000Z",
          });
        } else {
          Object.assign(payload, {
            name: resourceUrl.replace("https://beyondcorp.googleapis.com/v1/", ""),
            createTime: `2026-08-24T00:00:${String(this.genericIdentity % 60).padStart(2, "0")}Z`,
          });
        }
        this.genericResources.set(resourceUrl, payload);
      }
    }

    if (method === "GET" && url.includes("/addresses/")) {
      const suffix = url.includes("-backend-ip") ? "20" : "10";
      return { status: 200, payload: { address: `10.42.0.${suffix}` } };
    }
    if (method === "GET" && url.includes("/routers/")) {
      return {
        status: 200,
        payload: {
          id: "9000000000000000001",
          selfLink: url,
          fingerprint: "router-fingerprint-1",
          nats: [],
        },
      };
    }
    if (method === "GET" && url.endsWith("/getGuestAttributes")) {
      return {
        status: 200,
        payload: {
          queryValue: {
            items: [
              {
                namespace: "sgstudio",
                key: "T01",
                value: JSON.stringify({
                  status: 200,
                  configuration_hash: this.expectedConfigurationHash,
                }),
              },
              {
                namespace: "sgstudio",
                key: "T02",
                value: JSON.stringify({
                  status: 200,
                  configuration_hash: this.expectedConfigurationHash,
                }),
              },
              {
                namespace: "sgstudio",
                key: "T03",
                value: JSON.stringify({
                  http_status: 200,
                  tls_version: "TLSv1.3",
                  hostname: this.expectedHostname,
                  trust_mode: this.publicCertificatePayload === null
                    ? "presented_chain_pinned"
                    : "public_system_roots",
                  subject_alt_names: [this.expectedHostname],
                  configuration_hash: this.expectedConfigurationHash,
                }),
              },
            ],
          },
        },
      };
    }
    if (method === "POST" && url.endsWith(":addVersion")) {
      return {
        status: 200,
        payload: {
          name:
            "projects/enterprise-secgw-01/secrets/secure-gateway-http-offload-tls/versions/1",
        },
      };
    }
    if (
      method === "GET" &&
      url.endsWith("/secrets/enterprise-tls/versions/latest:access") &&
      this.publicCertificatePayload !== null
    ) {
      return {
        status: 200,
        payload: {
          name: "projects/enterprise-secgw-01/secrets/enterprise-tls/versions/7",
          payload: {
            data: Buffer.from(this.publicCertificatePayload).toString("base64"),
            dataCrc32c: String(crc32c(this.publicCertificatePayload)),
          },
        },
      };
    }
    if (method === "GET" && url.includes("/secrets/") && !url.endsWith(":getIamPolicy")) {
      return { status: 200, payload: { etag: "secret-etag", versionAliases: {}, labels: {} } };
    }
    if (method === "GET" && url.includes("/instanceGroupManagers/")) {
      return {
        status: 200,
        payload: {
          status: { isStable: true, currentInstanceStatuses: { running: 2 } },
          targetSize: 2,
        },
      };
    }
    if (url.endsWith("/getHealth")) {
      return {
        status: 200,
        payload: { healthStatus: [{ healthState: "HEALTHY" }, { healthState: "HEALTHY" }] },
      };
    }
    if (url.endsWith(":getIamPolicy")) {
      return {
        status: 200,
        payload: {
          version: 1,
          etag: "before-etag",
          bindings: [{ role: "roles/viewer", members: ["user:owner@example.com"] }],
        },
      };
    }
    if (method === "GET" && url.includes("/securityGateways/") && !url.includes("/applications")) {
      return {
        status: 200,
        payload: {
          name: "projects/enterprise-secgw-01/locations/global/securityGateways/default",
          state: "RUNNING",
          delegatingServiceAccount:
            "sg-delegate@enterprise-secgw-01.iam.gserviceaccount.com",
        },
      };
    }
    if (url.includes("/policySchemas/")) {
      const schemaName = url.split("/").pop() ?? "";
      const field = schemaName.endsWith("SimpleProxySettings")
        ? "simpleProxyMode"
        : schemaName.endsWith("ManagedConfiguration")
          ? "managedConfiguration"
          : "appInstallType";
      return {
        status: 200,
        payload: {
          schemaName,
          definition: { messageType: [{ name: "Policy", field: [{ name: field }] }] },
        },
      };
    }
    if (url.endsWith("/policies:resolve")) {
      return { status: 200, payload: { resolvedPolicies: [] } };
    }
    return { status: 200, payload: {} };
  }
}

function change(operation: Operation): ResourceChange {
  return {
    provider: operation.change.provider,
    resource_type: operation.change.resource_type,
    resource_name: operation.change.resource_name,
    action: "create",
    risk: "high",
    summary: "fixture",
    owned_after_apply: true,
    dependencies: [],
  };
}

/**
 * Resource types whose handlers are not ported yet.
 *
 * The Production instance template and the certificate-issuing types depend on
 * the WebCrypto work. Named here rather than skipped silently, and the run
 * prints how many were excluded so the check cannot look more complete than it
 * is.
 */
const NOT_PORTED = new Set<string>();

/**
 * `requestId` is an idempotency token, not a value the two implementations are
 * meant to agree on: Python derives it from a per-process UUID, the extension
 * persists one per run step so a retry after a service-worker restart presents
 * the same token. Compared for presence and shape instead of equality.
 */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UUID_FRAGMENT = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

function withoutRequestId(
  params: Record<string, string | number> | null,
): Record<string, string | number> | null {
  if (params === null) return null;
  const { requestId, ...rest } = params;
  void requestId;
  return Object.keys(rest).length === 0 ? null : rest;
}

/**
 * Ownership tokens are stable within one implementation's durable run, but
 * the Python fixture generator and the extension intentionally use different
 * run ids. Preserve the surrounding marker and compare only the UUID's shape.
 */
function normaliseOwnershipTokens(value: unknown, key = ""): unknown {
  if (Array.isArray(value)) return value.map((item) => normaliseOwnershipTokens(item));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([childKey, child]) => [
        childKey,
        normaliseOwnershipTokens(child, childKey),
      ]),
    );
  }
  if (typeof value !== "string") return value;
  if (key === "data") {
    try {
      const decoded = JSON.parse(Buffer.from(value, "base64").toString("utf8")) as unknown;
      if (
        typeof decoded === "object" && decoded !== null && !Array.isArray(decoded) &&
        "sgs_ownership_token" in decoded
      ) {
        return normaliseOwnershipTokens(decoded, "secret-payload");
      }
    } catch {
      // Ordinary binary/base64 fields remain byte-for-byte compared.
    }
  }
  if (key === "clientOperationId" || key === "sgs-owner-token") {
    return UUID.test(value) ? "<ownership-uuid>" : value;
  }
  if (key === "sgs_ownership_token") {
    return UUID.test(value) ? "<ownership-uuid>" : value;
  }
  if (value.includes("ownership-token=") || value.includes("sgs-owner=")) {
    return value.replace(UUID_FRAGMENT, "<ownership-uuid>");
  }
  return value;
}

/**
 * The shared Python fixture still carries Router.fingerprint, which the
 * current Compute v1 Router schema no longer defines. Keep every other byte of
 * the cross-runtime fixture comparison strict while requiring the extension's
 * live PATCH body to follow the official schema.
 */
function officialExpectedBody(request: RecordedRequest): Record<string, unknown> | null {
  if (
    request.method === "PATCH" &&
    /^https:\/\/compute\.googleapis\.com\/compute\/v1\/projects\/[^/]+\/regions\/[^/]+\/routers\/[^/]+$/.test(
      request.url,
    ) &&
    request.body !== null
  ) {
    const { fingerprint: _obsoleteFingerprint, ...body } = request.body;
    return body;
  }
  return request.body;
}

const PINNED_CERTIFICATE = {
  certificatePem: "-----BEGIN CERTIFICATE-----\nUElOTkVE\n-----END CERTIFICATE-----\n",
  certificateChainPem: ["-----BEGIN CERTIFICATE-----\nQ0hBSU4=\n-----END CERTIFICATE-----\n"],
  privateKeyPem: "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n",
  hostname: "demo-server-http.internal",
  issuerResourceName: null,
};

const golden = JSON.parse(readFileSync(goldenPath, "utf8")) as { scenarios: Scenario[] };
const publicCertificateBytes = new TextEncoder().encode(
  secretPayload(await issueLocalPoc("gw.example-company.com", 30)),
);
let excluded = 0;
const failures: string[] = [];
let comparedRequests = 0;

for (const scenario of golden.scenarios) {
  const spec = parseDeploymentSpec(scenario.spec);

  for (const operation of scenario.operations) {
    const label = `${scenario.name}/${operation.change.resource_type}`;
    if (NOT_PORTED.has(operation.change.resource_type)) {
      excluded += 1;
      continue;
    }
    const consumesPublicCertificate =
      spec.backend_kind !== "direct_https" && spec.certificate_strategy === "public_trusted";
    const transport = new ReplayTransport(
      configurationHash(spec),
      spec.private_hostname,
      consumesPublicCertificate ? publicCertificateBytes : null,
    );
    const executor = new GoogleResourceExecutor(transport, {
      // The same pinned bundle the Python generator injects; issuance produces
      // a fresh key each run and would make the recorded payload unstable.
      certificate: PINNED_CERTIFICATE,
      publicCertificateBinding: consumesPublicCertificate
        ? {
            secret_version_name:
              "projects/enterprise-secgw-01/secrets/enterprise-tls/versions/7",
            payload_sha256: sha256Hex(publicCertificateBytes),
          }
        : null,
      sourceImageBinding: spec.backend_kind === "direct_https"
        ? null
        : {
            name: spec.source_image!,
            id: "987654321",
            self_link: `https://www.googleapis.com/compute/v1/${spec.source_image!}`,
          },
      exportArtifact: async () => {},
    });

    try {
      await executor.prepareApply(spec);
      await executor.apply(change(operation), spec);
    } catch (error) {
      failures.push(`${label}: threw ${(error as Error).message}`);
      continue;
    }

    if (transport.calls.length !== operation.requests.length) {
      failures.push(
        `${label}: request count\n` +
          `    python    ${operation.requests.map((r) => `${r.method} ${r.url}`).join("\n              ")}\n` +
          `    extension ${transport.calls.map((r) => `${r.method} ${r.url}`).join("\n              ")}`,
      );
      continue;
    }

    for (const [index, expected] of operation.requests.entries()) {
      const produced = transport.calls[index];
      comparedRequests += 1;
      if (expected.method !== produced.method || expected.url !== produced.url) {
        failures.push(
          `${label} request[${index}]: target\n` +
            `    python    ${expected.method} ${expected.url}\n` +
            `    extension ${produced.method} ${produced.url}`,
        );
        continue;
      }
      const expectedId = expected.params?.requestId;
      const producedId = produced.params?.requestId;
      if (expectedId !== undefined && (typeof producedId !== "string" || !UUID.test(producedId))) {
        failures.push(
          `${label} request[${index}]: requestId missing or malformed\n` +
            `    extension ${String(producedId)}`,
        );
      }
      if (
        canonicalJson(normaliseOwnershipTokens(withoutRequestId(expected.params))) !==
        canonicalJson(normaliseOwnershipTokens(withoutRequestId(produced.params)))
      ) {
        failures.push(
          `${label} request[${index}]: params\n` +
            `    python    ${canonicalJson(normaliseOwnershipTokens(withoutRequestId(expected.params)))}\n` +
            `    extension ${canonicalJson(normaliseOwnershipTokens(withoutRequestId(produced.params)))}`,
        );
      }
      if (
        canonicalJson(normaliseOwnershipTokens(officialExpectedBody(expected))) !==
        canonicalJson(normaliseOwnershipTokens(produced.body ?? null))
      ) {
        failures.push(
          `${label} request[${index}]: body\n` +
            `    reference ${canonicalJson(normaliseOwnershipTokens(officialExpectedBody(expected)))}\n` +
            `    extension ${canonicalJson(normaliseOwnershipTokens(produced.body ?? null))}`,
        );
      }
    }
  }
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} difference(s)\n`);
  for (const failure of failures.slice(0, 12)) console.error(`  ${failure}\n`);
  if (failures.length > 12) console.error(`  ... and ${failures.length - 12} more`);
  process.exit(1);
}
console.log(
  `OK ${golden.scenarios.length} scenarios, ${comparedRequests} requests match the ` +
    `Python reference after the documented Compute Router schema correction ` +
    `(${excluded} excluded).`,
);
