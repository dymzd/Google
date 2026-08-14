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
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { canonicalJson } from "../src/domain/canonical.ts";
import { GoogleResourceExecutor, type Transport } from "../src/providers/executor.ts";
import { parseDeploymentSpec } from "../src/domain/spec.ts";
import type { ResourceChange } from "../src/domain/planner.ts";

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

    if (method === "GET" && url.includes("/addresses/")) {
      const suffix = url.includes("-backend-ip") ? "20" : "10";
      return { status: 200, payload: { address: `10.42.0.${suffix}` } };
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

function withoutRequestId(
  params: Record<string, string | number> | null,
): Record<string, string | number> | null {
  if (params === null) return null;
  const { requestId, ...rest } = params;
  void requestId;
  return Object.keys(rest).length === 0 ? null : rest;
}

const PINNED_CERTIFICATE = {
  certificatePem: "-----BEGIN CERTIFICATE-----\nUElOTkVE\n-----END CERTIFICATE-----\n",
  certificateChainPem: ["-----BEGIN CERTIFICATE-----\nQ0hBSU4=\n-----END CERTIFICATE-----\n"],
  privateKeyPem: "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n",
  hostname: "demo-server-http.internal",
  issuerResourceName: null,
};

const golden = JSON.parse(readFileSync(goldenPath, "utf8")) as { scenarios: Scenario[] };
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
    const transport = new ReplayTransport();
    const executor = new GoogleResourceExecutor(transport, {
      // The same pinned bundle the Python generator injects; issuance produces
      // a fresh key each run and would make the recorded payload unstable.
      certificate: PINNED_CERTIFICATE,
      exportArtifact: async () => {},
    });

    try {
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
        canonicalJson(withoutRequestId(expected.params)) !==
        canonicalJson(withoutRequestId(produced.params))
      ) {
        failures.push(
          `${label} request[${index}]: params\n` +
            `    python    ${canonicalJson(withoutRequestId(expected.params))}\n` +
            `    extension ${canonicalJson(withoutRequestId(produced.params))}`,
        );
      }
      if (canonicalJson(expected.body ?? null) !== canonicalJson(produced.body ?? null)) {
        failures.push(
          `${label} request[${index}]: body\n` +
            `    python    ${canonicalJson(expected.body ?? null)}\n` +
            `    extension ${canonicalJson(produced.body ?? null)}`,
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
    `Python reference (${excluded} excluded).`,
);
