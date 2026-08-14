/**
 * Discovery parity against the Python reference.
 *
 * Replays each recorded scenario through the ported discovery provider and
 * compares both halves of the contract:
 *
 *   - the request sequence, because a probe the extension skips is an existing
 *     resource it will then try to create, and
 *   - the assembled snapshot, because that is what decides whether a gate
 *     passes and therefore whether Apply is offered.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-discovery.ts
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve as resolvePath } from "node:path";

import { canonicalJson } from "../src/domain/canonical.ts";
import { GoogleDiscoveryProvider } from "../src/providers/discovery.ts";
import type { Transport } from "../src/providers/executor.ts";
import { parseDeploymentSpec } from "../src/domain/spec.ts";

interface RecordedRequest {
  method: string;
  url: string;
  params: Record<string, string | number> | null;
  body: Record<string, unknown> | null;
}

interface Scenario {
  name: string;
  spec: Record<string, unknown>;
  requests: RecordedRequest[];
  snapshot: Record<string, unknown>;
}

const goldenPath = resolvePath(
  dirname(fileURLToPath(import.meta.url)),
  "../../backend/tests/fixtures/discovery/golden.json",
);

const ENABLED = [
  "accesscontextmanager.googleapis.com",
  "admin.googleapis.com",
  "beyondcorp.googleapis.com",
  "chromemanagement.googleapis.com",
  "chromepolicy.googleapis.com",
  "cloudbilling.googleapis.com",
  "cloudresourcemanager.googleapis.com",
  "compute.googleapis.com",
  "iamcredentials.googleapis.com",
  "licensing.googleapis.com",
  "logging.googleapis.com",
  "serviceusage.googleapis.com",
];

/** Mirrors the Python RecordingTransport's fixed environment. */
class ReplayTransport implements Transport {
  readonly calls: RecordedRequest[] = [];
  // Explicit fields rather than parameter properties: Node's strip-only type
  // removal cannot desugar those, and the parity checks must keep running
  // with no build step.
  private readonly globalAccess: boolean | null;
  private readonly matcherIp: string | null;

  constructor(globalAccess: boolean | null, matcherIp: string | null) {
    this.globalAccess = globalAccess;
    this.matcherIp = matcherIp;
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

    if (url.includes("serviceusage.googleapis.com")) {
      return {
        status: 200,
        payload: { services: ENABLED.map((name) => ({ config: { name } })) },
      };
    }
    if (url.endsWith(":testIamPermissions")) {
      return {
        status: 200,
        payload: { permissions: (options.jsonBody?.permissions as string[]) ?? [] },
      };
    }
    if (url.includes("cloudbilling.googleapis.com")) {
      return { status: 200, payload: { billingEnabled: true } };
    }
    if (url.includes("/aggregated/forwardingRules")) {
      if (this.matcherIp === null || this.globalAccess === null) {
        return { status: 200, payload: { items: {} } };
      }
      return {
        status: 200,
        payload: {
          items: {
            "regions/asia-east1": {
              forwardingRules: [
                {
                  name: "app-ilb-fr",
                  IPAddress: this.matcherIp,
                  allowGlobalAccess: this.globalAccess,
                },
              ],
            },
          },
        },
      };
    }
    if (url.includes("/global/networks/")) {
      return { status: 200, payload: { name: url.split("/").pop() ?? "" } };
    }
    if (url.includes("accesscontextmanager.googleapis.com")) {
      return {
        status: 200,
        payload: { name: "accessPolicies/123456789/accessLevels/managed_chrome" },
      };
    }
    if (url.includes("/securityGateways/")) {
      return { status: 404, payload: {} };
    }
    if (
      url.includes("chromepolicy") ||
      url.includes("chromemanagement") ||
      url.includes("licensing") ||
      url.includes("admin.googleapis.com")
    ) {
      return { status: 200, payload: {} };
    }
    return { status: 404, payload: {} };
  }
}

const SETTINGS: Record<string, { globalAccess: boolean | null; matcherIp: string | null }> = {
  "global-access-enabled": { globalAccess: true, matcherIp: "10.20.0.10" },
  "global-access-disabled": { globalAccess: false, matcherIp: "10.20.0.10" },
  "fqdn-matcher-unresolvable": { globalAccess: null, matcherIp: null },
  "cross-project-upstream": { globalAccess: true, matcherIp: "10.20.0.10" },
};

const golden = JSON.parse(readFileSync(goldenPath, "utf8")) as { scenarios: Scenario[] };
const failures: string[] = [];
let comparedRequests = 0;

for (const scenario of golden.scenarios) {
  const spec = parseDeploymentSpec(scenario.spec);
  const settings = SETTINGS[scenario.name];
  const transport = new ReplayTransport(settings.globalAccess, settings.matcherIp);
  const provider = new GoogleDiscoveryProvider(transport, {
    cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
  });

  const result = await provider.preflight(spec);

  if (transport.calls.length !== scenario.requests.length) {
    failures.push(
      `${scenario.name}: request count ${scenario.requests.length} vs ${transport.calls.length}\n` +
        `    python    ${scenario.requests.map((r) => `${r.method} ${r.url}`).join("\n              ")}\n` +
        `    extension ${transport.calls.map((r) => `${r.method} ${r.url}`).join("\n              ")}`,
    );
  } else {
    for (const [index, expected] of scenario.requests.entries()) {
      const produced = transport.calls[index];
      comparedRequests += 1;
      if (expected.method !== produced.method || expected.url !== produced.url) {
        failures.push(
          `${scenario.name} request[${index}]: target\n` +
            `    python    ${expected.method} ${expected.url}\n` +
            `    extension ${produced.method} ${produced.url}`,
        );
        continue;
      }
      if (canonicalJson(expected.params ?? null) !== canonicalJson(produced.params ?? null)) {
        failures.push(
          `${scenario.name} request[${index}]: params\n` +
            `    python    ${canonicalJson(expected.params ?? null)}\n` +
            `    extension ${canonicalJson(produced.params ?? null)}`,
        );
      }
      if (canonicalJson(expected.body ?? null) !== canonicalJson(produced.body ?? null)) {
        failures.push(
          `${scenario.name} request[${index}]: body\n` +
            `    python    ${canonicalJson(expected.body ?? null)}\n` +
            `    extension ${canonicalJson(produced.body ?? null)}`,
        );
      }
    }
  }

  // Snapshot fields the planner actually reads. Comparing the whole object
  // would also assert on fields Path B never populates.
  for (const field of [
    "existing_resource_keys",
    "conflicting_resource_keys",
    "enabled_apis",
    "granted_permissions",
    "billing_enabled",
    "cloud_identity",
    "application_global_access",
    "application_forwarding_rule",
    "chrome_extension_group_conflicts",
    "chrome_enterprise_premium_license_count",
    "managed_chrome_profile_count",
    "secure_enterprise_browser_installed",
    "endpoint_verification_installed",
  ]) {
    const expected = scenario.snapshot[field] ?? null;
    const produced = (result.snapshot as Record<string, unknown>)[field] ?? null;
    if (canonicalJson(expected) !== canonicalJson(produced)) {
      failures.push(
        `${scenario.name} snapshot.${field}\n` +
          `    python    ${canonicalJson(expected)}\n` +
          `    extension ${canonicalJson(produced)}`,
      );
    }
  }
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} difference(s)\n`);
  for (const failure of failures.slice(0, 10)) console.error(`  ${failure}\n`);
  if (failures.length > 10) console.error(`  ... and ${failures.length - 10} more`);
  process.exit(1);
}
console.log(
  `OK ${golden.scenarios.length} scenarios, ${comparedRequests} requests and their ` +
    "snapshots match the Python reference.",
);
