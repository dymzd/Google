/**
 * Spec parity check.
 *
 * Rebuilds every specification in the planner golden set through the ported
 * validator and confirms two things:
 *
 *   1. the spec round-trips to the same JSON the Python model produced, and
 *   2. its `configuration_hash` matches, which is what approvals bind to.
 *
 * The second is the one that matters. A spec that serialises differently
 * produces a different hash, and the extension would then build plans the
 * Python implementation refuses to approve.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-spec.ts
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { canonicalDigest } from "../src/domain/canonical.ts";
import {
  applicationHostname,
  applicationPort,
  parseDeploymentSpec,
  specToJson,
  upstreamProjectId,
} from "../src/domain/spec.ts";

interface GoldenCase {
  name: string;
  spec: Record<string, unknown>;
  configuration_hash: string;
}

const here = dirname(fileURLToPath(import.meta.url));
const goldenPath = resolve(here, "../../backend/tests/fixtures/planner/golden.json");

function diffKeys(
  expected: Record<string, unknown>,
  produced: Record<string, unknown>,
): string[] {
  const notes: string[] = [];
  const keys = new Set([...Object.keys(expected), ...Object.keys(produced)]);
  for (const key of [...keys].sort()) {
    const a = JSON.stringify(expected[key]);
    const b = JSON.stringify(produced[key]);
    if (a !== b) notes.push(`      ${key}: python=${a} extension=${b}`);
  }
  return notes;
}

async function main(): Promise<void> {
  const golden = JSON.parse(readFileSync(goldenPath, "utf8")) as { cases: GoldenCase[] };
  const failures: string[] = [];

  for (const testCase of golden.cases) {
    let produced: Record<string, unknown>;
    try {
      const spec = parseDeploymentSpec(testCase.spec);
      produced = specToJson(spec);

      // Derived properties feed the matcher and the upstream binding.
      if (spec.backend_kind === "direct_https") {
        const host = applicationHostname(spec);
        const port = applicationPort(spec);
        if (!host) failures.push(`${testCase.name}: application hostname resolved empty`);
        if (!Number.isInteger(port)) {
          failures.push(`${testCase.name}: application port is not an integer`);
        }
        if (!upstreamProjectId(spec)) {
          failures.push(`${testCase.name}: upstream project resolved empty`);
        }
      }
    } catch (error) {
      failures.push(`${testCase.name}: rejected a spec Python accepted -- ${(error as Error).message}`);
      continue;
    }

    const notes = diffKeys(testCase.spec, produced);
    if (notes.length > 0) {
      failures.push(`${testCase.name}: serialised spec differs\n${notes.join("\n")}`);
      continue;
    }

    // canonical_configuration_hash sorts platforms then hashes the payload.
    const hashPayload = { ...produced, platforms: [...(produced.platforms as string[])].sort() };
    const digest = await canonicalDigest(hashPayload);
    if (digest !== testCase.configuration_hash) {
      failures.push(
        `${testCase.name}: configuration_hash differs\n` +
          `    expected ${testCase.configuration_hash}\n` +
          `    produced ${digest}`,
      );
    }
  }

  const enterpriseCase = golden.cases.find(
    (testCase) => testCase.spec.certificate_strategy === "enterprise_ca",
  );
  if (enterpriseCase === undefined) {
    failures.push("golden set has no enterprise CA specification");
  } else {
    for (const [label, patch] of [
      [
        "cross-project CA pool",
        { ca_pool: "projects/other-project/locations/asia-east1/caPools/enterprise" },
      ],
      [
        "authority outside selected pool",
        {
          ca_name:
            "projects/enterprise-secgw-01/locations/asia-east1/caPools/other/" +
            "certificateAuthorities/issuing",
        },
      ],
      [
        "authority name with query",
        {
          ca_name:
            "projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise/" +
            "certificateAuthorities/issuing?alt=json",
        },
      ],
    ] as const) {
      try {
        parseDeploymentSpec({ ...enterpriseCase.spec, ...patch });
        failures.push(`${label}: unsafe CA resource name was accepted`);
      } catch {
        // Expected: provider URLs and authority selection stay project/pool scoped.
      }
    }
  }

  if (enterpriseCase !== undefined) {
    try {
      parseDeploymentSpec({
        ...enterpriseCase.spec,
        mode: "production",
        backend_kind: "internal_https_lb",
        test_ou_confirmed: true,
        chrome_enterprise_premium_license_confirmed: true,
        workspace_services_confirmed: true,
        endpoint_verification_confirmed: true,
      });
      failures.push("production ILB: unsupported 0.2.1 architecture was accepted");
    } catch {
      // Expected: Production ILB needs durable versioned certificate/proxy rotation first.
    }
  }

  if (failures.length > 0) {
    console.error(`FAIL ${failures.length} problem(s) across ${golden.cases.length} cases\n`);
    for (const failure of failures) console.error(`  ${failure}`);
    process.exit(1);
  }

  console.log(`OK ${golden.cases.length} specs round-trip and hash identically.`);
}

await main();
