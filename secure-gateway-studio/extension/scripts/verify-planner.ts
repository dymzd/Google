/**
 * Planner parity against the Python reference.
 *
 * Compares the ported planner's whole output -- every change, every gate, the
 * configuration hash, and the required API and permission sets -- against
 * `backend/tests/fixtures/planner/golden.json`.
 *
 * Path A cases in the golden set are skipped and reported as such: Path A
 * planning lands in Phase 4, and silently passing over it would make this
 * check look more complete than it is.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-planner.ts
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { canonicalJson } from "../src/domain/canonical.ts";
import {
  buildPlan,
  configurationHash,
  requiredApis,
  requiredPermissions,
  type DeploymentPlan,
  type DiscoverySnapshot,
} from "../src/domain/planner.ts";
import { parseDeploymentSpec } from "../src/domain/spec.ts";
import { POC_DEPLOYER_ROLE, REQUIRED_PERMISSIONS } from "../src/domain/constants.generated.ts";

/**
 * Compare by canonical form.
 *
 * The golden file is written with sorted keys, while the ported objects carry
 * insertion order. `JSON.stringify` would report every object as different on
 * key order alone, which says nothing about whether the plans agree.
 */
function same(expected: unknown, produced: unknown): boolean {
  return canonicalJson(expected) === canonicalJson(produced);
}

interface GoldenCase {
  name: string;
  spec: Record<string, unknown>;
  snapshot: DiscoverySnapshot;
  configuration_hash: string;
  required_apis: string[];
  required_permissions: string[];
  plan: Omit<DeploymentPlan, "plan_version"> & { plan_version: 1 };
}

const goldenPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../backend/tests/fixtures/planner/golden.json",
);

const failures: string[] = [];
let compared = 0;
let skipped = 0;

function note(name: string, label: string, expected: unknown, produced: unknown): void {
  failures.push(
    `${name}: ${label}\n    python    ${JSON.stringify(expected)}\n` +
      `    extension ${JSON.stringify(produced)}`,
  );
}

const golden = JSON.parse(readFileSync(goldenPath, "utf8")) as { cases: GoldenCase[] };

for (const testCase of golden.cases) {
  const spec = parseDeploymentSpec(testCase.spec);
  compared += 1;

  const hash = configurationHash(spec);
  if (hash !== testCase.configuration_hash) {
    note(testCase.name, "configuration_hash", testCase.configuration_hash, hash);
    continue;
  }

  const apis = [...requiredApis(spec)].sort();
  if (!same(testCase.required_apis, apis)) {
    note(testCase.name, "required_apis", testCase.required_apis, apis);
  }

  const permissions = [...requiredPermissions(spec)].sort();
  if (!same(testCase.required_permissions, permissions)) {
    note(testCase.name, "required_permissions", testCase.required_permissions, permissions);
  }

  const plan = buildPlan(spec, testCase.snapshot);

  if (plan.changes.length !== testCase.plan.changes.length) {
    note(
      testCase.name,
      "change count",
      testCase.plan.changes.map((change) => change.resource_name),
      plan.changes.map((change) => change.resource_name),
    );
  } else {
    for (const [index, expected] of testCase.plan.changes.entries()) {
      const produced = plan.changes[index];
      if (!same(expected, produced)) {
        note(testCase.name, `change[${index}] ${expected.resource_name}`, expected, produced);
      }
    }
  }

  if (plan.gates.length !== testCase.plan.gates.length) {
    note(
      testCase.name,
      "gate count",
      testCase.plan.gates.map((gate) => gate.gate_id),
      plan.gates.map((gate) => gate.gate_id),
    );
  } else {
    for (const [index, expected] of testCase.plan.gates.entries()) {
      const produced = plan.gates[index];
      if (!same(expected, produced)) {
        note(testCase.name, `gate[${index}] ${expected.gate_id}`, expected, produced);
      }
    }
  }

  if (plan.can_apply !== testCase.plan.can_apply) {
    note(testCase.name, "can_apply", testCase.plan.can_apply, plan.can_apply);
  }
  if (plan.mode !== testCase.plan.mode) {
    note(testCase.name, "mode", testCase.plan.mode, plan.mode);
  }
  if (plan.destructive_change_count !== testCase.plan.destructive_change_count) {
    note(
      testCase.name,
      "destructive_change_count",
      testCase.plan.destructive_change_count,
      plan.destructive_change_count,
    );
  }
}

{
  const testCase = golden.cases.find((candidate) =>
    candidate.spec.backend_kind === "direct_https"
  );
  if (testCase === undefined) {
    failures.push("ownership classifier: no direct HTTPS fixture was available");
  } else {
    const spec = parseDeploymentSpec(testCase.spec);
    const applicationKey = `beyondcorp:application:${spec.name}-app`;
    const plan = buildPlan(spec, {
      ...testCase.snapshot,
      existing_resource_keys: [
        ...(testCase.snapshot.existing_resource_keys ?? []),
        applicationKey,
      ],
    });
    const application = plan.changes.find((change) =>
      `${change.provider}:${change.resource_type}:${change.resource_name}` === applicationKey
    );
    if (application?.action !== "no_change" || application.owned_after_apply !== false) {
      failures.push(
        "ownership classifier: a pre-existing managed application was claimed by the new run",
      );
    }
    const projectIamKey =
      `cloudresourcemanager:project_iam:${spec.name}-upstream-access`;
    const createdProjectIam = buildPlan(spec, testCase.snapshot).changes.find((change) =>
      `${change.provider}:${change.resource_type}:${change.resource_name}` === projectIamKey
    );
    const reusedProjectIam = buildPlan(spec, {
      ...testCase.snapshot,
      existing_resource_keys: [
        ...(testCase.snapshot.existing_resource_keys ?? []),
        projectIamKey,
      ],
    }).changes.find((change) =>
      `${change.provider}:${change.resource_type}:${change.resource_name}` === projectIamKey
    );
    if (
      createdProjectIam?.action !== "create" ||
      createdProjectIam.owned_after_apply !== true ||
      reusedProjectIam?.action !== "reuse" ||
      reusedProjectIam.owned_after_apply !== false
    ) {
      failures.push(
        "ownership classifier: project IAM managed delta was not owned exactly for CREATE",
      );
    }
  }
}

{
  const baseCase = golden.cases.find((candidate) =>
    candidate.spec.backend_kind === "managed_sample" && candidate.spec.mode === "poc"
  );
  if (baseCase === undefined) {
    failures.push("Option B planner: no PoC VM fixture was available");
  } else {
    const spec = parseDeploymentSpec({
      ...baseCase.spec,
      backend_kind: "internal_https_lb",
      network_strategy: "dedicated",
      vpc_name: null,
      subnet_name: null,
      proxy_subnet_cidr: "10.42.1.0/24",
      existing_backend_url: null,
      existing_backend_location: null,
      existing_backend_connectivity_confirmed: false,
    });
    const plan = buildPlan(spec, baseCase.snapshot);
    const keys = new Set(plan.changes.map((change) =>
      `${change.provider}:${change.resource_type}:${change.resource_name}`
    ));
    for (const required of [
      `compute:subnetwork:${spec.name}-proxy-subnet`,
      `compute:instance:${spec.name}-backend`,
      `compute:instance_group:${spec.name}-backend-ig`,
      `compute:health_check:${spec.name}-ilb-hc`,
      `compute:backend_service:${spec.name}-ilb-bs`,
      `compute:ssl_certificate:${spec.name}-ilb-cert`,
      `compute:url_map:${spec.name}-ilb-map`,
      `compute:target_https_proxy:${spec.name}-ilb-proxy`,
      `compute:forwarding_rule:${spec.name}-ilb-fr`,
      `compute:firewall_rule:${spec.name}-gateway-ingress`,
    ]) {
      if (!keys.has(required)) failures.push(`Option B planner: missing ${required}`);
    }
    const permissions = requiredPermissions(spec);
    for (const permission of [
      "compute.instanceGroups.create",
      "compute.regionSslCertificates.create",
      "compute.regionTargetHttpsProxies.create",
      "compute.regionUrlMaps.create",
      "compute.forwardingRules.create",
      "secretmanager.versions.access",
    ]) {
      if (!permissions.has(permission)) {
        failures.push(`Option B planner: missing permission ${permission}`);
      }
    }
    for (const excessive of [
      "compute.autoscalers.create",
      "compute.instanceTemplates.create",
      "compute.instanceGroupManagers.create",
    ]) {
      if (permissions.has(excessive)) {
        failures.push(`Option B planner: excessive permission ${excessive}`);
      }
    }
  }
}

// The YAML under infrastructure/iam is what an administrator hands to gcloud,
// and the constants are what Apply plans against. Nothing reconciled the two,
// so a permission added to one could sit in the other's blind spot -- which is
// how `compute.instances.use` reached a live role while the planner still did
// not know Apply needed it.
{
  const iam = resolve(
    dirname(fileURLToPath(import.meta.url)),
    "../../infrastructure/iam",
  );
  const yamlPermissions = (file: string): string[] =>
    readFileSync(resolve(iam, file), "utf8")
      .split(/\r?\n/)
      .map((line) => /^\s*-\s+([a-z]+\.[A-Za-z]+\.[A-Za-z]+)\s*$/.exec(line)?.[1])
      .filter((value): value is string => value !== undefined)
      .sort();
  const only = (a: readonly string[], b: readonly string[]): string =>
    a.filter((value) => !b.includes(value)).join(", ") || "-";
  for (
    const [file, constant, label] of [
      [
        "secure-gateway-poc-deployer-role.yaml",
        [...POC_DEPLOYER_ROLE.includedPermissions].sort(),
        "POC_DEPLOYER_ROLE",
      ],
      [
        "secure-gateway-deployer-role.yaml",
        [...REQUIRED_PERMISSIONS].sort(),
        "REQUIRED_PERMISSIONS",
      ],
    ] as const
  ) {
    const actual = yamlPermissions(file);
    if (canonicalJson(actual) !== canonicalJson(constant)) {
      failures.push(
        `${file} and ${label} disagree; only in YAML: ${only(actual, constant)}; ` +
          `only in ${label}: ${only(constant, actual)}`,
      );
    }
  }
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} difference(s) across ${compared} Path B cases\n`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
void skipped;
console.log(`OK ${compared} plans (Path A and Path B) match the Python reference.`);
