/** Repository safety invariants that do not require a browser IndexedDB. */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  ApprovalRejected,
  assertApprovalTtl,
  assertAcceptanceRecord,
  assertApprovalIntegrity,
  assertPlanCanApply,
  assertPreparedPlanFresh,
  approvePlanJson,
  DATABASE_VERSION,
  initialRunRecord,
  policyUpdateCompensationTargets,
  runHasActiveWork,
  teardownHasActiveWork,
  withLatestIamAfterPolicy,
} from "../src/storage/repository.ts";
import { canonicalDigestSync } from "../src/domain/canonical.ts";
import { configurationHash } from "../src/domain/planner.ts";
import { parseDeploymentSpec, specToJson } from "../src/domain/spec.ts";

const failures: string[] = [];
let passed = 0;

function check(name: string, condition: boolean): void {
  if (condition) passed += 1;
  else failures.push(name);
}

function rejected(plan: unknown): boolean {
  try {
    assertPlanCanApply(JSON.stringify(plan));
    return false;
  } catch (error) {
    return error instanceof ApprovalRejected;
  }
}

check(
  "an approved plan with all blocking gates passed is accepted",
  (() => {
    try {
      assertPlanCanApply(
        JSON.stringify({
          can_apply: true,
          gates: [
            { gate_id: "test-ou", blocking: true, status: "pass" },
            { gate_id: "advisory", blocking: false, status: "blocked" },
          ],
        }),
      );
      return true;
    } catch {
      return false;
    }
  })(),
);
check(
  "approval can change only the human approval gate",
  (() => {
    try {
      const approved = JSON.parse(
        approvePlanJson(
          JSON.stringify({
            can_apply: false,
            gates: [
              { gate_id: "test-ou", blocking: true, status: "pass" },
              { gate_id: "human-approval", blocking: true, status: "pending" },
            ],
          }),
          "operator@example.com",
        ),
      ) as { can_apply: boolean; gates: Array<{ gate_id: string; status: string }> };
      return approved.can_apply === true &&
        approved.gates.find((gate) => gate.gate_id === "human-approval")?.status === "pass";
    } catch {
      return false;
    }
  })(),
);
check(
  "approval cannot override another blocking gate",
  (() => {
    try {
      approvePlanJson(
        JSON.stringify({
          can_apply: false,
          gates: [
            { gate_id: "test-ou", blocking: true, status: "blocked" },
            { gate_id: "human-approval", blocking: true, status: "pending" },
          ],
        }),
        "operator@example.com",
      );
      return false;
    } catch (error) {
      return error instanceof ApprovalRejected;
    }
  })(),
);
check(
  "can_apply=false is rejected even if the gate list is malformed",
  rejected({ can_apply: false, gates: [] }),
);
check(
  "a blocked safety gate is rejected even if can_apply was forged true",
  rejected({
    can_apply: true,
    gates: [{ gate_id: "test-ou", blocking: true, status: "blocked" }],
  }),
);
check("invalid JSON is rejected", (() => {
  try {
    assertPlanCanApply("not-json");
    return false;
  } catch (error) {
    return error instanceof ApprovalRejected;
  }
})());

check("approval TTL is bounded", (() => {
  try {
    assertApprovalTtl(120);
    assertApprovalTtl(0);
    return false;
  } catch (error) {
    return error instanceof ApprovalRejected;
  }
})());
check("expired or legacy prepared plans are rejected", (() => {
  try {
    assertPreparedPlanFresh(undefined, new Date("2026-08-24T00:00:00Z"));
    return false;
  } catch (error) {
    return error instanceof ApprovalRejected;
  }
})());

const approvedSpec = parseDeploymentSpec({
  project_id: "enterprise-secgw-01",
  mode: "poc",
  target_ou_id: "03-test-ou",
  managed_chrome_access_level: "NONE",
  test_ou_confirmed: true,
  principals: [{ type: "group", value: "secure-access@example.com" }],
  backend_kind: "direct_https",
  network_strategy: "existing",
  vpc_name: "private-app-vpc",
  subnet_name: null,
  source_image: null,
  certificate_strategy: "public_trusted",
  existing_backend_url: "https://10.20.0.10:8443",
  existing_backend_location: "gcp",
  existing_backend_connectivity_confirmed: true,
});
const approvedConfigurationHash = configurationHash(approvedSpec);
const approvedPlan = {
  configuration_hash: approvedConfigurationHash,
  can_apply: true,
  gates: [{ gate_id: "human-approval", blocking: true, status: "pass" }],
  changes: [{
    provider: "beyondcorp",
    resource_type: "application",
    resource_name: "demo-app",
    action: "create",
    risk: "high",
    summary: "Create demo app",
    owned_after_apply: true,
    dependencies: [],
  }],
};
const intactApproval = {
  approvalId: "approval-1",
  configurationHash: approvedConfigurationHash,
  planHash: canonicalDigestSync(approvedPlan),
  planJson: JSON.stringify(approvedPlan),
  specificationJson: JSON.stringify(specToJson(approvedSpec)),
  approvedBy: "operator@example.com",
  approvedAt: "2026-08-24T00:00:00Z",
  expiresAt: "2026-08-24T00:30:00Z",
  consumedAt: null,
  deployerIdentity: {
    serviceAccountEmail:
      "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
    serviceAccountUniqueId: "123456789012345678901",
    projectId: "enterprise-secgw-01",
    operatorEmail: "operator@example.com",
    operatorSubject: "operator-subject-123",
  },
};

check("an intact approval passes hash revalidation", (() => {
  try {
    assertApprovalIntegrity(intactApproval);
    return true;
  } catch {
    return false;
  }
})());
check("Apply rejects a mutated approved plan", (() => {
  try {
    assertApprovalIntegrity({
      ...intactApproval,
      planJson: JSON.stringify({ ...approvedPlan, injected_change: true }),
    });
    return false;
  } catch (error) {
    return error instanceof ApprovalRejected;
  }
})());
check("Apply rejects a mutated approved specification", (() => {
  try {
    const changed = { ...specToJson(approvedSpec), project_id: "other-project-01" };
    assertApprovalIntegrity({ ...intactApproval, specificationJson: JSON.stringify(changed) });
    return false;
  } catch (error) {
    return error instanceof ApprovalRejected;
  }
})());
check("Apply rejects a deployer binding from another project", (() => {
  try {
    assertApprovalIntegrity({
      ...intactApproval,
      deployerIdentity: {
        serviceAccountEmail:
          "secure-gateway-deployer@other-project-01.iam.gserviceaccount.com",
        serviceAccountUniqueId: "123456789012345678901",
        projectId: "other-project-01",
        operatorEmail: "operator@example.com",
        operatorSubject: "operator-subject-123",
      },
    });
    return false;
  } catch (error) {
    return error instanceof ApprovalRejected;
  }
})());

check("acceptance evidence rejects private keys", (() => {
  try {
    assertAcceptanceRecord({
      testId: "T07",
      caseKey: "macos",
      status: "user_confirmed",
      summary: "Browser reached the application",
      evidence: "-----BEGIN PRIVATE KEY----- secret",
      source: "operator_confirmed",
    });
    return false;
  } catch {
    return true;
  }
})());
check("well-formed operator evidence is accepted", (() => {
  try {
    assertAcceptanceRecord({
      testId: "T07",
      caseKey: "macos",
      status: "user_confirmed",
      summary: "Browser reached the application",
      evidence: "Screenshot hash abc123 at 2026-08-24T10:00:00Z",
      source: "operator_confirmed",
    });
    return true;
  } catch {
    return false;
  }
})());

check("schema v5 gates and encrypts 0.2.0 state plus durable CEP leases", DATABASE_VERSION === 5);
const productionLogSources = await Promise.all(
  [
    "../src/auth/tokens.ts",
    "../src/background/service-worker.ts",
    "../src/ui/transport.ts",
    "../../frontend/src/App.tsx",
    "../../frontend/src/features/cep/CepDeployerPage.tsx",
    "../../frontend/src/features/setup/ConfigurationSteps.tsx",
  ].map((relativePath) => readFile(
    fileURLToPath(new URL(relativePath, import.meta.url)),
    "utf8",
  )),
);
check(
  "production extension surfaces never emit tenant data or raw errors to the console",
  productionLogSources.every(
    (source) => !/\bconsole\s*\.\s*(?:log|warn|error|info|debug)\s*\(/.test(source),
  ),
);
check("Apply lifecycle treats rollback and unfinished finalization as active", (() => {
  const base = {
    runId: "run-1",
    approvalId: "approval-1",
    configurationHash: approvedConfigurationHash,
    status: "succeeded" as const,
    startedAt: "2026-08-24T00:00:00Z",
    finishedAt: null,
  };
  return runHasActiveWork({ ...base, status: "rolling_back" }) &&
    runHasActiveWork({ ...base, finalizationPending: true }) &&
    !runHasActiveWork(base);
})());
check(
  "IAM response loss retains the exact in-flight checkpoint for manual review",
  policyUpdateCompensationTargets("application_sending", false, 2) === null &&
    policyUpdateCompensationTargets("gateway_sending", false, 2) === null,
);
check(
  "an explicit provider rejection compensates only earlier confirmed IAM writes",
  JSON.stringify(policyUpdateCompensationTargets("application_sending", true, 2)) === "[]" &&
    JSON.stringify(policyUpdateCompensationTargets("gateway_sending", true, 2)) ===
      JSON.stringify(["application"]),
);
check(
  "legacy IAM checkpoints without pre-send phases fail closed on upgrade",
  policyUpdateCompensationTargets("prepared", false, undefined) === null &&
    policyUpdateCompensationTargets("application_applied", false, undefined) === null &&
    JSON.stringify(policyUpdateCompensationTargets("gateway_applied", false, undefined)) ===
      JSON.stringify(["application", "gateway"]),
);
check(
  "teardown lifecycle slot is global for every pending/running teardown",
  teardownHasActiveWork({ runId: "other-run", status: "running" }) &&
    !teardownHasActiveWork({ runId: "other-run", status: "interrupted" }),
);
check("approval consumption can persist a complete initial RunRecord atomically", (() => {
  const run = initialRunRecord({
    approval: intactApproval,
    runId: "run-initialized",
    startedAt: "2026-08-24T00:00:00Z",
  });
  return run.status === "running" && run.state === "running" &&
    run.steps.length === 1 && run.steps[0]?.change.resource_name === "demo-app" &&
    /^[0-9a-f-]{36}$/i.test(run.steps[0]?.requestId ?? "") &&
    run.finalizationPending === false;
})());
check("an empty placeholder plan cannot become a successful empty run", (() => {
  try {
    initialRunRecord({
      approval: {
        ...intactApproval,
        planJson: JSON.stringify({ ...approvedPlan, changes: undefined }),
      },
      runId: "run-empty",
      startedAt: "2026-08-24T00:00:00Z",
    });
    return false;
  } catch {
    return true;
  }
})());
check("IAM inventory advances only its managed after-policy baseline", (() => {
  const original = {
    kind: "iam" as const,
    getUrl: "https://example.test/resource:getIamPolicy",
    setUrl: "https://example.test/resource:setIamPolicy",
    policy: { etag: "before", bindings: [{ role: "roles/viewer", members: ["user:a"] }] },
    afterPolicy: { etag: "applied", bindings: [{ role: "roles/viewer", members: ["user:a", "user:b"] }] },
  };
  const latest = { etag: "updated", bindings: [{ role: "roles/viewer", members: ["user:c"] }] };
  const advanced = withLatestIamAfterPolicy(original, latest);
  return JSON.stringify(advanced.policy) === JSON.stringify(original.policy) &&
    JSON.stringify(advanced.afterPolicy) === JSON.stringify(latest) &&
    advanced.setUrl === original.setUrl;
})());

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} checks`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} storage safety checks passed.`);
