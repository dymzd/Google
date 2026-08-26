/** Conditional IAM read/modify/write safety checks. */

import {
  replaceOwnedIamBinding,
  revertIamPolicyDelta,
  validatedIamPolicy,
} from "../src/domain/iam-policy.ts";

const oldCondition = { title: "Managed", expression: "'old' in request.auth.access_levels" };
const nextCondition = { expression: "'new' in request.auth.access_levels", title: "Managed" };
const otherCondition = { title: "Break glass", expression: "request.time < timestamp('2030-01-01T00:00:00Z')" };
const updated = replaceOwnedIamBinding({
  policy: {
    version: 3,
    etag: "etag-1",
    bindings: [
      {
        role: "roles/beyondcorp.sgApplicationUser",
        members: ["group:old@example.com", "group:shared@example.com"],
        condition: oldCondition,
      },
      {
        role: "roles/beyondcorp.sgApplicationUser",
        members: ["group:break-glass@example.com"],
        condition: otherCondition,
      },
      { role: "roles/viewer", members: ["user:auditor@example.com"] },
    ],
  },
  role: "roles/beyondcorp.sgApplicationUser",
  previousCondition: oldCondition,
  targetCondition: nextCondition,
  previousMembers: new Set(["group:old@example.com"]),
  targetMembers: new Set(["group:new@example.com"]),
});

const bindings = updated.bindings as Array<Record<string, unknown>>;
const failures: string[] = [];
let passed = 0;
function check(name: string, condition: boolean): void {
  if (condition) passed += 1;
  else failures.push(name);
}

check("etag is retained", updated.etag === "etag-1");
check("policy v3 is mandatory", updated.version === 3);
check(
  "only previously owned members are removed",
  bindings.some(
    (binding) =>
      (binding.condition as { expression?: string } | undefined)?.expression ===
        oldCondition.expression &&
      JSON.stringify(binding.members) === JSON.stringify(["group:shared@example.com"]),
  ),
);
check(
  "target condition receives the replacement member",
  bindings.some(
    (binding) =>
      (binding.condition as { expression?: string } | undefined)?.expression ===
        nextCondition.expression &&
      JSON.stringify(binding.members) === JSON.stringify(["group:new@example.com"]),
  ),
);
check(
  "other conditions survive",
  bindings.some(
    (binding) =>
      (binding.condition as { title?: string } | undefined)?.title === "Break glass",
  ),
);
check("other roles survive", bindings.some((binding) => binding.role === "roles/viewer"));

const reverted = revertIamPolicyDelta({
  beforePolicy: {
    version: 3,
    etag: "before",
    bindings: [
      {
        role: "roles/beyondcorp.sgApplicationUser",
        members: ["group:run@example.com", "group:shared@example.com"],
        condition: oldCondition,
      },
      { role: "roles/viewer", members: ["user:owner@example.com"] },
    ],
  },
  afterPolicy: {
    version: 3,
    etag: "after",
    bindings: [
      {
        role: "roles/beyondcorp.sgApplicationUser",
        members: ["group:shared@example.com"],
        condition: oldCondition,
      },
      {
        role: "roles/beyondcorp.sgApplicationUser",
        members: ["group:replacement@example.com"],
        condition: nextCondition,
      },
      { role: "roles/viewer", members: ["user:owner@example.com"] },
    ],
  },
  currentPolicy: {
    version: 3,
    etag: "fresh",
    auditConfigs: [{ service: "allServices" }],
    bindings: [
      {
        role: "roles/beyondcorp.sgApplicationUser",
        members: ["group:shared@example.com", "group:concurrent-old@example.com"],
        condition: oldCondition,
      },
      {
        role: "roles/beyondcorp.sgApplicationUser",
        members: ["group:replacement@example.com", "group:concurrent-new@example.com"],
        condition: nextCondition,
      },
      {
        role: "roles/beyondcorp.sgApplicationUser",
        members: ["group:break-glass@example.com"],
        condition: otherCondition,
      },
      {
        role: "roles/viewer",
        members: ["user:owner@example.com", "user:concurrent@example.com"],
      },
      { role: "roles/editor", members: ["user:new-admin@example.com"] },
    ],
  },
});
const revertedBindings = reverted.bindings as Array<Record<string, unknown>>;
check(
  "three-way rollback reverses only this run while preserving concurrent IAM edits",
  reverted.etag === "fresh" &&
    Array.isArray(reverted.auditConfigs) &&
    revertedBindings.some(
      (binding) =>
        (binding.condition as { expression?: string } | undefined)?.expression ===
          oldCondition.expression &&
        JSON.stringify(binding.members) === JSON.stringify([
          "group:concurrent-old@example.com",
          "group:run@example.com",
          "group:shared@example.com",
        ]),
    ) &&
    revertedBindings.some(
      (binding) =>
        (binding.condition as { expression?: string } | undefined)?.expression ===
          nextCondition.expression &&
        JSON.stringify(binding.members) === JSON.stringify(["group:concurrent-new@example.com"]),
    ) &&
    revertedBindings.some((binding) => binding.role === "roles/editor") &&
    revertedBindings.some(
      (binding) =>
        binding.role === "roles/viewer" &&
        (binding.members as string[]).includes("user:concurrent@example.com"),
    ) &&
    revertedBindings.some(
      (binding) =>
        (binding.condition as { title?: string } | undefined)?.title === "Break glass",
    ),
);

let malformedRejected = false;
try {
  replaceOwnedIamBinding({
    policy: { bindings: [{ role: "roles/test", members: "not-an-array" }] },
    role: "roles/test",
    previousMembers: new Set(),
    targetMembers: new Set(),
  });
} catch {
  malformedRejected = true;
}
check("malformed policies fail closed", malformedRejected);

let unrelatedMalformedRejected = false;
try {
  replaceOwnedIamBinding({
    policy: {
      bindings: [
        { role: "roles/target", members: ["user:target@example.com"] },
        { role: "roles/unrelated", members: "not-an-array" },
      ],
    },
    role: "roles/target",
    previousMembers: new Set(),
    targetMembers: new Set(["user:new@example.com"]),
  });
} catch {
  unrelatedMalformedRejected = true;
}
check(
  "malformed unrelated bindings fail before a live policy is re-sent",
  unrelatedMalformedRejected,
);

let malformedConditionRejected = false;
try {
  replaceOwnedIamBinding({
    policy: {
      bindings: [
        {
          role: "roles/unrelated",
          members: ["user:other@example.com"],
          condition: { title: "Missing expression" },
        },
      ],
    },
    role: "roles/target",
    previousMembers: new Set(),
    targetMembers: new Set(["user:new@example.com"]),
  });
} catch {
  malformedConditionRejected = true;
}
check("malformed unrelated IAM conditions fail closed", malformedConditionRejected);

const located = validatedIamPolicy({
  version: 3,
  etag: "etag-location",
  bindings: [{
    role: "roles/test",
    members: ["user:a@example.com"],
    condition: {
      title: "Located",
      expression: "request.time < timestamp('2030-01-01T00:00:00Z')",
      description: "Preserve this expression metadata",
      location: "policies/test:7",
    },
  }],
  auditConfigs: [{
    service: "allServices",
    auditLogConfigs: [{
      logType: "DATA_READ",
      exemptedMembers: ["user:auditor@example.com"],
    }],
  }],
});
check(
  "legal Expr.location and strict audit configs are preserved exactly",
  ((located.bindings as Array<{ condition?: { location?: string } }>)[0]?.condition?.location ===
    "policies/test:7") && Array.isArray(located.auditConfigs),
);

for (const [name, policy] of [
  ["missing etag", { version: 3, bindings: [] }],
  ["unknown policy field", { version: 3, etag: "e", bindings: [], unknown: true }],
  ["unknown binding field", {
    version: 3, etag: "e", bindings: [{ role: "roles/test", members: [], unknown: true }],
  }],
  ["duplicate member", {
    version: 3,
    etag: "e",
    bindings: [{ role: "roles/test", members: ["user:a", "user:a"] }],
  }],
  ["empty members", {
    version: 3,
    etag: "e",
    bindings: [{ role: "roles/test", members: [] }],
  }],
  ["duplicate role and condition", {
    version: 3,
    etag: "e",
    bindings: [
      { role: "roles/test", members: ["user:a"] },
      { role: "roles/test", members: ["user:b"] },
    ],
  }],
  ["unknown condition field", {
    version: 3,
    etag: "e",
    bindings: [{
      role: "roles/test",
      members: ["user:a"],
      condition: { title: "t", expression: "true", unknown: "x" },
    }],
  }],
  ["malformed audit configs", {
    version: 3,
    etag: "e",
    bindings: [],
    auditConfigs: [{ service: "allServices", auditLogConfigs: "DATA_READ" }],
  }],
  ["whitespace-only role", {
    version: 3, etag: "e", bindings: [{ role: "   ", members: ["user:a"] }],
  }],
  ["whitespace-only member", {
    version: 3, etag: "e", bindings: [{ role: "roles/test", members: ["  "] }],
  }],
  ["whitespace-only condition expression", {
    version: 3,
    etag: "e",
    bindings: [{
      role: "roles/test",
      members: ["user:a"],
      condition: { title: "condition", expression: "   " },
    }],
  }],
  ["whitespace-only audit service", {
    version: 3,
    etag: "e",
    bindings: [],
    auditConfigs: [{ service: "   " }],
  }],
] as const) {
  let rejected = false;
  try {
    validatedIamPolicy(policy);
  } catch {
    rejected = true;
  }
  check(`${name} is rejected before IAM mutation`, rejected);
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} IAM policy safety check(s)`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} IAM policy safety checks passed.`);
