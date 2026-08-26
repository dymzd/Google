/** Release checks for run-scoped teardown planning. */

import {
  assertTeardownSnapshotIntegrity,
  buildTeardownExecutionSnapshot,
  buildTeardownPlan,
  teardownInstructionHash,
  type DeploymentResource,
} from "../src/domain/teardown.ts";
import { teardownImmutableDigest } from "../src/storage/repository.ts";
import { canonicalDigestSync } from "../src/domain/canonical.ts";

const gatewayCreateRequestId = "b636157b-5c63-4278-b84e-89ad31b54c81";
const gatewayResourceUrl =
  "https://beyondcorp.googleapis.com/v1/projects/enterprise-secgw-01/locations/global/" +
  "securityGateways/default";

const inventory: DeploymentResource[] = [
  {
    resourceKey: "serviceusage:project_services:required-apis",
    provider: "serviceusage",
    resourceType: "project_services",
    resourceName: "required-apis",
    owned: false,
    shared: true,
  },
  {
    resourceKey: "cloudresourcemanager:project_iam:upstream-access",
    provider: "cloudresourcemanager",
    resourceType: "project_iam",
    resourceName: "upstream-access",
    owned: false,
    shared: true,
    beforeImage: { kind: "iam", policy: { etag: "before" } },
    requestId: "apply-request-iam",
  },
  {
    resourceKey: "compute:network:owned-vpc",
    provider: "compute",
    resourceType: "network",
    resourceName: "owned-vpc",
    owned: true,
    shared: false,
    requestId: "apply-request-network",
  },
  {
    resourceKey: "beyondcorp:security_gateway:default",
    provider: "beyondcorp",
    resourceType: "security_gateway",
    resourceName: "default",
    owned: false,
    shared: true,
    requestId: gatewayCreateRequestId,
    beforeImage: {
      kind: "generic_created_resource",
      protocolVersion: 2,
      phase: "applied",
      resourceKey: "beyondcorp:security_gateway:default",
      createUrl: gatewayResourceUrl.slice(0, gatewayResourceUrl.lastIndexOf("/")),
      resourceUrl: gatewayResourceUrl,
      createRequestId: gatewayCreateRequestId,
      expectedParamsDigest: canonicalDigestSync({
        securityGatewayId: "default",
        requestId: gatewayCreateRequestId,
      }),
      expectedPayloadDigest: canonicalDigestSync({
        displayName: "default",
        serviceDiscovery: {},
        logging: {},
      }),
      ownershipMarker: null,
      providerIdentityField: "createTime",
      providerIdentity: "2026-08-24T00:00:01Z",
    },
  },
  {
    resourceKey: "local:root_certificate_artifact:demo-poc-root",
    provider: "local",
    resourceType: "root_certificate_artifact",
    resourceName: "demo-poc-root",
    owned: true,
    shared: false,
  },
];

const first = buildTeardownPlan("run-1", "config-1", "demo", inventory);
const actionByKey = new Map(
  [...first.resources, ...first.retained_resources].map((item) => [
    item.resource_key,
    item.teardown_action,
  ]),
);

const failures: string[] = [];
function check(name: string, condition: boolean): void {
  if (!condition) failures.push(name);
}

check(
  "owned resources are deleted",
  actionByKey.get("compute:network:owned-vpc") === "delete",
);
check(
  "an exact finalized shared default-gateway CREATE is deleted only when empty",
  actionByKey.get("beyondcorp:security_gateway:default") === "delete_if_empty",
);

const snapshot = buildTeardownExecutionSnapshot("run-1", "config-1", inventory);
check(
  "destructive request ids are deterministic UUIDs",
  snapshot.every((item) =>
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      .test(item.requestId)) &&
    JSON.stringify(snapshot) === JSON.stringify(
      buildTeardownExecutionSnapshot("run-1", "config-1", inventory),
    ),
);
check(
  "plan binds the full canonical before-image content",
  buildTeardownPlan("run-1", "config-1", "demo", inventory.map((item) =>
    item.resourceType === "project_iam"
      ? { ...item, beforeImage: { kind: "iam", policy: { etag: "tampered" } } }
      : item)).plan_hash !== first.plan_hash,
);

for (const [field, mutate] of [
  ["provider", (item: typeof snapshot[number]) => ({ ...item, provider: "tampered" })],
  ["type", (item: typeof snapshot[number]) => ({ ...item, resourceType: "firewall_rule" })],
  ["name", (item: typeof snapshot[number]) => ({ ...item, resourceName: "other" })],
  ["owned", (item: typeof snapshot[number]) => ({ ...item, owned: !item.owned })],
  ["shared", (item: typeof snapshot[number]) => ({ ...item, shared: !item.shared })],
  ["action", (item: typeof snapshot[number]) => ({ ...item, action: "retain" as const })],
  ["requestId", (item: typeof snapshot[number]) => ({
    ...item,
    requestId: "00000000-0000-4000-8000-000000000000",
  })],
] as const) {
  const tampered = structuredClone(snapshot);
  tampered[0] = mutate(tampered[0]!);
  let rejected = false;
  try {
    assertTeardownSnapshotIntegrity({
      runId: "run-1",
      configurationHash: "config-1",
      planHash: first.plan_hash,
      instructions: tampered,
    });
  } catch {
    rejected = true;
  }
  check(`tampered ${field} is rejected before execution`, rejected);
}

const tamperedBeforeImage = structuredClone(snapshot);
tamperedBeforeImage[0]!.beforeImage = { kind: "iam", policy: { etag: "changed" } };
let beforeImageRejected = false;
try {
  assertTeardownSnapshotIntegrity({
    runId: "run-1",
    configurationHash: "config-1",
    planHash: first.plan_hash,
    instructions: tamperedBeforeImage,
  });
} catch {
  beforeImageRejected = true;
}
check("tampered before-image is rejected before execution", beforeImageRejected);

const durable = {
  teardownId: "td-1",
  runId: "run-1",
  configurationHash: "config-1",
  planHash: teardownInstructionHash("run-1", "config-1", snapshot),
  instructions: snapshot,
};
check(
  "durable immutable digest changes with its instruction snapshot",
  teardownImmutableDigest(durable) !== teardownImmutableDigest({
    ...durable,
    instructions: tamperedBeforeImage,
  }),
);
check(
  "shared mutations are restored from their before-image",
  actionByKey.get("cloudresourcemanager:project_iam:upstream-access") === "restore",
);
check(
  "shared resources that were only reused are retained",
  actionByKey.get("serviceusage:project_services:required-apis") === "retain",
);
check(
  "operator-installed local trust anchors are retained",
  actionByKey.get("local:root_certificate_artifact:demo-poc-root") === "retain",
);
check("restore operations participate in the hash-bound executable plan", first.resources.length === 3);
check(
  "a reused default gateway without creation provenance is retained",
  buildTeardownPlan("run-reuse", "config-1", "demo", [{
    resourceKey: "beyondcorp:security_gateway:default",
    provider: "beyondcorp",
    resourceType: "security_gateway",
    resourceName: "default",
    owned: false,
    shared: true,
  }]).retained_resources[0]?.teardown_action === "retain",
);
check(
  "confirmation is bound to the current inventory",
  buildTeardownPlan("run-1", "config-1", "demo", [inventory[0], inventory[2]]).plan_hash !==
    first.plan_hash,
);

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} teardown safety check(s)`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}

console.log("OK teardown safety checks passed.");
