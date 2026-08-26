/**
 * Release-safety checks for the resumable Google execution path.
 *
 * These checks use the public executor and run-engine interfaces. Google is the
 * only mocked boundary; no implementation methods are reached into directly.
 */

import {
  canonicalSecretVersionUrl,
  GoogleApiError,
  GoogleResourceExecutor,
  type Transport,
} from "../src/providers/executor.ts";
import {
  enterpriseCertificateId,
  issueEnterpriseCa,
  issueLocalPoc,
} from "../src/providers/certificates.ts";
import { buildPlan, type ResourceChange } from "../src/domain/planner.ts";
import { parseDeploymentSpec } from "../src/domain/spec.ts";
import {
  bootstrapDeployer,
  legacyDeployerIdentityFromStoredState,
  type BootstrapOptions,
  type BootstrapOwnershipCheckpoint,
} from "../src/providers/bootstrap.ts";
import { POC_DEPLOYER_ROLE } from "../src/domain/constants.generated.ts";
import { EXTENSION_DEPLOYER_ROLE } from "../src/domain/extension-deployer-role.ts";
import {
  resourceRecordsForPlan,
  runAuditTransitions,
  type RunRecord,
} from "../src/runtime/run-engine.ts";
import { withLatestIamAfterPolicy } from "../src/storage/repository.ts";
import { canonicalDigestSync } from "../src/domain/canonical.ts";
import { compensationCapability } from "../src/domain/compensation.ts";
import { ConnectionError } from "../src/providers/catalog.ts";

const POST_020_ROLE_PERMISSIONS = new Set([
  "beyondcorp.securityGateways.list",
  "beyondcorp.sgApplications.list",
  "compute.autoscalers.create",
  "compute.autoscalers.delete",
  "compute.autoscalers.get",
  "compute.disks.get",
  "compute.forwardingRules.list",
  "compute.instanceGroupManagers.create",
  "compute.instanceGroupManagers.delete",
  "compute.instanceGroupManagers.get",
  "compute.instanceGroupManagers.update",
  "compute.instanceTemplates.create",
  "compute.instanceTemplates.delete",
  "compute.instanceTemplates.get",
  "compute.routes.list",
  "dns.changes.get",
  "privateca.caPools.use",
  "privateca.certificates.create",
  "privateca.certificates.get",
  "privateca.certificates.update",
  "privateca.operations.get",
  "secretmanager.versions.destroy",
  "secretmanager.versions.get",
  "secretmanager.versions.list",
]);

const LEGACY_020_DEPLOYER_ROLE = {
  description:
    "Least-privilege project permissions for Secure Gateway Studio PoC apply and rollback.",
  includedPermissions: [
    ...POC_DEPLOYER_ROLE.includedPermissions.filter(
      (permission) => !POST_020_ROLE_PERMISSIONS.has(permission),
    ),
    "beyondcorp.securityGateways.update",
  ].sort(),
  stage: "GA",
  title: "Secure Gateway PoC Deployer",
} as const;

const failures: string[] = [];
let passed = 0;

function check(name: string, condition: boolean, detail = ""): void {
  if (condition) passed += 1;
  else failures.push(`${name}${detail ? `\n      ${detail}` : ""}`);
}

// 0.2.0 persisted only the reserved service-account email. The 0.2.1 adapter
// must recover the project embedded in that exact email before the explicit,
// fail-closed cloud audit can run.
{
  const projectId = "enterprise-secgw-01";
  const serviceAccountEmail =
    `secure-gateway-deployer@${projectId}.iam.gserviceaccount.com`;
  const identity = legacyDeployerIdentityFromStoredState({
    deployerServiceAccount: serviceAccountEmail,
  });
  check(
    "0.2.0 email-only deployer state is available to explicit migration",
    identity?.projectId === projectId &&
      identity.serviceAccountEmail === serviceAccountEmail,
    JSON.stringify(identity),
  );
  check(
    "legacy deployer recovery rejects a conflicting stored project",
    legacyDeployerIdentityFromStoredState({
      deployerServiceAccount: serviceAccountEmail,
      deployerProjectId: "different-secgw-01",
    }) === undefined,
  );
}

const SPEC = parseDeploymentSpec({
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

function change(provider: string, resourceType: string, resourceName: string): ResourceChange {
  return {
    provider,
    resource_type: resourceType,
    resource_name: resourceName,
    action: "create",
    risk: "high",
    summary: resourceName,
    owned_after_apply: true,
    dependencies: [],
  };
}

// Every evidence gate is classified by the same pure function used by both
// retry preflight and executor teardown. This prevents a new runtime-only
// `*-missing` branch from bypassing whole-run preflight.
{
  const cases = [
    [change("compute", "network", "legacy-vpc"),
      "generic-resource-ownership-checkpoint-missing"],
    [change("compute", "cloud_nat", "legacy-nat"),
      "cloud-nat-ownership-checkpoint-missing"],
    [change("dns", "record_set", "legacy-record"),
      "dns-record-ownership-checkpoint-missing"],
    [change("iam", "service_account", "legacy-sa"),
      "named-resource-ownership-checkpoint-missing"],
    [change("beyondcorp", "gateway_iam", "legacy-gateway-iam"),
      "iam-ownership-checkpoint-missing"],
    [change("chromepolicy", "extension_install", "legacy-policy"),
      "chrome-policy-before-image-missing"],
    [change("secretmanager", "secret_version", "legacy-version"),
      "secret-version-ownership-checkpoint-missing"],
  ] as const;
  for (const [target, expected] of cases) {
    const capability = compensationCapability(target, undefined);
    check(
      `preflight classifies ${target.provider}:${target.resource_type} without provider I/O`,
      !capability.available && capability.errorCode === expected,
      JSON.stringify(capability),
    );
  }
  check(
    "preflight recognizes a no-op compensation without a checkpoint",
    compensationCapability(
      change("serviceusage", "project_services", "required-apis"),
      undefined,
    ).available,
  );
  check(
    "preflight rejects a checkpoint kind that belongs to another resource type",
    !compensationCapability(
      change("beyondcorp", "application", `${SPEC.name}-app`),
      {
        kind: "iam",
        phase: "applied",
        setUrl: "https://example.invalid:setIamPolicy",
        policy: {},
        afterPolicy: {},
      },
    ).available,
  );
  const sendingIam = compensationCapability(
    change("beyondcorp", "gateway_iam", "legacy-gateway-iam"),
    {
      kind: "iam",
      phase: "sending",
      setUrl: "https://example.invalid:setIamPolicy",
      policy: {},
      afterPolicy: {},
    },
  );
  check(
    "preflight terminalizes an inherently ambiguous IAM send",
    !sendingIam.available && sendingIam.errorCode === "iam-rollback-outcome-ambiguous",
    JSON.stringify(sendingIam),
  );
  const sendingGateway = compensationCapability(
    change("beyondcorp", "security_gateway", SPEC.gateway_id),
    {
      kind: "generic_created_resource",
      protocolVersion: 2,
      phase: "sending",
      resourceKey: `beyondcorp:security_gateway:${SPEC.gateway_id}`,
      createUrl: "https://beyondcorp.googleapis.com/v1/projects/example/locations/global/securityGateways",
      resourceUrl: "https://beyondcorp.googleapis.com/v1/projects/example/locations/global/securityGateways/default",
      createRequestId: crypto.randomUUID(),
      expectedParamsDigest: "a".repeat(64),
      expectedPayloadDigest: "b".repeat(64),
      ownershipMarker: null,
    },
  );
  check(
    "preflight terminalizes a markerless ambiguous BeyondCorp create",
    !sendingGateway.available &&
      sendingGateway.errorCode === "generic-resource-provider-response-ambiguous",
    JSON.stringify(sendingGateway),
  );
  check(
    "preflight keeps an exactly recoverable Secret Version send available",
    compensationCapability(
      change("secretmanager", "secret_version", `${SPEC.name}-tls-version`),
      {
        kind: "secret_version",
        phase: "sending",
        secretUrl:
          `https://secretmanager.googleapis.com/v1/projects/${SPEC.project_id}` +
          `/secrets/${SPEC.name}-tls`,
        versionName: null,
        previousAliases: {},
        previousLabels: {},
        payloadDigest: "c".repeat(64),
        existingVersionNames: [],
        ownershipToken: crypto.randomUUID(),
      },
    ).available,
  );
}

const PRODUCTION_REFRESH_SPEC = {
  ...SPEC,
  mode: "production" as const,
  backend_kind: "existing_http" as const,
  source_image: "projects/enterprise-secgw-01/global/images/sgs-nginx-20260824",
  secondary_zone: "asia-east1-a",
};
const PRODUCTION_REFRESH_BINDING = {
  name: PRODUCTION_REFRESH_SPEC.source_image,
  id: "987654321",
  self_link:
    `https://www.googleapis.com/compute/v1/${PRODUCTION_REFRESH_SPEC.source_image}`,
};
function productionManagedInstanceResponse(
  method: string,
  url: string,
): { status: number; payload: Record<string, unknown> } | null {
  const names = [
    { zone: PRODUCTION_REFRESH_SPEC.zone, name: `${SPEC.name}-offload-a1` },
    { zone: PRODUCTION_REFRESH_SPEC.secondary_zone, name: `${SPEC.name}-offload-a2` },
  ];
  if (method === "POST" && url.endsWith("/listManagedInstances")) {
    return {
      status: 200,
      payload: {
        managedInstances: names.map(({ zone, name }) => ({
          instance:
            `https://www.googleapis.com/compute/v1/projects/${SPEC.project_id}/` +
            `zones/${zone}/instances/${name}`,
          instanceStatus: "RUNNING",
        })),
      },
    };
  }
  if (method === "GET" && url.endsWith("/global/images/sgs-nginx-20260824")) {
    return {
      status: 200,
      payload: {
        name: "sgs-nginx-20260824",
        id: PRODUCTION_REFRESH_BINDING.id,
        selfLink: PRODUCTION_REFRESH_BINDING.self_link,
      },
    };
  }
  for (const { zone, name } of names) {
    const instanceSuffix = `/zones/${zone}/instances/${name}`;
    const diskSuffix = `/zones/${zone}/disks/${name}`;
    if (method === "GET" && url.endsWith(instanceSuffix)) {
      return {
        status: 200,
        payload: {
          disks: [{
            boot: true,
            source:
              `https://www.googleapis.com/compute/v1/projects/${SPEC.project_id}` +
              diskSuffix,
          }],
        },
      };
    }
    if (method === "GET" && url.endsWith(diskSuffix)) {
      return {
        status: 200,
        payload: {
          name,
          status: "READY",
          selfLink:
            `https://www.googleapis.com/compute/v1/projects/${SPEC.project_id}${diskSuffix}`,
          zone:
            `https://www.googleapis.com/compute/v1/projects/${SPEC.project_id}/zones/${zone}`,
          sizeGb: "20",
          type:
            `https://www.googleapis.com/compute/v1/projects/${SPEC.project_id}/zones/${zone}/` +
            "diskTypes/pd-balanced",
          sourceImage: PRODUCTION_REFRESH_BINDING.self_link,
          sourceImageId: PRODUCTION_REFRESH_BINDING.id,
        },
      };
    }
  }
  return null;
}

{
  const relative =
    "projects/enterprise-secgw-01/secrets/strict-tls/versions/17";
  const canonical =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/" +
    "secrets/strict-tls/versions/17";
  let wrongProjectRejected = false;
  let nonNumericRejected = false;
  try {
    canonicalSecretVersionUrl(
      "projects/attacker-project/secrets/strict-tls/versions/17",
      SPEC.project_id,
      "strict-tls",
    );
  } catch {
    wrongProjectRejected = true;
  }
  try {
    canonicalSecretVersionUrl(
      "projects/enterprise-secgw-01/secrets/strict-tls/versions/latest",
      SPEC.project_id,
      "strict-tls",
    );
  } catch {
    nonNumericRejected = true;
  }
  check(
    "SecretVersion resource names canonicalize only inside the expected project and secret",
    canonicalSecretVersionUrl(relative, SPEC.project_id, "strict-tls") === canonical &&
      canonicalSecretVersionUrl(canonical, SPEC.project_id, "strict-tls") === canonical &&
      wrongProjectRejected && nonNumericRejected,
  );
}

// Bootstrap runs before the deployer exists and uses named APIs without a
// requestId. A raced ALREADY_EXISTS is ambiguous and must never be adopted.
{
  let accountGets = 0;
  const transport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.includes("/serviceAccounts/")) {
        accountGets += 1;
        return accountGets === 1
          ? { status: 404, payload: { error: { status: "NOT_FOUND" } } }
          : {
              status: 200,
              payload: {
                email: "unrelated@enterprise-secgw-01.iam.gserviceaccount.com",
                displayName: "Unrelated account",
              },
            };
      }
      if (method === "POST" && url.endsWith("/serviceAccounts")) {
        return { status: 409, payload: { error: { status: "ALREADY_EXISTS" } } };
      }
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await bootstrapDeployer(SPEC.project_id, {
      transport,
      operatorEmail: "admin@example.com",
      checkpointOwnershipPin: async () => undefined,
    });
  } catch (caught) {
    error = caught;
  }
  check(
    "bootstrap rejects an unreconciled service-account ALREADY_EXISTS",
    error instanceof Error &&
      (error as { code?: unknown }).code === "service-account-create-raced" &&
      accountGets === 1,
    String(error),
  );
}

// Mutable displayName/email are not ownership. An existing reserved account is
// rejected before any role lookup or IAM grant unless its immutable uniqueId
// was checkpointed by this installation's own successful create.
{
  const accountEmail =
    "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com";
  const calls: string[] = [];
  const transport: Transport = {
    async requestJson(method, url) {
      calls.push(`${method} ${url}`);
      if (method === "GET" && url.includes("/serviceAccounts/")) {
        return {
          status: 200,
          payload: {
            email: accountEmail,
            uniqueId: "123456789012345678901",
            displayName: "Secure Gateway Studio deployer",
          },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let error: unknown;
  try {
    await bootstrapDeployer(SPEC.project_id, {
      transport,
      operatorEmail: "admin@example.com",
      checkpointOwnershipPin: async () => undefined,
    });
  } catch (caught) {
    error = caught;
  }
  check(
    "bootstrap never grants roles to an unpinned pre-created service account",
    (error as { code?: unknown } | undefined)?.code ===
        "service-account-identity-unpinned" && calls.length === 1,
    `${String(error)} | ${calls.join(",")}`,
  );
}

// A cloud-side teardown can intentionally remove the exact pinned deployer.
// Rebootstrap is a separate, explicitly confirmed lifecycle: the old account,
// role, project grants, and Access Policy grants must all be absent before the
// local pin is retired or any replacement create is sent.
{
  const projectId = SPEC.project_id;
  const accountEmail =
    `secure-gateway-deployer@${projectId}.iam.gserviceaccount.com`;
  const roleName = `projects/${projectId}/roles/secureGatewayPocDeployer`;
  const pin = {
    version: 1 as const,
    project_id: projectId,
    service_account_email: accountEmail,
    service_account_unique_id: "123456789012345678901",
    operator_email: "admin@example.com",
    service_account_ownership_token: "f54e0a9c-e05d-4dde-ae3f-6c1cb0402376",
    service_account_iam_bindings: [{
      role: "roles/iam.serviceAccountTokenCreator",
      members: ["user:admin@example.com"],
    }],
    custom_role: roleName,
    custom_role_etag: "deleted-role-etag",
  };
  let account: Record<string, unknown> | undefined;
  let role: Record<string, unknown> | undefined = {
    ...EXTENSION_DEPLOYER_ROLE,
    name: roleName,
    etag: "deleted-role-etag",
    deleted: true,
  };
  let accountPolicy: Record<string, unknown> = {
    etag: "account-before",
    version: 3,
    bindings: [],
  };
  let projectPolicy: Record<string, unknown> = {
    etag: "project-before",
    version: 3,
    bindings: [],
  };
  let accessPolicy: Record<string, unknown> = {
    etag: "access-before",
    version: 3,
    bindings: [],
  };
  let injectRetiredPrincipalAfterCreate = false;
  let failAccessPolicySetOnce = false;
  const calls: string[] = [];
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      calls.push(`${method} ${url}`);
      if (method === "GET" && url.includes("/serviceAccounts/")) {
        return account === undefined
          ? { status: 404, payload: {} }
          : { status: 200, payload: structuredClone(account) };
      }
      if (method === "GET" && url.endsWith(roleName)) {
        return role === undefined
          ? { status: 404, payload: {} }
          : { status: 200, payload: structuredClone(role) };
      }
      if (method === "POST" && url.endsWith("/serviceAccounts")) {
        const request = options.jsonBody as {
          accountId: string;
          serviceAccount: Record<string, unknown>;
        };
        account = {
          ...request.serviceAccount,
          email: `${request.accountId}@${projectId}.iam.gserviceaccount.com`,
          uniqueId: "223456789012345678901",
        };
        return { status: 200, payload: structuredClone(account) };
      }
      if (method === "POST" && url.endsWith("/roles")) {
        const request = options.jsonBody as {
          roleId: string;
          role: Record<string, unknown>;
        };
        role = {
          ...request.role,
          name: `projects/${projectId}/roles/${request.roleId}`,
          etag: "new-role-etag",
        };
        if (injectRetiredPrincipalAfterCreate) {
          projectPolicy = {
            etag: "project-raced",
            version: 3,
            bindings: [{
              role: "roles/viewer",
              members: [
                `principal://iam.googleapis.com/projects/-/serviceAccounts/${pin.service_account_unique_id}`,
              ],
            }],
          };
        }
        return { status: 200, payload: structuredClone(role) };
      }
      if (method === "POST" && url.endsWith(":undelete")) {
        const request = options.jsonBody as { etag?: unknown };
        if (role?.deleted !== true || request.etag !== role.etag) {
          throw new Error("undelete-etag-mismatch");
        }
        role = { ...role, etag: "undeleted-role-etag", deleted: false };
        return { status: 200, payload: structuredClone(role) };
      }
      if (method === "POST" && url.endsWith(":getIamPolicy")) {
        if (url.includes("/serviceAccounts/")) {
          return { status: 200, payload: structuredClone(accountPolicy) };
        }
        if (url.includes("accessPolicies/456")) {
          return { status: 200, payload: structuredClone(accessPolicy) };
        }
        return { status: 200, payload: structuredClone(projectPolicy) };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        const next = structuredClone(
          (options.jsonBody as { policy: Record<string, unknown> }).policy,
        );
        if (url.includes("/serviceAccounts/")) {
          accountPolicy = { ...next, etag: "account-after" };
          return { status: 200, payload: structuredClone(accountPolicy) };
        }
        if (url.includes("accessPolicies/456")) {
          if (failAccessPolicySetOnce) {
            failAccessPolicySetOnce = false;
            throw new Error("simulated-access-policy-set-failure");
          }
          accessPolicy = { ...next, etag: "access-after" };
          return { status: 200, payload: structuredClone(accessPolicy) };
        }
        projectPolicy = { ...next, etag: "project-after" };
        return { status: 200, payload: structuredClone(projectPolicy) };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let currentPin: unknown = structuredClone(pin);
  let retiredPin: unknown;
  const recoveryCheckpoints: unknown[] = [];
  let error: unknown;
  try {
    await bootstrapDeployer(projectId, {
      transport,
      operatorEmail: "admin@example.com",
      accessPolicyId: "456",
      ownershipPin: currentPin,
      allowDeletedOwnedDeployerRebootstrap: true,
      retireDeletedOwnershipPin: async (deletedPin) => {
        retiredPin = structuredClone(deletedPin);
        currentPin = undefined;
      },
      checkpointOwnershipPin: async (checkpoint) => {
        currentPin = structuredClone(checkpoint);
        recoveryCheckpoints.push(structuredClone(checkpoint));
      },
    });
  } catch (caught) {
    error = caught;
  }
  const firstWrite = calls.findIndex((call) =>
    call.startsWith("POST ") &&
    (call.endsWith("/serviceAccounts") || call.endsWith("/roles") ||
      call.endsWith(":setIamPolicy"))
  );
  const requiredPreflightCalls = [
    `GET https://iam.googleapis.com/v1/${roleName}`,
    `POST https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:getIamPolicy`,
    "POST https://accesscontextmanager.googleapis.com/v1/accessPolicies/456:getIamPolicy",
  ];
  check(
    "explicit deleted-deployer rebootstrap retires the old pin only after a mutation-free cloud audit",
    error === undefined && retiredPin !== undefined &&
      (currentPin as { service_account_unique_id?: unknown })
          ?.service_account_unique_id === "223456789012345678901" &&
      (currentPin as { deleted_deployer_recovery?: unknown })
          ?.deleted_deployer_recovery === undefined &&
      recoveryCheckpoints.some((checkpoint) =>
        (checkpoint as { deleted_deployer_recovery?: { role_state?: unknown } })
          .deleted_deployer_recovery?.role_state === "soft_deleted"
      ) &&
      calls.includes(`POST https://iam.googleapis.com/v1/${roleName}:undelete`) &&
      requiredPreflightCalls.every((call) => calls.includes(call)) &&
      firstWrite > Math.max(...requiredPreflightCalls.map((call) => calls.indexOf(call))),
    JSON.stringify({ error: String(error), retiredPin, currentPin, calls }),
  );

  const crashCheckpoint = recoveryCheckpoints.find((checkpoint) => {
    const candidate = checkpoint as {
      service_account_unique_id?: unknown;
      custom_role_etag?: unknown;
      deleted_deployer_recovery?: unknown;
    };
    return candidate.service_account_unique_id === "223456789012345678901" &&
      candidate.custom_role_etag === null &&
      candidate.deleted_deployer_recovery !== undefined;
  });
  role = {
    ...EXTENSION_DEPLOYER_ROLE,
    name: roleName,
    etag: "deleted-role-etag",
    deleted: true,
  };
  accountPolicy = { etag: "account-before", version: 3, bindings: [] };
  projectPolicy = { etag: "project-before", version: 3, bindings: [] };
  accessPolicy = { etag: "access-before", version: 3, bindings: [] };
  calls.length = 0;
  let crashRetryPin: unknown = structuredClone(crashCheckpoint);
  failAccessPolicySetOnce = true;
  let partialGrantError: unknown;
  try {
    await bootstrapDeployer(projectId, {
      transport,
      operatorEmail: "admin@example.com",
      accessPolicyId: "456",
      ownershipPin: crashRetryPin,
      checkpointOwnershipPin: async (checkpoint) => {
        crashRetryPin = structuredClone(checkpoint);
      },
    });
  } catch (caught) {
    partialGrantError = caught;
  }
  let crashRetryError: unknown;
  try {
    await bootstrapDeployer(projectId, {
      transport,
      operatorEmail: "admin@example.com",
      accessPolicyId: "456",
      ownershipPin: crashRetryPin,
      checkpointOwnershipPin: async (checkpoint) => {
        crashRetryPin = structuredClone(checkpoint);
      },
    });
  } catch (caught) {
    crashRetryError = caught;
  }
  check(
    "deleted-role recovery survives a worker crash and a partial project grant",
    crashCheckpoint !== undefined &&
      (partialGrantError as Error | undefined)?.message ===
        "simulated-access-policy-set-failure" && crashRetryError === undefined &&
      calls.includes(`POST https://iam.googleapis.com/v1/${roleName}:undelete`) &&
      (crashRetryPin as { deleted_deployer_recovery?: unknown })
          .deleted_deployer_recovery === undefined,
    JSON.stringify({
      partialGrantError: String(partialGrantError),
      crashRetryError: String(crashRetryError),
      crashRetryPin,
      calls,
    }),
  );

  account = undefined;
  role = undefined;
  accountPolicy = { etag: "account-before", version: 3, bindings: [] };
  projectPolicy = {
    etag: "project-before",
    version: 3,
    bindings: [{
      role: "roles/browser",
      members: [`serviceAccount:${accountEmail}`],
    }],
  };
  accessPolicy = { etag: "access-before", version: 3, bindings: [] };
  currentPin = structuredClone(pin);
  retiredPin = undefined;
  calls.length = 0;
  let staleBindingError: unknown;
  try {
    await bootstrapDeployer(projectId, {
      transport,
      operatorEmail: "admin@example.com",
      accessPolicyId: "456",
      ownershipPin: currentPin,
      allowDeletedOwnedDeployerRebootstrap: true,
      retireDeletedOwnershipPin: async (deletedPin) => {
        retiredPin = structuredClone(deletedPin);
      },
      checkpointOwnershipPin: async () => undefined,
    });
  } catch (caught) {
    staleBindingError = caught;
  }
  check(
    "deleted-deployer rebootstrap rejects a stale IAM binding before retiring or mutating",
    (staleBindingError as { code?: unknown } | undefined)?.code ===
        "deleted-deployer-iam-binding-remains" && retiredPin === undefined &&
      calls.every((call) => !call.endsWith("/serviceAccounts") &&
        !call.endsWith("/roles") && !call.endsWith(":setIamPolicy")),
    JSON.stringify({ staleBindingError: String(staleBindingError), retiredPin, calls }),
  );

  account = undefined;
  role = undefined;
  accountPolicy = { etag: "account-before", version: 3, bindings: [] };
  projectPolicy = { etag: "project-before", version: 3, bindings: [] };
  accessPolicy = { etag: "access-before", version: 3, bindings: [] };
  currentPin = structuredClone(pin);
  retiredPin = undefined;
  calls.length = 0;
  injectRetiredPrincipalAfterCreate = true;
  let racedBindingError: unknown;
  try {
    await bootstrapDeployer(projectId, {
      transport,
      operatorEmail: "admin@example.com",
      accessPolicyId: "456",
      ownershipPin: currentPin,
      allowDeletedOwnedDeployerRebootstrap: true,
      retireDeletedOwnershipPin: async (deletedPin) => {
        retiredPin = structuredClone(deletedPin);
        currentPin = undefined;
      },
      checkpointOwnershipPin: async (checkpoint) => {
        currentPin = structuredClone(checkpoint);
      },
    });
  } catch (caught) {
    racedBindingError = caught;
  }
  check(
    "deleted-deployer rebootstrap rechecks the retired numeric identity before granting authority",
    (racedBindingError as { code?: unknown } | undefined)?.code ===
        "deleted-deployer-iam-binding-remains" && retiredPin !== undefined &&
      calls.filter((call) => call.endsWith(":setIamPolicy")).length === 1,
    JSON.stringify({ racedBindingError: String(racedBindingError), retiredPin, calls }),
  );
}

// 0.2.0 stored only the reserved email, but that hint can be absent after an
// extension reinstall or completed storage migration. Migration is a separate,
// explicitly confirmed path: it reads the immutable uniqueId, rejects retained
// user-managed keys, requires an exact known role definition, and audits both
// the account and project IAM allowlists before writing the first ownership pin.
{
  const projectId = SPEC.project_id;
  const accountEmail = `secure-gateway-deployer@${projectId}.iam.gserviceaccount.com`;
  const roleName = `projects/${projectId}/roles/secureGatewayPocDeployer`;
  const member = `serviceAccount:${accountEmail}`;
  const checkpoints: unknown[] = [];
  const calls: string[] = [];
  const accountBindings = [{
    role: "roles/iam.serviceAccountTokenCreator",
    members: ["user:admin@example.com"],
  }];
  const projectBindings = [
    { role: roleName, members: [member] },
    { role: "roles/browser", members: [member] },
    { role: "roles/serviceusage.serviceUsageConsumer", members: [member] },
  ];
  const transport: Transport = {
    async requestJson(method, url) {
      calls.push(`${method} ${url}`);
      if (method === "GET" && url.endsWith("/keys")) {
        return { status: 200, payload: { keys: [] } };
      }
      if (method === "GET" && url.includes("/serviceAccounts/")) {
        return {
          status: 200,
          payload: {
            email: accountEmail,
            uniqueId: "123456789012345678901",
            displayName: "Secure Gateway Studio deployer",
          },
        };
      }
      if (method === "GET" && url.endsWith(roleName)) {
        return {
          status: 200,
          payload: {
            ...LEGACY_020_DEPLOYER_ROLE,
            name: roleName,
            etag: "legacy-role-etag",
          },
        };
      }
      if (method === "PATCH" && url.endsWith(roleName)) {
        return {
          status: 200,
          payload: {
            ...EXTENSION_DEPLOYER_ROLE,
            name: roleName,
            etag: "current-role-etag",
          },
        };
      }
      if (method === "POST" && url.includes("/serviceAccounts/") &&
        url.endsWith(":getIamPolicy")) {
        return {
          status: 200,
          payload: { etag: "account-etag", version: 3, bindings: accountBindings },
        };
      }
      if (method === "POST" && url.includes("cloudresourcemanager.googleapis.com") &&
        url.endsWith(":getIamPolicy")) {
        return {
          status: 200,
          payload: { etag: "project-etag", version: 3, bindings: projectBindings },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let error: unknown;
  let result: Awaited<ReturnType<typeof bootstrapDeployer>> | undefined;
  try {
    result = await bootstrapDeployer(projectId, {
      transport,
      operatorEmail: "admin@example.com",
      allowOwnershipMigration: true,
      checkpointOwnershipPin: async (pin) => {
        checkpoints.push(structuredClone(pin));
      },
    });
  } catch (caught) {
    error = caught;
  }
  check(
    "explicit 0.2.0 recovery without local identity pins only after key, role, and IAM audits",
    error === undefined && result?.service_account_unique_id === "123456789012345678901" &&
      checkpoints.length >= 4 &&
      (checkpoints[0] as { custom_role_etag?: unknown }).custom_role_etag ===
        "legacy-role-etag" &&
      (checkpoints.at(-1) as { custom_role_etag?: unknown }).custom_role_etag ===
        "current-role-etag" &&
      calls.filter((call) => call.includes("cloudresourcemanager") &&
        call.endsWith(":getIamPolicy")).length >= 2 &&
      calls.some((call) => call.endsWith("/keys")) &&
      calls.filter((call) => call.startsWith("PATCH ") && call.endsWith(roleName)).length === 1 &&
      calls.every((call) => !call.endsWith(":setIamPolicy")),
    JSON.stringify({ error: String(error), result, checkpoints, calls }),
  );

  let conflictingReplacementError: unknown;
  const callsBeforeConflictingReplacement = calls.length;
  try {
    await bootstrapDeployer(projectId, {
      transport,
      operatorEmail: "admin@example.com",
      ownershipPin: checkpoints.at(-1),
      checkpointOwnershipPin: async () => undefined,
      createReplacementDeployer: true,
    });
  } catch (caught) {
    conflictingReplacementError = caught;
  }
  check(
    "replacement confirmation cannot redirect an existing compatibility ownership pin",
    (conflictingReplacementError as { code?: unknown } | undefined)?.code ===
        "replacement-deployer-conflicts-with-pin" &&
      calls.length === callsBeforeConflictingReplacement,
    String(conflictingReplacementError),
  );

  const keyedTransport: Transport = {
    async requestJson(method, url, options) {
      if (method === "GET" && url.endsWith("/keys")) {
        return {
          status: 200,
          payload: {
            keys: [{
              name: `projects/${projectId}/serviceAccounts/${accountEmail}/keys/key-1`,
              keyType: "USER_MANAGED",
            }],
          },
        };
      }
      return transport.requestJson(method, url, options);
    },
  };
  let keyedError: unknown;
  let keyedCheckpoint = false;
  try {
    await bootstrapDeployer(projectId, {
      transport: keyedTransport,
      operatorEmail: "admin@example.com",
      allowOwnershipMigration: true,
      checkpointOwnershipPin: async () => {
        keyedCheckpoint = true;
      },
    });
  } catch (caught) {
    keyedError = caught;
  }
  check(
    "0.2.0 recovery without local identity rejects a user-managed service-account key",
    (keyedError as { code?: unknown } | undefined)?.code ===
        "legacy-deployer-user-managed-key-present" && !keyedCheckpoint,
    String(keyedError),
  );

  const unsafeTransport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.includes("/serviceAccounts/")) {
        return {
          status: 200,
          payload: {
            email: accountEmail,
            uniqueId: "123456789012345678901",
            displayName: "Secure Gateway Studio deployer",
          },
        };
      }
      if (method === "GET" && url.endsWith(roleName)) {
        return {
          status: 200,
          payload: { ...LEGACY_020_DEPLOYER_ROLE, name: roleName, etag: "legacy-role-etag" },
        };
      }
      if (method === "POST" && url.includes("/serviceAccounts/") &&
        url.endsWith(":getIamPolicy")) {
        return {
          status: 200,
          payload: { etag: "account-etag", version: 3, bindings: accountBindings },
        };
      }
      if (method === "POST" && url.includes("cloudresourcemanager.googleapis.com") &&
        url.endsWith(":getIamPolicy")) {
        return {
          status: 200,
          payload: {
            etag: "project-etag",
            version: 3,
            bindings: [
              ...projectBindings,
              { role: "roles/owner", members: [member] },
            ],
          },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let unsafeError: unknown;
  let unsafeCheckpoint = false;
  try {
    await bootstrapDeployer(projectId, {
      transport: unsafeTransport,
      operatorEmail: "admin@example.com",
      allowOwnershipMigration: true,
      legacyDeployerIdentity: { serviceAccountEmail: accountEmail, projectId },
      checkpointOwnershipPin: async () => {
        unsafeCheckpoint = true;
      },
    });
  } catch (caught) {
    unsafeError = caught;
  }
  check(
    "0.2.0 migration rejects an extra project role before pinning",
    (unsafeError as { code?: unknown } | undefined)?.code ===
        "legacy-deployer-project-iam-unsafe" && !unsafeCheckpoint,
    String(unsafeError),
  );

  // A drifted legacy deployer is never adopted or modified. After that
  // fail-closed audit, an independently confirmed replacement uses fresh
  // reserved names and receives its own immutable ownership pin.
  {
    const replacementAccount =
      `secure-gateway-studio-deployer@${projectId}.iam.gserviceaccount.com`;
    const replacementRole =
      `projects/${projectId}/roles/secureGatewayStudioDeployer`;
    let account: Record<string, unknown> | undefined;
    let role: Record<string, unknown> | undefined;
    let accountPolicy: Record<string, unknown> = {
      etag: "account-before",
      version: 3,
      bindings: [],
    };
    let projectPolicy: Record<string, unknown> = {
      etag: "project-before",
      version: 3,
      bindings: [],
    };
    const replacementCalls: string[] = [];
    const replacementTransport: Transport = {
      async requestJson(method, url, options = {}) {
        replacementCalls.push(`${method} ${url}`);
        if (method === "GET" && url.includes("/serviceAccounts/")) {
          return account === undefined
            ? { status: 404, payload: {} }
            : { status: 200, payload: structuredClone(account) };
        }
        if (method === "POST" && url.endsWith("/serviceAccounts")) {
          const request = options.jsonBody as {
            accountId: string;
            serviceAccount: Record<string, unknown>;
          };
          account = {
            ...request.serviceAccount,
            email: `${request.accountId}@${projectId}.iam.gserviceaccount.com`,
            uniqueId: "223456789012345678901",
          };
          return { status: 200, payload: structuredClone(account) };
        }
        if (method === "GET" && url.includes("/roles/")) {
          return role === undefined
            ? { status: 404, payload: {} }
            : { status: 200, payload: structuredClone(role) };
        }
        if (method === "POST" && url.endsWith("/roles")) {
          const request = options.jsonBody as {
            roleId: string;
            role: Record<string, unknown>;
          };
          role = {
            ...request.role,
            name: `projects/${projectId}/roles/${request.roleId}`,
            etag: "replacement-role-etag",
          };
          return { status: 200, payload: structuredClone(role) };
        }
        if (method === "POST" && url.includes("/serviceAccounts/") &&
          url.endsWith(":getIamPolicy")) {
          return { status: 200, payload: structuredClone(accountPolicy) };
        }
        if (method === "POST" && url.includes("/serviceAccounts/") &&
          url.endsWith(":setIamPolicy")) {
          accountPolicy = structuredClone(
            (options.jsonBody as { policy: Record<string, unknown> }).policy,
          );
          accountPolicy.etag = "account-after";
          return { status: 200, payload: structuredClone(accountPolicy) };
        }
        if (method === "POST" && url.includes("cloudresourcemanager.googleapis.com") &&
          url.endsWith(":getIamPolicy")) {
          return { status: 200, payload: structuredClone(projectPolicy) };
        }
        if (method === "POST" && url.includes("cloudresourcemanager.googleapis.com") &&
          url.endsWith(":setIamPolicy")) {
          projectPolicy = structuredClone(
            (options.jsonBody as { policy: Record<string, unknown> }).policy,
          );
          projectPolicy.etag = "project-after";
          return { status: 200, payload: structuredClone(projectPolicy) };
        }
        throw new Error(`unexpected ${method} ${url}`);
      },
    };
    const replacementCheckpoints: BootstrapOwnershipCheckpoint[] = [];
    const replacementOptions = {
      transport: replacementTransport,
      operatorEmail: "admin@example.com",
      checkpointOwnershipPin: async (pin: BootstrapOwnershipCheckpoint) => {
        replacementCheckpoints.push(structuredClone(pin));
      },
      createReplacementDeployer: true,
    } as BootstrapOptions & { createReplacementDeployer: true };
    let replacementResult: Awaited<ReturnType<typeof bootstrapDeployer>> | undefined;
    let replacementError: unknown;
    try {
      replacementResult = await bootstrapDeployer(projectId, replacementOptions);
    } catch (caught) {
      replacementError = caught;
    }
    const callsBeforeResume = replacementCalls.length;
    let resumedReplacement: Awaited<ReturnType<typeof bootstrapDeployer>> | undefined;
    try {
      resumedReplacement = await bootstrapDeployer(projectId, {
        transport: replacementTransport,
        operatorEmail: "admin@example.com",
        ownershipPin: replacementCheckpoints.at(-1),
        checkpointOwnershipPin: async (pin) => {
          replacementCheckpoints.push(structuredClone(pin));
        },
      });
    } catch (caught) {
      replacementError = caught;
    }
    const resumeCalls = replacementCalls.slice(callsBeforeResume);
    check(
      "unsafe 0.2.0 migration can create an isolated replacement without touching the legacy identity",
      replacementError === undefined &&
        replacementResult?.service_account_email === replacementAccount &&
        replacementResult.custom_role === replacementRole &&
        resumedReplacement?.service_account_email === replacementAccount &&
        resumedReplacement.custom_role === replacementRole &&
        replacementCheckpoints.length >= 4 &&
        replacementCalls.every((call) => !call.includes(accountEmail) && !call.includes(roleName)) &&
        resumeCalls.every((call) => !call.endsWith("/serviceAccounts") && !call.endsWith("/roles")),
      JSON.stringify({
        replacementError: String(replacementError),
        replacementResult,
        resumedReplacement,
        replacementCalls,
      }),
    );
  }

  const attackerTransport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.includes("/serviceAccounts/")) {
        return {
          status: 200,
          payload: {
            email: accountEmail,
            uniqueId: "123456789012345678901",
            displayName: "Secure Gateway Studio deployer",
          },
        };
      }
      if (method === "GET" && url.endsWith(roleName)) {
        return {
          status: 200,
          payload: { ...LEGACY_020_DEPLOYER_ROLE, name: roleName, etag: "legacy-role-etag" },
        };
      }
      if (method === "POST" && url.includes("/serviceAccounts/") &&
        url.endsWith(":getIamPolicy")) {
        return {
          status: 200,
          payload: {
            etag: "account-etag",
            version: 3,
            bindings: [{
              role: "roles/iam.serviceAccountTokenCreator",
              members: ["user:admin@example.com", "user:attacker@example.com"],
            }],
          },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let attackerError: unknown;
  let attackerCheckpoint = false;
  try {
    await bootstrapDeployer(projectId, {
      transport: attackerTransport,
      operatorEmail: "admin@example.com",
      allowOwnershipMigration: true,
      legacyDeployerIdentity: { serviceAccountEmail: accountEmail, projectId },
      checkpointOwnershipPin: async () => {
        attackerCheckpoint = true;
      },
    });
  } catch (caught) {
    attackerError = caught;
  }
  check(
    "0.2.0 migration rejects any additional Token Creator principal",
    (attackerError as { code?: unknown } | undefined)?.code ===
        "legacy-deployer-service-account-iam-unsafe" && !attackerCheckpoint,
    String(attackerError),
  );
}

// Bootstrap IAM reads must request policy version 3 before any conditional
// binding is merged. Otherwise Google may return a synthetic `_withcond_` role
// and the subsequent SET can silently damage the real conditional binding.

// Every non-idempotent bootstrap write is preceded by a durable intent. If the
// provider commits and the MV3 worker loses the response, the next invocation
// must reconcile the exact managed-after state and must not issue the create or
// SET a second time.
{
  const projectId = SPEC.project_id;
  const accountEmail =
    `secure-gateway-deployer@${projectId}.iam.gserviceaccount.com`;
  const roleName = `projects/${projectId}/roles/secureGatewayPocDeployer`;
  const tokenCreator = {
    role: "roles/iam.serviceAccountTokenCreator",
    members: ["user:admin@example.com"],
  };
  const projectBindings = [
    { role: roleName, members: [`serviceAccount:${accountEmail}`] },
    { role: "roles/browser", members: [`serviceAccount:${accountEmail}`] },
    {
      role: "roles/serviceusage.serviceUsageConsumer",
      members: [`serviceAccount:${accountEmail}`],
    },
  ];

  let checkpoint: BootstrapOwnershipCheckpoint | undefined;
  let remoteAccount: Record<string, unknown> | undefined;
  let remoteRole: Record<string, unknown> | undefined;
  let accountCreateCount = 0;
  let accountPolicy = { version: 3, etag: "account-before", bindings: [] as typeof tokenCreator[] };
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.includes("/serviceAccounts/")) {
        return remoteAccount === undefined
          ? { status: 404, payload: {} }
          : { status: 200, payload: structuredClone(remoteAccount) };
      }
      if (method === "POST" && url.endsWith("/serviceAccounts")) {
        accountCreateCount += 1;
        const serviceAccount = (options.jsonBody?.serviceAccount ?? {}) as Record<string, unknown>;
        remoteAccount = {
          email: accountEmail,
          uniqueId: "123456789012345678901",
          displayName: serviceAccount.displayName,
          description: serviceAccount.description,
        };
        throw new Error("committed-account-create-response-lost");
      }
      if (method === "GET" && url.endsWith(roleName)) {
        return remoteRole === undefined
          ? { status: 404, payload: {} }
          : { status: 200, payload: structuredClone(remoteRole) };
      }
      if (method === "POST" && url.endsWith("/roles")) {
        remoteRole = {
          ...((options.jsonBody?.role ?? {}) as Record<string, unknown>),
          name: roleName,
          etag: "role-etag",
        };
        return { status: 200, payload: structuredClone(remoteRole) };
      }
      if (method === "POST" && url.endsWith(":getIamPolicy")) {
        if (url.includes("/serviceAccounts/")) {
          return { status: 200, payload: structuredClone(accountPolicy) };
        }
        return {
          status: 200,
          payload: { version: 3, etag: "project-etag", bindings: projectBindings },
        };
      }
      if (method === "POST" && url.includes("/serviceAccounts/") &&
          url.endsWith(":setIamPolicy")) {
        accountPolicy = {
          ...(structuredClone(options.jsonBody?.policy) as typeof accountPolicy),
          etag: "account-after",
        };
        return { status: 200, payload: structuredClone(accountPolicy) };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let firstError: unknown;
  try {
    await bootstrapDeployer(projectId, {
      transport,
      operatorEmail: "admin@example.com",
      checkpointOwnershipPin: async (pin) => { checkpoint = structuredClone(pin); },
    });
  } catch (error) {
    firstError = error;
  }
  const intentPersisted =
    (checkpoint as { pending_mutation?: { kind?: unknown } } | undefined)
      ?.pending_mutation?.kind === "service_account_create";
  const resumed = await bootstrapDeployer(projectId, {
    transport,
    operatorEmail: "admin@example.com",
    ownershipPin: checkpoint,
    checkpointOwnershipPin: async (pin) => { checkpoint = structuredClone(pin); },
  });
  check(
    "bootstrap reconciles an exact first service-account create after response loss",
    firstError instanceof Error && intentPersisted && accountCreateCount === 1 &&
      resumed.service_account_unique_id === "123456789012345678901" &&
      (checkpoint as { service_account_iam_bindings?: unknown[] } | undefined)
        ?.service_account_iam_bindings?.length === 1,
    JSON.stringify({ firstError: String(firstError), accountCreateCount, checkpoint }),
  );
}

{
  const projectId = SPEC.project_id;
  const accountEmail =
    `secure-gateway-deployer@${projectId}.iam.gserviceaccount.com`;
  const roleName = `projects/${projectId}/roles/secureGatewayPocDeployer`;
  const tokenCreator = {
    role: "roles/iam.serviceAccountTokenCreator",
    members: ["user:admin@example.com"],
  };
  let checkpoint: BootstrapOwnershipCheckpoint = {
    version: 1,
    project_id: projectId,
    service_account_email: accountEmail,
    service_account_unique_id: "123456789012345678901",
    operator_email: "admin@example.com",
    service_account_iam_bindings: [tokenCreator],
    custom_role: roleName,
    custom_role_etag: null,
  };
  let remoteRole: Record<string, unknown> | undefined;
  let roleCreateCount = 0;
  const projectBindings = [
    { role: roleName, members: [`serviceAccount:${accountEmail}`] },
    { role: "roles/browser", members: [`serviceAccount:${accountEmail}`] },
    { role: "roles/serviceusage.serviceUsageConsumer", members: [`serviceAccount:${accountEmail}`] },
  ];
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.includes("/serviceAccounts/")) {
        return {
          status: 200,
          payload: {
            email: accountEmail,
            uniqueId: "123456789012345678901",
            displayName: "Secure Gateway Studio deployer",
          },
        };
      }
      if (method === "GET" && url.endsWith(roleName)) {
        return remoteRole === undefined
          ? { status: 404, payload: {} }
          : { status: 200, payload: structuredClone(remoteRole) };
      }
      if (method === "POST" && url.endsWith("/roles")) {
        roleCreateCount += 1;
        remoteRole = {
          ...((options.jsonBody?.role ?? {}) as Record<string, unknown>),
          name: roleName,
          etag: "role-after",
        };
        throw new Error("committed-role-create-response-lost");
      }
      if (method === "POST" && url.endsWith(":getIamPolicy")) {
        return url.includes("/serviceAccounts/")
          ? { status: 200, payload: { version: 3, etag: "account", bindings: [tokenCreator] } }
          : { status: 200, payload: { version: 3, etag: "project", bindings: projectBindings } };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let firstError: unknown;
  try {
    await bootstrapDeployer(projectId, {
      transport,
      operatorEmail: "admin@example.com",
      ownershipPin: checkpoint,
      checkpointOwnershipPin: async (pin) => { checkpoint = structuredClone(pin); },
    });
  } catch (error) {
    firstError = error;
  }
  const roleIntentPersisted =
    (checkpoint as { pending_mutation?: { kind?: unknown } }).pending_mutation?.kind ===
      "custom_role";
  await bootstrapDeployer(projectId, {
    transport,
    operatorEmail: "admin@example.com",
    ownershipPin: checkpoint,
    checkpointOwnershipPin: async (pin) => { checkpoint = structuredClone(pin); },
  });
  check(
    "bootstrap reconciles an exact custom-role create after response loss",
    firstError instanceof Error && roleIntentPersisted && roleCreateCount === 1 &&
      (checkpoint as { custom_role_etag?: unknown }).custom_role_etag === "role-after" &&
      (checkpoint as { pending_mutation?: unknown }).pending_mutation === undefined,
    JSON.stringify({ firstError: String(firstError), roleCreateCount, checkpoint }),
  );
}

{
  const projectId = SPEC.project_id;
  const accountEmail =
    `secure-gateway-deployer@${projectId}.iam.gserviceaccount.com`;
  const roleName = `projects/${projectId}/roles/secureGatewayPocDeployer`;
  const tokenCreator = {
    role: "roles/iam.serviceAccountTokenCreator",
    members: ["user:admin@example.com"],
  };
  let checkpoint: BootstrapOwnershipCheckpoint = {
    version: 1,
    project_id: projectId,
    service_account_email: accountEmail,
    service_account_unique_id: "123456789012345678901",
    operator_email: "admin@example.com",
    service_account_iam_bindings: [],
    custom_role: roleName,
    custom_role_etag: "role-etag",
  };
  let accountPolicy = { version: 3, etag: "before", bindings: [] as typeof tokenCreator[] };
  let accountSetCount = 0;
  const projectBindings = [
    { role: roleName, members: [`serviceAccount:${accountEmail}`] },
    { role: "roles/browser", members: [`serviceAccount:${accountEmail}`] },
    { role: "roles/serviceusage.serviceUsageConsumer", members: [`serviceAccount:${accountEmail}`] },
  ];
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.includes("/serviceAccounts/")) {
        return {
          status: 200,
          payload: {
            email: accountEmail,
            uniqueId: "123456789012345678901",
            displayName: "Secure Gateway Studio deployer",
          },
        };
      }
      if (method === "GET" && url.endsWith(roleName)) {
        return {
          status: 200,
          payload: { ...EXTENSION_DEPLOYER_ROLE, name: roleName, etag: "role-etag" },
        };
      }
      if (method === "POST" && url.endsWith(":getIamPolicy")) {
        return url.includes("/serviceAccounts/")
          ? { status: 200, payload: structuredClone(accountPolicy) }
          : { status: 200, payload: { version: 3, etag: "project", bindings: projectBindings } };
      }
      if (method === "POST" && url.includes("/serviceAccounts/") &&
          url.endsWith(":setIamPolicy")) {
        accountSetCount += 1;
        accountPolicy = {
          ...(structuredClone(options.jsonBody?.policy) as typeof accountPolicy),
          etag: "after",
        };
        throw new Error("committed-service-account-iam-response-lost");
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let firstError: unknown;
  try {
    await bootstrapDeployer(projectId, {
      transport,
      operatorEmail: "admin@example.com",
      ownershipPin: checkpoint,
      checkpointOwnershipPin: async (pin) => { checkpoint = structuredClone(pin); },
    });
  } catch (error) {
    firstError = error;
  }
  const iamIntentPersisted =
    (checkpoint as { pending_mutation?: { kind?: unknown } }).pending_mutation?.kind ===
      "service_account_iam";
  await bootstrapDeployer(projectId, {
    transport,
    operatorEmail: "admin@example.com",
    ownershipPin: checkpoint,
    checkpointOwnershipPin: async (pin) => { checkpoint = structuredClone(pin); },
  });
  check(
    "bootstrap reconciles exact service-account IAM after response loss without a second SET",
    firstError instanceof Error && iamIntentPersisted && accountSetCount === 1 &&
      (checkpoint as { service_account_iam_bindings?: unknown[] })
        .service_account_iam_bindings?.length === 1 &&
      (checkpoint as { pending_mutation?: unknown }).pending_mutation === undefined,
    JSON.stringify({ firstError: String(firstError), accountSetCount, checkpoint }),
  );
}

{
  const iamReads: Array<{
    url: string;
    body?: Record<string, unknown>;
    params?: Record<string, string | number>;
  }> = [];
  const iamWrites: Array<Record<string, unknown>> = [];
  let roleUpdate: Record<string, unknown> | undefined;
  let checkpoint: unknown;
  const accountEmail =
    "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com";
  const roleName = "projects/enterprise-secgw-01/roles/secureGatewayPocDeployer";
  const existingCondition = {
    role: "roles/viewer",
    members: ["user:auditor@example.com"],
    condition: {
      title: "Existing condition",
      expression: "request.time < timestamp('2030-01-01T00:00:00Z')",
      location: "bootstrap-policy.cel:17",
    },
  };
  const tokenCreator = {
    role: "roles/iam.serviceAccountTokenCreator",
    members: ["user:admin@example.com"],
  };
  let accountPolicy = {
    etag: "account-etag-1",
    version: 3,
    bindings: [structuredClone(tokenCreator)],
  };
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.includes("/serviceAccounts/") && !url.endsWith("IamPolicy")) {
        return {
          status: 200,
          payload: {
            email: accountEmail,
            uniqueId: "123456789012345678901",
            displayName: "Secure Gateway Studio deployer",
          },
        };
      }
      if (method === "GET" && url.endsWith(roleName)) {
        return {
          status: 200,
          payload: {
            name: roleName,
            etag: "role-etag-1",
            title: "Secure Gateway PoC Deployer",
            description:
              "Least-privilege project permissions for Secure Gateway Studio PoC apply and rollback.",
            includedPermissions: ["resourcemanager.projects.get"],
            stage: "GA",
          },
        };
      }
      if (method === "PATCH" && url.endsWith(roleName)) {
        roleUpdate = options.jsonBody;
        return {
          status: 200,
          payload: {
            ...options.jsonBody,
            name: roleName,
            etag: "role-etag-2",
          },
        };
      }
      if (method === "POST" && url.endsWith(":getIamPolicy")) {
        iamReads.push({ url, body: options.jsonBody, params: options.params });
        if (url.includes("/serviceAccounts/")) {
          return { status: 200, payload: structuredClone(accountPolicy) };
        }
        return {
          status: 200,
          payload: {
            etag: "project-etag",
            version: 3,
            bindings: [structuredClone(existingCondition)],
          },
        };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        const written = (options.jsonBody?.policy ?? {}) as Record<string, unknown>;
        iamWrites.push(structuredClone(written));
        if (url.includes("/serviceAccounts/")) {
          accountPolicy = {
            ...(structuredClone(written) as typeof accountPolicy),
            etag: "account-etag-2",
          };
        }
      }
      return { status: 200, payload: {} };
    },
  };
  await bootstrapDeployer(SPEC.project_id, {
    transport,
    operatorEmail: "admin@example.com",
    ownershipPin: {
      version: 1,
      project_id: SPEC.project_id,
      service_account_email: accountEmail,
      service_account_unique_id: "123456789012345678901",
      operator_email: "admin@example.com",
      service_account_iam_bindings: [tokenCreator],
      custom_role: roleName,
      custom_role_etag: "role-etag-1",
    },
    checkpointOwnershipPin: async (pin) => {
      checkpoint = structuredClone(pin);
    },
  });
  const serviceAccountReads = iamReads.filter((read) =>
    read.url.includes("/serviceAccounts/"));
  const projectReads = iamReads.filter((read) =>
    read.url.includes("cloudresourcemanager.googleapis.com"));
  check(
    "bootstrap preserves conditional IAM via requestedPolicyVersion 3",
    serviceAccountReads.length === 2 && serviceAccountReads.every(
      (read) => read.body === undefined &&
        read.params?.["options.requestedPolicyVersion"] === 3
    ) && projectReads.length === 1 && projectReads.every(
      (read) =>
        (read.body?.options as { requestedPolicyVersion?: unknown } | undefined)
            ?.requestedPolicyVersion === 3,
    ) &&
      iamWrites.length === 1 && iamWrites.every((policy) => policy.version === 3) &&
      (iamWrites[0]?.bindings as Array<Record<string, unknown>> | undefined)?.some(
        (binding) => binding.role === "roles/viewer" &&
          (binding.condition as { location?: unknown } | undefined)?.location ===
            "bootstrap-policy.cel:17",
      ) === true,
    `reads=${JSON.stringify(iamReads)}; writes=${JSON.stringify(iamWrites)}`,
  );
  const updatedPermissions = new Set(
    (roleUpdate?.includedPermissions ?? []) as readonly string[],
  );
  check(
    "bootstrap upgrades the compatibility role for Enterprise CA and Production",
    roleUpdate?.title === "Secure Gateway Studio Deployer" &&
      roleUpdate?.description === EXTENSION_DEPLOYER_ROLE.description &&
      [
        "privateca.certificates.create",
        "privateca.certificates.get",
        "privateca.certificates.update",
        "compute.instanceTemplates.create",
        "compute.instanceGroupManagers.create",
        "compute.autoscalers.create",
        "compute.networks.list",
        "compute.regionHealthChecks.create",
        "compute.regionHealthChecks.delete",
        "compute.regionHealthChecks.get",
      ].every((permission) => updatedPermissions.has(permission)),
    JSON.stringify(roleUpdate),
  );
  check(
    "bootstrap checkpoints audited account IAM before project grants",
    (checkpoint as {
      service_account_iam_bindings?: Array<{ role?: unknown; members?: unknown[] }>;
      custom_role_etag?: unknown;
    } | undefined)?.custom_role_etag === "role-etag-2" &&
      (checkpoint as {
        service_account_iam_bindings?: Array<{ role?: unknown; members?: unknown[] }>;
      }).service_account_iam_bindings?.some(
        (binding) => binding.role === "roles/iam.serviceAccountTokenCreator" &&
          binding.members?.includes("user:admin@example.com"),
      ) === true,
    JSON.stringify(checkpoint),
  );
}

{
  const projectId = SPEC.project_id;
  const accountEmail =
    `secure-gateway-deployer@${projectId}.iam.gserviceaccount.com`;
  const roleName = `projects/${projectId}/roles/secureGatewayPocDeployer`;
  const tokenCreator = {
    role: "roles/iam.serviceAccountTokenCreator",
    members: ["user:admin@example.com"],
  };
  const malformedPolicies: Record<string, unknown>[] = [
    {
      version: 3,
      etag: "project-etag",
      bindings: [{
        role: "roles/viewer",
        members: ["user:auditor@example.com"],
        unexpected: true,
      }],
    },
    {
      version: 3,
      etag: "project-etag",
      bindings: [{ role: "roles/viewer", members: [] }],
    },
    {
      version: 3,
      etag: "project-etag",
      bindings: [{
        role: "roles/viewer",
        members: ["user:auditor@example.com"],
        condition: {
          title: "condition",
          expression: "true",
          unexpected: true,
        },
      }],
    },
    {
      version: 3,
      etag: "project-etag",
      bindings: [],
      auditConfigs: [{ service: "allServices", auditLogConfigs: "DATA_READ" }],
    },
    { version: 3, etag: "project-etag", bindings: null },
    { version: 3, bindings: [] },
  ];
  const results: Array<{ error: unknown; writes: number }> = [];
  for (const malformedPolicy of malformedPolicies) {
    let writes = 0;
    const transport: Transport = {
      async requestJson(method, url) {
        if (
          method === "GET" && url.includes("/serviceAccounts/") &&
          !url.endsWith("IamPolicy")
        ) {
          return {
            status: 200,
            payload: {
              email: accountEmail,
              uniqueId: "123456789012345678901",
              displayName: "Secure Gateway Studio deployer",
            },
          };
        }
        if (method === "GET" && url.endsWith(roleName)) {
          return {
            status: 200,
            payload: {
              ...EXTENSION_DEPLOYER_ROLE,
              name: roleName,
              etag: "role-etag-1",
            },
          };
        }
        if (method === "POST" && url.endsWith(":getIamPolicy")) {
          if (url.includes("/serviceAccounts/")) {
            return {
              status: 200,
              payload: {
                version: 3,
                etag: "account-etag",
                bindings: [structuredClone(tokenCreator)],
              },
            };
          }
          return { status: 200, payload: structuredClone(malformedPolicy) };
        }
        if (method === "POST" && url.endsWith(":setIamPolicy")) {
          writes += 1;
        }
        return { status: 200, payload: {} };
      },
    };
    let error: unknown;
    try {
      await bootstrapDeployer(projectId, {
        transport,
        operatorEmail: "admin@example.com",
        ownershipPin: {
          version: 1,
          project_id: projectId,
          service_account_email: accountEmail,
          service_account_unique_id: "123456789012345678901",
          operator_email: "admin@example.com",
          service_account_iam_bindings: [tokenCreator],
          custom_role: roleName,
          custom_role_etag: "role-etag-1",
        },
        checkpointOwnershipPin: async () => undefined,
      });
    } catch (caught) {
      error = caught;
    }
    results.push({ error, writes });
  }
  check(
    "bootstrap rejects every malformed fresh IAM policy before any SET",
    results.every(({ error, writes }) => error instanceof Error && writes === 0),
    JSON.stringify(results.map(({ error, writes }) => ({ error: String(error), writes }))),
  );
}

// Audit events are derived from persisted state transitions. Saving an
// unchanged checkpoint must not duplicate evidence, while every external
// attempt and terminal run result must be represented in the hash chain.
{
  const target = change("compute", "network", "audit-vpc");
  const pending: RunRecord = {
    runId: "run-audit",
    approvalId: "approval-audit",
    configurationHash: "configuration-audit",
    state: "running",
    steps: [{
      index: 0,
      change: target,
      digest: "operation-audit",
      requestId: "0675d719-b3ff-4f80-a5c5-885b1f34de13",
      status: "pending",
      attempts: 0,
      error: null,
    }],
  };
  const running = structuredClone(pending);
  running.steps[0]!.status = "running";
  running.steps[0]!.attempts = 1;
  const done = structuredClone(running);
  done.steps[0]!.status = "done";
  const succeeded = structuredClone(done);
  succeeded.state = "succeeded";
  const retry = structuredClone(running);
  retry.steps[0]!.status = "pending";
  retry.steps[0]!.error = "provider-operation-timeout";
  const rolledBack = structuredClone(retry);
  rolledBack.state = "rolled_back";
  const rollingBack = structuredClone(done);
  rollingBack.state = "rolling_back";
  const compensated = structuredClone(rollingBack);
  compensated.steps[0]!.status = "pending";

  check(
    "audit emits operation.started only for a new persisted attempt",
    runAuditTransitions(pending, running)[0]?.eventType === "operation.started" &&
      runAuditTransitions(running, structuredClone(running)).length === 0,
  );
  check(
    "audit emits operation completion and failure transitions",
    runAuditTransitions(running, done)[0]?.eventType === "operation.completed" &&
      runAuditTransitions(running, retry)[0]?.eventType === "operation.completed" &&
      runAuditTransitions(running, retry)[0]?.payload.status === "failed",
  );
  check(
    "audit emits hash-chain input for terminal run outcomes",
    runAuditTransitions(done, succeeded).some((event) => event.eventType === "run.succeeded") &&
      runAuditTransitions(retry, rolledBack).some((event) => event.eventType === "run.rolled_back"),
  );
  check(
    "audit attests successful rollback compensation",
    runAuditTransitions(rollingBack, compensated)[0]?.payload.status === "rolled_back",
  );
}

{
  const created = change("compute", "network", "owned-vpc");
  const sharedCreate = { ...change("compute", "network", "shared-vpc"), owned_after_apply: false };
  const reused = { ...change("compute", "network", "existing-vpc"), action: "reuse" as const };
  const unchanged = { ...change("compute", "network", "same-vpc"), action: "no_change" as const };
  const records = resourceRecordsForPlan([created, sharedCreate, reused, unchanged]);
  check("resource inventory records create and reuse only", records.length === 3, String(records.length));
  check(
    "resource inventory distinguishes owned and shared resources",
    records[0]?.owned === true && records[0]?.shared === false &&
      records[1]?.owned === false && records[1]?.shared === true &&
      records[2]?.owned === false && records[2]?.shared === true,
    JSON.stringify(records),
  );
}

// A retry after the mutation landed must retain the original compensation
// image persisted by the first worker. Re-reading the now-mutated policy as the
// new "before" state would make rollback preserve our own write.
{
  let policy: Record<string, unknown> = {
    version: 1,
    etag: "original-etag",
    bindings: [{ role: "roles/viewer", members: ["user:owner@example.com"] }],
  };
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        return { status: 200, payload: structuredClone(policy) };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        policy = structuredClone(
          (options.jsonBody?.policy ?? {}) as Record<string, unknown>,
        );
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change("beyondcorp", "gateway_iam", "default-iam");
  const first = await new GoogleResourceExecutor(transport).apply(target, SPEC, {
    runId: "run-before-retry",
    stepIndex: 0,
    requestId: "2f9162bf-7390-4eaf-9b31-303f001ec78a",
  });
  const second = await new GoogleResourceExecutor(transport).apply(target, SPEC, {
    runId: "run-before-retry",
    stepIndex: 0,
    requestId: "2f9162bf-7390-4eaf-9b31-303f001ec78a",
    beforeImage: first.beforeImage,
  });
  const original = (
    second.beforeImage as
      | { policy?: { etag?: unknown; bindings?: Array<{ role?: unknown }> } }
      | undefined
  )?.policy;
  check(
    "retry preserves the first worker's original before-image",
    original?.etag === "original-etag" &&
      original.bindings?.length === 1 &&
      original.bindings[0]?.role === "roles/viewer",
    JSON.stringify(second.beforeImage),
  );
}

// Secret Manager create has no requestId. A crash retry may return 409, but it
// is safe only after the exact secret is read and its ownership/configuration
// labels match this deployment.
{
  let expectedLabels: Record<string, unknown> = {};
  let reconciled = false;
  const transport: Transport = {
    async requestJson(method, _url, options = {}) {
      if (method === "POST") {
        expectedLabels = (options.jsonBody?.labels ?? {}) as Record<string, unknown>;
        return {
          status: 409,
          payload: { error: { status: "ALREADY_EXISTS", message: "exists" } },
        };
      }
      reconciled = true;
      return {
        status: 200,
        payload: { labels: expectedLabels, replication: { automatic: {} } },
      };
    },
  };
  const executor = new GoogleResourceExecutor(transport);
  let error: unknown;
  try {
    await executor.apply(
      change("secretmanager", "secret", "demo-tls"),
      SPEC,
      { runId: "run-secret-create", stepIndex: 0, requestId: crypto.randomUUID() },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "Secret Manager ALREADY_EXISTS is accepted only after semantic reconciliation",
    error === undefined && reconciled,
    String(error),
  );
}

// addVersion has no requestId. If the worker dies after Google created the
// version, the persisted before-image is also the durable operation result:
// retry must finish promoting that exact version instead of uploading a second
// copy of the private key.
{
  const secretUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/demo-tls";
  const versionName = `${secretUrl}/versions/7`;
  let addVersionCalls = 0;
  let activeAlias: unknown;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "POST" && url.endsWith(":addVersion")) {
        addVersionCalls += 1;
        return { status: 200, payload: { name: `${secretUrl}/versions/8` } };
      }
      if (method === "GET" && url === versionName) {
        return { status: 200, payload: { name: versionName, state: "ENABLED" } };
      }
      if (method === "GET" && url === secretUrl) {
        return {
          status: 200,
          payload: {
            etag: "after-add-etag",
            labels: { "managed-by": "secure-gateway-studio" },
            versionAliases: { active: "6" },
          },
        };
      }
      if (method === "PATCH" && url === secretUrl) {
        activeAlias = (options.jsonBody?.versionAliases as Record<string, unknown> | undefined)
          ?.active;
      }
      return { status: 200, payload: {} };
    },
  };
  const executor = new GoogleResourceExecutor(transport);
  let error: unknown;
  try {
    await executor.apply(
      change("secretmanager", "secret_version", "demo-tls"),
      SPEC,
      {
        runId: "run-secret-version-retry",
        stepIndex: 0,
        requestId: crypto.randomUUID(),
        beforeImage: {
          kind: "secret_version",
          secretUrl,
          versionName,
          previousAliases: { active: "6" },
          previousLabels: { "managed-by": "secure-gateway-studio" },
        },
      },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "secret-version retry resumes the recorded version without addVersion",
    error === undefined && addVersionCalls === 0 && activeAlias === "7",
    `${String(error)}; addVersion=${addVersionCalls}; active=${String(activeAlias)}`,
  );
}

// The GET used to prepare addVersion is not the compensation baseline for the
// later metadata PATCH. If an administrator changes the same alias/label keys
// while addVersion is in flight, the fresh etag-bearing GET immediately before
// PATCH must become both the before-image and the managed-after base.
{
  const secretUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/toctou-tls";
  const relativeVersion6 =
    "projects/enterprise-secgw-01/secrets/toctou-tls/versions/6";
  const relativeVersion7 =
    "projects/enterprise-secgw-01/secrets/toctou-tls/versions/7";
  let secretGets = 0;
  let checkpoint: unknown;
  let patched: Record<string, unknown> | undefined;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      // The service-worker transport constructs URL directly. Any relative
      // response name accidentally reused as a request must fail this test.
      new URL(url);
      if (method === "GET" && url === secretUrl) {
        secretGets += 1;
        return secretGets === 1
          ? {
            status: 200,
            payload: {
              etag: "original-etag",
              versionAliases: { active: "6" },
              labels: { shared: "original" },
            },
          }
          : {
            status: 200,
            payload: {
              etag: "fresh-etag",
              versionAliases: { active: "5", admin: "4" },
              labels: { shared: "admin-changed", admin: "kept" },
            },
          };
      }
      if (method === "GET" && url === `${secretUrl}/versions`) {
        return {
          status: 200,
          payload: { versions: [{ name: relativeVersion6, state: "ENABLED" }] },
        };
      }
      if (method === "POST" && url === `${secretUrl}:addVersion`) {
        return { status: 200, payload: { name: relativeVersion7 } };
      }
      if (method === "GET" && url === `${secretUrl}/versions/7`) {
        return { status: 200, payload: { name: relativeVersion7, state: "ENABLED" } };
      }
      if (method === "PATCH" && url === secretUrl) {
        patched = structuredClone(options.jsonBody ?? {});
        return { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(transport, {
      certificate: {
        certificatePem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
        certificateChainPem: [
          "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
        ],
        privateKeyPem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        hostname: SPEC.private_hostname,
        issuerResourceName: null,
      },
    }).apply(change("secretmanager", "secret_version", "toctou-tls"), SPEC, {
      runId: "run-secret-toctou",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (caught) {
    error = caught;
  }
  const image = checkpoint as {
    previousAliases?: Record<string, string>;
    previousLabels?: Record<string, string>;
    managedAfterAliases?: Record<string, string>;
    managedAfterLabels?: Record<string, string>;
  } | undefined;
  const patchedAliases = patched?.versionAliases as Record<string, string> | undefined;
  const patchedLabels = patched?.labels as Record<string, string> | undefined;
  check(
    "secret rotation checkpoints the fresh pre-PATCH snapshot and preserves in-flight admin edits",
    error === undefined && secretGets === 2 && patched?.etag === "fresh-etag" &&
      image?.previousAliases?.active === "5" && image.previousAliases.admin === "4" &&
      image.previousLabels?.shared === "admin-changed" && image.previousLabels.admin === "kept" &&
      image.managedAfterAliases?.active === "7" && image.managedAfterAliases.admin === "4" &&
      image.managedAfterLabels?.shared === "admin-changed" &&
      image.managedAfterLabels.admin === "kept" &&
      image.managedAfterLabels["sgs-previous-active"] === "5" &&
      patchedAliases?.active === "7" && patchedAliases.admin === "4" &&
      patchedLabels?.shared === "admin-changed" && patchedLabels.admin === "kept" &&
      patchedLabels["sgs-previous-active"] === "5",
    JSON.stringify({ error: String(error), checkpoint, patched }),
  );
}

// Secret Manager reports an etag race as HTTP 400/FAILED_PRECONDITION. The
// metadata RMW must fresh-read and retry that exact condition while preserving
// unrelated aliases/labels that appeared concurrently.
{
  const secretUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/etag-race-tls";
  const relativeVersion =
    "projects/enterprise-secgw-01/secrets/etag-race-tls/versions/7";
  let secretGets = 0;
  let patchCalls = 0;
  let finalPatch: Record<string, unknown> | undefined;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url === `${secretUrl}/versions`) {
        return { status: 200, payload: { versions: [] } };
      }
      if (method === "POST" && url === `${secretUrl}:addVersion`) {
        return { status: 200, payload: { name: relativeVersion } };
      }
      if (method === "GET" && url === secretUrl) {
        secretGets += 1;
        if (secretGets < 3) {
          return {
            status: 200,
            payload: {
              etag: `stale-${secretGets}`,
              versionAliases: { active: "6" },
              labels: { shared: "before" },
            },
          };
        }
        return {
          status: 200,
          payload: {
            etag: "fresh-after-admin-edit",
            versionAliases: { active: "6", admin: "9" },
            labels: { shared: "before", admin: "kept" },
          },
        };
      }
      if (method === "PATCH" && url === secretUrl) {
        patchCalls += 1;
        if (patchCalls === 1) {
          throw new GoogleApiError({
            status: 400,
            method,
            url,
            payload: { error: { status: "FAILED_PRECONDITION", message: "etag stale" } },
          });
        }
        finalPatch = structuredClone(options.jsonBody ?? {});
        return { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(transport, {
      certificate: {
        certificatePem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
        certificateChainPem: [],
        privateKeyPem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        hostname: SPEC.private_hostname,
        issuerResourceName: null,
      },
    }).apply(change("secretmanager", "secret_version", "etag-race-tls"), SPEC, {
      runId: "run-secret-etag-race",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
    });
  } catch (caught) {
    error = caught;
  }
  const aliases = finalPatch?.versionAliases as Record<string, string> | undefined;
  const labels = finalPatch?.labels as Record<string, string> | undefined;
  check(
    "secret metadata apply retries exact FAILED_PRECONDITION and preserves unrelated edits",
    error === undefined && patchCalls === 2 && secretGets === 3 &&
      finalPatch?.etag === "fresh-after-admin-edit" && aliases?.active === "7" &&
      aliases.admin === "9" && labels?.admin === "kept" && labels.shared === "before",
    JSON.stringify({ error: String(error), patchCalls, secretGets, finalPatch }),
  );
}

// Arbitrary HTTP 400 is a semantic rejection, not an etag race. It must not be
// retried with a fresh GET or a second metadata mutation.
{
  const secretUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/invalid-patch-tls";
  const relativeVersion =
    "projects/enterprise-secgw-01/secrets/invalid-patch-tls/versions/7";
  let patchCalls = 0;
  let secretGets = 0;
  const transport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url === `${secretUrl}/versions`) {
        return { status: 200, payload: { versions: [] } };
      }
      if (method === "POST" && url === `${secretUrl}:addVersion`) {
        return { status: 200, payload: { name: relativeVersion } };
      }
      if (method === "GET" && url === secretUrl) {
        secretGets += 1;
        return {
          status: 200,
          payload: { etag: `etag-${secretGets}`, versionAliases: {}, labels: {} },
        };
      }
      if (method === "PATCH" && url === secretUrl) {
        patchCalls += 1;
        throw new GoogleApiError({
          status: 400,
          method,
          url,
          payload: { error: { status: "INVALID_ARGUMENT", message: "bad metadata" } },
        });
      }
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(transport, {
      certificate: {
        certificatePem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
        certificateChainPem: [],
        privateKeyPem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        hostname: SPEC.private_hostname,
        issuerResourceName: null,
      },
    }).apply(change("secretmanager", "secret_version", "invalid-patch-tls"), SPEC, {
      runId: "run-secret-invalid-patch",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
    });
  } catch (caught) {
    error = caught;
  }
  check(
    "secret metadata apply does not retry arbitrary HTTP 400",
    error instanceof Error && patchCalls === 1 && secretGets === 2,
    JSON.stringify({ error: String(error), patchCalls, secretGets }),
  );
}

// If addVersion commits but its response is lost, the pre-call checkpoint
// contains the payload digest and exact baseline. Recovery lists only new
// versions, accesses their payload, and adopts one exact match before moving
// the alias; it never performs a second addVersion.
{
  const secretUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/recover-tls";
  const version7 = `${secretUrl}/versions/7`;
  const relativeVersion6 =
    "projects/enterprise-secgw-01/secrets/recover-tls/versions/6";
  const relativeVersion7 =
    "projects/enterprise-secgw-01/secrets/recover-tls/versions/7";
  let checkpoint: unknown;
  let created = false;
  let payloadData = "";
  let addVersionCalls = 0;
  let activeAlias: unknown;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      new URL(url);
      if (method === "GET" && url === `${secretUrl}/versions`) {
        return {
          status: 200,
          payload: {
            versions: [
              { name: relativeVersion6, state: "ENABLED" },
              ...(created ? [{ name: relativeVersion7, state: "ENABLED" }] : []),
            ],
          },
        };
      }
      if (method === "POST" && url === `${secretUrl}:addVersion`) {
        addVersionCalls += 1;
        payloadData = (
          options.jsonBody?.payload as { data?: string } | undefined
        )?.data ?? "";
        created = true;
        throw new Error("connection-reset-after-commit");
      }
      if (method === "GET" && url === `${version7}:access`) {
        return { status: 200, payload: { payload: { data: payloadData } } };
      }
      if (method === "GET" && url === version7) {
        return { status: 200, payload: { name: version7, state: "ENABLED" } };
      }
      if (method === "GET" && url === secretUrl) {
        return {
          status: 200,
          payload: {
            etag: "recovery-etag",
            labels: { "managed-by": "secure-gateway-studio" },
            versionAliases: { active: "6" },
          },
        };
      }
      if (method === "PATCH" && url === secretUrl) {
        activeAlias = (
          options.jsonBody?.versionAliases as Record<string, unknown> | undefined
        )?.active;
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change("secretmanager", "secret_version", "recover-tls");
  const requestId = "d84c38ca-f9a9-42a4-924b-ae96bddaa8bb";
  let firstError: unknown;
  try {
    await new GoogleResourceExecutor(transport, {
      certificate: {
        certificatePem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
        certificateChainPem: [
          "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
        ],
        privateKeyPem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        hostname: SPEC.private_hostname,
        issuerResourceName: null,
      },
    }).apply(target, SPEC, {
      runId: "run-secret-response-loss",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (caught) {
    firstError = caught;
  }
  let retryError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-secret-response-loss",
      stepIndex: 0,
      requestId,
      beforeImage: checkpoint,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (caught) {
    retryError = caught;
  }
  check(
    "secret-version response-loss recovery adopts one exact payload without duplicate add",
    firstError instanceof Error && retryError === undefined && addVersionCalls === 1 &&
      activeAlias === "7" &&
      (checkpoint as { phase?: unknown; versionName?: unknown } | undefined)?.phase ===
        "applied" &&
      (checkpoint as { versionName?: unknown } | undefined)?.versionName === version7,
    JSON.stringify({
      firstError: String(firstError),
      retryError: String(retryError),
      addVersionCalls,
      activeAlias,
      checkpoint,
    }),
  );
}

// A definite client rejection proves addVersion did not create anything. The
// durable checkpoint must advance through prepared/sending/rejected, and
// rollback must be a no-op instead of inventing a version to disable.
{
  const secretUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/rejected-tls";
  let checkpoint: unknown;
  const phases: unknown[] = [];
  let requests = 0;
  const transport: Transport = {
    async requestJson(method, url) {
      requests += 1;
      new URL(url);
      if (method === "GET" && url === secretUrl) {
        return {
          status: 200,
          payload: { etag: "before", versionAliases: { active: "6" }, labels: {} },
        };
      }
      if (method === "GET" && url === `${secretUrl}/versions`) {
        return { status: 200, payload: { versions: [] } };
      }
      if (method === "POST" && url === `${secretUrl}:addVersion`) {
        return {
          status: 400,
          payload: { error: { status: "INVALID_ARGUMENT", message: "rejected" } },
        };
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change("secretmanager", "secret_version", "rejected-tls");
  let applyError: unknown;
  try {
    await new GoogleResourceExecutor(transport, {
      certificate: {
        certificatePem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
        certificateChainPem: [
          "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
        ],
        privateKeyPem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        hostname: SPEC.private_hostname,
        issuerResourceName: null,
      },
    }).apply(target, SPEC, {
      runId: "run-secret-rejected",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
        phases.push((value as { phase?: unknown }).phase);
      },
    });
  } catch (error) {
    applyError = error;
  }
  const requestsBeforeRollback = requests;
  await new GoogleResourceExecutor(transport).rollback(target, SPEC, {
    runId: "run-secret-rejected",
    stepIndex: 0,
    requestId: crypto.randomUUID(),
    beforeImage: checkpoint,
  });
  check(
    "definite addVersion rejection leaves a no-op rollback checkpoint",
    applyError instanceof Error &&
      JSON.stringify(phases) === JSON.stringify(["prepared", "sending", "rejected"]) &&
      (checkpoint as { phase?: unknown; versionName?: unknown } | undefined)?.phase ===
        "rejected" &&
      (checkpoint as { versionName?: unknown } | undefined)?.versionName === null &&
      requests === requestsBeforeRollback,
    JSON.stringify({ applyError: String(applyError), phases, checkpoint, requests }),
  );
}

// A lost alias-PATCH response is reconciled from the durable alias_sending
// checkpoint. If live metadata is already the exact managed-after image, retry
// records applied and never sends the PATCH twice.
{
  const secretUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/alias-loss-tls";
  const relative6 =
    "projects/enterprise-secgw-01/secrets/alias-loss-tls/versions/6";
  const relative7 =
    "projects/enterprise-secgw-01/secrets/alias-loss-tls/versions/7";
  const version7 = `${secretUrl}/versions/7`;
  let checkpoint: unknown;
  let patchCalls = 0;
  let liveAliases: Record<string, string> = { active: "6" };
  let liveLabels: Record<string, string> = {};
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      new URL(url);
      if (method === "GET" && url === `${secretUrl}/versions`) {
        return {
          status: 200,
          payload: { versions: [{ name: relative6, state: "ENABLED" }] },
        };
      }
      if (method === "POST" && url === `${secretUrl}:addVersion`) {
        return { status: 200, payload: { name: relative7 } };
      }
      if (method === "GET" && url === version7) {
        return { status: 200, payload: { name: relative7, state: "ENABLED" } };
      }
      if (method === "GET" && url === secretUrl) {
        return {
          status: 200,
          payload: {
            etag: `etag-${patchCalls}`,
            versionAliases: structuredClone(liveAliases),
            labels: structuredClone(liveLabels),
          },
        };
      }
      if (method === "PATCH" && url === secretUrl) {
        patchCalls += 1;
        liveAliases = structuredClone(
          (options.jsonBody?.versionAliases ?? {}) as Record<string, string>,
        );
        liveLabels = structuredClone(
          (options.jsonBody?.labels ?? {}) as Record<string, string>,
        );
        throw new Error("connection-reset-after-alias-commit");
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change("secretmanager", "secret_version", "alias-loss-tls");
  let firstError: unknown;
  try {
    await new GoogleResourceExecutor(transport, {
      certificate: {
        certificatePem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
        certificateChainPem: [
          "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
        ],
        privateKeyPem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        hostname: SPEC.private_hostname,
        issuerResourceName: null,
      },
    }).apply(target, SPEC, {
      runId: "run-secret-alias-loss",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (error) {
    firstError = error;
  }
  let retryError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-secret-alias-loss",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      beforeImage: checkpoint,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (error) {
    retryError = error;
  }
  check(
    "alias PATCH response loss reconciles applied state without a second write",
    firstError instanceof Error && retryError === undefined && patchCalls === 1 &&
      liveAliases.active === "7" &&
      (checkpoint as { phase?: unknown; versionName?: unknown } | undefined)?.phase ===
        "applied" &&
      (checkpoint as { versionName?: unknown } | undefined)?.versionName === version7,
    JSON.stringify({ firstError: String(firstError), retryError: String(retryError), checkpoint }),
  );
}

// An AUTO_CREATE placeholder is never a valid IAM access-level name. If
// discovery/creation fails, application IAM must stop instead of embedding the
// placeholder into a condition and claiming success.
{
  let iamWrite = false;
  const transport: Transport = {
    async requestJson(method, url) {
      if (url.includes("cloudresourcemanager.googleapis.com")) {
        return { status: 200, payload: { projectId: SPEC.project_id } };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) iamWrite = true;
      return { status: 200, payload: { bindings: [], etag: "before" } };
    },
  };
  const executor = new GoogleResourceExecutor(transport);
  let error: unknown;
  try {
    await executor.apply(
      change("beyondcorp", "application_iam", `${SPEC.name}-app-iam`),
      { ...SPEC, managed_chrome_access_level: "AUTO_CREATE_PROFILE" },
      { runId: "run-access-level", stepIndex: 0, requestId: crypto.randomUUID() },
    );
  } catch (caught) {
    error = caught;
  }
  check("failed managed-access-level creation aborts application IAM", error instanceof Error);
  check("no IAM condition is written with an AUTO_CREATE placeholder", iamWrite === false);
}

// A successful Access Context Manager operation is not proof that the exact
// management predicate now occupies the reserved name. A concurrent or
// normalized wrong resource must stop before Application IAM is even read or
// written.
{
  const fullName = "accessPolicies/456/accessLevels/secgw_profile_managed";
  const operationName = `${fullName}/create/create-level-1`;
  let accessLevelReads = 0;
  let iamReads = 0;
  let iamWrites = 0;
  const transport: Transport = {
    async requestJson(method, url) {
      if (url.endsWith(`/projects/${SPEC.project_id}`)) {
        return {
          status: 200,
          payload: { name: "projects/111", parent: "organizations/123" },
        };
      }
      if (url.endsWith("/accessPolicies/456")) {
        return {
          status: 200,
          payload: { name: "accessPolicies/456", parent: "organizations/123" },
        };
      }
      if (url.endsWith(`/${fullName}`) && method === "GET") {
        accessLevelReads += 1;
        if (accessLevelReads === 1) {
          return { status: 404, payload: { error: { status: "NOT_FOUND" } } };
        }
        return {
          status: 200,
          payload: {
            name: fullName,
            title: "Managed Chrome Profile (SGS)",
            description: "Created automatically by Secure Gateway Studio",
            custom: { expr: { expression: "true" } },
          },
        };
      }
      if (url.endsWith("/accessPolicies/456/accessLevels") && method === "POST") {
        return { status: 200, payload: { name: operationName, done: true } };
      }
      if (url.endsWith(":getIamPolicy")) {
        iamReads += 1;
        return { status: 200, payload: { version: 3, etag: "before", bindings: [] } };
      }
      if (url.endsWith(":setIamPolicy") && method === "POST") {
        iamWrites += 1;
        return { status: 200, payload: { version: 3, etag: "after", bindings: [] } };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(transport, { accessPolicyId: "456" }).apply(
      change("beyondcorp", "application_iam", `${SPEC.name}-app-iam`),
      { ...SPEC, managed_chrome_access_level: "AUTO_CREATE_PROFILE" },
      { runId: "run-access-level-post-create-drift", stepIndex: 0, requestId: crypto.randomUUID() },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "post-create Access Level semantic drift aborts Application IAM",
    error instanceof ConnectionError && error.code === "access-level-verification-failed" &&
      accessLevelReads === 2 && iamReads === 0 && iamWrites === 0,
    JSON.stringify({ error: String(error), accessLevelReads, iamReads, iamWrites }),
  );
}

{
  const cases: Array<{
    target: ResourceChange;
    policy: Record<string, unknown>;
  }> = [
    {
      target: change("beyondcorp", "gateway_iam", "default-service-discovery-users"),
      policy: {
        version: 3,
        etag: "gateway-etag",
        bindings: [{
          role: "roles/viewer",
          members: ["user:auditor@example.com"],
          unknown: true,
        }],
      },
    },
    {
      target: change("beyondcorp", "gateway_iam", "default-service-discovery-users"),
      policy: {
        version: 3,
        etag: "gateway-empty-members-etag",
        bindings: [{ role: "roles/viewer", members: [] }],
      },
    },
    {
      target: change("beyondcorp", "application_iam", `${SPEC.name}-app-iam`),
      policy: {
        version: 3,
        etag: "application-etag",
        bindings: [{
          role: "roles/viewer",
          members: ["user:auditor@example.com", "user:auditor@example.com"],
        }],
      },
    },
    {
      target: change("cloudresourcemanager", "project_iam", `${SPEC.name}-upstream-access`),
      policy: {
        version: 3,
        etag: "project-etag",
        bindings: [],
        auditConfigs: [{ service: "allServices", unexpected: true }],
      },
    },
  ];
  const results: Array<{ error: unknown; writes: number }> = [];
  for (const testCase of cases) {
    let writes = 0;
    const transport: Transport = {
      async requestJson(method, url) {
        if (method === "GET" && url.endsWith("/securityGateways/default")) {
          return {
            status: 200,
            payload: {
              delegatingServiceAccount:
                "gateway@enterprise-secgw-01.iam.gserviceaccount.com",
            },
          };
        }
        if (
          (method === "GET" || method === "POST") &&
          url.endsWith(":getIamPolicy")
        ) {
          return { status: 200, payload: structuredClone(testCase.policy) };
        }
        if (method === "POST" && url.endsWith(":setIamPolicy")) writes += 1;
        return { status: 200, payload: {} };
      },
    };
    let error: unknown;
    try {
      await new GoogleResourceExecutor(transport).apply(testCase.target, SPEC, {
        runId: `run-malformed-${testCase.target.resource_type}`,
        stepIndex: 0,
        requestId: crypto.randomUUID(),
      });
    } catch (caught) {
      error = caught;
    }
    results.push({ error, writes });
  }
  check(
    "gateway, application, and project IAM reject malformed unrelated state before SET",
    results.every(({ error, writes }) =>
      (error as { code?: unknown } | undefined)?.code === "iam-policy-bindings-invalid" &&
      writes === 0
    ),
    JSON.stringify(results.map(({ error, writes }) => ({
      code: (error as { code?: unknown } | undefined)?.code,
      writes,
    }))),
  );
}

// IAM permits multiple bindings for one role when their conditions differ.
// Updating or tearing down SGS's binding must not merge or strip the members
// of a separate conditional grant owned by an administrator.
{
  const level = "accessPolicies/123/accessLevels/managed_profile";
  const managedCondition = {
    title: "Managed Chrome required",
    description: "Allow only profiles or browsers managed by this enterprise",
    expression: `'${level}' in request.auth.access_levels`,
  };
  const otherCondition = {
    title: "Emergency access",
    description: "Administrator-owned exception",
    expression: "request.time < timestamp('2030-01-01T00:00:00Z')",
  };
  let policy: Record<string, unknown> = {
    version: 3,
    etag: "iam-etag",
    bindings: [
      {
        role: "roles/beyondcorp.sgApplicationUser",
        members: ["group:breakglass@example.com"],
        condition: otherCondition,
      },
      {
        role: "roles/beyondcorp.sgApplicationUser",
        members: ["user:existing@example.com"],
        condition: managedCondition,
      },
      { role: "roles/viewer", members: ["user:auditor@example.com"] },
    ],
  };
  const requestedVersions: unknown[] = [];
  const writtenVersions: unknown[] = [];
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        requestedVersions.push(options.params?.["options.requestedPolicyVersion"]);
        return { status: 200, payload: structuredClone(policy) };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        policy = structuredClone(
          (options.jsonBody?.policy ?? {}) as Record<string, unknown>,
        );
        writtenVersions.push(policy.version);
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change("beyondcorp", "application_iam", `${SPEC.name}-app-iam`);
  const executor = new GoogleResourceExecutor(transport);
  await executor.apply(target, { ...SPEC, managed_chrome_access_level: level }, {
    runId: "run-conditional-iam",
    stepIndex: 0,
    requestId: crypto.randomUUID(),
  });
  const afterApply = structuredClone(policy.bindings) as Array<{
    role?: string;
    members?: string[];
    condition?: { title?: string };
  }>;
  await executor.destroy(
    target,
    { ...SPEC, managed_chrome_access_level: level },
    crypto.randomUUID(),
  );
  const afterDestroy = policy.bindings as Array<{
    role?: string;
    members?: string[];
    condition?: { title?: string };
  }>;
  const appliedOther = afterApply.find((binding) => binding.condition?.title === "Emergency access");
  const appliedManaged = afterApply.find(
    (binding) => binding.condition?.title === "Managed Chrome required",
  );
  const destroyedOther = afterDestroy.find(
    (binding) => binding.condition?.title === "Emergency access",
  );
  check(
    "IAM apply preserves same-role bindings with different conditions",
    afterApply.length === 3 &&
      JSON.stringify(appliedOther?.members) === JSON.stringify(["group:breakglass@example.com"]) &&
      appliedManaged?.members?.includes("user:existing@example.com") === true &&
      appliedManaged.members.includes("group:secure-access@example.com"),
    JSON.stringify(afterApply),
  );
  check(
    "IAM teardown removes members only from the exact SGS condition",
    afterDestroy.length === 3 &&
      JSON.stringify(destroyedOther?.members) === JSON.stringify(["group:breakglass@example.com"]) &&
      afterDestroy.find((binding) => binding.condition?.title === "Managed Chrome required")
        ?.members?.includes("user:existing@example.com") === true,
    JSON.stringify(afterDestroy),
  );
  check(
    "BeyondCorp IAM RMW requests and writes policy version 3",
    requestedVersions.length === 2 && requestedVersions.every((value) => value === 3) &&
      writtenVersions.length === 2 && writtenVersions.every((value) => value === 3),
    `reads=${JSON.stringify(requestedVersions)}; writes=${JSON.stringify(writtenVersions)}`,
  );
}

// The shared project IAM resource is an owned managed delta only when this
// run writes it.  Teardown restores that exact delta from a fresh v3 policy
// while retaining bindings added concurrently by an administrator.
{
  let policy: Record<string, unknown> = {
    version: 3,
    etag: "project-before",
    bindings: [{ role: "roles/viewer", members: ["user:auditor@example.com"] }],
  };
  let writes = 0;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith("/securityGateways/default")) {
        return {
          status: 200,
          payload: { delegatingServiceAccount: "gateway@example.iam.gserviceaccount.com" },
        };
      }
      if (method === "POST" && url.endsWith(":getIamPolicy")) {
        return { status: 200, payload: structuredClone(policy) };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        writes += 1;
        policy = structuredClone(
          (options.jsonBody?.policy ?? {}) as Record<string, unknown>,
        );
        policy.etag = `project-after-${writes}`;
        return { status: 200, payload: structuredClone(policy) };
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change(
    "cloudresourcemanager",
    "project_iam",
    `${SPEC.name}-upstream-access`,
  );
  const applied = await new GoogleResourceExecutor(transport).apply(target, SPEC, {
    runId: "run-project-iam-delta",
    stepIndex: 0,
    requestId: crypto.randomUUID(),
  });
  const bindings = policy.bindings as Array<Record<string, unknown>>;
  bindings.push({
    role: "roles/logging.viewer",
    members: ["group:concurrent@example.com"],
  });
  policy.etag = "project-concurrent";
  await new GoogleResourceExecutor(transport).destroy(
    target,
    SPEC,
    crypto.randomUUID(),
    applied.beforeImage,
  );
  const restored = policy.bindings as Array<Record<string, unknown>>;
  check(
    "project IAM managed delta teardown preserves concurrent bindings",
    writes === 2 &&
      restored.some((binding) => binding.role === "roles/logging.viewer") &&
      restored.some((binding) => binding.role === "roles/viewer") &&
      !restored.some((binding) => binding.role === "roles/beyondcorp.upstreamAccess"),
    JSON.stringify({ writes, policy }),
  );
}

// Path A's Secret Manager IAM mutation uses the GET form of getIamPolicy and
// must request the same version before preserving conditional bindings.
// Main Apply IAM writes have no requestId. A response-lost SET must remain
// ambiguous even when a later administrator writes the same target binding;
// it can never be claimed or automatically removed by equality alone.
{
  const role = "roles/beyondcorp.serviceDiscoveryUser";
  let policy: Record<string, unknown> = {
    version: 3,
    etag: "before",
    bindings: [{ role, members: ["group:existing@example.com"] }],
  };
  let writes = 0;
  let checkpoint: unknown;
  const phases: unknown[] = [];
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        return { status: 200, payload: structuredClone(policy) };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        writes += 1;
        policy = structuredClone(
          (options.jsonBody?.policy ?? {}) as Record<string, unknown>,
        );
        throw new Error("committed-iam-set-response-lost");
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change("beyondcorp", "gateway_iam", "default-service-discovery-users");
  let firstError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-iam-response-loss",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
        phases.push((value as { phase?: unknown }).phase);
      },
    });
  } catch (error) {
    firstError = error;
  }
  let retryError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-iam-response-loss",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      beforeImage: checkpoint,
      checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
    });
  } catch (error) {
    retryError = error;
  }
  let rollbackError: unknown;
  try {
    await new GoogleResourceExecutor(transport).rollback(target, SPEC, {
      runId: "run-iam-response-loss",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      beforeImage: checkpoint,
    });
  } catch (error) {
    rollbackError = error;
  }
  check(
    "IAM prepared/sending checkpoint retains a response-lost mutation for manual review",
    firstError instanceof Error &&
      phases.join(",") === "prepared,sending" && writes === 1 &&
      (retryError as { code?: unknown })?.code === "iam-mutation-outcome-ambiguous" &&
      (rollbackError as { code?: unknown })?.code === "iam-rollback-outcome-ambiguous" &&
      ((policy.bindings as Array<{ members?: string[] }>)[0]?.members ?? [])
        .includes("group:secure-access@example.com"),
    JSON.stringify({ phases, writes, retryError: String(retryError), rollbackError: String(rollbackError) }),
  );
}

{
  let checkpoint: unknown;
  let writes = 0;
  const transport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        return { status: 200, payload: { version: 3, etag: "before", bindings: [] } };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        writes += 1;
        return { status: 400, payload: { error: { status: "INVALID_ARGUMENT" } } };
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change("beyondcorp", "gateway_iam", "default-service-discovery-users");
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-iam-rejected",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
    });
  } catch {
    // Expected definitive rejection.
  }
  await new GoogleResourceExecutor(transport).rollback(target, SPEC, {
    runId: "run-iam-rejected",
    stepIndex: 0,
    requestId: crypto.randomUUID(),
    beforeImage: checkpoint,
  });
  check(
    "definitive IAM 4xx advances rejected and rollback is a no-op",
    (checkpoint as { phase?: unknown } | undefined)?.phase === "rejected" && writes === 1,
    JSON.stringify({ checkpoint, writes }),
  );
}

// A confirmed IAM 409 proves the SET did not commit. Retry from a fresh v3
// policy/etag and persist that exact new before/after delta so a concurrent
// administrator binding survives both Apply and later teardown.
{
  const target = change("beyondcorp", "gateway_iam", "default-service-discovery-users");
  let reads = 0;
  let writes = 0;
  const written: Record<string, unknown>[] = [];
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        reads += 1;
        return {
          status: 200,
          payload: reads === 1
            ? { version: 3, etag: "etag-1", bindings: [] }
            : {
                version: 3,
                etag: "etag-2",
                bindings: [{ role: "roles/editor", members: ["user:concurrent@example.com"] }],
              },
        };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        writes += 1;
        written.push(structuredClone(
          (options.jsonBody?.policy ?? {}) as Record<string, unknown>,
        ));
        return writes === 1
          ? { status: 409, payload: { error: { status: "ABORTED" } } }
          : { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  const applied = await new GoogleResourceExecutor(transport).apply(target, SPEC, {
    runId: "run-iam-409",
    stepIndex: 0,
    requestId: crypto.randomUUID(),
  });
  const before = applied.beforeImage as {
    phase?: unknown;
    policy?: { etag?: unknown; bindings?: Array<{ role?: string }> };
    afterPolicy?: { etag?: unknown; bindings?: Array<{ role?: string }> };
  };
  check(
    "IAM confirmed 409 retries from a fresh etag and preserves concurrent bindings",
    reads === 2 && writes === 2 && before.phase === "applied" &&
      before.policy?.etag === "etag-2" && before.afterPolicy?.etag === "etag-2" &&
      before.afterPolicy?.bindings?.some((binding) => binding.role === "roles/editor") === true &&
      (written[1]?.bindings as Array<{ role?: string }> | undefined)
        ?.some((binding) => binding.role === "roles/editor") === true,
    JSON.stringify({ reads, writes, before, written }),
  );
}

{
  let writes = 0;
  const transport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        return { status: 200, payload: { version: 3, bindings: [] } };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) writes += 1;
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(
      change("beyondcorp", "gateway_iam", "default-service-discovery-users"),
      SPEC,
      { runId: "run-iam-no-etag", stepIndex: 0, requestId: crypto.randomUUID() },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "IAM Apply refuses a missing etag before any SET",
    (error as { code?: unknown })?.code === "iam-policy-etag-missing" && writes === 0,
    JSON.stringify({ error: String(error), writes }),
  );
}

{
  const target = change("beyondcorp", "gateway_iam", "default-service-discovery-users");
  let reads = 0;
  let writes = 0;
  let checkpoint: unknown;
  const transport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        reads += 1;
        return { status: 200, payload: { version: 3, etag: "etag-1", bindings: [] } };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        writes += 1;
        return { status: 409, payload: { error: { status: "FAILED_PRECONDITION" } } };
      }
      return { status: 200, payload: {} };
    },
  };
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-iam-unconfirmed-409",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
    });
  } catch {
    // Expected: an arbitrary 409 is not proof that the IAM SET was rejected.
  }
  check(
    "IAM retries only exact 409/ABORTED and retains an unconfirmed 409 as sending",
    reads === 1 && writes === 1 &&
      (checkpoint as { phase?: unknown } | undefined)?.phase === "sending",
    JSON.stringify({ reads, writes, checkpoint }),
  );
}

{
  const requestedVersions: unknown[] = [];
  const writtenPolicies: Record<string, unknown>[] = [];
  let reads = 0;
  let restoreWrites = 0;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        reads += 1;
        requestedVersions.push(options.params?.["options.requestedPolicyVersion"]);
        return {
          status: 200,
          payload: {
            etag: reads === 1 ? "secret-iam-etag" : `secret-fresh-${reads}`,
            version: 3,
            auditConfigs: [{
              service: "allServices",
              auditLogConfigs: [{ logType: "DATA_READ" }],
            }],
            bindings: [{
              role: "roles/secretmanager.secretAccessor",
              members: ["group:conditional@example.com"],
              condition: {
                title: "Conditional",
                expression: "resource.name != ''",
                location: "secret-policy.cel:9",
              },
            }],
          },
        };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        const policy = options.jsonBody?.policy as Record<string, unknown>;
        writtenPolicies.push(policy);
        const bindings = policy.bindings as unknown[] | undefined;
        if (bindings?.length === 1) {
          restoreWrites += 1;
          if (restoreWrites === 1) {
            return { status: 409, payload: { error: { status: "ABORTED" } } };
          }
        }
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change("secretmanager", "secret_iam", `${SPEC.name}-tls-accessor`);
  const applied = await new GoogleResourceExecutor(transport).apply(
    target,
    SPEC,
    { runId: "run-secret-iam-v3", stepIndex: 0, requestId: crypto.randomUUID() },
  );
  await new GoogleResourceExecutor(transport).rollback(target, SPEC, {
    runId: "run-secret-iam-v3",
    stepIndex: 0,
    requestId: crypto.randomUUID(),
    beforeImage: applied.beforeImage,
  });
  const appliedPolicy = writtenPolicies[0];
  const restoredPolicy = writtenPolicies.at(-1);
  check(
    "Secret Manager IAM RMW and rollback preserve v3 with fresh etag retry",
    requestedVersions.length === 3 && requestedVersions.every((version) => version === 3) &&
      appliedPolicy?.version === 3 &&
      (appliedPolicy?.bindings as unknown[] | undefined)?.length === 2 &&
      (appliedPolicy?.bindings as Array<{ condition?: { location?: unknown } }> | undefined)
          ?.[0]?.condition?.location === "secret-policy.cel:9" &&
      Array.isArray(appliedPolicy?.auditConfigs) &&
      restoredPolicy?.etag === "secret-fresh-3" && restoreWrites === 2,
    `requested=${JSON.stringify(requestedVersions)}; ${JSON.stringify(writtenPolicies)}`,
  );
}

{
  const target = change("secretmanager", "secret_iam", `${SPEC.name}-tls-accessor`);
  const malformedPolicies: Record<string, unknown>[] = [
    {
      version: 3,
      etag: "secret-etag",
      bindings: [{ role: "roles/viewer", members: "user:a@example.com" }],
    },
    {
      version: 3,
      etag: "secret-etag",
      bindings: [{ role: "roles/viewer", members: [] }],
    },
    {
      version: 3,
      etag: "secret-etag",
      bindings: [{
        role: "roles/viewer",
        members: ["user:a@example.com", "user:a@example.com"],
      }],
    },
    {
      version: 3,
      etag: "secret-etag",
      bindings: [{
        role: "roles/viewer",
        members: ["user:a@example.com"],
        condition: { title: "bad", expression: "true", unexpected: "drift" },
      }],
    },
    {
      version: 3,
      etag: "secret-etag",
      bindings: [],
      auditConfigs: [{ service: "allServices", unexpected: true }],
    },
    { version: 3, bindings: [] },
  ];
  const results: Array<{ error: unknown; writes: number }> = [];
  for (const policy of malformedPolicies) {
    let writes = 0;
    const transport: Transport = {
      async requestJson(method, url) {
        if (method === "GET" && url.endsWith(":getIamPolicy")) {
          return { status: 200, payload: structuredClone(policy) };
        }
        if (method === "POST" && url.endsWith(":setIamPolicy")) writes += 1;
        return { status: 200, payload: {} };
      },
    };
    let error: unknown;
    try {
      await new GoogleResourceExecutor(transport).apply(target, SPEC, {
        runId: `run-secret-iam-malformed-${results.length}`,
        stepIndex: 0,
        requestId: crypto.randomUUID(),
      });
    } catch (caught) {
      error = caught;
    }
    results.push({ error, writes });
  }
  check(
    "Secret IAM rejects malformed unrelated policy state before SET",
    results.every(({ error, writes }) =>
      (error as { code?: unknown } | undefined)?.code === "secret-iam-policy-invalid" &&
      writes === 0
    ),
    JSON.stringify(results.map(({ error, writes }) => ({
      code: (error as { code?: unknown } | undefined)?.code,
      writes,
    }))),
  );
}

{
  const target = change("secretmanager", "secret_iam", `${SPEC.name}-tls-accessor`);
  let reads = 0;
  let writes = 0;
  const written: Record<string, unknown>[] = [];
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        reads += 1;
        return {
          status: 200,
          payload: reads === 1
            ? { version: 3, etag: "secret-etag-1", bindings: [] }
            : {
                version: 3,
                etag: "secret-etag-2",
                bindings: [{ role: "roles/viewer", members: ["user:concurrent@example.com"] }],
              },
        };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        writes += 1;
        written.push(structuredClone(
          (options.jsonBody?.policy ?? {}) as Record<string, unknown>,
        ));
        return writes === 1
          ? { status: 409, payload: { error: { status: "ABORTED" } } }
          : { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  const applied = await new GoogleResourceExecutor(transport).apply(target, SPEC, {
    runId: "run-secret-iam-409",
    stepIndex: 0,
    requestId: crypto.randomUUID(),
  });
  const checkpoint = applied.beforeImage as {
    phase?: unknown;
    policy?: { etag?: unknown };
    afterPolicy?: { bindings?: Array<{ role?: string }> };
  };
  check(
    "Secret IAM confirmed 409 rebases on a fresh etag without losing admin bindings",
    reads === 2 && writes === 2 && checkpoint.phase === "applied" &&
      checkpoint.policy?.etag === "secret-etag-2" &&
      checkpoint.afterPolicy?.bindings?.some((binding) => binding.role === "roles/viewer") === true &&
      (written[1]?.bindings as Array<{ role?: string }> | undefined)
        ?.some((binding) => binding.role === "roles/viewer") === true,
    JSON.stringify({ reads, writes, checkpoint, written }),
  );
}

{
  const target = change("secretmanager", "secret_iam", `${SPEC.name}-tls-accessor`);
  let reads = 0;
  let writes = 0;
  let checkpoint: unknown;
  const transport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        reads += 1;
        return { status: 200, payload: { version: 3, etag: "secret-etag", bindings: [] } };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        writes += 1;
        throw new GoogleApiError({
          status: 409,
          method,
          url,
          payload: { error: { status: "FAILED_PRECONDITION" } },
        });
      }
      return { status: 200, payload: {} };
    },
  };
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-secret-iam-unconfirmed-409",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
    });
  } catch {
    // Expected ambiguous mutation outcome.
  }
  check(
    "Secret IAM does not retry a 409 unless its canonical status is ABORTED",
    reads === 1 && writes === 1 &&
      (checkpoint as { phase?: unknown } | undefined)?.phase === "sending",
    JSON.stringify({ reads, writes, checkpoint }),
  );
}

// Cloud NAT is a named field nested on a Router. A retry sees the field already
// present; it must verify it and stop, not append a duplicate, and the Router
// PATCH must carry the step's durable requestId.
{
  let router: Record<string, unknown> = { nats: [], fingerprint: "router-fp-0" };
  let patches = 0;
  let patchRequestId: unknown;
  const transport: Transport = {
    async requestJson(method, _url, options = {}) {
      if (method === "GET") return { status: 200, payload: structuredClone(router) };
      if (method === "PATCH") {
        patches += 1;
        patchRequestId = options.params?.requestId;
        router = {
          nats: structuredClone(options.jsonBody?.nats ?? []),
          fingerprint: `router-fp-${patches}`,
        };
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change("compute", "cloud_nat", `${SPEC.name}-nat`);
  const requestId = "6a069ad7-e18a-403b-bde2-b543e357210d";
  const first = await new GoogleResourceExecutor(transport).apply(target, SPEC, {
    runId: "run-nat-retry",
    stepIndex: 0,
    requestId,
  });
  await new GoogleResourceExecutor(transport).apply(target, SPEC, {
    runId: "run-nat-retry",
    stepIndex: 0,
    requestId,
    beforeImage: first.beforeImage,
  });
  const nats = router.nats as Array<{ name?: unknown }>;
  check(
    "Cloud NAT retry semantically reconciles without a duplicate",
    patches === 1 && nats.length === 1 && nats[0]?.name === `${SPEC.name}-nat`,
    `patches=${patches}; ${JSON.stringify(router)}`,
  );
  check(
    "Router PATCH carries the persisted requestId",
    patchRequestId === requestId,
    String(patchRequestId),
  );
  (router.nats as unknown[]).push({
    name: "admin-added-nat",
    natIpAllocateOption: "AUTO_ONLY",
    sourceSubnetworkIpRangesToNat: "ALL_SUBNETWORKS_ALL_IP_RANGES",
  });
  await new GoogleResourceExecutor(transport).destroy(
    target,
    SPEC,
    "81af90d7-9fef-4995-a4a5-25abb0197c63",
    first.beforeImage,
  );
  check(
    "Cloud NAT teardown removes only SGS managed-after and preserves external NAT changes",
    Array.isArray(router.nats) && router.nats.length === 1 &&
      (router.nats[0] as { name?: unknown }).name === "admin-added-nat",
    JSON.stringify(router),
  );
}

{
  let patches = 0;
  const transport: Transport = {
    async requestJson(method) {
      if (method === "GET") {
        return { status: 200, payload: { fingerprint: "router-fp", nats: { malformed: true } } };
      }
      if (method === "PATCH") patches += 1;
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(
      change("compute", "cloud_nat", `${SPEC.name}-nat`),
      SPEC,
      { runId: "run-nat-malformed", stepIndex: 0, requestId: crypto.randomUUID() },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "Cloud NAT rejects a present non-array router.nats before PATCH",
    error instanceof Error && patches === 0,
    `${String(error)}; patches=${patches}`,
  );
}

{
  let patches = 0;
  const targetName = `${SPEC.name}-nat`;
  const transport: Transport = {
    async requestJson(method) {
      if (method === "GET") {
        return {
          status: 200,
          payload: {
            fingerprint: "router-fp",
            nats: [
              { name: targetName, natIpAllocateOption: "MANUAL_ONLY" },
              { name: targetName, natIpAllocateOption: "AUTO_ONLY" },
            ],
          },
        };
      }
      if (method === "PATCH") patches += 1;
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(
      change("compute", "cloud_nat", targetName),
      SPEC,
      { runId: "run-nat-duplicate", stepIndex: 0, requestId: crypto.randomUUID() },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "Cloud NAT rejects duplicate reserved-name configurations before PATCH",
    error instanceof Error && patches === 0,
    `${String(error)}; patches=${patches}`,
  );
}

// Explicit teardown restores shared Secret metadata before destroying the
// exact version recorded by Apply. A metadata failure must leave the version
// non-terminal so `active` can never point at a destroyed version.
{
  const calls: string[] = [];
  const secretUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/demo-tls";
  const versionName = `${secretUrl}/versions/7`;
  let versionState = "DISABLED";
  let failFirstMetadataRestore = true;
  let liveAliases: Record<string, string> = { active: "7" };
  let liveLabels: Record<string, string> = { "managed-by": "after" };
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      calls.push(`${method} ${url}`);
      if (method === "GET" && url === secretUrl) {
        return {
          status: 200,
          payload: {
            etag: "current",
            versionAliases: structuredClone(liveAliases),
            labels: structuredClone(liveLabels),
          },
        };
      }
      if (method === "GET" && url === versionName) {
        return { status: 200, payload: { state: versionState } };
      }
      if (method === "POST" && url === `${versionName}:destroy`) {
        versionState = "DESTROYED";
        return { status: 200, payload: {} };
      }
      if (method === "PATCH" && url === secretUrl && failFirstMetadataRestore) {
        failFirstMetadataRestore = false;
        return { status: 500, payload: { error: { status: "INTERNAL" } } };
      }
      if (method === "PATCH" && url === secretUrl) {
        liveAliases = structuredClone(
          (options.jsonBody?.versionAliases ?? {}) as Record<string, string>,
        );
        liveLabels = structuredClone(
          (options.jsonBody?.labels ?? {}) as Record<string, string>,
        );
      }
      return { status: 200, payload: {} };
    },
  };
  const beforeImage = {
    kind: "secret_version",
    secretUrl,
    versionName,
    previousAliases: { active: "6" },
    previousLabels: { "managed-by": "before" },
    managedAfterAliases: { active: "7" },
    managedAfterLabels: { "managed-by": "after" },
  };
  let firstError: unknown;
  try {
    await new GoogleResourceExecutor(transport).destroy(
      change("secretmanager", "secret_version", "demo-tls"),
      SPEC,
      crypto.randomUUID(),
      beforeImage,
    );
  } catch (error) {
    firstError = error;
  }
  const callsAfterFirstAttempt = [...calls];
  await new GoogleResourceExecutor(transport).destroy(
    change("secretmanager", "secret_version", "demo-tls"),
    SPEC,
    crypto.randomUUID(),
    beforeImage,
  );
  const firstDestroy = calls.indexOf(`POST ${versionName}:destroy`);
  const firstPatch = calls.indexOf(`PATCH ${secretUrl}`);
  check(
    "secret metadata restore failure never destroys the active version",
    firstError instanceof Error &&
      !callsAfterFirstAttempt.includes(`POST ${versionName}:destroy`) &&
      !callsAfterFirstAttempt.includes(`POST ${versionName}:disable`),
    callsAfterFirstAttempt.join(","),
  );
  check(
    "standard teardown restores metadata before destroying the exact version",
    firstPatch >= 0 && firstDestroy > firstPatch &&
      liveAliases.active === "6" && liveLabels["managed-by"] === "before" &&
      !calls.includes(`POST ${versionName}:disable`),
    calls.join(","),
  );
  check(
    "secret-version teardown retries metadata restoration then destroys once",
    calls.filter((call) => call === `POST ${versionName}:destroy`).length === 1 &&
      calls.filter((call) => call === `PATCH ${secretUrl}`).length === 2,
    calls.join(","),
  );
}

// Teardown uses the same real Secret Manager etag contract. A concurrent edit
// on an unrelated key is retained across the fresh-read retry, and the version
// is destroyed only after the metadata write succeeds.
{
  const secretUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/teardown-etag-tls";
  const versionName = `${secretUrl}/versions/7`;
  const calls: string[] = [];
  let patchCalls = 0;
  let secretGets = 0;
  let finalPatch: Record<string, unknown> | undefined;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      calls.push(`${method} ${url}`);
      if (method === "GET" && url === versionName) {
        return { status: 200, payload: { state: "ENABLED" } };
      }
      if (method === "GET" && url === secretUrl) {
        secretGets += 1;
        return secretGets === 1
          ? {
            status: 200,
            payload: {
              etag: "stale",
              versionAliases: { active: "7" },
              labels: { "managed-by": "after" },
            },
          }
          : {
            status: 200,
            payload: {
              etag: "fresh",
              versionAliases: { active: "7", admin: "9" },
              labels: { "managed-by": "after", admin: "kept" },
            },
          };
      }
      if (method === "PATCH" && url === secretUrl) {
        patchCalls += 1;
        if (patchCalls === 1) {
          throw new GoogleApiError({
            status: 400,
            method,
            url,
            payload: { error: { status: "FAILED_PRECONDITION" } },
          });
        }
        finalPatch = structuredClone(options.jsonBody ?? {});
        return { status: 200, payload: {} };
      }
      if (method === "POST" && url === `${versionName}:destroy`) {
        return { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(transport).destroy(
      change("secretmanager", "secret_version", "teardown-etag-tls"),
      SPEC,
      crypto.randomUUID(),
      {
        kind: "secret_version",
        phase: "applied",
        secretUrl,
        versionName,
        previousAliases: { active: "6" },
        previousLabels: { "managed-by": "before" },
        managedAfterAliases: { active: "7" },
        managedAfterLabels: { "managed-by": "after" },
      },
    );
  } catch (caught) {
    error = caught;
  }
  const aliases = finalPatch?.versionAliases as Record<string, string> | undefined;
  const labels = finalPatch?.labels as Record<string, string> | undefined;
  check(
    "secret teardown retries FAILED_PRECONDITION before destroy and preserves unrelated metadata",
    error === undefined && patchCalls === 2 && secretGets === 2 &&
      finalPatch?.etag === "fresh" && aliases?.active === "6" && aliases.admin === "9" &&
      labels?.["managed-by"] === "before" && labels.admin === "kept" &&
      calls.indexOf(`PATCH ${secretUrl}`) < calls.indexOf(`POST ${versionName}:destroy`),
    JSON.stringify({ error: String(error), calls, finalPatch }),
  );
}

// Recovery from an old destroy-first worker accepts only the exact recorded
// version already being DESTROYED. Secret Manager may have removed `active`;
// restore the previous alias without issuing another destructive call.
{
  const secretUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/destroyed-alias-tls";
  const versionName = `${secretUrl}/versions/7`;
  let destructiveCalls = 0;
  let restored: Record<string, unknown> | undefined;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url === versionName) {
        return { status: 200, payload: { state: "DESTROYED" } };
      }
      if (method === "GET" && url === secretUrl) {
        return {
          status: 200,
          payload: { etag: "after-destroy", versionAliases: {}, labels: { managed: "after" } },
        };
      }
      if (method === "PATCH" && url === secretUrl) {
        restored = structuredClone(options.jsonBody ?? {});
        return { status: 200, payload: {} };
      }
      if (method === "POST") destructiveCalls += 1;
      return { status: 200, payload: {} };
    },
  };
  await new GoogleResourceExecutor(transport).destroy(
    change("secretmanager", "secret_version", "destroyed-alias-tls"),
    SPEC,
    crypto.randomUUID(),
    {
      kind: "secret_version",
      phase: "applied",
      secretUrl,
      versionName,
      previousAliases: { active: "6" },
      previousLabels: { managed: "before" },
      managedAfterAliases: { active: "7" },
      managedAfterLabels: { managed: "after" },
    },
  );
  check(
    "secret teardown recovers a removed active alias from an exact destroyed version",
    destructiveCalls === 0 &&
      (restored?.versionAliases as Record<string, string> | undefined)?.active === "6" &&
      (restored?.labels as Record<string, string> | undefined)?.managed === "before",
    JSON.stringify({ destructiveCalls, restored }),
  );
}

// If an administrator changed one of the exact keys SGS managed, teardown
// cannot distinguish ownership and must retain both metadata and the version.
{
  const secretUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/shared-tls";
  const versionName = `${secretUrl}/versions/7`;
  const calls: string[] = [];
  let patchCalls = 0;
  let destroyCalls = 0;
  const transport: Transport = {
    async requestJson(method, url) {
      calls.push(`${method} ${url}`);
      if (method === "GET" && url === versionName) {
        return { status: 200, payload: { state: "ENABLED" } };
      }
      if (method === "POST" && url === `${versionName}:destroy`) {
        destroyCalls += 1;
        return { status: 200, payload: {} };
      }
      if (method === "GET" && url === secretUrl) {
        return {
          status: 200,
          payload: {
            etag: "fresh-external-etag",
            versionAliases: {
              active: "8",
              archive: "9",
              admin: "10",
            },
            labels: {
              "managed-by": "admin-changed",
              shared: "admin-changed",
              admin: "kept",
              "sgs-active-version": "7",
              "sgs-previous-active": "6",
            },
          },
        };
      }
      if (method === "PATCH" && url === secretUrl) {
        patchCalls += 1;
        return { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(transport).destroy(
      change("secretmanager", "secret_version", "shared-tls"),
      SPEC,
      crypto.randomUUID(),
      {
        kind: "secret_version",
        secretUrl,
        versionName,
        previousAliases: { active: "6", archive: "2" },
        previousLabels: { "managed-by": "before", shared: "before" },
        managedAfterAliases: { active: "7", archive: "2" },
        managedAfterLabels: {
          "managed-by": "secure-gateway-studio",
          shared: "before",
          "sgs-active-version": "7",
          "sgs-previous-active": "6",
        },
      },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "secret-version teardown fails closed on managed alias or label drift",
    error instanceof Error && patchCalls === 0 && destroyCalls === 0,
    `${String(error)} | ${calls.join(",")}`,
  );
}

// Enterprise CA issuance is an owned plan operation, not an engine prelude.
// Its exact server resource is checkpointed so both rollback and later
// teardown can revoke it without listing or guessing from a display name.
{
  const enterpriseSpec = {
    ...SPEC,
    backend_kind: "existing_http" as const,
    certificate_strategy: "enterprise_ca" as const,
    source_image:
      "projects/enterprise-secgw-01/global/images/sgs-nginx-20260824",
    ca_pool: "projects/enterprise-secgw-01/locations/us-central1/caPools/sgs",
    ca_name:
      "projects/enterprise-secgw-01/locations/us-central1/caPools/sgs/certificateAuthorities/root",
  };
  const enterpriseImageBinding = {
    name: enterpriseSpec.source_image,
    id: "987654321",
    self_link: `https://www.googleapis.com/compute/v1/${enterpriseSpec.source_image}`,
  };
  const plan = buildPlan(enterpriseSpec);
  const certificateIndex = plan.changes.findIndex(
    (item) => item.provider === "privateca" && item.resource_type === "certificate",
  );
  const versionIndex = plan.changes.findIndex(
    (item) => item.provider === "secretmanager" && item.resource_type === "secret_version",
  );
  check(
    "enterprise CA certificate is an owned step before secret material",
    certificateIndex >= 0 && certificateIndex < versionIndex &&
      plan.changes[certificateIndex]?.owned_after_apply === true &&
      plan.changes[versionIndex]?.dependencies.includes(
        `privateca:certificate:${enterpriseSpec.name}-certificate`,
      ) === true,
    JSON.stringify(plan.changes.slice(Math.max(0, certificateIndex), versionIndex + 1)),
  );

  const certificateName =
    `${enterpriseSpec.ca_pool}/certificates/` +
    enterpriseCertificateId(enterpriseSpec.name, "run0001-abcd");
  const calls: Array<{
    method: string;
    url: string;
    body?: Record<string, unknown>;
  }> = [];
  let revoked = false;
  const ownedCsr =
    "-----BEGIN CERTIFICATE REQUEST-----\nowned\n-----END CERTIFICATE REQUEST-----";
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      calls.push({ method, url, body: options.jsonBody });
      if (method === "GET" && url.endsWith("/global/images/sgs-nginx-20260824")) {
        return {
          status: 200,
          payload: {
            name: "sgs-nginx-20260824",
            id: "987654321",
            selfLink:
              "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
              "global/images/sgs-nginx-20260824",
          },
        };
      }
      if (method === "GET" && url.endsWith(certificateName)) {
        return {
          status: 200,
          payload: {
            name: certificateName,
            issuerCertificateAuthority: enterpriseSpec.ca_name,
            pemCsr: ownedCsr,
            ...(revoked ? { revocationDetails: {} } : {}),
          },
        };
      }
      if (method === "POST" && url.endsWith(`${certificateName}:revoke`)) {
        revoked = true;
      }
      return { status: 200, payload: {} };
    },
  };
  let issueCount = 0;
  const requestId = crypto.randomUUID();
  const applied = await new GoogleResourceExecutor(transport, {
    sourceImageBinding: {
      name: enterpriseSpec.source_image,
      id: "987654321",
      self_link:
        `https://www.googleapis.com/compute/v1/${enterpriseSpec.source_image}`,
    },
    issueEnterpriseCertificate: async (_runId, _spec, _requestId, checkpointCsr) => {
      issueCount += 1;
      await checkpointCsr(ownedCsr, "prepared");
      await checkpointCsr(ownedCsr, "sending");
      return {
        certificatePem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
        certificateChainPem: ["-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"],
        privateKeyPem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        hostname: enterpriseSpec.private_hostname,
        issuerResourceName: certificateName,
      };
    },
  }).apply(
    change("privateca", "certificate", `${enterpriseSpec.name}-certificate`),
    enterpriseSpec,
    { runId: "run0001-abcd", stepIndex: 0, requestId },
  );
  const beforeImage = applied.beforeImage as { certificateName?: unknown } | undefined;
  await new GoogleResourceExecutor(transport).destroy(
    change("privateca", "certificate", `${enterpriseSpec.name}-certificate`),
    enterpriseSpec,
    requestId,
    applied.beforeImage,
  );
  await new GoogleResourceExecutor(transport).destroy(
    change("privateca", "certificate", `${enterpriseSpec.name}-certificate`),
    enterpriseSpec,
    requestId,
    applied.beforeImage,
  );
  const revokeCalls = calls.filter((call) => call.url.endsWith(`${certificateName}:revoke`));
  check(
    "enterprise certificate checkpoints the exact issued resource",
    issueCount === 1 && beforeImage?.certificateName === certificateName,
    JSON.stringify({ issueCount, beforeImage }),
  );
  check(
    "enterprise certificate teardown revokes exactly once with stable requestId",
    revokeCalls.length === 1 && revokeCalls[0]?.body?.requestId === requestId,
    JSON.stringify(revokeCalls),
  );

  const issueCalls: Array<{
    params?: Record<string, string | number>;
    body?: Record<string, unknown>;
  }> = [];
  const validIssued = await issueLocalPoc(
    enterpriseSpec.private_hostname,
    enterpriseSpec.certificate_lifetime_days,
  );
  const issueTransport: Transport = {
    async requestJson(_method, _url, options = {}) {
      issueCalls.push({ params: options.params, body: options.jsonBody });
      return {
        status: 200,
        payload: {
          name: certificateName,
          issuerCertificateAuthority: enterpriseSpec.ca_name,
          pemCsr: checkpointedRequest.csrPem,
          pemCertificate: validIssued.certificatePem,
          pemCertificateChain: validIssued.certificateChainPem,
        },
      };
    },
  };
  const checkpointedRequest = {
    csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nstable\n-----END CERTIFICATE REQUEST-----",
    privateKeyPem: validIssued.privateKeyPem,
  };
  const certificateId = certificateName.split("/").at(-1) as string;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await issueEnterpriseCa(issueTransport, {
      hostname: enterpriseSpec.private_hostname,
      caPool: enterpriseSpec.ca_pool,
      caName: enterpriseSpec.ca_name,
      certificateId,
      lifetimeDays: enterpriseSpec.certificate_lifetime_days,
      requestId,
      request: checkpointedRequest,
    });
  }
  check(
    "enterprise CA retry reuses the checkpointed CSR and requestId",
    issueCalls.length === 2 &&
      issueCalls[0]?.params?.requestId === requestId &&
      JSON.stringify(issueCalls[0]) === JSON.stringify(issueCalls[1]) &&
      issueCalls[0]?.body?.pemCsr === checkpointedRequest.csrPem &&
      issueCalls[0]?.body?.issuingCertificateAuthority === undefined &&
      issueCalls[0]?.params?.issuingCertificateAuthorityId === "root",
    JSON.stringify(issueCalls),
  );

  let operationPolls = 0;
  const operationName =
    `${enterpriseSpec.ca_pool.split("/caPools/")[0]}/operations/issue-owned`;
  const lroTransport: Transport = {
    async requestJson(method, url) {
      if (method === "POST" && url.endsWith("/certificates")) {
        return { status: 200, payload: { name: operationName, done: false } };
      }
      if (method === "GET" && url.endsWith(operationName)) {
        operationPolls += 1;
        return {
          status: 200,
          payload: {
            name: operationName,
            done: true,
            response: {
              name: certificateName,
              issuerCertificateAuthority: enterpriseSpec.ca_name,
              pemCsr: checkpointedRequest.csrPem,
              pemCertificate: validIssued.certificatePem,
              pemCertificateChain: validIssued.certificateChainPem,
            },
          },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  const lroBundle = await issueEnterpriseCa(lroTransport, {
    hostname: enterpriseSpec.private_hostname,
    caPool: enterpriseSpec.ca_pool,
    caName: enterpriseSpec.ca_name,
    certificateId,
    lifetimeDays: enterpriseSpec.certificate_lifetime_days,
    requestId,
    request: checkpointedRequest,
    operationPollIntervalMs: 0,
    maxOperationPolls: 1,
  });
  check(
    "enterprise CA create waits for and unwraps the documented long-running operation",
    operationPolls === 1 && lroBundle.issuerResourceName === certificateName,
    JSON.stringify({ operationPolls, issuer: lroBundle.issuerResourceName }),
  );

  // A deterministic certificate-id collision is not ownership. The CSR is
  // checkpointed before POST, and rollback compares it before any revoke.
  const collisionCsr =
    "-----BEGIN CERTIFICATE REQUEST-----\nsomebody-else\n-----END CERTIFICATE REQUEST-----";
  const collisionCalls: Array<{ method: string; url: string }> = [];
  const collisionTransport: Transport = {
    async requestJson(method, url) {
      collisionCalls.push({ method, url });
      if (method === "GET" && url.endsWith("/global/images/sgs-nginx-20260824")) {
        return {
          status: 200,
          payload: {
            name: "sgs-nginx-20260824",
            id: enterpriseImageBinding.id,
            selfLink: enterpriseImageBinding.self_link,
          },
        };
      }
      if (method === "POST" && url.endsWith("/certificates")) {
        return { status: 409, payload: { error: { status: "ALREADY_EXISTS" } } };
      }
      if (method === "GET" && url.endsWith(certificateName)) {
        return {
          status: 200,
          payload: {
            name: certificateName,
            issuerCertificateAuthority: enterpriseSpec.ca_name,
            pemCsr: collisionCsr,
            pemCertificate: "other-leaf",
            pemCertificateChain: ["other-ca"],
          },
        };
      }
      throw new Error(`unexpected ${method} ${url}`);
    },
  };
  let collisionBefore: unknown;
  let collisionError: unknown;
  const collisionRequest = {
    csrPem: ownedCsr,
    privateKeyPem: "-----BEGIN PRIVATE KEY-----\nowned\n-----END PRIVATE KEY-----",
  };
  const collisionExecutor = new GoogleResourceExecutor(collisionTransport, {
    sourceImageBinding: enterpriseImageBinding,
    issueEnterpriseCertificate: async (_runId, targetSpec, stableId, checkpointCsr) => {
      await checkpointCsr(collisionRequest.csrPem, "prepared");
      await checkpointCsr(collisionRequest.csrPem, "sending");
      return issueEnterpriseCa(collisionTransport, {
        hostname: targetSpec.private_hostname,
        caPool: targetSpec.ca_pool as string,
        caName: targetSpec.ca_name as string,
        certificateId,
        lifetimeDays: targetSpec.certificate_lifetime_days,
        requestId: stableId,
        request: collisionRequest,
      });
    },
  });
  const certificateChange = change(
    "privateca",
    "certificate",
    `${enterpriseSpec.name}-certificate`,
  );
  try {
    await collisionExecutor.apply(certificateChange, enterpriseSpec, {
      runId: "run0001-abcd",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => {
        collisionBefore = structuredClone(value);
      },
    });
  } catch (error) {
    collisionError = error;
  }
  await collisionExecutor.rollback(certificateChange, enterpriseSpec, {
    runId: "run0001-abcd",
    stepIndex: 0,
    requestId,
    beforeImage: collisionBefore,
  });
  check(
    "enterprise CA name collision fails Apply after a durable CSR checkpoint",
    collisionError instanceof Error &&
      typeof (collisionBefore as { csrDigest?: unknown } | undefined)?.csrDigest === "string",
    JSON.stringify({ collisionError: String(collisionError), collisionBefore }),
  );
  check(
    "enterprise CA name collision never revokes the other certificate",
    !collisionCalls.some((call) => call.url.endsWith(":revoke")),
    JSON.stringify(collisionCalls),
  );

  // A create accepted at the provider can remain temporarily invisible. A
  // full browser restart loses the session key, but the durable sending CSR
  // checkpoint must retain ownership until the exact certificate is visible
  // and revoked; the first 404 is never proof of absence.
  let eventualVisible = false;
  let eventualRevoked = false;
  let eventualBefore: unknown;
  const eventualTransport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.endsWith("/global/images/sgs-nginx-20260824")) {
        return {
          status: 200,
          payload: {
            name: "sgs-nginx-20260824",
            id: enterpriseImageBinding.id,
            selfLink: enterpriseImageBinding.self_link,
          },
        };
      }
      if (method === "GET" && url.endsWith(certificateName)) {
        if (!eventualVisible) {
          eventualVisible = true;
          return { status: 404, payload: {} };
        }
        return {
          status: 200,
          payload: {
            name: certificateName,
            issuerCertificateAuthority: enterpriseSpec.ca_name,
            pemCsr: ownedCsr,
            ...(eventualRevoked ? { revocationDetails: {} } : {}),
          },
        };
      }
      if (method === "POST" && url.endsWith(`${certificateName}:revoke`)) {
        eventualRevoked = true;
        return { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  let responseLoss: unknown;
  try {
    await new GoogleResourceExecutor(eventualTransport, {
      sourceImageBinding: enterpriseImageBinding,
      issueEnterpriseCertificate: async (
        _runId,
        _spec,
        _stableId,
        checkpointCsr,
      ) => {
        await checkpointCsr(ownedCsr, "prepared");
        await checkpointCsr(ownedCsr, "sending");
        throw new Error("privateca-response-lost-after-commit");
      },
    }).apply(certificateChange, enterpriseSpec, {
      runId: "run0001-abcd",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => {
        eventualBefore = structuredClone(value);
      },
    });
  } catch (error) {
    responseLoss = error;
  }
  let firstRollback: unknown;
  try {
    // A new executor models a full browser/session restart.
    await new GoogleResourceExecutor(eventualTransport).rollback(
      certificateChange,
      enterpriseSpec,
      {
        runId: "run0001-abcd",
        stepIndex: 0,
        requestId,
        beforeImage: eventualBefore,
      },
    );
  } catch (error) {
    firstRollback = error;
  }
  const notReleasedAfter404 = !eventualRevoked &&
    (firstRollback as { code?: unknown })?.code ===
      "privateca-certificate-outcome-ambiguous";
  await new GoogleResourceExecutor(eventualTransport).rollback(
    certificateChange,
    enterpriseSpec,
    {
      runId: "run0001-abcd",
      stepIndex: 0,
      requestId,
      beforeImage: eventualBefore,
    },
  );
  check(
    "Private CA response loss retains the sending claim across an eventual 404",
    responseLoss instanceof Error &&
      (eventualBefore as { protocolVersion?: unknown; phase?: unknown; csrPem?: unknown })
          ?.protocolVersion === 1 &&
      (eventualBefore as { phase?: unknown })?.phase === "sending" &&
      typeof (eventualBefore as { csrPem?: unknown })?.csrPem === "string" &&
      notReleasedAfter404 && eventualRevoked,
    JSON.stringify({
      responseLoss: String(responseLoss),
      eventualBefore,
      firstRollback: String(firstRollback),
      notReleasedAfter404,
      eventualRevoked,
    }),
  );

  let rejectedBefore: unknown;
  const rejectedTransport: Transport = {
    async requestJson(method, url) {
      const image = productionManagedInstanceResponse(method, url);
      if (image !== null) return image;
      if (method === "GET" && url.endsWith(certificateName)) {
        return { status: 404, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  let rejectedError: unknown;
  try {
    await new GoogleResourceExecutor(rejectedTransport, {
      sourceImageBinding: enterpriseImageBinding,
      issueEnterpriseCertificate: async (
        _runId,
        _spec,
        _stableId,
        checkpointCsr,
      ) => {
        await checkpointCsr(ownedCsr, "prepared");
        await checkpointCsr(ownedCsr, "sending");
        await checkpointCsr(ownedCsr, "rejected");
        throw new GoogleApiError({
          status: 403,
          method: "POST",
          url: `https://privateca.googleapis.com/v1/${enterpriseSpec.ca_pool}/certificates`,
          payload: { error: { status: "PERMISSION_DENIED" } },
        });
      },
    }).apply(certificateChange, enterpriseSpec, {
      runId: "run0001-abcd",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => {
        rejectedBefore = structuredClone(value);
      },
    });
  } catch (error) {
    rejectedError = error;
  }
  await new GoogleResourceExecutor(rejectedTransport).rollback(
    certificateChange,
    enterpriseSpec,
    {
      runId: "run0001-abcd",
      stepIndex: 0,
      requestId,
      beforeImage: rejectedBefore,
    },
  );
  check(
    "Private CA definitive rejection makes a later 404 safely absent",
    rejectedError instanceof Error &&
      (rejectedBefore as { phase?: unknown } | undefined)?.phase === "rejected",
    JSON.stringify({ rejectedError: String(rejectedError), rejectedBefore }),
  );
}

// A Google HTTP failure must be observable to the run engine. Returning from
// apply would let it persist a false `done` step and a false successful run.
{
  const forbidden: Transport = {
    async requestJson() {
      return {
        status: 403,
        payload: { error: { status: "PERMISSION_DENIED", message: "denied" } },
      };
    },
  };
  const executor = new GoogleResourceExecutor(forbidden);
  let error: unknown;
  try {
    await executor.apply(
      change("serviceusage", "project_services", "enterprise-secgw-01"),
      SPEC,
    );
  } catch (caught) {
    error = caught;
  }
  check("403 is rejected instead of recorded as success", error instanceof Error);
  check(
    "HTTP failure retains a structured provider code",
    (error as { code?: unknown } | undefined)?.code ===
      "google-api-403-serviceusage-permission-denied",
    String((error as { code?: unknown } | undefined)?.code),
  );
}

// Teardown is idempotent: deleting an owned resource that is already absent is
// successful, but only because that individual DELETE opts into 404.
{
  const calls: Array<{ method: string; url: string }> = [];
  const createRequestId = "b141ab49-9f42-4eb8-a82c-d786fe32709f";
  const transport: Transport = {
    async requestJson(method, url) {
      calls.push({ method, url });
      return {
        status: 404,
        payload: { error: { status: "NOT_FOUND", message: "not found" } },
      };
    },
  };
  const executor = new GoogleResourceExecutor(transport);
  let error: unknown;
  try {
    await executor.destroy(
      change("compute", "network", "private-app-vpc"),
      SPEC,
      crypto.randomUUID(),
      {
        kind: "generic_created_resource",
        protocolVersion: 2,
        phase: "applied",
        resourceKey: "compute:network:private-app-vpc",
        createUrl:
          "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/global/networks",
        resourceUrl:
          "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/global/networks/private-app-vpc",
        createRequestId,
        expectedParamsDigest: canonicalDigestSync({ requestId: createRequestId }),
        expectedPayloadDigest: "a".repeat(64),
        ownershipMarker: "Secure Gateway Studio ownership-token=" + createRequestId,
        providerIdentityField: "id",
        providerIdentity: "101",
      },
    );
  } catch (caught) {
    error = caught;
  }
  check("owned-resource destroy explicitly accepts NOT_FOUND", error === undefined, String(error));
  check(
    "destroy targets the exact recorded resource name",
    calls[0]?.method === "GET" && calls[0]?.url.endsWith("/global/networks/private-app-vpc") &&
      calls.every((call) => call.method !== "DELETE"),
    JSON.stringify(calls),
  );
}

// A shared IAM policy must be restorable after the worker that applied it is
// gone. The before-image therefore travels through the public execution result,
// not an executor instance's in-memory map.
//
// A parent 404 is not a durable ownership checkpoint. Legacy child IAM rows
// without the exact before/after policy must fail before any provider read or
// write; whole-run preflight is responsible for terminalizing their recovery.
{
  const cases = [
    {
      label: "gateway",
      target: change("beyondcorp", "gateway_iam", "default-service-discovery-users"),
    },
    {
      label: "application",
      target: change("beyondcorp", "application_iam", `${SPEC.name}-app-iam`),
    },
  ] as const;
  for (const testCase of cases) {
    const calls: Array<{
      method: string;
      url: string;
      acceptedStatuses: readonly number[] | undefined;
    }> = [];
    const missingParent: Transport = {
      async requestJson(method, url, options = {}) {
        calls.push({ method, url, acceptedStatuses: options.acceptedStatuses });
        return { status: 404, payload: {} };
      },
    };
    let missingError: unknown;
    try {
      await new GoogleResourceExecutor(missingParent).rollback(
        testCase.target,
        SPEC,
        {
          runId: `run-legacy-${testCase.label}-iam`,
          stepIndex: 0,
          requestId: crypto.randomUUID(),
        },
      );
    } catch (error) {
      missingError = error;
    }
    check(
      `legacy ${testCase.label} IAM rollback fails before reading a missing parent`,
      missingError instanceof Error &&
        missingError.message === "iam-ownership-checkpoint-missing" && calls.length === 0,
      JSON.stringify({ error: String(missingError), calls }),
    );

    let liveError: unknown;
    let mutations = 0;
    const liveParent: Transport = {
      async requestJson(method, url) {
        if (method !== "GET") mutations += 1;
        return { status: 200, payload: { name: url } };
      },
    };
    try {
      await new GoogleResourceExecutor(liveParent).rollback(
        testCase.target,
        SPEC,
        {
          runId: `run-live-${testCase.label}-iam`,
          stepIndex: 0,
          requestId: crypto.randomUUID(),
        },
      );
    } catch (error) {
      liveError = error;
    }
    check(
      `legacy ${testCase.label} IAM rollback keeps a live parent fail-closed`,
      liveError instanceof Error &&
        liveError.message === "iam-ownership-checkpoint-missing" && mutations === 0,
      JSON.stringify({ error: String(liveError), mutations }),
    );
  }
}

{
  const originalPolicy = {
    version: 1,
    etag: "before-etag",
    bindings: [{ role: "roles/viewer", members: ["user:owner@example.com"] }],
  };
  const writtenPolicies: unknown[] = [];
  const requestedVersions: unknown[] = [];
  let policyReads = 0;
  let restoreWrites = 0;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        policyReads += 1;
        requestedVersions.push(options.params?.["options.requestedPolicyVersion"]);
        return {
          status: 200,
          payload: {
            ...structuredClone(originalPolicy),
            etag: policyReads === 1 ? "before-etag" : `fresh-etag-${policyReads}`,
          },
        };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        const policy = options.jsonBody?.policy as {
          etag?: unknown;
          bindings?: Array<{ role?: unknown }>;
        } | undefined;
        writtenPolicies.push(policy);
        const isRestore = policy?.bindings?.length === 1 &&
          policy.bindings[0]?.role === "roles/viewer";
        if (isRestore) {
          restoreWrites += 1;
          if (restoreWrites === 1) {
            return { status: 409, payload: { error: { status: "ABORTED" } } };
          }
        }
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change("beyondcorp", "gateway_iam", "default-iam");
  const firstExecutor = new GoogleResourceExecutor(transport);
  const applied = await firstExecutor.apply(target, SPEC, {
    runId: "run-before-image",
    stepIndex: 0,
    requestId: crypto.randomUUID(),
  });
  const secondExecutor = new GoogleResourceExecutor(transport);
  await secondExecutor.rollback?.(target, SPEC, {
    runId: "run-before-image",
    stepIndex: 0,
    requestId: crypto.randomUUID(),
    beforeImage: (applied as { beforeImage?: unknown } | undefined)?.beforeImage,
  });
  check(
    "IAM rollback refreshes etag and retries one concurrent-policy conflict",
    JSON.stringify(writtenPolicies.at(-1)) ===
      JSON.stringify({ ...originalPolicy, etag: "fresh-etag-3", version: 3 }) &&
      restoreWrites === 2 && requestedVersions.every((version) => version === 3),
    JSON.stringify(writtenPolicies),
  );
}

// Apply -> post-deploy IAM update -> teardown uses the original before-policy
// and the newest managed after-policy. Unrelated edits made after the update
// must survive while every grant currently owned by SGS is removed.
{
  const role = "roles/beyondcorp.serviceDiscoveryUser";
  const original = {
    version: 3,
    etag: "before-apply",
    bindings: [{ role, members: ["group:existing@example.com"] }],
  };
  const applyAfter = {
    version: 3,
    etag: "after-apply",
    bindings: [{
      role,
      members: ["group:existing@example.com", "group:initial@example.com"],
    }],
  };
  const updateAfter = {
    version: 3,
    etag: "after-update",
    bindings: [{
      role,
      members: ["group:existing@example.com", "group:new@example.com"],
    }],
  };
  const liveWithThirdPartyEdit = {
    version: 3,
    etag: "fresh-live",
    bindings: [{
      role,
      members: [
        "group:existing@example.com",
        "group:new@example.com",
        "group:third-party@example.com",
      ],
    }],
  };
  const beforeImage = withLatestIamAfterPolicy({
    kind: "iam",
    phase: "applied",
    getUrl: "https://beyondcorp.googleapis.com/v1/gateway:getIamPolicy",
    setUrl: "https://beyondcorp.googleapis.com/v1/gateway:setIamPolicy",
    policy: original,
    afterPolicy: applyAfter,
  }, updateAfter);
  let restored: Record<string, unknown> | undefined;
  const transport: Transport = {
    async requestJson(method, _url, options = {}) {
      if (method === "GET") return { status: 200, payload: liveWithThirdPartyEdit };
      restored = options.jsonBody?.policy as Record<string, unknown> | undefined;
      return { status: 200, payload: {} };
    },
  };
  const executor = new GoogleResourceExecutor(transport);
  await executor.destroy(
    change("beyondcorp", "gateway_iam", "default-service-discovery-users"),
    SPEC,
    crypto.randomUUID(),
    beforeImage,
  );
  const members = ((restored?.bindings as Array<{ members?: string[] }> | undefined)?.[0]
    ?.members ?? []).sort();
  check(
    "Apply-update-teardown removes latest SGS grants and preserves third-party IAM edits",
    members.join(",") === [
      "group:existing@example.com",
      "group:third-party@example.com",
    ].join(",") && restored?.etag === "fresh-live",
    JSON.stringify(restored),
  );
}

// APIs without requestId still have stable resource names. A retry may return
// ALREADY_EXISTS after the first call landed but before the step was persisted;
// that one status is an explicit reconciliation result, not a blanket success.
{
  let reconciled = false;
  let marker: unknown;
  const alreadyExists: Transport = {
    async requestJson(method, _url, options = {}) {
      if (method === "GET") {
        reconciled = true;
        return {
          status: 200,
          payload: {
            email: "sgs-runtime@enterprise-secgw-01.iam.gserviceaccount.com",
            displayName: "Secure Gateway Studio sgs-runtime",
            description: marker,
          },
        };
      }
      marker = (options.jsonBody?.serviceAccount as { description?: unknown } | undefined)
        ?.description;
      return {
        status: 409,
        payload: { error: { status: "ALREADY_EXISTS", message: "already exists" } },
      };
    },
  };
  const executor = new GoogleResourceExecutor(alreadyExists);
  let error: unknown;
  try {
    await executor.apply(
      change("iam", "service_account", "sgs-runtime"),
      SPEC,
      { runId: "run-reconcile", stepIndex: 0, requestId: crypto.randomUUID() },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "named create reconciles ALREADY_EXISTS only through its run ownership marker",
    error === undefined && reconciled && typeof marker === "string",
    String(error),
  );
}

// A semantically identical named resource created after Plan is still owned by
// the other administrator. Rollback may delete only a resource carrying this
// run's durable ownership marker.
{
  const target = change("iam", "service_account", "sgs-runtime-raced");
  let checkpoint: unknown;
  let deletes = 0;
  const transport: Transport = {
    async requestJson(method) {
      if (method === "POST") {
        return { status: 409, payload: { error: { status: "ALREADY_EXISTS" } } };
      }
      if (method === "DELETE") deletes += 1;
      return {
        status: 200,
        payload: {
          email: "sgs-runtime-raced@enterprise-secgw-01.iam.gserviceaccount.com",
          displayName: "Secure Gateway Studio sgs-runtime-raced",
          description: "Created by another administrator",
        },
      };
    },
  };
  const executor = new GoogleResourceExecutor(transport);
  const requestId = "0e6d625f-45a4-4e3a-9dd4-f9e0a76d3fb1";
  let error: unknown;
  try {
    await executor.apply(target, SPEC, {
      runId: "run-sa-race",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (caught) {
    error = caught;
  }
  let rollbackError: unknown;
  try {
    await executor.rollback(target, SPEC, {
      runId: "run-sa-race",
      stepIndex: 0,
      requestId,
      beforeImage: checkpoint,
    });
  } catch (caught) {
    rollbackError = caught;
  }
  check(
    "service-account Plan/Apply collision is retained and never deleted",
    error instanceof Error && rollbackError instanceof Error && deletes === 0,
    `${String(error)}; ${String(rollbackError)}; deletes=${deletes}`,
  );
}

{
  const target = change("secretmanager", "secret", "raced-tls");
  let checkpoint: unknown;
  let postedLabels: Record<string, unknown> = {};
  let deletes = 0;
  const resourceUrl =
    "https://secretmanager.googleapis.com/v1/projects/enterprise-secgw-01/secrets/raced-tls";
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "POST") {
        postedLabels = (options.jsonBody?.labels ?? {}) as Record<string, unknown>;
        return { status: 409, payload: { error: { status: "ALREADY_EXISTS" } } };
      }
      if (method === "DELETE") deletes += 1;
      if (method === "GET" && url === resourceUrl) {
        return {
          status: 200,
          payload: {
            labels: { ...postedLabels, "sgs-owner-token": "other-run" },
            replication: { automatic: {} },
          },
        };
      }
      return { status: 200, payload: {} };
    },
  };
  const executor = new GoogleResourceExecutor(transport);
  const requestId = "1a93ee60-67f4-41d9-8104-4163a2c77c5a";
  let error: unknown;
  try {
    await executor.apply(target, SPEC, {
      runId: "run-secret-race",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (caught) {
    error = caught;
  }
  let rollbackError: unknown;
  try {
    await executor.rollback(target, SPEC, {
      runId: "run-secret-race",
      stepIndex: 0,
      requestId,
      beforeImage: checkpoint,
    });
  } catch (caught) {
    rollbackError = caught;
  }
  check(
    "Secret Manager Plan/Apply collision is retained and never deleted",
    error instanceof Error && rollbackError instanceof Error && deletes === 0,
    `${String(error)}; ${String(rollbackError)}; deletes=${deletes}`,
  );
}

{
  const target = change("dns", "record_set", SPEC.private_hostname);
  let checkpoint: unknown;
  let changePosts = 0;
  const address = "10.20.0.25";
  const transport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.includes("/addresses/")) {
        return { status: 200, payload: { address } };
      }
      if (method === "POST" && url.endsWith("/changes")) {
        changePosts += 1;
        return { status: 409, payload: { error: { status: "ALREADY_EXISTS" } } };
      }
      if (method === "GET" && url.endsWith("/A")) {
        return {
          status: 200,
          payload: {
            name: `${SPEC.private_hostname}.`,
            type: "A",
            ttl: 60,
            rrdatas: [address],
          },
        };
      }
      if (method === "GET" && url.endsWith("/TXT")) {
        return { status: 404, payload: { error: { status: "NOT_FOUND" } } };
      }
      return { status: 200, payload: {} };
    },
  };
  const executor = new GoogleResourceExecutor(transport);
  const requestId = "392b90af-5be5-4ab3-9cf5-26f379535d98";
  let error: unknown;
  try {
    await executor.apply(target, SPEC, {
      runId: "run-dns-race",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (caught) {
    error = caught;
  }
  let rollbackError: unknown;
  try {
    await executor.rollback(target, SPEC, {
      runId: "run-dns-race",
      stepIndex: 0,
      requestId,
      beforeImage: checkpoint,
    });
  } catch (caught) {
    rollbackError = caught;
  }
  check(
    "DNS Plan/Apply collision without the ownership TXT is never deleted",
    error instanceof Error && rollbackError instanceof Error && changePosts === 1,
    `${String(error)}; ${String(rollbackError)}; changePosts=${changePosts}`,
  );
}

// A named create can commit while its response is lost and remain temporarily
// invisible. The durable sending phase must survive that first 404; a later
// exact marker is then safely reclaimed and deleted without a second create.
{
  const target = change("iam", "service_account", "sgs-eventual-runtime");
  const requestId = "fa927b9d-a78c-4f8a-b644-b9c2d893dd85";
  let checkpoint: unknown;
  let visible = false;
  let creates = 0;
  let deletes = 0;
  const resourceUrl =
    "https://iam.googleapis.com/v1/projects/enterprise-secgw-01/serviceAccounts/" +
    encodeURIComponent(
      "sgs-eventual-runtime@enterprise-secgw-01.iam.gserviceaccount.com",
    );
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "POST") {
        creates += 1;
        throw new Error("connection-reset-after-service-account-create");
      }
      if (method === "GET" && url === resourceUrl) {
        return visible
          ? {
            status: 200,
            payload: {
              email: "sgs-eventual-runtime@enterprise-secgw-01.iam.gserviceaccount.com",
              displayName: "Secure Gateway Studio sgs-eventual-runtime",
              description: `Secure Gateway Studio ownership-token=${requestId}`,
            },
          }
          : { status: 404, payload: { error: { status: "NOT_FOUND" } } };
      }
      if (method === "DELETE" && url === resourceUrl) {
        deletes += 1;
        visible = false;
        return { status: 200, payload: {} };
      }
      void options;
      return { status: 200, payload: {} };
    },
  };
  let firstError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-named-eventual",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
    });
  } catch (caught) {
    firstError = caught;
  }
  let firstRollbackError: unknown;
  try {
    await new GoogleResourceExecutor(transport).rollback(target, SPEC, {
      runId: "run-named-eventual",
      stepIndex: 0,
      requestId,
      beforeImage: checkpoint,
    });
  } catch (caught) {
    firstRollbackError = caught;
  }
  visible = true;
  await new GoogleResourceExecutor(transport).rollback(target, SPEC, {
    runId: "run-named-eventual",
    stepIndex: 0,
    requestId,
    beforeImage: checkpoint,
  });
  check(
    "named response loss retains sending claim through 404 then deletes exact visible owner",
    firstError instanceof Error && firstRollbackError instanceof Error &&
      (checkpoint as { phase?: unknown }).phase === "sending" &&
      creates === 1 && deletes === 1 && !visible,
    JSON.stringify({ firstError: String(firstError), firstRollbackError: String(firstRollbackError), checkpoint, creates, deletes }),
  );
}

// A mutation that returns google.longrunning.Operation is only successful once
// the operation reports done without an embedded error.
{
  let polls = 0;
  const transport: Transport = {
    async requestJson(method) {
      if (method === "POST") {
        return { status: 200, payload: { name: "operations/service-enable-1", done: false } };
      }
      polls += 1;
      return polls === 1
        ? { status: 200, payload: { name: "operations/service-enable-1", done: false } }
        : { status: 200, payload: { name: "operations/service-enable-1", done: true } };
    },
  };
  const executor = new GoogleResourceExecutor(transport, {
    operationPollIntervalMs: 0,
    maxOperationPolls: 3,
  });
  await executor.apply(
    change("serviceusage", "project_services", "enterprise-secgw-01"),
    SPEC,
    { runId: "run-lro", stepIndex: 0, requestId: crypto.randomUUID() },
  );
  check("long-running operations are polled to completion", polls === 2, String(polls));
}

// Chrome Policy's REST representation of FieldMask is a comma-separated
// string. A protobuf-shaped `{ paths: [...] }` body is rejected by batchModify.
{
  let updateMask: unknown;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.includes("/orgunits/id%3A")) {
        return { status: 200, payload: { orgUnitId: `id:${SPEC.target_ou_id}`, orgUnitPath: "/Pilot" } };
      }
      if (method === "GET" && url.includes("/policySchemas/")) {
        return {
          status: 200,
          payload: {
            definition: {
              messageType: [{ field: [{ name: "appInstallType" }] }],
            },
          },
        };
      }
      if (url.endsWith("/policies:resolve")) {
        return { status: 200, payload: {} };
      }
      const body = options.jsonBody as
        | { requests?: Array<{ updateMask?: unknown }> }
        | undefined;
      updateMask = body?.requests?.[0]?.updateMask;
      return { status: 200, payload: {} };
    },
  };
  let cloudCalls = 0;
  const cloudTransport: Transport = {
    async requestJson() {
      cloudCalls += 1;
      return { status: 500, payload: { error: { message: "wrong credential" } } };
    },
  };
  const executor = new GoogleResourceExecutor(cloudTransport, {
    workspaceTransport: transport,
  });
  await executor.apply(
    change("chromepolicy", "extension_install", "abcdefghijklmnopabcdefghijklmnop"),
    SPEC,
    { runId: "run-policy", stepIndex: 0, requestId: crypto.randomUUID() },
  );
  check(
    "Chrome Policy updateMask uses the REST FieldMask string",
    updateMask === "appInstallType",
    JSON.stringify(updateMask),
  );
  check("Chrome Policy uses the administrator Workspace transport", cloudCalls === 0);
}

// A Chrome Policy before-image is authority for both Apply and teardown. An
// omitted repeated field is an empty protobuf list, but malformed or duplicate
// policy values must never be interpreted as inherited empty policy state.
{
  const appId = "abcdefghijklmnopabcdefghijklmnop";
  const schema = "chrome.users.apps.InstallType";
  const targetKey = {
    targetResource: `orgunits/${SPEC.target_ou_id}`,
    additionalTargetKeys: { app_id: `chrome:${appId}` },
  };
  const validPolicy = {
    targetKey,
    sourceKey: { targetResource: `orgunits/${SPEC.target_ou_id}` },
    value: { policySchema: schema, value: { appInstallType: "BLOCKED" } },
  };
  const malformedPayloads: Record<string, unknown>[] = [
    { resolvedPolicies: {} },
    { resolvedPolicies: [null] },
    {
      resolvedPolicies: [{
        ...validPolicy,
        sourceKey: { targetResource: "groups/not-an-ou" },
      }],
    },
    {
      resolvedPolicies: [{
        ...validPolicy,
        targetKey: {
          ...targetKey,
          additionalTargetKeys: { app_id: "chrome:different-extension" },
        },
      }],
    },
    {
      resolvedPolicies: [{ ...validPolicy, value: { value: { appInstallType: "BLOCKED" } } }],
    },
    { resolvedPolicies: [validPolicy, structuredClone(validPolicy)] },
  ];
  let accepted = 0;
  let writes = 0;
  for (const payload of malformedPayloads) {
    const workspace: Transport = {
      async requestJson(method, url) {
        if (method === "GET" && url.includes("/orgunits/id%3A")) {
          return { status: 200, payload: { orgUnitId: `id:${SPEC.target_ou_id}`, orgUnitPath: "/Pilot" } };
        }
        if (method === "GET" && url.includes("/policySchemas/")) {
          return {
            status: 200,
            payload: { definition: { messageType: [{ field: [{ name: "appInstallType" }] }] } },
          };
        }
        if (url.endsWith("/policies:resolve")) {
          return { status: 200, payload: structuredClone(payload) };
        }
        if (url.endsWith(":batchModify")) writes += 1;
        return { status: 200, payload: {} };
      },
    };
    try {
      await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace }).apply(
        change("chromepolicy", "extension_install", appId),
        SPEC,
        { runId: "run-chrome-malformed", stepIndex: 0, requestId: crypto.randomUUID() },
      );
      accepted += 1;
    } catch {
      // Expected fail-closed validation.
    }
  }
  check(
    "Chrome Policy apply rejects malformed or duplicate direct resolve results before mutation",
    accepted === 0 && writes === 0,
    JSON.stringify({ accepted, writes }),
  );
}

{
  const appId = "abcdefghijklmnopabcdefghijklmnop";
  let malformed = false;
  let writes = 0;
  const workspace: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.includes("/orgunits/id%3A")) {
        return { status: 200, payload: { orgUnitId: `id:${SPEC.target_ou_id}`, orgUnitPath: "/Pilot" } };
      }
      if (method === "GET" && url.includes("/policySchemas/")) {
        return {
          status: 200,
          payload: { definition: { messageType: [{ field: [{ name: "appInstallType" }] }] } },
        };
      }
      if (url.endsWith("/policies:resolve")) {
        return malformed
          ? { status: 200, payload: { resolvedPolicies: { malformed: true } } }
          : { status: 200, payload: { resolvedPolicies: [] } };
      }
      if (url.endsWith(":batchModify") || url.endsWith(":batchInherit")) writes += 1;
      return { status: 200, payload: {} };
    },
  };
  const target = change("chromepolicy", "extension_install", appId);
  const applied = await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace })
    .apply(target, SPEC, {
      runId: "run-chrome-malformed-rollback",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
    });
  malformed = true;
  let error: unknown;
  try {
    await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace }).rollback(
      target,
      SPEC,
      {
        runId: "run-chrome-malformed-rollback",
        stepIndex: 0,
        requestId: crypto.randomUUID(),
        beforeImage: applied.beforeImage,
      },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "Chrome Policy rollback rejects malformed live state without an inherit or modify",
    error instanceof Error && writes === 1,
    JSON.stringify({ error: String(error), writes }),
  );
}

// Resolve is paginated even for exact schema/target filters. Apply and rollback
// must see a direct policy on a later page before they capture or restore it.
{
  const appId = "abcdefghijklmnopabcdefghijklmnop";
  const schema = "chrome.users.apps.InstallType";
  let direct = { appInstallType: "BLOCKED" };
  let writes = 0;
  const resolveBodies: Record<string, unknown>[] = [];
  const workspace: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.includes("/orgunits/id%3A")) {
        return { status: 200, payload: { orgUnitId: `id:${SPEC.target_ou_id}`, orgUnitPath: "/Pilot" } };
      }
      if (method === "GET" && url.includes("/policySchemas/")) {
        return {
          status: 200,
          payload: { definition: { messageType: [{ field: [{ name: "appInstallType" }] }] } },
        };
      }
      if (url.endsWith("/policies:resolve")) {
        const body = structuredClone(options.jsonBody ?? {});
        resolveBodies.push(body);
        if (body.pageToken === undefined) {
          return { status: 200, payload: { resolvedPolicies: [], nextPageToken: "resolve-page-2" } };
        }
        return {
          status: 200,
          payload: {
            resolvedPolicies: [{
              targetKey: body.policyTargetKey,
              sourceKey: { targetResource: `orgunits/${SPEC.target_ou_id}` },
              addedSourceKey: {},
              value: { policySchema: schema, value: structuredClone(direct) },
            }],
          },
        };
      }
      if (url.endsWith(":batchModify")) {
        writes += 1;
        direct = structuredClone(
          ((options.jsonBody?.requests as Array<{
            policyValue: { value: { appInstallType: string } };
          }>)[0]!).policyValue.value,
        );
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change("chromepolicy", "extension_install", appId);
  const applied = await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace })
    .apply(target, SPEC, {
      runId: "run-chrome-paged",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
    });
  await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace }).rollback(
    target,
    SPEC,
    {
      runId: "run-chrome-paged",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      beforeImage: applied.beforeImage,
    },
  );
  check(
    "Chrome Policy apply and rollback follow empty resolve pages before mutation",
    writes === 2 && direct.appInstallType === "BLOCKED" && resolveBodies.length === 4 &&
      resolveBodies.every((body, index) =>
        body.pageSize === 1_000 &&
        (index % 2 === 0 ? body.pageToken === undefined : body.pageToken === "resolve-page-2")
      ),
    JSON.stringify({ writes, direct, resolveBodies }),
  );
}

for (const tokenFault of ["non-string", "repeat"] as const) {
  let resolveCalls = 0;
  let writes = 0;
  const workspace: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.includes("/orgunits/id%3A")) {
        return { status: 200, payload: { orgUnitId: `id:${SPEC.target_ou_id}`, orgUnitPath: "/Pilot" } };
      }
      if (method === "GET" && url.includes("/policySchemas/")) {
        return {
          status: 200,
          payload: { definition: { messageType: [{ field: [{ name: "appInstallType" }] }] } },
        };
      }
      if (url.endsWith("/policies:resolve")) {
        resolveCalls += 1;
        return {
          status: 200,
          payload: {
            resolvedPolicies: [],
            nextPageToken: tokenFault === "non-string" ? null : "repeat",
          },
        };
      }
      if (url.endsWith(":batchModify") || url.endsWith(":batchInherit")) writes += 1;
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace }).apply(
      change("chromepolicy", "extension_install", "abcdefghijklmnopabcdefghijklmnop"),
      SPEC,
      { runId: `run-chrome-${tokenFault}`, stepIndex: 0, requestId: crypto.randomUUID() },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    `Chrome Policy ${tokenFault} pagination fails closed before mutation`,
    error instanceof Error && writes === 0 && resolveCalls === (tokenFault === "repeat" ? 2 : 1),
    JSON.stringify({ error: String(error), writes, resolveCalls }),
  );
}

// Rollback/teardown may restore a direct OU policy only while the live value is
// still exactly the managed-after value written by this run. A later Admin
// console edit is ownership of the current value, not something to overwrite.
{
  let direct: Record<string, unknown> | null = { appInstallType: "BLOCKED" };
  let writes = 0;
  let checkpoint: unknown;
  const phases: unknown[] = [];
  const workspace: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.includes("/orgunits/id%3A")) {
        return { status: 200, payload: { orgUnitId: `id:${SPEC.target_ou_id}`, orgUnitPath: "/Pilot" } };
      }
      if (method === "GET" && url.includes("/policySchemas/")) {
        return {
          status: 200,
          payload: { definition: { messageType: [{ field: [{ name: "appInstallType" }] }] } },
        };
      }
      if (url.endsWith("/policies:resolve")) {
        return {
          status: 200,
          payload: {
            resolvedPolicies: direct === null ? [] : [{
              targetKey: {
                targetResource: `orgunits/${SPEC.target_ou_id}`,
                additionalTargetKeys: {
                  app_id: "chrome:abcdefghijklmnopabcdefghijklmnop",
                },
              },
              sourceKey: { targetResource: `orgunits/${SPEC.target_ou_id}` },
              value: {
                policySchema: "chrome.users.apps.InstallType",
                value: structuredClone(direct),
              },
            }],
          },
        };
      }
      if (url.endsWith(":batchModify")) {
        writes += 1;
        direct = structuredClone((options.jsonBody as {
          requests?: Array<{ policyValue?: { value?: Record<string, unknown> } }>;
        }).requests?.[0]?.policyValue?.value ?? {});
        throw new Error("committed-chrome-policy-response-lost");
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change(
    "chromepolicy",
    "extension_install",
    "abcdefghijklmnopabcdefghijklmnop",
  );
  let firstError: unknown;
  try {
    await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace }).apply(
      target,
      SPEC,
      {
        runId: "run-chrome-response-loss",
        stepIndex: 0,
        requestId: crypto.randomUUID(),
        checkpointBeforeImage: async (value) => {
          checkpoint = structuredClone(value);
          phases.push((value as { phase?: unknown }).phase);
        },
      },
    );
  } catch (error) {
    firstError = error;
  }
  let retryError: unknown;
  try {
    await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace }).apply(
      target,
      SPEC,
      {
        runId: "run-chrome-response-loss",
        stepIndex: 0,
        requestId: crypto.randomUUID(),
        beforeImage: checkpoint,
        checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
      },
    );
  } catch (error) {
    retryError = error;
  }
  let rollbackError: unknown;
  try {
    await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace }).rollback(
      target,
      SPEC,
      {
        runId: "run-chrome-response-loss",
        stepIndex: 0,
        requestId: crypto.randomUUID(),
        beforeImage: checkpoint,
      },
    );
  } catch (error) {
    rollbackError = error;
  }
  check(
    "Chrome Policy prepared/sending never claims coincidental managed-after equality",
    firstError instanceof Error && phases.join(",") === "prepared,sending" && writes === 1 &&
      (retryError as { code?: unknown })?.code === "chrome-policy-mutation-outcome-ambiguous" &&
      (rollbackError as { code?: unknown })?.code === "chrome-policy-rollback-outcome-ambiguous" &&
      direct?.appInstallType === "FORCED",
    JSON.stringify({ phases, writes, retryError: String(retryError), rollbackError: String(rollbackError), direct }),
  );
}

{
  let checkpoint: unknown;
  let writes = 0;
  const workspace: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.includes("/orgunits/id%3A")) {
        return { status: 200, payload: { orgUnitId: `id:${SPEC.target_ou_id}`, orgUnitPath: "/Pilot" } };
      }
      if (method === "GET" && url.includes("/policySchemas/")) {
        return {
          status: 200,
          payload: { definition: { messageType: [{ field: [{ name: "appInstallType" }] }] } },
        };
      }
      if (url.endsWith("/policies:resolve")) {
        return { status: 200, payload: { resolvedPolicies: [] } };
      }
      if (url.endsWith(":batchModify")) {
        writes += 1;
        return { status: 400, payload: { error: { status: "INVALID_ARGUMENT" } } };
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change(
    "chromepolicy",
    "extension_install",
    "abcdefghijklmnopabcdefghijklmnop",
  );
  try {
    await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace }).apply(
      target,
      SPEC,
      {
        runId: "run-chrome-rejected",
        stepIndex: 0,
        requestId: crypto.randomUUID(),
        checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
      },
    );
  } catch {
    // Expected definitive rejection.
  }
  await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace }).rollback(
    target,
    SPEC,
    {
      runId: "run-chrome-rejected",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      beforeImage: checkpoint,
    },
  );
  check(
    "definitive Chrome Policy 4xx advances rejected and rollback is a no-op",
    (checkpoint as { phase?: unknown } | undefined)?.phase === "rejected" && writes === 1,
    JSON.stringify({ checkpoint, writes }),
  );
}

{
  type DirectValues = Record<string, unknown> | null;
  let direct: DirectValues = { appInstallType: "BLOCKED" };
  let writes = 0;
  const cloudOnly: Transport = {
    async requestJson() {
      throw new Error("Chrome Policy must not use the Cloud deployer transport");
    },
  };
  const workspaceTransport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.includes("/orgunits/id%3A")) {
        return { status: 200, payload: { orgUnitId: `id:${SPEC.target_ou_id}`, orgUnitPath: "/Pilot" } };
      }
      if (method === "GET" && url.includes("/policySchemas/")) {
        return {
          status: 200,
          payload: { definition: { messageType: [{ field: [{ name: "appInstallType" }] }] } },
        };
      }
      if (url.endsWith("/policies:resolve")) {
        return {
          status: 200,
          payload: {
            resolvedPolicies: direct === null
              ? []
              : [{
                  targetKey: {
                    targetResource: `orgunits/${SPEC.target_ou_id}`,
                    additionalTargetKeys: {
                      app_id: "chrome:abcdefghijklmnopabcdefghijklmnop",
                    },
                  },
                  sourceKey: { targetResource: `orgunits/${SPEC.target_ou_id}` },
                  value: {
                    policySchema: "chrome.users.apps.InstallType",
                    value: structuredClone(direct),
                  },
                }],
          },
        };
      }
      if (url.endsWith(":batchModify")) {
        writes += 1;
        const request = (
          options.jsonBody as {
            requests?: Array<{ policyValue?: { value?: Record<string, unknown> } }>;
          }
        ).requests?.[0];
        direct = structuredClone(request?.policyValue?.value ?? {});
        return { status: 200, payload: {} };
      }
      if (url.endsWith(":batchInherit")) {
        writes += 1;
        direct = null;
        return { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  const target = change(
    "chromepolicy",
    "extension_install",
    "abcdefghijklmnopabcdefghijklmnop",
  );
  const applied = await new GoogleResourceExecutor(cloudOnly, {
    workspaceTransport,
  }).apply(target, SPEC, {
    runId: "run-policy-managed-after",
    stepIndex: 0,
    requestId: crypto.randomUUID(),
  });
  const managedAfter = (
    applied.beforeImage as { managedAfter?: Record<string, unknown> } | undefined
  )?.managedAfter;
  check(
    "Chrome Policy checkpoint records the exact managed-after direct value",
    managedAfter?.appInstallType === "FORCED",
    JSON.stringify(applied.beforeImage),
  );

  direct = { appInstallType: "ALLOWED", adminMarker: "external" };
  let rollbackError: unknown;
  try {
    await new GoogleResourceExecutor(cloudOnly, { workspaceTransport }).rollback(
      target,
      SPEC,
      {
        runId: "run-policy-managed-after",
        stepIndex: 0,
        requestId: crypto.randomUUID(),
        beforeImage: applied.beforeImage,
      },
    );
  } catch (error) {
    rollbackError = error;
  }
  let teardownError: unknown;
  try {
    await new GoogleResourceExecutor(cloudOnly, { workspaceTransport }).destroy(
      target,
      SPEC,
      crypto.randomUUID(),
      applied.beforeImage,
    );
  } catch (error) {
    teardownError = error;
  }
  check(
    "Chrome Policy rollback and teardown preserve post-Apply administrator edits",
    (rollbackError as { code?: unknown })?.code === "chrome-policy-current-state-changed" &&
      (teardownError as { code?: unknown })?.code === "chrome-policy-current-state-changed" &&
      writes === 1 && direct.appInstallType === "ALLOWED" &&
      direct.adminMarker === "external",
    `${String(rollbackError)} | ${String(teardownError)} | ${JSON.stringify(direct)}`,
  );

  direct = structuredClone(managedAfter ?? {});
  await new GoogleResourceExecutor(cloudOnly, { workspaceTransport }).rollback(
    target,
    SPEC,
    {
      runId: "run-policy-managed-after",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      beforeImage: applied.beforeImage,
    },
  );
  check(
    "Chrome Policy rollback restores the original direct value after exact ownership match",
    direct?.appInstallType === "BLOCKED" && writes === 2,
    JSON.stringify(direct),
  );
}

// The run-engine request id, rather than a constructor-time random value, must
// reach Google so a retry after MV3 worker termination is deduplicated.
{
  let requestId: unknown;
  const transport: Transport = {
    async requestJson(method, _url, options = {}) {
      if (method === "POST") requestId = options.params?.requestId;
      if (method === "GET") {
        return {
          status: 200,
          payload: {
            id: "101",
            description:
              "Secure Gateway Studio ownership-token=" +
              "bd70a184-50e5-4321-8d33-7f576df30db7; " +
              "Managed by Secure Gateway Studio",
          },
        };
      }
      return { status: 200, payload: {} };
    },
  };
  const executor = new GoogleResourceExecutor(transport);
  await executor.apply(change("compute", "network", "private-app-vpc"), SPEC, {
    runId: "run-stable-id",
    stepIndex: 0,
    requestId: "bd70a184-50e5-4321-8d33-7f576df30db7",
  });
  check(
    "the persisted run-step request id reaches Google creates",
    requestId === "bd70a184-50e5-4321-8d33-7f576df30db7",
    String(requestId),
  );
}

// The official Private Web App REST flow uses the protobuf snake_case create
// identifiers. Pin those names so the extension and operator guide send the
// same request shape.
{
  const creates: Array<Record<string, string | number> | undefined> = [];
  let gatewayBody: Record<string, unknown> = {};
  let applicationBody: Record<string, unknown> = {};
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "POST" &&
          (url.endsWith("/securityGateways") || url.endsWith("/applications"))) {
        creates.push(options.params);
        if (url.endsWith("/applications")) {
          applicationBody = structuredClone(options.jsonBody ?? {});
        } else {
          gatewayBody = structuredClone(options.jsonBody ?? {});
        }
      }
      if (method === "GET" && url.includes("/securityGateways/")) {
        const application = url.includes("/applications/");
        return {
          status: 200,
          payload: {
            ...(application ? applicationBody : gatewayBody),
            name: application
              ? `projects/${SPEC.project_id}/locations/global/securityGateways/` +
                `${SPEC.gateway_id}/applications/${SPEC.name}-app`
              : `projects/${SPEC.project_id}/locations/global/securityGateways/` +
                SPEC.gateway_id,
            createTime: application
              ? "2026-08-24T00:00:02Z"
              : "2026-08-24T00:00:01Z",
            ...(application
              ? {}
              : {
                state: "RUNNING",
                delegatingServiceAccount:
                  "delegate@enterprise-secgw-01.iam.gserviceaccount.com",
              }),
          },
        };
      }
      return { status: 200, payload: {} };
    },
  };
  const executor = new GoogleResourceExecutor(transport, { operationPollIntervalMs: 0 });
  await executor.apply(
    change("beyondcorp", "security_gateway", SPEC.gateway_id),
    SPEC,
    { runId: "run-gateway-rest-fields", stepIndex: 0, requestId: crypto.randomUUID() },
  );
  await executor.apply(
    change("beyondcorp", "application", `${SPEC.name}-app`),
    SPEC,
    { runId: "run-application-rest-fields", stepIndex: 1, requestId: crypto.randomUUID() },
  );
  check(
    "BeyondCorp create IDs match the official Private Web App REST flow",
    typeof creates[0]?.securityGatewayId === "string" &&
      creates[0]?.security_gateway_id === undefined &&
      typeof creates[1]?.applicationId === "string" &&
      creates[1]?.application_id === undefined,
    JSON.stringify(creates),
  );
}

{
  let body: Record<string, unknown> = {};
  let checkpoint: unknown;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "POST") {
        body = structuredClone(options.jsonBody ?? {});
        return { status: 200, payload: { uid: "undocumented-uid-only" } };
      }
      if (method === "GET" && url.includes("/securityGateways/")) {
        return {
          status: 200,
          payload: {
            ...body,
            uid: "undocumented-uid-only",
            delegatingServiceAccount: "gateway-sa@example.iam.gserviceaccount.com",
          },
        };
      }
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(
      change("beyondcorp", "security_gateway", SPEC.gateway_id),
      SPEC,
      {
        runId: "run-beyondcorp-uid-only",
        stepIndex: 0,
        requestId: "25dabed9-058d-4760-96e3-e1f3836edbce",
        checkpointBeforeImage: async (value) => {
          checkpoint = structuredClone(value);
        },
      },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "BeyondCorp uid-only responses never become immutable ownership proof",
    (error as { code?: unknown })?.code === "generic-resource-provider-identity-missing" &&
      (checkpoint as { phase?: unknown } | undefined)?.phase === "sending",
    JSON.stringify({ error: String(error), checkpoint }),
  );
}

// Generic Compute creates persist the exact request marker and immutable
// provider id before the handler can report success. A committed response loss
// is reconciled by that marker, while a later same-name replacement is kept.
{
  const target = change("compute", "network", "owned-network");
  const resourceUrl =
    "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/global/" +
    "networks/owned-network";
  const requestId = "df01e0c7-9241-43f4-873d-53314e8ce22f";
  let live: Record<string, unknown> | null = null;
  let checkpoint: unknown;
  let creates = 0;
  let deletes = 0;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "POST") {
        creates += 1;
        live = { ...structuredClone(options.jsonBody ?? {}), id: "1001" };
        throw new Error("connection-reset-after-create-commit");
      }
      if (method === "GET" && url === resourceUrl) {
        return live === null
          ? { status: 404, payload: {} }
          : { status: 200, payload: structuredClone(live) };
      }
      if (method === "DELETE" && url === resourceUrl) {
        deletes += 1;
        live = null;
        return { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  let applyError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-generic-response-loss",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (error) {
    applyError = error;
  }
  check(
    "Compute response loss reconciles the exact marker and immutable provider id",
    applyError === undefined && creates === 1 &&
      (checkpoint as { phase?: unknown }).phase === "applied" &&
      (checkpoint as { providerIdentity?: unknown }).providerIdentity === "1001" &&
      (live as { description?: unknown } | null)?.description ===
        `Secure Gateway Studio ownership-token=${requestId}; Managed by Secure Gateway Studio`,
    JSON.stringify({ applyError: String(applyError), creates, checkpoint, live }),
  );

  // Even copying the visible marker does not make a replacement the immutable
  // object captured after Apply.
  live = { ...(live ?? {}), id: "foreign-replacement" };
  const outcome = await new GoogleResourceExecutor(transport).destroy(
    target,
    SPEC,
    crypto.randomUUID(),
    checkpoint,
  );
  check(
    "generic teardown retains a same-name replacement with a different provider id",
    outcome === "skipped" && deletes === 0 && live !== null,
    JSON.stringify({ outcome, deletes, live }),
  );
}

// A Gateway can be deleted only after every reachable application-list page
// is proven empty. Malformed pages and unreachable pagination retain it.
{
  const target = change("beyondcorp", "security_gateway", SPEC.gateway_id);
  const resourceUrl =
    "https://beyondcorp.googleapis.com/v1/projects/enterprise-secgw-01/locations/global/" +
    `securityGateways/${SPEC.gateway_id}`;
  const applicationPrefix =
    `projects/enterprise-secgw-01/locations/global/securityGateways/${SPEC.gateway_id}/` +
    "applications/";
  const checkpoint = {
    kind: "generic_created_resource",
    protocolVersion: 2,
    phase: "applied",
    resourceKey: `beyondcorp:security_gateway:${SPEC.gateway_id}`,
    createUrl: resourceUrl.slice(0, resourceUrl.lastIndexOf("/")),
    resourceUrl,
    createRequestId: "b636157b-5c63-4278-b84e-89ad31b54c81",
    expectedParamsDigest: canonicalDigestSync({
      securityGatewayId: SPEC.gateway_id,
      requestId: "b636157b-5c63-4278-b84e-89ad31b54c81",
    }),
    expectedPayloadDigest: canonicalDigestSync({
      displayName: SPEC.gateway_id,
      serviceDiscovery: {},
      logging: {},
    }),
    ownershipMarker: null,
    providerIdentityField: "createTime",
    providerIdentity: "2026-08-24T00:00:01Z",
  } as const;

  async function runDestroy(
    page: (token: string | undefined, call: number) => Record<string, unknown>,
  ): Promise<{
    deletes: number;
    error: unknown;
    outcome: string | undefined;
    tokens: Array<string | undefined>;
  }> {
    let deletes = 0;
    let pageCalls = 0;
    const tokens: Array<string | undefined> = [];
    const transport: Transport = {
      async requestJson(method, url, options = {}) {
        if (method === "GET" && url === resourceUrl) {
          return {
            status: 200,
            payload: { createTime: "2026-08-24T00:00:01Z" },
          };
        }
        if (method === "GET" && url === `${resourceUrl}/applications`) {
          const token = typeof options.params?.pageToken === "string"
            ? options.params.pageToken
            : undefined;
          tokens.push(token);
          pageCalls += 1;
          return { status: 200, payload: page(token, pageCalls) };
        }
        if (method === "DELETE" && url === resourceUrl) {
          deletes += 1;
          return { status: 200, payload: {} };
        }
        return { status: 200, payload: {} };
      },
    };
    let outcome: string | undefined;
    let error: unknown;
    try {
      outcome = await new GoogleResourceExecutor(transport).destroy(
        target,
        SPEC,
        crypto.randomUUID(),
        checkpoint,
      );
    } catch (caught) {
      error = caught;
    }
    return { deletes, error, outcome, tokens };
  }

  const nonempty = await runDestroy((token) => token === undefined
    ? { applications: [], nextPageToken: "page-2" }
    : { applications: [{ name: `${applicationPrefix}remaining` }] });
  check(
    "Gateway teardown follows later pages and retains the first valid application",
    nonempty.outcome === "skipped" && nonempty.deletes === 0 &&
      JSON.stringify(nonempty.tokens) === JSON.stringify([undefined, "page-2"]),
    JSON.stringify(nonempty),
  );

  const empty = await runDestroy((token) => token === undefined
    ? { applications: [], nextPageToken: "page-2" }
    : {});
  check(
    "Gateway teardown deletes only after terminal empty pagination",
    empty.outcome === "deleted" && empty.deletes === 1 && empty.error === undefined,
    JSON.stringify(empty),
  );

  const malformed = await runDestroy(() => ({ applications: [{ name: "invalid" }] }));
  const unreachable = await runDestroy(() => ({
    applications: [],
    unreachable: ["global"],
  }));
  const repeated = await runDestroy(() => ({
    applications: [],
    nextPageToken: "same-token",
  }));
  const limited = await runDestroy((_token, call) => ({
    applications: [],
    nextPageToken: `page-${call + 1}`,
  }));
  check(
    "Gateway teardown retains malformed, unreachable, repeated-token, and over-limit pagination",
    (malformed.error as { code?: unknown })?.code ===
        "teardown-gateway-applications-invalid" && malformed.deletes === 0 &&
      (unreachable.error as { code?: unknown })?.code ===
        "teardown-gateway-applications-unreachable" && unreachable.deletes === 0 &&
      (repeated.error as { code?: unknown })?.code ===
        "teardown-gateway-applications-pagination-invalid" && repeated.deletes === 0 &&
      (limited.error as { code?: unknown })?.code ===
        "teardown-gateway-applications-pagination-limit-exceeded" && limited.deletes === 0 &&
      limited.tokens.length === 100,
    JSON.stringify({ malformed, unreachable, repeated, limited }),
  );
}

// A Compute Operation's `id` identifies the operation; `targetId` identifies
// the created object. If the exact post-operation GET is briefly 404, pin the
// canonical target id so later teardown can match the live resource.
{
  const target = change("compute", "network", "transient-network");
  const resourceUrl =
    "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/global/" +
    "networks/transient-network";
  let checkpoint: unknown;
  let resourceGets = 0;
  let deletes = 0;
  let live: Record<string, unknown> | null = null;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "POST") {
        live = { ...structuredClone(options.jsonBody ?? {}), id: "resource-id" };
        return {
          status: 200,
          payload: { status: "DONE", id: "operation-id", targetId: "resource-id" },
        };
      }
      if (method === "GET" && url === resourceUrl) {
        resourceGets += 1;
        return resourceGets === 1
          ? { status: 404, payload: {} }
          : { status: 200, payload: structuredClone(live ?? {}) };
      }
      if (method === "DELETE" && url === resourceUrl) {
        deletes += 1;
        live = null;
        return { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  const applied = await new GoogleResourceExecutor(transport).apply(target, SPEC, {
    runId: "run-compute-target-id",
    stepIndex: 0,
    requestId: crypto.randomUUID(),
    checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
  });
  const outcome = await new GoogleResourceExecutor(transport).destroy(
    target,
    SPEC,
    crypto.randomUUID(),
    applied.beforeImage ?? checkpoint,
  );
  check(
    "Compute operation fallback pins targetId and teardown matches the live resource id",
    (checkpoint as { providerIdentityField?: unknown }).providerIdentityField === "id" &&
      (checkpoint as { providerIdentity?: unknown }).providerIdentity === "resource-id" &&
      outcome === "deleted" && deletes === 1 && live === null,
    JSON.stringify({ checkpoint, outcome, deletes, resourceGets }),
  );
}

// Secret Manager IAM is a requestId-less shared RMW just like the main
// Gateway/Application IAM path. A lost SET response must stay ambiguous and
// rollback must not remove a coincidental administrator binding.
{
  const target = change("secretmanager", "secret_iam", "enterprise-tls");
  const original = {
    version: 3,
    etag: "before-etag",
    bindings: [{ role: "roles/viewer", members: ["user:owner@example.com"] }],
  };
  let checkpoint: unknown;
  let writes = 0;
  const transport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.endsWith(":getIamPolicy")) {
        return { status: 200, payload: structuredClone(original) };
      }
      if (method === "POST" && url.endsWith(":setIamPolicy")) {
        writes += 1;
        throw new Error("connection-reset-after-secret-iam-commit");
      }
      return { status: 200, payload: {} };
    },
  };
  let applyError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-secret-iam-ambiguous",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (error) {
    applyError = error;
  }
  let retryError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-secret-iam-ambiguous",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      beforeImage: checkpoint,
    });
  } catch (error) {
    retryError = error;
  }
  let rollbackError: unknown;
  try {
    await new GoogleResourceExecutor(transport).rollback(target, SPEC, {
      runId: "run-secret-iam-ambiguous",
      stepIndex: 0,
      requestId: crypto.randomUUID(),
      beforeImage: checkpoint,
    });
  } catch (error) {
    rollbackError = error;
  }
  check(
    "Secret IAM response loss retains a sending claim and never retries or compensates",
    applyError instanceof Error &&
      (retryError as { code?: unknown }).code === "secret-iam-mutation-outcome-ambiguous" &&
      (rollbackError as { code?: unknown }).code === "iam-rollback-outcome-ambiguous" &&
      (checkpoint as { phase?: unknown }).phase === "sending" && writes === 1,
    JSON.stringify({ applyError: String(applyError), retryError: String(retryError), rollbackError: String(rollbackError), checkpoint, writes }),
  );
}

// BeyondCorp resources have no provider ownership marker. The stable requestId
// is therefore the ownership proof: after a response loss, restart must replay
// the exact POST/body/requestId and may mark the checkpoint applied only after
// an authoritative resource GET returns the same semantic body and identity.
for (const resourceType of ["security_gateway", "application"] as const) {
  const resourceName = resourceType === "security_gateway"
    ? SPEC.gateway_id
    : `${SPEC.name}-app`;
  const target = change("beyondcorp", resourceType, resourceName);
  const gatewayUrl =
    "https://beyondcorp.googleapis.com/v1/projects/enterprise-secgw-01/locations/global/" +
    `securityGateways/${SPEC.gateway_id}`;
  const createUrl = resourceType === "security_gateway"
    ? gatewayUrl.slice(0, gatewayUrl.lastIndexOf("/"))
    : `${gatewayUrl}/applications`;
  const resourceUrl = resourceType === "security_gateway"
    ? gatewayUrl
    : `${createUrl}/${resourceName}`;
  const stableRequestId = resourceType === "security_gateway"
    ? "041b1918-813a-47ae-aaca-5769a3143624"
    : "e9426ff4-28e2-47b4-a6cc-20d26e36d6b3";
  let checkpoint: unknown;
  let live: Record<string, unknown> | null = null;
  const sends: Array<{
    body: Record<string, unknown> | undefined;
    params: Record<string, string | number> | undefined;
  }> = [];
  let deletes = 0;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "POST" && url === createUrl) {
        sends.push({
          body: structuredClone(options.jsonBody),
          params: structuredClone(options.params),
        });
        live = {
          ...structuredClone(options.jsonBody ?? {}),
          name: resourceUrl.replace("https://beyondcorp.googleapis.com/v1/", ""),
          createTime: "2026-08-24T00:00:01Z",
          ...(resourceType === "security_gateway"
            ? {
              state: "RUNNING",
              delegatingServiceAccount: "gateway-sa@example.iam.gserviceaccount.com",
              externalIps: ["203.0.113.10", "2001:db8::1"],
            }
            : {}),
        };
        if (sends.length === 1) {
          throw new Error("connection-reset-after-beyondcorp-commit");
        }
        return { status: 200, payload: structuredClone(live) };
      }
      if (method === "GET" && url === resourceUrl) {
        return live === null
          ? { status: 404, payload: {} }
          : { status: 200, payload: structuredClone(live) };
      }
      if (method === "GET" && url === `${gatewayUrl}/applications`) {
        return { status: 200, payload: { applications: [] } };
      }
      if (method === "DELETE" && url === resourceUrl) {
        deletes += 1;
        live = null;
        return { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  let firstError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: `run-beyondcorp-replay-${resourceType}`,
      stepIndex: 0,
      requestId: stableRequestId,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (error) {
    firstError = error;
  }
  let retryError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: `run-beyondcorp-replay-${resourceType}`,
      stepIndex: 0,
      requestId: stableRequestId,
      beforeImage: checkpoint,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    });
  } catch (error) {
    retryError = error;
  }
  const appliedLive: Record<string, unknown> = structuredClone(live ?? {});
  const drifts: Record<string, unknown>[] = [];
  if (resourceType === "security_gateway") {
    const missingState = structuredClone(appliedLive);
    delete missingState.state;
    drifts.push(
      { ...appliedLive, serviceDiscovery: { apiGateway: {} } },
      { ...appliedLive, state: "ERROR" },
      missingState,
      { ...appliedLive, delegatingServiceAccount: "   " },
      { ...appliedLive, externalIps: ["999.1.1.1"] },
      { ...appliedLive, externalIps: ["203.0.113.10", "203.0.113.10"] },
      { ...appliedLive, proxyProtocolConfig: {} },
      { ...appliedLive, hubs: [] },
      { ...appliedLive, uid: "undocumented-identity" },
    );
  } else {
    const upstreams = structuredClone(appliedLive.upstreams) as Array<Record<string, unknown>>;
    upstreams[0] = { ...upstreams[0], proxyProtocol: {} };
    drifts.push(
      { ...appliedLive, upstreams },
      { ...appliedLive, state: "RUNNING" },
      {
        ...appliedLive,
        delegatingServiceAccount: "gateway-sa@example.iam.gserviceaccount.com",
      },
      { ...appliedLive, externalIps: ["203.0.113.10"] },
    );
  }
  const driftErrors: unknown[] = [];
  for (const drift of drifts) {
    live = drift;
    try {
      await new GoogleResourceExecutor(transport).apply(target, SPEC, {
        runId: `run-beyondcorp-replay-${resourceType}`,
        stepIndex: 0,
        requestId: stableRequestId,
        beforeImage: checkpoint,
      });
    } catch (error) {
      driftErrors.push(error);
    }
  }
  live = appliedLive;
  let teardown: unknown;
  try {
    teardown = await new GoogleResourceExecutor(transport).destroy(
      target,
      SPEC,
      crypto.randomUUID(),
      checkpoint,
    );
  } catch (error) {
    teardown = error;
  }
  check(
    `BeyondCorp ${resourceType} response loss replays exact stable request and tears down by identity`,
    firstError instanceof Error && retryError === undefined && sends.length === 2 &&
      JSON.stringify(sends[0]) === JSON.stringify(sends[1]) &&
      sends.every((send) => send.params?.requestId === stableRequestId) &&
      driftErrors.length === drifts.length && driftErrors.every((error) =>
        (error as { code?: unknown })?.code === "generic-resource-managed-state-changed"
      ) &&
      (checkpoint as { phase?: unknown }).phase === "applied" &&
      (checkpoint as { createRequestId?: unknown }).createRequestId === stableRequestId &&
      (checkpoint as { providerIdentity?: unknown }).providerIdentity ===
        "2026-08-24T00:00:01Z" &&
      teardown === "deleted" && deletes === 1 && live === null,
    JSON.stringify({
      firstError: String(firstError), retryError: String(retryError),
      driftErrors: driftErrors.map(String), sends,
      checkpoint, teardown: String(teardown), deletes,
    }),
  );
}

// Operation polling is bearer-authenticated. Bind selfLinks to the mutation's
// exact Compute project/scope family, and accept only the documented legacy
// www.googleapis.com Compute selfLink after canonical normalization.
{
  const requestId = "067d5792-f82b-4598-bcf0-c793342b3748";
  const resourceUrl =
    "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/global/" +
    "networks/operation-network";
  const validOperation =
    "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/global/" +
    "operations/op-valid";
  const polls: string[] = [];
  const validTransport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "POST") {
        return { status: 200, payload: { status: "PENDING", selfLink: validOperation } };
      }
      if (url.includes("/operations/")) {
        polls.push(url);
        return { status: 200, payload: { status: "DONE" } };
      }
      return {
        status: 200,
        payload: {
          id: "operation-id",
          description: options.jsonBody?.description ??
            `Secure Gateway Studio ownership-token=${requestId}; Managed by Secure Gateway Studio`,
        },
      };
    },
  };
  await new GoogleResourceExecutor(validTransport, {
    operationPollIntervalMs: 0,
  }).apply(change("compute", "network", "operation-network"), SPEC, {
    runId: "run-operation-url",
    stepIndex: 0,
    requestId,
  });
  check(
    "legacy Compute operation selfLink is normalized inside the exact project and scope",
    polls.length === 1 && polls[0] === validOperation.replace(
      "https://www.googleapis.com/compute/",
      "https://compute.googleapis.com/compute/",
    ),
    JSON.stringify(polls),
  );

  const invalidOperations = [
    "https://compute.googleapis.com/compute/v1/projects/foreign/global/operations/op",
    "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/regions/asia-east1/operations/op",
    "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/global/operations/op?alt=json",
    "https://user@compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/global/operations/op",
    "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/global/../operations/op",
  ];
  let rejected = 0;
  for (const selfLink of invalidOperations) {
    const transport: Transport = {
      async requestJson(method) {
        return method === "POST"
          ? { status: 200, payload: { status: "PENDING", selfLink } }
          : { status: 200, payload: { status: "DONE" } };
      },
    };
    try {
      await new GoogleResourceExecutor(transport, {
        operationPollIntervalMs: 0,
      }).apply(change("compute", "network", "operation-network"), SPEC, {
        runId: "run-invalid-operation-url",
        stepIndex: 0,
        requestId: crypto.randomUUID(),
      });
    } catch (error) {
      if ((error as { code?: unknown }).code === "provider-operation-poll-url-invalid") {
        rejected += 1;
      }
    }
  }
  check(
    "operation polling rejects cross-project, cross-scope, query, userinfo, and traversal URLs",
    rejected === invalidOperations.length,
    `${rejected}/${invalidOperations.length}`,
  );

  let operationPolls = 0;
  let missingIdentityError: unknown;
  try {
    await new GoogleResourceExecutor({
      async requestJson(method, url) {
        if (method === "POST") {
          return { status: 200, payload: { status: "PENDING" } };
        }
        if (url.includes("/operations/")) operationPolls += 1;
        return { status: 200, payload: { status: "DONE" } };
      },
    }, { operationPollIntervalMs: 0 }).apply(
      change("compute", "network", "operation-network"),
      SPEC,
      {
        runId: "run-operation-missing-name",
        stepIndex: 0,
        requestId: crypto.randomUUID(),
      },
    );
  } catch (error) {
    missingIdentityError = error;
  }
  check(
    "an unfinished status-only operation fails closed before dependent provider reads",
    (missingIdentityError as { code?: unknown })?.code ===
        "provider-operation-missing-name" && operationPolls === 0,
    JSON.stringify({ missingIdentityError: String(missingIdentityError), operationPolls }),
  );
}

// Cloud DNS Changes are their own asynchronous resource, not Google Long
// Running Operations. Both create and teardown must poll the exact change id
// returned by the same managed-zone collection.
{
  const requestId = "43f4a28e-8c2a-4cea-99d9-3752426ba48a";
  const fqdn = `${SPEC.private_hostname}.`;
  const markerName = `_sgs-owner.${fqdn}`;
  const marker = `"sgs-owner=${requestId}"`;
  const zone =
    `https://dns.googleapis.com/dns/v1/projects/${SPEC.project_id}/managedZones/` +
    `${SPEC.name}-zone`;
  const changePolls: string[] = [];
  let beforeImage: unknown;
  let changeSequence = 40;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(`/${SPEC.name}-offload-ip`)) {
        return { status: 200, payload: { address: "10.42.0.10" } };
      }
      if (method === "GET" && url.includes("/rrsets/")) {
        if (url.endsWith("/A")) {
          return {
            status: 200,
            payload: { name: fqdn, type: "A", ttl: 60, rrdatas: ["10.42.0.10"] },
          };
        }
        return {
          status: 200,
          payload: { name: markerName, type: "TXT", ttl: 60, rrdatas: [marker] },
        };
      }
      if (method === "POST" && url === `${zone}/changes`) {
        changeSequence += 1;
        return {
          status: 200,
          payload: { kind: "dns#change", id: String(changeSequence), status: "pending" },
        };
      }
      if (method === "GET" && url.startsWith(`${zone}/changes/`)) {
        changePolls.push(url);
        return {
          status: 200,
          payload: {
            kind: "dns#change",
            id: url.split("/").at(-1) as string,
            status: "done",
          },
        };
      }
      throw new Error(`unexpected DNS request ${method} ${url} ${JSON.stringify(options)}`);
    },
  };
  const recordChange = change("dns", "record_set", SPEC.private_hostname);
  await new GoogleResourceExecutor(transport, {
    operationPollIntervalMs: 0,
  }).apply(recordChange, SPEC, {
    runId: "run-dns-change",
    stepIndex: 0,
    requestId,
    checkpointBeforeImage: async (value) => {
      beforeImage = structuredClone(value);
    },
  });
  await new GoogleResourceExecutor(transport, {
    operationPollIntervalMs: 0,
  }).destroy(recordChange, SPEC, requestId, beforeImage);
  check(
    "DNS record create and teardown poll exact real-shaped Change resources",
    changePolls.length === 2 &&
      changePolls[0] === `${zone}/changes/41` &&
      changePolls[1] === `${zone}/changes/42`,
    JSON.stringify(changePolls),
  );
}

// Certificate rotation is an explicit planned mutation. PoC refresh stops and
// starts the existing offload VM. Compute requires a unique requestId for each
// request, while each phase still needs a stable token across worker retries.
{
  const calls: Array<{ method: string; url: string; requestId?: unknown }> = [];
  let instanceStatus = "RUNNING";
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      calls.push({ method, url, requestId: options.params?.requestId });
      if (method === "GET" && url.endsWith(`/${SPEC.name}-offload`)) {
        return { status: 200, payload: { status: instanceStatus } };
      }
      if (method === "POST" && url.endsWith("/stop")) instanceStatus = "TERMINATED";
      if (method === "POST" && url.endsWith("/start")) instanceStatus = "RUNNING";
      return { status: 200, payload: {} };
    },
  };
  const requestId = "d36ac6fb-431c-441a-ae78-3736e425ee25";
  let error: unknown;
  try {
    const executor = new GoogleResourceExecutor(transport);
    await executor.apply(
      change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
      SPEC,
      { runId: "run-refresh", stepIndex: 0, requestId },
    );
    await executor.apply(
      change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
      SPEC,
      { runId: "run-refresh", stepIndex: 0, requestId },
    );
  } catch (caught) {
    error = caught;
  }
  const mutations = calls.filter((call) => call.method === "POST");
  const uuidPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  check(
    "PoC certificate rotation refreshes the existing offload VM idempotently",
    error === undefined && mutations.length === 4 &&
      mutations[0]?.url.endsWith(`/${SPEC.name}-offload/stop`) === true &&
      mutations[1]?.url.endsWith(`/${SPEC.name}-offload/start`) === true &&
      mutations[0]?.requestId !== mutations[1]?.requestId &&
      mutations[0]?.requestId === mutations[2]?.requestId &&
      mutations[1]?.requestId === mutations[3]?.requestId &&
      mutations.every(
        (call) => typeof call.requestId === "string" && uuidPattern.test(call.requestId),
      ),
    `${String(error)}; ${JSON.stringify(mutations)}`,
  );
}

// If the stop response and the immediate reconciliation GET are both lost,
// the durable stop_sending checkpoint lets a fresh worker observe TERMINATED
// and start the VM without issuing stop a second time.
{
  let instanceStatus = "RUNNING";
  let loseStopReconcile = false;
  let checkpoint: unknown;
  const phases: unknown[] = [];
  const mutations: Array<{ url: string; requestId?: unknown }> = [];
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(`/${SPEC.name}-offload`)) {
        if (loseStopReconcile) {
          loseStopReconcile = false;
          throw new Error("instance GET response lost");
        }
        return { status: 200, payload: { status: instanceStatus } };
      }
      if (method === "POST") {
        mutations.push({ url, requestId: options.params?.requestId });
      }
      if (method === "POST" && url.endsWith("/stop")) {
        instanceStatus = "TERMINATED";
        loseStopReconcile = true;
        throw new Error("stop response lost");
      }
      if (method === "POST" && url.endsWith("/start")) {
        instanceStatus = "RUNNING";
      }
      return { status: 200, payload: {} };
    },
  };
  const requestId = "59b97eef-2c52-4a56-8b42-ac25f70fa1c2";
  let firstError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(
      change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
      SPEC,
      {
        runId: "run-refresh-stop-loss",
        stepIndex: 0,
        requestId,
        checkpointBeforeImage: async (value) => {
          checkpoint = structuredClone(value);
          phases.push((value as { phase?: unknown }).phase);
        },
      },
    );
  } catch (error) {
    firstError = error;
  }
  await new GoogleResourceExecutor(transport).apply(
    change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
    SPEC,
    {
      runId: "run-refresh-stop-loss",
      stepIndex: 0,
      requestId,
      beforeImage: checkpoint,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
        phases.push((value as { phase?: unknown }).phase);
      },
    },
  );
  check(
    "PoC refresh resumes a response-lost stop from TERMINATED without re-stopping",
    firstError instanceof Error && instanceStatus === "RUNNING" &&
      mutations.filter((call) => call.url.endsWith("/stop")).length === 1 &&
      mutations.filter((call) => call.url.endsWith("/start")).length === 1 &&
      phases.join(",") === "prepared,stop_sending,stopped,start_sending,applied" &&
      (checkpoint as { phase?: unknown })?.phase === "applied",
    `${String(firstError)}; ${instanceStatus}; ${JSON.stringify({ phases, mutations })}`,
  );
}

// Once stop has completed, a definite start rejection leaves start_sending
// durable. Retrying from TERMINATED reuses only the start requestId.
{
  let instanceStatus = "RUNNING";
  let rejectFirstStart = true;
  let checkpoint: unknown;
  const mutations: Array<{ url: string; requestId?: unknown }> = [];
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(`/${SPEC.name}-offload`)) {
        return { status: 200, payload: { status: instanceStatus } };
      }
      if (method === "POST") {
        mutations.push({ url, requestId: options.params?.requestId });
      }
      if (method === "POST" && url.endsWith("/stop")) {
        instanceStatus = "TERMINATED";
        return { status: 200, payload: {} };
      }
      if (method === "POST" && url.endsWith("/start")) {
        if (rejectFirstStart) {
          rejectFirstStart = false;
          return {
            status: 400,
            payload: { error: { status: "INVALID_ARGUMENT" } },
          };
        }
        instanceStatus = "RUNNING";
      }
      return { status: 200, payload: {} };
    },
  };
  const requestId = "c061f203-e6d7-4508-805b-cc0588fd14b7";
  let firstError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(
      change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
      SPEC,
      {
        runId: "run-refresh-start-reject",
        stepIndex: 0,
        requestId,
        checkpointBeforeImage: async (value) => {
          checkpoint = structuredClone(value);
        },
      },
    );
  } catch (error) {
    firstError = error;
  }
  const stoppedCheckpoint = structuredClone(checkpoint);
  await new GoogleResourceExecutor(transport).apply(
    change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
    SPEC,
    {
      runId: "run-refresh-start-reject",
      stepIndex: 0,
      requestId,
      beforeImage: checkpoint,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
      },
    },
  );
  const stops = mutations.filter((call) => call.url.endsWith("/stop"));
  const starts = mutations.filter((call) => call.url.endsWith("/start"));
  check(
    "PoC refresh retries a definitely rejected start without repeating stop",
    firstError instanceof Error &&
      (firstError as { code?: unknown }).code ===
        "google-api-400-compute-invalid-argument" &&
      (stoppedCheckpoint as { phase?: unknown })?.phase === "start_sending" &&
      instanceStatus === "RUNNING" && stops.length === 1 && starts.length === 2 &&
      starts[0]?.requestId === starts[1]?.requestId &&
      starts[0]?.requestId !== stops[0]?.requestId,
    `${String(firstError)}; ${JSON.stringify({ checkpoint, mutations })}`,
  );
}

// A lost start response is reconciled from RUNNING before Apply reports an
// error, and rollback of a partial stopped checkpoint actively restores RUNNING.
{
  const requestId = "1cc11f82-3b50-4c60-950c-1dc947ff5dc7";
  let instanceStatus = "RUNNING";
  let loseStartResponse = true;
  let checkpoint: unknown;
  const mutations: string[] = [];
  const transport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.endsWith(`/${SPEC.name}-offload`)) {
        return { status: 200, payload: { status: instanceStatus } };
      }
      if (method === "POST") mutations.push(url);
      if (method === "POST" && url.endsWith("/stop")) {
        instanceStatus = "TERMINATED";
      }
      if (method === "POST" && url.endsWith("/start")) {
        instanceStatus = "RUNNING";
        if (loseStartResponse) {
          loseStartResponse = false;
          throw new Error("start response lost");
        }
      }
      return { status: 200, payload: {} };
    },
  };
  let error: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(
      change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
      SPEC,
      {
        runId: "run-refresh-start-loss",
        stepIndex: 0,
        requestId,
        checkpointBeforeImage: async (value) => {
          checkpoint = structuredClone(value);
        },
      },
    );
  } catch (caught) {
    error = caught;
  }
  check(
    "PoC refresh reconciles a response-lost start as applied",
    error === undefined && instanceStatus === "RUNNING" &&
      (checkpoint as { phase?: unknown })?.phase === "applied" &&
      mutations.filter((url) => url.endsWith("/stop")).length === 1 &&
      mutations.filter((url) => url.endsWith("/start")).length === 1,
    `${String(error)}; ${JSON.stringify({ checkpoint, mutations })}`,
  );

  instanceStatus = "TERMINATED";
  const partialCheckpoint = {
    ...(checkpoint as Record<string, unknown>),
    phase: "start_sending",
  };
  await new GoogleResourceExecutor(transport).rollback(
    change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
    SPEC,
    {
      runId: "run-refresh-rollback",
      stepIndex: 0,
      requestId,
      beforeImage: partialCheckpoint,
    },
  );
  check(
    "PoC refresh rollback restores a partially stopped VM to RUNNING",
    instanceStatus === "RUNNING" &&
      mutations.filter((url) => url.endsWith("/stop")).length === 1 &&
      mutations.filter((url) => url.endsWith("/start")).length === 2,
    JSON.stringify({ checkpoint: partialCheckpoint, mutations }),
  );
}

// Status reconciliation can legitimately skip a send phase: TERMINATED proves
// stop completed, while RUNNING after stopped proves start completed. Both +2
// transitions must themselves reach the durable checkpoint callback.
{
  const requestId = "680fd88c-e68e-44ad-a844-bd87b37e849f";
  let instanceStatus = "RUNNING";
  let failFirstGet = true;
  let checkpoint: unknown;
  const reconciledPhases: unknown[] = [];
  const transport: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.endsWith(`/${SPEC.name}-offload`)) {
        if (failFirstGet) {
          failFirstGet = false;
          throw new Error("worker stopped before initial status read");
        }
        return { status: 200, payload: { status: instanceStatus } };
      }
      if (method === "POST" && url.endsWith("/start")) instanceStatus = "RUNNING";
      return { status: 200, payload: {} };
    },
  };
  try {
    await new GoogleResourceExecutor(transport).apply(
      change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
      SPEC,
      {
        runId: "run-refresh-skip-transitions",
        stepIndex: 0,
        requestId,
        checkpointBeforeImage: async (value) => {
          checkpoint = structuredClone(value);
        },
      },
    );
  } catch {
    // The durable prepared checkpoint is the state a fresh worker receives.
  }
  instanceStatus = "TERMINATED";
  await new GoogleResourceExecutor(transport).apply(
    change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
    SPEC,
    {
      runId: "run-refresh-skip-transitions",
      stepIndex: 0,
      requestId,
      beforeImage: checkpoint,
      checkpointBeforeImage: async (value) => {
        checkpoint = structuredClone(value);
        reconciledPhases.push((value as { phase?: unknown }).phase);
      },
    },
  );
  const stoppedCheckpoint = {
    ...(checkpoint as Record<string, unknown>),
    phase: "stopped",
  };
  const stoppedReconciliation: unknown[] = [];
  await new GoogleResourceExecutor(transport).apply(
    change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
    SPEC,
    {
      runId: "run-refresh-stopped-reconciliation",
      stepIndex: 0,
      requestId,
      beforeImage: stoppedCheckpoint,
      checkpointBeforeImage: async (value) => {
        stoppedReconciliation.push((value as { phase?: unknown }).phase);
      },
    },
  );
  check(
    "PoC refresh persists prepared-to-stopped and stopped-to-applied reconciliation",
    reconciledPhases[0] === "stopped" &&
      reconciledPhases.includes("applied") &&
      stoppedReconciliation.join(",") === "applied",
    JSON.stringify({ reconciledPhases, stoppedReconciliation }),
  );
}

// Rollback must not accept the stale pre-stop RUNNING state after a response
// loss. It replays the exact stop requestId, observes the confirmed boundary,
// and then starts the VM before releasing the durable claim.
{
  const target = change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`);
  const requestId = "67aecf38-9322-4d7c-918b-c7691e1482db";
  let checkpoint: unknown;
  let status = "RUNNING";
  let stopCalls = 0;
  let startCalls = 0;
  const stopIds: unknown[] = [];
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      if (method === "GET" && url.endsWith(`/${SPEC.name}-offload`)) {
        return { status: 200, payload: { status } };
      }
      if (method === "POST" && url.endsWith("/stop")) {
        stopCalls += 1;
        stopIds.push(options.params?.requestId);
        if (stopCalls === 1) {
          // The provider may still expose the pre-stop status immediately
          // after losing the response.
          throw new Error("stop response lost before status propagation");
        }
        status = "TERMINATED";
        return { status: 200, payload: {} };
      }
      if (method === "POST" && url.endsWith("/start")) {
        startCalls += 1;
        status = "RUNNING";
        return { status: 200, payload: {} };
      }
      return { status: 200, payload: {} };
    },
  };
  let applyError: unknown;
  try {
    await new GoogleResourceExecutor(transport).apply(target, SPEC, {
      runId: "run-refresh-stale-running",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
    });
  } catch (caught) {
    applyError = caught;
  }
  await new GoogleResourceExecutor(transport).rollback(target, SPEC, {
    runId: "run-refresh-stale-running",
    stepIndex: 0,
    requestId,
    beforeImage: checkpoint,
  });
  check(
    "offload rollback never accepts stale RUNNING after an ambiguous stop",
    applyError instanceof Error &&
      (checkpoint as { phase?: unknown }).phase === "stop_sending" &&
      stopCalls === 2 && startCalls === 1 && status === "RUNNING" &&
      stopIds[0] === stopIds[1],
    JSON.stringify({ applyError: String(applyError), checkpoint, stopCalls, startCalls, status, stopIds }),
  );
}

{
  let refreshBody: Record<string, unknown> | undefined;
  let refreshParams: Record<string, string | number | boolean> | undefined;
  let operationPolls = 0;
  let operationDone = false;
  let healthReadBeforeOperationDone = false;
  const operationUrl =
    `https://compute.googleapis.com/compute/v1/projects/${SPEC.project_id}/` +
    `regions/${SPEC.region}/operations/sgs-refresh-operation`;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      const managedProof = productionManagedInstanceResponse(method, url);
      if (managedProof !== null) return managedProof;
      if (method === "POST" && url.endsWith("/applyUpdatesToInstances")) {
        refreshBody = options.jsonBody;
        refreshParams = options.params;
        return {
          status: 200,
          payload: {
            name: "sgs-refresh-operation",
            selfLink: operationUrl,
            status: "PENDING",
          },
        };
      }
      if (method === "GET" && url === operationUrl) {
        operationPolls += 1;
        operationDone = operationPolls >= 2;
        return {
          status: 200,
          payload: {
            name: "sgs-refresh-operation",
            selfLink: operationUrl,
            status: operationDone ? "DONE" : "RUNNING",
          },
        };
      }
      if (method === "GET" && url.includes("instanceGroupManagers")) {
        if (!operationDone) healthReadBeforeOperationDone = true;
        return {
          status: 200,
          payload: {
            status: {
              isStable: true,
              currentInstanceStatuses: { running: SPEC.offload_min_replicas },
            },
          },
        };
      }
      if (method === "POST" && url.endsWith("/getHealth")) {
        if (!operationDone) healthReadBeforeOperationDone = true;
        return {
          status: 200,
          payload: {
            healthStatus: Array.from(
              { length: SPEC.offload_min_replicas },
              () => ({ healthState: "HEALTHY" }),
            ),
          },
        };
      }
      return { status: 200, payload: {} };
    },
  };
  const requestId = "4da0ec65-0b5a-4d74-8c6d-03f134ff975a";
  await new GoogleResourceExecutor(transport, {
    sourceImageBinding: PRODUCTION_REFRESH_BINDING,
    operationPollIntervalMs: 0,
  }).apply(
    change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
    PRODUCTION_REFRESH_SPEC,
    { runId: "run-production-refresh", stepIndex: 0, requestId },
  );
  check(
    "production certificate rotation restarts and verifies the managed group",
    (refreshParams === undefined || Object.keys(refreshParams).length === 0) &&
      refreshBody?.allInstances === true &&
      refreshBody.minimalAction === "RESTART" &&
      refreshBody.mostDisruptiveAllowedAction === "RESTART" &&
      operationPolls === 2 && operationDone && !healthReadBeforeOperationDone,
    JSON.stringify({ refreshBody, operationPolls, operationDone, healthReadBeforeOperationDone }),
  );
}

{
  const requestId = "ccce2500-1908-4bed-9fcb-88faf4e797f5";
  let refreshPosts = 0;
  const refreshRequestIds: unknown[] = [];
  let operationPolls = 0;
  const operationUrl =
    `https://compute.googleapis.com/compute/v1/projects/${SPEC.project_id}/` +
    `regions/${SPEC.region}/operations/sgs-refresh-lost-operation`;
  let checkpoint: unknown;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      const managedProof = productionManagedInstanceResponse(method, url);
      if (managedProof !== null) return managedProof;
      if (method === "POST" && url.endsWith("/applyUpdatesToInstances")) {
        refreshPosts += 1;
        refreshRequestIds.push(options.params?.requestId);
        return {
          status: 200,
          payload: {
            name: "sgs-refresh-lost-operation",
            selfLink: operationUrl,
            status: "PENDING",
          },
        };
      }
      if (method === "GET" && url === operationUrl) {
        operationPolls += 1;
        throw new Error("operation poll response lost after request send");
      }
      if (method === "GET" && url.includes("instanceGroupManagers")) {
        return {
          status: 200,
          payload: {
            status: {
              isStable: true,
              currentInstanceStatuses: { running: SPEC.offload_min_replicas },
            },
          },
        };
      }
      if (method === "POST" && url.endsWith("/getHealth")) {
        return {
          status: 200,
          payload: {
            healthStatus: Array.from(
              { length: SPEC.offload_min_replicas },
              () => ({ healthState: "HEALTHY" }),
            ),
          },
        };
      }
      return { status: 200, payload: {} };
    },
  };
  let firstError: unknown;
  try {
    await new GoogleResourceExecutor(transport, {
      sourceImageBinding: PRODUCTION_REFRESH_BINDING,
      operationPollIntervalMs: 0,
    }).apply(
      change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
      PRODUCTION_REFRESH_SPEC,
      {
        runId: "run-production-refresh-response-loss",
        stepIndex: 0,
        requestId,
        checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
      },
    );
  } catch (error) {
    firstError = error;
  }
  const phaseAfterLoss = (checkpoint as { phase?: unknown } | undefined)?.phase;
  let resumeError: unknown;
  try {
    await new GoogleResourceExecutor(transport, {
      sourceImageBinding: PRODUCTION_REFRESH_BINDING,
      operationPollIntervalMs: 0,
    }).apply(
      change("compute", "offload_refresh", `${SPEC.name}-certificate-refresh`),
      PRODUCTION_REFRESH_SPEC,
      {
        runId: "run-production-refresh-response-loss",
        stepIndex: 0,
        requestId,
        beforeImage: checkpoint,
        checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
      },
    );
  } catch (error) {
    resumeError = error;
  }
  check(
    "production refresh retains an ambiguous response-loss claim without replay",
    firstError !== undefined && resumeError instanceof Error &&
      resumeError.message.includes("offload-refresh-restart-outcome-ambiguous") &&
      phaseAfterLoss === "stop_sending" && refreshPosts === 1 &&
      operationPolls === 1 &&
      refreshRequestIds.every((value) => value === undefined) &&
      (checkpoint as { phase?: unknown } | undefined)?.phase === "stop_sending",
    JSON.stringify({
      firstError: String(firstError),
      resumeError: String(resumeError),
      phaseAfterLoss,
      refreshPosts,
      operationPolls,
      checkpoint,
    }),
  );
}

{
  let refreshPosts = 0;
  let operationPolls = 0;
  let healthReads = 0;
  let checkpoint: unknown;
  const operationUrl =
    `https://compute.googleapis.com/compute/v1/projects/${SPEC.project_id}/` +
    `regions/${SPEC.region}/operations/sgs-refresh-failed-operation`;
  const transport: Transport = {
    async requestJson(method, url) {
      const managedProof = productionManagedInstanceResponse(method, url);
      if (managedProof !== null) return managedProof;
      if (method === "POST" && url.endsWith("/applyUpdatesToInstances")) {
        refreshPosts += 1;
        return {
          status: 200,
          payload: {
            name: "sgs-refresh-failed-operation",
            selfLink: operationUrl,
            status: "PENDING",
          },
        };
      }
      if (method === "GET" && url === operationUrl) {
        operationPolls += 1;
        return {
          status: 200,
          payload: {
            name: "sgs-refresh-failed-operation",
            selfLink: operationUrl,
            status: "DONE",
            error: { errors: [{ code: "INVALID_USAGE", message: "restart rejected" }] },
          },
        };
      }
      if (
        (method === "GET" && url.includes("instanceGroupManagers")) ||
        (method === "POST" && url.endsWith("/getHealth"))
      ) healthReads += 1;
      return { status: 200, payload: {} };
    },
  };
  const target = change(
    "compute",
    "offload_refresh",
    `${SPEC.name}-certificate-refresh`,
  );
  const requestId = "7050e207-c6df-448c-9a08-bfef5f65bb34";
  const executor = new GoogleResourceExecutor(transport, {
    sourceImageBinding: PRODUCTION_REFRESH_BINDING,
    operationPollIntervalMs: 0,
  });
  let operationError: unknown;
  try {
    await executor.apply(target, PRODUCTION_REFRESH_SPEC, {
      runId: "run-production-refresh-operation-error",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
    });
  } catch (error) {
    operationError = error;
  }
  let resumeError: unknown;
  try {
    await executor.apply(target, PRODUCTION_REFRESH_SPEC, {
      runId: "run-production-refresh-operation-error",
      stepIndex: 0,
      requestId,
      beforeImage: checkpoint,
      checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
    });
  } catch (error) {
    resumeError = error;
  }
  check(
    "production refresh rejects a terminal operation error without old-health success or replay",
    operationError instanceof Error &&
      operationError.message === "provider-operation-failed" &&
      resumeError instanceof Error &&
      resumeError.message.includes("offload-refresh-restart-outcome-ambiguous") &&
      (checkpoint as { phase?: unknown } | undefined)?.phase === "stop_sending" &&
      refreshPosts === 1 && operationPolls === 1 && healthReads === 0,
    JSON.stringify({
      operationError: String(operationError),
      resumeError: String(resumeError),
      checkpoint,
      refreshPosts,
      operationPolls,
      healthReads,
    }),
  );
}

{
  let refreshPosts = 0;
  let checkpoint: unknown;
  const transport: Transport = {
    async requestJson(method, url, options = {}) {
      const managedProof = productionManagedInstanceResponse(method, url);
      if (managedProof !== null) return managedProof;
      if (method === "POST" && url.endsWith("/applyUpdatesToInstances")) {
        refreshPosts += 1;
        if (options.params !== undefined && Object.keys(options.params).length > 0) {
          throw new Error("unsupported applyUpdatesToInstances query parameter");
        }
        throw new GoogleApiError({
          status: 400,
          method,
          url,
          payload: { error: { message: "definite request rejection" } },
        });
      }
      if (method === "GET" && url.includes("instanceGroupManagers")) {
        return {
          status: 200,
          payload: {
            status: {
              isStable: true,
              currentInstanceStatuses: { running: SPEC.offload_min_replicas },
            },
          },
        };
      }
      if (method === "POST" && url.endsWith("/getHealth")) {
        return {
          status: 200,
          payload: {
            healthStatus: Array.from(
              { length: SPEC.offload_min_replicas },
              () => ({ healthState: "HEALTHY" }),
            ),
          },
        };
      }
      return { status: 200, payload: {} };
    },
  };
  const requestId = "c049817e-6416-4f2c-823e-a1cb5fc03057";
  const executor = new GoogleResourceExecutor(transport, {
    sourceImageBinding: PRODUCTION_REFRESH_BINDING,
  });
  const target = change(
    "compute",
    "offload_refresh",
    `${SPEC.name}-certificate-refresh`,
  );
  let rejection: unknown;
  try {
    await executor.apply(target, PRODUCTION_REFRESH_SPEC, {
      runId: "run-production-refresh-rejected",
      stepIndex: 0,
      requestId,
      checkpointBeforeImage: async (value) => { checkpoint = structuredClone(value); },
    });
  } catch (error) {
    rejection = error;
  }
  let rollbackError: unknown;
  try {
    await executor.rollback(target, PRODUCTION_REFRESH_SPEC, {
      runId: "run-production-refresh-rejected",
      stepIndex: 0,
      requestId,
      beforeImage: checkpoint,
    });
  } catch (error) {
    rollbackError = error;
  }
  check(
    "production refresh records a definite rejection before safe rollback",
    rejection instanceof Error && rejection.message === "google-api-400-compute" &&
      (checkpoint as { phase?: unknown } | undefined)?.phase === "restart_rejected" &&
      refreshPosts === 1 && rollbackError === undefined,
    JSON.stringify({ rejection: String(rejection), checkpoint, refreshPosts, rollbackError }),
  );
}

// A stale/root OU selection is re-attested immediately before each Chrome
// Policy mutation, so an approved plan can never widen to the whole domain.
{
  let policyMutations = 0;
  const workspace: Transport = {
    async requestJson(method, url) {
      if (method === "GET" && url.includes("/orgunits/id%3A")) {
        return {
          status: 200,
          payload: { orgUnitId: `id:${SPEC.target_ou_id}`, orgUnitPath: "/" },
        };
      }
      if (method !== "GET") policyMutations += 1;
      return { status: 200, payload: {} };
    },
  };
  let rejected = false;
  let rejection = "";
  try {
    await new GoogleResourceExecutor(workspace, { workspaceTransport: workspace }).apply(
      change("chromepolicy", "extension_install", "abcdefghijklmnopabcdefghijklmnop"),
      SPEC,
      { runId: "run-root-ou", stepIndex: 0, requestId: crypto.randomUUID() },
    );
  } catch (error) {
    rejection = String(error);
    rejected = error instanceof Error && error.message.includes("target-ou-invalid");
  }
  check(
    "Root OU is rejected by the fresh mutation guard before any Chrome Policy write",
    rejected && policyMutations === 0,
    JSON.stringify({ rejected, rejection, policyMutations }),
  );
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} checks\n`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} execution safety checks passed.`);
