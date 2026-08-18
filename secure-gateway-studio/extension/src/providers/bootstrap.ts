/**
 * Deployer bootstrap. Port of `providers/gcloud_bootstrap.py`.
 *
 * The Python implementation shells out to `gcloud`. An extension has no
 * subprocess, so every step is done over REST instead. That is not merely a
 * workaround: it removes the CLI from the product's prerequisites, which was
 * the largest remaining install step for an operator.
 *
 * What it creates, idempotently:
 *
 *   1. a dedicated deployer service account;
 *   2. a project custom role holding the least-privilege permission set;
 *   3. project bindings for that role plus Browser and Service Usage Consumer;
 *   4. Policy Reader on the Access Context Manager policy, when configured;
 *   5. Token Creator for the signed-in administrator on that service account.
 *
 * Step 5 is what makes impersonation possible at all: without it the
 * administrator cannot mint the deployer token, and every later call would run
 * with their own authority instead of the least-privilege one.
 *
 * Every IAM write is read-modify-write with the returned etag, so a concurrent
 * edit by another administrator is not silently discarded.
 */

import { POC_DEPLOYER_ROLE } from "../domain/constants.generated.ts";
import type { Transport } from "./executor.ts";

const IAM = "https://iam.googleapis.com/v1";
const CRM = "https://cloudresourcemanager.googleapis.com/v1";
const ACM = "https://accesscontextmanager.googleapis.com/v1";

const ACCOUNT_ID = "secure-gateway-deployer";
const ROLE_ID = "secureGatewayPocDeployer";

export interface BootstrapResult {
  project_id: string;
  operator_email: string;
  service_account_email: string;
  custom_role: string;
  access_policy_id: string | null;
  /**
   * Retained for the UI, which shows it as the manual fallback. The extension
   * itself no longer needs it: impersonation happens in `auth/tokens.ts`.
   */
  adc_command: string;
}

export class BootstrapError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "BootstrapError";
    this.code = code;
  }
}

interface IamBinding {
  role: string;
  members: string[];
  condition?: { title?: string; description?: string; expression?: string };
}

interface IamPolicy {
  version?: number;
  etag?: string;
  bindings?: IamBinding[];
  [key: string]: unknown;
}

export interface BootstrapOptions {
  transport: Transport;
  /** Signed-in administrator, from `chrome.identity.getProfileUserInfo`. */
  operatorEmail: string;
  accessPolicyId?: string;
}

export async function bootstrapDeployer(
  projectId: string,
  options: BootstrapOptions,
): Promise<BootstrapResult> {
  const { transport, operatorEmail } = options;
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(operatorEmail)) {
    throw new BootstrapError(
      "operator-identity-unavailable",
      "No signed-in Google account was found. Sign in before running setup.",
    );
  }

  const serviceAccountEmail = `${ACCOUNT_ID}@${projectId}.iam.gserviceaccount.com`;
  const roleName = `projects/${projectId}/roles/${ROLE_ID}`;

  // 1. Service account, created only when absent.
  const accountUrl = `${IAM}/projects/${projectId}/serviceAccounts/${serviceAccountEmail}`;
  const existingAccount = await transport.requestJson("GET", accountUrl);
  if (existingAccount.status >= 400 && existingAccount.status !== 404) {
    const errObj = existingAccount.payload as { error?: { message?: string } };
    throw new BootstrapError("service-account-lookup-failed", `Service account lookup failed: ${errObj?.error?.message ?? existingAccount.status}`);
  }
  if (existingAccount.status === 404) {
    const createRes = await transport.requestJson("POST", `${IAM}/projects/${projectId}/serviceAccounts`, {
      jsonBody: {
        accountId: ACCOUNT_ID,
        serviceAccount: { displayName: "Secure Gateway Studio deployer" },
      },
    });
    if (createRes.status >= 400 && createRes.status !== 409) {
      const errObj = createRes.payload as { error?: { message?: string } };
      throw new BootstrapError("service-account-create-failed", `Failed to create service account: ${errObj?.error?.message ?? createRes.status}`);
    }
  }

  // 2. Custom role. Create or update, so a permission added in a later release
  //    reaches an existing deployment rather than being silently absent.
  const roleUrl = `${IAM}/${roleName}`;
  const existingRole = await transport.requestJson("GET", roleUrl);
  if (existingRole.status >= 400 && existingRole.status !== 404) {
    const errObj = existingRole.payload as { error?: { message?: string } };
    throw new BootstrapError("role-lookup-failed", `Role lookup failed: ${errObj?.error?.message ?? existingRole.status}`);
  }
  if (existingRole.status === 404) {
    const createRoleRes = await transport.requestJson("POST", `${IAM}/projects/${projectId}/roles`, {
      jsonBody: { roleId: ROLE_ID, role: { ...POC_DEPLOYER_ROLE } },
    });
    if (createRoleRes.status >= 400 && createRoleRes.status !== 409) {
      const errObj = createRoleRes.payload as { error?: { message?: string } };
      throw new BootstrapError("role-create-failed", `Failed to create custom role: ${errObj?.error?.message ?? createRoleRes.status}`);
    }
  } else {
    const patchRes = await transport.requestJson("PATCH", roleUrl, {
      params: { updateMask: "includedPermissions,title,description,stage" },
      jsonBody: { ...POC_DEPLOYER_ROLE },
    });
    if (patchRes.status >= 400) {
      const errObj = patchRes.payload as { error?: { message?: string } };
      throw new BootstrapError("role-update-failed", `Failed to update custom role: ${errObj?.error?.message ?? patchRes.status}`);
    }
  }

  // 3. Project bindings for the deployer.
  const member = `serviceAccount:${serviceAccountEmail}`;
  await addProjectBindings(transport, projectId, [
    { role: roleName, members: [member] },
    { role: "roles/browser", members: [member] },
    { role: "roles/serviceusage.serviceUsageConsumer", members: [member] },
  ]);

  // 4. Policy Reader, when an access policy is configured. Without it the
  //    access-level picker returns nothing and the operator cannot bind the
  //    managed-Chrome condition.
  const accessPolicyId = (options.accessPolicyId ?? "").trim();
  const policyConfigured = /^\d+$/.test(accessPolicyId);
  if (policyConfigured) {
    await addBindings(
      transport,
      `${ACM}/accessPolicies/${accessPolicyId}:getIamPolicy`,
      `${ACM}/accessPolicies/${accessPolicyId}:setIamPolicy`,
      [{ role: "roles/accesscontextmanager.policyReader", members: [member] }],
    );
  }

  // 5. Token Creator for the administrator on the deployer account.
  await addBindings(
    transport,
    `${accountUrl}:getIamPolicy`,
    `${accountUrl}:setIamPolicy`,
    [
      {
        role: "roles/iam.serviceAccountTokenCreator",
        members: [`user:${operatorEmail}`],
      },
    ],
  );

  return {
    project_id: projectId,
    operator_email: operatorEmail,
    service_account_email: serviceAccountEmail,
    custom_role: roleName,
    access_policy_id: policyConfigured ? accessPolicyId : null,
    adc_command:
      `gcloud auth application-default login --impersonate-service-account=${serviceAccountEmail}`,
  };
}

function addProjectBindings(
  transport: Transport,
  projectId: string,
  bindings: IamBinding[],
): Promise<void> {
  return addBindings(
    transport,
    `${CRM}/projects/${projectId}:getIamPolicy`,
    `${CRM}/projects/${projectId}:setIamPolicy`,
    bindings,
    { getMethod: "POST" },
  );
}

/**
 * Merge bindings into an existing policy.
 *
 * Members are added to a matching role rather than replacing it, and the etag
 * is carried through, so this neither drops another administrator's grants nor
 * overwrites an edit made between the read and the write.
 */
async function addBindings(
  transport: Transport,
  getUrl: string,
  setUrl: string,
  additions: IamBinding[],
  options: { getMethod?: "GET" | "POST" } = {},
): Promise<void> {
  const getMethod = options.getMethod ?? "POST";
  const response = await transport.requestJson(getMethod, getUrl, {
    jsonBody: getMethod === "POST" ? {} : undefined,
  });
  if (response.status >= 400) {
    const errObj = response.payload as { error?: { message?: string; status?: string } };
    const detail = errObj?.error?.message ?? `Status ${response.status}`;
    throw new BootstrapError("iam-read-failed", `Failed to get IAM policy (${getUrl}): ${detail}`);
  }
  const policy = response.payload as IamPolicy;
  const bindings: IamBinding[] = [...(policy.bindings ?? [])].map((binding) => ({
    ...binding,
    members: [...binding.members],
  }));

  let changed = false;
  for (const addition of additions) {
    const existing = bindings.find(
      (binding) => binding.role === addition.role && binding.condition === undefined,
    ) as (IamBinding & { condition?: unknown }) | undefined;
    if (existing === undefined) {
      bindings.push({ role: addition.role, members: [...addition.members] });
      changed = true;
      continue;
    }
    for (const candidate of addition.members) {
      if (!existing.members.includes(candidate)) {
        existing.members.push(candidate);
        changed = true;
      }
    }
  }

  // Idempotent by design: re-running setup after a partial failure must not
  // rewrite a policy that already says what it should.
  if (!changed) return;

  const setResponse = await transport.requestJson("POST", setUrl, {
    jsonBody: { policy: { ...policy, bindings, version: policy.version ?? 1 } },
  });
  if (setResponse.status >= 400) {
    const errObj = setResponse.payload as { error?: { message?: string; status?: string } };
    const detail = errObj?.error?.message ?? `Status ${setResponse.status}`;
    throw new BootstrapError("iam-write-failed", `Failed to set IAM policy (${setUrl}): ${detail}`);
  }
}
