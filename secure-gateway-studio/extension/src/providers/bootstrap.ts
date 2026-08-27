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
 *   2. a project custom role holding the union for all supported product paths;
 *   3. project bindings for that role plus Browser and Service Usage Consumer;
 *   4. Policy Editor on the Access Context Manager policy, when configured;
 *   5. Token Creator for the signed-in administrator on that service account.
 *
 * Step 5 is what makes impersonation possible at all: without it the
 * administrator cannot mint the deployer token, and every later call would run
 * with their own authority instead of the dedicated product-scoped one.
 *
 * Every IAM write is read-modify-write with the returned etag, so a concurrent
 * edit by another administrator is not silently discarded.
 */

import { EXTENSION_DEPLOYER_ROLE } from "../domain/extension-deployer-role.ts";
import {
  deployerTargetForCheckpoint,
} from "../domain/deployer-identity.ts";
import { canonicalDigestSync, canonicalJson } from "../domain/canonical.ts";
import {
  validatedIamBindings,
  validatedIamPolicy,
} from "../domain/iam-policy.ts";
import { GoogleApiError, type Transport } from "./executor.ts";

const IAM = "https://iam.googleapis.com/v1";
const CRM = "https://cloudresourcemanager.googleapis.com/v1";
const ACM = "https://accesscontextmanager.googleapis.com/v1";

const LEGACY_020_ROLE_DEFINITION_DIGEST =
  "9e52930185796ea4ba7fca0b2dc69fad5d8e309b445d773aae974ea34402dcf3";
export interface BootstrapResult {
  project_id: string;
  operator_email: string;
  service_account_email: string;
  service_account_unique_id: string;
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

export interface IamBinding {
  role: string;
  members: string[];
  condition?: {
    title?: string;
    description?: string;
    expression?: string;
    location?: string;
  };
}

interface IamPolicy {
  version?: number;
  etag?: string;
  bindings?: IamBinding[];
  [key: string]: unknown;
}

export interface BootstrapOwnershipPin {
  version: 1;
  project_id: string;
  service_account_email: string;
  /** Immutable across renames and different after delete/recreate. */
  service_account_unique_id: string;
  /** Human Google identity that created/adopted this ownership record. */
  operator_email: string;
  /** Random marker written into the SA description by a fresh 0.2.1 create. */
  service_account_ownership_token?: string | null;
  /** Exact audited policy attached to the service-account resource. */
  service_account_iam_bindings: IamBinding[];
  custom_role: string;
  /** Null only between our successful service-account and role creates. */
  custom_role_etag: string | null;
  /** Provider mutation intent committed before a request can leave the worker. */
  pending_mutation?: BootstrapPendingMutation;
  /** Durable proof needed until a deleted identity has been fully replaced. */
  deleted_deployer_recovery?: DeletedDeployerRecovery;
}

export interface DeletedDeployerRecovery {
  version: 1;
  service_account_email: string;
  service_account_unique_id: string;
  custom_role: string;
  role_state: "absent" | "soft_deleted";
  deleted_role_etag: string | null;
  expected_definition_digest: string;
}

export type BootstrapPendingMutation =
  | {
      kind: "custom_role";
      action: "create" | "update" | "undelete";
      phase: "sending";
      role_name: string;
      before_etag: string | null;
      expected_definition_digest: string;
    }
  | {
      kind: "service_account_iam";
      phase: "sending";
      operator_email: string;
      before_bindings: IamBinding[];
      expected_bindings: IamBinding[];
    };

export interface BootstrapServiceAccountCreateIntent {
  version: 1;
  project_id: string;
  operator_email: string;
  pending_mutation: {
    kind: "service_account_create";
    phase: "sending";
    service_account_email: string;
    ownership_token: string;
  };
  deleted_deployer_recovery?: DeletedDeployerRecovery;
}

export type BootstrapOwnershipCheckpoint =
  | BootstrapOwnershipPin
  | BootstrapServiceAccountCreateIntent;

export interface LegacyDeployerIdentity {
  serviceAccountEmail: string;
  projectId: string;
}

/**
 * Recover the exact non-secret identity hint written by 0.2.0.
 *
 * Version 0.2.0 persisted only `deployerServiceAccount`; it did not persist a
 * separate project id. The reserved email embeds that id, so accept only the
 * exact SGS account shape and reject any conflicting newer field. This hint is
 * never ownership proof: explicit migration still audits the live immutable
 * uniqueId, exact custom role, and both IAM allowlists before checkpointing.
 */
export function legacyDeployerIdentityFromStoredState(
  stored: Record<string, unknown>,
): LegacyDeployerIdentity | undefined {
  const liveEmail = stored.deployerServiceAccount;
  if (liveEmail !== undefined) {
    if (typeof liveEmail !== "string") return undefined;
    const prefix = "secure-gateway-deployer@";
    const suffix = ".iam.gserviceaccount.com";
    if (!liveEmail.startsWith(prefix) || !liveEmail.endsWith(suffix)) return undefined;
    const projectId = liveEmail.slice(prefix.length, -suffix.length);
    if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) return undefined;
    const storedProjectId = stored.deployerProjectId;
    if (storedProjectId !== undefined && storedProjectId !== projectId) return undefined;
    return { serviceAccountEmail: liveEmail, projectId };
  }

  const legacy = stored.legacyDeployerIdentityV020;
  if (typeof legacy !== "object" || legacy === null || Array.isArray(legacy)) {
    return undefined;
  }
  const value = legacy as Record<string, unknown>;
  if (
    typeof value.projectId !== "string" ||
    typeof value.serviceAccountEmail !== "string" ||
    !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(value.projectId) ||
    value.serviceAccountEmail !==
      `secure-gateway-deployer@${value.projectId}.iam.gserviceaccount.com`
  ) return undefined;
  return {
    projectId: value.projectId,
    serviceAccountEmail: value.serviceAccountEmail,
  };
}

export interface BootstrapOptions {
  transport: Transport;
  /** Verified administrator email attested by OIDC UserInfo for the current token. */
  operatorEmail: string;
  accessPolicyId?: string;
  /** Previously checkpointed immutable identities for this exact project. */
  ownershipPin?: unknown;
  /** Must durably complete before any project-level privilege is granted. */
  checkpointOwnershipPin: (pin: BootstrapOwnershipCheckpoint) => Promise<void>;
  /** Clear only a provider-confirmed non-applied initial-create intent. */
  clearOwnershipPin?: (projectId: string) => Promise<void>;
  /** Exact identity stored by 0.2.0, before uniqueId pinning existed. */
  legacyDeployerIdentity?: LegacyDeployerIdentity;
  /** True only after the operator confirms MIGRATE_EXISTING_DEPLOYER. */
  allowOwnershipMigration?: boolean;
  /** Create fresh isolated names after a legacy migration audit fails closed. */
  createReplacementDeployer?: boolean;
  /** True only after the operator confirms the provider-deleted pinned identity. */
  allowDeletedOwnedDeployerRebootstrap?: boolean;
  /** Durably tombstone the old immutable identity before a fresh create intent. */
  retireDeletedOwnershipPin?: (pin: BootstrapOwnershipPin) => Promise<void>;
}

export function normaliseIamBindings(value: unknown): IamBinding[] {
  try {
    const bindings = validatedIamBindings(value === undefined ? [] : value) as IamBinding[];
    return bindings
      .map((binding) => ({
        ...structuredClone(binding),
        members: [...binding.members].sort(),
      }))
      .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  } catch {
    throw new BootstrapError(
      "service-account-iam-policy-invalid",
      "The deployer service-account IAM policy is malformed.",
    );
  }
}

function readDeletedDeployerRecovery(
  value: unknown,
  serviceAccountEmail: string,
  roleName: string,
): DeletedDeployerRecovery | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new BootstrapError(
      "deleted-deployer-recovery-invalid",
      "The deleted deployer recovery checkpoint is malformed.",
    );
  }
  const recovery = value as Partial<DeletedDeployerRecovery>;
  if (
    recovery.version !== 1 ||
    recovery.service_account_email !== serviceAccountEmail ||
    typeof recovery.service_account_unique_id !== "string" ||
    !/^\d+$/.test(recovery.service_account_unique_id) ||
    recovery.custom_role !== roleName ||
    (recovery.role_state !== "absent" && recovery.role_state !== "soft_deleted") ||
    !(recovery.deleted_role_etag === null ||
      (typeof recovery.deleted_role_etag === "string" && recovery.deleted_role_etag !== "")) ||
    (recovery.role_state === "soft_deleted") !==
      (typeof recovery.deleted_role_etag === "string") ||
    typeof recovery.expected_definition_digest !== "string" ||
    !/^[0-9a-f]{64}$/.test(recovery.expected_definition_digest)
  ) {
    throw new BootstrapError(
      "deleted-deployer-recovery-invalid",
      "The deleted deployer recovery checkpoint does not match the reserved identity.",
    );
  }
  return structuredClone(recovery as DeletedDeployerRecovery);
}

function readOwnershipPin(
  value: unknown,
  projectId: string,
  serviceAccountEmail: string,
  roleName: string,
): BootstrapOwnershipPin | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new BootstrapError(
      "bootstrap-ownership-pin-invalid",
      "The persisted deployer ownership record is malformed.",
    );
  }
  const pin = value as Partial<BootstrapOwnershipPin>;
  const bindings = normaliseIamBindings(pin.service_account_iam_bindings);
  const inferredOperator = soleTokenCreatorOperator(bindings);
  const pinnedOperator = typeof pin.operator_email === "string"
    ? pin.operator_email.trim().toLowerCase()
    : inferredOperator;
  const ownershipToken = pin.service_account_ownership_token;
  const pending = pin.pending_mutation;
  const deletedRecovery = readDeletedDeployerRecovery(
    pin.deleted_deployer_recovery,
    serviceAccountEmail,
    roleName,
  );
  if (
    pin.version !== 1 || pin.project_id !== projectId ||
    pin.service_account_email !== serviceAccountEmail ||
    typeof pin.service_account_unique_id !== "string" ||
    !/^\d+$/.test(pin.service_account_unique_id) ||
    pin.custom_role !== roleName ||
    pinnedOperator === null ||
    !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(pinnedOperator) ||
    !(ownershipToken === undefined || ownershipToken === null ||
      (typeof ownershipToken === "string" && /^[0-9a-f-]{20,64}$/i.test(ownershipToken))) ||
    !(pending === undefined || isBootstrapPendingMutation(pending, roleName, pinnedOperator)) ||
    !(pin.custom_role_etag === null ||
      (typeof pin.custom_role_etag === "string" && pin.custom_role_etag !== ""))
  ) {
    throw new BootstrapError(
      "bootstrap-ownership-pin-invalid",
      "The persisted deployer ownership record does not match this project.",
    );
  }
  return {
    version: 1,
    project_id: projectId,
    service_account_email: serviceAccountEmail,
    service_account_unique_id: pin.service_account_unique_id,
    operator_email: pinnedOperator,
    service_account_ownership_token: ownershipToken ?? null,
    service_account_iam_bindings: bindings,
    custom_role: roleName,
    custom_role_etag: pin.custom_role_etag,
    ...(pending === undefined ? {} : { pending_mutation: structuredClone(pending) }),
    ...(deletedRecovery === undefined
      ? {}
      : { deleted_deployer_recovery: deletedRecovery }),
  };
}

function isBootstrapPendingMutation(
  value: unknown,
  roleName: string,
  operatorEmail: string,
): value is BootstrapPendingMutation {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const pending = value as Record<string, unknown>;
  if (pending.phase !== "sending") return false;
  if (pending.kind === "custom_role") {
    return (pending.action === "create" || pending.action === "update" ||
      pending.action === "undelete") &&
      pending.role_name === roleName &&
      (pending.before_etag === null || typeof pending.before_etag === "string") &&
      typeof pending.expected_definition_digest === "string" &&
      /^[0-9a-f]{64}$/.test(pending.expected_definition_digest);
  }
  if (pending.kind === "service_account_iam") {
    try {
      return pending.operator_email === operatorEmail &&
        Array.isArray(pending.before_bindings) &&
        Array.isArray(pending.expected_bindings) &&
        canonicalJson(normaliseIamBindings(pending.before_bindings)) ===
          canonicalJson(pending.before_bindings) &&
        canonicalJson(normaliseIamBindings(pending.expected_bindings)) ===
          canonicalJson(pending.expected_bindings);
    } catch {
      return false;
    }
  }
  return false;
}

function readServiceAccountCreateIntent(
  value: unknown,
  projectId: string,
  operatorEmail: string,
  expectedEmail: string,
): BootstrapServiceAccountCreateIntent | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const raw = value as Record<string, unknown>;
  const pending = raw.pending_mutation as Record<string, unknown> | undefined;
  if (
    raw.version !== 1 || raw.project_id !== projectId ||
    raw.operator_email !== operatorEmail.toLowerCase() ||
    pending?.kind !== "service_account_create" || pending.phase !== "sending" ||
    pending.service_account_email !== expectedEmail ||
    typeof pending.ownership_token !== "string" ||
    !/^[0-9a-f-]{20,64}$/i.test(pending.ownership_token)
  ) return undefined;
  readDeletedDeployerRecovery(
    raw.deleted_deployer_recovery,
    expectedEmail,
    deployerTargetForCheckpoint(projectId, value).roleName,
  );
  return structuredClone(value) as BootstrapServiceAccountCreateIntent;
}

function soleTokenCreatorOperator(bindings: readonly IamBinding[]): string | null {
  if (
    bindings.length !== 1 ||
    bindings[0]?.role !== "roles/iam.serviceAccountTokenCreator" ||
    bindings[0].condition !== undefined ||
    bindings[0].members.length !== 1
  ) return null;
  const match = /^user:([^@\s]+@[^@\s]+\.[^@\s]+)$/.exec(bindings[0].members[0] ?? "");
  return match?.[1]?.toLowerCase() ?? null;
}

/**
 * Validate a persisted ownership pin before any privileged bootstrap or
 * steady-state mutation. Existing pins never grow a second Token Creator:
 * operator rotation is an explicit out-of-band review, not an idempotent
 * bootstrap side effect.
 */
export function assertBootstrapOwnershipOperator(
  value: unknown,
  projectId: string,
  currentOperatorEmail: string,
): BootstrapOwnershipPin {
  const target = deployerTargetForCheckpoint(projectId, value);
  const pin = readOwnershipPin(
    value,
    projectId,
    target.serviceAccountEmail,
    target.roleName,
  );
  if (pin === undefined) {
    throw new BootstrapError(
      "bootstrap-ownership-pin-missing",
      "The project-bound deployer ownership record is missing.",
    );
  }
  const current = currentOperatorEmail.trim().toLowerCase();
  if (pin.operator_email !== current) {
    throw new BootstrapError(
      "bootstrap-operator-changed",
      "The signed-in Google operator differs from the sole operator pinned to this deployer. Use an explicit reviewed operator-rotation workflow.",
    );
  }
  if (pin.service_account_iam_bindings.length > 0) {
    const bound = soleTokenCreatorOperator(pin.service_account_iam_bindings);
    if (bound !== pin.operator_email) {
      throw new BootstrapError(
        "service-account-iam-policy-changed",
        "The pinned deployer policy is not the sole unconditional Token Creator binding for its operator.",
      );
    }
  }
  return pin;
}

function roleDefinitionDigest(payload: Record<string, unknown>): string | null {
  if (
    typeof payload.title !== "string" || typeof payload.description !== "string" ||
    typeof payload.stage !== "string" || !Array.isArray(payload.includedPermissions) ||
    payload.includedPermissions.some((permission) => typeof permission !== "string")
  ) {
    return null;
  }
  return canonicalDigestSync({
    title: payload.title,
    description: payload.description,
    stage: payload.stage,
    includedPermissions: [...payload.includedPermissions as string[]].sort(),
  });
}

function deletedManagedRoleEtag(
  payload: Record<string, unknown>,
  expectedName: string,
): string {
  const desiredDigest = roleDefinitionDigest(
    EXTENSION_DEPLOYER_ROLE as Record<string, unknown>,
  );
  if (
    payload.name !== expectedName || payload.deleted !== true ||
    typeof payload.etag !== "string" || payload.etag === "" ||
    desiredDigest === null || roleDefinitionDigest(payload) !== desiredDigest
  ) {
    throw new BootstrapError(
      "deleted-deployer-role-mismatch",
      "The deleted reserved custom role does not exactly match the managed SGS definition. Nothing was retired or restored.",
    );
  }
  return payload.etag;
}

function isKnownMigrationRole(
  payload: Record<string, unknown>,
  roleName: string,
): boolean {
  return isCurrentManagedRole(payload, roleName) ||
    (payload.name === roleName && payload.deleted !== true &&
      roleDefinitionDigest(payload) === LEGACY_020_ROLE_DEFINITION_DIGEST);
}

function assertLegacyServiceAccountIam(
  bindings: IamBinding[],
  operatorEmail: string,
): void {
  // The 0.2.0 bootstrap wrote exactly one unconditional Token Creator
  // binding for the operator who ran setup.  Allowing any additional member
  // here would make a pre-claimed reserved account migratable while an
  // attacker's token-minting authority remains attached.
  const safe = bindings.length === 1 &&
    bindings[0].role === "roles/iam.serviceAccountTokenCreator" &&
    bindings[0].condition === undefined &&
    bindings[0].members.length === 1 &&
    bindings[0].members[0] === `user:${operatorEmail}`;
  if (!safe) {
    throw new BootstrapError(
      "legacy-deployer-service-account-iam-unsafe",
      "The legacy deployer service account has IAM principals outside the 0.2.0 Token Creator allowlist. Nothing was adopted or granted.",
    );
  }
}

function assertLegacyProjectIam(
  policy: IamPolicy,
  serviceAccountMember: string,
  roleName: string,
): void {
  const expectedRoles = new Set([
    roleName,
    "roles/browser",
    "roles/serviceusage.serviceUsageConsumer",
  ]);
  const bindings = normaliseIamBindings(policy.bindings);
  const attached = bindings.filter((binding) => binding.members.includes(serviceAccountMember));
  const observedRoles = new Set(attached.map((binding) => binding.role));
  const customRoleBindings = bindings.filter((binding) => binding.role === roleName);
  const safe = attached.every((binding) =>
    binding.condition === undefined && expectedRoles.has(binding.role)
  ) && observedRoles.size === expectedRoles.size &&
    attached.length === expectedRoles.size &&
    [...expectedRoles].every((role) => observedRoles.has(role)) &&
    customRoleBindings.length === 1 &&
    customRoleBindings[0].condition === undefined &&
    customRoleBindings[0].members.length === 1 &&
    customRoleBindings[0].members[0] === serviceAccountMember;
  if (!safe) {
    throw new BootstrapError(
      "legacy-deployer-project-iam-unsafe",
      "The legacy deployer has project bindings outside the exact 0.2.0 allowlist, or required bindings are missing. Nothing was adopted or granted.",
    );
  }
}

function referencesPinnedDeployer(
  member: string,
  pin: Pick<BootstrapOwnershipPin,
    "service_account_email" | "service_account_unique_id">,
): boolean {
  const email = pin.service_account_email;
  const uniqueId = pin.service_account_unique_id;
  return member === `serviceAccount:${email}` ||
    member.startsWith(`deleted:serviceAccount:${email}?uid=`) ||
    member === `principal://iam.googleapis.com/projects/-/serviceAccounts/${uniqueId}`;
}

/**
 * Prove that a deliberately deleted pinned deployer left no live authority.
 * This audit is read-only and completes in full before the local identity is
 * retired or a provider create request can be sent.
 */
async function assertDeletedPinnedDeployerCloudStateClean(
  transport: Transport,
  projectId: string,
  pin: BootstrapOwnershipPin,
  accessPolicyId?: string,
): Promise<DeletedDeployerRecovery> {
  const roleResponse = await transport.requestJson(
    "GET",
    `${IAM}/${pin.custom_role}`,
    { acceptedStatuses: [404] },
  );
  if (roleResponse.status >= 400 && roleResponse.status !== 404) {
    throw new BootstrapError(
      "deleted-deployer-role-lookup-failed",
      "The pinned deployer role could not be inspected. Nothing was retired or recreated.",
    );
  }
  if (roleResponse.status !== 404 && roleResponse.payload.deleted !== true) {
    throw new BootstrapError(
      "deleted-deployer-role-still-exists",
      "The pinned deployer custom role still exists. Delete or review it before recreating the deployer.",
    );
  }
  const deletedRoleEtag = roleResponse.status === 404
    ? null
    : deletedManagedRoleEtag(roleResponse.payload, pin.custom_role);

  await assertNoPinnedDeployerIamBindings(
    transport,
    projectId,
    pin,
    accessPolicyId,
  );
  const expectedDefinitionDigest = roleDefinitionDigest(
    EXTENSION_DEPLOYER_ROLE as Record<string, unknown>,
  );
  if (expectedDefinitionDigest === null) throw new Error("managed-role-definition-invalid");
  return {
    version: 1,
    service_account_email: pin.service_account_email,
    service_account_unique_id: pin.service_account_unique_id,
    custom_role: pin.custom_role,
    role_state: deletedRoleEtag === null ? "absent" : "soft_deleted",
    deleted_role_etag: deletedRoleEtag,
    expected_definition_digest: expectedDefinitionDigest,
  };
}

async function assertNoPinnedDeployerIamBindings(
  transport: Transport,
  projectId: string,
  pin: Pick<BootstrapOwnershipPin,
    "service_account_email" | "service_account_unique_id" | "custom_role">,
  accessPolicyId?: string,
  replacement?: Pick<BootstrapOwnershipPin,
    "service_account_email" | "custom_role">,
): Promise<void> {
  const policies: Array<{ scope: "project" | "access_policy"; policy: IamPolicy }> = [
    { scope: "project", policy: await readIamPolicy(
      transport,
      `${CRM}/projects/${projectId}:getIamPolicy`,
    ) },
  ];
  const normalizedPolicyId = (accessPolicyId ?? "").trim();
  if (/^\d+$/.test(normalizedPolicyId)) {
    policies.push({
      scope: "access_policy",
      policy: await readIamPolicy(
        transport,
        `${ACM}/accessPolicies/${normalizedPolicyId}:getIamPolicy`,
      ),
    });
  }
  const replacementMember = replacement === undefined
    ? null
    : `serviceAccount:${replacement.service_account_email}`;
  const allowedReplacementRoles = {
    project: new Set([
      replacement?.custom_role,
      "roles/browser",
      "roles/serviceusage.serviceUsageConsumer",
    ]),
    access_policy: new Set(["roles/accesscontextmanager.policyEditor"]),
  };
  const staleBinding = policies.flatMap(({ scope, policy }) =>
    normaliseIamBindings(policy.bindings).map((binding) => ({ scope, binding }))
  ).find(({ scope, binding }) => {
    const hasReplacementMember = replacementMember !== null &&
      binding.members.includes(replacementMember);
    const validReplacementBinding = hasReplacementMember &&
      binding.condition === undefined &&
      allowedReplacementRoles[scope].has(binding.role);
    if (binding.role === pin.custom_role) {
      return !validReplacementBinding || binding.members.length !== 1;
    }
    return binding.members.some((member) => {
      if (member === replacementMember) return !validReplacementBinding;
      return referencesPinnedDeployer(member, pin);
    });
  });
  if (staleBinding !== undefined) {
    throw new BootstrapError(
      "deleted-deployer-iam-binding-remains",
      "The deleted deployer or its custom role still appears in project or Access Policy IAM. Nothing was retired or recreated.",
    );
  }
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

  const selectedModes = [
    options.allowOwnershipMigration === true,
    options.createReplacementDeployer === true,
    options.allowDeletedOwnedDeployerRebootstrap === true,
  ].filter(Boolean).length;
  if (selectedModes > 1) {
    throw new BootstrapError(
      "bootstrap-mode-conflict",
      "Legacy adoption, isolated replacement, and deleted-deployer recreation cannot be requested together.",
    );
  }
  const target = deployerTargetForCheckpoint(
    projectId,
    options.ownershipPin,
    options.createReplacementDeployer === true,
  );
  if (
    options.createReplacementDeployer === true &&
    target.variant !== "isolated-replacement"
  ) {
    throw new BootstrapError(
      "replacement-deployer-conflicts-with-pin",
      "An existing ownership pin belongs to the compatibility deployer; an isolated replacement was not created.",
    );
  }
  const serviceAccountEmail = target.serviceAccountEmail;
  const roleName = target.roleName;
  const accountCreateIntent = readServiceAccountCreateIntent(
    options.ownershipPin,
    projectId,
    operatorEmail.toLowerCase(),
    serviceAccountEmail,
  );
  let ownershipPin = accountCreateIntent === undefined
    ? readOwnershipPin(options.ownershipPin, projectId, serviceAccountEmail, roleName)
    : undefined;
  if (ownershipPin !== undefined) {
    ownershipPin = assertBootstrapOwnershipOperator(
      ownershipPin,
      projectId,
      operatorEmail,
    );
  }
  let legacyMigrationUniqueId: string | undefined;
  let auditUnstoredLegacyKeys = false;
  let deletedDeployerRecovery =
    accountCreateIntent?.deleted_deployer_recovery ??
    ownershipPin?.deleted_deployer_recovery;

  // 1. Service account. Email/displayName are mutable or reusable, so only the
  //    immutable numeric uniqueId returned by our own successful create proves
  //    ownership. Unknown pre-existing names and create races are never adopted.
  const accountUrl = `${IAM}/projects/${projectId}/serviceAccounts/${serviceAccountEmail}`;
  const existingAccount = await transport.requestJson("GET", accountUrl, {
    acceptedStatuses: [404],
  });
  if (existingAccount.status >= 400 && existingAccount.status !== 404) {
    const errObj = existingAccount.payload as { error?: { message?: string } };
    throw new BootstrapError("service-account-lookup-failed", `Service account lookup failed: ${errObj?.error?.message ?? existingAccount.status}`);
  }
  if (existingAccount.status === 404) {
    if (ownershipPin !== undefined) {
      if (options.allowDeletedOwnedDeployerRebootstrap !== true) {
        throw new BootstrapError(
          "service-account-pinned-identity-missing",
          "The pinned deployer service account no longer exists. Review the deletion and recreate it explicitly before bootstrap.",
        );
      }
      if (options.retireDeletedOwnershipPin === undefined) {
        throw new BootstrapError(
          "deleted-deployer-retirement-unavailable",
          "The deleted deployer cannot be durably retired in this runtime.",
        );
      }
      deletedDeployerRecovery = await assertDeletedPinnedDeployerCloudStateClean(
        transport,
        projectId,
        ownershipPin,
        options.accessPolicyId,
      );
      await options.retireDeletedOwnershipPin(structuredClone(ownershipPin));
      ownershipPin = undefined;
    }
    const intent = accountCreateIntent ?? {
      version: 1 as const,
      project_id: projectId,
      operator_email: operatorEmail.toLowerCase(),
      pending_mutation: {
        kind: "service_account_create" as const,
        phase: "sending" as const,
        service_account_email: serviceAccountEmail,
        ownership_token: crypto.randomUUID(),
      },
      ...(deletedDeployerRecovery === undefined
        ? {}
        : { deleted_deployer_recovery: structuredClone(deletedDeployerRecovery) }),
    };
    if (accountCreateIntent === undefined) {
      await options.checkpointOwnershipPin(structuredClone(intent));
    }
    let createRes;
    try {
      createRes = await transport.requestJson(
        "POST",
        `${IAM}/projects/${projectId}/serviceAccounts`,
        {
          jsonBody: {
            accountId: target.accountId,
            serviceAccount: {
              displayName: "Secure Gateway Studio deployer",
              description: ownershipDescription(intent.pending_mutation.ownership_token),
            },
          },
        },
      );
    } catch (error) {
      if (isDefiniteProviderRejection(error)) {
        await options.clearOwnershipPin?.(projectId);
      }
      throw error;
    }
    if (createRes.status >= 400) {
      if (createRes.status < 500 && createRes.status !== 408 && createRes.status !== 429) {
        await options.clearOwnershipPin?.(projectId);
      }
      throw new BootstrapError(
        createRes.status === 409 ? "service-account-create-raced" : "service-account-create-failed",
        createRes.status === 409
          ? "The reserved deployer service-account name was created concurrently. It was not adopted."
          : `Failed to create service account (status ${createRes.status}).`,
      );
    }
    const uniqueId = assertManagedServiceAccount(
      createRes.payload,
      serviceAccountEmail,
      undefined,
      intent.pending_mutation.ownership_token,
    );
    ownershipPin = {
      version: 1,
      project_id: projectId,
      service_account_email: serviceAccountEmail,
      service_account_unique_id: uniqueId,
      operator_email: operatorEmail.toLowerCase(),
      service_account_ownership_token: intent.pending_mutation.ownership_token,
      service_account_iam_bindings: [],
      custom_role: roleName,
      custom_role_etag: null,
      ...(deletedDeployerRecovery === undefined
        ? {}
        : { deleted_deployer_recovery: structuredClone(deletedDeployerRecovery) }),
    };
    await options.checkpointOwnershipPin(structuredClone(ownershipPin));
  } else {
    if (accountCreateIntent !== undefined) {
      const uniqueId = assertManagedServiceAccount(
        existingAccount.payload,
        serviceAccountEmail,
        undefined,
        accountCreateIntent.pending_mutation.ownership_token,
      );
      ownershipPin = {
        version: 1,
        project_id: projectId,
        service_account_email: serviceAccountEmail,
        service_account_unique_id: uniqueId,
        operator_email: operatorEmail.toLowerCase(),
        service_account_ownership_token:
          accountCreateIntent.pending_mutation.ownership_token,
        service_account_iam_bindings: [],
        custom_role: roleName,
        custom_role_etag: null,
        ...(deletedDeployerRecovery === undefined
          ? {}
          : { deleted_deployer_recovery: structuredClone(deletedDeployerRecovery) }),
      };
      await options.checkpointOwnershipPin(structuredClone(ownershipPin));
    } else if (ownershipPin === undefined) {
      if (options.allowOwnershipMigration !== true) {
        throw new BootstrapError(
          "service-account-identity-unpinned",
          "The reserved deployer service-account name already exists but has no immutable SGS ownership record. It was not granted any role; use the explicit 0.2.0 migration review.",
        );
      }
      const legacy = options.legacyDeployerIdentity;
      if (legacy !== undefined && (
        legacy.projectId !== projectId ||
        legacy.serviceAccountEmail !== serviceAccountEmail
      )) {
        throw new BootstrapError(
          "legacy-deployer-identity-mismatch",
          "The stored 0.2.0 deployer identity does not match this project and reserved account.",
        );
      }
      legacyMigrationUniqueId = assertManagedServiceAccount(
        existingAccount.payload,
        serviceAccountEmail,
      );
      // A Chrome reinstall or an already-completed 0.2.1 storage migration can
      // legitimately leave no 0.2.0 email hint.  In that recovery case the
      // operator's explicit confirmation is not enough on its own: also prove
      // that the reserved account has no user-managed keys before the exact
      // role and IAM allowlist audits below.  This keeps recovery keyless and
      // prevents adopting a lookalike account whose creator retained a key.
      auditUnstoredLegacyKeys = legacy === undefined;
      if (auditUnstoredLegacyKeys) {
        const keysResponse = await transport.requestJson(
          "GET",
          `${accountUrl}/keys`,
          { params: { keyTypes: "USER_MANAGED" } },
        );
        const keys = keysResponse.payload.keys;
        if (keys !== undefined && !Array.isArray(keys)) {
          throw new BootstrapError(
            "legacy-deployer-key-inventory-invalid",
            "Google returned an invalid user-managed key inventory for the legacy deployer. Nothing was adopted or granted.",
          );
        }
        if (Array.isArray(keys) && keys.length > 0) {
          throw new BootstrapError(
            "legacy-deployer-user-managed-key-present",
            "The legacy deployer has a user-managed service-account key. Remove and investigate it before migration; nothing was adopted or granted.",
          );
        }
      }
    } else {
      assertManagedServiceAccount(
        existingAccount.payload,
        serviceAccountEmail,
        ownershipPin.service_account_unique_id,
        ownershipPin.service_account_ownership_token ?? undefined,
      );
    }
  }

  // 2. Custom role. A lookalike role can already be bound to an attacker, so a
  //    name/title match is not ownership. Pin its etag at our create and require
  //    that exact version before any later permission expansion.
  const roleUrl = `${IAM}/${roleName}`;
  const desiredRoleDigest = roleDefinitionDigest(EXTENSION_DEPLOYER_ROLE as Record<string, unknown>);
  if (desiredRoleDigest === null) throw new Error("managed-role-definition-invalid");
  let existingRole = await transport.requestJson("GET", roleUrl, {
    acceptedStatuses: [404],
  });
  if (existingRole.status >= 400 && existingRole.status !== 404) {
    const errObj = existingRole.payload as { error?: { message?: string } };
    throw new BootstrapError("role-lookup-failed", `Role lookup failed: ${errObj?.error?.message ?? existingRole.status}`);
  }
  if (existingRole.status !== 404 && existingRole.payload.deleted === true) {
    if (ownershipPin === undefined) {
      throw new BootstrapError(
        "deleted-deployer-role-unpinned",
        "The reserved custom role is deleted but no durable recreation checkpoint owns it.",
      );
    }
    const deletedEtag = deletedManagedRoleEtag(existingRole.payload, roleName);
    if (
      deletedDeployerRecovery === undefined ||
      deletedDeployerRecovery.role_state !== "soft_deleted" ||
      deletedDeployerRecovery.deleted_role_etag !== deletedEtag ||
      deletedDeployerRecovery.expected_definition_digest !== desiredRoleDigest
    ) {
      throw new BootstrapError(
        "deleted-deployer-role-unpinned",
        "The soft-deleted custom role does not match the durable deleted-deployer recovery checkpoint.",
      );
    }
    const pendingRole = ownershipPin.pending_mutation;
    if (pendingRole !== undefined && (
      pendingRole.kind !== "custom_role" ||
      pendingRole.action !== "undelete" ||
      pendingRole.before_etag !== deletedEtag ||
      pendingRole.expected_definition_digest !== desiredRoleDigest
    )) {
      throw new BootstrapError(
        "bootstrap-mutation-ambiguous",
        "A different bootstrap mutation is awaiting exact reconciliation.",
      );
    }
    if (pendingRole === undefined) {
      ownershipPin = {
        ...ownershipPin,
        pending_mutation: {
          kind: "custom_role",
          action: "undelete",
          phase: "sending",
          role_name: roleName,
          before_etag: deletedEtag,
          expected_definition_digest: desiredRoleDigest,
        },
      };
      await options.checkpointOwnershipPin(structuredClone(ownershipPin));
    }
    let undeleteRoleRes;
    try {
      undeleteRoleRes = await transport.requestJson(
        "POST",
        `${roleUrl}:undelete`,
        { jsonBody: { etag: deletedEtag } },
      );
    } catch (error) {
      // Keep the exact undelete intent for retry. A lost response can mean the
      // role is already active, which the next GET reconciles without a second
      // mutation.
      throw error;
    }
    if (undeleteRoleRes.status >= 400) {
      throw new BootstrapError(
        "role-undelete-failed",
        `Failed to undelete the exact managed custom role (status ${undeleteRoleRes.status}).`,
      );
    }
    assertCurrentManagedRole(undeleteRoleRes.payload, roleName);
    existingRole = undeleteRoleRes;
  }
  if (existingRole.status === 404) {
    if (ownershipPin === undefined) {
      throw new BootstrapError(
        "legacy-deployer-role-mismatch",
        "The exact 0.2.0 deployer custom role was not found. Nothing was adopted or granted.",
      );
    }
    if (ownershipPin.custom_role_etag !== null) {
      throw new BootstrapError(
        "role-pinned-identity-missing",
        "The pinned deployer custom role no longer exists. Review the deletion and migrate explicitly before bootstrap.",
      );
    }
    let pendingRole = ownershipPin.pending_mutation;
    if (pendingRole?.kind === "custom_role" && pendingRole.action === "undelete") {
      // The deleted role passed the explicit audit but became permanently
      // purged before undelete. Convert the durable intent before attempting
      // to reuse the now-free role ID.
      ownershipPin = withoutPendingMutation(ownershipPin);
      pendingRole = undefined;
    }
    if (pendingRole !== undefined &&
        (pendingRole.kind !== "custom_role" || pendingRole.action !== "create")) {
      throw new BootstrapError(
        "bootstrap-mutation-ambiguous",
        "A different bootstrap mutation is awaiting exact reconciliation.",
      );
    }
    if (pendingRole === undefined) {
      ownershipPin = {
        ...ownershipPin,
        pending_mutation: {
          kind: "custom_role",
          action: "create",
          phase: "sending",
          role_name: roleName,
          before_etag: null,
          expected_definition_digest: desiredRoleDigest,
        },
      };
      await options.checkpointOwnershipPin(structuredClone(ownershipPin));
    }
    let createRoleRes;
    try {
      createRoleRes = await transport.requestJson(
        "POST",
        `${IAM}/projects/${projectId}/roles`,
        { jsonBody: { roleId: target.roleId, role: { ...EXTENSION_DEPLOYER_ROLE } } },
      );
    } catch (error) {
      if (isDefiniteProviderRejection(error)) {
        ownershipPin = withoutPendingMutation(ownershipPin);
        await options.checkpointOwnershipPin(structuredClone(ownershipPin));
      }
      throw error;
    }
    if (createRoleRes.status >= 400) {
      if (createRoleRes.status < 500 && createRoleRes.status !== 408 && createRoleRes.status !== 429) {
        ownershipPin = withoutPendingMutation(ownershipPin);
        await options.checkpointOwnershipPin(structuredClone(ownershipPin));
      }
      throw new BootstrapError(
        createRoleRes.status === 409 ? "role-create-raced" : "role-create-failed",
        createRoleRes.status === 409
          ? "The reserved deployer role name was created concurrently. It was not adopted."
          : `Failed to create custom role (status ${createRoleRes.status}).`,
      );
    }
    const roleEtag = assertCurrentManagedRole(createRoleRes.payload, roleName);
    ownershipPin = {
      ...withoutPendingMutation(ownershipPin),
      custom_role_etag: roleEtag,
    };
    await options.checkpointOwnershipPin(structuredClone(ownershipPin));
  } else {
    if (ownershipPin === undefined) {
      if (
        legacyMigrationUniqueId === undefined ||
        !isKnownMigrationRole(existingRole.payload, roleName)
      ) {
        throw new BootstrapError(
          "legacy-deployer-role-mismatch",
          "The reserved role does not exactly match a known 0.2.0 or current SGS deployer definition. Nothing was adopted or granted.",
        );
      }
      const migrationRoleEtag = roleEtag(existingRole.payload, roleName);
      const migrationAccountPolicy = await readIamPolicy(
        transport,
        `${accountUrl}:getIamPolicy`,
      );
      const migrationAccountBindings = normaliseIamBindings(
        migrationAccountPolicy.bindings,
      );
      assertLegacyServiceAccountIam(migrationAccountBindings, operatorEmail);
      const migrationProjectPolicy = await readIamPolicy(
        transport,
        `${CRM}/projects/${projectId}:getIamPolicy`,
      );
      assertLegacyProjectIam(
        migrationProjectPolicy,
        `serviceAccount:${serviceAccountEmail}`,
        roleName,
      );
      ownershipPin = {
        version: 1,
        project_id: projectId,
        service_account_email: serviceAccountEmail,
        service_account_unique_id: legacyMigrationUniqueId,
        operator_email: operatorEmail.toLowerCase(),
        service_account_iam_bindings: migrationAccountBindings,
        custom_role: roleName,
        custom_role_etag: migrationRoleEtag,
      };
      await options.checkpointOwnershipPin(structuredClone(ownershipPin));
    }
    const pendingRole = ownershipPin.pending_mutation;
    if (pendingRole?.kind === "custom_role") {
      const observedPendingEtag = roleEtag(existingRole.payload, roleName);
      if (
        pendingRole.expected_definition_digest === desiredRoleDigest &&
        roleDefinitionDigest(existingRole.payload) === desiredRoleDigest
      ) {
        ownershipPin = {
          ...withoutPendingMutation(ownershipPin),
          custom_role_etag: observedPendingEtag,
        };
        await options.checkpointOwnershipPin(structuredClone(ownershipPin));
      } else if (
        pendingRole.action !== "update" ||
        observedPendingEtag !== pendingRole.before_etag
      ) {
        throw new BootstrapError(
          "bootstrap-mutation-ambiguous",
          "The custom role differs from both the durable before and exact managed-after state.",
        );
      }
    } else if (pendingRole?.kind === "service_account_iam") {
      // A response-lost account-policy SET is reconciled later in this same
      // invocation. It is safe to pass the role stage only while the role is
      // still the exact pinned managed definition; never overwrite the
      // account-IAM intent with a role update.
      const observedPendingEtag = roleEtag(existingRole.payload, roleName);
      if (
        ownershipPin.custom_role_etag === null ||
        observedPendingEtag !== ownershipPin.custom_role_etag ||
        !isCurrentManagedRole(existingRole.payload, roleName)
      ) {
        throw new BootstrapError(
          "bootstrap-mutation-ambiguous",
          "The custom role changed while a service-account IAM mutation awaits reconciliation.",
        );
      }
    }
    if (ownershipPin.custom_role_etag === null) {
      throw new BootstrapError(
        "role-identity-unpinned",
        "The reserved deployer role name already exists but has no SGS ownership record. It was not expanded or granted; review it and migrate explicitly.",
      );
    }
    const observedEtag = roleEtag(existingRole.payload, roleName);
    if (observedEtag !== ownershipPin.custom_role_etag) {
      if (isCurrentManagedRole(existingRole.payload, roleName)) {
        ownershipPin = { ...ownershipPin, custom_role_etag: observedEtag };
        await options.checkpointOwnershipPin(structuredClone(ownershipPin));
      } else {
        throw new BootstrapError(
          "role-version-changed",
          "The pinned deployer custom role was changed outside this bootstrap. Review it before migrating the ownership record.",
        );
      }
    }
    if (!isCurrentManagedRole(existingRole.payload, roleName)) {
      ownershipPin = {
        ...ownershipPin,
        pending_mutation: {
          kind: "custom_role",
          action: "update",
          phase: "sending",
          role_name: roleName,
          before_etag: observedEtag,
          expected_definition_digest: desiredRoleDigest,
        },
      };
      await options.checkpointOwnershipPin(structuredClone(ownershipPin));
      let updated: string;
      try {
        updated = await updateManagedRole(
          transport,
          roleUrl,
          roleName,
          observedEtag,
        );
      } catch (error) {
        if (isDefiniteProviderRejection(error)) {
          ownershipPin = withoutPendingMutation(ownershipPin);
          await options.checkpointOwnershipPin(structuredClone(ownershipPin));
        }
        throw error;
      }
      ownershipPin = {
        ...withoutPendingMutation(ownershipPin),
        custom_role_etag: updated,
      };
      await options.checkpointOwnershipPin(structuredClone(ownershipPin));
    }
  }

  // 3. Audit the complete policy attached to the service-account resource,
  //    then grant the current operator Token Creator and checkpoint the exact
  //    managed-after policy before the account receives any project role.
  const member = `serviceAccount:${serviceAccountEmail}`;
  const accountGetIamUrl = `${accountUrl}:getIamPolicy`;
  const accountSetIamUrl = `${accountUrl}:setIamPolicy`;
  const accountPolicy = await readIamPolicy(transport, accountGetIamUrl);
  const observedAccountBindings = normaliseIamBindings(accountPolicy.bindings);
  const pendingIam = ownershipPin.pending_mutation;
  let expectedAccountBindings: IamBinding[];
  if (pendingIam?.kind === "service_account_iam") {
    const before = normaliseIamBindings(pendingIam.before_bindings);
    const expected = normaliseIamBindings(pendingIam.expected_bindings);
    if (canonicalJson(observedAccountBindings) === canonicalJson(expected)) {
      ownershipPin = {
        ...withoutPendingMutation(ownershipPin),
        service_account_iam_bindings: expected,
      };
      await options.checkpointOwnershipPin(structuredClone(ownershipPin));
      expectedAccountBindings = expected;
    } else if (canonicalJson(observedAccountBindings) === canonicalJson(before)) {
      expectedAccountBindings = expected;
    } else {
      throw new BootstrapError(
        "bootstrap-mutation-ambiguous",
        "The deployer IAM policy differs from both the durable before and exact managed-after state.",
      );
    }
  } else {
    if (pendingIam !== undefined) {
      throw new BootstrapError(
        "bootstrap-mutation-ambiguous",
        "A custom-role mutation is still awaiting reconciliation.",
      );
    }
    if (
      canonicalJson(observedAccountBindings) !==
        canonicalJson(ownershipPin.service_account_iam_bindings)
    ) {
      throw new BootstrapError(
        "service-account-iam-policy-changed",
        "The deployer service account has unreviewed IAM principals. No project role was granted; review the policy and migrate explicitly.",
      );
    }
    expectedAccountBindings = mergeIamBindings(observedAccountBindings, [
      {
        role: "roles/iam.serviceAccountTokenCreator",
        members: [`user:${operatorEmail.toLowerCase()}`],
      },
    ]);
  }
  const writeRequired =
    canonicalJson(observedAccountBindings) !== canonicalJson(expectedAccountBindings);
  if (writeRequired && ownershipPin.pending_mutation === undefined) {
    ownershipPin = {
      ...ownershipPin,
      pending_mutation: {
        kind: "service_account_iam",
        phase: "sending",
        operator_email: operatorEmail.toLowerCase(),
        before_bindings: observedAccountBindings,
        expected_bindings: expectedAccountBindings,
      },
    };
    await options.checkpointOwnershipPin(structuredClone(ownershipPin));
  }
  if (writeRequired) {
    let nextAccountPolicy: IamPolicy;
    try {
      nextAccountPolicy = validatedIamPolicy({
        ...accountPolicy,
        bindings: expectedAccountBindings,
        version: 3,
      }) as IamPolicy;
    } catch {
      throw new BootstrapError(
        "iam-policy-invalid",
        "The deployer service-account IAM policy could not be safely merged.",
      );
    }
    try {
      await transport.requestJson("POST", accountSetIamUrl, {
        jsonBody: {
          policy: nextAccountPolicy,
        },
      });
    } catch (error) {
      if (isDefiniteProviderRejection(error)) {
        ownershipPin = withoutPendingMutation(ownershipPin);
        await options.checkpointOwnershipPin(structuredClone(ownershipPin));
      }
      throw error;
    }
  }
  const confirmedAccountPolicy = await readIamPolicy(transport, accountGetIamUrl);
  const confirmedAccountBindings = normaliseIamBindings(confirmedAccountPolicy.bindings);
  if (canonicalJson(confirmedAccountBindings) !== canonicalJson(expectedAccountBindings)) {
    throw new BootstrapError(
      "service-account-iam-policy-verification-failed",
      "The deployer service-account IAM policy changed during bootstrap. No project role was granted.",
    );
  }
  ownershipPin = {
    ...withoutPendingMutation(ownershipPin),
    service_account_iam_bindings: confirmedAccountBindings,
  };
  await options.checkpointOwnershipPin(structuredClone(ownershipPin));

  // 4. Project bindings for the deployer.
  if (deletedDeployerRecovery !== undefined) {
    // Close the audit-to-grant race after the new account and role exist but
    // before either receives project or Access Policy authority. Recheck the
    // retired immutable identity, not merely the newly created account: a
    // deleted principal:// member can preserve the old numeric id while the
    // replacement legitimately reuses the same email.
    await assertNoPinnedDeployerIamBindings(
      transport,
      projectId,
      deletedDeployerRecovery,
      options.accessPolicyId,
      ownershipPin,
    );
  }
  await addProjectBindings(transport, projectId, [
    { role: roleName, members: [member] },
    { role: "roles/browser", members: [member] },
    { role: "roles/serviceusage.serviceUsageConsumer", members: [member] },
  ]);

  // 5. Policy Editor, when an access policy is configured. It supplies both
  //    catalogue reads and the access-level create/delete permissions used by
  //    CEP AUTO_CREATE flows. Existing Reader bindings are deliberately left
  //    in place; IAM binding merge only adds the required Editor role.
  const accessPolicyId = (options.accessPolicyId ?? "").trim();
  const policyConfigured = /^\d+$/.test(accessPolicyId);
  if (policyConfigured) {
    await addBindings(
      transport,
      `${ACM}/accessPolicies/${accessPolicyId}:getIamPolicy`,
      `${ACM}/accessPolicies/${accessPolicyId}:setIamPolicy`,
      [{ role: "roles/accesscontextmanager.policyEditor", members: [member] }],
    );
  }

  if (ownershipPin.deleted_deployer_recovery !== undefined) {
    const { deleted_deployer_recovery: _completedRecovery, ...settledPin } = ownershipPin;
    ownershipPin = settledPin;
    await options.checkpointOwnershipPin(structuredClone(ownershipPin));
  }

  return {
    project_id: projectId,
    operator_email: operatorEmail,
    service_account_email: serviceAccountEmail,
    service_account_unique_id: ownershipPin.service_account_unique_id,
    custom_role: roleName,
    access_policy_id: policyConfigured ? accessPolicyId : null,
    adc_command:
      `gcloud auth application-default login --impersonate-service-account=${serviceAccountEmail}`,
  };
}

function ownershipDescription(token: string): string {
  return `Secure Gateway Studio ownership:${token}`;
}

function isDefiniteProviderRejection(error: unknown): boolean {
  return error instanceof GoogleApiError &&
    error.status >= 400 && error.status < 500 &&
    error.status !== 408 && error.status !== 429;
}

function withoutPendingMutation(pin: BootstrapOwnershipPin): BootstrapOwnershipPin {
  const copy = { ...pin };
  delete copy.pending_mutation;
  return copy;
}

function mergeIamBindings(
  existing: readonly IamBinding[],
  additions: readonly IamBinding[],
): IamBinding[] {
  const bindings = normaliseIamBindings(existing);
  for (const addition of additions) {
    const target = bindings.find(
      (binding) => binding.role === addition.role && binding.condition === undefined,
    );
    if (target === undefined) {
      bindings.push({ role: addition.role, members: [...addition.members].sort() });
      continue;
    }
    target.members = [...new Set([...target.members, ...addition.members])].sort();
  }
  return normaliseIamBindings(bindings);
}

function assertManagedServiceAccount(
  payload: Record<string, unknown>,
  expectedEmail: string,
  expectedUniqueId?: string,
  expectedOwnershipToken?: string,
): string {
  if (
    payload.email !== expectedEmail ||
    payload.displayName !== "Secure Gateway Studio deployer" ||
    typeof payload.uniqueId !== "string" || !/^\d+$/.test(payload.uniqueId) ||
    (expectedUniqueId !== undefined && payload.uniqueId !== expectedUniqueId) ||
    (expectedOwnershipToken !== undefined &&
      payload.description !== ownershipDescription(expectedOwnershipToken)) ||
    payload.disabled === true
  ) {
    throw new BootstrapError(
      "service-account-reconciliation-failed",
      "The reserved deployer service-account name is occupied by an incompatible account.",
    );
  }
  return payload.uniqueId;
}

function roleEtag(payload: Record<string, unknown>, expectedName: string): string {
  if (
    payload.name !== expectedName ||
    typeof payload.etag !== "string" || payload.etag === "" ||
    payload.deleted === true
  ) {
    throw new BootstrapError(
      "role-reconciliation-failed",
      "The reserved deployer role name is occupied by an incompatible role.",
    );
  }
  return payload.etag;
}

function isCurrentManagedRole(
  payload: Record<string, unknown>,
  expectedName: string,
): boolean {
  if (payload.name !== expectedName || payload.deleted === true) return false;
  if (!Array.isArray(payload.includedPermissions)) return false;
  const permissions = payload.includedPermissions;
  if (permissions.some((permission) => typeof permission !== "string")) return false;
  return payload.title === EXTENSION_DEPLOYER_ROLE.title &&
    payload.description === EXTENSION_DEPLOYER_ROLE.description &&
    payload.stage === EXTENSION_DEPLOYER_ROLE.stage &&
    canonicalJson([...permissions].sort()) ===
      canonicalJson([...EXTENSION_DEPLOYER_ROLE.includedPermissions].sort());
}

function assertCurrentManagedRole(
  payload: Record<string, unknown>,
  expectedName: string,
): string {
  const etag = roleEtag(payload, expectedName);
  if (!isCurrentManagedRole(payload, expectedName)) {
    throw new BootstrapError(
      "role-reconciliation-failed",
      "Google did not return the exact deployer role definition created by this bootstrap.",
    );
  }
  return etag;
}

async function updateManagedRole(
  transport: Transport,
  roleUrl: string,
  roleName: string,
  etag: string,
): Promise<string> {
  const patchRes = await transport.requestJson("PATCH", roleUrl, {
    params: { updateMask: "includedPermissions,title,description,stage" },
    jsonBody: { ...EXTENSION_DEPLOYER_ROLE, name: roleName, etag },
  });
  if (patchRes.status >= 400) {
    const errObj = patchRes.payload as { error?: { message?: string } };
    throw new BootstrapError(
      "role-update-failed",
      `Failed to update custom role: ${errObj?.error?.message ?? patchRes.status}`,
    );
  }
  return assertCurrentManagedRole(patchRes.payload, roleName);
}

async function addProjectBindings(
  transport: Transport,
  projectId: string,
  bindings: IamBinding[],
): Promise<void> {
  await addBindings(
    transport,
    `${CRM}/projects/${projectId}:getIamPolicy`,
    `${CRM}/projects/${projectId}:setIamPolicy`,
    bindings,
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
  existingPolicy?: IamPolicy,
): Promise<IamPolicy> {
  let policy: IamPolicy;
  try {
    policy = validatedIamPolicy(
      existingPolicy ?? await readIamPolicy(transport, getUrl),
    ) as IamPolicy;
  } catch {
    throw new BootstrapError(
      "iam-policy-invalid",
      `Google returned a malformed IAM policy for ${getUrl}`,
    );
  }
  const bindings: IamBinding[] = [...(policy.bindings ?? [])].map((binding) => ({
    ...binding,
    members: [...binding.members],
  }));

  let changed = false;
  for (const addition of additions) {
    const existing = bindings.find(
      (binding) =>
        binding.role === addition.role &&
        (binding.condition === undefined || binding.condition === null),
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
  if (!changed) return policy;
  if (typeof policy.etag !== "string" || policy.etag === "") {
    throw new BootstrapError(
      "iam-etag-missing",
      `Google did not return an etag for IAM policy ${getUrl}`,
    );
  }

  let nextPolicy: IamPolicy;
  try {
    nextPolicy = validatedIamPolicy({ ...policy, bindings, version: 3 }) as IamPolicy;
  } catch {
    throw new BootstrapError(
      "iam-policy-invalid",
      `The IAM policy for ${getUrl} could not be safely merged.`,
    );
  }
  const setResponse = await transport.requestJson("POST", setUrl, {
    jsonBody: { policy: nextPolicy },
  });
  if (setResponse.status >= 400) {
    const errObj = setResponse.payload as { error?: { message?: string; status?: string } };
    const detail = errObj?.error?.message ?? `Status ${setResponse.status}`;
    throw new BootstrapError("iam-write-failed", `Failed to set IAM policy (${setUrl}): ${detail}`);
  }
  return nextPolicy;
}

async function readIamPolicy(
  transport: Transport,
  getUrl: string,
): Promise<IamPolicy> {
  // IAM Admin's serviceAccounts.getIamPolicy exposes GetPolicyOptions as query
  // parameters and requires an empty body. Resource Manager and Access Context
  // Manager expose the same options in their JSON request body.
  const serviceAccountPolicy = getUrl.startsWith(IAM) && getUrl.includes("/serviceAccounts/");
  const response = await transport.requestJson(
    "POST",
    getUrl,
    serviceAccountPolicy
      ? { params: { "options.requestedPolicyVersion": 3 } }
      : { jsonBody: { options: { requestedPolicyVersion: 3 } } },
  );
  if (response.status >= 400) {
    const errObj = response.payload as { error?: { message?: string; status?: string } };
    const detail = errObj?.error?.message ?? `Status ${response.status}`;
    throw new BootstrapError("iam-read-failed", `Failed to get IAM policy (${getUrl}): ${detail}`);
  }
  try {
    return validatedIamPolicy(response.payload) as IamPolicy;
  } catch {
    throw new BootstrapError(
      "iam-policy-invalid",
      `Google returned a malformed IAM policy for ${getUrl}`,
    );
  }
}
