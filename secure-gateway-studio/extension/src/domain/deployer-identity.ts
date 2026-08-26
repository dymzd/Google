export type DeployerVariant = "legacy-compatible" | "isolated-replacement";

export interface DeployerTarget {
  accountId: string;
  roleId: string;
  serviceAccountEmail: string;
  roleName: string;
  variant: DeployerVariant;
}

const TARGET_IDS: Record<DeployerVariant, { accountId: string; roleId: string }> = {
  "legacy-compatible": {
    accountId: "secure-gateway-deployer",
    roleId: "secureGatewayPocDeployer",
  },
  "isolated-replacement": {
    accountId: "secure-gateway-studio-deployer",
    roleId: "secureGatewayStudioDeployer",
  },
};

export function deployerTarget(
  projectId: string,
  variant: DeployerVariant = "legacy-compatible",
): DeployerTarget {
  const ids = TARGET_IDS[variant];
  return {
    ...ids,
    serviceAccountEmail: `${ids.accountId}@${projectId}.iam.gserviceaccount.com`,
    roleName: `projects/${projectId}/roles/${ids.roleId}`,
    variant,
  };
}

export function isSupportedDeployerServiceAccountEmail(
  value: unknown,
  projectId: string,
): value is string {
  return value === deployerTarget(projectId).serviceAccountEmail ||
    value === deployerTarget(projectId, "isolated-replacement").serviceAccountEmail;
}

/**
 * Select a target only from the two product-owned name pairs. A persisted
 * checkpoint may resume either variant; arbitrary stored names never steer an
 * IAM request.
 */
export function deployerTargetForCheckpoint(
  projectId: string,
  checkpoint: unknown,
  createReplacement = false,
): DeployerTarget {
  if (typeof checkpoint === "object" && checkpoint !== null && !Array.isArray(checkpoint)) {
    const value = checkpoint as Record<string, unknown>;
    const pending = value.pending_mutation;
    const pendingEmail = typeof pending === "object" && pending !== null && !Array.isArray(pending)
      ? (pending as Record<string, unknown>).service_account_email
      : undefined;
    for (const variant of ["legacy-compatible", "isolated-replacement"] as const) {
      const target = deployerTarget(projectId, variant);
      if (
        (value.service_account_email === target.serviceAccountEmail &&
          value.custom_role === target.roleName) ||
        pendingEmail === target.serviceAccountEmail
      ) {
        return target;
      }
    }
  }
  return deployerTarget(
    projectId,
    createReplacement ? "isolated-replacement" : "legacy-compatible",
  );
}
