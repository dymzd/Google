/**
 * Teardown planning. Port of `domain/teardown.py`.
 *
 * Teardown deletes only what this deployment created, in reverse dependency
 * order, and never touches a shared resource. That constraint is the whole
 * design: a PoC that removed the caller's existing VPC, or a gateway another
 * application still uses, would be far worse than one that leaves something
 * behind.
 *
 * The plan is hash-bound like an Apply plan. The operator confirms a phrase
 * derived from that hash, so a teardown approved against one inventory cannot
 * execute against another.
 */

import { canonicalDigestSync } from "./canonical.ts";

export type TeardownAction = "delete" | "delete_if_empty" | "retain";

export interface DeploymentResource {
  resourceKey: string;
  provider: string;
  resourceType: string;
  resourceName: string;
  owned: boolean;
  /** True when the resource is shared and may still be in use elsewhere. */
  shared: boolean;
}

export interface TeardownResource {
  resource_key: string;
  provider: string;
  resource_type: string;
  resource_name: string;
  owned: boolean;
  teardown_action: TeardownAction;
}

export interface TeardownPlan {
  run_id: string;
  plan_hash: string;
  confirmation: string;
  resources: TeardownResource[];
  retained_resources: TeardownResource[];
  can_destroy: boolean;
}

function action(resource: DeploymentResource): TeardownAction {
  if (!resource.owned) return "retain";
  // A gateway is removed only once no application remains under it; anything
  // else this deployment owns outright is deleted.
  if (resource.resourceType === "security_gateway") return "delete_if_empty";
  return "delete";
}

export function buildTeardownPlan(
  runId: string,
  configurationHash: string,
  deploymentName: string,
  inventory: readonly DeploymentResource[],
): TeardownPlan {
  const described: TeardownResource[] = inventory.map((resource) => ({
    resource_key: resource.resourceKey,
    provider: resource.provider,
    resource_type: resource.resourceType,
    resource_name: resource.resourceName,
    owned: resource.owned,
    teardown_action: action(resource),
  }));

  // Reverse order: dependents go before the things they depend on.
  const deletions = described.filter((item) => item.teardown_action !== "retain").reverse();
  const retained = described.filter((item) => item.teardown_action === "retain");

  const planHash = canonicalDigestSync({
    run_id: runId,
    configuration_hash: configurationHash,
    resources: deletions.map((item) => ({
      key: item.resource_key,
      action: item.teardown_action,
    })),
  });

  return {
    run_id: runId,
    plan_hash: planHash,
    // Bound to the hash: a confirmation typed for one inventory will not match
    // a plan rebuilt from a different one.
    confirmation: `DELETE ${deploymentName} ${planHash.slice(0, 12)}`,
    resources: deletions,
    retained_resources: retained,
    can_destroy: deletions.length > 0,
  };
}
