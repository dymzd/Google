import { POC_DEPLOYER_ROLE } from "./constants.generated.ts";

/**
 * A newly created/updated deployer is not considered connected until these
 * Option B permissions are visible through its impersonated token. This also
 * covers the private-DNS read that failed alongside the regional health check
 * while the custom-role update was still propagating.
 */
export const EXTENSION_DEPLOYER_READINESS_PERMISSIONS = [
  "compute.instances.use",
  "compute.regionHealthChecks.create",
  "compute.regionHealthChecks.delete",
  "compute.regionHealthChecks.get",
  "dns.managedZones.get",
  "dns.managedZones.list",
  "serviceusage.services.use",
] as const;

/**
 * Extension-only permissions used by read-only setup discovery.
 *
 * The generated role mirrors the shared planner. Keep the extension's catalog
 * permissions here so adding a browser-only discovery call does not silently
 * broaden the backend implementation.
 */
const EXTENSION_DISCOVERY_PERMISSIONS = [
  "compute.networks.list",
  // Every extension-managed health check is regional. The generated shared
  // role still carries the global healthChecks permissions, which do not
  // authorize GET/insert/delete on regions/*/healthChecks.
  ...EXTENSION_DEPLOYER_READINESS_PERMISSIONS,
] as const;

export const EXTENSION_DEPLOYER_ROLE = {
  ...POC_DEPLOYER_ROLE,
  includedPermissions: [
    ...new Set([
      ...POC_DEPLOYER_ROLE.includedPermissions,
      ...EXTENSION_DISCOVERY_PERMISSIONS,
    ]),
  ].sort(),
} as const;
