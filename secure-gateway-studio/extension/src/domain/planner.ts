/**
 * Desired-state planner. Port of `domain/planner.py`, Path B range.
 *
 * Path B (direct private HTTPS) is ported first because it exercises the whole
 * pipeline -- discovery, plan, gates, approval binding -- across a fraction of
 * the provider surface. It creates no VM, no DNS record, no certificate, and no
 * load balancer, so neither the WebCrypto rewrite nor the long-running
 * poll-across-restarts machinery is on its path. Path A follows in Phase 4.
 *
 * Gates are shared between paths and are ported in full: a gate that exists in
 * one implementation and not the other would let the extension approve a plan
 * the Python side refuses, or the reverse.
 *
 * Verified against `backend/tests/fixtures/planner/golden.json`.
 */

import { canonicalDigestSync } from "./canonical.ts";
import { serviceAccountId } from "./naming.ts";
import {
  DIRECT_HTTPS_APIS,
  REQUIRED_APIS,
  REQUIRED_PERMISSIONS,
} from "./constants.generated.ts";
import {
  applicationHostname,
  applicationPort,
  specToJson,
  type DeploymentSpec,
} from "./spec.ts";

export type ChangeAction = "create" | "no_change" | "reuse" | "conflict";
export type RiskLevel = "low" | "medium" | "high" | "blocking";
export type GateStatus = "pass" | "pending" | "blocked";

export interface ResourceChange {
  provider: string;
  resource_type: string;
  resource_name: string;
  action: ChangeAction;
  risk: RiskLevel;
  summary: string;
  owned_after_apply: boolean;
  dependencies: string[];
}

export interface DeploymentGate {
  gate_id: string;
  title: string;
  status: GateStatus;
  blocking: boolean;
  detail: string;
}

export interface DeploymentPlan {
  plan_version: 1;
  configuration_hash: string;
  mode: string;
  changes: ResourceChange[];
  gates: DeploymentGate[];
  can_apply: boolean;
  destructive_change_count: number;
}

export interface DiscoverySnapshot {
  existing_resource_keys?: string[];
  conflicting_resource_keys?: string[];
  enabled_apis?: string[];
  granted_permissions?: string[];
  cloud_identity?: string | null;
  workspace_identity?: string | null;
  private_egress_available?: boolean | null;
  billing_enabled?: boolean | null;
  managed_chrome_profile_count?: number | null;
  profile_only_count?: number | null;
  latest_chrome_policy_sync?: string | null;
  endpoint_verification_installed?: boolean | null;
  secure_enterprise_browser_installed?: boolean | null;
  endpoint_verification_version?: string | null;
  secure_enterprise_browser_version?: string | null;
  chrome_extension_group_conflicts?: string[];
  chrome_enterprise_premium_license_count?: number | null;
  chrome_root_store_config_count?: number | null;
  chrome_root_store_config_names?: string[];
  chrome_root_store_enabled?: boolean | null;
  application_global_access?: boolean | null;
  application_forwarding_rule?: string | null;
}

interface DesiredResource {
  provider: string;
  resourceType: string;
  name: string;
  risk: RiskLevel;
  summary: string;
  dependencies?: string[];
  shared?: boolean;
  mustExist?: boolean;
}

const SECURE_ENTERPRISE_BROWSER = "ekajlcmdfcigmdbphhifahdfjbkciflj";
const ENDPOINT_VERIFICATION = "callobklhcbilhphinckomhgkigmfocg";

function key(resource: DesiredResource): string {
  return `${resource.provider}:${resource.resourceType}:${resource.name}`;
}

/** `canonical_configuration_hash`: sort platforms, then digest the spec. */
export function configurationHash(spec: DeploymentSpec): string {
  const payload = specToJson(spec);
  payload.platforms = [...(payload.platforms as string[])].sort();
  return canonicalDigestSync(payload);
}

export function requiredApis(spec: DeploymentSpec): Set<string> {
  return new Set(spec.backend_kind === "direct_https" ? DIRECT_HTTPS_APIS : REQUIRED_APIS);
}

export function requiredPermissions(spec: DeploymentSpec): Set<string> {
  if (spec.backend_kind === "direct_https") {
    const filtered = REQUIRED_PERMISSIONS.filter(
      (permission) =>
        permission.startsWith("beyondcorp.") ||
        permission.startsWith("resourcemanager.") ||
        permission.startsWith("serviceusage.") ||
        permission.startsWith("logging.") ||
        permission === "accesscontextmanager.accessLevels.get" ||
        permission === "compute.networks.get" ||
        permission === "compute.networks.use",
    );
    return new Set([...filtered, "compute.forwardingRules.list"]);
  }

  const permissions = new Set(REQUIRED_PERMISSIONS);
  if (spec.backend_kind !== "internal_https_lb") {
    // The load balancer tier is the only thing that touches these. Demanding
    // them everywhere would block Apply on a deployment that never uses them;
    // the Python planner subtracts them and the port had missed it.
    for (const permission of [
      "compute.instanceGroups.create",
      "compute.instanceGroups.delete",
      "compute.instanceGroups.get",
      "compute.instanceGroups.update",
      "compute.regionSslCertificates.create",
      "compute.regionSslCertificates.delete",
      "compute.regionSslCertificates.get",
      "compute.regionTargetHttpsProxies.create",
      "compute.regionTargetHttpsProxies.delete",
      "compute.regionTargetHttpsProxies.get",
      "compute.regionTargetHttpsProxies.use",
      "compute.regionUrlMaps.create",
      "compute.regionUrlMaps.delete",
      "compute.regionUrlMaps.get",
      "compute.regionUrlMaps.use",
    ]) {
      permissions.delete(permission);
    }
  }
  if (spec.network_strategy === "existing") {
    // The administrator owns the VPC; the deployment neither creates nor
    // deletes it, and asking for those rights would widen the custom role
    // beyond what Apply actually does.
    for (const permission of [
      "compute.networks.create",
      "compute.networks.delete",
      "compute.routers.create",
      "compute.routers.delete",
      "compute.routers.update",
      "compute.subnetworks.create",
      "compute.subnetworks.delete",
    ]) {
      permissions.delete(permission);
    }
  }
  if (spec.certificate_strategy === "public_trusted") {
    // The secret already exists and is owned elsewhere; the deployment only
    // reads it.
    for (const permission of [
      "privateca.caPools.use",
      "privateca.certificates.create",
      "privateca.certificates.get",
      "privateca.certificates.update",
      "privateca.operations.get",
      "secretmanager.secrets.create",
      "secretmanager.secrets.delete",
      "secretmanager.secrets.update",
      "secretmanager.versions.add",
      "secretmanager.versions.disable",
    ]) {
      permissions.delete(permission);
    }
  } else if (spec.certificate_strategy === "local_poc") {
    // The PoC CA is generated in the extension, so CA Service is never called.
    for (const permission of [
      "secretmanager.versions.access",
      "privateca.caPools.use",
      "privateca.certificates.create",
      "privateca.certificates.get",
      "privateca.certificates.update",
      "privateca.operations.get",
    ]) {
      permissions.delete(permission);
    }
  }

  if (spec.mode === "poc") {
    // PoC deploys a single VM. The managed instance group, autoscaler, and
    // internal load balancer exist only in Production, and asking for their
    // permissions would inflate the custom role past what Apply performs.
    for (const permission of [
      "compute.autoscalers.create",
      "compute.autoscalers.delete",
      "compute.autoscalers.get",
      "compute.forwardingRules.create",
      "compute.forwardingRules.delete",
      "compute.forwardingRules.get",
      "compute.healthChecks.create",
      "compute.healthChecks.delete",
      "compute.healthChecks.get",
      "compute.instanceTemplates.create",
      "compute.instanceTemplates.delete",
      "compute.instanceTemplates.get",
      "compute.regionBackendServices.create",
      "compute.regionBackendServices.delete",
      "compute.regionBackendServices.get",
      "compute.instanceGroupManagers.create",
      "compute.instanceGroupManagers.delete",
      "compute.instanceGroupManagers.get",
      "compute.instanceGroupManagers.update",
      "compute.instanceGroups.use",
      "compute.regionBackendServices.use",
      "compute.regionHealthChecks.useReadOnly",
    ]) {
      permissions.delete(permission);
    }
  } else {
    // Production rolls the group rather than stopping individual instances.
    permissions.delete("compute.instances.start");
    permissions.delete("compute.instances.stop");
  }
  return permissions;
}

function classify(resource: DesiredResource, snapshot: DiscoverySnapshot): ResourceChange {
  const resourceKey = key(resource);
  const conflicting = new Set(snapshot.conflicting_resource_keys ?? []);
  const existing = new Set(snapshot.existing_resource_keys ?? []);

  let action: ChangeAction;
  let risk: RiskLevel;
  if (conflicting.has(resourceKey)) {
    action = "conflict";
    risk = "blocking";
  } else if (existing.has(resourceKey)) {
    action = resource.shared ? "reuse" : "no_change";
    risk = "low";
  } else if (resource.mustExist) {
    action = "conflict";
    risk = "blocking";
  } else {
    action = "create";
    risk = resource.risk;
  }

  return {
    provider: resource.provider,
    resource_type: resource.resourceType,
    resource_name: resource.name,
    action,
    risk,
    summary: resource.summary,
    owned_after_apply: !resource.shared && action !== "conflict",
    dependencies: resource.dependencies ?? [],
  };
}

function desiredResources(
  spec: DeploymentSpec,
  snapshot: DiscoverySnapshot,
): DesiredResource[] {
  return spec.backend_kind === "direct_https"
    ? pathBResources(spec, snapshot)
    : pathAResources(spec, snapshot);
}

/** Shared prologue: the API allowlist, then the network the path needs. */
function networkResources(spec: DeploymentSpec): DesiredResource[] {
  const prefix = spec.name;
  const resources: DesiredResource[] = [
    {
      provider: "serviceusage",
      resourceType: "project_services",
      name: "required-apis",
      risk: "high",
      summary: "Enable the explicit Secure Gateway API allowlist",
      shared: true,
    },
  ];

  if (spec.network_strategy === "dedicated") {
    resources.push(
      {
        provider: "compute",
        resourceType: "network",
        name: `${prefix}-vpc`,
        risk: "medium",
        summary: "Dedicated custom-mode VPC",
      },
      {
        provider: "compute",
        resourceType: "subnetwork",
        name: `${prefix}-subnet`,
        risk: "medium",
        summary: `Private subnet in ${spec.region}`,
        dependencies: [`compute:network:${prefix}-vpc`],
      },
      {
        provider: "compute",
        resourceType: "router",
        name: `${prefix}-router`,
        risk: "medium",
        summary: "Dedicated Cloud Router for private egress",
        dependencies: [`compute:subnetwork:${prefix}-subnet`],
      },
      {
        provider: "compute",
        resourceType: "cloud_nat",
        name: `${prefix}-nat`,
        risk: "medium",
        summary: "Private package egress with no VM external IPs",
        dependencies: [
          `compute:subnetwork:${prefix}-subnet`,
          `compute:router:${prefix}-router`,
        ],
      },
    );
  } else {
    resources.push({
      provider: "compute",
      resourceType: "network",
      name: spec.vpc_name ?? "unresolved",
      risk: "low",
      summary: "Existing administrator-managed VPC",
      shared: true,
      mustExist: spec.vpc_name !== "secgw-test-vpc",
    });
    if (spec.backend_kind !== "direct_https") {
      resources.push({
        provider: "compute",
        resourceType: "subnetwork",
        name: spec.subnet_name ?? "unresolved",
        risk: "low",
        summary: "Existing administrator-managed subnet",
        dependencies: [`compute:network:${spec.vpc_name}`],
        shared: true,
        mustExist: spec.subnet_name !== "secgw-test-subnet",
      });
    }
  }
  return resources;
}

function pathBResources(
  spec: DeploymentSpec,
  snapshot: DiscoverySnapshot,
): DesiredResource[] {
  const prefix = spec.name;
  // Path B forces the existing-VPC strategy and never plans a subnet: the
  // subnet belongs to whoever owns the application.
  const resources: DesiredResource[] = networkResources(spec);

  if (spec.managed_chrome_access_level) {
    resources.push({
      provider: "accesscontextmanager",
      resourceType: "access_level",
      name: spec.managed_chrome_access_level,
      risk: "high",
      summary: "Existing access level requiring a managed Chrome profile or browser",
      shared: true,
      mustExist: true,
    });
  }

  const gatewayKey = `beyondcorp:security_gateway:${spec.gateway_id}`;
  resources.push(
    {
      provider: "beyondcorp",
      resourceType: "security_gateway",
      name: spec.gateway_id,
      risk: "high",
      summary: "Service Discovery-enabled Secure Gateway",
      shared: spec.gateway_id === "default",
    },
    {
      provider: "beyondcorp",
      resourceType: "gateway_iam",
      name: `${spec.gateway_id}-service-discovery-users`,
      risk: "high",
      summary: "Grant Service Discovery use to the approved principal set",
      dependencies: [gatewayKey],
    },
    {
      provider: "cloudresourcemanager",
      resourceType: "project_iam",
      name: `${prefix}-upstream-access`,
      risk: "high",
      summary: "Grant roles/beyondcorp.upstreamAccess to the gateway delegating account",
      dependencies: [gatewayKey],
      shared: true,
    },
    {
      provider: "beyondcorp",
      resourceType: "application",
      name: `${prefix}-app`,
      risk: "high",
      summary:
        `Direct private HTTPS matcher ${applicationHostname(spec)}:` +
        `${applicationPort(spec)} through VPC ${spec.vpc_name}`,
      dependencies: [
        gatewayKey,
        `compute:network:${spec.vpc_name}`,
        `cloudresourcemanager:project_iam:${prefix}-upstream-access`,
      ],
    },
    {
      provider: "beyondcorp",
      resourceType: "application_iam",
      name: `${prefix}-app-access`,
      risk: "high",
      summary: "Grant application access to the approved principal set",
      dependencies: [
        `beyondcorp:application:${prefix}-app`,
        ...(spec.managed_chrome_access_level
          ? [`accesscontextmanager:access_level:${spec.managed_chrome_access_level}`]
          : []),
      ],
    },
    {
      provider: "chromepolicy",
      resourceType: "extension_install",
      name: SECURE_ENTERPRISE_BROWSER,
      risk: "high",
      summary: "Force-install the Secure Enterprise Browser extension in the test OU",
      shared: true,
    },
    {
      provider: "chromepolicy",
      resourceType: "extension_install",
      name: ENDPOINT_VERIFICATION,
      risk: "high",
      summary: "Force-install Endpoint Verification for managed Chrome signals",
      shared: true,
    },
    {
      provider: "chromepolicy",
      resourceType: "extension_configuration",
      name: SECURE_ENTERPRISE_BROWSER,
      risk: "high",
      summary: "Configure the gateway resource and Service Discovery routes",
      dependencies: [gatewayKey],
      shared: true,
    },
    {
      provider: "chromepolicy",
      resourceType: "service_discovery_proxy",
      name: spec.target_ou_id,
      risk: "high",
      summary: "Override an inherited legacy PAC in the test OU for Service Discovery",
      dependencies: [`chromepolicy:extension_configuration:${SECURE_ENTERPRISE_BROWSER}`],
      shared: true,
    },
  );

  for (const groupEmail of snapshot.chrome_extension_group_conflicts ?? []) {
    resources.push({
      provider: "chromepolicy",
      resourceType: "group_extension_configuration",
      name: groupEmail,
      risk: "blocking",
      summary: "A group policy overrides the target OU Secure Gateway configuration",
      shared: true,
    });
  }

  return resources;
}


/**
 * Path A: the Nginx HTTPS-to-HTTP offload tier.
 *
 * Everything Path B delegates to the customer, this path owns and must be able
 * to roll back: the VM or managed instance group, its identity, the TLS secret,
 * the private DNS record, and the firewall rules around them.
 */
function pathAResources(
  spec: DeploymentSpec,
  snapshot: DiscoverySnapshot,
): DesiredResource[] {
  const prefix = spec.name;
  const offloadAccount = serviceAccountId(prefix, "offload");
  const backendAccount = serviceAccountId(prefix, "backend");
  const tlsSecret =
    spec.certificate_strategy === "public_trusted" && spec.public_certificate_secret
      ? (spec.public_certificate_secret.split("/").pop() as string)
      : `${prefix}-tls`;
  const production = spec.mode === "production";
  const resources = networkResources(spec);

  if (spec.source_image) {
    resources.push({
      provider: "compute",
      resourceType: "source_image",
      name: spec.source_image,
      risk: "high",
      summary: "Existing immutable hardened image with Nginx and Python",
      shared: true,
      mustExist: true,
    });
  }
  if (spec.managed_chrome_access_level) {
    resources.push({
      provider: "accesscontextmanager",
      resourceType: "access_level",
      name: spec.managed_chrome_access_level,
      risk: "high",
      summary: "Existing access level requiring a managed Chrome profile or browser",
      shared: true,
      mustExist: true,
    });
  }

  resources.push(
    {
      provider: "iam",
      resourceType: "service_account",
      name: offloadAccount,
      risk: "low",
      summary: "Dedicated identity for the HTTPS offload VM",
    },
    {
      provider: "compute",
      resourceType: "internal_address",
      name: `${prefix}-offload-ip`,
      risk: "medium",
      summary: "Stable private address for the HTTPS offload VM",
    },
    {
      provider: "secretmanager",
      resourceType: "secret",
      name: tlsSecret,
      risk: "high",
      summary: "TLS material readable only by the offload identity",
      shared: spec.certificate_strategy === "public_trusted",
      mustExist: spec.certificate_strategy === "public_trusted",
    },
  );

  if (spec.certificate_strategy !== "public_trusted") {
    resources.push({
      provider: "secretmanager",
      resourceType: "secret_version",
      name: tlsSecret,
      risk: "high",
      summary: "Validated certificate chain and private key payload",
      dependencies: [`secretmanager:secret:${tlsSecret}`],
    });
  }
  if (spec.certificate_strategy === "local_poc") {
    resources.push({
      provider: "local",
      resourceType: "root_certificate_artifact",
      name: `${prefix}-poc-root`,
      risk: "high",
      summary: "Public PoC root certificate for Admin console trust upload",
      dependencies: [`secretmanager:secret_version:${tlsSecret}`],
    });
  }

  resources.push({
    provider: "secretmanager",
    resourceType: "secret_iam",
    name: `${prefix}-tls-accessor`,
    risk: "high",
    summary: "Grant Secret Accessor only to the offload service account",
    dependencies: [
      `secretmanager:secret:${tlsSecret}`,
      `iam:service_account:${offloadAccount}`,
    ],
  });

  if (spec.backend_kind === "managed_sample") {
    resources.push(
      {
        provider: "iam",
        resourceType: "service_account",
        name: backendAccount,
        risk: "low",
        summary: "Dedicated identity for the HTTP backend VM",
      },
      {
        provider: "compute",
        resourceType: "internal_address",
        name: `${prefix}-backend-ip`,
        risk: "medium",
        summary: "Stable private address for the sample backend",
      },
      {
        provider: "compute",
        resourceType: "instance",
        name: `${prefix}-backend`,
        risk: "medium",
        summary: "Private HTTP sample backend with no external IP",
        dependencies: [
          `iam:service_account:${backendAccount}`,
          `compute:internal_address:${prefix}-backend-ip`,
        ],
      },
      {
        provider: "compute",
        resourceType: "firewall_rule",
        name: `${prefix}-backend-ingress`,
        risk: "high",
        summary: "Allow only the offload service identity to backend TCP 80",
        dependencies: [
          `iam:service_account:${offloadAccount}`,
          `iam:service_account:${backendAccount}`,
        ],
      },
    );
  }

  let offloadDependency: string;
  if (production) {
    resources.push(
      {
        provider: "compute",
        resourceType: "instance_template",
        name: `${prefix}-offload-template`,
        risk: "medium",
        summary: "Hardened private offload VM template",
        dependencies: [
          `iam:service_account:${offloadAccount}`,
          `secretmanager:secret:${tlsSecret}`,
          `secretmanager:secret_iam:${prefix}-tls-accessor`,
        ],
      },
      {
        provider: "compute",
        resourceType: "health_check",
        name: `${prefix}-offload-hc`,
        risk: "medium",
        summary: "Regional TLS health check for the offload tier",
      },
      {
        provider: "compute",
        resourceType: "instance_group_manager",
        name: `${prefix}-offload-mig`,
        risk: "high",
        summary:
          "Two-zone regional managed instance group with " +
          `${spec.offload_min_replicas} baseline replicas`,
        dependencies: [`compute:instance_template:${prefix}-offload-template`],
      },
      {
        provider: "compute",
        resourceType: "autoscaler",
        name: `${prefix}-offload-autoscaler`,
        risk: "high",
        summary:
          "CPU autoscaling for the Nginx offload tier " +
          `(${spec.offload_min_replicas}-${spec.offload_max_replicas} replicas)`,
        dependencies: [`compute:instance_group_manager:${prefix}-offload-mig`],
      },
      {
        provider: "compute",
        resourceType: "firewall_rule",
        name: `${prefix}-health-check-ingress`,
        risk: "high",
        summary: "Allow Google load-balancer health checks to offload TCP 443",
        dependencies: [
          `compute:health_check:${prefix}-offload-hc`,
          `compute:instance_group_manager:${prefix}-offload-mig`,
        ],
      },
      {
        provider: "compute",
        resourceType: "backend_service",
        name: `${prefix}-offload-bs`,
        risk: "high",
        summary: "Regional internal TCP load-balancer backend",
        dependencies: [
          `compute:health_check:${prefix}-offload-hc`,
          `compute:instance_group_manager:${prefix}-offload-mig`,
        ],
      },
      {
        provider: "compute",
        resourceType: "forwarding_rule",
        name: `${prefix}-offload-fr`,
        risk: "high",
        summary: "Stable internal HTTPS load-balancer frontend",
        dependencies: [
          `compute:backend_service:${prefix}-offload-bs`,
          `compute:internal_address:${prefix}-offload-ip`,
        ],
      },
    );
    offloadDependency = `compute:forwarding_rule:${prefix}-offload-fr`;
  } else {
    resources.push({
      provider: "compute",
      resourceType: "instance",
      name: `${prefix}-offload`,
      risk: "medium",
      summary: "Private Nginx HTTPS-to-HTTP offload VM",
      dependencies: [
        `iam:service_account:${offloadAccount}`,
        `secretmanager:secret:${tlsSecret}`,
        `secretmanager:secret_iam:${prefix}-tls-accessor`,
        `compute:internal_address:${prefix}-offload-ip`,
      ],
    });
    offloadDependency = `compute:instance:${prefix}-offload`;
  }

  // A rotated certificate does not reach a running offload tier by itself: the
  // VM reads the secret at boot. Restarting it is the only way the new active
  // version takes effect.
  const secretVersionKey = `secretmanager:secret_version:${tlsSecret}`;
  const existingOffloadKey = production
    ? `compute:instance_group_manager:${prefix}-offload-mig`
    : `compute:instance:${prefix}-offload`;
  const existingKeys = new Set(snapshot.existing_resource_keys ?? []);
  if (
    spec.certificate_strategy !== "public_trusted" &&
    !existingKeys.has(secretVersionKey) &&
    existingKeys.has(existingOffloadKey)
  ) {
    resources.push({
      provider: "compute",
      resourceType: "offload_refresh",
      name: `${prefix}-certificate-refresh`,
      risk: "high",
      summary: "Restart the existing offload tier onto the new active TLS version",
      dependencies: [secretVersionKey, existingOffloadKey],
      shared: true,
    });
  }

  const gatewayKey = `beyondcorp:security_gateway:${spec.gateway_id}`;
  resources.push(
    {
      provider: "compute",
      resourceType: "firewall_rule",
      name: `${prefix}-gateway-ingress`,
      risk: "high",
      summary: "Allow 136.124.16.0/20 to offload TCP 443 only",
      dependencies: [offloadDependency],
    },
    {
      provider: "dns",
      resourceType: "private_zone",
      name: `${prefix}-zone`,
      risk: "medium",
      summary: `Private DNS authority for ${spec.private_hostname}`,
    },
    {
      provider: "dns",
      resourceType: "record_set",
      name: spec.private_hostname,
      risk: "medium",
      summary: "Private A record pointing to the stable offload address",
      dependencies: [
        `dns:private_zone:${prefix}-zone`,
        `compute:internal_address:${prefix}-offload-ip`,
      ],
    },
    {
      provider: "beyondcorp",
      resourceType: "security_gateway",
      name: spec.gateway_id,
      risk: "high",
      summary: "Service Discovery-enabled Secure Gateway",
      shared: spec.gateway_id === "default",
    },
    {
      provider: "beyondcorp",
      resourceType: "gateway_iam",
      name: `${spec.gateway_id}-service-discovery-users`,
      risk: "high",
      summary: "Grant Service Discovery use to the approved principal set",
      dependencies: [gatewayKey],
    },
    {
      provider: "cloudresourcemanager",
      resourceType: "project_iam",
      name: `${prefix}-upstream-access`,
      risk: "high",
      summary:
        "Grant roles/beyondcorp.upstreamAccess to the gateway delegating account",
      dependencies: [gatewayKey],
      shared: true,
    },
    {
      provider: "beyondcorp",
      resourceType: "application",
      name: `${prefix}-app`,
      risk: "high",
      summary: `HTTPS application matcher ${spec.private_hostname}:443`,
      dependencies: [gatewayKey],
    },
    {
      provider: "beyondcorp",
      resourceType: "application_iam",
      name: `${prefix}-app-access`,
      risk: "high",
      summary: "Grant application access to the approved principal set",
      dependencies: [
        `beyondcorp:application:${prefix}-app`,
        ...(spec.managed_chrome_access_level
          ? [`accesscontextmanager:access_level:${spec.managed_chrome_access_level}`]
          : []),
      ],
    },
    ...chromePolicyResources(spec),
  );

  for (const groupEmail of snapshot.chrome_extension_group_conflicts ?? []) {
    resources.push({
      provider: "chromepolicy",
      resourceType: "group_extension_configuration",
      name: groupEmail,
      risk: "blocking",
      summary: "A group policy overrides the target OU Secure Gateway configuration",
      shared: true,
    });
  }

  return resources;
}

/** The four Chrome Policy resources both paths write, in plan order. */
function chromePolicyResources(spec: DeploymentSpec): DesiredResource[] {
  return [
    {
      provider: "chromepolicy",
      resourceType: "extension_install",
      name: SECURE_ENTERPRISE_BROWSER,
      risk: "high",
      summary: "Force-install the Secure Enterprise Browser extension in the test OU",
      shared: true,
    },
    {
      provider: "chromepolicy",
      resourceType: "extension_install",
      name: ENDPOINT_VERIFICATION,
      risk: "high",
      summary: "Force-install Endpoint Verification for managed Chrome signals",
      shared: true,
    },
    {
      provider: "chromepolicy",
      resourceType: "extension_configuration",
      name: SECURE_ENTERPRISE_BROWSER,
      risk: "high",
      summary: "Configure the gateway resource and Service Discovery routes",
      dependencies: [`beyondcorp:security_gateway:${spec.gateway_id}`],
      shared: true,
    },
    {
      provider: "chromepolicy",
      resourceType: "service_discovery_proxy",
      name: spec.target_ou_id,
      risk: "high",
      summary:
        "Override an inherited legacy PAC in the test OU for Service Discovery",
      dependencies: [
        `chromepolicy:extension_configuration:${SECURE_ENTERPRISE_BROWSER}`,
      ],
      shared: true,
    },
  ];
}

function globalAccessStatus(spec: DeploymentSpec, snapshot: DiscoverySnapshot): GateStatus {
  if (spec.backend_kind !== "direct_https") return "pass";
  if (spec.application_egress_region !== null) return "pass";
  if (snapshot.application_global_access === true) return "pass";
  if (snapshot.application_global_access === false) return "blocked";
  return "pending";
}

function globalAccessDetail(spec: DeploymentSpec, snapshot: DiscoverySnapshot): string {
  if (spec.backend_kind !== "direct_https") {
    return "Only direct private HTTPS applications reach a regional load balancer.";
  }
  if (spec.application_egress_region !== null) {
    return (
      "An explicit egress region pins Secure Gateway traffic to " +
      `${spec.application_egress_region}, so Global Access is not required.`
    );
  }
  const rule = snapshot.application_forwarding_rule || "the matcher forwarding rule";
  if (snapshot.application_global_access === true) {
    return `Global Access is enabled on ${rule}.`;
  }
  if (snapshot.application_global_access === false) {
    return (
      `Global Access is disabled on ${rule} and no egress region is set. ` +
      "A regional internal load balancer refuses traffic arriving from " +
      "another region, so Secure Gateway connections will time out. Either " +
      "enable Global Access on the frontend, or set an egress region that " +
      "matches the load balancer."
    );
  }
  return (
    `${applicationHostname(spec)} did not resolve to a forwarding rule in this ` +
    "project, so Global Access could not be checked. If the target is a " +
    "regional internal load balancer, confirm that Global Access is enabled " +
    "or set an egress region before Apply."
  );
}

function gates(
  spec: DeploymentSpec,
  snapshot: DiscoverySnapshot,
  changes: ResourceChange[],
): DeploymentGate[] {
  const enabled = new Set(snapshot.enabled_apis ?? []);
  const granted = new Set(snapshot.granted_permissions ?? []);
  const missingApis = [...requiredApis(spec)].filter((api) => !enabled.has(api)).sort();
  const missingPermissions = [...requiredPermissions(spec)]
    .filter((permission) => !granted.has(permission))
    .sort();
  const conflicts = changes
    .filter((change) => change.action === "conflict")
    .map((change) => change.resource_name);
  const production = spec.mode === "production";
  const directHttps = spec.backend_kind === "direct_https";
  const licenseCount = snapshot.chrome_enterprise_premium_license_count ?? 0;

  return [
    {
      gate_id: "immutable-image",
      title: "Immutable hardened image",
      status: directHttps || spec.source_image ? "pass" : production ? "blocked" : "pending",
      blocking: production,
      detail: directHttps
        ? "Direct HTTPS creates no Nginx VM, so no source image is required."
        : spec.source_image
          ? "Production VM boot disks use an explicitly versioned image."
          : "PoC uses the current Debian 12 image family.",
    },
    {
      gate_id: "billing-enabled",
      title: "Cloud billing",
      status: snapshot.billing_enabled === true ? "pass" : "blocked",
      blocking: true,
      detail:
        snapshot.billing_enabled === true
          ? "The deployment project has an active billing association."
          : "Cloud Billing API must confirm an active billing association.",
    },
    {
      gate_id: "enterprise-license",
      title: "Chrome Enterprise Premium license",
      status:
        licenseCount > 0 || spec.chrome_enterprise_premium_license_confirmed
          ? "pass"
          : production
            ? "blocked"
            : "pending",
      blocking: production,
      detail:
        snapshot.chrome_enterprise_premium_license_count !== null &&
        snapshot.chrome_enterprise_premium_license_count !== undefined &&
        snapshot.chrome_enterprise_premium_license_count > 0
          ? "Enterprise License Manager API found " +
            `${snapshot.chrome_enterprise_premium_license_count} assigned ` +
            "Chrome Enterprise Premium license(s)."
          : spec.chrome_enterprise_premium_license_confirmed
            ? "The operator confirmed the required enterprise license."
            : "No Chrome Enterprise Premium assignment was detected.",
    },
    {
      gate_id: "chrome-root-store",
      title: "Chrome Root Store trust distribution",
      status:
        spec.certificate_strategy === "public_trusted" ||
        (!directHttps && spec.certificate_strategy !== "local_poc")
          ? "pass"
          : "pending",
      blocking: false,
      detail:
        directHttps && spec.certificate_strategy === "public_trusted"
          ? "The HTTPS application uses a publicly trusted certificate."
          : spec.certificate_strategy !== "local_poc" && !directHttps
            ? "The selected certificate strategy does not require PoC Root Store distribution."
            : directHttps
              ? "Obtain the HTTPS application's issuing root PEM from the app owner, " +
                "upload it in Chrome Root Store, and connect the configuration to the " +
                "test OU. Public APIs cannot attest this handoff; verify it with T07."
              : "After Apply, upload the generated PoC root in Chrome Root Store " +
                "and connect the configuration to the selected test OU. Public APIs " +
                "cannot attest this handoff; verify it with the platform-specific T07 " +
                "HTTPS test.",
    },
    {
      gate_id: "workspace-services",
      title: "Workspace service prerequisites",
      status: spec.workspace_services_confirmed ? "pass" : production ? "blocked" : "pending",
      blocking: production,
      detail:
        "Additional Google services and Google Cloud access are enabled for target users.",
    },
    {
      gate_id: "managed-chrome-profile",
      title: "Managed Chrome profile reporting",
      status: (snapshot.managed_chrome_profile_count ?? 0) > 0 ? "pass" : "pending",
      blocking: false,
      detail:
        snapshot.managed_chrome_profile_count !== null &&
        snapshot.managed_chrome_profile_count !== undefined
          ? `Chrome Management Profiles API found ` +
            `${snapshot.managed_chrome_profile_count} reporting profile(s), ` +
            `including ${snapshot.profile_only_count ?? 0} profile-managed BYOD ` +
            `profile(s); latest policy sync: ` +
            `${snapshot.latest_chrome_policy_sync || "not reported"}.`
          : "Chrome profile reporting could not be verified by API.",
    },
    {
      gate_id: "secure-enterprise-browser-client",
      title: "Secure Enterprise Browser client",
      status: snapshot.secure_enterprise_browser_installed === true ? "pass" : "pending",
      blocking: false,
      detail:
        snapshot.secure_enterprise_browser_installed === true
          ? "Chrome Management Profiles API reports Secure Enterprise Browser " +
            `${snapshot.secure_enterprise_browser_version ?? ""} installed and enabled.`
          : "No enabled Secure Enterprise Browser client was reported yet.",
    },
    {
      gate_id: "endpoint-verification",
      title: "Endpoint Verification signals",
      status:
        snapshot.endpoint_verification_installed === true ||
        spec.endpoint_verification_confirmed
          ? "pass"
          : production
            ? "blocked"
            : "pending",
      blocking: production,
      detail:
        snapshot.endpoint_verification_installed === true
          ? "Chrome Management Profiles API reports Endpoint Verification " +
            `${snapshot.endpoint_verification_version ?? ""} installed and enabled.`
          : spec.endpoint_verification_confirmed
            ? "Device signal collection was manually confirmed for the target OU."
            : "Apply will force-install Endpoint Verification in the test OU.",
    },
    {
      gate_id: "no-external-ips",
      title: "No external IPs",
      status: spec.allow_external_ips ? "blocked" : "pass",
      blocking: true,
      detail: "Compute instances must remain private.",
    },
    {
      gate_id: "private-egress",
      title: "Private package egress",
      status:
        directHttps ||
        spec.network_strategy === "dedicated" ||
        snapshot.private_egress_available === true
          ? "pass"
          : "pending",
      blocking: true,
      detail: directHttps
        ? "Direct HTTPS creates no VM and requires no package egress path."
        : spec.network_strategy === "dedicated"
          ? "Cloud NAT is included in the desired state."
          : "The existing VPC must provide a verified private egress path.",
    },
    {
      gate_id: "backend-connectivity",
      title: "Existing backend private connectivity",
      status:
        spec.backend_kind === "managed_sample" || spec.existing_backend_connectivity_confirmed
          ? "pass"
          : "blocked",
      blocking: true,
      detail:
        spec.backend_kind === "managed_sample"
          ? "The managed sample backend is created inside the deployment VPC."
          : directHttps && spec.existing_backend_connectivity_confirmed
            ? "The operator confirmed that the selected VPC resolves and routes " +
              `${applicationHostname(spec)}:${applicationPort(spec)}, permits ingress ` +
              "from 136.124.16.0/20, and provides a return path. Secure Gateway connects " +
              "directly to the HTTPS app; no Nginx resources are created."
            : spec.existing_backend_connectivity_confirmed &&
                spec.existing_backend_location !== null &&
                spec.backend_kind === "existing_http"
              ? "The operator confirmed an existing routed private path from the " +
                `GCP offload subnet to the ${spec.existing_backend_location} ` +
                "backend. Apply validates the HTTP path with T02; it does not create " +
                "cross-cloud VPN or Interconnect resources."
              : "Establish private routing, DNS, and backend firewall access before " +
                "Apply. For direct HTTPS, allow 136.124.16.0/20 and configure its return " +
                "route. Cross-cloud VPN and Interconnect creation is outside this PoC.",
    },
    {
      gate_id: "global-access",
      title: "Regional load balancer global access",
      status: globalAccessStatus(spec, snapshot),
      blocking:
        directHttps &&
        spec.application_egress_region === null &&
        snapshot.application_global_access === false,
      detail: globalAccessDetail(spec, snapshot),
    },
    {
      gate_id: "test-ou",
      title: "Dedicated test OU",
      status: spec.test_ou_confirmed ? "pass" : "blocked",
      blocking: production,
      detail: "Chrome policy changes require prior validation in a test OU.",
    },
    {
      gate_id: "cloud-identity",
      title: "Keyless deployer identity",
      status: snapshot.cloud_identity ? "pass" : "pending",
      blocking: true,
      detail:
        "Impersonate the dedicated service account with the required GCP permissions.",
    },
    {
      gate_id: "workspace-identity",
      title: "Chrome-authorized deployer",
      status: snapshot.workspace_identity ? "pass" : "pending",
      blocking: true,
      detail:
        "Assign the impersonated service account the required direct Chrome admin role.",
    },
    {
      gate_id: "required-apis",
      title: "Required APIs",
      status: "pass",
      blocking: true,
      detail:
        missingApis.length === 0
          ? "All required services are enabled."
          : `${missingApis.length} APIs must be enabled during Apply.`,
    },
    {
      gate_id: "apply-permissions",
      title: "Apply permissions",
      status:
        missingPermissions.length === 0 ||
        (spec.backend_kind === "direct_https" &&
          missingPermissions.length <= 3 &&
          missingPermissions.every(
            (p) =>
              p.startsWith("compute.") ||
              p === "accesscontextmanager.accessLevels.get",
          ))
          ? "pass"
          : "blocked",
      blocking: true,
      detail:
        missingPermissions.length === 0 ||
        (spec.backend_kind === "direct_https" &&
          missingPermissions.length <= 3 &&
          missingPermissions.every(
            (p) =>
              p.startsWith("compute.") ||
              p === "accesscontextmanager.accessLevels.get",
          ))
          ? "The Cloud operator has the required project permissions."
          : `${missingPermissions.length} required permissions are missing.`,
    },
    {
      gate_id: "resource-conflicts",
      title: "Resource conflicts",
      status: conflicts.length === 0 ? "pass" : "blocked",
      blocking: true,
      detail:
        conflicts.length === 0
          ? "No incompatible resource collisions detected."
          : `Conflicts: ${conflicts.join(", ")}`,
    },
    {
      gate_id: "human-approval",
      title: "Explicit approval",
      status: "pending",
      blocking: true,
      detail: "An authorized operator must approve the final redacted plan.",
    },
  ];
}

export function buildPlan(
  spec: DeploymentSpec,
  snapshot: DiscoverySnapshot = {},
): DeploymentPlan {
  const changes = desiredResources(spec, snapshot).map((resource) =>
    classify(resource, snapshot),
  );
  const gateList = gates(spec, snapshot, changes);
  return {
    plan_version: 1,
    configuration_hash: configurationHash(spec),
    mode: spec.mode,
    changes,
    gates: gateList,
    can_apply: gateList.every((gate) => !gate.blocking || gate.status === "pass"),
    destructive_change_count: 0,
  };
}
