/**
 * Path A resource handlers: the network and offload tier.
 *
 * Split from `executor.ts` because Path A roughly doubles the provider surface
 * and the two paths share nothing below the transport. Keeping them apart makes
 * it obvious which handlers a given deployment can reach.
 *
 * Two Path A types are deliberately absent and throw rather than silently doing
 * nothing:
 *
 *   - `compute:instance` and `compute:instance_template` embed the Nginx
 *     startup script, a large verbatim asset that must be shared with the
 *     Python implementation rather than retyped. Duplicating it would create
 *     two subtly different offload configurations with no test able to see the
 *     difference.
 *   - `secretmanager:secret_version` and `local:root_certificate_artifact`
 *     depend on the WebCrypto certificate work.
 *
 * Both are tracked in the migration plan. An explicit refusal keeps the gap
 * visible; a stub would let Apply report success having built nothing.
 */

import { ProviderExecutionError, type Transport } from "./executor.ts";
import type { ResourceChange } from "../domain/planner.ts";
import { serviceAccountEmail, serviceAccountId } from "../domain/naming.ts";
import type { DeploymentSpec } from "../domain/spec.ts";
import type { CertificateBundle } from "./certificates.ts";
import { offloadStartupScript, sampleBackendStartupScript } from "./startup-scripts.ts";
import { applyProduction } from "./executor-production.ts";

const COMPUTE = "https://compute.googleapis.com/compute/v1";
const SECURE_GATEWAY_SOURCE_RANGE = "136.124.16.0/20";
const MANAGED_BY = "Managed by Secure Gateway Studio";

export interface PathAContext {
  transport: Transport;
  /**
   * Idempotency token for this change.
   *
   * Google deduplicates a create by `requestId`, so a retry after a crash must
   * present the same value or it creates a second resource. The Python
   * implementation derives it from a per-process UUID, which cannot survive a
   * service-worker restart; here it is persisted with the run step instead, so
   * the retry path -- the normal path under Manifest V3 -- stays idempotent.
   */
  requestId: (change: ResourceChange) => string;
  /** Bundle issued earlier in the run, when the plan issues one. */
  certificate?: CertificateBundle;
  /**
   * Hand an artefact to the operator.
   *
   * The local application wrote it to disk at `0600`. An extension has no
   * filesystem, so this is a download the operator saves deliberately -- which
   * also makes the Root Store handoff a visible step rather than a file that
   * silently appeared.
   */
  exportArtifact: (filename: string, contents: string) => Promise<void>;
}

function networkUrl(spec: DeploymentSpec, name: string): string {
  return `${COMPUTE}/projects/${spec.project_id}/global/networks/${name}`;
}

function subnetUrl(spec: DeploymentSpec, name: string): string {
  return `${COMPUTE}/projects/${spec.project_id}/regions/${spec.region}/subnetworks/${name}`;
}

export function networkName(spec: DeploymentSpec): string {
  return spec.network_strategy === "existing" && spec.vpc_name
    ? spec.vpc_name
    : `${spec.name}-vpc`;
}

export function subnetName(spec: DeploymentSpec): string {
  return spec.network_strategy === "existing" && spec.subnet_name
    ? spec.subnet_name
    : `${spec.name}-subnet`;
}

export async function applyPathA(
  context: PathAContext,
  change: ResourceChange,
  spec: DeploymentSpec,
): Promise<void> {
  const { transport } = context;
  const project = spec.project_id;
  const kind = `${change.provider}:${change.resource_type}`;

  const post = async (
    url: string,
    body: Record<string, unknown>,
    withRequestId = true,
  ): Promise<Record<string, unknown>> => {
    const response = await transport.requestJson("POST", url, {
      params: withRequestId ? { requestId: context.requestId(change) } : undefined,
      jsonBody: body,
    });
    return response.payload;
  };

  // Production replaces the single VM with a managed group behind an internal
  // load balancer; those types are handled there and fall through here.
  if (await applyProduction(context, change, spec)) return;

  switch (kind) {
    case "compute:network":
      // Custom mode: automatic subnets would create a subnet in every region,
      // widening the private surface far beyond the one region in the plan.
      await post(`${COMPUTE}/projects/${project}/global/networks`, {
        autoCreateSubnetworks: false,
        description: MANAGED_BY,
        name: change.resource_name,
        routingConfig: { routingMode: "REGIONAL" },
      });
      return;

    case "compute:subnetwork":
      await post(`${COMPUTE}/projects/${project}/regions/${spec.region}/subnetworks`, {
        ipCidrRange: spec.subnet_cidr,
        name: change.resource_name,
        network: networkUrl(spec, networkName(spec)),
        // Lets the VM reach Google APIs without an external IP.
        privateIpGoogleAccess: true,
        stackType: "IPV4_ONLY",
      });
      return;

    case "compute:router":
      await post(`${COMPUTE}/projects/${project}/regions/${spec.region}/routers`, {
        name: change.resource_name,
        network: networkUrl(spec, networkName(spec)),
      });
      return;

    case "compute:cloud_nat": {
      // NAT is a field on the router, not a resource: read the router, add the
      // config, and patch it back so any other NAT on it survives.
      const routerUrl =
        `${COMPUTE}/projects/${project}/regions/${spec.region}/routers/${spec.name}-router`;
      const router = (await transport.requestJson("GET", routerUrl)).payload;
      const nats = Array.isArray(router.nats) ? [...(router.nats as unknown[])] : [];
      nats.push({
        logConfig: { enable: true, filter: "ERRORS_ONLY" },
        name: change.resource_name,
        natIpAllocateOption: "AUTO_ONLY",
        sourceSubnetworkIpRangesToNat: "LIST_OF_SUBNETWORKS",
        subnetworks: [
          {
            name: subnetUrl(spec, subnetName(spec)),
            sourceIpRangesToNat: ["ALL_IP_RANGES"],
          },
        ],
      });
      await transport.requestJson("PATCH", routerUrl, { jsonBody: { nats } });
      return;
    }

    case "iam:service_account":
      await post(
        `https://iam.googleapis.com/v1/projects/${project}/serviceAccounts`,
        {
          accountId: change.resource_name,
          serviceAccount: { displayName: `Secure Gateway Studio ${change.resource_name}` },
        },
        false,
      );
      return;

    case "compute:internal_address":
      await post(`${COMPUTE}/projects/${project}/regions/${spec.region}/addresses`, {
        addressType: "INTERNAL",
        name: change.resource_name,
        subnetwork: subnetUrl(spec, subnetName(spec)),
      });
      return;

    case "compute:firewall_rule": {
      await post(`${COMPUTE}/projects/${project}/global/firewalls`, {
        allowed: [{ IPProtocol: "tcp", ports: ["443"] }],
        direction: "INGRESS",
        logConfig: { enable: true, metadata: "INCLUDE_ALL_METADATA" },
        name: change.resource_name,
        network: networkUrl(spec, networkName(spec)),
        priority: 1000,
        sourceRanges: [SECURE_GATEWAY_SOURCE_RANGE],
        targetServiceAccounts: [
          serviceAccountEmail(spec.name, project, "offload"),
        ],
      });
      return;
    }

    case "dns:private_zone":
      await post(
        `https://dns.googleapis.com/dns/v1/projects/${project}/managedZones`,
        {
          description: MANAGED_BY,
          dnsName: `${spec.private_hostname}.`,
          name: change.resource_name,
          privateVisibilityConfig: {
            networks: [{ networkUrl: networkUrl(spec, networkName(spec)) }],
          },
          visibility: "private",
        },
        false,
      );
      return;

    case "dns:record_set": {
      const address = (await reservedAddress(
        context,
        spec,
        `${spec.name}-offload-ip`,
      )) as string;
      await post(
        `https://dns.googleapis.com/dns/v1/projects/${project}/managedZones/` +
          `${spec.name}-zone/changes`,
        {
          additions: [
            {
              name: `${spec.private_hostname}.`,
              rrdatas: [address],
              ttl: 60,
              type: "A",
            },
          ],
        },
        false,
      );
      return;
    }

    case "secretmanager:secret_iam": {
      // The TLS bundle must be readable by the offload VM's identity and by
      // nothing else, so this grants one role to one service account and
      // preserves every binding already on the secret.
      const secretName =
        spec.certificate_strategy === "public_trusted" && spec.public_certificate_secret
          ? (spec.public_certificate_secret.split("/").pop() as string)
          : `${spec.name}-tls`;
      const resource =
        `https://secretmanager.googleapis.com/v1/projects/${project}/secrets/${secretName}`;
      const policy = (await transport.requestJson("GET", `${resource}:getIamPolicy`))
        .payload as { bindings?: unknown[]; [key: string]: unknown };
      const bindings = Array.isArray(policy.bindings) ? [...policy.bindings] : [];
      bindings.push({
        role: "roles/secretmanager.secretAccessor",
        members: [`serviceAccount:${serviceAccountEmail(spec.name, project, "offload")}`],
      });
      await transport.requestJson("POST", `${resource}:setIamPolicy`, {
        jsonBody: { policy: { ...policy, bindings } },
      });
      return;
    }

    case "compute:instance": {
      const role = change.resource_name.endsWith("-backend") ? "backend" : "offload";
      // Both addresses are read first, in this order, because the offload VM
      // embeds the backend's address in its Nginx upstream.
      const backendAddress = await reservedAddress(
        context,
        spec,
        `${spec.name}-backend-ip`,
        { optional: true },
      );
      const address = await reservedAddress(context, spec, `${spec.name}-${role}-ip`);
      const script =
        role === "backend"
          ? sampleBackendStartupScript(spec)
          : offloadStartupScript(spec, { backendAddress: backendAddress ?? undefined });

      await post(`${COMPUTE}/projects/${project}/zones/${spec.zone}/instances`, {
        deletionProtection: false,
        disks: [
          {
            autoDelete: true,
            boot: true,
            initializeParams: {
              diskSizeGb: "20",
              diskType: `zones/${spec.zone}/diskTypes/pd-balanced`,
              sourceImage:
                spec.source_image ?? "projects/debian-cloud/global/images/family/debian-12",
            },
          },
        ],
        labels: { "managed-by": "secure-gateway-studio", role },
        machineType: `zones/${spec.zone}/machineTypes/e2-small`,
        metadata: {
          items: [
            { key: "startup-script", value: script },
            // The VM writes its own T01-T03 self-test results here; Apply reads
            // them back rather than trusting that the boot succeeded.
            { key: "enable-guest-attributes", value: "TRUE" },
          ],
        },
        name: change.resource_name,
        networkInterfaces: [
          {
            network: networkUrl(spec, networkName(spec)),
            networkIP: address,
            stackType: "IPV4_ONLY",
            subnetwork: subnetUrl(spec, subnetName(spec)),
          },
        ],
        serviceAccounts: [
          {
            email: serviceAccountEmail(spec.name, project, role),
            scopes: ["https://www.googleapis.com/auth/cloud-platform"],
          },
        ],
        shieldedInstanceConfig: {
          enableIntegrityMonitoring: true,
          enableSecureBoot: true,
          enableVtpm: true,
        },
        tags: { items: [change.resource_name] },
      });

      await transport.requestJson(
        "GET",
        `${COMPUTE}/projects/${project}/zones/${spec.zone}/instances/` +
          `${change.resource_name}/getGuestAttributes`,
        { params: { queryPath: "sgstudio/" } },
      );
      return;
    }

    default:
      throw new ProviderExecutionError("unsupported-resource-type");
  }
}

/** The allocated internal address, needed by the VM and the DNS record. */
async function reservedAddress(
  context: PathAContext,
  spec: DeploymentSpec,
  name: string,
  options: { optional?: boolean } = {},
): Promise<string | null> {
  const response = await context.transport.requestJson(
    "GET",
    `${COMPUTE}/projects/${spec.project_id}/regions/${spec.region}/addresses/${name}`,
  );
  const address = response.payload.address;
  if (typeof address !== "string") {
    if (options.optional === true) return null;
    throw new ProviderExecutionError("reserved-address-missing");
  }
  return address;
}

export { serviceAccountId };
