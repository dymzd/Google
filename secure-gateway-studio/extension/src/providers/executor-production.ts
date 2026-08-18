/**
 * Production offload tier: managed instance group and internal load balancer.
 *
 * The PoC path runs a single VM. Production replaces it with a two-zone
 * regional managed instance group behind an internal TCP load balancer, so a
 * zone outage or an instance replacement does not take the gateway down. That
 * is the whole difference, and it is why these handlers exist separately.
 *
 * Two waits here are not optional. The group must report stable with the
 * configured baseline running before the load balancer is pointed at it, and
 * the backend must report healthy before the forwarding rule is considered
 * done -- otherwise Apply reports success while Secure Gateway is still
 * connecting to nothing.
 */

import { ProviderExecutionError, type Transport } from "./executor.ts";
import { secretPayload } from "./certificates.ts";
import { canonicalDigestSync } from "../domain/canonical.ts";
import { configurationHash } from "../domain/planner.ts";
import type { ResourceChange } from "../domain/planner.ts";
import { serviceAccountEmail } from "../domain/naming.ts";
import type { DeploymentSpec } from "../domain/spec.ts";
import { offloadStartupScript } from "./startup-scripts.ts";
import { networkName, subnetName, type PathAContext } from "./executor-path-a.ts";

const COMPUTE = "https://compute.googleapis.com/compute/v1";
const SECRETS = "https://secretmanager.googleapis.com/v1";
const MANAGED_BY = "Managed by Secure Gateway Studio";

function base(spec: DeploymentSpec): string {
  return `${COMPUTE}/projects/${spec.project_id}`;
}

function regional(spec: DeploymentSpec, collection: string): string {
  return `${base(spec)}/regions/${spec.region}/${collection}`;
}

/**
 * Labels that let an operator see, from the Google console alone, which
 * deployment a secret belongs to and whether it is current.
 */
function secretLabels(spec: DeploymentSpec): Record<string, string> {
  const certificateInputs = {
    ca_name: spec.ca_name ?? null,
    ca_pool: spec.ca_pool ?? null,
    certificate_lifetime_days: spec.certificate_lifetime_days,
    certificate_strategy: spec.certificate_strategy,
    private_hostname: spec.private_hostname,
    public_certificate_secret: spec.public_certificate_secret ?? null,
  };
  return {
    "certificate-spec-hash": canonicalDigestSync(certificateInputs).slice(0, 32),
    "configuration-hash": configurationHash(spec).slice(0, 32),
    "managed-by": "secure-gateway-studio",
  };
}

export async function applyProduction(
  context: PathAContext,
  change: ResourceChange,
  spec: DeploymentSpec,
): Promise<boolean> {
  const { transport } = context;
  const kind = `${change.provider}:${change.resource_type}`;

  const post = async (
    url: string,
    body: Record<string, unknown>,
    params?: Record<string, string | number>,
  ): Promise<Record<string, unknown>> =>
    (await transport.requestJson("POST", url, { params, jsonBody: body })).payload;

  switch (kind) {
    case "secretmanager:secret":
      await post(
        `${SECRETS}/projects/${spec.project_id}/secrets`,
        { labels: secretLabels(spec), replication: { automatic: {} } },
        { secretId: change.resource_name },
      );
      return true;

    case "secretmanager:secret_version": {
      // Promotion is deliberately three steps: add the version, then move the
      // `active` alias onto it. The offload VM reads `active`, so the alias
      // move is the moment the rotation takes effect -- and it is atomic, so a
      // half-written rotation cannot leave the VM reading a version that does
      // not exist.
      const bundle = context.certificate;
      if (bundle === undefined) {
        throw new ProviderExecutionError("certificate-not-issued");
      }
      const secretUrl =
        `${SECRETS}/projects/${spec.project_id}/secrets/${change.resource_name}`;

      await transport.requestJson("GET", secretUrl);

      const payload = (
        await transport.requestJson("POST", `${secretUrl}:addVersion`, {
          jsonBody: { payload: { data: base64Utf8(secretPayload(bundle)) } },
        })
      ).payload;
      const versionName = payload.name;
      if (typeof versionName !== "string" || versionName === "") {
        throw new ProviderExecutionError("secret-version-name-missing");
      }
      const version = versionName.split("/").pop() as string;

      const secret = (await transport.requestJson("GET", secretUrl)).payload as {
        etag?: unknown;
        versionAliases?: Record<string, string>;
        labels?: Record<string, string>;
      };
      await transport.requestJson("PATCH", secretUrl, {
        params: { updateMask: "version_aliases,labels" },
        jsonBody: {
          etag: secret.etag,
          labels: { ...(secret.labels ?? {}), ...secretLabels(spec) },
          versionAliases: { ...(secret.versionAliases ?? {}), active: version },
        },
      });
      return true;
    }

    case "local:root_certificate_artifact": {
      // The PoC root is handed to the operator for Chrome Root Store upload;
      // no public API can attest that handoff, which is why T07 verifies it.
      const bundle = context.certificate;
      if (bundle === undefined) {
        throw new ProviderExecutionError("certificate-not-issued");
      }
      if (bundle.certificateChainPem.length !== 1) {
        throw new ProviderExecutionError("local-poc-chain-missing-root");
      }
      await context.exportArtifact(
        `${spec.name}-poc-root.pem`,
        bundle.certificateChainPem[0],
      );
      return true;
    }

    case "compute:instance_template": {
      // The Nginx upstream is the sample backend's reserved address, so it has
      // to be resolved before the template that embeds it.
      const script = offloadStartupScript(spec, {
        backendAddress: await sampleBackendAddress(transport, spec),
      });
      await post(
        `${base(spec)}/global/instanceTemplates`,
        {
          description: MANAGED_BY,
          name: change.resource_name,
          properties: {
            disks: [
              {
                autoDelete: true,
                boot: true,
                initializeParams: {
                  diskSizeGb: "20",
                  // Templates take bare types; only zonal resources are URLs.
                  diskType: "pd-balanced",
                  sourceImage: spec.source_image,
                },
              },
            ],
            labels: { "managed-by": "secure-gateway-studio", role: "offload" },
            machineType: "e2-small",
            metadata: {
              items: [
                { key: "startup-script", value: script },
                { key: "enable-guest-attributes", value: "TRUE" },
              ],
            },
            networkInterfaces: [
              {
                network: `${base(spec)}/global/networks/${networkName(spec)}`,
                stackType: "IPV4_ONLY",
                subnetwork: `${regional(spec, "subnetworks")}/${subnetName(spec)}`,
              },
            ],
            serviceAccounts: [
              {
                email: serviceAccountEmail(spec.name, spec.project_id, "offload"),
                scopes: ["https://www.googleapis.com/auth/cloud-platform"],
              },
            ],
            shieldedInstanceConfig: {
              enableIntegrityMonitoring: true,
              enableSecureBoot: true,
              enableVtpm: true,
            },
            tags: { items: [`${spec.name}-offload`] },
          },
        },
        { requestId: context.requestId(change) },
      );
      return true;
    }

    case "compute:health_check":
      await post(
        regional(spec, "healthChecks"),
        {
          checkIntervalSec: 10,
          healthyThreshold: 2,
          name: change.resource_name,
          // TLS, not HTTP: the offload tier terminates TLS, so an HTTP check
          // would pass against a VM whose certificate never loaded.
          sslHealthCheck: { port: 443 },
          timeoutSec: 5,
          type: "SSL",
          unhealthyThreshold: 3,
        },
        { requestId: context.requestId(change) },
      );
      return true;

    case "compute:instance_group_manager": {
      await post(
        regional(spec, "instanceGroupManagers"),
        {
          baseInstanceName: `${spec.name}-offload`,
          distributionPolicy: {
            targetShape: "EVEN",
            zones: [{ zone: `zones/${spec.zone}` }, { zone: `zones/${spec.secondary_zone}` }],
          },
          name: change.resource_name,
          namedPorts: [{ name: "https", port: 443 }],
          targetSize: spec.offload_min_replicas,
          updatePolicy: {
            // Never drop below the baseline while replacing instances.
            maxSurge: { fixed: 1 },
            maxUnavailable: { fixed: 0 },
            minimalAction: "REPLACE",
            type: "PROACTIVE",
          },
          versions: [
            {
              instanceTemplate:
                `${base(spec)}/global/instanceTemplates/${spec.name}-offload-template`,
              name: "primary",
            },
          ],
        },
        { requestId: context.requestId(change) },
      );
      await waitForStableGroup(transport, spec);
      return true;
    }

    case "compute:autoscaler":
      await post(
        regional(spec, "autoscalers"),
        {
          autoscalingPolicy: {
            coolDownPeriodSec: 90,
            cpuUtilization: { utilizationTarget: spec.offload_cpu_target },
            maxNumReplicas: spec.offload_max_replicas,
            minNumReplicas: spec.offload_min_replicas,
            mode: "ON",
          },
          name: change.resource_name,
          target: `${regional(spec, "instanceGroupManagers")}/${spec.name}-offload-mig`,
        },
        { requestId: context.requestId(change) },
      );
      return true;

    case "compute:backend_service":
      await post(
        regional(spec, "backendServices"),
        {
          backends: [
            { group: `${regional(spec, "instanceGroups")}/${spec.name}-offload-mig` },
          ],
          healthChecks: [`${regional(spec, "healthChecks")}/${spec.name}-offload-hc`],
          loadBalancingScheme: "INTERNAL",
          name: change.resource_name,
          protocol: "TCP",
          timeoutSec: 10,
        },
        { requestId: context.requestId(change) },
      );
      return true;

    case "compute:forwarding_rule": {
      const addressResponse = await transport.requestJson(
        "GET",
        `${regional(spec, "addresses")}/${spec.name}-offload-ip`,
      );
      const address = addressResponse.payload.address;
      if (typeof address !== "string") {
        throw new ProviderExecutionError("reserved-address-missing");
      }
      await post(
        regional(spec, "forwardingRules"),
        {
          IPAddress: address,
          IPProtocol: "TCP",
          // Secure Gateway connects from Google's own range, which is not in
          // this region. Without Global Access the rule refuses that traffic --
          // the failure the Path B gate exists to catch, here by construction.
          allowGlobalAccess: true,
          backendService:
            `${regional(spec, "backendServices")}/${spec.name}-offload-bs`,
          loadBalancingScheme: "INTERNAL",
          name: change.resource_name,
          network: `${base(spec)}/global/networks/${networkName(spec)}`,
          ports: ["443"],
          subnetwork: `${regional(spec, "subnetworks")}/${subnetName(spec)}`,
        },
        { requestId: context.requestId(change) },
      );
      await waitForHealthyBackend(transport, spec);
      return true;
    }

    default:
      return false;
  }
}

/** The sample backend's reserved address, when the deployment creates one. */
async function sampleBackendAddress(
  transport: Transport,
  spec: DeploymentSpec,
): Promise<string | undefined> {
  if (spec.backend_kind !== "managed_sample") return undefined;
  const response = await transport.requestJson(
    "GET",
    `${regional(spec, "addresses")}/${spec.name}-backend-ip`,
  );
  const address = response.payload.address;
  return typeof address === "string" ? address : undefined;
}

/**
 * Wait until the group is stable with the baseline running.
 *
 * Pointing the load balancer at a group that has not finished creating
 * instances produces a deployment that looks applied and serves nothing.
 */
async function waitForStableGroup(transport: Transport, spec: DeploymentSpec): Promise<void> {
  const response = await transport.requestJson(
    "GET",
    `${regional(spec, "instanceGroupManagers")}/${spec.name}-offload-mig`,
  );
  const status = response.payload.status as
    | { isStable?: unknown; currentInstanceStatuses?: { running?: unknown } }
    | undefined;
  const running = Number(status?.currentInstanceStatuses?.running ?? 0);
  if (status?.isStable !== true || running < spec.offload_min_replicas) {
    // The caller reschedules; under Manifest V3 waiting is an alarm, not a loop.
    throw new ProviderExecutionError("managed-instance-group-not-stable");
  }
}

async function waitForHealthyBackend(
  transport: Transport,
  spec: DeploymentSpec,
): Promise<void> {
  const response = await transport.requestJson(
    "POST",
    `${regional(spec, "backendServices")}/${spec.name}-offload-bs/getHealth`,
    {
      jsonBody: {
        group: `${regional(spec, "instanceGroups")}/${spec.name}-offload-mig`,
      },
    },
  );
  const states = response.payload.healthStatus;
  const healthy = Array.isArray(states)
    ? states.filter((entry) => (entry as { healthState?: unknown }).healthState === "HEALTHY")
        .length
    : 0;
  if (healthy < spec.offload_min_replicas) {
    throw new ProviderExecutionError("offload-backend-not-healthy");
  }
}

/** UTF-8 aware base64, since btoa alone mangles non-ASCII. */
function base64Utf8(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
