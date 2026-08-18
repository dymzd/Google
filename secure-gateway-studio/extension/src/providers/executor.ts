/**
 * Resource executor. Port of `providers/google_executor.py`, Path B range.
 *
 * What this module produces is a sequence of HTTP requests, so that is what the
 * golden set pins: for a given change and specification, the same requests, in
 * the same order, with the same bodies. Comparing plans alone would not catch a
 * reordered IAM read/write, a missing egress policy, or the wrong project in an
 * upstream network path -- each of which is a materially different deployment.
 *
 * Two behaviours are load-bearing and easy to lose in a port:
 *
 *   - **IAM is read-modify-write with the returned etag.** Dropping the etag
 *     turns a concurrent policy edit into a silent overwrite of someone else's
 *     binding. The before-image is retained for rollback.
 *   - **Chrome Policy schemas are discovered, not assumed.** The Python
 *     implementation fetches the schema and asserts the field exists before
 *     writing. A schema change then surfaces as a refusal rather than a policy
 *     written into the wrong field.
 *
 * Path A resource types are not handled; they land in Phase 4 and reaching one
 * throws rather than silently doing nothing.
 */

import { canonicalJson } from "../domain/canonical.ts";
import { applyPathA } from "./executor-path-a.ts";
import type { CertificateBundle } from "./certificates.ts";
import { DIRECT_HTTPS_APIS, REQUIRED_APIS } from "../domain/constants.generated.ts";
import type { ResourceChange } from "../domain/planner.ts";
import {
  applicationHostname,
  applicationPort,
  iamMember,
  upstreamProjectId,
  type DeploymentSpec,
} from "../domain/spec.ts";
import { ensureManagedChromeAccessLevel } from "./catalog.ts";
import { bootstrapSampleBackend } from "./sample-backend.ts";

const SECURE_ENTERPRISE_BROWSER = "ekajlcmdfcigmdbphhifahdfjbkciflj";

export class ProviderExecutionError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "ProviderExecutionError";
    this.code = code;
  }
}

export interface TransportResponse {
  status: number;
  payload: Record<string, unknown>;
}

export interface Transport {
  requestJson(
    method: string,
    url: string,
    options?: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
    },
  ): Promise<TransportResponse>;
}

interface IamPolicy {
  version?: number;
  etag?: string;
  bindings?: IamBinding[];
  [key: string]: unknown;
}

interface IamBinding {
  role: string;
  members: string[];
  condition?: { title: string; description: string; expression: string };
}

export class GoogleResourceExecutor {
  private readonly transport: Transport;
  private readonly before = new Map<string, unknown>();
  private gatewayServiceAccount: string | null = null;

  private readonly requestIds: (change: ResourceChange) => string;
  private readonly exportArtifact: (filename: string, contents: string) => Promise<void>;
  /** Set once the run issues a certificate; reused by every step that needs it. */
  certificate: CertificateBundle | undefined;

  constructor(
    transport: Transport,
    options: {
      requestId?: (change: ResourceChange) => string;
      exportArtifact?: (filename: string, contents: string) => Promise<void>;
      certificate?: CertificateBundle;
    } = {},
  ) {
    this.transport = transport;
    // Google deduplicates creates by requestId, so a retry must present the
    // same token. The run engine supplies one persisted with the step; the
    // fallback only covers callers that never retry.
    this.requestIds = options.requestId ?? (() => crypto.randomUUID());
    this.exportArtifact = options.exportArtifact ?? defaultExportArtifact;
    this.certificate = options.certificate;
  }

  private pathAContext() {
    return {
      transport: this.transport,
      requestId: this.requestIds,
      certificate: this.certificate,
      exportArtifact: this.exportArtifact,
    };
  }

  async apply(change: ResourceChange, spec: DeploymentSpec): Promise<void> {
    const kind = `${change.provider}:${change.resource_type}`;
    switch (kind) {
      case "serviceusage:project_services":
        return this.enableServices(spec);
      case "compute:network":
        if (spec.backend_kind === "direct_https" && spec.vpc_name === "secgw-test-vpc") {
          try {
            await bootstrapSampleBackend(spec.project_id, {
              transport: this.transport,
              region: spec.application_egress_region || "asia-northeast1",
            });
            return;
          } catch (e) {
            console.warn("[SGS Executor] Sample backend bootstrap notice:", e);
          }
        }
        return applyPathA(this.pathAContext(), change, spec);
      case "compute:subnetwork":
      case "compute:router":
      case "compute:cloud_nat":
      case "iam:service_account":
      case "compute:internal_address":
      case "compute:firewall_rule":
      case "dns:private_zone":
      case "dns:record_set":
      case "secretmanager:secret_iam":
      case "compute:instance":
      case "compute:instance_template":
      case "secretmanager:secret":
      case "secretmanager:secret_version":
      case "local:root_certificate_artifact":
        return applyPathA(this.pathAContext(), change, spec);
      case "accesscontextmanager:access_level":
        // Reused, never created. The planner marks it must-exist, so a missing
        // one is a conflict at plan time rather than an apply failure.
        return;
      case "beyondcorp:security_gateway":
        return this.createGateway(change, spec);
      case "beyondcorp:gateway_iam":
        return this.setGatewayIam(change, spec);
      case "cloudresourcemanager:project_iam":
        return this.setUpstreamAccess(change, spec);
      case "beyondcorp:application":
        return this.createApplication(change, spec);
      case "beyondcorp:application_iam":
        return this.setApplicationIam(change, spec);
      case "chromepolicy:extension_install":
        return this.setChromeInstall(change, spec);
      case "chromepolicy:extension_configuration":
        return this.setChromeConfiguration(change, spec);
      case "chromepolicy:service_discovery_proxy":
        return this.setServiceDiscoveryProxy(change, spec);
      default:
        // Everything else belongs to the Nginx offload path.
        return applyPathA(this.pathAContext(), change, spec);
    }
  }

  private async request(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      body?: Record<string, unknown>;
    } = {},
  ): Promise<Record<string, unknown>> {
    const response = await this.transport.requestJson(method, url, {
      params: options.params,
      jsonBody: options.body,
    });
    return response.payload;
  }

  private gatewayResource(spec: DeploymentSpec): string {
    return (
      `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
      `/locations/global/securityGateways/${spec.gateway_id}`
    );
  }

  private key(change: ResourceChange): string {
    return `${change.provider}:${change.resource_type}:${change.resource_name}`;
  }

  private async enableServices(spec: DeploymentSpec): Promise<void> {
    const services =
      spec.backend_kind === "direct_https" ? DIRECT_HTTPS_APIS : REQUIRED_APIS;
    await this.request(
      "POST",
      `https://serviceusage.googleapis.com/v1/projects/${spec.project_id}/services:batchEnable`,
      { body: { serviceIds: [...services].sort() } },
    );
  }

  private async createGateway(change: ResourceChange, spec: DeploymentSpec): Promise<void> {
    const parent =
      `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
      "/locations/global/securityGateways";
    await this.request("POST", parent, {
      params: { security_gateway_id: change.resource_name },
      body: { display_name: change.resource_name, service_discovery: {} },
    });
    // Read back: the delegating service account is assigned by the service and
    // is needed before the upstream-access binding can be written.
    const gateway = await this.request("GET", `${parent}/${change.resource_name}`);
    const account = gateway.delegatingServiceAccount;
    if (typeof account === "string") this.gatewayServiceAccount = account;
  }

  /**
   * Read-modify-write an IAM policy, preserving the etag and every binding the
   * deployment does not own.
   */
  private async setIam(
    change: ResourceChange,
    options: {
      getUrl: string;
      setUrl: string;
      role: string;
      members: string[];
      version?: number;
      condition?: IamBinding["condition"];
      getMethod?: string;
    },
  ): Promise<void> {
    // Resource Manager reads its policy with POST and an empty body; BeyondCorp
    // reads with GET. Sending no body on the POST form is a different request.
    const getMethod = options.getMethod ?? "GET";
    const policy = (await this.request(getMethod, options.getUrl, {
      body: getMethod === "POST" ? {} : undefined,
    })) as IamPolicy;
    this.before.set(this.key(change), structuredClone(policy));

    const bindings: IamBinding[] = [...(policy.bindings ?? [])];
    const binding: IamBinding = { role: options.role, members: options.members };
    if (options.condition) binding.condition = options.condition;
    bindings.push(binding);

    const updated: IamPolicy = {
      ...policy,
      bindings,
      version: options.version ?? policy.version ?? 1,
    };
    await this.request("POST", options.setUrl, { body: { policy: updated } });
  }

  private principalMembers(spec: DeploymentSpec): string[] {
    return spec.principals.map(iamMember);
  }

  private async setGatewayIam(change: ResourceChange, spec: DeploymentSpec): Promise<void> {
    const resource = this.gatewayResource(spec);
    await this.setIam(change, {
      getUrl: `${resource}:getIamPolicy`,
      setUrl: `${resource}:setIamPolicy`,
      role: "roles/beyondcorp.serviceDiscoveryUser",
      members: this.principalMembers(spec),
    });
  }

  private async setUpstreamAccess(
    change: ResourceChange,
    spec: DeploymentSpec,
  ): Promise<void> {
    if (this.gatewayServiceAccount === null) {
      const gateway = await this.request("GET", this.gatewayResource(spec));
      const account = gateway.delegatingServiceAccount;
      if (typeof account !== "string") {
        throw new ProviderExecutionError("gateway-missing-delegating-account");
      }
      this.gatewayServiceAccount = account;
    }
    // The binding belongs to the project owning the upstream VPC, which for a
    // cross-project upstream is not the deployment project.
    const resource =
      "https://cloudresourcemanager.googleapis.com/v1/projects/" +
      upstreamProjectId(spec);
    await this.setIam(change, {
      getUrl: `${resource}:getIamPolicy`,
      setUrl: `${resource}:setIamPolicy`,
      getMethod: "POST",
      role: "roles/beyondcorp.upstreamAccess",
      members: [`serviceAccount:${this.gatewayServiceAccount}`],
    });
  }

  private async createApplication(
    change: ResourceChange,
    spec: DeploymentSpec,
  ): Promise<void> {
    const parent = `${this.gatewayResource(spec)}/applications`;
    const upstream: Record<string, unknown> = {
      network: {
        name: `projects/${upstreamProjectId(spec)}/global/networks/${spec.vpc_name}`,
      },
    };
    if (spec.backend_kind === "direct_https" && spec.application_egress_region) {
      upstream.egress_policy = { regions: [spec.application_egress_region] };
    }
    await this.request("POST", parent, {
      params: { application_id: change.resource_name },
      body: {
        display_name: change.resource_name,
        endpoint_matchers: [
          { hostname: applicationHostname(spec), ports: [applicationPort(spec)] },
        ],
        upstreams: [upstream],
      },
    });
  }

  private async setApplicationIam(
    change: ResourceChange,
    spec: DeploymentSpec,
  ): Promise<void> {
    const resource = `${this.gatewayResource(spec)}/applications/${spec.name}-app`;
    let level = spec.managed_chrome_access_level;
    if (level && level.startsWith("AUTO_CREATE_")) {
      const kind = level.includes("BROWSER") ? "browser" : level.includes("ANY") ? "any" : "profile";
      try {
        level = await ensureManagedChromeAccessLevel(this.transport, spec.project_id, kind);
      } catch (e) {
        console.warn("[SGS Executor] Could not auto-create access level:", e);
      }
    }
    const condition =
      level && level !== "NONE"
        ? {
            title: "Managed Chrome required",
            description: "Allow only profiles or browsers managed by this enterprise",
            expression: `'${level}' in request.auth.access_levels`,
          }
        : undefined;
    await this.setIam(change, {
      getUrl: `${resource}:getIamPolicy`,
      setUrl: `${resource}:setIamPolicy`,
      role: "roles/beyondcorp.sgApplicationUser",
      members: this.principalMembers(spec),
      version: 3,
      condition,
    });
  }

  // -- Chrome Policy ----------------------------------------------------------

  private async chromeSchema(
    spec: DeploymentSpec,
    schemaName: string,
  ): Promise<Record<string, unknown>> {
    return this.request(
      "GET",
      `https://chromepolicy.googleapis.com/v1/customers/${spec.customer_id}` +
        `/policySchemas/${schemaName}`,
    );
  }

  /**
   * Refuse to write a field the live schema does not advertise.
   *
   * Chrome Policy schemas change. Assuming a field would write a policy that
   * silently does nothing; this turns that into a refusal.
   */
  private assertSchemaField(schema: Record<string, unknown>, field: string): void {
    const definition = schema.definition as
      | { messageType?: { field?: { name?: string }[] }[] }
      | undefined;
    const fields = (definition?.messageType ?? []).flatMap(
      (message) => message.field ?? [],
    );
    if (!fields.some((entry) => entry.name === field)) {
      throw new ProviderExecutionError(`chrome-policy-schema-missing-${field}`);
    }
  }

  private async resolveChromePolicy(
    spec: DeploymentSpec,
    schemaName: string,
    appId: string | null,
  ): Promise<Record<string, unknown>> {
    const targetKey: Record<string, unknown> = {
      targetResource: `orgunits/${spec.target_ou_id}`,
    };
    if (appId !== null) targetKey.additionalTargetKeys = { app_id: `chrome:${appId}` };
    return this.request(
      "POST",
      `https://chromepolicy.googleapis.com/v1/customers/${spec.customer_id}/policies:resolve`,
      { body: { policySchemaFilter: schemaName, policyTargetKey: targetKey } },
    );
  }

  private async batchModify(
    spec: DeploymentSpec,
    schemaName: string,
    field: string,
    value: unknown,
    appId: string | null,
  ): Promise<void> {
    const targetKey: Record<string, unknown> = {
      targetResource: `orgunits/${spec.target_ou_id}`,
    };
    if (appId !== null) targetKey.additionalTargetKeys = { app_id: `chrome:${appId}` };
    await this.request(
      "POST",
      `https://chromepolicy.googleapis.com/v1/customers/${spec.customer_id}` +
        "/policies/orgunits:batchModify",
      {
        body: {
          requests: [
            {
              policyTargetKey: targetKey,
              policyValue: { policySchema: schemaName, value: { [field]: value } },
              updateMask: { paths: [field] },
            },
          ],
        },
      },
    );
  }

  private async chromePolicy(
    change: ResourceChange,
    spec: DeploymentSpec,
    options: { schemaName: string; field: string; value: unknown; appId: string | null },
  ): Promise<void> {
    const schema = await this.chromeSchema(spec, options.schemaName);
    this.assertSchemaField(schema, options.field);
    const previous = await this.resolveChromePolicy(spec, options.schemaName, options.appId);
    this.before.set(this.key(change), { schema: options.schemaName, previous });
    await this.batchModify(spec, options.schemaName, options.field, options.value, options.appId);
  }

  private setChromeInstall(change: ResourceChange, spec: DeploymentSpec): Promise<void> {
    return this.chromePolicy(change, spec, {
      schemaName: "chrome.users.apps.InstallType",
      field: "appInstallType",
      value: "FORCED",
      appId: change.resource_name,
    });
  }

  private setChromeConfiguration(
    change: ResourceChange,
    spec: DeploymentSpec,
  ): Promise<void> {
    const configuration = canonicalJson({
      securityGateway: {
        Value: {
          authentication: {},
          context: {
            resource:
              `projects/${spec.project_id}/locations/global/` +
              `securityGateways/${spec.gateway_id}`,
          },
          serviceDiscovery: { routes: {} },
        },
      },
    });
    return this.chromePolicy(change, spec, {
      schemaName: "chrome.users.apps.ManagedConfiguration",
      field: "managedConfiguration",
      value: configuration,
      appId: SECURE_ENTERPRISE_BROWSER,
    });
  }

  private setServiceDiscoveryProxy(
    change: ResourceChange,
    spec: DeploymentSpec,
  ): Promise<void> {
    return this.chromePolicy(change, spec, {
      schemaName: "chrome.users.SimpleProxySettings",
      field: "simpleProxyMode",
      value: "PROXY_MODE_ENUM_USER_CONFIGURED",
      appId: null,
    });
  }
}

/**
 * Hand an artefact to the operator as a download.
 *
 * The local application wrote it to disk at `0600`. An extension has no
 * filesystem, so the operator saves it deliberately -- which also makes the
 * Root Store handoff a visible step rather than a file that silently appeared.
 */
async function defaultExportArtifact(filename: string, contents: string): Promise<void> {
  const url = `data:application/x-pem-file;base64,${btoa(contents)}`;
  await chrome.downloads.download({ url, filename, saveAs: true });
}
