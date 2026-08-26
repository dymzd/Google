/**
 * Discovery parity against the Python reference.
 *
 * Replays each recorded scenario through the ported discovery provider and
 * compares both halves of the contract:
 *
 *   - the request sequence, because a probe the extension skips is an existing
 *     resource it will then try to create, and
 *   - the assembled snapshot, because that is what decides whether a gate
 *     passes and therefore whether Apply is offered.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-discovery.ts
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve as resolvePath } from "node:path";

import { canonicalDigestSync, canonicalJson } from "../src/domain/canonical.ts";
import {
  crc32c,
  discoveryOwnershipProofs,
  GoogleDiscoveryProvider,
  isCanonicalManagedChromeAccessLevel,
} from "../src/providers/discovery.ts";
import { GoogleApiError, type Transport } from "../src/providers/executor.ts";
import { parseDeploymentSpec } from "../src/domain/spec.ts";
import { buildPlan } from "../src/domain/planner.ts";
import { configurationHash } from "../src/domain/planner.ts";
import { serviceAccountEmail, serviceAccountId } from "../src/domain/naming.ts";
import { issueLocalPoc, secretPayload } from "../src/providers/certificates.ts";
import { validateLicenseAssignment } from "../src/providers/licensing.ts";
import {
  offloadStartupScript,
  sampleBackendStartupScript,
} from "../src/providers/startup-scripts.ts";

interface RecordedRequest {
  method: string;
  url: string;
  params: Record<string, string | number> | null;
  body: Record<string, unknown> | null;
}

interface Scenario {
  name: string;
  spec: Record<string, unknown>;
  requests: RecordedRequest[];
  snapshot: Record<string, unknown>;
}

const goldenPath = resolvePath(
  dirname(fileURLToPath(import.meta.url)),
  "../../backend/tests/fixtures/discovery/golden.json",
);

const ENABLED = [
  "accesscontextmanager.googleapis.com",
  "admin.googleapis.com",
  "beyondcorp.googleapis.com",
  "chromemanagement.googleapis.com",
  "chromepolicy.googleapis.com",
  "cloudbilling.googleapis.com",
  "cloudresourcemanager.googleapis.com",
  "compute.googleapis.com",
  "iamcredentials.googleapis.com",
  "licensing.googleapis.com",
  "logging.googleapis.com",
  "serviceusage.googleapis.com",
];
const IMMUTABLE_SOURCE_IMAGE =
  "projects/enterprise-secgw-01/global/images/sgs-nginx-20260824";

function licenseAssignment(
  userId: string,
  host = "licensing.googleapis.com",
): Record<string, unknown> {
  return {
    kind: "licensing#licenseAssignment",
    productId: "101040",
    skuId: "1010400001",
    userId,
    selfLink:
      `https://${host}/apps/licensing/v1/product/101040/` +
      `sku/1010400001/user/${encodeURIComponent(userId)}`,
  };
}

for (const host of ["licensing.googleapis.com", "www.googleapis.com"]) {
  try {
    validateLicenseAssignment(licenseAssignment("user@example.com", host), {
      productId: "101040",
      skuId: "1010400001",
      userId: "user@example.com",
    });
  } catch (error) {
    throw new Error(`License selfLink official host rejected: ${host}: ${String(error)}`);
  }
}
try {
  validateLicenseAssignment(licenseAssignment("user@example.com", "example.com"), {
    productId: "101040",
    skuId: "1010400001",
    userId: "user@example.com",
  });
  throw new Error("License selfLink untrusted host was accepted");
} catch (error) {
  if (String(error).includes("untrusted host was accepted")) throw error;
}

/** Mirrors the Python RecordingTransport's fixed environment. */
class ReplayTransport implements Transport {
  readonly calls: RecordedRequest[] = [];
  // Explicit fields rather than parameter properties: Node's strip-only type
  // removal cannot desugar those, and the parity checks must keep running
  // with no build step.
  private readonly globalAccess: boolean | null;
  private readonly matcherIp: string | null;

  constructor(globalAccess: boolean | null, matcherIp: string | null) {
    this.globalAccess = globalAccess;
    this.matcherIp = matcherIp;
  }

  async requestJson(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
    } = {},
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    this.calls.push({
      method,
      url,
      params: options.params ?? null,
      body: options.jsonBody ?? null,
    });

    if (url.includes("serviceusage.googleapis.com")) {
      return {
        status: 200,
        payload: { services: ENABLED.map((name) => ({ config: { name } })) },
      };
    }
    if (url.endsWith(":testIamPermissions")) {
      return {
        status: 200,
        payload: { permissions: (options.jsonBody?.permissions as string[]) ?? [] },
      };
    }
    if (url.includes("cloudbilling.googleapis.com")) {
      return { status: 200, payload: { billingEnabled: true } };
    }
    if (url.includes("admin.googleapis.com") && url.includes("/orgunits/id%3A")) {
      return {
        status: 200,
        payload: { orgUnitId: "id:03-test-ou", orgUnitPath: "/Secure Gateway Test" },
      };
    }
    if (url.includes("/aggregated/forwardingRules")) {
      if (this.matcherIp === null || this.globalAccess === null) {
        return { status: 200, payload: { items: {} } };
      }
      return {
        status: 200,
        payload: {
          items: {
            "regions/asia-east1": {
              forwardingRules: [
                {
                  name: "app-ilb-fr",
                  IPAddress: this.matcherIp,
                  allowGlobalAccess: this.globalAccess,
                  loadBalancingScheme: "INTERNAL_MANAGED",
                  IPProtocol: "TCP",
                  ports: ["8443"],
                },
              ],
            },
          },
        },
      };
    }
    if (url.includes("/global/networks/")) {
      return { status: 200, payload: { name: url.split("/").pop() ?? "" } };
    }
    if (url.includes("accesscontextmanager.googleapis.com")) {
      return {
        status: 200,
        payload: { name: "accessPolicies/123456789/accessLevels/managed_chrome" },
      };
    }
    if (url.includes("/securityGateways/")) {
      return { status: 404, payload: {} };
    }
    if (url.includes("chromepolicy")) {
      return { status: 200, payload: { resolvedPolicies: [] } };
    }
    if (
      url.includes("chromemanagement") ||
      url.includes("licensing") ||
      url.includes("admin.googleapis.com")
    ) {
      return { status: 200, payload: {} };
    }
    return { status: 404, payload: {} };
  }
}

const SETTINGS: Record<string, { globalAccess: boolean | null; matcherIp: string | null }> = {
  "global-access-enabled": { globalAccess: true, matcherIp: "10.20.0.10" },
  "global-access-disabled": { globalAccess: false, matcherIp: "10.20.0.10" },
  "fqdn-matcher-unresolvable": { globalAccess: null, matcherIp: null },
  "cross-project-upstream": { globalAccess: true, matcherIp: "10.20.0.10" },
};

const golden = JSON.parse(readFileSync(goldenPath, "utf8")) as { scenarios: Scenario[] };
const failures: string[] = [];
let comparedRequests = 0;

for (const scenario of golden.scenarios) {
  const spec = parseDeploymentSpec(scenario.spec);
  const settings = SETTINGS[scenario.name];
  const transport = new ReplayTransport(settings.globalAccess, settings.matcherIp);
  const provider = new GoogleDiscoveryProvider(transport, {
    cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
  });

  const result = await provider.preflight(spec);

  const expectedRequests = scenario.requests;
  if (transport.calls.length !== expectedRequests.length) {
    failures.push(
      `${scenario.name}: request count ${expectedRequests.length} vs ${transport.calls.length}\n` +
        `    reference ${expectedRequests.map((r) => `${r.method} ${r.url}`).join("\n              ")}\n` +
        `    extension ${transport.calls.map((r) => `${r.method} ${r.url}`).join("\n              ")}`,
    );
  } else {
    for (const [index, expected] of expectedRequests.entries()) {
      const produced = transport.calls[index];
      comparedRequests += 1;
      if (expected.method !== produced.method || expected.url !== produced.url) {
        failures.push(
          `${scenario.name} request[${index}]: target\n` +
            `    python    ${expected.method} ${expected.url}\n` +
            `    extension ${produced.method} ${produced.url}`,
        );
        continue;
      }
      if (canonicalJson(expected.params ?? null) !== canonicalJson(produced.params ?? null)) {
        failures.push(
          `${scenario.name} request[${index}]: params\n` +
            `    python    ${canonicalJson(expected.params ?? null)}\n` +
            `    extension ${canonicalJson(produced.params ?? null)}`,
        );
      }
      if (canonicalJson(expected.body ?? null) !== canonicalJson(produced.body ?? null)) {
        failures.push(
          `${scenario.name} request[${index}]: body\n` +
            `    python    ${canonicalJson(expected.body ?? null)}\n` +
            `    extension ${canonicalJson(produced.body ?? null)}`,
        );
      }
    }
  }

  // Snapshot fields the planner actually reads. Comparing the whole object
  // would also assert on fields Path B never populates.
  for (const field of [
    "existing_resource_keys",
    "conflicting_resource_keys",
    "enabled_apis",
    "granted_permissions",
    "billing_enabled",
    "cloud_identity",
    "application_global_access",
    "application_forwarding_rule",
    "application_global_access_discovery_complete",
    "chrome_extension_group_conflicts",
    "chrome_group_policy_discovery_complete",
    "chrome_enterprise_premium_license_count",
    "managed_chrome_profile_count",
    "secure_enterprise_browser_installed",
    "endpoint_verification_installed",
    "public_certificate_binding",
  ]) {
    const expected = scenario.snapshot[field] ?? null;
    const produced = (result.snapshot as Record<string, unknown>)[field] ?? null;
    if (canonicalJson(expected) !== canonicalJson(produced)) {
      failures.push(
        `${scenario.name} snapshot.${field}\n` +
          `    python    ${canonicalJson(expected)}\n` +
          `    extension ${canonicalJson(produced)}`,
      );
    }
  }
}

class PaginatedWorkspaceTransport extends ReplayTransport {
  readonly profileParams: Record<string, string | number>[] = [];
  readonly licenseParams: Record<string, string | number>[] = [];
  private readonly license404: boolean;

  constructor(license404 = false) {
    super(true, "10.20.0.10");
    this.license404 = license404;
  }

  override async requestJson(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    if (url.includes("chromemanagement.googleapis.com")) {
      const params = options.params ?? {};
      this.profileParams.push(params);
      this.calls.push({ method, url, params, body: options.jsonBody ?? null });
      if (params.pageToken === "profiles-2") {
        return {
          status: 200,
          payload: {
            chromeBrowserProfiles: [
              {
                affiliationState: "BROWSER_MANAGED",
                lastPolicySyncTime: "2026-08-03T07:15:16Z",
                reportingData: {
                  extensionData: [
                    {
                      extensionId: "ekajlcmdfcigmdbphhifahdfjbkciflj",
                      version: "1.26.129",
                      isDisabled: false,
                    },
                  ],
                },
              },
            ],
          },
        };
      }
      return {
        status: 200,
        payload: {
          chromeBrowserProfiles: [
            {
              affiliationState: "PROFILE_ONLY",
              lastPolicySyncTime: "2026-08-04T08:00:00Z",
              reportingData: {
                extensionData: [
                  {
                    extensionId: "callobklhcbilhphinckomhgkigmfocg",
                    version: "1.140.0",
                    isDisabled: false,
                  },
                ],
              },
            },
          ],
          nextPageToken: "profiles-2",
        },
      };
    }
    if (url.includes("licensing.googleapis.com")) {
      const params = options.params ?? {};
      this.licenseParams.push(params);
      this.calls.push({ method, url, params, body: options.jsonBody ?? null });
      if (this.license404) return { status: 404, payload: {} };
      if (params.pageToken === "licenses-2") {
        return {
          status: 200,
          payload: { items: [licenseAssignment("three@example.com")] },
        };
      }
      return {
        status: 200,
        payload: {
          items: [
            licenseAssignment("one@example.com"),
            licenseAssignment("two@example.com"),
          ],
          nextPageToken: "licenses-2",
        },
      };
    }
    return super.requestJson(method, url, options);
  }
}

class RepeatedProfileTokenTransport extends PaginatedWorkspaceTransport {
  override async requestJson(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    if (url.includes("chromemanagement.googleapis.com")) {
      const params = options.params ?? {};
      this.profileParams.push(params);
      this.calls.push({ method, url, params, body: options.jsonBody ?? null });
      return {
        status: 200,
        payload: {
          chromeBrowserProfiles: [{}],
          nextPageToken: String(params.pageToken ?? "profiles-loop"),
        },
      };
    }
    return super.requestJson(method, url, options);
  }
}

{
  const spec = parseDeploymentSpec(golden.scenarios[0].spec);
  const transport = new PaginatedWorkspaceTransport();
  const result = await new GoogleDiscoveryProvider(transport, {
    cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
  }).preflight(spec);
  const snapshot = result.snapshot;
  const assertions: Array<[string, boolean]> = [
    ["profile pagination follows nextPageToken", transport.profileParams[1]?.pageToken === "profiles-2"],
    ["profile pagination counts every page", snapshot.managed_chrome_profile_count === 2],
    ["profile-only count uses affiliationState", snapshot.profile_only_count === 1],
    ["latest sync is selected across pages", snapshot.latest_chrome_policy_sync === "2026-08-04T08:00:00Z"],
    ["Endpoint Verification comes from reportingData", snapshot.endpoint_verification_version === "1.140.0"],
    ["Secure Enterprise Browser comes from reportingData", snapshot.secure_enterprise_browser_version === "1.26.129"],
    ["license pagination follows nextPageToken", transport.licenseParams[1]?.pageToken === "licenses-2"],
    ["license pagination counts every page", snapshot.chrome_enterprise_premium_license_count === 3],
  ];
  for (const [name, condition] of assertions) {
    if (!condition) failures.push(`workspace signals: ${name}`);
  }
}

const DISCOVERY_OWNER = "123e4567-e89b-42d3-a456-426614174000";
const DISCOVERY_MARKER = `Secure Gateway Studio ownership-token=${DISCOVERY_OWNER}`;

function pathAOwnershipProofs(
  spec: ReturnType<typeof parseDeploymentSpec>,
): Record<string, { marker: string | null; providerIdentityField?: string; providerIdentity?: string }> {
  const prefix = spec.name;
  const marker = (suffix = "") => ({ marker: `${DISCOVERY_MARKER}${suffix}` });
  const proofs: Record<string, { marker: string | null; providerIdentityField?: string; providerIdentity?: string }> = {
    [`compute:network:${prefix}-vpc`]: marker("; Managed by Secure Gateway Studio"),
    [`compute:subnetwork:${prefix}-subnet`]: marker(),
    [`compute:router:${prefix}-router`]: marker(),
    [`compute:cloud_nat:${prefix}-nat`]: { marker: null },
    [`iam:service_account:${serviceAccountId(prefix, "offload")}`]: marker(),
    [`iam:service_account:${serviceAccountId(prefix, "backend")}`]: marker(),
    [`secretmanager:secret:${prefix}-tls`]: { marker: DISCOVERY_OWNER },
    [`secretmanager:secret_version:${prefix}-tls`]: {
      marker: DISCOVERY_OWNER,
      providerIdentityField: "versionName",
      providerIdentity: `projects/${spec.project_id}/secrets/${prefix}-tls/versions/7`,
    },
    [`secretmanager:secret_iam:${prefix}-tls-accessor`]: { marker: null },
    [`compute:internal_address:${prefix}-offload-ip`]: marker(),
    [`compute:internal_address:${prefix}-backend-ip`]: marker(),
    [`compute:instance:${prefix}-offload`]: marker(),
    [`compute:instance:${prefix}-backend`]: marker(),
    [`compute:instance_template:${prefix}-offload-template`]: marker(
      "; Managed by Secure Gateway Studio",
    ),
    [`compute:health_check:${prefix}-offload-hc`]: marker(),
    [`compute:instance_group_manager:${prefix}-offload-mig`]: marker(),
    [`compute:autoscaler:${prefix}-offload-autoscaler`]: marker(),
    [`compute:backend_service:${prefix}-offload-bs`]: marker(),
    [`compute:forwarding_rule:${prefix}-offload-fr`]: marker(),
    [`compute:firewall_rule:${prefix}-gateway-ingress`]: marker(),
    [`compute:firewall_rule:${prefix}-health-check-ingress`]: marker(),
    [`compute:firewall_rule:${prefix}-backend-ingress`]: marker(),
    [`dns:private_zone:${prefix}-zone`]: marker(),
    [`dns:record_set:${spec.private_hostname}`]: { marker: `"sgs-owner=${DISCOVERY_OWNER}"` },
    [`beyondcorp:security_gateway:${spec.gateway_id}`]: {
      marker: null,
      providerIdentityField: "createTime",
      providerIdentity: "2026-08-24T00:00:01Z",
    },
    [`beyondcorp:application:${prefix}-app`]: {
      marker: null,
      providerIdentityField: "createTime",
      providerIdentity: "2026-08-24T00:00:02Z",
    },
  };
  return proofs;
}

class PathAExistingTransport extends ReplayTransport {
  private readonly spec: ReturnType<typeof parseDeploymentSpec>;
  private readonly encodedSecret: string;
  private readonly secretCrc: number;
  private readonly drift:
    | "none"
    | "vm-startup"
    | "vm-machine"
    | "template-startup"
    | "mig-template"
    | "health-nondefault"
    | "firewall-network"
    | "forwarding-ip";

  constructor(
    spec: ReturnType<typeof parseDeploymentSpec>,
    secret: string,
    drift: PathAExistingTransport["drift"] = "none",
  ) {
    super(null, null);
    this.spec = spec;
    const bytes = new TextEncoder().encode(secret);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    this.encodedSecret = btoa(binary);
    this.secretCrc = crc32c(bytes);
    this.drift = drift;
  }

  override async requestJson(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    const spec = this.spec;
    const project = spec.project_id;
    const prefix = spec.name;
    const record = (payload: Record<string, unknown>, status = 200) => {
      this.calls.push({ method, url, params: options.params ?? null, body: options.jsonBody ?? null });
      return { status, payload };
    };
    const computeDescription = { description: DISCOVERY_MARKER };
    const networkUrl =
      `https://compute.googleapis.com/compute/v1/projects/${project}` +
      `/global/networks/${prefix}-vpc`;
    const dnsNetworkUrl =
      `https://www.googleapis.com/compute/v1/projects/${project}` +
      `/global/networks/${prefix}-vpc`;
    const subnetUrl =
      `https://compute.googleapis.com/compute/v1/projects/${project}/regions/${spec.region}` +
      `/subnetworks/${prefix}-subnet`;
    const offloadEmail = serviceAccountEmail(prefix, project, "offload");
    const backendEmail = serviceAccountEmail(prefix, project, "backend");

    if (url.includes("accesscontextmanager.googleapis.com")) {
      return record({
        name: spec.managed_chrome_access_level,
        custom: {
          expr: {
            expression:
              "device.chrome.management_state == ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED",
          },
        },
      });
    }
    if (url.endsWith("/global/images/sgs-nginx-20260824")) {
      return record({
        id: "987654321",
        name: "sgs-nginx-20260824",
        selfLink: `https://www.googleapis.com/compute/v1/${IMMUTABLE_SOURCE_IMAGE}`,
      });
    }
    if (url === networkUrl) {
      return record({
        description: `${DISCOVERY_MARKER}; Managed by Secure Gateway Studio`,
        name: `${prefix}-vpc`,
        autoCreateSubnetworks: false,
        routingConfig: {
          routingMode: "REGIONAL",
          bgpBestPathSelectionMode: "LEGACY",
          bgpInterRegionCost: "DEFAULT",
          effectiveBgpAlwaysCompareMed: false,
        },
        selfLink: networkUrl,
      });
    }
    if (url === subnetUrl) {
      return record({
        ...computeDescription,
        name: `${prefix}-subnet`,
        network: networkUrl,
        ipCidrRange: spec.subnet_cidr,
        privateIpGoogleAccess: true,
        stackType: "IPV4_ONLY",
        selfLink: subnetUrl,
      });
    }
    if (url.endsWith(`/routers/${prefix}-router`)) {
      return record({
        ...computeDescription,
        name: `${prefix}-router`,
        network: networkUrl,
        fingerprint: "router-etag",
        nats: [{
          name: `${prefix}-nat`,
          natIpAllocateOption: "AUTO_ONLY",
          sourceSubnetworkIpRangesToNat: "LIST_OF_SUBNETWORKS",
          subnetworks: [{ name: subnetUrl, sourceIpRangesToNat: ["ALL_IP_RANGES"] }],
          logConfig: { enable: true, filter: "ERRORS_ONLY" },
        }],
      });
    }
    if (url.includes("iam.googleapis.com/v1/projects/") && url.includes("/serviceAccounts/")) {
      const backend = decodeURIComponent(url).includes(backendEmail);
      const email = backend ? backendEmail : offloadEmail;
      return record({
        name: `projects/${project}/serviceAccounts/${email}`,
        email,
        uniqueId: backend ? "1002" : "1001",
        description: DISCOVERY_MARKER,
        displayName: `Secure Gateway Studio ${backend ? serviceAccountId(prefix, "backend") : serviceAccountId(prefix, "offload")}`,
      });
    }
    if (url.endsWith(`/secrets/${prefix}-tls/versions/7:access`)) {
      return record({
        name: `projects/${project}/secrets/${prefix}-tls/versions/7`,
        payload: { data: this.encodedSecret, dataCrc32c: String(this.secretCrc) },
      });
    }
    if (url.endsWith(`/secrets/${prefix}-tls`)) {
      return record({
        name: `projects/${project}/secrets/${prefix}-tls`,
        labels: {
          "managed-by": "secure-gateway-studio",
          "sgs-owner-token": DISCOVERY_OWNER,
          "certificate-spec-hash": canonicalDigestSync({
            ca_name: spec.ca_name ?? null,
            ca_pool: spec.ca_pool ?? null,
            certificate_lifetime_days: spec.certificate_lifetime_days,
            certificate_strategy: spec.certificate_strategy,
            private_hostname: spec.private_hostname,
            public_certificate_secret: spec.public_certificate_secret ?? null,
          }).slice(0, 32),
          "configuration-hash": configurationHash(spec).slice(0, 32),
        },
        replication: { automatic: {} },
        versionAliases: { active: "7" },
      });
    }
    if (url.endsWith(`/${prefix}-offload-ip`)) {
      return record({
        ...computeDescription,
        name: `${prefix}-offload-ip`,
        address: "10.42.0.10",
        addressType: "INTERNAL",
        subnetwork: subnetUrl,
      });
    }
    if (url.endsWith(`/${prefix}-backend-ip`)) {
      return record({
        ...computeDescription,
        name: `${prefix}-backend-ip`,
        address: "10.42.0.11",
        addressType: "INTERNAL",
        subnetwork: subnetUrl,
      });
    }
    const startup = (role: "offload" | "backend") =>
      role === "backend"
        ? sampleBackendStartupScript(spec)
        : offloadStartupScript(spec, { backendAddress: "10.42.0.11" });
    const vm = (role: "offload" | "backend") => ({
      ...computeDescription,
      name: `${prefix}-${role}`,
      deletionProtection: false,
      disks: [{
        autoDelete: true,
        boot: true,
        mode: "READ_WRITE",
        source: `https://www.googleapis.com/compute/v1/projects/${project}` +
          `/zones/${spec.zone}/disks/${prefix}-${role}`,
        type: "PERSISTENT",
      }],
      labels: { "managed-by": "secure-gateway-studio", role },
      machineType: role === "offload" && this.drift === "vm-machine"
        ? `zones/${spec.zone}/machineTypes/e2-standard-8`
        : `zones/${spec.zone}/machineTypes/e2-small`,
      metadata: { items: [
        {
          key: "startup-script",
          value: role === "offload" && this.drift === "vm-startup"
            ? `${startup(role)}\necho injected-command\n`
            : startup(role),
        },
        { key: "enable-guest-attributes", value: "TRUE" },
      ] },
      networkInterfaces: [{
        network: networkUrl,
        networkIP: role === "offload" ? "10.42.0.10" : "10.42.0.11",
        stackType: "IPV4_ONLY",
        subnetwork: subnetUrl,
      }],
      serviceAccounts: [{
        email: role === "offload" ? offloadEmail : backendEmail,
        scopes: ["https://www.googleapis.com/auth/cloud-platform"],
      }],
      shieldedInstanceConfig: {
        enableIntegrityMonitoring: true,
        enableSecureBoot: true,
        enableVtpm: true,
      },
      tags: { items: [`${prefix}-${role}`], fingerprint: "output-only-tags-fingerprint" },
    });
    if (url.includes(`/zones/${spec.zone}/disks/${prefix}-`)) {
      const role = url.endsWith(`/${prefix}-backend`) ? "backend" : "offload";
      const name = `${prefix}-${role}`;
      return record({
        name,
        selfLink: `https://www.googleapis.com/compute/v1/projects/${project}` +
          `/zones/${spec.zone}/disks/${name}`,
        zone: `https://www.googleapis.com/compute/v1/projects/${project}/zones/${spec.zone}`,
        status: "READY",
        sizeGb: "20",
        type: `https://www.googleapis.com/compute/v1/projects/${project}` +
          `/zones/${spec.zone}/diskTypes/pd-balanced`,
        sourceImage: `https://www.googleapis.com/compute/v1/${IMMUTABLE_SOURCE_IMAGE}`,
        sourceImageId: "987654321",
      });
    }
    if (url.endsWith(`/instances/${prefix}-offload`)) return record(vm("offload"));
    if (url.endsWith(`/instances/${prefix}-backend`)) return record(vm("backend"));
    if (url.endsWith(`/instanceTemplates/${prefix}-offload-template`)) {
      const properties = vm("offload");
      delete (properties as { name?: unknown }).name;
      delete (properties as { deletionProtection?: unknown }).deletionProtection;
      (properties as { machineType: string }).machineType = "e2-small";
      (properties as Record<string, unknown>).disks = [{
        autoDelete: true,
        boot: true,
        initializeParams: {
          diskSizeGb: "20",
          diskType: "pd-balanced",
          sourceImage: IMMUTABLE_SOURCE_IMAGE,
        },
      }];
      delete ((properties.networkInterfaces as Array<Record<string, unknown>>)[0]!).networkIP;
      if (this.drift === "template-startup") {
        const metadata = properties.metadata as { items: Array<{ key: string; value: string }> };
        metadata.items[0]!.value += "\necho injected-template-command\n";
      }
      return record({
        description: `${DISCOVERY_MARKER}; Managed by Secure Gateway Studio`,
        properties,
      });
    }
    if (url.endsWith(`/healthChecks/${prefix}-offload-hc`)) {
      return record({
        ...computeDescription,
        name: `${prefix}-offload-hc`,
        checkIntervalSec: 10,
        healthyThreshold: 2,
        sslHealthCheck: {
          port: 443,
          portName: "",
          portSpecification: "USE_FIXED_PORT",
          proxyHeader: this.drift === "health-nondefault" ? "PROXY_V1" : "NONE",
          request: "",
          response: "",
        },
        timeoutSec: 5,
        type: "SSL",
        unhealthyThreshold: 3,
      });
    }
    if (url.endsWith(`/instanceGroupManagers/${prefix}-offload-mig`)) {
      return record({
        ...computeDescription,
        name: `${prefix}-offload-mig`,
        baseInstanceName: `${prefix}-offload`,
        targetSize: spec.offload_min_replicas,
        distributionPolicy: {
          targetShape: "EVEN",
          zones: [{ zone: `zones/${spec.zone}` }, { zone: `zones/${spec.secondary_zone}` }],
        },
        namedPorts: [{ name: "https", port: 443 }],
        updatePolicy: {
          maxSurge: { fixed: 2, calculated: 2 },
          maxUnavailable: { fixed: 0, calculated: 0 },
          minimalAction: "REPLACE",
          type: "PROACTIVE",
          replacementMethod: "SUBSTITUTE",
          mostDisruptiveAllowedAction: "REPLACE",
          instanceRedistributionType: "PROACTIVE",
          minReadySec: 0,
        },
        versions: [{
          instanceTemplate: `${networkUrl.split("/global/networks/")[0]}/global/instanceTemplates/${prefix}-${this.drift === "mig-template" ? "attacker" : "offload-template"}`,
          name: "primary",
        }],
      });
    }
    if (url.endsWith(`/autoscalers/${prefix}-offload-autoscaler`)) {
      return record({
        ...computeDescription,
        name: `${prefix}-offload-autoscaler`,
        target:
          `https://compute.googleapis.com/compute/v1/projects/${project}/regions/${spec.region}` +
          `/instanceGroupManagers/${prefix}-offload-mig`,
        autoscalingPolicy: {
          coolDownPeriodSec: 90,
          minNumReplicas: spec.offload_min_replicas,
          maxNumReplicas: spec.offload_max_replicas,
          cpuUtilization: { utilizationTarget: spec.offload_cpu_target },
          mode: "ON",
        },
      });
    }
    if (url.endsWith(`/backendServices/${prefix}-offload-bs`)) {
      return record({
        ...computeDescription,
        name: `${prefix}-offload-bs`,
        protocol: "TCP",
        loadBalancingScheme: "INTERNAL",
        backends: [{ group: `${COMPUTE_RESOURCE}/projects/${project}/regions/${spec.region}/instanceGroups/${prefix}-offload-mig` }],
        healthChecks: [`${COMPUTE_RESOURCE}/projects/${project}/regions/${spec.region}/healthChecks/${prefix}-offload-hc`],
        timeoutSec: 10,
      });
    }
    if (url.endsWith(`/forwardingRules/${prefix}-offload-fr`)) {
      return record({
        ...computeDescription,
        name: `${prefix}-offload-fr`,
        IPAddress: this.drift === "forwarding-ip" ? "10.42.0.99" : "10.42.0.10",
        IPProtocol: "TCP",
        loadBalancingScheme: "INTERNAL",
        allowGlobalAccess: true,
        ports: ["443"],
        network: networkUrl,
        subnetwork: subnetUrl,
        backendService: `${COMPUTE_RESOURCE}/projects/${project}/regions/${spec.region}/backendServices/${prefix}-offload-bs`,
      });
    }
    if (url.includes("/global/firewalls/")) {
      const name = url.split("/").pop() ?? "";
      const common = {
        ...computeDescription,
        name,
        direction: "INGRESS",
        disabled: false,
        logConfig: { enable: true, metadata: "INCLUDE_ALL_METADATA" },
        network: this.drift === "firewall-network"
          ? `https://compute.googleapis.com/compute/v1/projects/${project}/global/networks/attacker-vpc`
          : networkUrl,
        priority: 1000,
      };
      if (name.endsWith("-backend-ingress")) {
        return record({
          ...common,
          allowed: [{ IPProtocol: "tcp", ports: ["80"] }],
          sourceServiceAccounts: [offloadEmail],
          targetServiceAccounts: [backendEmail],
        });
      }
      if (name.endsWith("-health-check-ingress")) {
        return record({
          ...common,
          allowed: [{ IPProtocol: "tcp", ports: ["443"] }],
          sourceRanges: ["35.191.0.0/16", "130.211.0.0/22"],
          targetServiceAccounts: [offloadEmail],
        });
      }
      return record({
        ...common,
        allowed: [{ IPProtocol: "tcp", ports: ["443"] }],
        sourceRanges: ["136.124.16.0/20"],
        targetServiceAccounts: [offloadEmail],
      });
    }
    if (url.endsWith(`/managedZones/${prefix}-zone`)) {
      return record({
        name: `${prefix}-zone`,
        description: DISCOVERY_MARKER,
        dnsName: `${spec.private_hostname}.`,
        visibility: "private",
        privateVisibilityConfig: { networks: [{ networkUrl: dnsNetworkUrl }] },
      });
    }
    if (url.includes("/rrsets/")) {
      if (url.endsWith("/TXT")) {
        return record({
          name: `_sgs-owner.${spec.private_hostname}.`,
          type: "TXT",
          ttl: 60,
          rrdatas: [`"sgs-owner=${DISCOVERY_OWNER}"`],
        });
      }
      return record({
        name: `${spec.private_hostname}.`, type: "A", ttl: 60, rrdatas: ["10.42.0.10"],
      });
    }
    const gateway =
      `https://beyondcorp.googleapis.com/v1/projects/${project}` +
      `/locations/global/securityGateways/${spec.gateway_id}`;
    if (url === gateway) {
      return record({
        name: `projects/${project}/locations/global/securityGateways/${spec.gateway_id}`,
        displayName: spec.gateway_id,
        createTime: "2026-08-24T00:00:01Z",
        serviceDiscovery: {},
        logging: {},
        state: "RUNNING",
        delegatingServiceAccount: "gateway@example.iam.gserviceaccount.com",
      });
    }
    if (url === `${gateway}/applications/${prefix}-app`) {
      return record({
        name: `projects/${project}/locations/global/securityGateways/${spec.gateway_id}` +
          `/applications/${prefix}-app`,
        displayName: `${prefix}-app`,
        createTime: "2026-08-24T00:00:02Z",
        endpointMatchers: [{ hostname: spec.private_hostname, ports: [443] }],
        upstreams: [{ network: { name: `projects/${project}/global/networks/${prefix}-vpc` } }],
      });
    }
    if (url.endsWith(":getIamPolicy")) {
      if (url.includes("secretmanager.googleapis.com")) {
        return record({ etag: "iam-etag", bindings: [{ role: "roles/secretmanager.secretAccessor", members: [`serviceAccount:${offloadEmail}`] }] });
      }
      if (url.includes("/applications/")) {
        return record({ etag: "iam-etag", bindings: [{
          role: "roles/beyondcorp.sgApplicationUser",
          members: ["group:secure-access@example.com"],
          condition: {
            title: "Managed Chrome required",
            description: "Allow only profiles or browsers managed by this enterprise",
            expression: `'${spec.managed_chrome_access_level}' in request.auth.access_levels`,
          },
        }] });
      }
      if (url.includes("securityGateways")) {
        return record({ etag: "iam-etag", bindings: [{ role: "roles/beyondcorp.serviceDiscoveryUser", members: ["group:secure-access@example.com"] }] });
      }
      if (url.includes("cloudresourcemanager")) {
        return record({ etag: "iam-etag", bindings: [{ role: "roles/beyondcorp.upstreamAccess", members: ["serviceAccount:gateway@example.iam.gserviceaccount.com"] }] });
      }
    }
    if (method === "POST" && url.includes("chromepolicy.googleapis.com")) {
      const target = options.jsonBody?.policyTargetKey as Record<string, unknown>;
      const schema = options.jsonBody?.policySchemaFilter;
      const sourceKey = { targetResource: `orgunits/${spec.target_ou_id}` };
      let value: Record<string, unknown> | null = null;
      if (schema === "chrome.users.apps.InstallType") value = { appInstallType: "FORCED" };
      if (schema === "chrome.users.SimpleProxySettings") value = { simpleProxyMode: "PROXY_MODE_ENUM_USER_CONFIGURED" };
      if (schema === "chrome.users.apps.ManagedConfiguration") {
        value = { managedConfiguration: canonicalJson({
          securityGateway: { Value: { authentication: {}, context: { resource: `projects/${project}/locations/global/securityGateways/${spec.gateway_id}` }, serviceDiscovery: { routes: {} } } },
        }) };
      }
      return record(value === null ? { resolvedPolicies: [] } : {
        resolvedPolicies: [{ targetKey: target, sourceKey, value: { policySchema: schema, value } }],
      });
    }
    return super.requestJson(method, url, options);
  }
}

{
  const profileExpression =
    "device.chrome.management_state == ChromeManagementState.CHROME_MANAGEMENT_STATE_PROFILE_MANAGED";
  const canonical = { custom: { expr: { expression: profileExpression } } };
  const canonicalWithMetadata = {
    custom: {
      expr: {
        expression: profileExpression,
        title: "Managed profile",
        description: "Exact canonical managed-profile gate",
        location: "sgstudio:managed-profile",
      },
    },
  };
  const malicious = {
    custom: { expr: { expression: `true || ${profileExpression}` } },
  };
  const legacyMultiple = {
    custom: {
      expr: { expression: profileExpression },
      conditions: [{ expr: { expression: profileExpression } }],
    },
  };
  if (!isCanonicalManagedChromeAccessLevel(canonical)) {
    failures.push("access level: canonical managed Chrome expression was rejected");
  }
  if (!isCanonicalManagedChromeAccessLevel(canonicalWithMetadata)) {
    failures.push("access level: legal Expr metadata was rejected");
  }
  if (isCanonicalManagedChromeAccessLevel(malicious)) {
    failures.push("access level: malicious OR expression was accepted");
  }
  if (isCanonicalManagedChromeAccessLevel(legacyMultiple)) {
    failures.push("access level: multiple/legacy conditions were accepted");
  }
  if (isCanonicalManagedChromeAccessLevel({ custom: { expr: { expression: 7 } } })) {
    failures.push("access level: non-string expression was accepted");
  }
  if (isCanonicalManagedChromeAccessLevel({
    basic: { conditions: [] },
    custom: { expr: { expression: profileExpression } },
  })) {
    failures.push("access level: basic and custom coexistence was accepted");
  }
  if (isCanonicalManagedChromeAccessLevel({
    custom: { expr: { expression: profileExpression, unknown: "semantic" } },
  })) {
    failures.push("access level: unknown Expr fields were accepted");
  }

  class AccessLevelIdentityTransport extends ReplayTransport {
    private readonly wrongName: boolean;

    constructor(wrongName: boolean) {
      super(true, "10.20.0.10");
      this.wrongName = wrongName;
    }

    override async requestJson(
      method: string,
      url: string,
      options: {
        params?: Record<string, string | number>;
        jsonBody?: Record<string, unknown>;
        acceptedStatuses?: readonly number[];
      } = {},
    ): Promise<{ status: number; payload: Record<string, unknown> }> {
      if (method === "GET" && url.includes("accesscontextmanager.googleapis.com")) {
        return {
          status: 200,
          payload: {
            name: this.wrongName
              ? "accessPolicies/123456789/accessLevels/other"
              : "accessPolicies/123456789/accessLevels/managed_chrome",
            ...canonicalWithMetadata,
          },
        };
      }
      return super.requestJson(method, url, options);
    }
  }
  const accessSpec = parseDeploymentSpec(golden.scenarios[0].spec);
  const accessKey =
    "accesscontextmanager:access_level:accessPolicies/123456789/accessLevels/managed_chrome";
  const exact = await new GoogleDiscoveryProvider(
    new AccessLevelIdentityTransport(false),
    { cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com" },
  ).preflight(accessSpec);
  const wrong = await new GoogleDiscoveryProvider(
    new AccessLevelIdentityTransport(true),
    { cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com" },
  ).preflight(accessSpec);
  if (!exact.snapshot.existing_resource_keys?.includes(accessKey)) {
    failures.push("access level: exact name with legal metadata was not reusable");
  }
  if (!wrong.snapshot.conflicting_resource_keys?.includes(accessKey)) {
    failures.push("access level: wrong returned resource name did not conflict");
  }
}

const COMPUTE_RESOURCE = "https://www.googleapis.com/compute/v1";

for (const mode of ["poc", "production"] as const) {
  const spec = parseDeploymentSpec({
    project_id: "enterprise-secgw-01",
    mode,
    target_ou_id: "03-test-ou",
    managed_chrome_access_level: "accessPolicies/123456789/accessLevels/managed_chrome",
    test_ou_confirmed: true,
    principals: [{ type: "group", value: "secure-access@example.com" }],
    backend_kind: "managed_sample",
    network_strategy: "dedicated",
    chrome_enterprise_premium_license_confirmed: mode === "production",
    workspace_services_confirmed: mode === "production",
    endpoint_verification_confirmed: mode === "production",
    source_image: IMMUTABLE_SOURCE_IMAGE,
    certificate_strategy: mode === "poc" ? "local_poc" : "enterprise_ca",
    ca_pool: mode === "production"
      ? "projects/enterprise-secgw-01/locations/asia-east1/caPools/secure-gateway"
      : null,
    ca_name: mode === "production"
      ? "projects/enterprise-secgw-01/locations/asia-east1/caPools/secure-gateway/" +
        "certificateAuthorities/secure-gateway"
      : null,
  });
  const bundle = await issueLocalPoc(spec.private_hostname, 90);
  const result = await new GoogleDiscoveryProvider(
    new PathAExistingTransport(spec, secretPayload(bundle)),
    {
      cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
      ownershipProofs: pathAOwnershipProofs(spec),
    },
  ).preflight(spec);
  const plan = buildPlan(spec, result.snapshot);
  const stableKeys = [
    `compute:network:${spec.name}-vpc`,
    `compute:subnetwork:${spec.name}-subnet`,
    `compute:router:${spec.name}-router`,
    `compute:cloud_nat:${spec.name}-nat`,
    `iam:service_account:${serviceAccountId(spec.name, "offload")}`,
    `iam:service_account:${serviceAccountId(spec.name, "backend")}`,
    `secretmanager:secret:${spec.name}-tls`,
    `secretmanager:secret_version:${spec.name}-tls`,
    `secretmanager:secret_iam:${spec.name}-tls-accessor`,
    `compute:internal_address:${spec.name}-offload-ip`,
    `compute:internal_address:${spec.name}-backend-ip`,
    `compute:instance:${spec.name}-backend`,
    `compute:firewall_rule:${spec.name}-backend-ingress`,
    `compute:firewall_rule:${spec.name}-gateway-ingress`,
    `dns:private_zone:${spec.name}-zone`,
    `dns:record_set:${spec.private_hostname}`,
    `beyondcorp:security_gateway:${spec.gateway_id}`,
    `beyondcorp:application:${spec.name}-app`,
    ...(mode === "poc"
      ? [`compute:instance:${spec.name}-offload`]
      : [
        `compute:instance_template:${spec.name}-offload-template`,
        `compute:health_check:${spec.name}-offload-hc`,
        `compute:instance_group_manager:${spec.name}-offload-mig`,
        `compute:autoscaler:${spec.name}-offload-autoscaler`,
        `compute:backend_service:${spec.name}-offload-bs`,
        `compute:forwarding_rule:${spec.name}-offload-fr`,
        `compute:firewall_rule:${spec.name}-health-check-ingress`,
      ]),
  ];
  for (const key of stableKeys) {
    if (!result.snapshot.existing_resource_keys?.includes(key)) {
      failures.push(`Path A ${mode} second-plan discovery omitted ${key}`);
      continue;
    }
    const change = plan.changes.find((item) =>
      `${item.provider}:${item.resource_type}:${item.resource_name}` === key
    );
    if (change?.action === "create" || change?.owned_after_apply === true) {
      failures.push(`Path A ${mode} second plan re-created or claimed ${key}`);
    }
  }
}

for (const [drift, mode, expectedKey] of [
  ["vm-startup", "poc", "compute:instance:secure-gateway-http-offload-offload"],
  ["vm-machine", "poc", "compute:instance:secure-gateway-http-offload-offload"],
  ["template-startup", "production", "compute:instance_template:secure-gateway-http-offload-offload-template"],
  ["mig-template", "production", "compute:instance_group_manager:secure-gateway-http-offload-offload-mig"],
  ["health-nondefault", "production", "compute:health_check:secure-gateway-http-offload-offload-hc"],
  ["firewall-network", "production", "compute:firewall_rule:secure-gateway-http-offload-gateway-ingress"],
  ["forwarding-ip", "production", "compute:forwarding_rule:secure-gateway-http-offload-offload-fr"],
] as const) {
  const spec = parseDeploymentSpec({
    project_id: "enterprise-secgw-01",
    mode,
    target_ou_id: "03-test-ou",
    managed_chrome_access_level: "accessPolicies/123456789/accessLevels/managed_chrome",
    test_ou_confirmed: true,
    principals: [{ type: "group", value: "secure-access@example.com" }],
    backend_kind: "managed_sample",
    network_strategy: "dedicated",
    chrome_enterprise_premium_license_confirmed: mode === "production",
    workspace_services_confirmed: mode === "production",
    endpoint_verification_confirmed: mode === "production",
    source_image: IMMUTABLE_SOURCE_IMAGE,
    certificate_strategy: mode === "poc" ? "local_poc" : "enterprise_ca",
    ca_pool: mode === "production"
      ? "projects/enterprise-secgw-01/locations/asia-east1/caPools/secure-gateway"
      : null,
    ca_name: mode === "production"
      ? "projects/enterprise-secgw-01/locations/asia-east1/caPools/secure-gateway/" +
        "certificateAuthorities/secure-gateway"
      : null,
  });
  const bundle = await issueLocalPoc(spec.private_hostname, 90);
  const result = await new GoogleDiscoveryProvider(
    new PathAExistingTransport(spec, secretPayload(bundle), drift),
    {
      cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
      ownershipProofs: pathAOwnershipProofs(spec),
    },
  ).preflight(spec);
  if (
    !result.snapshot.conflicting_resource_keys?.includes(expectedKey) ||
    result.snapshot.existing_resource_keys?.includes(expectedKey)
  ) {
    failures.push(`Path A semantic drift ${drift} did not conflict ${expectedKey}`);
  }
}

for (const items of [
  [{}],
  [{ ...licenseAssignment("user@example.com"), skuId: "wrong" }],
  [
    licenseAssignment("User@example.com"),
    licenseAssignment("user@EXAMPLE.com"),
  ],
] as Array<Array<Record<string, unknown>>>) {
  class InvalidLicenseTransport extends PaginatedWorkspaceTransport {
    override async requestJson(
      method: string,
      url: string,
      options: {
        params?: Record<string, string | number>;
        jsonBody?: Record<string, unknown>;
        acceptedStatuses?: readonly number[];
      } = {},
    ) {
      if (url.includes("licensing.googleapis.com")) {
        return { status: 200, payload: { items: structuredClone(items) } };
      }
      return super.requestJson(method, url, options);
    }
  }
  const spec = parseDeploymentSpec(golden.scenarios[0].spec);
  const result = await new GoogleDiscoveryProvider(new InvalidLicenseTransport(), {
    cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
  }).preflight(spec);
  if (
    result.snapshot.chrome_enterprise_premium_license_count !== null ||
    !result.diagnostics.some((item) => item.code === "chrome-enterprise-premium-manual-confirmation")
  ) {
    failures.push(`workspace signals: malformed/duplicate license assignments were counted: ${JSON.stringify(items)}`);
  }
}

{
  const spec = parseDeploymentSpec(golden.scenarios[0].spec);
  const result = await new GoogleDiscoveryProvider(new PaginatedWorkspaceTransport(true), {
    cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
  }).preflight(spec);
  if (result.snapshot.chrome_enterprise_premium_license_count !== 0) {
    failures.push("workspace signals: Licensing API 404 must mean zero visible assignments");
  }
  if (!result.diagnostics.some((item) => item.code === "chrome-enterprise-premium-license-not-detected")) {
    failures.push("workspace signals: Licensing API 404 must emit the zero-assignment warning");
  }
}

{
  const spec = parseDeploymentSpec(golden.scenarios[0].spec);
  const result = await new GoogleDiscoveryProvider(new RepeatedProfileTokenTransport(), {
    cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
  }).preflight(spec);
  if (result.snapshot.managed_chrome_profile_count !== null) {
    failures.push("workspace signals: repeated profile page token returned partial counts");
  }
  if (!result.diagnostics.some((item) => item.code === "chrome-profile-readiness-pagination-invalid")) {
    failures.push("workspace signals: repeated profile page token did not fail closed");
  }
}

type DiscoveryPaginationFault =
  | "group-repeat"
  | "group-malformed"
  | "group-malformed-item"
  | "group-invalid-identity"
  | "group-over-limit"
  | "forward-repeat"
  | "forward-rotating";

class PaginationSafetyTransport extends ReplayTransport {
  private readonly fault: DiscoveryPaginationFault;
  private forwardPages = 0;

  constructor(fault: DiscoveryPaginationFault) {
    super(true, "10.20.0.10");
    this.fault = fault;
  }

  override async requestJson(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    if (url === "https://admin.googleapis.com/admin/directory/v1/groups" &&
        this.fault.startsWith("group-")) {
      this.calls.push({
        method,
        url,
        params: options.params ?? null,
        body: options.jsonBody ?? null,
      });
      if (this.fault === "group-malformed") {
        return { status: 200, payload: { groups: { not: "an array" } } };
      }
      if (this.fault === "group-malformed-item") {
        return { status: 200, payload: { groups: [null] } };
      }
      if (this.fault === "group-invalid-identity") {
        return { status: 200, payload: { groups: [{ id: "", email: 42 }] } };
      }
      if (this.fault === "group-over-limit") {
        return {
          status: 200,
          payload: {
            groups: Array.from({ length: 2_001 }, (_, index) => ({
              id: `group-${index}`,
              email: `group-${index}@example.com`,
            })),
          },
        };
      }
      return { status: 200, payload: { groups: [], nextPageToken: "same-token" } };
    }
    if (url.includes("/aggregated/forwardingRules") && this.fault.startsWith("forward-")) {
      this.calls.push({
        method,
        url,
        params: options.params ?? null,
        body: options.jsonBody ?? null,
      });
      this.forwardPages += 1;
      return {
        status: 200,
        payload: {
          items: {},
          nextPageToken: this.fault === "forward-repeat"
            ? "same-token"
            : `page-${this.forwardPages}`,
        },
      };
    }
    return super.requestJson(method, url, options);
  }
}

{
  const spec = parseDeploymentSpec(golden.scenarios[0].spec);
  for (const fault of [
    "group-repeat",
    "group-malformed",
    "group-malformed-item",
    "group-invalid-identity",
    "group-over-limit",
  ] as const) {
    const transport = new PaginationSafetyTransport(fault);
    const result = await new GoogleDiscoveryProvider(transport, {
      cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
    }).preflight(spec);
    if (result.snapshot.chrome_group_policy_discovery_complete !== false) {
      failures.push(`group pagination: ${fault} was accepted as a complete group-policy snapshot`);
    }
    const groupCalls = transport.calls.filter((call) =>
      call.url === "https://admin.googleapis.com/admin/directory/v1/groups"
    );
    if (groupCalls.length > 10) {
      failures.push(`group pagination: ${fault} exceeded the ten-page safety limit`);
    }
  }
}

type GroupResponseFault =
  | "membership-type"
  | "resolve-missing"
  | "resolve-empty-added-source"
  | "resolve-non-array"
  | "resolve-item"
  | "resolve-source"
  | "resolve-value"
  | "resolve-configuration"
  | "resolve-duplicate"
  | "resolve-paged";

class GroupResponseSafetyTransport extends ReplayTransport {
  private readonly fault: GroupResponseFault;
  private groupResolvePage = 0;

  constructor(fault: GroupResponseFault) {
    super(true, "10.20.0.10");
    this.fault = fault;
  }

  override async requestJson(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    if (url === "https://admin.googleapis.com/admin/directory/v1/groups") {
      return {
        status: 200,
        payload: {
          groups: [{
            id: "group-123",
            email: this.fault === "membership-type"
              ? "indirect@example.com"
              : "secure-access@example.com",
          }],
        },
      };
    }
    if (url.includes("/hasMember/")) {
      return { status: 200, payload: { isMember: "false" } };
    }
    if (
      method === "POST" && url.includes("chromepolicy.googleapis.com") &&
      options.jsonBody?.policySchemaFilter === "chrome.users.apps.ManagedConfiguration" &&
      (options.jsonBody.policyTargetKey as { targetResource?: unknown } | undefined)
        ?.targetResource === "groups/group-123"
    ) {
      const target = {
        targetResource: "groups/group-123",
        additionalTargetKeys: {
          app_id: "chrome:ekajlcmdfcigmdbphhifahdfjbkciflj",
        },
      };
      const valid = {
        targetKey: target,
        sourceKey: { targetResource: "groups/group-123" },
        value: {
          policySchema: "chrome.users.apps.ManagedConfiguration",
          value: { managedConfiguration: "{}" },
        },
      };
      switch (this.fault) {
        case "resolve-paged":
          this.groupResolvePage += 1;
          return this.groupResolvePage === 1
            ? { status: 200, payload: { resolvedPolicies: [], nextPageToken: "group-page-2" } }
            : { status: 200, payload: { resolvedPolicies: [valid] } };
        case "resolve-missing":
          return { status: 200, payload: {} };
        case "resolve-empty-added-source":
          return {
            status: 200,
            payload: {
              resolvedPolicies: [{ ...valid, addedSourceKey: {} }],
            },
          };
        case "resolve-non-array":
          return { status: 200, payload: { resolvedPolicies: {} } };
        case "resolve-item":
          return { status: 200, payload: { resolvedPolicies: [null] } };
        case "resolve-source":
          return {
            status: 200,
            payload: {
              resolvedPolicies: [{
                ...valid,
                targetKey: { ...target, targetResource: "groups/other" },
              }],
            },
          };
        case "resolve-value":
          return {
            status: 200,
            payload: { resolvedPolicies: [{ ...valid, value: { value: {} } }] },
          };
        case "resolve-configuration":
          return {
            status: 200,
            payload: {
              resolvedPolicies: [{
                ...valid,
                value: {
                  policySchema: "chrome.users.apps.ManagedConfiguration",
                  value: { managedConfiguration: "{" },
                },
              }],
            },
          };
        case "resolve-duplicate":
          return { status: 200, payload: { resolvedPolicies: [valid, structuredClone(valid)] } };
        default:
          return { status: 200, payload: { resolvedPolicies: [] } };
      }
    }
    return super.requestJson(method, url, options);
  }
}

class ChromeResolvePaginationTransport extends ReplayTransport {
  readonly resolveBodies: Record<string, unknown>[] = [];

  constructor() {
    super(null, null);
  }

  override async requestJson(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    const target = options.jsonBody?.policyTargetKey as Record<string, unknown> | undefined;
    const additional = target?.additionalTargetKeys as Record<string, unknown> | undefined;
    if (
      method === "POST" && url.endsWith("/policies:resolve") &&
      options.jsonBody?.policySchemaFilter === "chrome.users.apps.InstallType" &&
      additional?.app_id === "chrome:ekajlcmdfcigmdbphhifahdfjbkciflj"
    ) {
      throw new GoogleApiError({
        status: 500,
        method,
        url,
        payload: {
          error: { code: 500, message: "Internal error encountered.", status: "INTERNAL" },
        },
      });
    }
    if (
      method === "POST" && url.endsWith("/policies:resolve") &&
      options.jsonBody?.policySchemaFilter === "chrome.users.apps.InstallType" &&
      target?.additionalTargetKeys === undefined
    ) {
      this.resolveBodies.push(structuredClone(options.jsonBody ?? {}));
      if (options.jsonBody?.pageToken === undefined) {
        return {
          status: 200,
          payload: { resolvedPolicies: [], nextPageToken: "install-page-2" },
        };
      }
      return {
        status: 200,
        payload: {
          resolvedPolicies: [{
            targetKey: {
              targetResource: target?.targetResource,
              additionalTargetKeys: {
                app_id: "chrome:ekajlcmdfcigmdbphhifahdfjbkciflj",
              },
            },
            sourceKey: { targetResource: target?.targetResource },
            value: {
              policySchema: "chrome.users.apps.InstallType",
              value: { appInstallType: "FORCED" },
            },
          }],
        },
      };
    }
    return super.requestJson(method, url, options);
  }
}

class UnmanagedChromeAppTransport extends ReplayTransport {
  readonly appResolveTargets: Record<string, unknown>[] = [];

  constructor() {
    super(null, null);
  }

  override async requestJson(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    if (url === "https://admin.googleapis.com/admin/directory/v1/groups") {
      return {
        status: 200,
        payload: { groups: [{ id: "group-123", email: "secure-access@example.com" }] },
      };
    }
    if (
      method === "POST" && url.endsWith("/policies:resolve") &&
      String(options.jsonBody?.policySchemaFilter).startsWith("chrome.users.apps.")
    ) {
      const target = options.jsonBody?.policyTargetKey as Record<string, unknown>;
      this.appResolveTargets.push(structuredClone(target));
      if (target.additionalTargetKeys !== undefined) {
        throw new GoogleApiError({
          status: 500,
          method,
          url,
          payload: {
            error: { code: 500, message: "Internal error encountered.", status: "INTERNAL" },
          },
        });
      }
      return {
        status: 200,
        payload: {
          resolvedPolicies: [{
            targetKey: {
              targetResource: target.targetResource,
              additionalTargetKeys: { app_id: "chrome:unrelated-managed-app" },
            },
            sourceKey: { targetResource: target.targetResource },
            value: {
              policySchema: options.jsonBody?.policySchemaFilter,
              value: options.jsonBody?.policySchemaFilter ===
                  "chrome.users.apps.ManagedConfiguration"
                ? { managedConfiguration: "{}" }
                : { appInstallType: "FORCED" },
            },
          }],
        },
      };
    }
    return super.requestJson(method, url, options);
  }
}

{
  const spec = parseDeploymentSpec(golden.scenarios[0].spec);
  const transport = new UnmanagedChromeAppTransport();
  const result = await new GoogleDiscoveryProvider(transport, {
    cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
  }).preflight(spec);
  const diagnosticCodes = new Set(result.diagnostics.map((item) => item.code));
  const usedExactResolve = transport.appResolveTargets.some(
    (target) => target.additionalTargetKeys !== undefined,
  );
  const usedAggregateFallback = transport.appResolveTargets.some(
    (target) => target.additionalTargetKeys === undefined,
  );
  if (
    diagnosticCodes.has("chrome-policy") ||
    diagnosticCodes.has("chrome-group-policy") ||
    !usedExactResolve ||
    !usedAggregateFallback
  ) {
    failures.push(
      "Chrome app discovery did not recover from an unmanaged-app internal error with aggregate resolve",
    );
  }
}

{
  const userSpec = parseDeploymentSpec({
    ...golden.scenarios[0].spec,
    principals: [{ type: "user", value: "approved-user@example.com" }],
  });
  const result = await new GoogleDiscoveryProvider(
    new GroupResponseSafetyTransport("membership-type"),
    { cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com" },
  ).preflight(userSpec);
  if (result.snapshot.chrome_group_policy_discovery_complete !== false) {
    failures.push("group policy: non-boolean hasMember response was treated as not-a-member");
  }
}

{
  const spec = parseDeploymentSpec(golden.scenarios[0].spec);
  const transport = new ChromeResolvePaginationTransport();
  const result = await new GoogleDiscoveryProvider(transport, {
    cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
  }).preflight(spec);
  if (
    !result.snapshot.existing_resource_keys?.includes(
      "chromepolicy:extension_install:ekajlcmdfcigmdbphhifahdfjbkciflj",
    ) ||
    transport.resolveBodies.length !== 2 ||
    transport.resolveBodies[0]?.pageSize !== 1_000 ||
    (transport.resolveBodies[0]?.policyTargetKey as Record<string, unknown>)
      ?.additionalTargetKeys !== undefined ||
    transport.resolveBodies[1]?.pageToken !== "install-page-2"
  ) {
    failures.push("Chrome Policy discovery did not follow an empty first resolve page");
  }

  const groupResult = await new GoogleDiscoveryProvider(
    new GroupResponseSafetyTransport("resolve-paged"),
    { cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com" },
  ).preflight(spec);
  if (
    groupResult.snapshot.chrome_group_policy_discovery_complete !== true ||
    !groupResult.snapshot.chrome_extension_group_conflicts?.includes("secure-access@example.com")
  ) {
    failures.push("Chrome group policy discovery ignored a direct policy on a later page");
  }
}

{
  const spec = parseDeploymentSpec(golden.scenarios[0].spec);
  for (const legalEmptyShape of ["resolve-missing", "resolve-empty-added-source"] as const) {
    const result = await new GoogleDiscoveryProvider(
      new GroupResponseSafetyTransport(legalEmptyShape),
      { cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com" },
    ).preflight(spec);
    if (result.snapshot.chrome_group_policy_discovery_complete !== true) {
      failures.push(
        `group policy: legal empty protobuf shape ${legalEmptyShape} blocked discovery`,
      );
    }
  }

  for (const fault of [
    "resolve-non-array",
    "resolve-item",
    "resolve-source",
    "resolve-value",
    "resolve-configuration",
    "resolve-duplicate",
  ] as const) {
    const result = await new GoogleDiscoveryProvider(
      new GroupResponseSafetyTransport(fault),
      { cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com" },
    ).preflight(spec);
    const gate = buildPlan(spec, result.snapshot).gates.find(
      (item) => item.gate_id === "group-policy-discovery",
    );
    if (
      result.snapshot.chrome_group_policy_discovery_complete !== false ||
      gate?.blocking !== true
    ) {
      failures.push(`group policy: ${fault} did not fail discovery and Apply closed`);
    }
    const diagnostic = result.diagnostics.find((item) => item.message.startsWith("chrome-group-policy"));
    if (
      diagnostic?.remediation?.includes("signed-in Workspace administrator") !== true ||
      diagnostic.remediation.includes("deployer")
    ) {
      failures.push(`group policy: ${fault} reported the wrong identity in remediation`);
    }
  }
}

{
  const spec = parseDeploymentSpec(golden.scenarios[0].spec);
  for (const fault of ["forward-repeat", "forward-rotating"] as const) {
    const transport = new PaginationSafetyTransport(fault);
    const result = await new GoogleDiscoveryProvider(transport, {
      cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
    }).preflight(spec);
    const gate = buildPlan(spec, result.snapshot).gates.find((item) => item.gate_id === "global-access");
    if (
      result.snapshot.application_global_access_discovery_complete !== false ||
      gate?.status !== "blocked" || gate.blocking !== true
    ) {
      failures.push(`forwarding pagination: ${fault} did not fail the Global Access gate closed`);
    }
    const forwardingCalls = transport.calls.filter((call) =>
      call.url.includes("/aggregated/forwardingRules")
    );
    if (forwardingCalls.length > 10) {
      failures.push(`forwarding pagination: ${fault} exceeded the ten-page safety limit`);
    }
  }
}

type PrivateEgressCase = "valid" | "other-region" | "private-nat" | "missing-route" |
  "competing-route" | "unreachable";

class PrivateEgressTransport extends ReplayTransport {
  private readonly variant: PrivateEgressCase;

  constructor(variant: PrivateEgressCase) {
    super(null, null);
    this.variant = variant;
  }

  override async requestJson(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    const record = (payload: Record<string, unknown>) => {
      this.calls.push({
        method,
        url,
        params: options.params ?? null,
        body: options.jsonBody ?? null,
      });
      return { status: 200, payload };
    };
    if (url.endsWith("/aggregated/routers")) {
      if (
        canonicalJson(options.params ?? {}) !== canonicalJson({
          maxResults: 500,
          returnPartialSuccess: "true",
        })
      ) throw new Error("private egress router request omitted strict pagination parameters");
      const scope = this.variant === "other-region" ? "regions/us-central1" : "regions/asia-east1";
      return record({
        ...(this.variant === "unreachable" ? { unreachables: ["regions/asia-east1"] } : {}),
        items: {
          [scope]: {
            routers: [{
              network: (
                "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
                "global/networks/private-app-vpc"
              ),
              nats: [{
                name: "admin-nat",
                ...(this.variant === "private-nat" ? { type: "PRIVATE" } : { type: "PUBLIC" }),
                endpointTypes: ["ENDPOINT_TYPE_VM"],
                natIpAllocateOption: "AUTO_ONLY",
                sourceSubnetworkIpRangesToNat: "ALL_SUBNETWORKS_ALL_IP_RANGES",
              }],
            }],
          },
        },
      });
    }
    if (url.endsWith("/global/routes")) {
      return record({
        items: this.variant === "missing-route" ? [] : [
          {
            name: "default-internet-route",
            network: (
              "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
              "global/networks/private-app-vpc"
            ),
            destRange: "0.0.0.0/0",
            nextHopGateway: (
              "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
              "global/gateways/default-internet-gateway"
            ),
            priority: 1000,
            routeType: "STATIC",
            status: "ACTIVE",
          },
          ...(this.variant === "competing-route" ? [{
            name: "higher-priority-vpn-default",
            network: (
              "https://www.googleapis.com/compute/v1/projects/enterprise-secgw-01/" +
              "global/networks/private-app-vpc"
            ),
            destRange: "0.0.0.0/0",
            nextHopIp: "10.42.0.5",
            priority: 100,
            routeType: "STATIC",
            status: "ACTIVE",
          }] : []),
        ],
      });
    }
    return super.requestJson(method, url, options);
  }
}

{
  const spec = parseDeploymentSpec({
    ...golden.scenarios[0].spec,
    backend_kind: "existing_http",
    existing_backend_url: "http://10.20.0.10:8080",
    network_strategy: "existing",
    vpc_name: "private-app-vpc",
    subnet_name: "private-app-subnet",
    source_image: IMMUTABLE_SOURCE_IMAGE,
    private_hostname: "gateway.customer.dev",
    public_certificate_secret:
      "projects/enterprise-secgw-01/secrets/operator-public-tls",
  });
  for (const variant of [
    "valid",
    "other-region",
    "private-nat",
    "missing-route",
    "competing-route",
    "unreachable",
  ] as const) {
    const result = await new GoogleDiscoveryProvider(
      new PrivateEgressTransport(variant),
      { cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com" },
    ).preflight(spec);
    const expected = variant === "valid" ? true
      : variant === "unreachable" ? null
      : false;
    if (result.snapshot.private_egress_available !== expected) {
      failures.push(
        `private egress: ${variant} returned ${String(result.snapshot.private_egress_available)}`,
      );
    }
    const gate = buildPlan(spec, result.snapshot).gates.find(
      (item) => item.gate_id === "private-egress",
    );
    if (variant !== "valid" && gate?.blocking !== true) {
      failures.push(`private egress: ${variant} did not block Apply`);
    }
  }
}

type ProbeMismatch =
  | "none"
  | "crc"
  | "image"
  | "subnet_identity"
  | "gateway"
  | "gateway_state"
  | "gateway_state_missing"
  | "gateway_dsa"
  | "gateway_ips"
  | "gateway_proxy"
  | "gateway_hubs"
  | "gateway_uid"
  | "application"
  | "application_proxy"
  | "application_external"
  | "application_schema"
  | "application_case_conflict"
  | "application_name";

class IntegrityProbeTransport extends ReplayTransport {
  private readonly encodedSecret: string;
  private readonly secretCrc: number;
  private readonly mismatch: ProbeMismatch;

  constructor(secret: string, mismatch: ProbeMismatch) {
    super(null, null);
    const bytes = new TextEncoder().encode(secret);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    this.encodedSecret = btoa(binary);
    this.secretCrc = crc32c(bytes);
    this.mismatch = mismatch;
  }

  override async requestJson(
    method: string,
    url: string,
    options: {
      params?: Record<string, string | number>;
      jsonBody?: Record<string, unknown>;
      acceptedStatuses?: readonly number[];
    } = {},
  ): Promise<{ status: number; payload: Record<string, unknown> }> {
    const record = (payload: Record<string, unknown>, status = 200) => {
      this.calls.push({
        method,
        url,
        params: options.params ?? null,
        body: options.jsonBody ?? null,
      });
      return { status, payload };
    };
    if (url.endsWith("/global/images/sgs-nginx-20260824")) {
      return record({
        id: "987654321",
        name: "sgs-nginx-20260824",
        selfLink: this.mismatch === "image"
          ? "https://www.googleapis.com/compute/v1/projects/other-project/global/images/sgs-nginx-20260824"
          : `https://www.googleapis.com/compute/v1/${IMMUTABLE_SOURCE_IMAGE}`,
      });
    }
    if (url.endsWith("/regions/asia-east1/subnetworks/private-app-subnet")) {
      return record({
        name: "private-app-subnet",
        network: this.mismatch === "subnet_identity"
          ? "https://compute.googleapis.com/compute/v1/projects/other-project/global/networks/private-app-vpc"
          : "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/global/networks/private-app-vpc",
        // This existing subnet intentionally differs from the hidden
        // creation-only 10.42.0.0/24 default.
        ipCidrRange: "10.43.0.0/24",
        privateIpGoogleAccess: true,
        stackType: "IPV4_ONLY",
        selfLink:
          "https://compute.googleapis.com/compute/v1/projects/enterprise-secgw-01/regions/asia-east1/subnetworks/private-app-subnet",
      });
    }
    if (url.endsWith("/secrets/operator-public-tls/versions/latest:access")) {
      return record({
        name:
          "projects/enterprise-secgw-01/secrets/operator-public-tls/versions/7",
        payload: {
          data: this.encodedSecret,
          dataCrc32c: String(this.secretCrc + (this.mismatch === "crc" ? 1 : 0)),
        },
      });
    }
    if (url.endsWith("/secrets/operator-public-tls")) {
      return record({ name: "projects/enterprise-secgw-01/secrets/operator-public-tls" });
    }
    const gateway =
      "https://beyondcorp.googleapis.com/v1/projects/enterprise-secgw-01" +
      "/locations/global/securityGateways/default";
    if (url === gateway) {
      return record({
        name: "projects/enterprise-secgw-01/locations/global/securityGateways/default",
        displayName: "default",
        createTime: "2026-08-24T00:00:01Z",
        serviceDiscovery: this.mismatch === "gateway" ? { apiGateway: {} } : {},
        logging: {},
        ...(this.mismatch === "gateway_state_missing"
          ? {}
          : { state: this.mismatch === "gateway_state" ? "ERROR" : "RUNNING" }),
        delegatingServiceAccount: this.mismatch === "gateway_dsa"
          ? "   "
          : "gateway@example.iam.gserviceaccount.com",
        externalIps: this.mismatch === "gateway_ips"
          ? ["999.1.1.1"]
          : ["203.0.113.10", "2001:db8::1"],
        ...(this.mismatch === "gateway_proxy" ? { proxyProtocolConfig: {} } : {}),
        ...(this.mismatch === "gateway_hubs" ? { hubs: [] } : {}),
        ...(this.mismatch === "gateway_uid" ? { uid: "undocumented-identity" } : {}),
      });
    }
    if (url === `${gateway}/applications/secure-gateway-http-offload-app`) {
      const upstream: Record<string, unknown> = {
        network: {
          name: "projects/enterprise-secgw-01/global/networks/private-app-vpc",
        },
      };
      if (this.mismatch === "application_proxy") upstream.proxyProtocol = {};
      if (this.mismatch === "application_external") upstream.external = {};
      return record({
        name: this.mismatch === "application_name"
          ? "projects/enterprise-secgw-01/locations/global/securityGateways/default/" +
            "applications/foreign-app"
          : "projects/enterprise-secgw-01/locations/global/securityGateways/default/" +
            "applications/secure-gateway-http-offload-app",
        displayName: "secure-gateway-http-offload-app",
        createTime: "2026-08-24T00:00:02Z",
        endpointMatchers: [
          {
            hostname: "gateway.customer.dev",
            ports: [this.mismatch === "application" ? 8443 : 443],
          },
        ],
        ...(this.mismatch === "application_case_conflict"
          ? { endpoint_matchers: [{ hostname: "gateway.customer.dev", ports: [443] }] }
          : {}),
        ...(this.mismatch === "application_schema" ? { schema: "CUSTOM_SCHEMA" } : {}),
        upstreams: [upstream],
      });
    }
    return super.requestJson(method, url, options);
  }
}

{
  const publicBundle = await issueLocalPoc("gateway.customer.dev", 90);
  const encodedSecret = secretPayload(publicBundle);
  const spec = parseDeploymentSpec({
    ...golden.scenarios[0].spec,
    backend_kind: "existing_http",
    existing_backend_url: "http://10.20.0.10:8080",
    network_strategy: "existing",
    subnet_name: "private-app-subnet",
    source_image: "projects/enterprise-secgw-01/global/images/sgs-nginx-20260824",
    private_hostname: "gateway.customer.dev",
    public_certificate_secret:
      "projects/enterprise-secgw-01/secrets/operator-public-tls",
  });
  const expectedKeys: Record<Exclude<ProbeMismatch, "none">, string> = {
    crc: "secretmanager:secret:operator-public-tls",
    image: "compute:source_image:projects/enterprise-secgw-01/global/images/sgs-nginx-20260824",
    subnet_identity: "compute:subnetwork:private-app-subnet",
    gateway: "beyondcorp:security_gateway:default",
    gateway_state: "beyondcorp:security_gateway:default",
    gateway_state_missing: "beyondcorp:security_gateway:default",
    gateway_dsa: "beyondcorp:security_gateway:default",
    gateway_ips: "beyondcorp:security_gateway:default",
    gateway_proxy: "beyondcorp:security_gateway:default",
    gateway_hubs: "beyondcorp:security_gateway:default",
    gateway_uid: "beyondcorp:security_gateway:default",
    application: "beyondcorp:application:secure-gateway-http-offload-app",
    application_proxy: "beyondcorp:application:secure-gateway-http-offload-app",
    application_external: "beyondcorp:application:secure-gateway-http-offload-app",
    application_schema: "beyondcorp:application:secure-gateway-http-offload-app",
    application_case_conflict: "beyondcorp:application:secure-gateway-http-offload-app",
    application_name: "beyondcorp:application:secure-gateway-http-offload-app",
  };

  const valid = await new GoogleDiscoveryProvider(
    new IntegrityProbeTransport(encodedSecret, "none"),
    {
      cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
      ownershipProofs: pathAOwnershipProofs(spec),
    },
  ).preflight(spec);
  for (const key of Object.values(expectedKeys)) {
    if (!valid.snapshot.existing_resource_keys?.includes(key)) {
      failures.push(`integrity probes: compatible ${key} was not reusable`);
    }
  }
  const existingSubnetChange = buildPlan(spec, valid.snapshot).changes.find(
    (change) =>
      `${change.provider}:${change.resource_type}:${change.resource_name}` ===
        "compute:subnetwork:private-app-subnet",
  );
  if (
    existingSubnetChange?.action !== "reuse" ||
    existingSubnetChange.owned_after_apply !== false
  ) {
    failures.push(
      "integrity probes: non-default-CIDR existing subnet was not a non-owned reuse",
    );
  }

  {
    const requestId = "b636157b-5c63-4278-b84e-89ad31b54c81";
    const resourceKey = "beyondcorp:security_gateway:default";
    const resourceUrl =
      "https://beyondcorp.googleapis.com/v1/projects/enterprise-secgw-01/" +
      "locations/global/securityGateways/default";
    const gatewayProof = discoveryOwnershipProofs([{
      runId: "run-created-gateway",
      resourceKey,
      provider: "beyondcorp",
      resourceType: "security_gateway",
      resourceName: "default",
      owned: false,
      shared: true,
      requestId,
      beforeImage: {
        kind: "generic_created_resource",
        protocolVersion: 2,
        phase: "applied",
        resourceKey,
        createUrl: resourceUrl.slice(0, resourceUrl.lastIndexOf("/")),
        resourceUrl,
        createRequestId: requestId,
        expectedParamsDigest: canonicalDigestSync({
          securityGatewayId: "default",
          requestId,
        }),
        expectedPayloadDigest: canonicalDigestSync({
          displayName: "default",
          serviceDiscovery: {},
          logging: {},
        }),
        ownershipMarker: null,
        providerIdentityField: "createTime",
        providerIdentity: "2026-08-24T00:00:01Z",
      },
    }], spec);
    const otherProofs = { ...pathAOwnershipProofs(spec) };
    delete otherProofs[resourceKey];
    const result = await new GoogleDiscoveryProvider(
      new IntegrityProbeTransport(encodedSecret, "none"),
      {
        cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
        ownershipProofs: { ...otherProofs, ...gatewayProof },
      },
    ).preflight(spec);
    const gateway = buildPlan(spec, result.snapshot).changes.find(
      (change) =>
        `${change.provider}:${change.resource_type}:${change.resource_name}` === resourceKey,
    );
    if (gateway?.action !== "reuse" || gateway.owned_after_apply !== false) {
      failures.push(
        "shared gateway: exact finalized CREATE proof did not produce non-owned REUSE",
      );
    }
  }

  for (const mismatch of [
    "crc",
    "image",
    "subnet_identity",
    "gateway",
    "gateway_state",
    "gateway_state_missing",
    "gateway_dsa",
    "gateway_ips",
    "gateway_proxy",
    "gateway_hubs",
    "gateway_uid",
    "application",
    "application_proxy",
    "application_external",
    "application_schema",
    "application_case_conflict",
    "application_name",
  ] as const) {
    const result = await new GoogleDiscoveryProvider(
      new IntegrityProbeTransport(encodedSecret, mismatch),
      {
        cloudIdentity: "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
        ownershipProofs: pathAOwnershipProofs(spec),
      },
    ).preflight(spec);
    const key = expectedKeys[mismatch];
    if (!result.snapshot.conflicting_resource_keys?.includes(key)) {
      failures.push(`integrity probes: ${mismatch} mismatch did not conflict ${key}`);
    }
    if (result.snapshot.existing_resource_keys?.includes(key)) {
      failures.push(`integrity probes: ${mismatch} mismatch was incorrectly reusable`);
    }
  }
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} difference(s)\n`);
  for (const failure of failures.slice(0, 10)) console.error(`  ${failure}\n`);
  if (failures.length > 10) console.error(`  ... and ${failures.length - 10} more`);
  process.exit(1);
}
console.log(
  `OK ${golden.scenarios.length} scenarios, ${comparedRequests} requests and their ` +
    "snapshots match the Python reference.",
);
