export type Locale = "en" | "ja";
export type DeploymentMode = "poc" | "production";
export type ChromePlatform = "macos" | "windows" | "linux" | "chromeos";
export type NetworkStrategy = "dedicated" | "existing";
export type CertificateStrategy = "enterprise_ca" | "public_trusted" | "local_poc";
export type BackendKind =
  | "managed_sample"
  | "existing_http"
  | "direct_https"
  | "internal_https_lb";
export type BackendLocation = "gcp" | "aws" | "azure" | "on_prem";
export type PrincipalType = "user" | "group" | "domain";
export type ConnectionStatus =
  | "not_connected"
  | "checking"
  | "connected"
  | "error";

export interface AccessPrincipal {
  id: string;
  type: PrincipalType;
  value: string;
}

export interface SetupState {
  schemaVersion: 8;
  currentStep: number;
  deploymentName: string;
  mode: DeploymentMode;
  platforms: Record<ChromePlatform, boolean>;
  networkStrategy: NetworkStrategy;
  certificateStrategy: CertificateStrategy;
  projectId: string;
  cloudIdentity: string;
  cloudConnection: ConnectionStatus;
  cloudConnectionError: string;
  workspaceIdentity: string;
  workspaceConnection: ConnectionStatus;
  workspaceConnectionError: string;
  region: string;
  zone: string;
  secondaryZone: string;
  sourceImage: string;
  offloadMinReplicas: string;
  offloadMaxReplicas: string;
  offloadCpuTarget: string;
  vpcName: string;
  subnetName: string;
  proxySubnetCidr: string;
  backendKind: BackendKind;
  existingBackendUrl: string;
  existingBackendLocation: BackendLocation;
  existingBackendConnectivityConfirmed: boolean;
  applicationEgressRegion: string;
  privateHostname: string;
  caPool: string;
  caName: string;
  publicCertificateSecret: string;
  customerId: string;
  targetOuId: string;
  managedChromeAccessLevel: string;
  chromeEnterprisePremiumLicenseConfirmed: boolean;
  workspaceServicesConfirmed: boolean;
  endpointVerificationConfirmed: boolean;
  principals: AccessPrincipal[];
  testOuAvailable: boolean;
  testOuConfirmed: boolean;
  approvalConfirmed: boolean;
  updatedAt: string;
}

const SETUP_KEY = "sgs.setup.v8";
const LEGACY_SETUP_KEYS = ["sgs.setup.v7", "sgs.setup.v6"];
const LOCALE_KEY = "sgs.locale.v1";

export const defaultSetupState: SetupState = {
  schemaVersion: 8,
  currentStep: 0,
  deploymentName: "secure-gateway-ilb-https-offload",
  mode: "poc",
  platforms: {
    macos: true,
    windows: false,
    linux: false,
    chromeos: false,
  },
  networkStrategy: "dedicated",
  certificateStrategy: "enterprise_ca",
  projectId: "",
  cloudIdentity: "",
  cloudConnection: "not_connected",
  cloudConnectionError: "",
  workspaceIdentity: "",
  workspaceConnection: "not_connected",
  workspaceConnectionError: "",
  region: "asia-east1",
  zone: "asia-east1-c",
  secondaryZone: "asia-east1-a",
  sourceImage: "",
  offloadMinReplicas: "2",
  offloadMaxReplicas: "20",
  offloadCpuTarget: "0.6",
  vpcName: "",
  subnetName: "",
  proxySubnetCidr: "10.42.1.0/24",
  backendKind: "internal_https_lb",
  existingBackendUrl: "",
  existingBackendLocation: "gcp",
  existingBackendConnectivityConfirmed: false,
  applicationEgressRegion: "",
  privateHostname: "demo-server-http.internal",
  caPool: "",
  caName: "",
  publicCertificateSecret: "",
  customerId: "my_customer",
  targetOuId: "",
  managedChromeAccessLevel: "",
  chromeEnterprisePremiumLicenseConfirmed: false,
  workspaceServicesConfirmed: false,
  endpointVerificationConfirmed: false,
  principals: [
    {
      id: "principal-1",
      type: "group",
      value: "",
    },
  ],
  testOuAvailable: true,
  testOuConfirmed: false,
  approvalConfirmed: false,
  updatedAt: new Date(0).toISOString(),
};

export function toDeploymentSpec(
  setup: SetupState,
  locale: Locale,
): DeploymentSpec {
  return {
    schema_version: 1,
    name: setup.deploymentName,
    locale,
    mode: setup.mode,
    platforms: (
      Object.entries(setup.platforms) as Array<[ChromePlatform, boolean]>
    )
      .filter(([, selected]) => selected)
      .map(([platform]) => platform),
    network_strategy: setup.networkStrategy,
    certificate_strategy: setup.certificateStrategy,
    project_id: setup.projectId,
    region: setup.region,
    zone: setup.zone,
    secondary_zone: setup.secondaryZone,
    source_image: setup.sourceImage.trim() || null,
    offload_min_replicas: Number(setup.offloadMinReplicas),
    offload_max_replicas: Number(setup.offloadMaxReplicas),
    offload_cpu_target: Number(setup.offloadCpuTarget),
    vpc_name: setup.networkStrategy === "existing" ? setup.vpcName.trim() || null : null,
    subnet_name:
      setup.networkStrategy === "existing" && setup.backendKind !== "direct_https"
        ? setup.subnetName.trim() || null
        : null,
    proxy_subnet_cidr: setup.proxySubnetCidr.trim() || "10.42.1.0/24",
    private_hostname: setup.privateHostname.trim() || "secgw-backend.internal",
    gateway_id: "default",
    target_ou_id: setup.targetOuId,
    customer_id: setup.customerId,
    managed_chrome_access_level:
      !setup.managedChromeAccessLevel ||
      setup.managedChromeAccessLevel === "NONE"
        ? null
        : setup.managedChromeAccessLevel.trim() || null,
    chrome_enterprise_premium_license_confirmed:
      setup.chromeEnterprisePremiumLicenseConfirmed,
    workspace_services_confirmed: setup.workspaceServicesConfirmed,
    endpoint_verification_confirmed: setup.endpointVerificationConfirmed,
    test_ou_confirmed: setup.testOuConfirmed,
    backend_kind: setup.backendKind,
    existing_backend_url:
      setup.backendKind === "managed_sample" ||
      setup.backendKind === "internal_https_lb"
        ? null
        : setup.existingBackendUrl.trim() || null,
    existing_backend_location:
      setup.backendKind === "managed_sample" ||
      setup.backendKind === "internal_https_lb"
        ? null
        : setup.existingBackendLocation,
    application_egress_region:
      setup.backendKind === "direct_https" && setup.applicationEgressRegion.trim()
        ? setup.applicationEgressRegion.trim()
        : null,
    existing_backend_connectivity_confirmed:
      setup.backendKind !== "managed_sample" &&
      setup.backendKind !== "internal_https_lb" &&
      setup.existingBackendConnectivityConfirmed,
    ca_pool: setup.certificateStrategy === "enterprise_ca" ? setup.caPool : null,
    ca_name: setup.certificateStrategy === "enterprise_ca" ? setup.caName : null,
    public_certificate_secret:
      setup.certificateStrategy === "public_trusted"
        ? setup.publicCertificateSecret
        : null,
    certificate_lifetime_days: setup.mode === "production" ? 90 : 30,
    principals: setup.principals.map(({ type, value }) => ({
      type,
      value: value.trim(),
    })),
    allow_external_ips: false,
    require_cloud_nat: true,
    require_human_approval: true,
  };
}

function isSetupState(value: unknown): value is SetupState {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<SetupState>;
  const schemaVersion = (value as { schemaVersion?: number }).schemaVersion;
  return (
    (schemaVersion === 6 || schemaVersion === 7 || schemaVersion === 8) &&
    (candidate.mode === "poc" || candidate.mode === "production") &&
    (candidate.networkStrategy === "dedicated" ||
      candidate.networkStrategy === "existing") &&
    (candidate.certificateStrategy === "enterprise_ca" ||
      candidate.certificateStrategy === "public_trusted" ||
      candidate.certificateStrategy === "local_poc") &&
    candidate.platforms !== undefined
  );
}

export function loadSetupState(): SetupState {
  try {
    const serialized =
      window.localStorage.getItem(SETUP_KEY) ??
      LEGACY_SETUP_KEYS.map((key) => window.localStorage.getItem(key)).find(Boolean);
    if (!serialized) return defaultSetupState;
    const parsed: unknown = JSON.parse(serialized);
    if (!isSetupState(parsed)) return defaultSetupState;
    const migrated: SetupState = {
      ...defaultSetupState,
      ...parsed,
      schemaVersion: 8,
      // This release is intentionally scoped to rapid PoC deployments.
      // Keep Production-shaped drafts usable without exposing a disabled mode.
      mode: "poc",
      platforms: {
        ...defaultSetupState.platforms,
        ...parsed.platforms,
      },
      principals:
        Array.isArray(parsed.principals) && parsed.principals.length > 0
          ? parsed.principals
          : defaultSetupState.principals,
      currentStep:
        typeof parsed.currentStep === "number"
          ? Math.max(0, Math.min(6, parsed.currentStep))
          : 0,
    };
    // Preserve successfully validated identities for the local operator. A
    // plan still revalidates both providers server-side before approval, so
    // this is display/workflow continuity rather than an Apply attestation.
    migrated.cloudConnection =
      parsed.cloudConnection === "connected" && migrated.cloudIdentity.trim()
        ? "connected"
        : "not_connected";
    migrated.cloudConnectionError = "";
    migrated.workspaceConnection =
      parsed.workspaceConnection === "connected" && migrated.workspaceIdentity.trim()
        ? "connected"
        : "not_connected";
    migrated.workspaceConnectionError = "";
    migrated.approvalConfirmed = false;
    return migrated;
  } catch {
    return defaultSetupState;
  }
}

export function saveSetupState(state: SetupState): void {
  window.localStorage.setItem(SETUP_KEY, JSON.stringify(state));
}

export function loadLocale(): Locale {
  const locale = window.localStorage.getItem(LOCALE_KEY);
  return locale === "ja" ? "ja" : "en";
}

export function saveLocale(locale: Locale): void {
  window.localStorage.setItem(LOCALE_KEY, locale);
}

export function countSelectedPlatforms(
  platforms: Record<ChromePlatform, boolean>,
): number {
  return Object.values(platforms).filter(Boolean).length;
}
import type { DeploymentSpec } from "./api";
