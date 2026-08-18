/**
 * DeploymentSpec. Port of the spec half of `backend/src/sgstudio/domain/models.py`.
 *
 * Validation messages are reproduced verbatim from the Python implementation.
 * They are not decoration: the UI surfaces them, and the golden set compares
 * them, so a reworded message is a behaviour change.
 *
 * No schema library is used. The parity checks must run with nothing installed
 * but Node, and a security product that ships a reviewable extension benefits
 * from a dependency it does not have. The cost is that every constraint is
 * written out; the benefit is that every constraint is visible.
 */

export class SpecValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SpecValidationError";
  }
}

export type DeploymentMode = "poc" | "production";
export type ProductLocale = "en" | "ja";
export type ChromePlatform = "macos" | "windows" | "linux" | "chromeos";
export type NetworkStrategy = "dedicated" | "existing";
export type CertificateStrategy = "enterprise_ca" | "public_trusted" | "local_poc";
export type BackendKind =
  | "managed_sample"
  | "existing_http"
  | "direct_https"
  // The internal Application Load Balancer path. Its absence here made
  // every comparison against it dead code, so the extension planned an
  // ALB deployment as though it were a plain one.
  | "internal_https_lb";
export type BackendLocation = "gcp" | "aws" | "azure" | "on_prem";
export type PrincipalType = "user" | "group" | "domain";

export const CHROME_PLATFORMS: readonly ChromePlatform[] = [
  "macos",
  "windows",
  "linux",
  "chromeos",
];

export interface AccessPrincipal {
  type: PrincipalType;
  value: string;
}

export interface DeploymentSpec {
  schema_version: 1;
  name: string;
  locale: ProductLocale;
  mode: DeploymentMode;
  platforms: Set<ChromePlatform>;
  network_strategy: NetworkStrategy;
  certificate_strategy: CertificateStrategy;
  project_id: string;
  region: string;
  zone: string;
  secondary_zone: string;
  source_image: string | null;
  offload_min_replicas: number;
  offload_max_replicas: number;
  offload_cpu_target: number;
  vpc_name: string | null;
  subnet_name: string | null;
  subnet_cidr: string;
  proxy_subnet_cidr: string;
  private_hostname: string;
  gateway_id: string;
  target_ou_id: string;
  customer_id: string;
  managed_chrome_access_level: string | null;
  chrome_enterprise_premium_license_confirmed: boolean;
  workspace_services_confirmed: boolean;
  endpoint_verification_confirmed: boolean;
  test_ou_confirmed: boolean;
  backend_kind: BackendKind;
  existing_backend_url: string | null;
  existing_backend_location: BackendLocation | null;
  existing_backend_connectivity_confirmed: boolean;
  application_egress_region: string | null;
  upstream_vpc_project_id: string | null;
  ca_pool: string | null;
  ca_name: string | null;
  public_certificate_secret: string | null;
  certificate_lifetime_days: number;
  principals: AccessPrincipal[];
  allow_external_ips: false;
  require_cloud_nat: boolean;
  require_human_approval: boolean;
}

const RESOURCE_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PROJECT_ID = /^[a-z][a-z0-9-]+$/;
const REGION = /^[a-z]+-[a-z]+[0-9]$/;
const ZONE = /^[a-z]+-[a-z]+[0-9]-[a-z]$/;
const CIDR = /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/;
const OU_ID = /^[A-Za-z0-9_-]+$/;
const CUSTOMER_ID = /^(?:my_customer|[A-Za-z0-9_-]+)$/;
const DNS_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const FQDN = new RegExp(`^(?:${DNS_LABEL}\\.)+${DNS_LABEL}$`);
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SOURCE_IMAGE =
  /^projects\/[a-z][a-z0-9-]{4,61}[a-z0-9]\/global\/images\/[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ACCESS_LEVEL = /^accessPolicies\/[0-9]+\/accessLevels\/[A-Za-z][A-Za-z0-9_]{0,49}$/;
const UNSAFE_PROXY_CHARS = /[\s{};#]/;
const FORBIDDEN_HOSTS = new Set(["localhost", "metadata", "metadata.google.internal"]);

function fail(message: string): never {
  throw new SpecValidationError(message);
}

// -- private address ranges ---------------------------------------------------
// RFC1918 plus IPv6 ULA, matching the Python allowed_private_ranges tuple.

function parseIPv4(host: string): number[] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    octets.push(value);
  }
  return octets;
}

function isPrivateAddress(host: string): boolean | null {
  const v4 = parseIPv4(host);
  if (v4 !== null) {
    const [a, b] = v4;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    return false;
  }
  // IPv6 only needs the ULA test (fc00::/7), i.e. a leading fc or fd byte.
  if (host.includes(":")) {
    const head = host.replace(/^\[|\]$/g, "").split(":")[0];
    if (head === "") return false; // "::1" and friends are not ULA
    const first = Number.parseInt(head.padStart(4, "0").slice(0, 2), 16);
    return Number.isFinite(first) && (first & 0xfe) === 0xfc;
  }
  return null; // not an IP literal
}

interface SplitUrl {
  scheme: string;
  hostname: string;
  port: number | null;
  path: string;
  query: string;
  fragment: string;
  hasCredentials: boolean;
}

function splitUrl(value: string): SplitUrl | null {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  // URL keeps IPv6 brackets; urlsplit().hostname does not.
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return {
    scheme: parsed.protocol.replace(/:$/, ""),
    hostname,
    port: parsed.port === "" ? null : Number(parsed.port),
    path: parsed.pathname,
    query: parsed.search.replace(/^\?/, ""),
    fragment: parsed.hash.replace(/^#/, ""),
    hasCredentials: parsed.username !== "" || parsed.password !== "",
  };
}

function validatePrivateEndpointHost(hostname: string, ipMessage: string, dnsMessage: string): void {
  if (FORBIDDEN_HOSTS.has(hostname)) {
    fail(
      dnsMessage.startsWith("Direct")
        ? "Direct HTTPS URL targets a forbidden host"
        : "Existing backend URL targets a forbidden host",
    );
  }
  const priv = isPrivateAddress(hostname);
  if (priv === true) return;
  if (priv === false) fail(ipMessage);
  if (!FQDN.test(hostname)) fail(dnsMessage);
}

export function validateAccessPrincipal(principal: AccessPrincipal): AccessPrincipal {
  const value = principal.value.trim().toLowerCase();
  if (value.length < 3 || value.length > 320) {
    fail("Principal value must be between 3 and 320 characters");
  }
  if (principal.type === "user" || principal.type === "group") {
    if (!EMAIL.test(value)) fail("User and group principals must be email addresses");
  } else if (!DOMAIN.test(value)) {
    fail("Domain principals must be valid DNS domains");
  }
  return { type: principal.type, value };
}

export function iamMember(principal: AccessPrincipal): string {
  return `${principal.type}:${principal.value}`;
}

export function normalisePrivateHostname(value: string): string {
  const hostname = value.trim().toLowerCase().replace(/\.$/, "");
  if (hostname.length > 253 || !FQDN.test(hostname)) {
    fail("private_hostname must be a valid fully qualified DNS name");
  }
  return hostname;
}

const DEFAULTS = {
  schema_version: 1,
  name: "secure-gateway-http-offload",
  locale: "en",
  mode: "production",
  network_strategy: "dedicated",
  certificate_strategy: "enterprise_ca",
  region: "asia-east1",
  zone: "asia-east1-c",
  secondary_zone: "asia-east1-a",
  source_image: null,
  offload_min_replicas: 2,
  offload_max_replicas: 20,
  offload_cpu_target: 0.6,
  vpc_name: null,
  subnet_name: null,
  subnet_cidr: "10.42.0.0/24",
  proxy_subnet_cidr: "10.42.1.0/24",
  private_hostname: "demo-server-http.internal",
  gateway_id: "default",
  customer_id: "my_customer",
  managed_chrome_access_level: null,
  chrome_enterprise_premium_license_confirmed: false,
  workspace_services_confirmed: false,
  endpoint_verification_confirmed: false,
  test_ou_confirmed: false,
  backend_kind: "managed_sample",
  existing_backend_url: null,
  existing_backend_location: null,
  existing_backend_connectivity_confirmed: false,
  application_egress_region: null,
  upstream_vpc_project_id: null,
  ca_pool: null,
  ca_name: null,
  public_certificate_secret: null,
  certificate_lifetime_days: 90,
  allow_external_ips: false,
  require_cloud_nat: true,
  require_human_approval: true,
} as const;

function requireInt(value: unknown, field: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    fail(`${field} must be an integer between ${min} and ${max}`);
  }
  return value;
}

function requirePattern(value: unknown, field: string, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(`${field} does not match ${pattern.source}`);
  }
  return value;
}

function optionalPattern(value: unknown, field: string, pattern: RegExp): string | null {
  if (value === null || value === undefined || (typeof value === "string" && value.trim() === "")) return null;
  return requirePattern(value, field, pattern);
}

/**
 * Validate and normalise a raw specification.
 *
 * Mirrors `DeploymentSpec.__init__` plus `enforce_enterprise_invariants`, in
 * the same order, so the first failure reported is the same one Python
 * reports.
 */
export function parseDeploymentSpec(input: Record<string, unknown>): DeploymentSpec {
  const raw = { ...DEFAULTS, ...input } as Record<string, unknown>;

  const platformsInput = (input.platforms ?? CHROME_PLATFORMS) as Iterable<ChromePlatform>;
  const platforms = new Set<ChromePlatform>(platformsInput);
  if (platforms.size === 0) fail("platforms must contain at least one entry");
  for (const platform of platforms) {
    if (!CHROME_PLATFORMS.includes(platform)) fail(`Unknown Chrome platform ${platform}`);
  }

  const principalsInput = (input.principals ?? []) as AccessPrincipal[];
  if (principalsInput.length === 0) fail("principals must contain at least one entry");
  const principals = principalsInput.map(validateAccessPrincipal);

  const spec: DeploymentSpec = {
    schema_version: 1,
    name: requirePattern(raw.name, "name", RESOURCE_NAME),
    locale: raw.locale as ProductLocale,
    mode: raw.mode as DeploymentMode,
    platforms,
    network_strategy: raw.network_strategy as NetworkStrategy,
    certificate_strategy: raw.certificate_strategy as CertificateStrategy,
    project_id: requirePattern(raw.project_id, "project_id", PROJECT_ID),
    region: requirePattern(raw.region, "region", REGION),
    zone: requirePattern(raw.zone, "zone", ZONE),
    secondary_zone: requirePattern(raw.secondary_zone, "secondary_zone", ZONE),
    source_image: (raw.source_image as string | null) ?? null,
    offload_min_replicas: requireInt(raw.offload_min_replicas, "offload_min_replicas", 2, 100),
    offload_max_replicas: requireInt(raw.offload_max_replicas, "offload_max_replicas", 2, 1000),
    offload_cpu_target: raw.offload_cpu_target as number,
    vpc_name: optionalPattern(raw.vpc_name, "vpc_name", RESOURCE_NAME),
    subnet_name: optionalPattern(raw.subnet_name, "subnet_name", RESOURCE_NAME),
    subnet_cidr: requirePattern(raw.subnet_cidr, "subnet_cidr", CIDR),
    proxy_subnet_cidr: requirePattern(raw.proxy_subnet_cidr, "proxy_subnet_cidr", CIDR),
    private_hostname: normalisePrivateHostname(raw.private_hostname as string),
    gateway_id: requirePattern(raw.gateway_id, "gateway_id", RESOURCE_NAME),
    target_ou_id: requirePattern(raw.target_ou_id, "target_ou_id", OU_ID),
    customer_id: requirePattern(raw.customer_id, "customer_id", CUSTOMER_ID),
    managed_chrome_access_level: (raw.managed_chrome_access_level as string | null) ?? null,
    chrome_enterprise_premium_license_confirmed:
      raw.chrome_enterprise_premium_license_confirmed as boolean,
    workspace_services_confirmed: raw.workspace_services_confirmed as boolean,
    endpoint_verification_confirmed: raw.endpoint_verification_confirmed as boolean,
    test_ou_confirmed: raw.test_ou_confirmed as boolean,
    backend_kind: raw.backend_kind as BackendKind,
    existing_backend_url: (raw.existing_backend_url as string | null) ?? null,
    existing_backend_location: (raw.existing_backend_location as BackendLocation | null) ?? null,
    existing_backend_connectivity_confirmed:
      raw.existing_backend_connectivity_confirmed as boolean,
    application_egress_region: optionalPattern(
      raw.application_egress_region,
      "application_egress_region",
      REGION,
    ),
    upstream_vpc_project_id: optionalPattern(
      raw.upstream_vpc_project_id,
      "upstream_vpc_project_id",
      PROJECT_ID,
    ),
    ca_pool: (raw.ca_pool as string | null) ?? null,
    ca_name: (raw.ca_name as string | null) ?? null,
    public_certificate_secret: (raw.public_certificate_secret as string | null) ?? null,
    certificate_lifetime_days: requireInt(
      raw.certificate_lifetime_days,
      "certificate_lifetime_days",
      1,
      397,
    ),
    principals,
    allow_external_ips: false,
    require_cloud_nat: raw.require_cloud_nat as boolean,
    require_human_approval: raw.require_human_approval as boolean,
  };

  enforceEnterpriseInvariants(spec);
  return spec;
}

function enforceEnterpriseInvariants(spec: DeploymentSpec): void {
  if (spec.offload_max_replicas < spec.offload_min_replicas) {
    fail("offload_max_replicas must be greater than or equal to offload_min_replicas");
  }

  if (spec.mode === "production") {
    if (spec.certificate_strategy === "local_poc") {
      fail("Production mode cannot use a local PoC CA");
    }
    if (!spec.test_ou_confirmed) fail("Production mode requires a confirmed test OU");
    if (!spec.require_cloud_nat) {
      fail("Production mode requires a private package egress path");
    }
    if (!spec.require_human_approval) {
      fail("Production mode requires explicit approval before Apply");
    }
    if (spec.secondary_zone === spec.zone) {
      fail("Production mode requires two distinct zones");
    }
    if (
      !spec.zone.startsWith(`${spec.region}-`) ||
      !spec.secondary_zone.startsWith(`${spec.region}-`)
    ) {
      fail("Production zones must belong to the selected region");
    }
    if (!spec.managed_chrome_access_level) {
      fail("Production mode requires a managed Chrome access level");
    }
    if (!spec.chrome_enterprise_premium_license_confirmed) {
      fail("Production mode requires Chrome Enterprise Premium license confirmation");
    }
    if (!spec.workspace_services_confirmed) {
      fail("Production mode requires Workspace service prerequisites confirmation");
    }
    if (!spec.endpoint_verification_confirmed) {
      fail("Production mode requires Endpoint Verification confirmation");
    }
    if (spec.backend_kind !== "direct_https" && !spec.source_image) {
      fail("Production mode requires an immutable hardened source image");
    }
  }

  if (spec.source_image && !SOURCE_IMAGE.test(spec.source_image)) {
    fail("source_image must be a full immutable Compute Engine image name");
  }

  if (
    spec.managed_chrome_access_level &&
    !spec.managed_chrome_access_level.startsWith("AUTO_CREATE_") &&
    spec.managed_chrome_access_level !== "NONE" &&
    !ACCESS_LEVEL.test(spec.managed_chrome_access_level)
  ) {
    fail(
      "managed_chrome_access_level must be a full Access Context Manager access level name",
    );
  }

  if (spec.network_strategy === "existing" && !spec.vpc_name) {
    fail("Existing VPC strategy requires vpc_name");
  }
  if (
    spec.network_strategy === "existing" &&
    spec.backend_kind !== "direct_https" &&
    !spec.subnet_name
  ) {
    fail("Nginx deployment in an existing VPC requires subnet_name");
  }
  if (spec.backend_kind === "direct_https" && spec.network_strategy !== "existing") {
    fail("Direct HTTPS requires the existing VPC that reaches the app");
  }
  if (spec.upstream_vpc_project_id !== null && spec.backend_kind !== "direct_https") {
    fail(
      "upstream_vpc_project_id applies only to direct private HTTPS, where " +
        "the VPC may belong to another project",
    );
  }

  if (
    spec.backend_kind !== "direct_https" &&
    spec.certificate_strategy === "enterprise_ca" &&
    (!spec.ca_pool || !spec.ca_name)
  ) {
    fail("Enterprise CA strategy requires ca_pool and ca_name");
  }
  if (
    spec.backend_kind !== "direct_https" &&
    spec.certificate_strategy === "public_trusted" &&
    !spec.public_certificate_secret
  ) {
    fail("Public certificate strategy requires public_certificate_secret");
  }
  if (
    spec.certificate_strategy === "public_trusted" &&
    spec.public_certificate_secret &&
    spec.public_certificate_secret.includes("/") &&
    !spec.public_certificate_secret.startsWith(`projects/${spec.project_id}/secrets/`)
  ) {
    fail("Public certificate secret must belong to the deployment project");
  }

  if (spec.backend_kind === "existing_http") {
    if (!spec.existing_backend_url) fail("Existing HTTP backend requires existing_backend_url");
    if (spec.existing_backend_location === null) {
      fail("Existing HTTP backend requires its hosting location");
    }
    if (!spec.existing_backend_url.startsWith("http://")) {
      fail("Existing backend URL must use http:// for HTTP offload");
    }
    const parsed = splitUrl(spec.existing_backend_url);
    if (parsed === null || parsed.hasCredentials || !parsed.hostname) {
      fail("Existing backend URL must not contain user info");
    }
    if (parsed.query || parsed.fragment) {
      fail("Existing backend URL must not contain a query or fragment");
    }
    if (UNSAFE_PROXY_CHARS.test(spec.existing_backend_url)) {
      fail("Existing backend URL contains unsafe proxy configuration characters");
    }
    validatePrivateEndpointHost(
      parsed.hostname,
      "Existing backend IP must be RFC1918 or IPv6 ULA",
      "Existing backend host must be a private IP or fully qualified DNS name",
    );
  } else if (spec.backend_kind === "direct_https") {
    if (!spec.existing_backend_url) fail("Direct HTTPS requires existing_backend_url");
    if (spec.existing_backend_location === null) {
      fail("Direct HTTPS requires its hosting location");
    }
    const parsed = splitUrl(spec.existing_backend_url);
    if (parsed === null || parsed.scheme !== "https" || !parsed.hostname) {
      fail("Direct HTTPS URL must use https://");
    }
    if (parsed.hasCredentials || parsed.query || parsed.fragment) {
      fail("Direct HTTPS URL must not contain credentials, query, or fragment");
    }
    if (parsed.path !== "" && parsed.path !== "/") {
      fail("Direct HTTPS URL identifies an endpoint, not an application path");
    }
    if (UNSAFE_PROXY_CHARS.test(spec.existing_backend_url)) {
      fail("Direct HTTPS URL contains unsafe characters");
    }
    validatePrivateEndpointHost(
      parsed.hostname,
      "Direct HTTPS IP must be RFC1918 or IPv6 ULA",
      "Direct HTTPS host must be a private IP or FQDN",
    );
    const port = parsed.port ?? 443;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      fail("Direct HTTPS port must be between 1 and 65535");
    }
  }

  const members = new Set(spec.principals.map(iamMember));
  if (members.size !== spec.principals.length) {
    fail("Duplicate access principals are not allowed");
  }
}

// -- derived properties -------------------------------------------------------

/** Project owning the upstream VPC; the deployment project by default. */
export function upstreamProjectId(spec: DeploymentSpec): string {
  return spec.upstream_vpc_project_id || spec.project_id;
}

export function applicationHostname(spec: DeploymentSpec): string {
  if (spec.backend_kind === "direct_https" && spec.existing_backend_url) {
    return splitUrl(spec.existing_backend_url)?.hostname ?? spec.private_hostname;
  }
  return spec.private_hostname;
}

export function applicationPort(spec: DeploymentSpec): number {
  if (spec.backend_kind === "direct_https" && spec.existing_backend_url) {
    return splitUrl(spec.existing_backend_url)?.port ?? 443;
  }
  return 443;
}

/**
 * Serialise for hashing, matching `model_dump(mode="json", exclude_none=True)`.
 *
 * `platforms` is a set in both implementations and is sorted before hashing,
 * exactly as `canonical_configuration_hash` does.
 */
export function specToJson(spec: DeploymentSpec, excludeNone = true): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    ...spec,
    platforms: [...spec.platforms].sort(),
    principals: spec.principals.map((principal) => ({ ...principal })),
  };
  if (excludeNone) {
    for (const key of Object.keys(payload)) {
      if (payload[key] === null || payload[key] === undefined) delete payload[key];
    }
  }
  return payload;
}
