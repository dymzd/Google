export interface ConnectionValidation {
  provider: "google_cloud" | "workspace";
  status: "connected";
  principal_hint: string;
  resource_id: string;
  credential_kind: string;
  read_only: true;
}

export interface DeployerBootstrapResult {
  project_id: string;
  operator_email: string;
  service_account_email: string;
  custom_role: string;
  access_policy_id: string | null;
  adc_command: string;
}

export interface SetupOption {
  value: string;
  label: string;
  description: string;
}

export interface DeploymentSpec {
  schema_version: 1;
  name: string;
  locale: "en" | "ja";
  mode: "poc" | "production";
  platforms: Array<"macos" | "windows" | "linux" | "chromeos">;
  network_strategy: "dedicated" | "existing";
  certificate_strategy: "enterprise_ca" | "public_trusted" | "local_poc";
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
  private_hostname: string;
  gateway_id: string;
  target_ou_id: string;
  customer_id: string;
  managed_chrome_access_level: string | null;
  chrome_enterprise_premium_license_confirmed: boolean;
  workspace_services_confirmed: boolean;
  endpoint_verification_confirmed: boolean;
  test_ou_confirmed: boolean;
  backend_kind:
    | "managed_sample"
    | "existing_http"
    | "direct_https"
    | "internal_https_lb";
  proxy_subnet_cidr: string;
  existing_backend_url: string | null;
  existing_backend_location: "gcp" | "aws" | "azure" | "on_prem" | null;
  existing_backend_connectivity_confirmed: boolean;
  application_egress_region: string | null;
  ca_pool: string | null;
  ca_name: string | null;
  public_certificate_secret: string | null;
  certificate_lifetime_days: number;
  principals: Array<{ type: "user" | "group" | "domain"; value: string }>;
  allow_external_ips: false;
  require_cloud_nat: true;
  require_human_approval: true;
}

export interface PreflightDiagnostic {
  code: string;
  severity: "info" | "warning" | "error";
  message: string;
  remediation: string | null;
}

export interface DeploymentGate {
  gate_id: string;
  title: string;
  status: "pass" | "pending" | "blocked";
  blocking: boolean;
  detail: string;
}

export interface ResourceChange {
  provider: string;
  resource_type: string;
  resource_name: string;
  action: "create" | "update" | "reuse" | "no_change" | "conflict";
  risk: "low" | "medium" | "high" | "blocking";
  summary: string;
  owned_after_apply: boolean;
  dependencies: string[];
}

export interface PreparedPlan {
  plan_id: string;
  specification: DeploymentSpec;
  preflight: {
    diagnostics: PreflightDiagnostic[];
    read_only: true;
    snapshot: {
      managed_chrome_profile_count: number | null;
      profile_only_count: number | null;
      latest_chrome_policy_sync: string | null;
      endpoint_verification_installed: boolean | null;
      secure_enterprise_browser_installed: boolean | null;
      endpoint_verification_version: string | null;
      secure_enterprise_browser_version: string | null;
      chrome_extension_group_conflicts: string[];
      chrome_enterprise_premium_license_count: number | null;
      chrome_root_store_config_count: number | null;
      chrome_root_store_config_names: string[];
      chrome_root_store_enabled: boolean | null;
    };
  };
  plan: {
    configuration_hash: string;
    changes: ResourceChange[];
    gates: DeploymentGate[];
    can_apply: boolean;
  };
  created_at: string;
  expires_at: string;
}

export interface ApprovedPlan {
  approval_id: string;
  configuration_hash: string;
  plan_hash: string;
  approved_by: string;
  approved_at: string;
  expires_at: string;
}

export interface DeploymentRun {
  run_id: string;
  approval_id: string;
  configuration_hash: string;
  status:
    | "pending"
    | "running"
    | "succeeded"
    | "failed"
    | "rolled_back"
    | "rollback_failed"
    | "interrupted";
  started_at: string;
  completed_at: string | null;
  operations: Array<{
    operation_id: string;
    resource_key: string;
    action: string;
    status: string;
    error_code: string | null;
  }>;
}

export interface DeploymentResource {
  resource_key: string;
  summary: string;
  provider: string;
  resource_type: string;
  resource_name: string;
  owned: boolean;
  teardown_action: "delete" | "delete_if_empty" | "retain";
}

export interface DeploymentDetails {
  run: DeploymentRun;
  ownership_run_id: string | null;
  deployment_name: string;
  project_id: string;
  gateway_id: string;
  backend_kind:
    | "managed_sample"
    | "existing_http"
    | "direct_https"
    | "internal_https_lb";
  application_hostname: string;
  application_port: number;
  resources: DeploymentResource[];
  teardown_available: boolean;
}

export type GatewayLogCategory = "access" | "connection" | "admin" | "nginx";

export interface GatewayLogEntry {
  insert_id: string;
  timestamp: string | null;
  severity: string;
  category: GatewayLogCategory;
  summary: string;
  principal: string | null;
  method: string | null;
  resource: string | null;
  request_id: string | null;
  payload: Record<string, unknown>;
}

export interface GatewayLogsResponse {
  run_id: string;
  category: GatewayLogCategory;
  entries: GatewayLogEntry[];
  logging_enabled: boolean | null;
  data_access_notice: boolean;
  setup_notice: string | null;
}

export interface TeardownPlan {
  run_id: string;
  plan_hash: string;
  confirmation: string;
  resources: DeploymentResource[];
  retained_resources: DeploymentResource[];
  can_destroy: boolean;
}

export interface TeardownRun {
  teardown_id: string;
  source_run_id: string;
  plan_hash: string;
  status: "pending" | "running" | "succeeded" | "failed" | "interrupted";
  started_at: string;
  completed_at: string | null;
  operations: Array<{
    resource_key: string;
    status: "pending" | "running" | "succeeded" | "failed" | "skipped";
    error_code: string | null;
    started_at: string | null;
    completed_at: string | null;
  }>;
}

export interface AuditEvent {
  event_id: string;
  deployment_id: string | null;
  event_type: string;
  actor: string;
  payload: Record<string, string | number | boolean | null>;
  created_at: string;
  previous_hash: string | null;
  event_hash: string | null;
}

export interface AuditIntegrity {
  valid: boolean;
  event_count: number;
  algorithm: "sha256-chain";
  chain_head_hash: string | null;
}

export type AcceptanceTestId =
  | "T01"
  | "T02"
  | "T03"
  | "T04"
  | "T05"
  | "T06"
  | "T07"
  | "T08"
  | "T09";

export interface AcceptanceResult {
  result_id: string;
  run_id: string;
  test_id: AcceptanceTestId;
  case_key: string;
  status: "passed" | "failed" | "user_confirmed" | "skipped";
  source: "system" | "operator";
  summary: string;
  evidence: string;
  actor: string;
  recorded_at: string;
}

export interface AcceptanceRequirement {
  test_id: AcceptanceTestId;
  case_key: string;
  operator_confirmable: boolean;
}

export interface AcceptanceReadiness {
  run_id: string;
  mode: "poc" | "production";
  acceptance_complete: boolean;
  production_ready: boolean;
  required_tests: AcceptanceTestId[];
  operator_confirmable_tests: AcceptanceTestId[];
  satisfied_tests: AcceptanceTestId[];
  missing_tests: AcceptanceTestId[];
  required_cases: AcceptanceRequirement[];
  operator_confirmable_cases: AcceptanceRequirement[];
  satisfied_cases: AcceptanceRequirement[];
  missing_cases: AcceptanceRequirement[];
  results: AcceptanceResult[];
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function postJson<TResponse>(
  path: string,
  body: unknown,
): Promise<TResponse> {
  const sessionNonce = await getSessionNonce();
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "SecureGatewayStudio",
      "X-SGS-Session": sessionNonce,
    },
    body: JSON.stringify(body),
    credentials: "omit",
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    let code = "request-failed";
    try {
      const payload = (await response.json()) as {
        detail?: string | { code?: string; message?: string };
      };
      if (typeof payload.detail === "string") message = payload.detail;
      if (payload.detail && typeof payload.detail === "object") {
        if (typeof payload.detail.code === "string") code = payload.detail.code;
        if (typeof payload.detail.message === "string") {
          message = payload.detail.message;
        }
      }
    } catch {
      // Keep the safe generic message for non-JSON responses.
    }
    throw new ApiError(response.status, code, message);
  }
  return (await response.json()) as TResponse;
}

let sessionNoncePromise: Promise<string> | null = null;

function getSessionNonce(): Promise<string> {
  if (sessionNoncePromise === null) {
    sessionNoncePromise = fetch("/api/v1/health", {
      method: "GET",
      headers: { "X-Requested-With": "SecureGatewayStudio" },
      credentials: "omit",
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new ApiError(
            response.status,
            "session-bootstrap-failed",
            `Session bootstrap failed (${response.status})`,
          );
        }
        const payload = (await response.json()) as { session_nonce?: string };
        if (!payload.session_nonce) {
          throw new ApiError(
            500,
            "session-bootstrap-failed",
            "The local API did not return a session nonce",
          );
        }
        return payload.session_nonce;
      })
      .catch((error) => {
        sessionNoncePromise = null;
        throw error;
      });
  }
  return sessionNoncePromise;
}

async function getJson<TResponse>(path: string): Promise<TResponse> {
  const sessionNonce = await getSessionNonce();
  const response = await fetch(path, {
    method: "GET",
    headers: {
      "X-Requested-With": "SecureGatewayStudio",
      "X-SGS-Session": sessionNonce,
    },
    credentials: "omit",
  });
  if (!response.ok) {
    throw new ApiError(response.status, "request-failed", `Request failed (${response.status})`);
  }
  return (await response.json()) as TResponse;
}

export function validateGoogleCloudConnection(
  projectId: string,
): Promise<ConnectionValidation> {
  return postJson("/api/v1/connections/google-cloud/validate", {
    project_id: projectId,
  });
}

export function bootstrapGoogleCloudDeployer(
  projectId: string,
): Promise<DeployerBootstrapResult> {
  return postJson("/api/v1/bootstrap/google-cloud/deployer", {
    project_id: projectId,
    confirmation: "BOOTSTRAP",
  });
}

export function validateWorkspaceConnection(
  customerId: string,
): Promise<ConnectionValidation> {
  return postJson("/api/v1/connections/workspace/validate", {
    customer_id: customerId,
  });
}

export function listOrganizationalUnitOptions(
  customerId: string,
): Promise<SetupOption[]> {
  return postJson("/api/v1/setup-options/organizational-units", {
    customer_id: customerId,
  });
}

export function listGroupOptions(customerId: string): Promise<SetupOption[]> {
  return postJson("/api/v1/setup-options/groups", {
    customer_id: customerId,
  });
}

export function listAccessLevelOptions(
  projectId: string,
): Promise<SetupOption[]> {
  return postJson("/api/v1/setup-options/access-levels", {
    project_id: projectId,
  });
}

export function preparePlan(
  specification: DeploymentSpec,
): Promise<PreparedPlan> {
  return postJson("/api/v1/plans", { specification });
}

export function approvePlan(
  planId: string,
): Promise<ApprovedPlan> {
  return postJson("/api/v1/approvals", {
    plan_id: planId,
    confirmation: "APPROVE",
    ttl_minutes: 30,
  });
}

export function applyApprovedPlan(
  approvalId: string,
): Promise<DeploymentRun> {
  return postJson("/api/v1/runs", {
    approval_id: approvalId,
    confirmation: "APPLY",
  });
}

export function getPreparedPlan(planId: string): Promise<PreparedPlan> {
  return getJson(`/api/v1/plans/${encodeURIComponent(planId)}`);
}

export function getApprovedPlan(approvalId: string): Promise<ApprovedPlan> {
  return getJson(`/api/v1/approvals/${encodeURIComponent(approvalId)}`);
}

export function getDeploymentRun(runId: string): Promise<DeploymentRun> {
  return getJson(`/api/v1/runs/${encodeURIComponent(runId)}`);
}

export async function downloadLocalPocRootCertificate(
  deploymentName: string,
): Promise<Blob> {
  const sessionNonce = await getSessionNonce();
  const response = await fetch(
    `/api/v1/certificates/local-poc/${encodeURIComponent(deploymentName)}`,
    {
      method: "GET",
      headers: {
        "X-Requested-With": "SecureGatewayStudio",
        "X-SGS-Session": sessionNonce,
      },
      credentials: "omit",
    },
  );
  if (!response.ok) {
    throw new ApiError(
      response.status,
      "certificate-download-failed",
      `Certificate download failed (${response.status})`,
    );
  }
  return response.blob();
}

export function listDeploymentRuns(): Promise<DeploymentRun[]> {
  return getJson("/api/v1/runs?limit=100");
}

export function getDeploymentDetails(runId: string): Promise<DeploymentDetails> {
  return getJson(`/api/v1/runs/${encodeURIComponent(runId)}/details`);
}

export function listGatewayLogs(
  runId: string,
  category: GatewayLogCategory,
  hours = 24,
): Promise<GatewayLogsResponse> {
  return getJson(
    `/api/v1/runs/${encodeURIComponent(runId)}/logs?category=${encodeURIComponent(category)}&hours=${hours}&limit=100`,
  );
}

export function enableGatewayLogging(runId: string): Promise<{ enabled: boolean }> {
  return postJson(`/api/v1/runs/${encodeURIComponent(runId)}/logs/enable`, {
    confirmation: "ENABLE LOGGING",
  });
}

export function getTeardownPlan(runId: string): Promise<TeardownPlan> {
  return getJson(`/api/v1/runs/${encodeURIComponent(runId)}/teardown-plan`);
}

export function startTeardown(
  runId: string,
  plan: TeardownPlan,
  confirmation: string,
): Promise<TeardownRun> {
  return postJson(`/api/v1/runs/${encodeURIComponent(runId)}/teardowns`, {
    plan_hash: plan.plan_hash,
    confirmation,
  });
}

export function getTeardownRun(teardownId: string): Promise<TeardownRun> {
  return getJson(`/api/v1/teardowns/${encodeURIComponent(teardownId)}`);
}

export function listAuditEvents(): Promise<AuditEvent[]> {
  return getJson("/api/v1/evidence/audit-events?limit=100");
}

export function getAuditIntegrity(): Promise<AuditIntegrity> {
  return getJson("/api/v1/evidence/integrity");
}

export function getAcceptanceReadiness(
  runId: string,
): Promise<AcceptanceReadiness> {
  return getJson(
    `/api/v1/runs/${encodeURIComponent(runId)}/acceptance`,
  );
}

export function verifySystemAcceptance(
  runId: string,
): Promise<AcceptanceReadiness> {
  return postJson(
    `/api/v1/runs/${encodeURIComponent(runId)}/acceptance/verify`,
    {},
  );
}

export function recordOperatorAcceptance(
  runId: string,
  request: {
    test_id: AcceptanceTestId;
    case_key: string;
    status: "user_confirmed" | "failed" | "skipped";
    summary: string;
    evidence: string;
  },
): Promise<AcceptanceResult> {
  return postJson(
    `/api/v1/runs/${encodeURIComponent(runId)}/acceptance-results`,
    { ...request, confirmation: "RECORD" },
  );
}
