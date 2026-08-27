export interface ConnectionValidation {
  provider: "google_cloud" | "workspace";
  status: "connected";
  principal_hint: string;
  resource_id: string;
  credential_kind: string;
  access_policy_id: string | null;
  read_only: true;
}

export interface DeployerBootstrapResult {
  project_id: string;
  operator_email: string;
  service_account_email: string;
  service_account_unique_id: string;
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
  subnet_cidr: string;
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
  upstream_vpc_project_id: string | null;
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
  /** Absent only when restoring a plan created by extension 0.2.9 or earlier. */
  created_at?: string;
  /** Approval freshness is authoritative after the server accepts approval. */
  expires_at?: string;
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
    | "rolling_back"
    | "rolled_back"
    | "rollback_unavailable"
    | "rollback_failed"
    | "interrupted"
    | "deleted"
    | "torn_down"
    | "clean";
  started_at: string;
  completed_at: string | null;
  retry_available?: boolean;
  residual_resources?: Array<{
    resource_key: string;
    provider: string;
    resource_type: string;
    resource_name: string;
    owned: boolean;
    shared: boolean;
  }>;
  operations: Array<{
    operation_id: string;
    resource_key: string;
    action: string;
    status: string;
    error_code: string | null;
  }>;
}

export type TeardownAction = "delete" | "delete_if_empty" | "restore" | "retain";

export interface DeploymentResource {
  resource_key: string;
  summary: string;
  provider: string;
  resource_type: string;
  resource_name: string;
  owned: boolean;
  teardown_action: TeardownAction;
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
  managed_chrome_access_level?: string | null;
  policy_principals: string[];
  target_group_email?: string | null;
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
  caller_ip: string | null;
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

import {
  ApiError,
  getBlob,
  getJson,
  postJson,
  runtimeCapabilities,
} from "./transport";

export { ApiError, runtimeCapabilities };

export function validateGoogleCloudConnection(
  projectId: string,
): Promise<ConnectionValidation> {
  return postJson("/api/v1/connections/google-cloud/validate", {
    project_id: projectId,
  });
}

export function bootstrapGoogleCloudDeployer(
  projectId: string,
  accessPolicyId?: string | null,
  migrateExistingDeployer = false,
  createReplacementDeployer = false,
  recreateDeletedDeployer = false,
): Promise<DeployerBootstrapResult> {
  return postJson("/api/v1/bootstrap/google-cloud/deployer", {
    project_id: projectId,
    ...(runtimeCapabilities.bootstrapAccessPolicyId
      ? { access_policy_id: accessPolicyId || null }
      : {}),
    confirmation: "BOOTSTRAP",
    ...(runtimeCapabilities.bootstrapAccessPolicyId && migrateExistingDeployer
      ? { ownership_migration_confirmation: "MIGRATE_EXISTING_DEPLOYER" }
      : {}),
    ...(runtimeCapabilities.bootstrapAccessPolicyId && createReplacementDeployer
      ? { replacement_deployer_confirmation: "CREATE_ISOLATED_REPLACEMENT" }
      : {}),
    ...(runtimeCapabilities.bootstrapAccessPolicyId && recreateDeletedDeployer
      ? { deleted_deployer_rebootstrap_confirmation: "RECREATE_DELETED_DEPLOYER" }
      : {}),
  });
}

export interface UserDataConsentStatus {
  accepted: boolean;
  migrationPrepared: boolean;
  version: string | null;
}

export interface ExtensionClientState {
  setup: unknown | null;
  workflow: unknown | null;
}

export function getUserDataConsentStatus(): Promise<UserDataConsentStatus> {
  return getJson<UserDataConsentStatus>("/api/v1/privacy/consent");
}

export function prepareUserDataConsent(options: {
  legacySetup?: unknown;
  legacyWorkflow?: unknown;
}): Promise<{ prepared: true }> {
  return postJson<{ prepared: true }>("/api/v1/privacy/consent/prepare", {
    legacy_setup: options.legacySetup,
    legacy_workflow: options.legacyWorkflow,
  });
}

export function finalizeUserDataConsent(): Promise<UserDataConsentStatus> {
  return postJson<UserDataConsentStatus>("/api/v1/privacy/consent/finalize", {});
}

export function getExtensionClientState(): Promise<ExtensionClientState> {
  return getJson<ExtensionClientState>("/api/v1/client-state");
}

export function saveExtensionClientState(state: {
  setup?: unknown | null;
  workflow?: unknown | null;
}): Promise<{ stored: true }> {
  return postJson<{ stored: true }>("/api/v1/client-state", state);
}

export function validateWorkspaceConnection(
  customerId: string,
): Promise<ConnectionValidation> {
  return postJson("/api/v1/connections/workspace/validate", {
    customer_id: customerId,
  });
}

export async function listOrganizationalUnitOptions(
  customerId: string,
): Promise<SetupOption[]> {
  const res = await postJson<{ options?: SetupOption[] } | SetupOption[]>(
    "/api/v1/setup-options/organizational-units",
    { customer_id: customerId },
  );
  return Array.isArray(res) ? res : res?.options ?? [];
}

export async function listGroupOptions(
  customerId: string,
): Promise<SetupOption[]> {
  const res = await postJson<{ options?: SetupOption[] } | SetupOption[]>(
    "/api/v1/setup-options/groups",
    { customer_id: customerId },
  );
  return Array.isArray(res) ? res : res?.options ?? [];
}

export async function listAccessLevelOptions(
  projectId: string,
): Promise<SetupOption[]> {
  const res = await postJson<{ options?: SetupOption[] } | SetupOption[]>(
    "/api/v1/setup-options/access-levels",
    { project_id: projectId },
  );
  return Array.isArray(res) ? res : res?.options ?? [];
}

export async function listVpcNetworkOptions(projectId: string): Promise<SetupOption[]> {
  const res = await postJson<{ options?: SetupOption[] } | SetupOption[]>(
    "/api/v1/setup-options/vpc-networks",
    { project_id: projectId },
  );
  return Array.isArray(res) ? res : (res.options ?? []);
}

export async function getRecommendedPocSourceImage(
  projectId: string,
): Promise<SetupOption> {
  const res = await postJson<{ option: SetupOption }>(
    "/api/v1/setup-options/recommended-poc-source-image",
    { project_id: projectId },
  );
  return res.option;
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

export function resumeDeploymentRun(runId: string): Promise<DeploymentRun> {
  return postJson(`/api/v1/runs/${encodeURIComponent(runId)}/resume`, {
    confirmation: "RESUME",
  });
}

export function downloadLocalPocRootCertificate(
  deploymentName: string,
): Promise<Blob> {
  return getBlob(
    `/api/v1/certificates/local-poc/${encodeURIComponent(deploymentName)}`,
    "certificate-download-failed",
  );
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

export function getLatestTeardownRun(runId: string): Promise<TeardownRun> {
  return getJson(
    `/api/v1/runs/${encodeURIComponent(runId)}/teardowns/latest`,
  );
}

export function resumeTeardownRun(teardownId: string): Promise<TeardownRun> {
  return postJson(
    `/api/v1/teardowns/${encodeURIComponent(teardownId)}/resume`,
    { confirmation: "RESUME" },
  );
}

export function listAuditEvents(): Promise<AuditEvent[]> {
  return getJson("/api/v1/evidence/audit-events?limit=100");
}

export function getAuditIntegrity(): Promise<AuditIntegrity> {
  return getJson("/api/v1/evidence/integrity");
}

export interface EvidenceBundle {
  schema_version: number;
  generated_at: string;
  app_version: string;
  integrity: AuditIntegrity;
  runs: DeploymentRun[];
  acceptance: AcceptanceResult[];
  audit_events: AuditEvent[];
}

export function exportEvidenceBundle(): Promise<EvidenceBundle> {
  return getJson<EvidenceBundle>("/api/v1/evidence/export");
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

export interface UpdateAccessLevelResult {
  success: boolean;
  access_level: string;
  policy_principals: string[];
  run_id: string;
}

export function updateAccessLevel(
  runId: string,
  accessLevel: string,
  principals?: string[],
): Promise<UpdateAccessLevelResult> {
  return postJson<UpdateAccessLevelResult>(`/api/v1/runs/${encodeURIComponent(runId)}/update-access-level`, {
    access_level: accessLevel,
    principals,
  });
}

/** Modules the CEP deployer can apply. */
export type CepModule =
  | "core"
  | "extensions"
  | "connectors"
  | "contextAwareAccess"
  | "dlpDetectors"
  | "dlpRules"
  | "dataBoundary";

export type CepDataBoundaryMode = "copy_paste" | "block_non_corp" | "none";

export type CepDlpRuleId =
  | "universal_upload"
  | "universal_download"
  | "payment_card"
  | "national_id"
  | "access_level"
  | "watermark"
  | "genai_block";

/** What a rule does when it matches. `off` means do not create it. */
export type CepDlpAction = "off" | "warnUser" | "blockContent";

export type CepDlpOperation = "upload" | "download" | "paste" | "print" | "watermark";

export interface CepDlpMatrixRuleConfig {
  upload?: CepDlpAction;
  download?: CepDlpAction;
  paste?: CepDlpAction;
  print?: CepDlpAction;
  watermark?: boolean;
  byodOnly?: boolean;
}

export type CepDlpMatrixState = Partial<Record<CepDlpRuleId, CepDlpMatrixRuleConfig>>;

export interface CepProvisionConfig {
  customer_id: string;
  project_id?: string;
  /** Bare organizational unit id. */
  target_ou_id: string;
  /** `orgUnitPath` of the same unit, needed to create sub OUs beneath it. */
  target_ou_path?: string;
  /** Exact current OU path typed immediately before the provision mutation. */
  target_ou_confirmation?: string;
  create_sub_ous?: boolean;
  core_policies?: boolean;
  force_extensions?: boolean;
  connectors?: boolean;
  /**
   * `NONE`, an `AUTO_CREATE_*` sentinel, or the resource name of an existing
   * access level. Same vocabulary as the deployment wizard's access step.
   */
  access_level?: string;
  /** Cloud Identity policy API; mutations are still in beta. */
  dlp_detectors?: boolean;
  dlp_rules?: boolean;
  /** ISO country code selecting which national identifier the rules scan for. */
  dlp_region?: string;
  /** Per-rule action; a rule set to `off` is not created. */
  dlp_rule_actions?: Partial<Record<CepDlpRuleId, CepDlpAction>>;
  /** Comprehensive DLP matrix state */
  dlp_matrix?: CepDlpMatrixState;
  data_boundary_mode?: CepDataBoundaryMode;
  internal_urls?: string[];
}

export interface CepRollbackConfig {
  customer_id: string;
  project_id?: string;
  target_ou_id: string;
  target_ou_path?: string;
  verify_match?: boolean;
  rollback_modules?: CepModule[];
  /** AUTO_CREATE candidates are inspected but retained without durable ownership. */
  access_level?: string;
}

export interface CepLicenseAssignConfig {
  customer_id: string;
  project_id: string;
  target_ou_id: string;
  target_ou_path?: string;
  /** Exact current OU path typed immediately before the licence mutation. */
  target_ou_confirmation?: string;
  product_id?: string;
  sku_id?: string;
}

export interface CepLicenseAssignResult {
  success: boolean;
  message: string;
  total_users: number;
  assigned_count: number;
  already_assigned_count: number;
  failed_count: number;
  assigned_users: string[];
  errors: string[];
  debug_trace: CepTraceItem[];
}

export interface CepTraceItem {
  label: string;
  method: string;
  url: string;
  status: number;
  ok: boolean;
  error?: string;
}

export interface CepProvisionResult {
  success: boolean;
  message: string;
  created_items: string[];
  skipped_items: string[];
  debug_trace: CepTraceItem[];
}

export function provisionCepPolicies(
  config: CepProvisionConfig,
): Promise<CepProvisionResult> {
  return postJson<CepProvisionResult>("/api/v1/cep/provision", config);
}

export function rollbackCepPolicies(
  config: CepRollbackConfig,
): Promise<CepProvisionResult> {
  return postJson<CepProvisionResult>("/api/v1/cep/rollback", config);
}

export function assignCepLicenses(
  config: CepLicenseAssignConfig,
): Promise<CepLicenseAssignResult> {
  return postJson<CepLicenseAssignResult>("/api/v1/cep/assign-licenses", config);
}

export function generateCepScript(
  config: CepProvisionConfig,
): Promise<{ script: string; filename: string }> {
  return postJson<{ script: string; filename: string }>(
    "/api/v1/cep/script",
    config,
  );
}

/**
 * Ask the runtime for an administrator session, prompting for consent.
 *
 * Every other call path acquires tokens silently so nothing can open a consent
 * window on its own. Call this only from an explicit operator action; a build
 * without the capability has nothing to prompt and reports the session as-is.
 */
export async function signInSession(): Promise<
  { authenticated: boolean; operator?: string }
> {
  if (!runtimeCapabilities.sessionSignIn) return { authenticated: true };
  return await postJson<{ authenticated: boolean; operator?: string }>(
    "/api/v1/auth/sign-in",
    {},
  );
}

export async function signOutSession(): Promise<void> {
  if (!runtimeCapabilities.sessionSignOut) return;
  await postJson<{ success: boolean }>("/api/v1/auth/sign-out", {});
}


