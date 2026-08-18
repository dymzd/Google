import type { Locale } from "../lib/setup-state";

export interface WorkflowMessages {
  identitiesTitle: string;
  identitiesIntro: string;
  cloudAccount: string;
  cloudAccountDescription: string;
  workspaceAccount: string;
  workspaceAccountDescription: string;
  projectId: string;
  operatorIdentity: string;
  adminIdentity: string;
  connect: string;
  connected: string;
  notConnected: string;
  checking: string;
  connectionFailed: string;
  adcUnavailable: string;
  cloudValidationFailed: string;
  workspaceValidationFailed: string;
  workspaceRequiredRolesHint: string;
  connectionNotice: string;
  bootstrapDeployer: string;
  bootstrapDeployerHint: string;
  bootstrapConfirm: string;
  bootstrapWorking: string;
  bootstrapComplete: string;
  bootstrapNext: string;
  bootstrapFailed: string;
  progressTitle: string;
  progressCount: (completed: number, total: number) => string;
  currentOperation: string;
  waitingForOperation: string;
  environmentTitle: string;
  environmentIntro: string;
  deploymentName: string;
  region: string;
  zone: string;
  secondaryZone: string;
  sourceImage: string;
  sourceImageHint: string;
  minimumReplicas: string;
  maximumReplicas: string;
  cpuTarget: string;
  autoscalingHint: string;
  network: string;
  vpcName: string;
  subnetName: string;
  managedSample: string;
  managedSampleDescription: string;
  existingBackend: string;
  existingBackendDescription: string;
  directHttps: string;
  directHttpsDescription: string;
  internalHttpsLb: string;
  internalHttpsLbDescription: string;
  legacyNginxTitle: string;
  legacyNginxDescription: string;
  proxySubnetCidr: string;
  backendUrl: string;
  directHttpsUrl: string;
  applicationEgressRegion: string;
  applicationEgressRegionHint: string;
  backendLocation: string;
  backendLocationGcp: string;
  backendLocationAws: string;
  backendLocationAzure: string;
  backendLocationOnPrem: string;
  confirmBackendConnectivity: string;
  backendConnectivityHint: string;
  deploySampleBackend: string;
  deployingSampleBackend: string;
  sampleBackendReady: string;
  sampleBackendDescription: string;
  cloudConsoleLinks: string;
  openInCloudConsole: string;
  computeInstancesLink: string;
  securityGatewaysLink: string;
  vpcNetworksLink: string;
  cloudNatLink: string;
  chromeAdminLink: string;
  architectureBlueprint: string;
  directHttpsConnectivity: string;
  directHttpsConnectivityHint: string;
  hostname: string;
  noExternalIpNotice: string;
  certificateStepTitle: string;
  certificateIntro: string;
  internalLbCertificateIntro: string;
  caPool: string;
  caName: string;
  secretName: string;
  certificateNotice: string;
  internalLbCertificateNotice: string;
  directCertificateIntro: string;
  directCertificateNotice: string;
  directPrivateCertificate: string;
  accessTitle: string;
  accessIntro: string;
  customerId: string;
  targetOuId: string;
  managedChromeAccessLevel: string;
  managedChromeAccessLevelHint: string;
  optionsLoadedHint: string;
  optionsLoading: string;
  chooseOption: string;
  noOptions: string;
  retryOptions: string;
  ouOptionsFailed: string;
  accessLevelOptionsFailed: string;
  groupOptionsFailed: string;
  prerequisitesTitle: string;
  confirmEnterpriseLicense: string;
  confirmWorkspaceServices: string;
  confirmEndpointVerification: string;
  confirmTestOu: string;
  principalType: string;
  principalValue: string;
  addPrincipal: string;
  removePrincipal: string;
  user: string;
  group: string;
  domain: string;
  accessNotice: string;
  reviewTitle: string;
  reviewIntro: string;
  configuration: string;
  safetyGates: string;
  ready: string;
  incomplete: string;
  verified: string;
  plannedOnApply: string;
  manualCheck: string;
  actionRequired: string;
  approvalPending: string;
  pocDefault: string;
  reviewGateLegend: string;
  gateLabels: Record<string, string>;
  gateDescriptions: Record<string, string>;
  managedProfileEvidence: (total: number, profileOnly: number, sync: string | null) => string;
  clientExtensionEvidence: (name: string, version: string | null, installed: boolean) => string;
  missingPermissions: (count: number) => string;
  approvePlan: string;
  approvePlanDescription: string;
  generatePlan: string;
  runPreflight: string;
  preparingPlan: string;
  planReady: string;
  planBlocked: string;
  changesCount: (count: number) => string;
  preflightProgressTitle: string;
  preflightStage1: string;
  preflightStage2: string;
  preflightStage3: string;
  preflightStage4: string;
  preflightStage5: string;
  preflightComplete: string;
  plannedChangesTitle: string;
  plannedChangesIntro: string;
  changeAction: (action: string) => string;
  changeRisk: (risk: string) => string;
  changeSummary: (resourceType: string, fallback: string) => string;
  diagnosticsTitle: string;
  apiEvidence: string;
  diagnosticMessage: (code: string, fallback: string) => string;
  diagnosticRemediation: (code: string, fallback: string | null) => string;
  approveWorking: string;
  approvalReady: string;
  continueToApply: string;
  applyTitle: string;
  applyIntro: string;
  preflight: string;
  desiredStatePlan: string;
  applyChanges: string;
  applyLocked: string;
  applying: string;
  runSucceeded: string;
  runRolledBack: string;
  runInterrupted: string;
  runFailed: string;
  operationCount: (count: number) => string;
  evidenceNotice: string;
  caHandoffTitle: string;
  caHandoffDescription: string;
  caHandoffSteps: readonly [string, string, string];
  downloadRootCa: string;
  downloadingRootCa: string;
  openAdminConsoleGuide: string;
  caDownloadFailed: string;
  previous: string;
  next: string;
}

export interface OperationsMessages {
  deploymentsTitle: string;
  deploymentsIntro: string;
  evidenceTitle: string;
  evidenceIntro: string;
  loading: string;
  loadFailed: string;
  noRuns: string;
  noEvents: string;
  runId: string;
  status: string;
  started: string;
  operationsCount: string;
  manage: string;
  close: string;
  overviewTab: string;
  logsTab: string;
  resourcesTab: string;
  deleteTab: string;
  deploymentName: string;
  project: string;
  gateway: string;
  application: string;
  architecture: string;
  ownershipRun: string;
  architectureLabel: (kind: string) => string;
  accessLevelControlTitle: string;
  accessLevelControlIntro: string;
  selectAccessLevelLabel: string;
  principalsLabel: string;
  principalsHelper: string;
  noAccessLevelRequired: string;
  boundGroup: string;
  updateAccessLevelButton: string;
  updatingAccessLevel: string;
  accessLevelSaved: string;
  ownedResources: string;
  retainedResources: string;
  resourceAction: (action: string) => string;
  logsTitle: string;
  logsIntro: string;
  logCategory: (category: string) => string;
  hours24: string;
  hours168: string;
  refreshLogs: string;
  refreshingLogs: string;
  enableLogging: string;
  enablingLogging: string;
  loggingEnabled: string;
  loggingNotEnabled: string;
  noLogs: string;
  logQueryFailed: string;
  dataAccessNotice: string;
  nginxNotice: string;
  principal: string;
  method: string;
  requestId: string;
  payload: string;
  teardownTitle: string;
  teardownIntro: string;
  teardownSharedNotice: string;
  teardownUnavailable: string;
  teardownConfirmation: string;
  teardownConfirmationHint: string;
  startTeardown: string;
  teardownRunning: string;
  teardownSucceeded: string;
  teardownFailed: string;
  teardownActionFailed: string;
  teardownProgress: (completed: number, total: number) => string;
  exportEvidence: string;
  integrityValid: string;
  integrityInvalid: string;
  eventCount: (count: number) => string;
  chainHead: string;
  recentEvents: string;
  notAvailable: string;
  acceptanceTitle: string;
  acceptanceIntro: string;
  noSuccessfulRun: string;
  runSystemChecks: string;
  runningSystemChecks: string;
  acceptanceComplete: string;
  acceptancePending: string;
  requiredProgress: (satisfied: number, required: number) => string;
  acceptanceTest: (testId: string) => string;
  acceptanceScope: (caseKey: string) => string;
  acceptanceStatus: (status: string) => string;
  evidenceSource: (source: string) => string;
  missingEvidence: string;
  viewEvidence: string;
  operatorEvidenceTitle: string;
  operatorEvidenceIntro: string;
  testCase: string;
  testInstruction: (testId: string, caseKey: string) => string;
  evidenceOutcome: string;
  outcomePassed: string;
  outcomeFailed: string;
  outcomeSkipped: string;
  evidenceSummary: string;
  evidenceDetail: string;
  recordEvidence: string;
  recordingEvidence: string;
  evidenceRecorded: string;
  acceptanceActionFailed: string;
  statusSucceeded: string;
  statusDeleted: string;
  statusRunning: string;
  statusPending: string;
  statusFailed: string;
  t07DiagnosticsTitle: string;
  t07DiagnosticsIntro: string;
  t07Diagnostics: readonly {
    symptom: string;
    meaning: string;
    actions: readonly string[];
  }[];
}

export interface GuideFaqItem {
  id: string;
  category: string;
  question: string;
  answer: string;
  checklist?: readonly string[];
}

export interface GuideStepApiCall {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  endpoint: string;
  purpose: string;
}

export interface GuideStepOptionBehavior {
  name: string;
  behavior: string;
}

export interface GuideStep {
  title: string;
  subtitle: string;
  summary: string;
  actions: readonly string[];
  optionsBehavior?: readonly GuideStepOptionBehavior[];
  apiCalls?: readonly GuideStepApiCall[];
  safetyNote?: string;
}

export interface GuideMessages {
  eyebrow: string;
  title: string;
  intro: string;
  pocNoticeTitle: string;
  pocNoticeBody: string;
  quickOverviewTitle: string;
  quickOverviewIntro: string;
  architectureTitle: string;
  architectureIntro: string;
  costOverviewTitle: string;
  costOverviewIntro: string;
  architectures: readonly {
    eyebrow: string;
    title: string;
    summary: string;
    estimatedCost: string;
    costFixed: string;
    costVariable: string;
    nodes: readonly { label: string; detail: string; costBadge?: string }[];
    supports: readonly { label: string; detail: string }[];
  }[];
  implementationTitle: string;
  implementationIntro: string;
  implementationGroups: readonly {
    eyebrow: string;
    title: string;
    items: readonly string[];
  }[];
  stepLabel: (step: number) => string;
  technicalDeepDiveTitle: string;
  technicalDeepDiveIntro: string;
  optionsBehaviorLabel: string;
  apiCallsLabel: string;
  safetyGuardrailLabel: string;
  steps: readonly GuideStep[];
  faqTitle: string;
  faqIntro: string;
  faqs: readonly GuideFaqItem[];
}

export interface Messages {
  productName: string;
  localOnly: string;
  cloudIdentity: string;
  cloudProject: string;
  workspaceIdentity: string;
  adminEmail: string;
  help: string;
  nav: {
    deployments: string;
    newSetup: string;
    policies: string;
    evidence: string;
    settings: string;
    guide: string;
    cepDeployer: string;
    easyPoc: string;
    sgwDeployer: string;
  };
  title: string;
  steps: readonly string[];
  modeTitle: string;
  poc: string;
  pocDescription: string;
  production: string;
  productionDescription: string;
  productionUnavailable: string;
  platformsTitle: string;
  managedChromeOnly: string;
  platformNote: string;
  infrastructureTitle: string;
  dedicatedNetwork: string;
  recommended: string;
  dedicatedDescription: string;
  existingVpc: string;
  existingDescription: string;
  certificateTitle: string;
  enterpriseCa: string;
  enterpriseCaDescription: string;
  publicCertificate: string;
  publicCertificateDescription: string;
  localPocCa: string;
  disabledProduction: string;
  localPocAdminConsole: string;
  localPocCaDescription: string;
  posture: string;
  mode: string;
  managedPlatforms: string;
  platformCount: (count: number) => string;
  infrastructure: string;
  certificateStrategy: string;
  targetOu: string;
  testOuAvailable: string;
  deploymentGates: string;
  noExternalIps: string;
  cloudNat: string;
  upstreamVpc: string;
  privateDnsRoute: string;
  applicationOwnedTls: string;
  apiPreflight: string;
  approval: string;
  required: string;
  willValidate: string;
  gateNote: string;
  back: string;
  continue: string;
  noChanges: string;
  draftSaved: string;
  lastSaved: string;
  justNow: string;
  languages: {
    english: string;
    japanese: string;
  };
  mainTitle: string;
  workflow: WorkflowMessages;
  operations: OperationsMessages;
  guide: GuideMessages;
  cepDeployer: CepDeployerMessages;
}

export interface CepDeployerMessages {
  title: string;
  subtitle: string;
  intro: string;
  targetOuCardTitle: string;
  targetOuCardSubtitle: string;
  selectTargetOu: string;
  ouLoadFailed: string;
  autoCreateSubOus: string;
  autoCreateSubOusHint: string;
  presetsTitle: string;
  presetsSubtitle: string;
  presetFullPoc: string;
  presetFullPocDesc: string;
  presetAiProtection: string;
  presetAiProtectionDesc: string;
  presetEndpoint: string;
  presetEndpointDesc: string;
  presetAudit: string;
  presetAuditDesc: string;
  modulesTitle: string;
  modulesSubtitle: string;
  moduleCorePolicies: string;
  moduleCorePoliciesDesc: string;
  moduleForceExtensions: string;
  moduleForceExtensionsDesc: string;
  moduleConnectors: string;
  moduleConnectorsDesc: string;
  accessLevelTitle: string;
  accessLevelHint: string;
  accessLevelNone: string;
  accessLevelNoneDesc: string;
  accessLevelAutoProfile: string;
  accessLevelAutoBrowser: string;
  accessLevelAutoAny: string;
  accessLevelExistingGroup: string;
  accessLevelLoadFailed: string;
  moduleDlpDetectors: string;
  moduleDlpDetectorsDesc: string;
  moduleDlpRules: string;
  moduleDlpRulesDesc: string;
  betaBadge: string;
  dlpBetaNote: string;
  dlpRegionTitle: string;
  dlpRegionHint: string;
  dlpRulesTableTitle: string;
  dlpRulesTableHint: string;
  dlpActionOff: string;
  dlpActionAudit: string;
  dlpActionWarn: string;
  dlpActionBlock: string;
  dlpRuleNationalId: string;
  dlpRulePaymentCard: string;
  dlpRuleAccessLevel: string;
  dlpRuleWatermark: string;
  dataBoundaryModeTitle: string;
  dataBoundaryModeCopyPaste: string;
  dataBoundaryModeCopyPasteDesc: string;
  dataBoundaryModeBlockNonCorp: string;
  dataBoundaryModeBlockNonCorpDesc: string;
  dataBoundaryModeNone: string;
  dataBoundaryModeNoneDesc: string;
  internalUrlsTitle: string;
  internalUrlsPlaceholder: string;
  internalUrlsHint: string;
  rolesCardTitle: string;
  rolesCardSubtitle: string;
  roleAdminLabel: string;
  roleAdminDesc: string;
  roleAuditorLabel: string;
  roleAuditorDesc: string;
  assignUserEmailLabel: string;
  assignUserEmailPlaceholder: string;
  provisionRolesButton: string;
  provisioningRoles: string;
  rolesProjectRequired: string;
  testingScenariosTitle: string;
  testingScenariosSubtitle: string;
  copyDummyData: string;
  copiedToClipboard: string;
  dummyPiiLabel: string;
  dummyPiiValue: string;
  dummyPiiHint: string;
  dummyCreditCardLabel: string;
  dummyCreditCardValue: string;
  dummyCreditCardHint: string;
  dummySourceCodeLabel: string;
  dummySourceCodeValue: string;
  dummySourceCodeHint: string;
  scenarioGenAiTitle: string;
  scenarioGenAiStep: string;
  scenarioDataBoundaryTitle: string;
  scenarioDataBoundaryStep: string;
  scenarioWatermarkTitle: string;
  scenarioWatermarkStep: string;
  manualChecklistTitle: string;
  manualChecklistSubtitle: string;
  manualChecklistItems: ReadonlyArray<{
    title: string;
    detail: string;
    href: string;
  }>;
  btnDeploy: string;
  btnDeploying: string;
  btnRollback: string;
  btnRollingBack: string;
  btnDownloadScript: string;
  confirmRollback: string;
  downloadFailed: string;
  noModulesSelected: string;
  appliedTitle: string;
  skippedTitle: string;
  statusLogTitle: string;
  noActionYet: string;

  // License assignment & Auto-assign guidance
  licenseCardTitle: string;
  licenseCardSubtitle: string;
  licenseAutoAssignWarning: string;
  licenseAutoAssignWarningLink: string;
  licenseAutoAssignSteps: ReadonlyArray<string>;
  btnAssignLicensesToOu: string;
  btnAssigningLicenses: string;
  licenseAssignUsersFound: string;
  noUsersFoundInOu: string;

  // DLP Controls Matrix
  dlpMatrixTitle: string;
  dlpMatrixSubtitle: string;
  dlpColThreat: string;
  dlpColUpload: string;
  dlpColDownload: string;
  dlpColPaste: string;
  dlpColPrint: string;
  dlpColWatermark: string;
  dlpColDeviceScope: string;

  dlpRowUniversalUpload: string;
  dlpRowUniversalUploadDesc: string;
  dlpRowUniversalDownload: string;
  dlpRowUniversalDownloadDesc: string;
  dlpRowPaymentCard: string;
  dlpRowPaymentCardDesc: string;
  dlpRowNationalId: string;
  dlpRowNationalIdDesc: string;
  dlpRowAccessLevel: string;
  dlpRowAccessLevelDesc: string;
  dlpRowWatermark: string;
  dlpRowWatermarkDesc: string;
  dlpRowGenAiBlock: string;
  dlpRowGenAiBlockDesc: string;

  dlpScopeAll: string;
  dlpScopeByodOnly: string;
  dlpActionBadgeBlock: string;
  dlpActionBadgeWarn: string;
  dlpActionBadgeAudit: string;
  dlpActionBadgeOff: string;

  dlpPresetRecommended: string;
  dlpPresetRecommendedDesc: string;
  dlpPresetStrictZeroTrust: string;
  dlpPresetStrictZeroTrustDesc: string;
  dlpPresetGenAiSecure: string;
  dlpPresetGenAiSecureDesc: string;
  dlpPresetAuditOnly: string;
  dlpPresetAuditOnlyDesc: string;
}

const en: Messages = {
  mainTitle: "Chrome Enterprise Premium PoC Deployer",
  productName: "Secure Gateway Studio",
  localOnly: "Local only",
  cloudIdentity: "Google Cloud",
  cloudProject: "Not connected",
  workspaceIdentity: "Google Workspace",
  adminEmail: "Not connected",
  help: "Help",
  nav: {
    deployments: "Deployments",
    newSetup: "New setup",
    policies: "Policies",
    evidence: "Evidence",
    settings: "Settings",
    guide: "Guide",
    cepDeployer: "Easy PoC",
    easyPoc: "Easy PoC",
    sgwDeployer: "Secure Gateway Deployer",
  },
  title: "New secure gateway setup",
  steps: ["Mode", "Identities", "Environment", "Certificate", "Access", "Review", "Apply"],
  modeTitle: "1. Start a rapid Secure Gateway PoC",
  poc: "Rapid proof of concept",
  pocDescription:
    "Build a test-OU deployment quickly with disposable resources and explicit safety gates. A local CA can be uploaded to managed Chrome through the Admin console.",
  production: "Production",
  productionDescription:
    "Enterprise PKI, regional high availability, dedicated service identities, least privilege, and auditable change control are retained for a future release.",
  productionUnavailable: "coming later",
  platformsTitle: "2. Managed Chrome platforms",
  managedChromeOnly: "targets managed Google Chrome only",
  platformNote:
    "Select only platforms you can test during this PoC. Each selected platform creates a required T07 end-to-end acceptance case. Other browsers are not targeted.",
  infrastructureTitle: "3. Infrastructure strategy",
  dedicatedNetwork: "Dedicated network",
  recommended: "Recommended",
  dedicatedDescription: "Create a new VPC dedicated to Secure Gateway services.",
  existingVpc: "Existing VPC",
  existingDescription: "Deploy into an existing VPC that you manage.",
  certificateTitle: "4. Certificate strategy",
  enterpriseCa: "Enterprise PKI / CA Service",
  enterpriseCaDescription: "Use organization CA or Cloud CA Service for internal TLS certificates.",
  publicCertificate: "Publicly trusted certificate",
  publicCertificateDescription: "Use a publicly trusted certificate for a controlled DNS name.",
  localPocCa: "Local PoC CA",
  disabledProduction: "disabled in Production",
  localPocAdminConsole: "Admin console upload required",
  localPocCaDescription:
    "Generate a private root and leaf certificate, download the public root after Apply, then upload it for the test OU and selected platforms in the Google Admin console.",
  posture: "Deployment posture",
  mode: "Mode",
  managedPlatforms: "Managed Chrome platforms",
  platformCount: (count: number) => `${count} platforms selected`,
  infrastructure: "Infrastructure",
  certificateStrategy: "Certificate strategy",
  targetOu: "Target OU",
  testOuAvailable: "Test OU available",
  deploymentGates: "Deployment gates",
  noExternalIps: "No external IPs",
  cloudNat: "Cloud NAT",
  upstreamVpc: "Existing upstream VPC",
  privateDnsRoute: "Private DNS, firewall, and return route",
  applicationOwnedTls: "TLS owned by the HTTPS application",
  apiPreflight: "API preflight",
  approval: "Approval",
  required: "Required",
  willValidate: "Will validate",
  gateNote: "All gates must pass before deployment can be applied.",
  back: "Back",
  continue: "Continue to identities",
  noChanges: "No changes have been applied",
  draftSaved: "Draft saved locally",
  lastSaved: "Last saved",
  justNow: "just now",
  languages: { english: "English", japanese: "日本語" },
  workflow: {
    identitiesTitle: "Connect administrator identities",
    identitiesIntro:
      "Use keyless Application Default Credentials that impersonate a dedicated service account. JSON keys are never accepted or stored.",
    cloudAccount: "Google Cloud deployer",
    cloudAccountDescription:
      "Used for discovery, planning, and applying approved GCP changes.",
    workspaceAccount: "Chrome-authorized service account",
    workspaceAccountDescription:
      "The same keyless identity, assigned a direct Chrome admin role for the target OU.",
    projectId: "Google Cloud project ID",
    operatorIdentity: "Validated credential",
    adminIdentity: "Validated administrator credential",
    connect: "Validate connection",
    connected: "Connected",
    notConnected: "Not connected",
    checking: "Checking…",
    connectionFailed: "Validation failed",
    adcUnavailable:
      "Keyless Application Default Credentials are unavailable. Run “gcloud auth application-default login --impersonate-service-account=SERVICE_ACCOUNT_EMAIL”, then retry.",
    cloudValidationFailed:
      "Google Cloud validation failed. Verify the project ID and read permissions.",
    workspaceValidationFailed:
      "Workspace validation failed. Verify the customer ID and Chrome Policy administrator permissions.",
    workspaceRequiredRolesHint:
      "Required Workspace privileges: Chrome Management (Policy & Settings), Organizational Units (Create/Read for sub-OUs), Groups (Read-only), Domain (Read-only), and Rule Management (Chrome DLP). Super Admin is not required if these are granted via Chrome Admin or custom admin roles.",
    connectionNotice:
      "Connection validation is read-only. Apply permissions are checked separately during preflight.",
    bootstrapDeployer: "Create deployer and least-privilege role",
    bootstrapDeployerHint:
      "Required operator roles: Service Account Admin (roles/iam.serviceAccountAdmin), Role Administrator (roles/iam.roleAdmin), and Project IAM Admin (roles/resourcemanager.projectIamAdmin). Alternatively, Security Admin (roles/iam.securityAdmin) or Owner.",
    bootstrapConfirm:
      "Create or update the deployer service account, custom role, project bindings, and your Token Creator binding?",
    bootstrapWorking: "Creating deployer…",
    bootstrapComplete: "Deployer service account ready",
    bootstrapNext:
      "The deployer service account and least-privilege role were configured in Google Cloud. Browser authentication is active.",
    bootstrapFailed: "Automatic deployer setup failed",
    progressTitle: "Deployment progress",
    progressCount: (completed: number, total: number) =>
      `${completed} of ${total} operations complete`,
    currentOperation: "Current operation",
    waitingForOperation: "Waiting for the first operation…",
    environmentTitle: "Configure the private environment",
    environmentIntro:
      "Define the desired state. Existing resources are discovered before any mutation.",
    deploymentName: "Deployment name",
    region: "Region",
    zone: "Zone",
    secondaryZone: "Secondary zone (Production HA)",
    sourceImage: "Immutable hardened VM image",
    sourceImageHint:
      "Production requires a versioned image with Python 3 and Nginx preinstalled; image families are rejected.",
    minimumReplicas: "Minimum Nginx replicas",
    maximumReplicas: "Maximum Nginx replicas",
    cpuTarget: "Autoscaling CPU target (0.1–0.9)",
    autoscalingHint:
      "Production uses a two-zone regional managed instance group. CPU autoscaling is used because passthrough load-balancer utilization is not an autoscaling signal.",
    network: "Deployment architecture",
    vpcName: "Existing VPC name",
    subnetName: "Existing subnet name",
    managedSample: "Managed sample backend (Nginx)",
    managedSampleDescription:
      "Create a private HTTP backend for validation and evidence collection.",
    existingBackend: "Existing HTTP backend (Nginx)",
    existingBackendDescription:
      "Route to an administrator-managed private HTTP endpoint over connectivity that already exists.",
    directHttps: "Option A — Connect directly to an existing HTTPS app",
    directHttpsDescription:
      "Connect Secure Gateway directly to an existing HTTPS endpoint through its VPC. No Nginx, VM, NAT, or offload certificate is created.",
    internalHttpsLb:
      "Option B — HTTPS offload with Internal Application Load Balancer",
    internalHttpsLbDescription:
      "Terminate HTTPS on a regional internal Application Load Balancer, then forward HTTP to a private sample backend. No Nginx offload tier is deployed.",
    legacyNginxTitle: "Option C — Legacy Nginx method / advanced settings",
    legacyNginxDescription:
      "Expand only when an HTTP application or the previous Nginx-based deployment is required.",
    proxySubnetCidr: "ILB proxy-only subnet CIDR",
    backendUrl: "Backend URL (http://)",
    directHttpsUrl: "Private HTTPS endpoint (https://host[:port])",
    applicationEgressRegion: "Egress region (optional)",
    applicationEgressRegionHint:
      "Leave empty for cross-region-capable targets. Set the app or static-route region for a regional target.",
    backendLocation: "Backend hosting location",
    backendLocationGcp: "Google Cloud",
    backendLocationAws: "AWS",
    backendLocationAzure: "Azure",
    backendLocationOnPrem: "On premises",
    confirmBackendConnectivity:
      "I confirm private routing, DNS, and backend firewall access already exist from the selected GCP VPC/subnet",
    backendConnectivityHint:
      "This PoC configures Nginx and verifies the upstream with T02. It does not create AWS/Azure VPNs, Cloud VPN, Interconnect, or on-premises routing. Establish that private path first; do not enter public endpoints or credentials here.",
    deploySampleBackend: "Deploy Sample Backend VM (1-Click)",
    deployingSampleBackend: "Deploying VM, VPC, NAT & Firewall...",
    sampleBackendReady: "Sample backend VM is running at secgw-backend.internal",
    sampleBackendDescription:
      "Provisions a private Debian 12 Nginx HTTPS/HTTP VM (10.10.0.2), custom VPC, Cloud NAT (fixed static IP), and firewall rules in Google Cloud.",
    cloudConsoleLinks: "Google Cloud & Workspace Console Deep-Links",
    openInCloudConsole: "Open in Cloud Console",
    computeInstancesLink: "Compute Engine VM Instances",
    securityGatewaysLink: "BeyondCorp Security Gateways",
    vpcNetworksLink: "VPC Networks & Firewalls",
    cloudNatLink: "Cloud NAT (Egress Fixed IP)",
    chromeAdminLink: "Chrome Admin Policies",
    architectureBlueprint: "Architecture Blueprint & Telemetry",
    directHttpsConnectivity:
      "I confirm the selected VPC resolves this hostname, routes to the HTTPS app, allows TCP from 136.124.16.0/20, and has a return path",
    directHttpsConnectivityHint:
      "Secure Gateway connects directly to the HTTPS app. For AWS, Azure, or on-premises, first configure Cloud VPN/Interconnect, Cloud DNS forwarding, firewall rules, and an explicit return route for 136.124.16.0/20.",
    hostname: "Private application hostname",
    noExternalIpNotice:
      "VM external IPs are permanently disabled. Cloud NAT provides controlled package egress.",
    certificateStepTitle: "Configure TLS certificate source",
    certificateIntro:
      "The offload VM reads certificate material at runtime from Secret Manager; private keys are never written into startup scripts.",
    internalLbCertificateIntro:
      "The regional internal Application Load Balancer terminates HTTPS with a regional server certificate. Certificate material moves directly from memory to the Compute API and remains in Secret Manager for controlled lifecycle management.",
    caPool: "CA pool resource",
    caName: "Issuing CA resource",
    secretName: "Secret Manager certificate secret",
    certificateNotice:
      "Local CA is PoC-only. After Apply, download the public PEM root, add it at Chrome > Connectors > Chrome Root Store, and connect that configuration to the dedicated test OU. Public APIs cannot reliably inspect or perform this handoff; verify trust with T07. Production still requires enterprise-pretrusted PKI or a publicly trusted certificate.",
    internalLbCertificateNotice:
      "For a local CA, the ILB presents the generated server certificate. After Apply, distribute only its public PEM root through Chrome Root Store to the test OU, restart Chrome, and verify HTTPS with T07. The private key is never distributed to Chrome.",
    directCertificateIntro:
      "The HTTPS application owns TLS termination. Secure Gateway does not create or store its certificate or private key.",
    directCertificateNotice:
      "For a publicly trusted app certificate, no Root Store action is needed. For a private CA, obtain the issuing root PEM from the application owner and add it manually at Chrome > Connectors > Chrome Root Store for the test OU; this configuration cannot be read or written reliably through the public API.",
    directPrivateCertificate: "Private app CA / manual Chrome Root Store trust",
    accessTitle: "Limit Chrome policy and application access",
    accessIntro:
      "Start with the dedicated test OU and the smallest possible principal set.",
    customerId: "Workspace customer ID",
    targetOuId: "Dedicated test OU ID",
    managedChromeAccessLevel: "Managed Chrome access level",
    managedChromeAccessLevelHint:
      "Select the existing Access Context Manager level for this setup. It may target profile-managed Chrome, browser-managed Chrome, or both.",
    optionsLoadedHint:
      "Options are loaded read-only from Google Cloud and Google Workspace using the validated service account.",
    optionsLoading: "Loading options…",
    chooseOption: "Select an option",
    noOptions: "No options available",
    retryOptions: "Retry",
    ouOptionsFailed:
      "Organizational units could not be loaded. Enable Admin SDK API and grant the service account Organizational Units read access.",
    accessLevelOptionsFailed:
      "Access levels could not be loaded. Grant the service account Policy Reader on the intended Access Context Manager policy.",
    groupOptionsFailed:
      "Groups could not be loaded. Add Groups read permission to the service account's Google Workspace administrator role.",
    prerequisitesTitle: "Manual prerequisite confirmation",
    confirmEnterpriseLicense:
      "Chrome Enterprise Premium licenses are assigned to the target users",
    confirmWorkspaceServices:
      "Additional Google services and Google Cloud access are enabled for the target users",
    confirmEndpointVerification:
      "Endpoint Verification device-signal collection is enabled for this OU",
    confirmTestOu: "I confirm this is a non-production test OU",
    principalType: "Principal type",
    principalValue: "Principal",
    addPrincipal: "Add principal",
    removePrincipal: "Remove",
    user: "User",
    group: "Group",
    domain: "Domain",
    accessNotice:
      "The app conditionally grants application access through the verified managed-Chrome access level, and force-installs Secure Gateway plus Endpoint Verification only in this OU.",
    reviewTitle: "Review detected state and automatic changes",
    reviewIntro:
      "Compare what the APIs verified, what Apply will configure, and what still needs attention. This screen makes no changes.",
    configuration: "Configuration",
    safetyGates: "Safety gates",
    ready: "Ready",
    incomplete: "Incomplete",
    verified: "Ready",
    plannedOnApply: "Automatic on Apply",
    manualCheck: "Manual check",
    actionRequired: "Action required",
    approvalPending: "Awaiting approval",
    pocDefault: "PoC setting",
    reviewGateLegend:
      "Ready = resolved by API discovery, administrator confirmation, or a configuration invariant. Automatic on Apply = created or updated after approval. Manual check = not reliably detectable by the available API. Action required = blocks Apply.",
    gateLabels: {
      "immutable-image": "PoC image",
      "billing-enabled": "Cloud Billing",
      "enterprise-license": "Chrome Enterprise Premium license",
      "chrome-root-store": "Chrome Root Store trust",
      "workspace-services": "Workspace services",
      "managed-chrome-profile": "Managed Chrome profile",
      "secure-enterprise-browser-client": "Secure Enterprise Browser client",
      "endpoint-verification": "Endpoint Verification",
      "no-external-ips": "No external IPs",
      "private-egress": "Cloud NAT",
      "backend-connectivity": "Existing backend connectivity",
      "test-ou": "Target OU",
      "cloud-identity": "Google Cloud deployer",
      "workspace-identity": "Chrome-authorized service account",
      "required-apis": "Required APIs",
      "apply-permissions": "Apply permissions",
      "resource-conflicts": "Resource conflicts",
      "human-approval": "Approval",
    },
    gateDescriptions: {
      "immutable-image": "PoC uses the current Debian 12 image family; an immutable image is a Production requirement.",
      "billing-enabled": "Cloud Billing API checks that the project has an active billing association.",
      "enterprise-license": "Enterprise License Manager API checks assigned Chrome Enterprise Premium licenses; administrator confirmation remains a fallback.",
      "chrome-root-store": "Chrome Root Store configuration, certificate upload, and OU binding are not reliably exposed by public APIs. Complete this one-time Admin console step after Apply, then verify trust with the platform-specific T07 HTTPS test.",
      "workspace-services": "The target users' Workspace service settings require administrator confirmation.",
      "managed-chrome-profile": "Chrome Management Profiles API checks actual profile and policy-sync reports for the selected OU.",
      "secure-enterprise-browser-client": "Chrome Management Profiles API checks the installed and enabled client extension.",
      "endpoint-verification": "Chrome Management Profiles API checks the actual client; Apply force-installs it when it has not reported yet.",
      "no-external-ips": "Apply creates the PoC VMs without external IP addresses.",
      "private-egress": "Apply creates Cloud NAT for controlled package egress.",
      "backend-connectivity": "The managed sample is created in the deployment VPC. For an existing backend, the operator confirms private routing, DNS, and firewall access; Apply validates the path from Nginx with T02. This PoC does not create cross-cloud VPN or Interconnect resources.",
      "test-ou": "The selected OU was confirmed as a non-production test OU.",
      "cloud-identity": "The Google Cloud deployer identity was validated read-only.",
      "workspace-identity": "The Chrome-authorized service account was validated read-only.",
      "required-apis": "Missing allowlisted APIs are enabled automatically during Apply.",
      "apply-permissions": "The API checks whether the deployer has every permission required by the planned operations.",
      "resource-conflicts": "Existing resources are checked for compatibility with the desired state.",
      "human-approval": "An authorized operator approves the exact configuration hash before Apply.",
    },
    managedProfileEvidence: (total, profileOnly, sync) =>
      `${total} reporting profile(s), including ${profileOnly} profile-managed BYOD profile(s). Latest policy sync: ${sync ?? "not reported"}.`,
    clientExtensionEvidence: (name, version, installed) =>
      installed
        ? `${name} ${version ?? ""} is installed and enabled according to the Profiles API.`
        : `${name} has not reported as installed and enabled yet.`,
    missingPermissions: (count: number) =>
      `${count} required permissions are missing from the deployer.`,
    approvePlan: "Approve this exact plan",
    approvePlanDescription:
      "Approval is bound to the configuration hash and becomes invalid when settings change.",
    generatePlan: "Run preflight and generate plan",
    runPreflight: "Run trusted preflight",
    preparingPlan: "Discovering resources and generating an exact plan…",
    planReady: "Server-attested plan is ready",
    planBlocked: "The plan has blocking gates",
    changesCount: (count: number) =>
      count === 1
        ? "1 mutating operation requires approval"
        : `${count} mutating operations require approval`,
    preflightProgressTitle: "Preflight Discovery Progress",
    preflightStage1: "1/5: Verifying Service Usage & IAM permissions...",
    preflightStage2: "2/5: Validating Cloud Billing & Project association...",
    preflightStage3: "3/5: Discovering BeyondCorp Gateway & VPC network...",
    preflightStage4: "4/5: Resolving Chrome Management & Test OU policies...",
    preflightStage5: "5/5: Compiling change plan & evaluating safety gates...",
    preflightComplete: "All preflight checks and safety gates verified",
    plannedChangesTitle: "Exact changes requiring approval",
    plannedChangesIntro:
      "Only create and update operations are shown here. Reused and unchanged resources are not mutated.",
    changeAction: (action) =>
      ({ create: "Create / override", update: "Update" })[action] ?? action,
    changeRisk: (risk) =>
      ({ low: "Low risk", medium: "Medium risk", high: "High risk", blocking: "Blocking" })[
        risk
      ] ?? risk,
    changeSummary: (resourceType, fallback) =>
      resourceType === "service_discovery_proxy"
        ? "Override the inherited legacy PAC in the test OU with Allow user to configure, enabling Service Discovery routing without a PAC file."
        : fallback,
    diagnosticsTitle: "Detected conditions",
    apiEvidence: "API evidence",
    diagnosticMessage: (code, fallback) =>
      code === "legacy-pac-policy-detected"
        ? "A legacy PAC policy inherited from a parent OU is still active for this test OU."
        : code === "chrome-extension-group-policy-conflict"
          ? "A Chrome group policy overrides the Secure Enterprise Browser configuration from the target OU."
        : fallback,
    diagnosticRemediation: (code, fallback) =>
      code === "legacy-pac-policy-detected"
        ? "A hostname omitted from the PAC falls through to DIRECT, where private DNS commonly returns ERR_NAME_NOT_RESOLVED. Apply will override only the selected test OU; the parent OU and existing PAC file are not changed."
        : code === "chrome-extension-group-policy-conflict"
          ? "Review the named group in Apps & extensions. Remove its empty or incompatible managed configuration, or set it to the same Secure Gateway configuration as the test OU. This is blocked because changing a group affects every member."
        : fallback ?? "",
    approveWorking: "Binding approval…",
    approvalReady: "Exact plan approved",
    continueToApply: "Continue to Apply",
    applyTitle: "Apply with checkpoints and evidence",
    applyIntro:
      "Changes execute in dependency order. On failure, the run stops and offers rollback only for resources owned by this deployment.",
    preflight: "Preflight",
    desiredStatePlan: "Desired-state plan",
    applyChanges: "Apply approved changes",
    applyLocked: "Complete preflight and approval to unlock Apply",
    applying: "Applying approved changes…",
    runSucceeded: "Deployment succeeded",
    runRolledBack: "Deployment failed and owned changes were rolled back",
    runInterrupted:
      "The local service restarted during Apply. Reconcile the recorded operations before retrying.",
    runFailed: "Deployment requires operator attention",
    operationCount: (count: number) => `${count} operations recorded`,
    evidenceNotice:
      "Every action records an audit event, redacted request metadata, result, and ownership for safe rollback.",
    caHandoffTitle: "Complete managed Chrome trust",
    caHandoffDescription:
      "Chrome Root Store configuration, certificate upload, and OU binding cannot be reliably inspected or performed through public APIs. Complete this one-time Admin console handoff before end-to-end testing.",
    caHandoffSteps: [
      "Download the public PoC root certificate below; it never contains the private key.",
      "In Google Admin console, open All browsers and devices, then Chrome > Connectors > New provider configuration > Chrome Root Store. Add the PEM as a Root certificate and add the configuration.",
      "Select the dedicated test OU. Under Certificate connectors > Chrome Root Store, select the new configuration and Save. Restart Chrome and verify it under chrome://certificate-manager > Local certificates.",
    ],
    downloadRootCa: "Download public root CA",
    downloadingRootCa: "Preparing download…",
    openAdminConsoleGuide: "Open Google's CA setup guide",
    caDownloadFailed:
      "The root CA could not be downloaded. Confirm that Apply succeeded and retry.",
    previous: "Back",
    next: "Continue",
  },
  operations: {
    deploymentsTitle: "Deployment runs",
    deploymentsIntro:
      "Review server-recorded Apply attempts and their terminal state.",
    evidenceTitle: "Audit evidence",
    evidenceIntro:
      "Verify the local hash chain and export a portable JSON evidence bundle.",
    loading: "Loading recorded state…",
    loadFailed: "Recorded state could not be loaded from the local API.",
    noRuns: "No deployment runs have been recorded.",
    noEvents: "No audit events have been recorded.",
    runId: "Run",
    status: "Status",
    started: "Started",
    operationsCount: "Operations",
    manage: "Manage",
    close: "Close",
    overviewTab: "Overview",
    logsTab: "Logs",
    resourcesTab: "Resources",
    deleteTab: "Delete",
    deploymentName: "Deployment",
    project: "Project",
    gateway: "Secure Gateway",
    application: "Application route",
    architecture: "Architecture",
    ownershipRun: "Resource ownership run",
    architectureLabel: (kind) =>
      ({
        managed_sample: "Nginx HTTP offload · managed sample",
        existing_http: "Nginx HTTP offload · existing backend",
        direct_https: "Direct private HTTPS",
        internal_https_lb: "Internal Application Load Balancer HTTPS offload",
      })[kind] ?? kind,
    accessLevelControlTitle: "Access Control & Access Level Policies",
    accessLevelControlIntro:
      "Update the Access Context Manager condition bound to the BeyondCorp Application IAM policy.",
    selectAccessLevelLabel: "Target Access Level Policy",
    principalsLabel: "Allowed Principals (Users, Groups, Domains)",
    principalsHelper: "Comma-separated list (e.g. user:admin@test-domain.dev, domain:test-domain.dev)",
    noAccessLevelRequired: "(No Access Level constraint / All authenticated group users)",
    boundGroup: "Target IAM Group",
    updateAccessLevelButton: "Update Access Level Policy",
    updatingAccessLevel: "Updating IAM Policy...",
    accessLevelSaved: "Access Level updated and audited in hash chain",
    ownedResources: "Owned deployment resources",
    retainedResources: "Shared or reused resources retained",
    resourceAction: (action) =>
      ({
        delete: "Delete",
        delete_if_empty: "Delete only if no applications remain",
        retain: "Retain",
      })[action] ?? action,
    logsTitle: "Secure Gateway logs",
    logsIntro:
      "Query access decisions, gateway connections, administrative activity, and collected Nginx entries from Cloud Logging.",
    logCategory: (category) =>
      ({
        access: "Access decisions",
        connection: "Connections",
        admin: "Admin activity",
        nginx: "Nginx requests",
      })[category] ?? category,
    hours24: "Last 24 hours",
    hours168: "Last 7 days",
    refreshLogs: "Refresh logs",
    refreshingLogs: "Querying Cloud Logging…",
    enableLogging: "Enable Gateway logging",
    enablingLogging: "Enabling logging…",
    loggingEnabled: "Gateway connection logging is enabled",
    loggingNotEnabled: "Gateway connection logging is not enabled",
    noLogs: "No matching log entries were returned for this time range.",
    logQueryFailed:
      "Cloud Logging could not be queried. Re-run Create deployer and least-privilege role in the ID step to add logging.logEntries.list and Secure Gateway update permission, then retry.",
    dataAccessNotice:
      "Access decisions require Data Access audit logs for the BeyondCorp Enterprise API.",
    nginxNotice:
      "Nginx entries require the Google Cloud Ops Agent to collect sgstudio-access.log.",
    principal: "Principal",
    method: "Method",
    requestId: "Request ID",
    payload: "Sanitized payload",
    teardownTitle: "Teardown this deployment",
    teardownIntro:
      "Delete only resources recorded as owned by this successful Apply, in reverse dependency order.",
    teardownSharedNotice:
      "Existing VPCs, Access Levels, project APIs, Chrome policies, and reused/shared resources are retained. A Gateway created by this run is deleted only when no applications remain.",
    teardownUnavailable: "This run has no safely owned resources available for teardown.",
    teardownConfirmation: "Exact confirmation",
    teardownConfirmationHint: "Type the exact phrase shown above",
    startTeardown: "Delete owned resources",
    teardownRunning: "Deleting owned resources…",
    teardownSucceeded: "Teardown completed",
    teardownFailed: "Teardown stopped and requires review",
    teardownActionFailed: "Teardown could not be started or refreshed.",
    teardownProgress: (completed, total) => `${completed} of ${total} operations complete`,
    exportEvidence: "Export evidence",
    integrityValid: "Audit chain verified",
    integrityInvalid: "Audit chain verification failed",
    eventCount: (count: number) => `${count} chained events`,
    chainHead: "Chain head SHA-256",
    recentEvents: "Recent audit events",
    notAvailable: "Not available",
    acceptanceTitle: "Acceptance certification",
    acceptanceIntro:
      "Run machine checks for T01–T05, then record endpoint and log evidence from the managed Chrome test.",
    noSuccessfulRun: "A successful deployment run is required before acceptance testing.",
    runSystemChecks: "Verify T01–T05",
    runningSystemChecks: "Verifying Google Cloud resources…",
    acceptanceComplete: "PoC acceptance complete",
    acceptancePending: "Acceptance evidence incomplete",
    requiredProgress: (satisfied, required) =>
      `${satisfied} of ${required} required cases satisfied`,
    acceptanceTest: (testId) =>
      ({
        T01: "HTTP backend response",
        T02: "Offload-to-backend response",
        T03: "TLS termination",
        T04: "Private DNS",
        T05: "Secure Gateway matcher",
        T06: "Direct HTTPS control",
        T07: "Managed Chrome end to end",
        T08: "Log correlation",
        T09: "Unauthorized / unmanaged denial",
      })[testId] ?? testId,
    acceptanceScope: (caseKey) =>
      ({
        default: "Deployment-wide",
        macos: "macOS",
        windows: "Windows",
        linux: "Linux",
        chromeos: "ChromeOS",
        unauthorized_principal: "Unauthorized principal",
        unmanaged_browser: "Unmanaged browser",
      })[caseKey] ?? caseKey,
    acceptanceStatus: (status) =>
      ({
        passed: "Passed",
        failed: "Failed",
        user_confirmed: "Operator confirmed",
        skipped: "Skipped",
        missing: "Missing",
      })[status] ?? status,
    evidenceSource: (source) =>
      source === "system" ? "System verified" : "Operator evidence",
    missingEvidence: "No evidence recorded",
    viewEvidence: "View sanitized evidence",
    operatorEvidenceTitle: "Record endpoint evidence",
    operatorEvidenceIntro:
      "Store only sanitized observations or artifact hashes. Never paste tokens, cookies, private keys, or credentials.",
    testCase: "Test case",
    testInstruction: (testId, caseKey) =>
      testId === "T06"
        ? "Open an existing HTTPS Secure Gateway control application in the same managed work profile (the source guide uses https://demo-server1.internal/). Record Passed only if it opens without a certificate warning. For a greenfield PoC with no existing control application, record Skipped with that reason; Production still requires a pass."
        : testId === "T07"
          ? `Open the newly deployed private HTTPS application in the authorized managed Chrome profile on ${caseKey}. Record the visible result and timestamp.`
          : testId === "T08"
            ? "Correlate gateway, offload, and backend events using a sanitized request identifier and timestamp."
            : testId === "T09"
              ? "Confirm the selected unauthorized case is denied and that the backend receives no successful request."
              : "Record the observed result for this acceptance case.",
    evidenceOutcome: "Observed outcome",
    outcomePassed: "Passed",
    outcomeFailed: "Failed",
    outcomeSkipped: "Skipped",
    evidenceSummary: "Result summary",
    evidenceDetail: "Sanitized evidence or artifact SHA-256",
    recordEvidence: "Record confirmation",
    recordingEvidence: "Recording…",
    evidenceRecorded: "Acceptance evidence recorded.",
    acceptanceActionFailed: "Acceptance action failed. Check the local API and credentials.",
    statusSucceeded: "Success",
    statusDeleted: "Deleted",
    statusRunning: "Running",
    statusPending: "Pending",
    statusFailed: "Failed",
    t07DiagnosticsTitle: "Managed Chrome client diagnostics",
    t07DiagnosticsIntro:
      "Match the browser result before recording T07. These symptoms identify whether routing, authorization, or certificate trust is still incomplete.",
    t07Diagnostics: [
      {
        symptom: "ERR_NAME_NOT_RESOLVED",
        meaning:
          "The private hostname was not captured. The managed extension may be inactive, or Service Discovery may be unable to load the route because an inherited legacy PAC still controls this profile.",
        actions: [
          "Run preflight in this app. If it detects a legacy PAC, review the exact target-OU-only override before approval.",
          "Confirm the same Chrome work profile reports Secure Enterprise Browser as administrator-installed and recently synchronized.",
          "If no PAC is active, confirm the gateway route, Service Discovery IAM binding, and application access binding.",
        ],
      },
      {
        symptom: "Access Denied (403)",
        meaning:
          "Service Discovery reached Secure Gateway, but the principal or Access Context Manager condition was not satisfied.",
        actions: [
          "Open Endpoint Verification in the same work profile, add the corporate account if prompted, and run Sync now.",
          "Confirm the user or group has both gateway Service Discovery and application access bindings.",
          "Check that the selected access level accepts PROFILE_MANAGED Chrome for a BYOD test.",
        ],
      },
      {
        symptom: "Certificate authority error",
        meaning:
          "Secure Gateway routing and TLS offload are active, but the PoC root CA is not trusted by this endpoint.",
        actions: [
          "Download the generated PoC root certificate from Apply.",
          "In Admin console, add the PEM at Chrome > Connectors > Chrome Root Store, then connect the configuration to the dedicated test OU and restart Chrome.",
          "Verify the certificate fingerprint before trusting it and retry the private HTTPS URL.",
        ],
      },
    ],
  },
  guide: {
    eyebrow: "New setup guide",
    title: "What happens in each setup step",
    intro:
      "The wizard turns a small set of PoC choices into a discovered, reviewable, and approved Secure Gateway deployment. It does not mutate Google Cloud or Chrome policy until the final Apply step.",
    pocNoticeTitle: "Built for doing a Secure Gateway PoC ASAP",
    pocNoticeBody:
      "Production is shown for future readiness but is disabled in this release. Use a dedicated non-production OU and test principals; do not route production traffic through this workflow.",
    quickOverviewTitle: "Quick Overview & Core Concepts",
    quickOverviewIntro:
      "A fast summary of the 3 architecture deployment paths and the 7-step wizard workflow.",
    technicalDeepDiveTitle: "Step-by-Step Technical Deep Dive & API Calls",
    technicalDeepDiveIntro:
      "Comprehensive breakdown of the underlying logic, configuration behaviors, and Google Cloud / Workspace REST APIs invoked at every stage.",
    optionsBehaviorLabel: "Option Behaviors & Logic",
    apiCallsLabel: "Google Cloud & Workspace REST API Calls",
    safetyGuardrailLabel: "Safety & Rollback Guardrails",
    architectureTitle: "Three independent deployment architectures",
    architectureIntro:
      "Choose one path per application. Options A and B are the primary PoC paths; the previous Nginx method remains available as Option C under Legacy / advanced settings.",
    costOverviewTitle: "Estimated GCP Infrastructure Costs (Beyond CEP Licenses)",
    costOverviewIntro:
      "BeyondCorp Security Gateway resources are included in your Chrome Enterprise Premium (CEP) subscription with no base gateway fee. The following are estimated monthly Google Cloud infrastructure costs incurred by each architecture option outside the CEP user license.",
    architectures: [
      {
        eyebrow: "Option A · Direct HTTPS",
        title: "Secure Gateway + existing private HTTPS app",
        summary:
          "Use when the application already serves HTTPS. Secure Gateway routes directly through the selected VPC; no Nginx, VM, NAT, or offload certificate is created.",
        estimatedCost: "≈ $0.20 – $1.00 / month",
        costFixed: "Fixed: Cloud DNS private zone ($0.20/mo). No Load Balancer, VM, NAT, or Router is created ($0.00).",
        costVariable: "Variable: Cloud DNS query volume ($0.40/million queries) + standard VPC network egress traffic.",
        nodes: [
          { label: "Managed Chrome", detail: "User identity + device/profile context", costBadge: "Free" },
          { label: "Secure Gateway", detail: "Hostname:port matcher + access policy ($0.00 base)", costBadge: "Included in CEP trial" },
          { label: "Upstream VPC", detail: "Delegating service account has upstreamAccess", costBadge: "$0 base / traffic only" },
          { label: "HTTPS app", detail: "Existing certificate and TLS termination", costBadge: "Existing Infra" },
        ],
        supports: [
          { label: "DNS resolution", detail: "Cloud DNS private zone or forwarding zone" },
          { label: "Network policy", detail: "Allow TCP from 136.124.16.0/20 and return route" },
          { label: "Regional routing", detail: "Optional egress region, or Global Access for regional LB" },
        ],
      },
      {
        eyebrow: "Option B · ILB HTTPS offload",
        title: "Secure Gateway + internal HTTPS load balancer + HTTP app",
        summary:
          "Use a regional internal Application Load Balancer as the HTTPS offload tier. The ILB presents the server certificate and forwards decrypted HTTP to the private backend; Nginx is not deployed in the offload path.",
        estimatedCost: "≈ $18.00 – $25.00 / month",
        costFixed: "Fixed: Regional Internal Application LB forwarding rule (≈ $18.25/mo) + Cloud DNS ($0.20/mo). Local CA / DevOps CA ($0.00).",
        costVariable: "Variable: LB data processing / LCU charges (≈ $0.008–$0.01/GB) + backend VPC traffic.",
        nodes: [
          { label: "Managed Chrome", detail: "Trusts the issuing root through Chrome Root Store", costBadge: "Free" },
          { label: "Secure Gateway", detail: "Identity, context, and hostname:443 policy", costBadge: "Included in CEP trial" },
          { label: "Regional internal Application LB", detail: "HTTPS termination with a regional server certificate (≈ $18.25/mo base)", costBadge: "≈ $18/mo + LCU" },
          { label: "HTTP backend", detail: "Private sample VM on port 80 or existing HTTP endpoint", costBadge: "Sample VM: ≈ $7–15/mo or Existing" },
        ],
        supports: [
          { label: "Proxy-only subnet", detail: "REGIONAL_MANAGED_PROXY subnet dedicated to Google-managed Envoy proxies" },
          { label: "TLS ownership", detail: "Enterprise CA, local PoC CA, or validated existing certificate secret" },
          { label: "Chrome trust", detail: "Download the public root PEM and connect it to the test OU through Chrome Root Store" },
          { label: "Managed L7 path", detail: "HTTP health check, backend service, URL map, target HTTPS proxy, and internal forwarding rule" },
          { label: "Safe lifecycle", detail: "Discovery, conflict checks, reverse rollback, ownership-only teardown, and least-privilege IAM" },
        ],
      },
      {
        eyebrow: "Option C · Legacy Nginx / advanced",
        title: "Secure Gateway + Nginx + HTTP app",
        summary:
          "Use only when the private application speaks HTTP or the previous Nginx deployment is required. PoC uses one private Nginx VM; the implemented scale-ready path uses an internal passthrough Network Load Balancer and two-zone Nginx MIG (Production selection is disabled).",
        estimatedCost: "≈ $10.00 – $45.00 / month",
        costFixed: "Fixed: Compute Engine VM (e2-micro ≈ $7–$10/mo, e2-small ≈ $15/mo) + 10GB disk ($0.40/mo) + Cloud DNS ($0.20/mo). (Cloud NAT if enabled: ≈ $32/mo).",
        costVariable: "Variable: VM runtime hours + NAT egress data processing ($0.045/GB).",
        nodes: [
          { label: "Managed Chrome", detail: "User identity + device/profile context", costBadge: "Free" },
          { label: "Secure Gateway", detail: "Service Discovery + access policy", costBadge: "Included in CEP trial" },
          { label: "Nginx offload tier", detail: "PoC: 1 private VM · Scale-ready: passthrough ILB + 2-zone MIG", costBadge: "PoC VM: ≈ $7–15/mo" },
          { label: "HTTP app", detail: "GCP, AWS, Azure, or on premises", costBadge: "Existing Infra" },
        ],
        supports: [
          { label: "CPU autoscaling", detail: "Scale-ready default 2–20 replicas at 60%; min, max, and target are configurable" },
          { label: "Healthy capacity gate", detail: "Apply waits until the configured minimum replica count is healthy" },
          { label: "Two-zone resilience", detail: "Regional MIG distributes Nginx replicas across two zones" },
          { label: "Private DNS", detail: "App hostname resolves to the Nginx internal IP" },
          { label: "TLS material", detail: "CA Service/local CA or existing secret for Nginx" },
          { label: "Private path", detail: "VPN/Interconnect and backend firewall when off-GCP" },
          { label: "Discovery + conflicts", detail: "MIG and autoscaler state is discovered before mutations" },
          { label: "Rollback", detail: "Owned MIG/autoscaler changes participate in deployment rollback" },
          { label: "Least-privilege IAM", detail: "Preflight includes the required instance-group and autoscaler permissions" },
        ],
      },
    ],
    implementationTitle: "What is implemented",
    implementationIntro:
      "This is the implementation inventory for the current codebase. “Scale-ready” items exist in the backend but are not selectable while Production remains disabled; they are not presented as an active PoC resource.",
    implementationGroups: [
      {
        eyebrow: "Data plane",
        title: "HTTP offload and direct HTTPS",
        items: [
          "HTTP offload supports a managed sample backend or an existing private HTTP app in GCP, AWS, Azure, or on premises.",
          "ILB HTTPS offload creates a REGIONAL_MANAGED_PROXY subnet, HTTP backend group and health check, INTERNAL_MANAGED backend service, regional URL map, regional server certificate, target HTTPS proxy, internal forwarding rule, and private DNS record without an Nginx offload VM.",
          "Direct HTTPS creates an exact hostname:port Secure Gateway application route through an existing VPC and omits Nginx, offload TLS, NAT, and managed A records.",
          "Dedicated-VPC and existing-VPC strategies, private-only VM addressing, Cloud NAT for created HTTP-offload VMs, private DNS, and the 136.124.16.0/20 gateway firewall source are modeled.",
          "Off-GCP connectivity is consumed, not created: VPN/Interconnect, private DNS forwarding, backend firewall, and return routes remain explicit prerequisites.",
        ],
      },
      {
        eyebrow: "Scale-ready HTTP tier",
        title: "Regional Nginx availability and autoscaling",
        items: [
          "A two-zone regional Nginx managed instance group, internal passthrough Network Load Balancer, regional TLS health check, and health-check firewall are implemented for the scale-ready path. TLS remains on Nginx.",
          "CPU autoscaling defaults to 2–20 replicas at 60% CPU; minimum, maximum, and CPU target are configurable in English and Japanese.",
          "Deployment waits for the configured minimum number of healthy replicas before continuing.",
          "MIG/autoscaler discovery, compatibility and conflict detection, ownership-bounded reverse rollback, and required IAM permission checks are implemented.",
        ],
      },
      {
        eyebrow: "Google control plane",
        title: "Cloud and Chrome API automation",
        items: [
          "Service Usage, IAM, Compute Engine, Cloud DNS, Secret Manager, CA Service, BeyondCorp, Access Context Manager, Chrome Policy, Chrome Management, Licensing, and Billing are discovered or orchestrated as required by the selected architecture.",
          "The helper bootstraps a keyless deployer service account, least-privilege custom role and bindings; Apply enables missing approved APIs.",
          "Secure Gateway, Service Discovery user IAM, delegating-account upstreamAccess, application matcher, application IAM, and optional Access Level condition are planned and applied.",
          "The test OU receives Secure Enterprise Browser and Endpoint Verification force-install policies, gateway route configuration, and the inherited legacy PAC override; OU, group, and Access Level options are fetched from APIs.",
        ],
      },
      {
        eyebrow: "TLS and identity",
        title: "Certificates and managed Chrome access",
        items: [
          "HTTP offload supports Enterprise CA, a validated existing public certificate secret, and a generated local PoC CA with its public root exported as PEM.",
          "Private keys remain in Secret Manager with a dedicated accessor identity; active-version aliasing, renewal checks, offload refresh, and failure compensation are implemented.",
          "Chrome Root Store upload and OU connection are documented as a manual Admin console handoff because the public API cannot reliably read or mutate that configuration.",
          "Profile-managed BYOD Chrome and browser-managed Chrome can be represented by the selected Access Context Manager level; current profile, client, and Endpoint Verification reporting is surfaced separately.",
        ],
      },
      {
        eyebrow: "Safe Apply",
        title: "Discovery, approval, progress, and rollback",
        items: [
          "Trusted discovery builds a desired-state diff, labels create/update/no-op/conflict actions, and blocks incompatible existing resources before mutation.",
          "Billing, licenses, Workspace prerequisites, test OU, APIs, deployer identities, permissions, private connectivity, certificates, and Chrome signals are shown as API-verified, automatic, manual, or blocking gates.",
          "Approvals are bound to the exact configuration hash, expire, are single-use, and are invalidated by edits; browser-supplied audit actors are rejected.",
          "Apply records operation checkpoints and visual progress, permits one active run, detects interruption, and rolls back only owned changes in reverse order while preserving shared resources and exact IAM/Chrome Policy before-images.",
          "The Deploy tab exposes sanitized Secure Gateway and Nginx log queries, gateway logging enablement, an owned/shared resource inventory, and an exact-confirmation teardown that deletes only recorded ownership in reverse dependency order.",
        ],
      },
      {
        eyebrow: "Verification and local security",
        title: "Acceptance evidence and operator protections",
        items: [
          "Durable T01–T09 acceptance records cover VM/runtime probes, exact Google API routes, selected-platform HTTPS access, request correlation, and required negative tests; evidence exports as portable JSON.",
          "A SHA-256 audit chain, deployment history, sanitized logs, generated request IDs, and query/credential redaction preserve traceability without recording secrets.",
          "The app is loopback-only and enforces Host/Origin checks, a per-launch nonce, CSP, no-store responses, and a 0600 local SQLite database.",
          "Keyless ADC service-account impersonation is required; service-account JSON keys and AWS/Azure credentials are not accepted. The entire workflow and configuration UI are available in English and Japanese.",
        ],
      },
    ],
    stepLabel: (step) => `Step ${step}`,
    steps: [
      {
        title: "Mode",
        subtitle: "Deployment boundary and strategy selection",
        summary:
          "Define the operational scope, client platform targets, network strategy, and certificate authority model.",
        actions: [
          "Keep rapid PoC mode enabled to validate against dedicated test infrastructure without mutating production.",
          "Select target Chrome client platforms (macOS, Windows, Linux, ChromeOS) for acceptance testing.",
          "Choose between creating a dedicated VPC network or integrating with an existing corporate VPC.",
          "Select the TLS certificate issuance strategy (Enterprise CA, Public Secret, or Local PoC CA).",
        ],
        optionsBehavior: [
          {
            name: "PoC vs. Production Mode",
            behavior:
              "PoC mode enforces single-zone test deployments with lightweight provisioning. Production is intentionally locked during PoC to prevent accidental production impact.",
          },
          {
            name: "Dedicated VPC vs. Existing VPC",
            behavior:
              "Dedicated VPC automatically provisions a clean 10.0.0.0/16 VPC with zero conflicts. Existing VPC routes directly into your specified VPC subnet.",
          },
          {
            name: "Certificate Strategy",
            behavior:
              "Enterprise CA connects to Google Private CA Service; Public Secret uses pre-existing TLS certs; Local PoC CA generates an in-browser self-signed Root CA for testing.",
          },
        ],
        apiCalls: [],
        safetyNote: "Local PoC CA should only be distributed to non-production test Organizational Units.",
      },
      {
        title: "Identities",
        subtitle: "Keyless cloud and workspace authentication",
        summary:
          "Establish keyless administrator sessions and bootstrap least-privilege service account impersonation.",
        actions: [
          "Connect using browser-managed OAuth2 tokens without exporting service account JSON keys.",
          "Bootstrap the keyless deployer service account (`secure-gateway-deployer`) with least-privilege custom roles.",
          "Validate read-only API access to Google Cloud project and Google Workspace Chrome Policy.",
        ],
        optionsBehavior: [
          {
            name: "Google Cloud Project ID",
            behavior:
              "Identifies the target GCP project where Secure Gateway and network infrastructure are provisioned.",
          },
          {
            name: "Google Workspace Customer ID",
            behavior:
              "Identifies the Workspace tenant (e.g. C012abcde) for Chrome Enterprise policy distribution.",
          },
          {
            name: "Bootstrap Deployer Action",
            behavior:
              "Automatically provisions `secure-gateway-deployer@<project>.iam.gserviceaccount.com`, binds `secureGatewayPocDeployer` custom role, and grants Token Creator to the signed-in administrator.",
          },
        ],
        apiCalls: [
          {
            method: "GET",
            endpoint: "https://iam.googleapis.com/v1/projects/{projectId}/serviceAccounts/{saEmail}",
            purpose: "Checks if the deployer service account already exists.",
          },
          {
            method: "POST",
            endpoint: "https://iam.googleapis.com/v1/projects/{projectId}/serviceAccounts",
            purpose: "Creates the dedicated keyless deployer service account.",
          },
          {
            method: "PATCH",
            endpoint: "https://iam.googleapis.com/v1/projects/{projectId}/roles/{roleId}",
            purpose: "Creates or updates the least-privilege custom role with 76 required permissions.",
          },
          {
            method: "POST",
            endpoint: "https://cloudresourcemanager.googleapis.com/v1/projects/{projectId}:setIamPolicy",
            purpose: "Binds custom deployer role, roles/browser, and roles/serviceusage.serviceUsageConsumer to the SA.",
          },
          {
            method: "POST",
            endpoint: "https://iam.googleapis.com/v1/projects/{projectId}/serviceAccounts/{saEmail}:setIamPolicy",
            purpose: "Grants roles/iam.serviceAccountTokenCreator to the administrator on the service account.",
          },
          {
            method: "POST",
            endpoint: "https://chromepolicy.googleapis.com/v1/customers/{customerId}/policies/orgunits:batchGet",
            purpose: "Validates read access to Chrome Enterprise Policy management.",
          },
        ],
        safetyNote: "No private key files or long-lived credentials are ever written to disk or extension storage.",
      },
      {
        title: "Environment",
        subtitle: "Data plane architecture and routing specification",
        summary:
          "Configure the target VPC, regional placement, private hostname, and backend architecture tier.",
        actions: [
          "Select between Option A (Direct HTTPS), Option B (ILB HTTPS Offload), or Option C (Legacy Nginx).",
          "Specify the application private hostname, port, and upstream VPC network.",
          "For Option B, configure a dedicated proxy-only subnet CIDR for Google-managed Envoy proxies.",
        ],
        optionsBehavior: [
          {
            name: "Option A (Direct HTTPS)",
            behavior:
              "Routes traffic directly to an existing private HTTPS endpoint. Bypasses Nginx and Load Balancer creation.",
          },
          {
            name: "Option B (ILB HTTPS Offload)",
            behavior:
              "Creates a Regional Internal Application Load Balancer with Envoy proxy subnet to terminate TLS and forward to HTTP backend.",
          },
          {
            name: "Option C (Legacy Nginx)",
            behavior:
              "Deploys a dedicated private Compute Engine VM or Managed Instance Group running Nginx reverse proxy.",
          },
        ],
        apiCalls: [
          {
            method: "POST",
            endpoint: "https://beyondcorp.googleapis.com/v1/projects/{projectId}/locations/global/securityGateways",
            purpose: "Provisions the Secure Gateway resource.",
          },
          {
            method: "POST",
            endpoint: "https://beyondcorp.googleapis.com/v1/projects/{projectId}/locations/global/securityGateways/{gw}/applications",
            purpose: "Registers the private application with hostname:port matcher and VPC route.",
          },
          {
            method: "POST",
            endpoint: "https://compute.googleapis.com/v1/projects/{projectId}/global/firewalls",
            purpose: "Creates ingress firewall rule allowing TCP from 136.124.16.0/20 gateway source range.",
          },
          {
            method: "POST",
            endpoint: "https://dns.googleapis.com/dns/v1/projects/{projectId}/managedZones",
            purpose: "Creates Cloud DNS private zone bound to the target VPC network.",
          },
          {
            method: "POST",
            endpoint: "https://compute.googleapis.com/v1/projects/{projectId}/regions/{region}/subnetworks",
            purpose: "Provisions REGIONAL_MANAGED_PROXY subnet for Option B ILB Envoy proxies.",
          },
          {
            method: "POST",
            endpoint: "https://compute.googleapis.com/v1/projects/{projectId}/regions/{region}/forwardingRules",
            purpose: "Creates internal HTTPS forwarding rule for ILB offload tier.",
          },
        ],
        safetyNote: "Regional ILBs must have Global Access enabled if accessed across regions.",
      },
      {
        title: "Certificate",
        subtitle: "TLS ownership and trust propagation",
        summary:
          "Manage certificate issuance, Secret Manager key encapsulation, and Chrome Root Store connector distribution.",
        actions: [
          "Choose certificate origin: Enterprise CA Service, existing secret, or browser-generated local PoC CA.",
          "Store TLS private keys securely in Google Cloud Secret Manager with least-privilege accessor bindings.",
          "Download generated root CA PEM and link it to Chrome Root Store in Google Admin console.",
        ],
        optionsBehavior: [
          {
            name: "Enterprise CA Service",
            behavior:
              "Issues certificates through an existing Google Cloud CA Service pool and authority.",
          },
          {
            name: "Public Secret",
            behavior:
              "References pre-existing validated server certificates stored in Secret Manager.",
          },
          {
            name: "Local PoC CA",
            behavior:
              "Generates an ephemeral ECDSA P-256 self-signed root CA in browser WebCrypto and signs server certificates.",
          },
        ],
        apiCalls: [
          {
            method: "POST",
            endpoint: "https://secretmanager.googleapis.com/v1/projects/{projectId}/secrets",
            purpose: "Creates encrypted secret container for TLS certificates and private keys.",
          },
          {
            method: "POST",
            endpoint: "https://secretmanager.googleapis.com/v1/projects/{projectId}/secrets/{secretId}/versions:add",
            purpose: "Uploads certificate payload version with automatic accessor IAM restriction.",
          },
        ],
        safetyNote: "Root CA private key is never exported; only the public root PEM certificate is distributed.",
      },
      {
        title: "Access",
        subtitle: "Zero-Trust policy and user authorization",
        summary:
          "Bind Context-Aware Access levels and enforce Chrome Enterprise browser policies on the test OU.",
        actions: [
          "Select the target Organizational Unit (OU) from Google Workspace Directory API.",
          "Apply Context-Aware Access Level condition (e.g. Managed Chrome device/profile required).",
          "Grant Secure Gateway application access to specific test users, groups, or domains.",
        ],
        optionsBehavior: [
          {
            name: "Target Organizational Unit (OU)",
            behavior:
              "Scopes Chrome policy push so only managed browsers in the dedicated test OU receive gateway configuration.",
          },
          {
            name: "Managed Chrome Access Level",
            behavior:
              "Restricts application access at the gateway level to devices/profiles satisfying BeyondCorp posture.",
          },
          {
            name: "Principal Types (User, Group, Domain)",
            behavior:
              "Binds `roles/beyondcorp.sgApplicationUser` to authorized test identities in IAM.",
          },
        ],
        apiCalls: [
          {
            method: "GET",
            endpoint: "https://admin.googleapis.com/admin/directory/v1/customer/{customerId}/orgunits",
            purpose: "Retrieves organizational unit hierarchy from Google Workspace.",
          },
          {
            method: "GET",
            endpoint: "https://accesscontextmanager.googleapis.com/v1/accessPolicies/{policyId}/accessLevels",
            purpose: "Lists available Context-Aware Access Levels.",
          },
          {
            method: "POST",
            endpoint: "https://chromepolicy.googleapis.com/v1/customers/{customerId}/policies/orgunits:batchModify",
            purpose: "Force-installs Secure Enterprise Browser & Endpoint Verification extensions and sets routing policy.",
          },
          {
            method: "POST",
            endpoint: "https://beyondcorp.googleapis.com/v1/projects/{projectId}/locations/global/securityGateways/{gw}/applications/{app}:setIamPolicy",
            purpose: "Binds application user roles and access level conditions to test principals.",
          },
        ],
        safetyNote: "Existing PAC policies on parent OUs are overridden only within the target test OU.",
      },
      {
        title: "Review",
        subtitle: "Deterministic preflight and cryptographic approval",
        summary:
          "Perform comprehensive read-only discovery, evaluate 12 safety gates, and bind approval to SHA-256 hash.",
        actions: [
          "Scan existing Google Cloud and Workspace assets to build an exact desired-state diff.",
          "Evaluate safety gates (APIs, permissions, CIDR conflicts, licenses, existing certificates).",
          "Confirm human approval bound cryptographically to the exact configuration payload hash.",
        ],
        optionsBehavior: [
          {
            name: "Preflight Discovery",
            behavior:
              "Runs non-mutating scans across all required APIs to detect resource conflicts before execution.",
          },
          {
            name: "Safety Gates Verification",
            behavior:
              "Enforces prerequisites (Billing, CEP license, Private DNS, Firewalls) with Pass / Planned / Blocked status.",
          },
          {
            name: "SHA-256 Approval Binding",
            behavior:
              "Calculates a deterministic canonical hash of the plan. Any subsequent modification immediately revokes the approval.",
          },
        ],
        apiCalls: [
          {
            method: "GET",
            endpoint: "https://serviceusage.googleapis.com/v1/projects/{projectId}/services",
            purpose: "Audits enabled Google Cloud APIs.",
          },
          {
            method: "POST",
            endpoint: "https://iam.googleapis.com/v1/projects/{projectId}:testIamPermissions",
            purpose: "Validates caller possesses all necessary IAM permissions for planned changes.",
          },
        ],
        safetyNote: "Approval cannot be granted while any blocking safety gate remains unresolved.",
      },
      {
        title: "Apply",
        subtitle: "Ordered orchestration, rollback, and evidence capture",
        summary:
          "Execute approved mutations in topological dependency order with ownership tracking and automated test verification.",
        actions: [
          "Provision resources sequentially: Subnets -> Certs -> ILB/VM -> Gateways -> DNS -> Chrome Policies.",
          "Track resource ownership in IndexedDB audit store; reverse-rollback only owned assets on failure.",
          "Run acceptance suite T01–T09 and export cryptographically audited JSON evidence.",
        ],
        optionsBehavior: [
          {
            name: "Dependency-Ordered Execution",
            behavior:
              "Ensures prerequisite infrastructure (VPC, Subnets, Secrets) exists before higher-level services bind to them.",
          },
          {
            name: "Automated Reverse Rollback",
            behavior:
              "If any step fails, undoes previously created resources in strict reverse order while preserving pre-existing shared assets.",
          },
          {
            name: "T01–T09 Acceptance Verification",
            behavior:
              "Validates end-to-end connectivity, TLS handshake, context posture, and negative denial tests.",
          },
        ],
        apiCalls: [
          {
            method: "POST",
            endpoint: "https://logging.googleapis.com/v2/entries:write",
            purpose: "Records structured audit log entry for deployment operations.",
          },
        ],
        safetyNote: "Interruption or crash recovery safely resumes or cleanly rolls back without orphaned cloud resources.",
      },
    ],
    faqTitle: "Frequently Asked Questions & Troubleshooting (FAQ)",
    faqIntro:
      "Essential guides, troubleshooting procedures, certificate trust mechanisms, and operational best practices derived from real-world Secure Gateway deployments.",
    faqs: [
      {
        id: "faq-503-unavailable",
        category: "Routing & Data Path",
        question: "Why does Chrome show '503 Service Unavailable' or connection failure when accessing private applications?",
        answer:
          "A 503 error indicates that BeyondCorp Security Gateway cannot establish a TCP/TLS connection with the backend in your VPC (10.10.0.2). Verify that the Compute VM is running, Cloud NAT has an external static IP, Firewall rules allow TCP 80/443 ingress, and Cloud DNS A-record is correctly registered.",
        checklist: [
          "Check Compute VM instance state (secgw-https-backend-01) in Deployment Manager -> GCP Resource Diagnostics.",
          "Verify firewall rule allow-secgw-ingress-https allows ingress on TCP ports 80 and 443 from 0.0.0.0/0.",
          "Verify Cloud Router & NAT are configured with a valid static IP on secgw-test-vpc.",
          "Ensure Cloud DNS Managed Zone contains an A record matching secgw-backend.internal. -> 10.10.0.2.",
        ],
      },
      {
        id: "faq-cert-authority-invalid",
        category: "Certificates & Root CA",
        question: "Why does Chrome report 'net::ERR_CERT_AUTHORITY_INVALID' or 'Not Secure' with a certificate warning?",
        answer:
          "This occurs when the TLS server certificate served by the backend VM is not signed by the Root CA installed in the Chrome Root Store, or when Chrome retains a cached 'USER_OVERRIDDEN' bypass flag from a previous warning bypass.",
        checklist: [
          "Download the latest secure-gateway-private-https-poc-root.pem from Apply (Step 7) or Deployment Manager.",
          "Upload the PEM into Google Admin Console under Devices > Chrome > Certificates > Chrome Root Store.",
          "Open chrome://policy and click 'Reload policies' to synchronize.",
          "Open https://secgw-backend.internal/ in a fresh Incognito window (Ctrl+Shift+N) or restart Chrome (chrome://restart) to clear session bypass flags and view the secure green lock (🔒).",
        ],
      },
      {
        id: "faq-oauth-external-mode",
        category: "OAuth & Distribution",
        question: "How should the Google Cloud OAuth Consent Screen be configured when sharing the extension with external testers?",
        answer:
          "For testing outside your Workspace domain (@gmail.com or other domains), switch User Type to 'External'. Under 'Testing', add testers' Google email addresses to 'Test Users' (up to 100 accounts). In 'Production', anyone can log in by clicking 'Advanced -> Go to Secure Gateway Studio (unsafe)'.",
        checklist: [
          "In Google Cloud Console -> APIs & Services -> OAuth consent screen, set User Type to External.",
          "If in Testing mode, add tester emails under 'Test users' section.",
          "If set to Production, no user registration is needed; testers can authenticate through the unverified app screen.",
        ],
      },
      {
        id: "faq-extension-id-mismatch",
        category: "OAuth & Distribution",
        question: "How do we prevent 'OAuth2 request failed: Bad Client ID' errors on testers' computers?",
        answer:
          "Unpacked extensions calculate their Extension ID from local directory paths unless a fixed public key ('key') is specified in manifest.json. Ensure the extension ID matches the Item ID configured in GCP OAuth 2.0 Client Credentials.",
        checklist: [
          "Verify the Item ID in GCP Credentials -> OAuth 2.0 Client IDs matches the extension ID on chrome://extensions.",
          "The packaged dist.zip includes a fixed key to guarantee the exact same extension ID on every tester machine.",
        ],
      },
      {
        id: "faq-access-level-cel",
        category: "Zero Trust & Security",
        question: "How does Access Context Manager (CEL) enforce Managed Chrome device/profile requirements?",
        answer:
          "BeyondCorp Application IAM bindings can evaluate Common Expression Language (CEL) conditions such as device.is_managed_device == true. Any request originating from an unmanaged browser, personal profile, or non-compliant device is blocked at Google's edge.",
        checklist: [
          "Configure access levels in Deployment Manager -> Access Control & Level Settings.",
          "Select pre-configured levels such as browser_is_managed or input custom Access Policy resource names.",
          "All modifications are logged to the tamper-proof cryptographic audit trail.",
        ],
      },
      {
        id: "faq-teardown-clean-state",
        category: "Operations & Teardown",
        question: "How do we cleanly delete all deployed resources and restore the project to a pristine state?",
        answer:
          "Use 'Teardown' in Deployment Manager to delete only owned resources in reverse topological dependency order, or 'Clean State All' to completely purge Gateway, Application, test VM, VPC, NAT, Firewalls, Cloud DNS, and local IndexedDB database records.",
        checklist: [
          "In Deployment Manager -> Delete tab, type the exact confirmation phrase to execute teardown.",
          "Click 'Clean State All' to purge all PoC cloud resources and reset deployment run status to 'Deleted'.",
        ],
      },
    ],
  },
  cepDeployer: {
    title: "Chrome Enterprise Premium PoC Deployer",
    subtitle:
      "Apply a CEP evaluation baseline to one organizational unit, and take it back out again.",
    intro:
      "Writes Chrome policies for threat protection, content inspection, and data boundaries into a pilot OU, creates the least-privilege IAM roles to run it, and rolls the whole thing back to the parent OU when the evaluation is over. Every policy is checked against your tenant's live Chrome Policy schemas before it is written.",
    targetOuCardTitle: "1. Target organizational unit",
    targetOuCardSubtitle:
      "Pick an isolated pilot OU. Policies land here and nowhere else, so production users are unaffected.",
    selectTargetOu: "Target organizational unit",
    ouLoadFailed:
      "Organizational units could not be loaded. Confirm the Google Workspace connection on the setup screen, then reopen this tab.",
    autoCreateSubOus: "Create \"CEP Users\" and \"CEP Browsers\" sub OUs",
    autoCreateSubOusHint:
      "User-scoped policies go to the first, browser-scoped policies to the second. Existing sub OUs with these names are reused. Without this, everything targets the OU selected above.",
    presetsTitle: "2. Presets",
    presetsSubtitle:
      "A starting point for the usual evaluation shapes. Adjust the modules below afterwards.",
    presetFullPoc: "Full evaluation",
    presetFullPocDesc:
      "Every module: threat protection, content inspection, reporting, posture signals, and copy/paste boundaries.",
    presetAiProtection: "Generative AI and data leaks",
    presetAiProtectionDesc:
      "Paste and upload inspection aimed at prompts typed into external AI tools, plus non-corporate account blocking.",
    presetEndpoint: "Endpoint hardening",
    presetEndpointDesc:
      "Enhanced Safe Browsing, real-time URL checks, forced Endpoint Verification, and Context-Aware Access.",
    presetAudit: "Audit and visibility",
    presetAuditDesc: "Reporting and security event telemetry only. Nothing is blocked.",
    modulesTitle: "3. Policy modules",
    modulesSubtitle:
      "Each module is applied as its own batch, so one unsupported policy does not take the others with it.",
    moduleCorePolicies: "Chrome core security policies",
    moduleCorePoliciesDesc:
      "Enhanced Safe Browsing, a warning when a corporate password is reused elsewhere, and Chrome cloud and profile reporting.",
    moduleForceExtensions: "Force-install Endpoint Verification",
    moduleForceExtensionsDesc:
      "Pushes Google's Endpoint Verification extension so device posture signals reach Context-Aware Access.",
    moduleConnectors: "Content inspection connectors",
    moduleConnectorsDesc:
      "Real-time URL checks plus file upload and download inspection, and security event reporting to Google.",
    accessLevelTitle: "Context-Aware Access level",
    accessLevelHint:
      "Sessions that do not meet the selected level are blocked from uploading files. Pick a level your organization already has, or have one created for managed Chrome.",
    accessLevelNone: "None",
    accessLevelNoneDesc: "Do not require an access level.",
    accessLevelAutoProfile: "Create one: managed Chrome profile",
    accessLevelAutoBrowser: "Create one: managed Chrome browser",
    accessLevelAutoAny: "Create one: managed profile or browser",
    accessLevelExistingGroup: "Existing access levels",
    accessLevelLoadFailed:
      "Existing access levels could not be listed. A Google Cloud project attached to an organization with an Access Context Manager policy is required to create one.",
    moduleDlpDetectors: "DLP detector for internal sites",
    moduleDlpDetectorsDesc:
      "Creates a reusable URL-list detector from the internal sites below, which the rules reference to leave your own properties alone.",
    moduleDlpRules: "Starter DLP rules",
    moduleDlpRulesDesc:
      "Blocks uploads containing card numbers, warns on pasting national ID numbers, and watermarks internal pages while blocking screenshots.",
    betaBadge: "Beta",
    dlpBetaNote:
      "Creating DLP rules and detectors uses the Cloud Identity policy API, whose mutation methods are still in beta. If a call is refused the module is reported as skipped with the reason, and the rest of the deployment still applies.",
    dlpRegionTitle: "National identifier to scan for",
    dlpRegionHint:
      "Sets which Cloud DLP detector the national ID rule uses. A detector for the wrong country matches nothing, and a rule that never fires looks the same as one that works.",
    dlpRulesTableTitle: "Rules and what each one does",
    dlpRulesTableHint:
      "Audit only records the event without interrupting anyone, which is usually where an evaluation should start. Tighten to warn or block once you have seen the volume.",
    dlpActionOff: "Do not create",
    dlpActionAudit: "Audit only",
    dlpActionWarn: "Allow with warning",
    dlpActionBlock: "Block",
    dlpRuleNationalId: "National ID numbers pasted into pages",
    dlpRulePaymentCard: "Payment card numbers in uploads",
    dlpRuleAccessLevel: "Uploads from unmanaged Chrome",
    dlpRuleWatermark: "Watermark internal pages",
    dataBoundaryModeTitle: "Data boundary",
    dataBoundaryModeCopyPaste: "Inspect pasted content",
    dataBoundaryModeCopyPasteDesc:
      "Bulk text pasted into a page is inspected, and secondary sign-in is restricted to your primary domain.",
    dataBoundaryModeBlockNonCorp: "Block non-corporate Google accounts",
    dataBoundaryModeBlockNonCorpDesc:
      "Google apps only accept accounts on your primary domain, which closes the personal-Gmail-tab route.",
    dataBoundaryModeNone: "None",
    dataBoundaryModeNoneDesc:
      "Leave clipboard and account behaviour inherited from the parent OU.",
    internalUrlsTitle: "Internal sites (one per line)",
    internalUrlsPlaceholder: "https://intranet.example.com\nhttps://wiki.corp.example.com",
    internalUrlsHint:
      "Exempted from content inspection, so your own intranet is not scanned on every upload and paste.",
    rolesCardTitle: "4. Least-privilege IAM roles",
    rolesCardSubtitle:
      "Two custom roles for running and reviewing the evaluation, so nobody needs project owner.",
    roleAdminLabel: "CEP Policy Administrator",
    roleAdminDesc: "Read and modify Chrome policies and Access Context Manager levels.",
    roleAuditorLabel: "CEP Security Auditor",
    roleAuditorDesc:
      "Read-only: policy state and security log entries, with no ability to change anything.",
    assignUserEmailLabel: "Grant the roles to (optional)",
    assignUserEmailPlaceholder: "security-auditor@example.com",
    provisionRolesButton: "Create IAM roles",
    provisioningRoles: "Creating IAM roles...",
    rolesProjectRequired:
      "A Google Cloud project is required to create IAM roles. Set one on the setup screen first.",
    testingScenariosTitle: "5. Testing the result",
    testingScenariosSubtitle:
      "Sample values that trip the detectors, so you can demonstrate an interception without using real data.",
    copyDummyData: "Copy",
    copiedToClipboard: "Copied",
    dummyPiiLabel: "Sample national ID number",
    dummyPiiValue: "1234-5678-9012",
    dummyPiiHint: "Formatted as a Japanese My Number / US SSN. Not a real identifier.",
    dummyCreditCardLabel: "Sample card number",
    dummyCreditCardValue: "4532015112830366",
    dummyCreditCardHint: "A Visa test number that passes the Luhn check. Not a real card.",
    dummySourceCodeLabel: "Sample API key in source",
    dummySourceCodeValue:
      "const GCP_SECRET_KEY = 'AIzaSyA_DEMO_CONFIDENTIAL_KEY_FOR_TESTING';",
    dummySourceCodeHint: "Shaped like a Google API key. Not a working credential.",
    scenarioGenAiTitle: "Paste inspection",
    scenarioGenAiStep:
      "Open an external AI tool and paste the sample API key. With paste inspection on, Chrome holds the paste until the verdict returns.",
    scenarioDataBoundaryTitle: "Data boundary",
    scenarioDataBoundaryStep:
      "Sign in to a personal Google account in the managed profile. With non-corporate accounts blocked, the sign-in is refused.",
    scenarioWatermarkTitle: "Upload inspection",
    scenarioWatermarkStep:
      "Upload a file containing the sample card number to any site outside your internal list. The upload is held for inspection and the event reaches the security investigation tool.",
    manualChecklistTitle: "Steps this tool cannot perform",
    manualChecklistSubtitle:
      "Google exposes no API for these, so complete them in the Admin Console before running the tests above.",
    manualChecklistItems: [
      {
        title: "Turn on sensitive content storage",
        detail: "Security > Access and data control > Data protection.",
        href: "https://admin.google.com/ac/dp",
      },
      {
        title: "Turn on optical character recognition",
        detail: "Needed for detectors to read text inside images.",
        href: "https://admin.google.com/ac/dp",
      },
      {
        title: "Enable automatic CEP licensing",
        detail: "Billing > License settings, for the pilot OU.",
        href: "https://admin.google.com/ac/billing/licensesettings",
      },
    ],
    btnDeploy: "Apply to the target OU",
    btnDeploying: "Applying...",
    btnRollback: "Roll back to the parent OU",
    btnRollingBack: "Rolling back...",
    btnDownloadScript: "Export as a Python script",
    confirmRollback:
      "Return every CEP policy on this OU to whatever the parent OU sets, and delete the Context-Aware Access level this tool created. Continue?",
    downloadFailed: "The script could not be generated",
    noModulesSelected: "Select at least one policy module.",
    appliedTitle: "Applied",
    skippedTitle: "Skipped",
    statusLogTitle: "Execution trace",
    noActionYet: "Nothing has run yet. Pick a target OU and the modules you want, then apply.",

    licenseCardTitle: "License Management & Auto-Assignment Control",
    licenseCardSubtitle:
      "Prevent unexpected domain-wide license consumption and assign CEP licenses directly to the target OU.",
    licenseAutoAssignWarning:
      "If auto-assign is enabled on the Root OU, CEP licenses will be automatically consumed by random users across your entire organization.",
    licenseAutoAssignWarningLink: "Open Google Admin Console License Settings",
    licenseAutoAssignSteps: [
      "1. Open License Settings in Google Admin Console and select the Root OU.",
      "2. Turn Auto-assign OFF for Chrome Enterprise Premium.",
      "3. Either turn Auto-assign ON only for this pilot OU, or use the button below to assign licenses directly.",
    ],
    btnAssignLicensesToOu: "Assign CEP licenses to all users in this OU",
    btnAssigningLicenses: "Assigning licenses to OU users...",
    licenseAssignUsersFound: "Processed users in OU",
    noUsersFoundInOu: "No users found in this organizational unit.",

    dlpMatrixTitle: "DLP Control Matrix",
    dlpMatrixSubtitle:
      "Configure actions (Block, Warn, Audit, Off) across all operations (Upload, Download, Paste, Print, Screen Capture) and device scopes (All vs BYOD / Unmanaged).",
    dlpColThreat: "Data & Threat Category",
    dlpColUpload: "Upload",
    dlpColDownload: "Download",
    dlpColPaste: "Paste",
    dlpColPrint: "Print",
    dlpColWatermark: "Watermark",
    dlpColDeviceScope: "Device Scope",

    dlpRowUniversalUpload: "All file uploads",
    dlpRowUniversalUploadDesc: "Inspects and audits/blocks all file uploads from Chrome.",
    dlpRowUniversalDownload: "All file downloads",
    dlpRowUniversalDownloadDesc: "Inspects and audits/blocks all file downloads in Chrome.",
    dlpRowPaymentCard: "Credit card / Payment data",
    dlpRowPaymentCardDesc: "Detects credit card numbers in uploads, pastes, and prints.",
    dlpRowNationalId: "National ID / PII data",
    dlpRowNationalIdDesc: "Detects regional PII / National ID numbers (e.g. My Number / SSN).",
    dlpRowAccessLevel: "Unmanaged / BYOD devices",
    dlpRowAccessLevelDesc: "Applies Context-Aware Access controls on non-compliant / BYOD sessions.",
    dlpRowWatermark: "Internal sites / Watermark",
    dlpRowWatermarkDesc: "Overlays dynamic watermark and blocks screenshots on internal sites.",
    dlpRowGenAiBlock: "Unapproved GenAI (allow Gemini)",
    dlpRowGenAiBlockDesc: "Blocks ChatGPT, Claude, DeepSeek, etc. while allowing corporate Gemini.",

    dlpScopeAll: "All Devices",
    dlpScopeByodOnly: "BYOD Only",
    dlpActionBadgeBlock: "Block",
    dlpActionBadgeWarn: "Warn",
    dlpActionBadgeAudit: "Audit",
    dlpActionBadgeOff: "Off",

    dlpPresetRecommended: "Recommended PoC",
    dlpPresetRecommendedDesc: "Audit sensitive data, warn on BYOD, block unapproved GenAI, and watermark internal sites.",
    dlpPresetStrictZeroTrust: "Strict Zero Trust",
    dlpPresetStrictZeroTrustDesc: "Block sensitive uploads, pastes, and unmanaged devices completely.",
    dlpPresetGenAiSecure: "Secure GenAI Pilot",
    dlpPresetGenAiSecureDesc: "Block unapproved consumer AI, permit Gemini with paste inspection.",
    dlpPresetAuditOnly: "Audit Only",
    dlpPresetAuditOnlyDesc: "Monitor all activities across all surfaces without user disruption.",
  },
};

const ja: Messages = {
  mainTitle: "Chrome Enterprise Premium PoC デプロイヤー",
  productName: "Secure Gateway Studio",
  localOnly: "ローカルのみ",
  cloudIdentity: "Google Cloud",
  cloudProject: "未接続",
  workspaceIdentity: "Google Workspace",
  adminEmail: "未接続",
  help: "ヘルプ",
  nav: {
    deployments: "デプロイ",
    newSetup: "新規セットアップ",
    policies: "ポリシー",
    evidence: "エビデンス",
    settings: "設定",
    guide: "ガイド",
    cepDeployer: "Easy PoC",
    easyPoc: "Easy PoC",
    sgwDeployer: "Secure Gateway Deployer",
  },
  title: "セキュア ゲートウェイの新規セットアップ",
  steps: ["モード", "ID", "環境", "証明書", "アクセス", "確認", "適用"],
  modeTitle: "1. Secure Gateway の迅速な PoC を開始",
  poc: "迅速なPoC",
  pocDescription:
    "明示的な安全ゲートと削除可能なリソースを使い、テストOUへ迅速に構築します。管理コンソール経由で管理対象ChromeへローカルCAを配布できます。",
  production: "本番",
  productionDescription:
    "エンタープライズPKI、リージョン高可用性、専用サービスID、最小権限、監査可能な変更管理などの本番向け機能は、今後のリリースで提供予定です。",
  productionUnavailable: "今後対応",
  platformsTitle: "2. 管理対象 Chrome プラットフォーム",
  managedChromeOnly: "管理対象 Google Chrome のみ",
  platformNote:
    "このPoC期間中に実機テストできるプラットフォームだけを選択してください。選択した各プラットフォームが必須のT07 E2E受入ケースになります。他のブラウザは対象外です。",
  infrastructureTitle: "3. ネットワーク構成",
  dedicatedNetwork: "専用ネットワーク",
  recommended: "推奨",
  dedicatedDescription: "Secure Gateway サービス専用の新しいVPCを作成します。",
  existingVpc: "既存VPC",
  existingDescription: "管理している既存VPCへデプロイします。",
  certificateTitle: "4. 証明書方式",
  enterpriseCa: "エンタープライズPKI / CA Service",
  enterpriseCaDescription: "組織CAまたはCloud CA Serviceで内部TLS証明書を発行します。",
  publicCertificate: "公開信頼済み証明書",
  publicCertificateDescription: "管理するDNS名に公開信頼済み証明書を使用します。",
  localPocCa: "ローカルPoC CA",
  disabledProduction: "本番では無効",
  localPocAdminConsole: "管理コンソールへのアップロードが必要",
  localPocCaDescription:
    "プライベートルート証明書とサーバー証明書を生成します。適用後に公開ルートをダウンロードし、Google管理コンソールでテストOUと対象プラットフォームへアップロードします。",
  posture: "デプロイ方針",
  mode: "モード",
  managedPlatforms: "管理対象 Chrome",
  platformCount: (count: number) => `${count} プラットフォーム`,
  infrastructure: "ネットワーク",
  certificateStrategy: "証明書方式",
  targetOu: "対象OU",
  testOuAvailable: "テスト用OUの確認",
  deploymentGates: "デプロイゲート",
  noExternalIps: "外部IPなし",
  cloudNat: "Cloud NAT",
  upstreamVpc: "既存Upstream VPC",
  privateDnsRoute: "Private DNS・ファイアウォール・戻り経路",
  applicationOwnedTls: "HTTPSアプリ所有のTLS",
  apiPreflight: "API事前確認",
  approval: "承認",
  required: "必須",
  willValidate: "適用時に検証",
  gateNote: "適用するには、すべてのゲートを通過する必要があります。",
  back: "戻る",
  continue: "ID設定へ進む",
  noChanges: "変更はまだ適用されていません",
  draftSaved: "下書きをローカル保存",
  lastSaved: "最終保存",
  justNow: "数秒前",
  languages: { english: "English", japanese: "日本語" },
  workflow: {
    identitiesTitle: "管理者IDを接続",
    identitiesIntro:
      "専用サービスアカウントの権限を借用（Impersonate）するキーレス Application Default Credentials を使用します。JSONキーファイルは受け付けず、ローカルに保存もしません。",
    cloudAccount: "Google Cloud デプロイヤー",
    cloudAccountDescription: "GCP変更の検出、計画、承認後の適用に使用します。",
    workspaceAccount: "Chrome 権限付きサービスアカウント",
    workspaceAccountDescription:
      "同じキーレスIDに対象OU用のChrome管理者ロールを直接割り当てます。",
    projectId: "Google Cloud プロジェクトID",
    operatorIdentity: "検証済み認証情報",
    adminIdentity: "検証済み管理者認証情報",
    connect: "接続を検証",
    connected: "接続済み",
    notConnected: "未接続",
    checking: "検証中…",
    connectionFailed: "検証に失敗しました",
    adcUnavailable:
      "キーレス Application Default Credentials がありません。「gcloud auth application-default login --impersonate-service-account=SERVICE_ACCOUNT_EMAIL」を実行し、再試行してください。",
    cloudValidationFailed:
      "Google Cloud の検証に失敗しました。プロジェクトIDと読み取り権限を確認してください。",
    workspaceValidationFailed:
      "Workspace の検証に失敗しました。顧客IDと Chrome Policy 管理者権限を確認してください。",
    workspaceRequiredRolesHint:
      "必要なWorkspace特権: Chrome 管理 (ポリシー・設定)、組織部門 (サブOU作成用の作成・読取)、グループ (読取)、ドメイン (読取)、ルール管理 (Chrome DLP)。これらの特権を持つカスタム管理者ロール、またはChrome管理者ロールがあれば特権管理者は不要です。",
    connectionNotice:
      "接続検証は読み取り専用です。適用権限は事前確認で別途検証します。",
    bootstrapDeployer: "SAと最小権限ロールを自動作成",
    bootstrapDeployerHint:
      "必要な最小ロール: サービス アカウント管理者 (roles/iam.serviceAccountAdmin)、ロール管理者 (roles/iam.roleAdmin)、プロジェクト IAM 管理者 (roles/resourcemanager.projectIamAdmin)。または セキュリティ管理者 / オーナー。",
    bootstrapConfirm:
      "デプロイヤーSA、カスタムロール、プロジェクトIAM、あなたのToken Creator権限を作成または更新します。続行しますか？",
    bootstrapWorking: "デプロイヤーを作成中…",
    bootstrapComplete: "デプロイヤーの自動構成が完了しました",
    bootstrapNext:
      "デプロイヤー用サービスアカウントと最小権限カスタムロールがGoogle Cloud上に構成され、ブラウザ内で自動連携されました。",
    bootstrapFailed: "デプロイヤーの自動準備に失敗しました",
    progressTitle: "デプロイ進捗",
    progressCount: (completed: number, total: number) =>
      `${total}件中${completed}件を完了`,
    currentOperation: "現在の操作",
    waitingForOperation: "最初の操作を待っています…",
    environmentTitle: "プライベート環境を設定",
    environmentIntro:
      "望ましい状態を定義します。変更前に既存リソースを検出します。",
    deploymentName: "デプロイ名",
    region: "リージョン",
    zone: "ゾーン",
    secondaryZone: "セカンダリゾーン（本番HA）",
    sourceImage: "不変のハードニング済みVMイメージ",
    sourceImageHint:
      "本番ではPython 3とNginxを事前導入したバージョン固定イメージが必要です。イメージファミリーは使用できません。",
    minimumReplicas: "Nginx最小レプリカ数",
    maximumReplicas: "Nginx最大レプリカ数",
    cpuTarget: "オートスケーリングCPU目標値（0.1～0.9）",
    autoscalingHint:
      "本番では2ゾーンのリージョンManaged Instance Groupを使用します。パススルー型ロードバランサの使用率はスケーリング指標にできないため、CPUで自動スケールします。",
    network: "デプロイ方式",
    vpcName: "既存VPC名",
    subnetName: "既存サブネット名",
    managedSample: "管理対象サンプルバックエンド（Nginx）",
    managedSampleDescription:
      "検証とエビデンス収集用のプライベートHTTPバックエンドを作成します。",
    existingBackend: "既存HTTPバックエンド（Nginx）",
    existingBackendDescription:
      "既に確立済みのプライベート接続を使い、管理者が管理するHTTPエンドポイントへ転送します。",
    directHttps: "Option A — 既存HTTPSアプリへ直接接続",
    directHttpsDescription:
      "Secure Gatewayから既存HTTPSエンドポイントへVPC経由で直接接続します。Nginx、VM、NAT、オフロード証明書は作成しません。",
    internalHttpsLb:
      "Option B — Internal Application Load BalancerでHTTPSオフロード",
    internalHttpsLbDescription:
      "Regional Internal Application Load BalancerでHTTPSを終端し、プライベートサンプルへHTTP転送します。Nginxオフロード層は作成しません。",
    legacyNginxTitle: "Option C — 旧Nginx方式 / Legacy・詳細設定",
    legacyNginxDescription:
      "HTTPアプリ、または従来のNginxベース構成が必要な場合だけ展開します。",
    proxySubnetCidr: "ILB Proxy-onlyサブネットCIDR",
    backendUrl: "バックエンドURL（http://）",
    directHttpsUrl: "プライベートHTTPSエンドポイント（https://host[:port]）",
    applicationEgressRegion: "下り（外向き）リージョン（任意）",
    applicationEgressRegionHint:
      "クロスリージョン対応ターゲットでは空欄にします。リージョンターゲットまたは静的ルートではアプリのリージョンを指定します。",
    backendLocation: "バックエンドのホスティング先",
    backendLocationGcp: "Google Cloud",
    backendLocationAws: "AWS",
    backendLocationAzure: "Azure",
    backendLocationOnPrem: "オンプレミス",
    confirmBackendConnectivity:
      "選択したGCP VPC/サブネットからのプライベートルーティング、DNS、バックエンドのファイアウォール許可が確立済みです",
    backendConnectivityHint:
      "本PoCではNginxを構成し、T02でアップストリームを検証します。AWS/Azure VPN、Cloud VPN、Interconnect、オンプレミス側ルートは作成しません。先にプライベート経路を確立し、公開エンドポイントや認証情報は入力しないでください。",
    deploySampleBackend: "🚀 テスト用バックエンドVMを1クリック構築",
    deployingSampleBackend: "バックエンドVM・VPC・NAT・ファイアウォールを構築中...",
    sampleBackendReady: "テスト用バックエンドVMが稼働中 (secgw-backend.internal)",
    sampleBackendDescription:
      "専用VPC (secgw-test-vpc)、固定送信元IP付きCloud NAT、ポート80/443対応のDebian 12 Nginx VM (10.10.0.2) をGCP上にワンクリックで一括自動構築します。",
    cloudConsoleLinks: "Google Cloud & Workspace コンソール直リンク",
    openInCloudConsole: "コンソールで確認",
    computeInstancesLink: "Compute Engine VM インスタンス一覧",
    securityGatewaysLink: "BeyondCorp Security Gateways",
    vpcNetworksLink: "VPC ネットワーク & サブネット",
    cloudNatLink: "Cloud NAT (GitHub Allowlist用 固定送信元IP)",
    chromeAdminLink: "Chrome 管理ポリシー (Root Store)",
    architectureBlueprint: "アーキテクチャ設計図 & テレメトリ",
    directHttpsConnectivity:
      "選択したVPCでホスト名を解決でき、HTTPSアプリへの経路、136.124.16.0/20からのTCP許可、戻り経路が設定済みです",
    directHttpsConnectivityHint:
      "Secure GatewayはHTTPSアプリへ直接接続します。AWS・Azure・オンプレミスでは、先にCloud VPN/Interconnect、Cloud DNS転送ゾーン、ファイアウォール、136.124.16.0/20への明示的な戻り経路を設定します。",
    hostname: "プライベートアプリのホスト名",
    noExternalIpNotice:
      "VMの外部IPは常に無効です。Cloud NATで制御されたパッケージ取得経路を提供します。",
    certificateStepTitle: "TLS証明書ソースを設定",
    certificateIntro:
      "オフロードVMは実行時にSecret Managerから証明書を読み取ります。秘密鍵は起動スクリプトに書き込まれません。",
    internalLbCertificateIntro:
      "Regional Internal Application Load Balancerがリージョンサーバー証明書でHTTPSを終端します。証明書データはメモリからCompute APIへ直接送信し、Secret Managerでライフサイクル管理します。",
    caPool: "CAプールのリソース名",
    caName: "発行CAのリソース名",
    secretName: "Secret Managerの証明書シークレット",
    certificateNotice:
      "ローカルCAはPoC専用です。適用後に公開ルート証明書（PEM）をダウンロードし、[Chrome] > [コネクタ] > [Chrome Root Store] へ追加して専用テストOUへ接続します。公開APIではこの引き渡しを確実に参照・実行できないため、T07で信頼を検証します。本番ではエンタープライズPKIまたは公開信頼済み証明書が必要です。",
    internalLbCertificateNotice:
      "ローカルCAではILBが生成済みサーバー証明書を提示します。Apply（適用）後に公開ルート証明書（PEM）を管理コンソールのChrome Root Store経由でテストOUへ配布し、Chrome再起動後にT07でHTTPS接続を検証します。秘密鍵はChromeへ配布しません。",
    directCertificateIntro:
      "HTTPSアプリ自身がTLS終端を行います。Secure Gatewayはアプリの証明書や秘密鍵を作成・保存しません。",
    directCertificateNotice:
      "公開信頼済み証明書ならRoot Store操作は不要です。プライベートCAの場合はアプリ管理者から発行元ルートPEMを入手し、[Chrome] > [コネクタ] > [Chrome Root Store] でテストOUへ手動配布します。この構成は公開APIで確実に参照・変更できません。",
    directPrivateCertificate: "アプリのプライベートCA / Chrome Root Store手動信頼",
    accessTitle: "Chromeポリシーとアプリへのアクセスを制限",
    accessIntro: "専用テストOUと最小限のプリンシパルから開始します。",
    customerId: "Workspace 顧客ID",
    targetOuId: "専用テストOU ID",
    managedChromeAccessLevel: "管理対象Chromeのアクセスレベル",
    managedChromeAccessLevelHint:
      "このセットアップで使用する既存のAccess Context Managerレベルを選択します。プロファイル管理、ブラウザ管理、またはその両方を対象にできます。",
    optionsLoadedHint:
      "検証済みサービスアカウントを使用し、Google CloudとGoogle Workspaceから読み取り専用で選択肢を取得します。",
    optionsLoading: "選択肢を取得中…",
    chooseOption: "選択してください",
    noOptions: "選択肢がありません",
    retryOptions: "再取得",
    ouOptionsFailed:
      "組織部門を取得できませんでした。Admin SDK APIとサービスアカウントの組織部門読み取り権限を確認してください。",
    accessLevelOptionsFailed:
      "アクセスレベルを取得できませんでした。対象のAccess Context ManagerポリシーでサービスアカウントにPolicy Readerを付与してください。",
    groupOptionsFailed:
      "グループを取得できませんでした。サービスアカウントのGoogle Workspace管理者ロールにグループ読み取り権限を追加してください。",
    prerequisitesTitle: "手動の前提条件確認",
    confirmEnterpriseLicense:
      "対象ユーザーにChrome Enterprise Premiumライセンスを割り当て済み",
    confirmWorkspaceServices:
      "対象ユーザーの追加のGoogleサービスとGoogle Cloudアクセスを有効化済み",
    confirmEndpointVerification:
      "このOUでEndpoint Verificationのデバイス信号収集を有効化済み",
    confirmTestOu: "非本番のテストOUであることを確認しました",
    principalType: "プリンシパル種別",
    principalValue: "プリンシパル",
    addPrincipal: "プリンシパルを追加",
    removePrincipal: "削除",
    user: "ユーザー",
    group: "グループ",
    domain: "ドメイン",
    accessNotice:
      "検証済みの管理対象Chromeアクセスレベルを条件にアプリへのアクセスを付与し、このOUだけにSecure GatewayとEndpoint Verificationを強制配布します。",
    reviewTitle: "検出結果と自動設定予定を確認",
    reviewIntro:
      "APIで確認できた状態、Applyで自動設定する項目、対応が必要な項目を分けて表示します。この画面ではまだ変更しません。",
    configuration: "構成",
    safetyGates: "安全ゲート",
    ready: "準備完了",
    incomplete: "未完了",
    verified: "検証済み",
    plannedOnApply: "Applyで自動設定",
    manualCheck: "手動確認",
    actionRequired: "要対応",
    approvalPending: "承認待ち",
    pocDefault: "PoC設定",
    reviewGateLegend:
      "【検証済み】API検出や構成条件で確認完了 / 【Applyで自動設定】承認後に自動プロビジョニング / 【手動確認】管理者の確認が必要な項目 / 【要対応】適用をブロックする問題です。",
    gateLabels: {
      "immutable-image": "PoC用イメージ",
      "billing-enabled": "Cloud Billing",
      "enterprise-license": "Chrome Enterprise Premiumライセンス",
      "chrome-root-store": "Chrome Root Store信頼配布",
      "workspace-services": "Workspaceサービス",
      "managed-chrome-profile": "管理対象Chromeプロファイル",
      "secure-enterprise-browser-client": "Secure Enterprise Browserクライアント",
      "endpoint-verification": "Endpoint Verification",
      "no-external-ips": "外部IPなし",
      "private-egress": "Cloud NAT",
      "backend-connectivity": "既存バックエンド接続",
      "test-ou": "対象OU",
      "cloud-identity": "Google Cloudデプロイヤー",
      "workspace-identity": "Chrome権限付きサービスアカウント",
      "required-apis": "必須API",
      "apply-permissions": "Apply実行権限",
      "resource-conflicts": "既存リソース競合",
      "human-approval": "承認",
    },
    gateDescriptions: {
      "immutable-image": "PoCでは現在のDebian 12イメージファミリーを使用します。固定イメージは本番要件です。",
      "billing-enabled": "Cloud Billing APIでプロジェクトに有効な課金アカウントが紐付いているか確認します。",
      "enterprise-license": "Enterprise License Manager APIでChrome Enterprise Premiumの割り当て数を確認します。APIで確認できない場合のみ管理者確認を使用します。",
      "chrome-root-store": "Chrome Root Store構成、証明書アップロード、OUバインドは公開APIで確実に参照できません。Apply後にこの1回限りの管理コンソール操作を完了し、各プラットフォームのT07 HTTPSテストで信頼を検証します。",
      "workspace-services": "対象ユーザーのWorkspaceサービス設定は管理者による確認が必要です。",
      "managed-chrome-profile": "Chrome Management Profiles APIで対象OUの実プロファイルとポリシー同期報告を確認します。",
      "secure-enterprise-browser-client": "Chrome Management Profiles APIでクライアント拡張機能のインストール・有効状態を確認します。",
      "endpoint-verification": "Chrome Management Profiles APIで実クライアントを確認し、未報告の場合はApplyで対象OUへ強制インストールします。",
      "no-external-ips": "Applyで外部IPを持たないPoC用VMを作成します。",
      "private-egress": "Applyでパッケージ取得用のCloud NATを作成します。",
      "backend-connectivity": "管理対象サンプルはデプロイVPC内に作成します。既存バックエンドではプライベートルーティング、DNS、ファイアウォール許可を確認し、ApplyがNginxからT02で経路を検証します。本PoCではクロスクラウドVPNやInterconnectを作成しません。",
      "test-ou": "選択したOUが非本番テスト用であることを確認済みです。",
      "cloud-identity": "Google Cloudデプロイヤーを読み取り専用で検証済みです。",
      "workspace-identity": "Chrome権限付きサービスアカウントを読み取り専用で検証済みです。",
      "required-apis": "不足している許可済みAPIはApply中に自動で有効化します。",
      "apply-permissions": "計画した操作に必要な全権限がデプロイヤーにあるかAPIで確認します。",
      "resource-conflicts": "既存リソースが望ましい状態と互換性を持つか確認します。",
      "human-approval": "Apply前に、構成ハッシュへ紐付いたプランを管理者が承認します。",
    },
    managedProfileEvidence: (total, profileOnly, sync) =>
      `検出されたプロファイル数: ${total}件（プロファイル管理BYOD: ${profileOnly}件）、最終ポリシー同期: ${sync ?? "未同期"}`,
    clientExtensionEvidence: (name, version, installed) =>
      installed
        ? `Profiles APIで${name} ${version ?? ""}のインストール済み・有効を確認しました。`
        : `${name}のインストール済み・有効報告はまだありません。`,
    missingPermissions: (count: number) =>
      `デプロイヤーに必要な権限が${count}件不足しています。`,
    approvePlan: "この正確なプランを承認",
    approvePlanDescription:
      "承認は構成ハッシュに紐付き、設定を変更すると無効になります。",
    generatePlan: "事前確認を実行してプランを生成",
    runPreflight: "信頼済み事前確認を実行",
    preparingPlan: "リソースを検出し、正確なプランを生成しています…",
    planReady: "サーバー検証済みプランを生成しました",
    planBlocked: "プランにブロッキングゲートがあります",
    changesCount: (count: number) => `承認が必要な実変更 ${count} 件`,
    preflightProgressTitle: "事前確認・リソース検出の進捗",
    preflightStage1: "1/5: Service Usage & IAM 権限の検証中...",
    preflightStage2: "2/5: Cloud Billing & プロジェクト関連付けの検証中...",
    preflightStage3: "3/5: BeyondCorp Security Gateway & VPC リソースの検出中...",
    preflightStage4: "4/5: Chrome Management & テスト OU ポリシーの照合中...",
    preflightStage5: "5/5: 差分計画の構築 & セーフティゲートの判定中...",
    preflightComplete: "すべての事前確認とセーフティゲートの検証が完了しました",
    plannedChangesTitle: "承認対象の正確な変更",
    plannedChangesIntro:
      "作成・更新する項目だけを表示します。再利用または変更なしのリソースは更新しません。",
    changeAction: (action) =>
      ({ create: "新規作成", update: "更新" })[action] ?? action,
    changeRisk: (risk) =>
      ({ low: "低リスク", medium: "中リスク", high: "高リスク", blocking: "ブロック" })[
        risk
      ] ?? risk,
    changeSummary: (resourceType, fallback) =>
      resourceType === "service_discovery_proxy"
        ? "対象テストOUで継承中の旧PACを［ユーザーによる設定を許可］で上書きし、PACファイルなしのService Discoveryルーティングへ切り替えます。"
        : fallback,
    diagnosticsTitle: "検出した状態",
    apiEvidence: "API検出値",
    diagnosticMessage: (code, fallback) =>
      code === "legacy-pac-policy-detected"
        ? "親OUから継承した旧PACポリシーが、このテストOUでまだ有効です。"
        : code === "chrome-extension-group-policy-conflict"
          ? "Chromeのグループポリシーが、対象OUのSecure Enterprise Browser設定を上書きしています。"
        : fallback,
    diagnosticRemediation: (code, fallback) =>
      code === "legacy-pac-policy-detected"
        ? "PACに定義されていないホスト名はDIRECT（直接接続）となり、通常DNSで名前解決できずに ERR_NAME_NOT_RESOLVED が発生します。Applyでは選択したテストOUだけを上書きし、親OUと既存PACファイルは変更しません。"
        : code === "chrome-extension-group-policy-conflict"
          ? "表示されたグループの［アプリと拡張機能］を確認し、空または不整合な管理対象設定を削除するか、テストOUと同じSecure Gateway設定にします。グループ変更は全メンバーへ影響するため、自動適用せずブロックします。"
        : fallback ?? "",
    approveWorking: "承認を紐付けています…",
    approvalReady: "正確なプランを承認済み",
    continueToApply: "適用へ進む",
    applyTitle: "チェックポイントとエビデンス付きで適用",
    applyIntro:
      "依存関係に従って順番に変更を適用します。途中で失敗した場合は即座に停止し、本デプロイで作成されたリソースのみを安全にロールバックします。",
    preflight: "事前確認",
    desiredStatePlan: "望ましい状態プラン",
    applyChanges: "承認済み変更を適用",
    applyLocked: "事前確認と承認を完了すると適用できます",
    applying: "承認済み変更を適用しています…",
    runSucceeded: "デプロイに成功しました",
    runRolledBack: "デプロイに失敗し、所有する変更をロールバックしました",
    runInterrupted:
      "適用中にローカルサービスが再起動しました。記録された操作を確認してから再実行してください。",
    runFailed: "オペレーターによる確認が必要です",
    operationCount: (count: number) => `${count} 件の操作を記録`,
    evidenceNotice:
      "すべての操作について、監査イベント、マスク済みリクエスト情報、結果、所有権を記録します。",
    caHandoffTitle: "管理対象Chromeの信頼設定を完了",
    caHandoffDescription:
      "Chrome Root Store構成、証明書アップロード、OUバインドは公開APIで確実に参照・実行できません。E2Eテスト前に、この1回限りの管理コンソール引き渡しを完了してください。",
    caHandoffSteps: [
      "下から公開PoCルート証明書をダウンロードします。秘密鍵は含まれません。",
      "Google管理コンソールで [すべてのブラウザとデバイス] を開き、[Chrome] > [コネクタ] > [新しいプロバイダの設定] > [Chrome Root Store] と進みます。PEMを [ルート] 証明書として追加し、構成を追加します。",
      "専用テストOUを選択し、[証明書コネクタ] > [Chrome Root Store] で新しい構成を選んで保存します。Chromeを再起動し、chrome://certificate-manager > [ローカル証明書] で確認します。",
    ],
    downloadRootCa: "公開ルートCAをダウンロード",
    downloadingRootCa: "ダウンロードを準備中…",
    openAdminConsoleGuide: "GoogleのCA設定ガイドを開く",
    caDownloadFailed:
      "ルートCAをダウンロードできませんでした。適用が成功していることを確認して再試行してください。",
    previous: "戻る",
    next: "続行",
  },
  operations: {
    deploymentsTitle: "デプロイ実行履歴",
    deploymentsIntro:
      "サーバーに記録された適用処理と、その最終状態を確認します。",
    evidenceTitle: "監査証跡",
    evidenceIntro:
      "ローカルのハッシュチェーンを検証し、持ち運び可能なJSON証跡を出力します。",
    loading: "記録済みの状態を読み込み中…",
    loadFailed: "ローカルAPIから記録済みの状態を読み込めませんでした。",
    noRuns: "デプロイ実行履歴はまだありません。",
    noEvents: "監査イベントはまだありません。",
    runId: "実行ID",
    status: "状態",
    started: "開始日時",
    operationsCount: "操作数",
    manage: "管理",
    close: "閉じる",
    overviewTab: "概要",
    logsTab: "ログ",
    resourcesTab: "リソース",
    deleteTab: "削除",
    deploymentName: "デプロイ",
    project: "プロジェクト",
    gateway: "Secure Gateway",
    application: "Application route",
    architecture: "アーキテクチャ",
    ownershipRun: "リソース所有権を記録した実行",
    architectureLabel: (kind) =>
      ({
        managed_sample: "Nginx HTTPオフロード・管理サンプル",
        existing_http: "Nginx HTTPオフロード・既存バックエンド",
        direct_https: "プライベートHTTPS直接接続",
        internal_https_lb: "Internal Application Load Balancer HTTPSオフロード",
      })[kind] ?? kind,
    accessLevelControlTitle: "アクセス制御・アクセスレベル設定",
    accessLevelControlIntro:
      "BeyondCorp Application の IAM ポリシーにバインドされている Access Context Manager のアクセスレベル条件や許可プリンシパルを即時更新します。",
    selectAccessLevelLabel: "適用するアクセスレベル",
    principalsLabel: "許可するプリンシパル（ユーザー / グループ / ドメイン）",
    principalsHelper: "カンマ区切りで指定（例: user:admin@test-domain.dev, domain:test-domain.dev）",
    noAccessLevelRequired: "（アクセスレベル制限なし・認証済みグループ全ユーザー）",
    boundGroup: "対象 IAM グループ",
    updateAccessLevelButton: "アクセスレベルを即時更新",
    updatingAccessLevel: "IAMポリシーを更新中...",
    accessLevelSaved: "アクセスレベルを更新し、暗号化ハッシュチェーンに記録しました",
    ownedResources: "このデプロイが所有するリソース",
    retainedResources: "保持する共有・再利用リソース",
    resourceAction: (action) =>
      ({
        delete: "削除",
        delete_if_empty: "Applicationが残っていない場合だけ削除",
        retain: "保持",
      })[action] ?? action,
    logsTitle: "Secure Gatewayログ",
    logsIntro:
      "Cloud Loggingからアクセス判定、Gateway接続、管理操作、収集済みNginxログを取得します。",
    logCategory: (category) =>
      ({
        access: "アクセス判定",
        connection: "接続",
        admin: "管理操作",
        nginx: "Nginxリクエスト",
      })[category] ?? category,
    hours24: "過去24時間",
    hours168: "過去7日間",
    refreshLogs: "ログを更新",
    refreshingLogs: "Cloud Loggingを照会中…",
    enableLogging: "Gateway loggingを有効化",
    enablingLogging: "Loggingを有効化中…",
    loggingEnabled: "Gateway接続ログは有効です",
    loggingNotEnabled: "Gateway接続ログは有効になっていません",
    noLogs: "指定期間に一致するログは返されませんでした。",
    logQueryFailed:
      "Cloud Loggingを照会できません。IDステップの［SAと最小権限ロールを自動作成］を再実行してlogging.logEntries.listとSecure Gateway更新権限を追加し、再試行してください。",
    dataAccessNotice:
      "アクセス判定ログにはBeyondCorp Enterprise APIのData Access Audit Logsが必要です。",
    nginxNotice:
      "NginxログにはGoogle Cloud Ops Agentによるsgstudio-access.logの収集が必要です。",
    principal: "プリンシパル",
    method: "メソッド",
    requestId: "リクエストID",
    payload: "サニタイズ済みペイロード",
    teardownTitle: "このデプロイを削除",
    teardownIntro:
      "成功したApplyが所有権を記録したリソースだけを、依存関係の逆順で削除します。",
    teardownSharedNotice:
      "既存VPC、Access Level、Project API、Chrome Policy、共有・再利用リソースは保持します。この実行が作成したGatewayも、Applicationが残っていない場合だけ削除します。",
    teardownUnavailable: "安全に削除できる所有リソースがこの実行にはありません。",
    teardownConfirmation: "正確な確認文",
    teardownConfirmationHint: "上に表示された確認文をそのまま入力",
    startTeardown: "所有リソースを削除",
    teardownRunning: "所有リソースを削除中…",
    teardownSucceeded: "削除完了",
    teardownFailed: "削除を停止しました。確認が必要です",
    teardownActionFailed: "削除処理を開始または更新できませんでした。",
    teardownProgress: (completed, total) => `${total}件中${completed}件の操作が完了`,
    exportEvidence: "証跡を出力",
    integrityValid: "監査チェーン検証済み",
    integrityInvalid: "監査チェーンの検証に失敗",
    eventCount: (count: number) => `${count}件の連結イベント`,
    chainHead: "チェーン先頭 SHA-256",
    recentEvents: "最近の監査イベント",
    notAvailable: "利用できません",
    acceptanceTitle: "受入検証・テスト",
    acceptanceIntro:
      "T01〜T05の自動システム検証を実行し、管理対象Chrome（T06〜T09）のテスト結果と監査ログ証跡を記録・管理します。",
    noSuccessfulRun: "受入テストを開始するには、成功したデプロイ実行が必要です。",
    runSystemChecks: "T01〜T05を検証",
    runningSystemChecks: "Google Cloudリソースを検証しています…",
    acceptanceComplete: "PoC受入を完了",
    acceptancePending: "受入証跡が未完了",
    requiredProgress: (satisfied, required) =>
      `必須ケース ${required}件中 ${satisfied}件を充足`,
    acceptanceTest: (testId) =>
      ({
        T01: "HTTPバックエンド応答",
        T02: "オフロードからバックエンドへの応答",
        T03: "TLS終端",
        T04: "プライベートDNS",
        T05: "Secure Gatewayマッチャー",
        T06: "既存の直接HTTPS制御アプリ",
        T07: "管理対象ChromeのE2E",
        T08: "ログ相関",
        T09: "未承認・非管理端末の拒否",
      })[testId] ?? testId,
    acceptanceScope: (caseKey) =>
      ({
        default: "デプロイ全体",
        macos: "macOS",
        windows: "Windows",
        linux: "Linux",
        chromeos: "ChromeOS",
        unauthorized_principal: "未承認プリンシパル",
        unmanaged_browser: "非管理ブラウザ",
      })[caseKey] ?? caseKey,
    acceptanceStatus: (status) =>
      ({
        passed: "合格",
        failed: "不合格",
        user_confirmed: "オペレーター確認済み",
        skipped: "スキップ",
        missing: "未記録",
      })[status] ?? status,
    evidenceSource: (source) =>
      source === "system" ? "システム検証" : "オペレーター証跡",
    missingEvidence: "証跡は未記録です",
    viewEvidence: "マスク済み証跡を表示",
    operatorEvidenceTitle: "エンドポイント証跡を記録",
    operatorEvidenceIntro:
      "マスク済みの観測結果または成果物のハッシュだけを保存してください。トークン、Cookie、秘密鍵、認証情報は入力しないでください。",
    testCase: "テスト項目",
    testInstruction: (testId, caseKey) =>
      testId === "T06"
        ? "同じ管理対象仕事用プロファイルで既存のHTTPS Secure Gatewayコントロールアプリを開きます（例: https://demo-server1.internal/）。証明書警告なしで開いた場合だけ合格として記録します。既存の制御アプリがない新規PoCでは、その理由を付けて［スキップ］を記録できます。本番では引き続き合格が必須です。"
        : testId === "T07"
          ? `${caseKey}の許可済み管理対象Chromeプロファイルで、新しくデプロイしたプライベートHTTPSアプリを開き、表示結果と時刻を記録します。`
          : testId === "T08"
            ? "マスク済みリクエスト識別子と時刻を使い、Gateway・オフロード・バックエンドのイベントを相関します。"
            : testId === "T09"
              ? "選択した未承認ケースが拒否され、バックエンドへ成功リクエストが届いていないことを確認します。"
              : "この受入ケースで観測した結果を記録します。",
    evidenceOutcome: "観測結果",
    outcomePassed: "合格",
    outcomeFailed: "不合格",
    outcomeSkipped: "スキップ",
    evidenceSummary: "結果の概要",
    evidenceDetail: "マスク済み証跡または成果物のSHA-256",
    recordEvidence: "確認結果を記録",
    recordingEvidence: "記録中…",
    evidenceRecorded: "受入証跡を記録しました。",
    acceptanceActionFailed:
      "受入操作に失敗しました。ローカルAPIと認証情報を確認してください。",
    statusSucceeded: "適用完了",
    statusDeleted: "削除完了",
    statusRunning: "実行中",
    statusPending: "待機中",
    statusFailed: "エラー",
    t07DiagnosticsTitle: "管理対象Chromeクライアント診断",
    t07DiagnosticsIntro:
      "T07受入テストを記録する前に、ブラウザで発生した事象を診断・切り分けます。エラー内容に応じて、ルーティング、IAM認可、証明書信頼のどの設定に問題があるかを特定できます。",
    t07Diagnostics: [
      {
        symptom: "ERR_NAME_NOT_RESOLVED",
        meaning:
          "プライベートホスト名が捕捉されていません。管理対象拡張機能が未有効、または親OUから継承した旧PACがこのプロファイルを制御してService Discoveryのルートを読み込めない状態が考えられます。",
        actions: [
          "このアプリで事前確認を実行し、旧PACが検出された場合は対象テストOUだけの上書き内容を承認前に確認します。",
          "同じChrome仕事用プロファイルでSecure Enterprise Browserが管理者によるインストール済みかつ最近同期済みであることを確認します。",
          "PACが有効でなければ、Gatewayルート、Service Discovery IAM、アプリ利用IAMを確認します。",
        ],
      },
      {
        symptom: "Access Denied（403）",
        meaning:
          "Service DiscoveryはSecure Gatewayへ到達しましたが、プリンシパルまたはAccess Context Manager条件を満たしていません。",
        actions: [
          "同じ仕事用プロファイルでEndpoint Verificationを開き、必要なら会社アカウントを追加して［今すぐ同期］を実行します。",
          "ユーザーまたはグループにGatewayのService Discovery権限とアプリ利用権限の両方があることを確認します。",
          "BYODテストでは選択したAccess LevelがPROFILE_MANAGED Chromeを許可していることを確認します。",
        ],
      },
      {
        symptom: "NET::ERR_CERT_AUTHORITY_INVALID（証明書エラー）",
        meaning:
          "Secure GatewayのルーティングとTLSオフロードは動作していますが、この端末がPoCルートCAを信頼していません。",
        actions: [
          "Apply画面から生成済みPoCルート証明書をダウンロードします。",
          "管理コンソールの [Chrome] > [コネクタ] > [Chrome Root Store] でPEMを追加し、その構成を専用テストOUへ接続してからChromeを再起動します。",
          "信頼前に証明書フィンガープリントを照合し、プライベートHTTPS URLを再試験します。",
        ],
      },
    ],
  },
  guide: {
    eyebrow: "新規セットアップガイド",
    title: "各セットアップ手順で実行すること",
    intro:
      "ウィザードは少数のPoC設定から現在の状態を検出し、確認・承認可能なSecure Gatewayデプロイを作成します。最後の「適用」まではGoogle CloudリソースやChromeポリシーを変更しません。",
    pocNoticeTitle: "Secure Gateway の PoC を最短で実施するためのツール",
    pocNoticeBody:
      "本番モードは将来対応を示すために表示していますが、このリリースでは無効です。非本番専用OUとテスト用プリンシパルを使用し、本番トラフィックはこの手順へ流さないでください。",
    quickOverviewTitle: "クイック概要 & 基本アーキテクチャ",
    quickOverviewIntro:
      "3つのデプロイアーキテクチャと7つのセットアップステップの概要です。",
    technicalDeepDiveTitle: "ステップ別の技術詳細と Google REST API 連携",
    technicalDeepDiveIntro:
      "各ステップで内部的に行われる処理、オプションごとの挙動、および呼び出される Google Cloud / Workspace REST API の詳細解説です。",
    optionsBehaviorLabel: "オプションの挙動と動作ロジック",
    apiCallsLabel: "実行される Google REST API コール",
    safetyGuardrailLabel: "安全制御とロールバック保護",
    architectureTitle: "独立した3つのデプロイアーキテクチャ",
    architectureIntro:
      "アプリごとに1方式を選択します。Option A/Bを主要PoC方式とし、従来のNginx方式はOption CとしてLegacy／詳細設定に残します。",
    costOverviewTitle: "GCPインフラ概算月額コスト（CEPライセンス外）",
    costOverviewIntro:
      "BeyondCorp Security Gatewayリソース自体の作成・利用はChrome Enterprise Premium（CEP）ライセンスに含まれており、追加のGateway基本料金はかかりません。以下は、CEPユーザーライセンス外で発生する各アーキテクチャのGoogle Cloudインフラ概算月額費用です。",
    architectures: [
      {
        eyebrow: "Option A · 既存HTTPSへ直接接続",
        title: "Secure Gateway + 既存プライベートHTTPSアプリ",
        summary:
          "アプリが既にHTTPSを提供する場合に使います。Secure Gatewayが選択VPC経由で直接ルーティングし、Nginx、VM、NAT、オフロード証明書は作成しません。",
        estimatedCost: "約 $0.20 〜 $1.00 / 月（約30円〜150円）",
        costFixed: "固定費: Cloud DNS限定公開ゾーン（約$0.20/月）。ロードバランサー・VM・NAT・Router等の固定費リソースは一切不要（$0.00）。",
        costVariable: "変動費: Cloud DNSクエリ課金（100万回あたり$0.40）+ VPC標準ネットワークトラフィック（通常利用では数十円未満）。",
        nodes: [
          { label: "管理対象Chrome", detail: "ユーザーID + 端末/プロファイル情報", costBadge: "無料" },
          { label: "Secure Gateway", detail: "hostname:port matcher + アクセスポリシー（Gateway基本料 $0.00）", costBadge: "CEPトライアルライセンス内に含まれる" },
          { label: "Upstream VPC", detail: "委任SAにupstreamAccessを付与（VPC自体は無料）", costBadge: "基本無料 / 通信量のみ" },
          { label: "HTTPSアプリ", detail: "既存証明書でアプリ自身がTLS終端", costBadge: "既存インフラ" },
        ],
        supports: [
          { label: "DNS解決", detail: "Cloud DNS限定公開ゾーンまたは転送ゾーン" },
          { label: "ネットワーク制御", detail: "136.124.16.0/20からTCP許可 + 戻り経路" },
          { label: "リージョン経路", detail: "任意egress region、またはregional LBのGlobal Access" },
        ],
      },
      {
        eyebrow: "Option B · ILB HTTPSオフロード",
        title: "Secure Gateway + 内部HTTPSロードバランサー + HTTPアプリ",
        summary:
          "Regional Internal Application Load BalancerをHTTPSオフロード層として使用します。ILBがサーバー証明書を提示して復号後のHTTPをプライベートバックエンドへ転送し、オフロード経路にNginxを作成しません。",
        estimatedCost: "約 $18.00 〜 $25.00 / 月（約2,700円〜3,800円）",
        costFixed: "固定費: Regional Internal Application LBの転送ルール基本料（約$18.25/月）+ Cloud DNS（約$0.20/月）。ローカルPoC CA/DevOps CAは$0.00。",
        costVariable: "変動費: ロードバランサーのデータ処理量・LCU（1GBあたり約$0.008〜$0.01）+ バックエンド通信トラフィック。",
        nodes: [
          { label: "管理対象Chrome", detail: "Chrome Root Storeから発行元Root CAを信頼", costBadge: "無料" },
          { label: "Secure Gateway", detail: "ID・コンテキスト・hostname:443ポリシー", costBadge: "CEPトライアルライセンス内に含まれる" },
          { label: "Regional Internal Application LB", detail: "リージョンサーバー証明書でHTTPS終端（転送ルール基本料 約$18.25/月）", costBadge: "約 $18/月 + LCU従量" },
          { label: "HTTPバックエンド", detail: "TCP 80のプライベートサンプルVM または 既存HTTPアプリ", costBadge: "サンプルVM: 約$7〜15/月 または 既存" },
        ],
        supports: [
          { label: "Proxy-onlyサブネット", detail: "Google管理Envoy専用のREGIONAL_MANAGED_PROXYサブネット" },
          { label: "TLS所有", detail: "Enterprise CA、ローカルPoC CA、または検証済み既存Secret" },
          { label: "Chrome信頼", detail: "公開Root PEMをダウンロードしてChrome Root StoreからテストOUへ接続" },
          { label: "管理型L7経路", detail: "HTTP health check、backend service、URL map、target HTTPS proxy、内部forwarding rule" },
          { label: "安全なライフサイクル", detail: "検出、競合判定、逆順ロールバック、所有範囲限定削除、最小権限IAM" },
        ],
      },
      {
        eyebrow: "Option C · 旧Nginx方式 / Legacy・詳細設定",
        title: "Secure Gateway + Nginx + HTTPアプリ",
        summary:
          "HTTPしか提供しないプライベートアプリ、または従来のNginx構成が必要な場合だけ使用します。PoCは非公開Nginx VM 1台を使い、実装済みスケール対応方式は内部パススルーNetwork Load Balancerと2ゾーンNginx MIGを使用します（Production選択は無効）。",
        estimatedCost: "約 $10.00 〜 $45.00 / 月（約1,500円〜6,800円）",
        costFixed: "固定費: Compute Engine Nginx VM（e2-microで約$7〜$10/月、e2-smallで約$15/月）+ ディスク代（約$0.40/月）+ Cloud DNS（約$0.20/月）。（Cloud NAT有効時のみ基本料 約$32/月）。",
        costVariable: "変動費: VM稼働時間 + NATデータ処理量（$0.045/GB）。",
        nodes: [
          { label: "管理対象Chrome", detail: "ユーザーID + 端末/プロファイル情報", costBadge: "無料" },
          { label: "Secure Gateway", detail: "Service Discovery + アクセスポリシー", costBadge: "CEPトライアルライセンス内に含まれる" },
          { label: "Nginxオフロード層", detail: "PoC: 非公開VM 1台 · スケール対応: パススルーILB + 2ゾーンMIG", costBadge: "PoC VM: 約$7〜15/月" },
          { label: "HTTPアプリ", detail: "GCP・AWS・Azure・オンプレミス", costBadge: "既存インフラ" },
        ],
        supports: [
          { label: "CPUオートスケール", detail: "スケール対応の既定2～20台・CPU 60%。最小、最大、CPU目標を設定可能" },
          { label: "Healthy台数ゲート", detail: "設定した最小レプリカ数がHealthyになるまでApplyが待機" },
          { label: "2ゾーン冗長化", detail: "Regional MIGがNginxレプリカを2つのゾーンへ分散" },
          { label: "Private DNS", detail: "アプリ名をNginx内部IPへ解決" },
          { label: "TLS証明書", detail: "CA Service・ローカルCA・既存SecretをNginxで利用" },
          { label: "プライベート経路", detail: "GCP外ではVPN/Interconnectとbackend firewall" },
          { label: "検出 + 競合判定", detail: "変更前にMIGとAutoscalerの既存状態・互換性を検出" },
          { label: "ロールバック", detail: "所有するMIG/Autoscaler変更をデプロイ失敗時に巻き戻し" },
          { label: "最小権限IAM", detail: "Instance GroupとAutoscalerの必須権限も事前確認" },
        ],
      },
    ],
    implementationTitle: "実装済み機能の全体像",
    implementationIntro:
      "現在のコードベースに実装されている技術要素を列挙しています。「スケール対応」はバックエンドに実装済みですが、Productionが無効な間は選択できず、PoCで作成済みのリソースとしては表示しません。",
    implementationGroups: [
      {
        eyebrow: "データプレーン",
        title: "HTTPオフロードと直接HTTPS",
        items: [
          "HTTPオフロードは、管理対象サンプルまたはGCP・AWS・Azure・オンプレミスの既存プライベートHTTPアプリに対応します。",
          "ILB HTTPSオフロードはREGIONAL_MANAGED_PROXYサブネット、HTTP backend group/health check、INTERNAL_MANAGED backend service、regional URL map/サーバー証明書/target HTTPS proxy、内部forwarding rule、Private DNSを作り、NginxオフロードVMを作成しません。",
          "直接HTTPSは既存VPC経由の正確なhostname:portルートを作り、Nginx、オフロードTLS、NAT、管理Aレコードを作成しません。",
          "専用/既存VPC、VM外部IPなし、作成VM用Cloud NAT、Private DNS、Secure Gateway送信元136.124.16.0/20のFWをモデル化しています。",
          "GCP外へのVPN/Interconnect、DNS転送、backend firewall、戻り経路は作成せず、明示的な事前条件として利用します。",
        ],
      },
      {
        eyebrow: "スケール対応HTTP層",
        title: "Regional Nginxの可用性とオートスケール",
        items: [
          "2ゾーンRegional Nginx MIG、内部パススルーNetwork Load Balancer、リージョンTLSヘルスチェック、ヘルスチェック用FWをスケール対応方式に実装し、TLS終端はNginxに残します。",
          "CPUオートスケールは既定2～20台・CPU 60%。最小、最大、CPU目標を日本語/英語UIから設定できます。",
          "設定した最小レプリカ数がHealthyになるまでデプロイを待機します。",
          "MIG/Autoscalerの検出、互換性・競合判定、所有範囲限定の逆順ロールバック、必須IAM権限確認を実装しています。",
        ],
      },
      {
        eyebrow: "Google制御プレーン",
        title: "CloudとChrome APIの自動化",
        items: [
          "選択方式に応じ、Service Usage、IAM、Compute、Cloud DNS、Secret Manager、CA Service、BeyondCorp、Access Context Manager、Chrome Policy/Management、Licensing、Billingを検出・操作します。",
          "ヘルパーがキーレスデプロイヤーSA、最小権限カスタムロールとバインディングを準備し、Applyが不足する許可済みAPIを自動有効化します。",
          "Secure Gateway、Service Discovery利用IAM、委任SAのupstreamAccess、application matcher、application IAM、任意Access Level条件をPlan/Applyします。",
          "テストOUへSecure Enterprise BrowserとEndpoint Verificationを強制インストールし、Gateway routeと継承PAC overrideを設定します。OU、グループ、Access LevelはAPIから取得します。",
        ],
      },
      {
        eyebrow: "TLSとID",
        title: "証明書と管理対象Chromeアクセス",
        items: [
          "HTTPオフロードはEnterprise CA、検証済み公開証明書Secret、公開ルートPEMを出力するローカルPoC CAに対応します。",
          "秘密鍵は専用accessor identity付きSecret Managerに保持し、active version alias、更新期限確認、offload refresh、失敗時補償を実装しています。",
          "Chrome Root StoreへのアップロードとOU接続は、公開APIで直接更新できないため管理コンソールでの手動登録手順として案内します。",
          "選択したAccess Context Managerレベルでプロファイル管理BYOD Chromeとブラウザ管理Chromeを表現でき、プロファイル・クライアント・Endpoint Verificationの報告状態を個別表示します。",
        ],
      },
      {
        eyebrow: "安全なApply",
        title: "検出、承認、進捗、ロールバック",
        items: [
          "信頼済みDiscoveryが望ましい状態との差分を作成し、新規作成/更新/変更なし/競合を分類して互換性のない既存リソースを変更前に安全に停止します。",
          "Billing、License、Workspace、テストOU、API、デプロイヤーID、権限、プライベート接続性、証明書、ChromeシグナルをAPI確認/自動/手動/ブロックに分類します。",
          "承認は正確な構成ハッシュに紐付き、有効期限・1回限り・編集時無効化を持ちます。ブラウザから直接指定された監査アクターは拒否します。",
          "Applyは操作チェックポイントとビジュアル進捗を記録し、同時実行を1件に制限。中断を検出し、共有リソースとIAM/Chrome Policyの変更前状態（before-image）を守りつつ所有変更のみを逆順にロールバックします。",
          "デプロイ管理画面でサニタイズ済みSecure Gateway/Nginxログ、Gateway logging有効化、所有/共有リソース一覧、正確な確認文を必要とする所有範囲限定の逆順削除を提供します。",
        ],
      },
      {
        eyebrow: "検証とローカル保護",
        title: "Acceptance証跡とオペレーター保護",
        items: [
          "永続的なT01～T09テスト記録でVM/ランタイムプローブ、正確なGoogle APIルート、各選択OSのHTTPS、リクエスト相関、必須の拒否テスト（Negative Test）を扱い、暗号検証可能な証跡をJSON出力します。",
          "SHA-256監査チェーン、デプロイ履歴、サニタイズ済みログ、リクエストID、クエリ/認証情報除去により秘密情報を残さず完全な追跡性を確保します。",
          "本アプリはローカル（ループバック）専用で動作し、Host/Originヘッダー検証、起動毎のワンタイムトークン（nonce）、厳格なCSP、キャッシュ無効化（no-store）、権限 0600 の SQLite データベースを適用します。",
          "キーレスADCのサービスアカウント借用（Impersonation）を必須とし、サービスアカウントJSONキーや他クラウドの認証情報は受け付けません。ワークフローと設定UI全体は日本語/英語に完全対応しています。",
        ],
      },
    ],
    stepLabel: (step) => `ステップ ${step}`,
    steps: [
      {
        title: "モード",
        subtitle: "PoC 境界の画定と戦略の選択",
        summary:
          "PoC の対象範囲、対象クライアント OS、VPC ネットワーク戦略、および TLS 認証局モデルを決定します。",
        actions: [
          "本番影響を防ぐため、迅速な PoC モードを維持し専用の非本番環境で検証します。",
          "受入テスト対象とする管理対象 Chrome プラットフォーム（macOS, Windows, Linux, ChromeOS）を選択します。",
          "新規の専用 VPC を自動作成するか、既存の社内 VPC に直接ルーティングするかを選択します。",
          "TLS 証明書の発行元（Enterprise CA / パブリック証明書 / ローカル PoC CA）を選択します。",
        ],
        optionsBehavior: [
          {
            name: "PoC モード vs 本番モード",
            behavior:
              "PoC モードでは単一ゾーン・軽量構成に絞り、迅速な検証を可能にします。誤操作による本番影響を防ぐため、本番モードは意図的にロックされています。",
          },
          {
            name: "専用 VPC vs 既存 VPC",
            behavior:
              "専用 VPC は競合のないクリーンな 10.0.0.0/16 ネットワークを自動作成します。既存 VPC は指定された既存サブネットへ直接ルーティングします。",
          },
          {
            name: "証明書戦略（Enterprise / Public / Local）",
            behavior:
              "Enterprise CA は Google CA Service と連携、Public は既存 Secret を参照、Local PoC CA はブラウザ内で一時的な自己署名 Root CA を自動生成します。",
          },
        ],
        apiCalls: [],
        safetyNote: "Local PoC CA を使用する場合は、本番環境ではなく必ず専用のテスト用 OU に限定して配布してください。",
      },
      {
        title: "ID",
        subtitle: "完全キーレスなクラウド & Workspace 管理者認証",
        summary:
          "サービスアカウントキー（JSON）を発行・保存せず、管理者アカウントによる安全なキーレスのサービスアカウント借用（Impersonation）認証を確立します。",
        actions: [
          "ブラウザの OAuth2 トークンを使用し、秘密鍵ファイルを持たないキーレス接続を行います。",
          "最小権限カスタムロールを持つ専用デプロイヤー SA（`secure-gateway-deployer`）を自動プロビジョニングします。",
          "GCP プロジェクトおよび Google Workspace Chrome Policy への読み取り専用 API アクセスを検証します。",
        ],
        optionsBehavior: [
          {
            name: "Google Cloud プロジェクト ID",
            behavior:
              "Secure Gateway やロードバランサーなどのインフラリソースを構築する対象 GCP プロジェクトを指定します。",
          },
          {
            name: "Google Workspace 顧客 ID",
            behavior:
              "Chrome Enterprise ポリシーを配布する対象テナント（例: C012abcde）を指定します。",
          },
          {
            name: "デプロイヤー自動作成（Bootstrap）",
            behavior:
              "SA `secure-gateway-deployer` を作成し、76個の必要権限を含むカスタムロールをバインドした上で、ログイン中管理者に Token Creator 権限を付与します。",
          },
        ],
        apiCalls: [
          {
            method: "GET",
            endpoint: "https://iam.googleapis.com/v1/projects/{projectId}/serviceAccounts/{saEmail}",
            purpose: "デプロイヤー用サービスアカウントが既に存在するか確認します。",
          },
          {
            method: "POST",
            endpoint: "https://iam.googleapis.com/v1/projects/{projectId}/serviceAccounts",
            purpose: "キーレスデプロイヤー専用サービスアカウントを新規作成します。",
          },
          {
            method: "PATCH",
            endpoint: "https://iam.googleapis.com/v1/projects/{projectId}/roles/{roleId}",
            purpose: "最小権限のカスタムロール（secureGatewayPocDeployer）を作成・更新します。",
          },
          {
            method: "POST",
            endpoint: "https://cloudresourcemanager.googleapis.com/v1/projects/{projectId}:setIamPolicy",
            purpose: "プロジェクトレベルでカスタムロール、roles/browser、roles/serviceusage.serviceUsageConsumer をバインドします。",
          },
          {
            method: "POST",
            endpoint: "https://iam.googleapis.com/v1/projects/{projectId}/serviceAccounts/{saEmail}:setIamPolicy",
            purpose: "サービスアカウントに対して、管理者に roles/iam.serviceAccountTokenCreator を付与します。",
          },
          {
            method: "POST",
            endpoint: "https://chromepolicy.googleapis.com/v1/customers/{customerId}/policies/orgunits:batchGet",
            purpose: "Chrome Enterprise Policy 管理への読み取りアクセスを検証します。",
          },
        ],
        safetyNote: "サービスアカウントの秘密鍵ファイル（JSON）はディスクやブラウザストレージに一切生成・保存されません。",
      },
      {
        title: "環境",
        subtitle: "データプレーン設計とプライベートルーティングの定義",
        summary:
          "ターゲット VPC、リージョン、プライベートホスト名、および 3 つのアーキテクチャパスのいずれかを構成します。",
        actions: [
          "Option A（直接 HTTPS）、Option B（ILB オフロード）、Option C（Nginx オフロード）から選択します。",
          "アプリのプライベートホスト名、ポート、および Upstream VPC ネットワークを指定します。",
          "Option B の場合、Google 管理 Envoy プロキシ用の Proxy-Only サブネット CIDR を設定します。",
        ],
        optionsBehavior: [
          {
            name: "Option A（Direct HTTPS）",
            behavior:
              "既存の HTTPS アプリへ直接 Secure Gateway をルーティングします。Nginx や ILB は作成しません。",
          },
          {
            name: "Option B（ILB HTTPS Offload）",
            behavior:
              "Regional Internal Application Load Balancer と Envoy Proxy サブネットを自動作成し、TLS 終端して HTTP バックエンドへ転送します。",
          },
          {
            name: "Option C（Legacy Nginx）",
            behavior:
              "専用の Nginx VM または MIG を VPC 内にデプロイし、リバースプロキシとして HTTPS 終端と HTTP 転送を行います。",
          },
        ],
        apiCalls: [
          {
            method: "POST",
            endpoint: "https://beyondcorp.googleapis.com/v1/projects/{projectId}/locations/global/securityGateways",
            purpose: "Secure Gateway リソースを作成・プロビジョニングします。",
          },
          {
            method: "POST",
            endpoint: "https://beyondcorp.googleapis.com/v1/projects/{projectId}/locations/global/securityGateways/{gw}/applications",
            purpose: "ホスト名:ポートのマッチャーと VPC ルートを持つプライベートアプリケーションを登録します。",
          },
          {
            method: "POST",
            endpoint: "https://compute.googleapis.com/v1/projects/{projectId}/global/firewalls",
            purpose: "送信元 136.124.16.0/20（Gateway IP 範囲）からの TCP 通信を許可する Ingress ルールを作成します。",
          },
          {
            method: "POST",
            endpoint: "https://dns.googleapis.com/dns/v1/projects/{projectId}/managedZones",
            purpose: "対象 VPC ネットワークに紐づく Cloud DNS 限定公開ゾーンを作成します。",
          },
          {
            method: "POST",
            endpoint: "https://compute.googleapis.com/v1/projects/{projectId}/regions/{region}/subnetworks",
            purpose: "Option B 用に Google 管理 Envoy プロキシ専用の REGIONAL_MANAGED_PROXY サブネットを作成します。",
          },
          {
            method: "POST",
            endpoint: "https://compute.googleapis.com/v1/projects/{projectId}/regions/{region}/forwardingRules",
            purpose: "ILB オフロード用の内部 HTTPS フォワーディングルールを作成します。",
          },
        ],
        safetyNote: "リージョン ILB をクロスリージョンで利用する場合は、Frontend の Global Access 有効化が必須です。",
      },
      {
        title: "証明書",
        subtitle: "TLS 所有権と Chrome Root Store への信頼伝播",
        summary:
          "証明書の発行元を定義し、Secret Manager で秘密鍵を隔離保管した上で、Chrome Root Store コネクタによる信頼配布を準備します。",
        actions: [
          "Enterprise CA Service、既存 Secret、またはブラウザ自動生成の Local PoC CA を指定します。",
          "TLS 秘密鍵を Secret Manager に暗号化保管し、最小権限のアクセス権を設定します。",
          "生成されたパブリック Root PEM をダウンロードし、Google 管理コンソールの Chrome Root Store に登録します。",
        ],
        optionsBehavior: [
          {
            name: "Enterprise CA Service",
            behavior:
              "Google Cloud CA Service の既存 CA プールおよび認証局からサーバー証明書を発行します。",
          },
          {
            name: "Public Secret",
            behavior:
              "Secret Manager に事前に格納・検証されたパブリック信頼サーバー証明書を参照します。",
          },
          {
            name: "Local PoC CA",
            behavior:
              "ブラウザの WebCrypto API を使用して ECDSA P-256 自己署名 Root CA を一時生成し、サーバー証明書に署名します。",
          },
        ],
        apiCalls: [
          {
            method: "POST",
            endpoint: "https://secretmanager.googleapis.com/v1/projects/{projectId}/secrets",
            purpose: "TLS 証明書および秘密鍵を格納する暗号化シークレットコンテナを作成します。",
          },
          {
            method: "POST",
            endpoint: "https://secretmanager.googleapis.com/v1/projects/{projectId}/secrets/{secretId}/versions:add",
            purpose: "証明書・鍵のバージョンを追加し、専用サービスアカウントへのアクセス権限を自動設定します。",
          },
        ],
        safetyNote: "Root CA の秘密鍵は外部に一切出力されず、ダウンロードされるファイルは公開 Root PEM のみです。",
      },
      {
        title: "アクセス",
        subtitle: "ゼロトラスト認可と Chrome ポリシーの配信",
        summary:
          "コンテキストに応じたアクセスレベル（Context-Aware Access）を適用し、テスト OU の管理対象ブラウザにポリシーを強制配信します。",
        actions: [
          "Google Workspace Directory API から対象の組織部門（OU）を選択します。",
          "BeyondCorp のデバイス・プロファイル状態を検証するアクセスレベルを紐付けます。",
          "テスト対象のユーザー、グループ、またはドメインに Secure Gateway アプリケーション利用権限を付与します。",
        ],
        optionsBehavior: [
          {
            name: "対象組織部門（OU）",
            behavior:
              "Chrome Enterprise ポリシーの適用範囲を限定し、テスト OU 配下のブラウザだけに Gateway 設定を配信します。",
          },
          {
            name: "Managed Chrome Access Level",
            behavior:
              "Endpoint Verification 等のゼロトラストポスチャ条件を満たす端末・プロファイルのみ通信を許可します。",
          },
          {
            name: "プリンシパル（ユーザー / グループ / ドメイン）",
            behavior:
              "IAM において `roles/beyondcorp.sgApplicationUser` ロールを対象 ID にバインドします。",
          },
        ],
        apiCalls: [
          {
            method: "GET",
            endpoint: "https://admin.googleapis.com/admin/directory/v1/customer/{customerId}/orgunits",
            purpose: "Google Workspace から組織部門（OU）の階層ツリーを取得します。",
          },
          {
            method: "GET",
            endpoint: "https://accesscontextmanager.googleapis.com/v1/accessPolicies/{policyId}/accessLevels",
            purpose: "利用可能な Context-Aware Access レベルの一覧を取得します。",
          },
          {
            method: "POST",
            endpoint: "https://chromepolicy.googleapis.com/v1/customers/{customerId}/policies/orgunits:batchModify",
            purpose: "Secure Enterprise Browser / Endpoint Verification 拡張機能の強制インストールと Gateway ルーティングを設定します。",
          },
          {
            method: "POST",
            endpoint: "https://beyondcorp.googleapis.com/v1/projects/{projectId}/locations/global/securityGateways/{gw}/applications/{app}:setIamPolicy",
            purpose: "アプリ利用権限とアクセスレベル条件をテスト対象プリンシパルにバインドします。",
          },
        ],
        safetyNote: "親 OU から継承されたレガシー PAC ポリシーが存在する場合、対象テスト OU だけを安全にバイパス上書きします。",
      },
      {
        title: "確認",
        subtitle: "決定論的事前ディスカバリーと暗号的承認",
        summary:
          "既存リソースの非破壊スキャンを実行し、12個の安全ゲート（Safety Gates）を評価した上で、構成ハッシュに紐づく承認を行います。",
        actions: [
          "Google Cloud / Workspace のリソースを読み取り専用スキャンし、望ましい状態との差分プランを作成します。",
          "課金、ライセンス、API、CIDR 重複、IAM 権限などの安全ゲートを Pass / Planned / Blocked で評価します。",
          "設定ハッシュ（SHA-256）に暗号的に拘束される人手承認を実施します。",
        ],
        optionsBehavior: [
          {
            name: "事前確認ディスカバリー",
            behavior:
              "変更を加えることなく全 API をプローブし、既存インフラとの互換性や競合を事前検出します。",
          },
          {
            name: "安全ゲート（Safety Gates）",
            behavior:
              "前提条件（Billing, CEP License, Private DNS, Firewall 等）が満たされているか自動判定します。",
          },
          {
            name: "SHA-256 承認バインディング",
            behavior:
              "プラン全体の正規化ハッシュを算出して承認を記録します。設定が1文字でも変更されると承認は即時失効します。",
          },
        ],
        apiCalls: [
          {
            method: "GET",
            endpoint: "https://serviceusage.googleapis.com/v1/projects/{projectId}/services",
            purpose: "有効化されている Google Cloud API を監査します。",
          },
          {
            method: "POST",
            endpoint: "https://iam.googleapis.com/v1/projects/{projectId}:testIamPermissions",
            purpose: "計画された変更を実行するために必要なすべての IAM 権限を呼び出し元 SA が持っているか検証します。",
          },
        ],
        safetyNote: "ブロック判定（Action Required）の安全ゲートが残っている間は承認操作ができません。",
      },
      {
        title: "適用",
        subtitle: "依存順オーケストレーション、逆順ロールバック、受入検証",
        summary:
          "承認済みオペレーションをトポロジカル依存順に実行し、所有権を追跡しながら T01〜T09 受入テストを実施します。",
        actions: [
          "サブネット ➡️ 証明書 ➡️ ILB/VM ➡️ Gateway ➡️ DNS ➡️ Chrome ポリシーの順に依存関係に従って作成します。",
          "作成したリソースの所有権（Ownership）を記録し、異常発生時は作成済みリソースのみを逆順ロールバックします。",
          "受入テストスイート（T01〜T09）を実施し、暗号的に監査可能な受入証跡 JSON をエクスポートします。",
        ],
        optionsBehavior: [
          {
            name: "依存関係順のデプロイ実行",
            behavior:
              "下位インフラ（VPC, Subnet, Secret）が確実に準備完了してから上位サービス（LB, Gateway, Route）をバインドします。",
          },
          {
            name: "所有範囲限定の自動ロールバック",
            behavior:
              "途中で失敗した場合、既存の共有リソースを傷つけることなく、本デプロイで作成したリソースのみを正確に逆順削除します。",
          },
          {
            name: "T01〜T09 受入テストと証跡出力",
            behavior:
              "エンドツーエンドの HTTPS 通信、DNS 解決、Root CA 信頼、およびゼロトラスト拒否ケースを検証・記録します。",
          },
        ],
        apiCalls: [
          {
            method: "POST",
            endpoint: "https://logging.googleapis.com/v2/entries:write",
            purpose: "デプロイ操作の構造化監査ログエントリを記録します。",
          },
        ],
        safetyNote: "通信切断やブラウザ終了が発生した場合でも、中断検出機能により安全に再開またはロールバックが可能です。",
      },
    ],
    faqTitle: "よくある質問とトラブルシューティング (FAQ)",
    faqIntro:
      "実際の Secure Gateway 構築・検証現場で発生しやすいトラブルへの対処法、証明書信頼の仕組み、OAuth 配布設定、運用ベストプラクティスをまとめています。",
    faqs: [
      {
        id: "faq-503-unavailable",
        category: "ルーティング・データプレーン",
        question: "Chrome でプライベートアプリにアクセスすると「503 Service Unavailable」や接続エラーになる原因は？",
        answer:
          "BeyondCorp Security Gateway が Google Cloud VPC 内のバックエンド（10.10.0.2）に TCP/TLS 疎通できていない状態です。VM の起動状態、Cloud Router & NAT、ファイアウォール、および Cloud DNS A レコードを確認してください。",
        checklist: [
          "「デプロイ管理」タブの「GCP リソース完全診断（リアルタイム）」を実行し、全リソースが RUNNING / 存在するか確認する。",
          "ファイアウォールルール（allow-secgw-ingress-https）で 0.0.0.0/0 からの TCP 80/443 イングレスが許可されているか確認する。",
          "VPC（secgw-test-vpc）に Cloud Router と Cloud NAT が構成され、静的 IP が割り当てられているか確認する。",
          "Cloud DNS プライベートゾーンで secgw-backend.internal. が 10.10.0.2 に正しく登録されているか確認する。",
        ],
      },
      {
        id: "faq-cert-authority-invalid",
        category: "証明書・Root CA 信頼",
        question: "「net::ERR_CERT_AUTHORITY_INVALID」や「保護されていない通信」の警告が出る理由は？",
        answer:
          "バックエンド VM が提示する TLS サーバー証明書が、Chrome Root Store に登録された Root CA から署名されたものと一致していないか、以前の警告バイパス時のキャッシュ（USER_OVERRIDDEN フラグ）がブラウザセッションに残っていることが原因です。",
        checklist: [
          "「適用（Step 7）」またはデプロイ管理画面から最新の secure-gateway-private-https-poc-root.pem をダウンロードする。",
          "Google 管理コンソールで [デバイス] > [Chrome] > [証明書] > [Chrome Root Store] に PEM をアップロードする。",
          "chrome://policy を開き、「ポリシーを再読み込み」をクリックして同期する。",
          "シークレットウィンドウ（Ctrl+Shift+N）を開くか、Chrome を再起動（chrome://restart）してアクセスすると、警告が消えて緑色の南京錠マーク（🔒）になります。",
        ],
      },
      {
        id: "faq-oauth-external-mode",
        category: "OAuth・配布設定",
        question: "社外のテスターや複数ドメインのユーザーに拡張機能を配布する場合、OAuth 同意画面はどのように設定しますか？",
        answer:
          "社内（同一 Workspace ドメイン）のみであれば「内部 (Internal)」で利用できます。@gmail.com や別ドメインのテスターに Zip を配布する場合は「外部 (External)」に変更します。",
        checklist: [
          "Google Cloud Console の [APIとサービス] > [OAuth 同意画面] でユーザータイプを「外部 (External)」に変更する。",
          "「テスト中 (Testing)」モードの場合、「テストユーザー」にテスターの Google メールアドレスを追加（最大100人）すれば審査不要でログインできます。",
          "「本番環境 (Production)」に設定するとテストユーザー登録不要で誰でもログイン可能になります（Googleの未検証アプリ警告が表示された場合は「詳細」＞「○○（安全ではないページ）に移動」をクリックします）。",
        ],
      },
      {
        id: "faq-extension-id-mismatch",
        category: "OAuth・配布設定",
        question: "テスターの PC で「OAuth2 request failed: Bad Client ID」エラーが出るのを防ぐには？",
        answer:
          "Zip を解凍して読み込むフォルダパスによって Chrome 拡張機能 ID（32桁の英字）が変わるためです。GCP の OAuth クライアント ID で指定した「アイテム ID」とテスター側の拡張機能 ID を一致させる必要があります。",
        checklist: [
          "GCP の [認証情報] > [OAuth 2.0 クライアント ID] に設定されているアイテム ID と、chrome://extensions の ID が一致しているか確認する。",
          "本プロジェクトの配布用 dist.zip は固定公開鍵（key）を含むため、どの PC で解凍しても全世界同一の拡張機能 ID に固定されます。",
        ],
      },
      {
        id: "faq-access-level-cel",
        category: "ゼロトラスト・アクセス制御",
        question: "Access Context Manager（CEL 式）で「管理対象 Chrome のみ」にアクセス制限する仕組みは？",
        answer:
          "BeyondCorp Application の IAM ポリシー（roles/beyondcorp.sgApplicationUser）に CEL 条件式（device.is_managed_device == true など）をバインドすることで、未管理ブラウザや私用端末からの通信を Google のエッジで自動遮断します。",
        checklist: [
          "デプロイ管理画面の「アクセス制御・アクセスレベル設定」から適用するアクセスレベルを即時更新できます。",
          "許可するプリンシパル（ユーザー、グループ、ドメイン全体）を柔軟に切り替え可能です。",
          "変更内容はすべて暗号化監査チェーンに記録されます。",
        ],
      },
      {
        id: "faq-teardown-clean-state",
        category: "運用・クリーンアップ",
        question: "PoC 検証終了後、作成されたリソースを完全に一括削除するにはどうすればよいですか？",
        answer:
          "デプロイ管理画面の「削除」タブから、用途に合わせて「所有リソースの削除 (Teardown)」または「全インフラ・SGWを完全クリーン削除 (Clean State All)」を実行します。",
        checklist: [
          "Teardown: このデプロイで作成された BeyondCorp Gateway / Application のみを依存関係の逆順で安全に削除します。",
          "Clean State All: Gateway、Application、サンプル VM、Cloud DNS、VPC、NAT、ファイアウォール、ローカル IndexedDB を一括削除し、ステータスを「削除完了 (Deleted)」に更新します。",
        ],
      },
    ],
  },
  cepDeployer: {
    title: "Chrome Enterprise Premium PoC デプロイヤー",
    subtitle: "CEP の評価用ベースラインを 1 つの組織部門に適用し、評価後は元に戻します。",
    intro:
      "脅威対策・コンテンツ検査・データ境界の Chrome ポリシーをパイロット OU に書き込み、運用に必要な最小権限 IAM ロールを作成します。評価が終われば親 OU の設定へ一括で戻せます。各ポリシーは書き込み前に、お使いのテナントの Chrome Policy スキーマと照合されます。",
    targetOuCardTitle: "1. 対象の組織部門（OU）",
    targetOuCardSubtitle:
      "隔離されたパイロット OU を選んでください。ポリシーはここにのみ適用され、本番ユーザーには影響しません。",
    selectTargetOu: "対象の組織部門",
    ouLoadFailed:
      "組織部門を取得できませんでした。セットアップ画面で Google Workspace の接続を確認してから、このタブを開き直してください。",
    autoCreateSubOus: "サブ OU「CEP Users」「CEP Browsers」を作成する",
    autoCreateSubOusHint:
      "ユーザー向けポリシーは前者に、ブラウザ向けポリシーは後者に適用されます。同名のサブ OU が既にあれば再利用します。オフの場合はすべて上で選択した OU に適用されます。",
    presetsTitle: "2. プリセット",
    presetsSubtitle: "代表的な評価パターンの出発点です。適用前に下のモジュールで調整できます。",
    presetFullPoc: "フル評価",
    presetFullPocDesc:
      "全モジュール。脅威対策、コンテンツ検査、レポート、端末シグナル、コピー＆ペースト境界を含みます。",
    presetAiProtection: "生成 AI とデータ漏えい対策",
    presetAiProtectionDesc:
      "外部 AI ツールへの入力を想定した貼り付け・アップロード検査と、非社用アカウントの遮断に絞ります。",
    presetEndpoint: "端末ハードニング",
    presetEndpointDesc:
      "強化セーフブラウジング、リアルタイム URL 検査、Endpoint Verification の強制、コンテキストアウェアアクセス。",
    presetAudit: "監査・可視化",
    presetAuditDesc: "レポートとセキュリティイベント送信のみ。何もブロックしません。",
    modulesTitle: "3. ポリシーモジュール",
    modulesSubtitle:
      "モジュールごとに別のバッチで適用するため、非対応のポリシーが 1 つあっても他を巻き込みません。",
    moduleCorePolicies: "Chrome コアセキュリティポリシー",
    moduleCorePoliciesDesc:
      "強化セーフブラウジング、社用パスワードの使い回し警告、Chrome のクラウドレポートとプロファイルレポート。",
    moduleForceExtensions: "Endpoint Verification の強制インストール",
    moduleForceExtensionsDesc:
      "Google 公式の Endpoint Verification 拡張機能を配布し、端末の状態シグナルをコンテキストアウェアアクセスに渡します。",
    moduleConnectors: "コンテンツ検査コネクタ",
    moduleConnectorsDesc:
      "リアルタイム URL 検査、ファイルのアップロード／ダウンロード検査、Google へのセキュリティイベント送信。",
    accessLevelTitle: "コンテキストアウェアアクセス レベル",
    accessLevelHint:
      "選択したレベルを満たさないセッションからのファイルアップロードを遮断します。組織で既に使用しているレベルを選ぶか、管理対象 Chrome 用のレベルを新規作成できます。",
    accessLevelNone: "なし",
    accessLevelNoneDesc: "アクセスレベルによる制限を行いません。",
    accessLevelAutoProfile: "新規作成: 管理対象 Chrome プロファイル",
    accessLevelAutoBrowser: "新規作成: 管理対象 Chrome ブラウザ",
    accessLevelAutoAny: "新規作成: 管理対象のプロファイルまたはブラウザ",
    accessLevelExistingGroup: "既存のアクセスレベル",
    accessLevelLoadFailed:
      "既存のアクセスレベルを取得できませんでした。作成するには、Access Context Manager ポリシーを持つ組織に属した Google Cloud プロジェクトが必要です。",
    moduleDlpDetectors: "社内サイト用の DLP 検出器",
    moduleDlpDetectorsDesc:
      "下に入力した社内サイトから再利用可能な URL リスト検出器を作成します。ルールがこれを参照し、自社サイトを対象外にします。",
    moduleDlpRules: "DLP ルール（サンプル一式）",
    moduleDlpRulesDesc:
      "カード番号を含むアップロードを遮断し、個人番号の貼り付けを警告し、社内ページに電子透かしを表示してスクリーンショットを禁止します。",
    betaBadge: "ベータ",
    dlpBetaNote:
      "DLP ルールと検出器の作成には Cloud Identity ポリシー API を使います。変更系メソッドはまだベータ版です。呼び出しが拒否された場合は理由付きでスキップとして報告され、他のモジュールは通常どおり適用されます。",
    dlpRegionTitle: "検出対象とする個人番号の国・地域",
    dlpRegionHint:
      "個人番号ルールが使用する Cloud DLP 検出器を切り替えます。国が合っていない検出器は何も検知しないため、動作しているルールと見分けがつきません。",
    dlpRulesTableTitle: "ルールごとの動作",
    dlpRulesTableHint:
      "「監査のみ」は利用者を妨げずにイベントだけを記録します。まずはここから始め、検知量を把握してから警告・ブロックへ強めるのが一般的です。",
    dlpActionOff: "作成しない",
    dlpActionAudit: "監査のみ",
    dlpActionWarn: "警告して許可",
    dlpActionBlock: "ブロック",
    dlpRuleNationalId: "ページへの個人番号の貼り付け",
    dlpRulePaymentCard: "アップロードに含まれるカード番号",
    dlpRuleAccessLevel: "管理対象外 Chrome からのアップロード",
    dlpRuleWatermark: "社内ページへの電子透かし",
    dataBoundaryModeTitle: "データ境界",
    dataBoundaryModeCopyPaste: "貼り付け内容を検査する",
    dataBoundaryModeCopyPasteDesc:
      "ページに貼り付けられたテキストを検査し、追加ログインを主要ドメインのアカウントに制限します。",
    dataBoundaryModeBlockNonCorp: "非社用の Google アカウントを遮断する",
    dataBoundaryModeBlockNonCorpDesc:
      "Google アプリで主要ドメインのアカウントのみを許可し、個人 Gmail タブ経由の持ち出し経路を塞ぎます。",
    dataBoundaryModeNone: "なし",
    dataBoundaryModeNoneDesc:
      "クリップボードとアカウントの挙動は親 OU の設定を継承したままにします。",
    internalUrlsTitle: "社内サイト（1 行に 1 件）",
    internalUrlsPlaceholder: "https://intranet.example.com\nhttps://wiki.corp.example.com",
    internalUrlsHint:
      "コンテンツ検査の対象から除外します。社内イントラがアップロードや貼り付けのたびに検査されるのを防ぎます。",
    rolesCardTitle: "4. 最小権限の IAM ロール",
    rolesCardSubtitle:
      "評価の実施者と確認者のためのカスタムロールです。プロジェクト オーナー権限は不要になります。",
    roleAdminLabel: "CEP Policy Administrator",
    roleAdminDesc: "Chrome ポリシーと Access Context Manager レベルの参照・変更ができます。",
    roleAuditorLabel: "CEP Security Auditor",
    roleAuditorDesc:
      "読み取り専用。ポリシーの状態とセキュリティログを参照でき、変更はできません。",
    assignUserEmailLabel: "ロールを付与する相手（任意）",
    assignUserEmailPlaceholder: "security-auditor@example.com",
    provisionRolesButton: "IAM ロールを作成",
    provisioningRoles: "IAM ロールを作成中...",
    rolesProjectRequired:
      "IAM ロールの作成には Google Cloud プロジェクトが必要です。先にセットアップ画面で設定してください。",
    testingScenariosTitle: "5. 結果を確認する",
    testingScenariosSubtitle:
      "検出器に反応するサンプル値です。実データを使わずに検知の様子を実演できます。",
    copyDummyData: "コピー",
    copiedToClipboard: "コピーしました",
    dummyPiiLabel: "サンプルの個人番号",
    dummyPiiValue: "1234-5678-9012",
    dummyPiiHint: "マイナンバー／SSN の書式に合わせたダミー値です。実在の番号ではありません。",
    dummyCreditCardLabel: "サンプルのカード番号",
    dummyCreditCardValue: "4532015112830366",
    dummyCreditCardHint: "Luhn チェックを通る Visa のテスト番号です。実在のカードではありません。",
    dummySourceCodeLabel: "サンプルの API キー入りソースコード",
    dummySourceCodeValue:
      "const GCP_SECRET_KEY = 'AIzaSyA_DEMO_CONFIDENTIAL_KEY_FOR_TESTING';",
    dummySourceCodeHint: "Google API キーの形式に似せた文字列です。実際には使えません。",
    scenarioGenAiTitle: "貼り付け検査",
    scenarioGenAiStep:
      "外部の AI ツールを開き、上のサンプル API キーを貼り付けます。貼り付け検査が有効なら、判定が返るまで Chrome が貼り付けを保留します。",
    scenarioDataBoundaryTitle: "データ境界",
    scenarioDataBoundaryStep:
      "管理対象プロファイルで個人の Google アカウントにログインします。非社用アカウントの遮断が有効なら、ログインが拒否されます。",
    scenarioWatermarkTitle: "アップロード検査",
    scenarioWatermarkStep:
      "サンプルのカード番号を含むファイルを、社内サイト一覧に無いサイトへアップロードします。検査のため保留され、イベントがセキュリティ調査ツールに届きます。",
    manualChecklistTitle: "このツールでは実施できない設定",
    manualChecklistSubtitle:
      "Google が API を公開していない項目です。上のテストを実施する前に管理コンソールで設定してください。",
    manualChecklistItems: [
      {
        title: "機密コンテンツの保存を有効化",
        detail: "セキュリティ › アクセスとデータ管理 › データ保護。",
        href: "https://admin.google.com/ac/dp",
      },
      {
        title: "光学文字認識（OCR）を有効化",
        detail: "画像内のテキストを検出器が読むために必要です。",
        href: "https://admin.google.com/ac/dp",
      },
      {
        title: "CEP ライセンスの自動割り当てを有効化",
        detail: "お支払い › ライセンス設定で、パイロット OU に対して設定します。",
        href: "https://admin.google.com/ac/billing/licensesettings",
      },
    ],
    btnDeploy: "対象 OU に適用",
    btnDeploying: "適用中...",
    btnRollback: "親 OU の設定に戻す",
    btnRollingBack: "復元中...",
    btnDownloadScript: "Python スクリプトとして出力",
    confirmRollback:
      "この OU の CEP ポリシーをすべて親 OU の設定に戻し、このツールが作成したコンテキストアウェアアクセス レベルを削除します。続行しますか？",
    downloadFailed: "スクリプトを生成できませんでした",
    noModulesSelected: "ポリシーモジュールを 1 つ以上選択してください。",
    appliedTitle: "適用した設定",
    skippedTitle: "スキップした設定",
    statusLogTitle: "実行トレース",
    noActionYet: "まだ実行していません。対象 OU とモジュールを選び、適用してください。",

    licenseCardTitle: "ライセンス管理と自動割り当て制御",
    licenseCardSubtitle:
      "全社への意図しないライセンス消費を防ぎ、対象 OU のユーザーにのみ CEP ライセンスを直接割り当てます。",
    licenseAutoAssignWarning:
      "最上位組織（ドメイン全体）で自動割り当てが有効な場合、意図しない一般ユーザーに CEP ライセンスが自動消費されてしまいます。",
    licenseAutoAssignWarningLink: "Google 管理コンソールのライセンス設定を開く",
    licenseAutoAssignSteps: [
      "1. Google 管理コンソールの「お支払い › ライセンス設定」を開き、最上位組織（ルート OU）を選択します。",
      "2. Chrome Enterprise Premium の自動割り当てを「オフ」に変更します。",
      "3. このパイロット OU のみ自動割り当てを「オン」にするか、または下のボタンから対象ユーザーへ直接一括割り当てを行います。",
    ],
    btnAssignLicensesToOu: "選択した組織（OU）の全ユーザーに CEP ライセンスを一括割り当て",
    btnAssigningLicenses: "OU 内のユーザーへライセンスを割り当て中...",
    licenseAssignUsersFound: "OU 内のユーザーを処理しました",
    noUsersFoundInOu: "選択された組織部門内にユーザーは見つかりませんでした。",

    dlpMatrixTitle: "DLP コントロール マトリクス",
    dlpMatrixSubtitle:
      "各操作（アップロード・ダウンロード・貼り付け・印刷・画面透かし）と端末条件（全端末 vs BYOD/未管理端末）ごとに、動作（ブロック・警告・監査・オフ）を一目で直感的に設定できます。",
    dlpColThreat: "データ・脅威種別",
    dlpColUpload: "アップロード",
    dlpColDownload: "ダウンロード",
    dlpColPaste: "貼り付け",
    dlpColPrint: "印刷",
    dlpColWatermark: "画面透かし",
    dlpColDeviceScope: "対象端末スコープ",

    dlpRowUniversalUpload: "すべてのファイルアップロード",
    dlpRowUniversalUploadDesc: "Chrome からのあらゆるファイルアップロードを検査・制御します。",
    dlpRowUniversalDownload: "すべてのファイルダウンロード",
    dlpRowUniversalDownloadDesc: "Chrome でのファイルダウンロードを検査・不正ダウンロードを防止します。",
    dlpRowPaymentCard: "クレジットカード・金融情報",
    dlpRowPaymentCardDesc: "アップロード、貼り付け、印刷時のカード番号漏洩を検知・制御します。",
    dlpRowNationalId: "マイナンバー・個人識別情報",
    dlpRowNationalIdDesc: "各国の個人番号（マイナンバー／SSN等）の外部送信を検知・制御します。",
    dlpRowAccessLevel: "未管理端末・BYODからの操作",
    dlpRowAccessLevelDesc: "コンテキストアウェア非準拠端末や BYOD からの操作を制限します。",
    dlpRowWatermark: "社内機密サイト保護・透かし",
    dlpRowWatermarkDesc: "登録した社内サイト上で動的透かしを表示し、画面キャプチャを禁止します。",
    dlpRowGenAiBlock: "未承認の生成AI利用ブロック（Geminiのみ許可）",
    dlpRowGenAiBlockDesc: "ChatGPT・Claude・DeepSeek 等をブロックし、承認済み Gemini のみ安全に許可します。",

    dlpScopeAll: "全端末",
    dlpScopeByodOnly: "BYODのみ",
    dlpActionBadgeBlock: "ブロック",
    dlpActionBadgeWarn: "警告",
    dlpActionBadgeAudit: "監査のみ",
    dlpActionBadgeOff: "オフ",

    dlpPresetRecommended: "推奨PoC設定",
    dlpPresetRecommendedDesc: "機密データは監査、BYODは警告/ブロック、未承認AIは遮断、社内サイトは透かし保護します。",
    dlpPresetStrictZeroTrust: "厳格なゼロトラスト",
    dlpPresetStrictZeroTrustDesc: "機密データの外部送信や未管理端末からの操作を完全にブロックします。",
    dlpPresetGenAiSecure: "生成AIセキュア活用",
    dlpPresetGenAiSecureDesc: "ChatGPT等の個人向けAIを遮断し、Geminiの業務利用を安全に保護します。",
    dlpPresetAuditOnly: "監査ファースト",
    dlpPresetAuditOnlyDesc: "ユーザー業務を中断させず、全操作のログ記録・可視化を先行して開始します。",
  },
};

export function getMessages(locale: Locale): Messages {
  return locale === "ja" ? ja : en;
}

