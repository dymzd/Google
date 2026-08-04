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
  connectionNotice: string;
  bootstrapDeployer: string;
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
  directHttpsConnectivity: string;
  directHttpsConnectivityHint: string;
  hostname: string;
  noExternalIpNotice: string;
  certificateStepTitle: string;
  certificateIntro: string;
  caPool: string;
  caName: string;
  secretName: string;
  certificateNotice: string;
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
  t07DiagnosticsTitle: string;
  t07DiagnosticsIntro: string;
  t07Diagnostics: readonly {
    symptom: string;
    meaning: string;
    actions: readonly string[];
  }[];
}

export interface GuideMessages {
  eyebrow: string;
  title: string;
  intro: string;
  pocNoticeTitle: string;
  pocNoticeBody: string;
  architectureTitle: string;
  architectureIntro: string;
  architectures: readonly {
    eyebrow: string;
    title: string;
    summary: string;
    nodes: readonly { label: string; detail: string }[];
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
  steps: readonly {
    title: string;
    summary: string;
    actions: readonly string[];
  }[];
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
  workflow: WorkflowMessages;
  operations: OperationsMessages;
  guide: GuideMessages;
}

const en: Messages = {
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
    connectionNotice:
      "Connection validation is read-only. Apply permissions are checked separately during preflight.",
    bootstrapDeployer: "Create deployer and least-privilege role",
    bootstrapConfirm:
      "Create or update the deployer service account, custom role, project bindings, and your Token Creator binding?",
    bootstrapWorking: "Creating deployer…",
    bootstrapComplete: "Deployer bootstrap completed",
    bootstrapNext:
      "Run the command below once, restart this local app, then validate both connections. The Chrome admin role must still be assigned directly in Google Admin console.",
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
    network: "Network",
    vpcName: "Existing VPC name",
    subnetName: "Existing subnet name",
    managedSample: "Managed sample backend",
    managedSampleDescription:
      "Create a private HTTP backend for validation and evidence collection.",
    existingBackend: "Existing HTTP backend",
    existingBackendDescription:
      "Route to an administrator-managed private HTTP endpoint over connectivity that already exists.",
    directHttps: "Direct private HTTPS app",
    directHttpsDescription:
      "Connect Secure Gateway directly to an existing HTTPS endpoint through its VPC. No Nginx, VM, NAT, or offload certificate is created.",
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
    caPool: "CA pool resource",
    caName: "Issuing CA resource",
    secretName: "Secret Manager certificate secret",
    certificateNotice:
      "Local CA is PoC-only. After Apply, download the public PEM root, add it at Chrome > Connectors > Chrome Root Store, and connect that configuration to the dedicated test OU. Public APIs cannot reliably inspect or perform this handoff; verify trust with T07. Production still requires enterprise-pretrusted PKI or a publicly trusted certificate.",
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
      })[kind] ?? kind,
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
    architectureTitle: "Two independent deployment architectures",
    architectureIntro:
      "Choose one path per application. The direct HTTPS path does not pass through or deploy Nginx.",
    architectures: [
      {
        eyebrow: "Option A · HTTP offload",
        title: "Secure Gateway + Nginx + HTTP app",
        summary:
          "Use when the private application only speaks HTTP. PoC uses one private Nginx VM; the implemented scale-ready path adds a regional internal load balancer and two-zone managed instance group (Production selection is currently disabled).",
        nodes: [
          { label: "Managed Chrome", detail: "User identity + device/profile context" },
          { label: "Secure Gateway", detail: "Service Discovery + access policy" },
          { label: "Nginx offload tier", detail: "PoC: 1 private VM · Scale-ready: regional ILB + 2-zone MIG" },
          { label: "HTTP app", detail: "GCP, AWS, Azure, or on premises" },
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
      {
        eyebrow: "Option B · Native HTTPS",
        title: "Secure Gateway + private HTTPS app",
        summary:
          "Use when the application already serves HTTPS. Secure Gateway routes directly through the selected VPC; no Nginx, VM, NAT, or offload certificate is created.",
        nodes: [
          { label: "Managed Chrome", detail: "User identity + device/profile context" },
          { label: "Secure Gateway", detail: "Hostname:port matcher + access policy" },
          { label: "Upstream VPC", detail: "Delegating service account has upstreamAccess" },
          { label: "HTTPS app", detail: "Existing certificate and TLS termination" },
        ],
        supports: [
          { label: "DNS resolution", detail: "Cloud DNS private zone or forwarding zone" },
          { label: "Network policy", detail: "Allow TCP from 136.124.16.0/20 and return route" },
          { label: "Regional routing", detail: "Optional egress region, or Global Access for regional LB" },
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
          "Direct HTTPS creates an exact hostname:port Secure Gateway application route through an existing VPC and omits Nginx, offload TLS, NAT, and managed A records.",
          "Dedicated-VPC and existing-VPC strategies, private-only VM addressing, Cloud NAT for created HTTP-offload VMs, private DNS, and the 136.124.16.0/20 gateway firewall source are modeled.",
          "Off-GCP connectivity is consumed, not created: VPN/Interconnect, private DNS forwarding, backend firewall, and return routes remain explicit prerequisites.",
        ],
      },
      {
        eyebrow: "Scale-ready HTTP tier",
        title: "Regional Nginx availability and autoscaling",
        items: [
          "A two-zone regional Nginx managed instance group, regional internal TCP load balancer, regional TLS health check, and health-check firewall are implemented for the scale-ready path.",
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
        summary:
          "Set the PoC boundary before collecting cloud details.",
        actions: [
          "Keep the deployment in rapid PoC mode and select every managed Chrome platform you will test.",
          "Choose a dedicated new VPC or an existing VPC, plus enterprise, public, or Admin-console-managed local CA trust.",
          "Use local CA only for a dedicated non-production test OU.",
        ],
      },
      {
        title: "Identities",
        summary:
          "Confirm that the local app can read both control planes without storing keys.",
        actions: [
          "Validate keyless Application Default Credentials that impersonate the deployer service account.",
          "Check read-only Google Cloud project access and Chrome Policy access for the Workspace customer.",
          "Keep connection checks separate from the stronger permissions required by Apply.",
        ],
      },
      {
        title: "Environment",
        summary:
          "Choose either Nginx HTTP offload or a separate direct private HTTPS deployment.",
        actions: [
          "Capture project, region, zone, deployment name, network, subnet, and private hostname.",
          "For HTTP, choose the managed sample or an existing private HTTP backend; Secure Gateway targets Nginx on HTTPS and Nginx forwards HTTP.",
          "For an existing HTTPS application, select Direct private HTTPS. The application hostname and port become the Secure Gateway matcher and Nginx resources are omitted.",
          "For AWS, Azure, or on-premises apps, first connect the selected GCP VPC with VPN/Interconnect and Cloud DNS forwarding. This PoC does not store third-party credentials or create that tunnel.",
          "HTTP offload validates Nginx-to-backend HTTP with T02. Direct HTTPS instead requires TCP from 136.124.16.0/20, a return route, and validates the exact Gateway hostname:port/VPC route with T05.",
          "Only HTTP offload creates a private Nginx VM, Cloud NAT, offload certificate, and managed A record.",
        ],
      },
      {
        title: "Certificate",
        summary: "Define TLS ownership for the selected architecture.",
        actions: [
          "Nginx offload creates or references the certificate presented by Nginx.",
          "Direct HTTPS keeps TLS termination and the private key at the existing application; Secure Gateway does not copy them.",
          "Reference enterprise CA Service resources or a publicly trusted certificate secret.",
          "For a local-CA PoC, Apply generates a public PEM root certificate. The download never contains the private key.",
          "Complete the one-time manual step in Google Admin console: All browsers and devices > Chrome > Connectors > New provider configuration > Chrome Root Store.",
          "Enter a configuration name, add the downloaded PEM, set Type to Root, choose Add certificate, and then add the configuration.",
          "Select the dedicated test OU. Under Certificate connectors > Chrome Root Store, choose the new configuration and Save.",
          "Public APIs cannot reliably inspect the Root Store configuration, uploaded certificate, or OU binding. The platform-specific T07 HTTPS test is the proof that trust reached the endpoint.",
          "Restart Chrome and verify the root under chrome://certificate-manager > Local certificates before running T07.",
          "Keep private key material in Secret Manager instead of browser storage or startup scripts.",
        ],
      },
      {
        title: "Access",
        summary:
          "Limit Secure Gateway policy and application access to the intended test population.",
        actions: [
          "Set the Workspace customer and dedicated non-production OU.",
          "Add the smallest user, group, or domain principal set needed for the PoC.",
          "Confirm the test-OU boundary before policy changes can be planned.",
        ],
      },
      {
        title: "Review",
        summary:
          "Discover current state and produce the exact change set before approval.",
        actions: [
          "Run read-only API preflight checks for identities, services, permissions, and existing resources.",
          "Generate a deterministic, redacted desired-state plan with blocking safety gates.",
          "Bind human approval to the exact configuration hash so later edits invalidate it.",
        ],
      },
      {
        title: "Apply",
        summary:
          "Execute only the approved operations, then capture evidence for the PoC.",
        actions: [
          "Create or update resources in dependency order with ownership checkpoints.",
          "Stop on failure and roll back only resources created by this deployment.",
          "This PoC enables Secure Gateway Service Discovery and supplies the extension-managed configuration, so it does not create a PAC file. PAC routing is only for legacy gateways without Service Discovery.",
          "If preflight detects an inherited legacy PAC, Apply overrides proxy mode only in the selected test OU with Allow user to configure. The parent OU and PAC object remain unchanged, and rollback restores inheritance.",
          "For BYOD T07, the Chrome browser itself may remain unmanaged and Chrome Enterprise Companion is not required. Sign in to Chrome itself with the target organization's account so the work profile receives cloud user policies; signing into a Google website as a secondary account is not enough.",
          "After Endpoint Verification is force-installed, open it once, add the corporate account if prompted, and run Sync now before testing the Access Context Manager level.",
          "Record an audit hash chain and verify T01–T09, including managed-Chrome access and denial cases.",
        ],
      },
    ],
  },
};

const ja: Messages = {
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
  },
  title: "セキュア ゲートウェイの新規セットアップ",
  steps: ["モード", "ID", "環境", "証明書", "アクセス", "確認", "適用"],
  modeTitle: "1. Secure Gateway の迅速な PoC を開始",
  poc: "迅速なPoC",
  pocDescription:
    "明示的な安全ゲートと削除可能なリソースを使い、テストOUへ迅速に構築します。管理コンソール経由で管理対象ChromeへローカルCAを配布できます。",
  production: "本番",
  productionDescription:
    "エンタープライズPKI、リージョン高可用性、専用サービスID、最小権限、監査可能な変更管理は将来のリリース向けに保持しています。",
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
  testOuAvailable: "テストOU利用可能",
  deploymentGates: "デプロイゲート",
  noExternalIps: "外部IPなし",
  cloudNat: "Cloud NAT",
  upstreamVpc: "既存Upstream VPC",
  privateDnsRoute: "Private DNS・ファイアウォール・戻り経路",
  applicationOwnedTls: "HTTPSアプリ所有のTLS",
  apiPreflight: "API事前確認",
  approval: "承認",
  required: "必須",
  willValidate: "検証予定",
  gateNote: "適用するには、すべてのゲートを通過する必要があります。",
  back: "戻る",
  continue: "ID設定へ進む",
  noChanges: "変更はまだ適用されていません",
  draftSaved: "下書きをローカル保存",
  lastSaved: "最終保存",
  justNow: "たった今",
  languages: { english: "English", japanese: "日本語" },
  workflow: {
    identitiesTitle: "管理者IDを接続",
    identitiesIntro:
      "専用サービスアカウントを偽装するキーレス Application Default Credentials を使用します。JSONキーは受け付けず、保存もしません。",
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
    connectionNotice:
      "接続検証は読み取り専用です。適用権限は事前確認で別途検証します。",
    bootstrapDeployer: "SAと最小権限ロールを自動作成",
    bootstrapConfirm:
      "デプロイヤーSA、カスタムロール、プロジェクトIAM、あなたのToken Creator権限を作成または更新します。続行しますか？",
    bootstrapWorking: "デプロイヤーを作成中…",
    bootstrapComplete: "デプロイヤーの自動準備が完了しました",
    bootstrapNext:
      "下のコマンドを一度実行してローカルアプリを再起動し、両方の接続を検証してください。Chrome管理者ロールだけはGoogle管理コンソールでSAへ直接割り当てる必要があります。",
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
    network: "ネットワーク",
    vpcName: "既存VPC名",
    subnetName: "既存サブネット名",
    managedSample: "管理対象サンプルバックエンド",
    managedSampleDescription:
      "検証とエビデンス収集用のプライベートHTTPバックエンドを作成します。",
    existingBackend: "既存HTTPバックエンド",
    existingBackendDescription:
      "既に確立済みのプライベート接続を使い、管理者が管理するHTTPエンドポイントへ転送します。",
    directHttps: "プライベートHTTPSアプリへ直接接続",
    directHttpsDescription:
      "Secure Gatewayから既存HTTPSエンドポイントへVPC経由で直接接続します。Nginx、VM、NAT、オフロード証明書は作成しません。",
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
      "このPoCはNginxを構成し、T02でアップストリームを検証します。AWS/Azure VPN、Cloud VPN、Interconnect、オンプレミス側ルートは作成しません。先にプライベート経路を確立し、公開エンドポイントや認証情報は入力しないでください。",
    directHttpsConnectivity:
      "選択したVPCでホスト名を解決でき、HTTPSアプリへの経路、136.124.16.0/20からのTCP許可、戻り経路が設定済みです",
    directHttpsConnectivityHint:
      "Secure GatewayはHTTPSアプリへ直接接続します。AWS・Azure・オンプレミスでは、先にCloud VPN/Interconnect、Cloud DNS転送ゾーン、ファイアウォール、136.124.16.0/20への明示的な戻り経路を設定します。",
    hostname: "プライベートアプリのホスト名",
    noExternalIpNotice:
      "VMの外部IPは常に無効です。Cloud NATで制御されたパッケージ取得経路を提供します。",
    certificateStepTitle: "TLS証明書ソースを設定",
    certificateIntro:
      "オフロードVMは実行時にSecret Managerから証明書を読み取ります。秘密鍵を起動スクリプトへ書き込みません。",
    caPool: "CAプールのリソース名",
    caName: "発行CAのリソース名",
    secretName: "Secret Managerの証明書シークレット",
    certificateNotice:
      "ローカルCAはPoC専用です。適用後に公開PEMルートをダウンロードし、[Chrome] > [コネクタ] > [Chrome Root Store] へ追加して、その構成を専用テストOUへ接続します。公開APIではこの引き渡しを確実に参照・実行できないため、T07で信頼を検証します。本番ではエンタープライズPKIまたは公開信頼済み証明書が必要です。",
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
    verified: "準備完了",
    plannedOnApply: "Applyで自動設定",
    manualCheck: "手動確認",
    actionRequired: "要対応",
    approvalPending: "承認待ち",
    pocDefault: "PoC設定",
    reviewGateLegend:
      "準備完了＝API検出、管理者確認、または構成上の安全条件で解決済み、Applyで自動設定＝承認後に作成・更新、手動確認＝APIでは確実に判定できない項目、要対応＝Applyを止める問題です。",
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
      "backend-connectivity": "管理対象サンプルはデプロイVPC内に作成します。既存バックエンドではプライベートルーティング、DNS、ファイアウォール許可を確認し、ApplyがNginxからT02で経路を検証します。このPoCはクロスクラウドVPNやInterconnectを作成しません。",
      "test-ou": "選択したOUが非本番テスト用であることを確認済みです。",
      "cloud-identity": "Google Cloudデプロイヤーを読み取り専用で検証済みです。",
      "workspace-identity": "Chrome権限付きサービスアカウントを読み取り専用で検証済みです。",
      "required-apis": "不足している許可済みAPIはApply中に自動で有効化します。",
      "apply-permissions": "計画した操作に必要な全権限がデプロイヤーにあるかAPIで確認します。",
      "resource-conflicts": "既存リソースが望ましい状態と互換性を持つか確認します。",
      "human-approval": "Apply前に、構成ハッシュへ紐付いたプランを管理者が承認します。",
    },
    managedProfileEvidence: (total, profileOnly, sync) =>
      `報告中プロファイル ${total} 件（プロファイル管理BYOD ${profileOnly} 件）。最終ポリシー同期: ${sync ?? "未報告"}。`,
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
    plannedChangesTitle: "承認対象の正確な変更",
    plannedChangesIntro:
      "作成・更新する項目だけを表示します。再利用または変更なしのリソースは更新しません。",
    changeAction: (action) =>
      ({ create: "作成・上書き", update: "更新" })[action] ?? action,
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
        ? "PACにないホスト名はDIRECTへ落ち、通常DNSでERR_NAME_NOT_RESOLVEDになります。Applyでは選択したテストOUだけを上書きし、親OUと既存PACファイルは変更しません。"
        : code === "chrome-extension-group-policy-conflict"
          ? "表示されたグループの［アプリと拡張機能］を確認し、空または不整合な管理対象設定を削除するか、テストOUと同じSecure Gateway設定にします。グループ変更は全メンバーへ影響するため、自動適用せずブロックします。"
        : fallback ?? "",
    approveWorking: "承認を紐付けています…",
    approvalReady: "正確なプランを承認済み",
    continueToApply: "適用へ進む",
    applyTitle: "チェックポイントとエビデンス付きで適用",
    applyIntro:
      "依存順に変更します。失敗時は停止し、このデプロイが所有するリソースだけをロールバック対象にします。",
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
      })[kind] ?? kind,
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
    payload: "サニタイズ済みPayload",
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
    acceptanceTitle: "受入認証",
    acceptanceIntro:
      "T01〜T05のシステム検証を実行し、管理対象Chromeのテスト結果とログ証跡を記録します。",
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
        T06: "直接HTTPS制御",
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
        ? "同じ管理対象仕事用プロファイルで既存のHTTPS Secure Gatewayコントロールアプリを開きます（元手順書では https://demo-server1.internal/）。証明書警告なしで開いた場合だけ合格として記録します。既存の制御アプリがない新規PoCでは、その理由を付けて［スキップ］を記録できます。本番では引き続き合格が必須です。"
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
    t07DiagnosticsTitle: "管理対象Chromeクライアント診断",
    t07DiagnosticsIntro:
      "T07を記録する前にブラウザの結果を選別します。症状から、ルーティング・認可・証明書信頼のどこが未完了か判断できます。",
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
        symptom: "認証局エラー",
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
    architectureTitle: "独立した2つのデプロイアーキテクチャ",
    architectureIntro:
      "アプリごとにどちらか一方を選択します。直接HTTPS方式はNginxを経由せず、Nginx自体もデプロイしません。",
    architectures: [
      {
        eyebrow: "オプションA · HTTPオフロード",
        title: "Secure Gateway + Nginx + HTTPアプリ",
        summary:
          "プライベートアプリがHTTPだけを提供する場合に使います。PoCはプライベートNginx VM 1台を使用し、実装済みのスケール対応方式ではリージョン内部LBと2ゾーンMIGを使用します（現在Production選択は無効）。",
        nodes: [
          { label: "管理対象Chrome", detail: "ユーザーID + 端末/プロファイル情報" },
          { label: "Secure Gateway", detail: "Service Discovery + アクセスポリシー" },
          { label: "Nginxオフロード層", detail: "PoC: 非公開VM 1台 · スケール対応: リージョンILB + 2ゾーンMIG" },
          { label: "HTTPアプリ", detail: "GCP・AWS・Azure・オンプレミス" },
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
      {
        eyebrow: "オプションB · ネイティブHTTPS",
        title: "Secure Gateway + プライベートHTTPSアプリ",
        summary:
          "アプリが既にHTTPSを提供する場合に使います。Secure Gatewayが選択VPC経由で直接ルーティングし、Nginx、VM、NAT、オフロード証明書は作成しません。",
        nodes: [
          { label: "管理対象Chrome", detail: "ユーザーID + 端末/プロファイル情報" },
          { label: "Secure Gateway", detail: "hostname:port matcher + アクセスポリシー" },
          { label: "Upstream VPC", detail: "委任SAにupstreamAccessを付与" },
          { label: "HTTPSアプリ", detail: "既存証明書でアプリ自身がTLS終端" },
        ],
        supports: [
          { label: "DNS解決", detail: "Cloud DNS限定公開ゾーンまたは転送ゾーン" },
          { label: "ネットワーク制御", detail: "136.124.16.0/20からTCP許可 + 戻り経路" },
          { label: "リージョン経路", detail: "任意egress region、またはregional LBのGlobal Access" },
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
          "直接HTTPSは既存VPC経由の正確なhostname:portルートを作り、Nginx、オフロードTLS、NAT、管理Aレコードを作成しません。",
          "専用/既存VPC、VM外部IPなし、作成VM用Cloud NAT、Private DNS、Secure Gateway送信元136.124.16.0/20のFWをモデル化しています。",
          "GCP外へのVPN/Interconnect、DNS転送、backend firewall、戻り経路は作成せず、明示的な事前条件として利用します。",
        ],
      },
      {
        eyebrow: "スケール対応HTTP層",
        title: "Regional Nginxの可用性とオートスケール",
        items: [
          "2ゾーンRegional Nginx MIG、リージョン内部TCP LB、リージョンTLSヘルスチェック、ヘルスチェック用FWをスケール対応方式に実装しています。",
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
          "ヘルパーが鍵なしデプロイヤーSA、最小権限カスタムロールとBindingを準備し、Applyが不足する許可済みAPIを有効化します。",
          "Secure Gateway、Service Discovery利用IAM、委任SAのupstreamAccess、application matcher、application IAM、任意Access Level条件をPlan/Applyします。",
          "テストOUへSecure Enterprise BrowserとEndpoint Verificationを強制インストールし、Gateway routeと継承PAC overrideを設定します。OU、Group、Access LevelはAPIから取得します。",
        ],
      },
      {
        eyebrow: "TLSとID",
        title: "証明書と管理対象Chromeアクセス",
        items: [
          "HTTPオフロードはEnterprise CA、検証済み公開証明書Secret、公開ルートPEMを出力するローカルPoC CAに対応します。",
          "秘密鍵は専用accessor identity付きSecret Managerに保持し、active version alias、更新期限確認、offload refresh、失敗時補償を実装しています。",
          "Chrome Root StoreへのアップロードとOU接続は、公開APIで確実に参照・変更できないためAdmin Consoleの手動引き渡しとして案内します。",
          "選択Access Context Managerレベルでプロファイル管理BYOD Chromeとブラウザ管理Chromeを表現でき、profile/client/Endpoint Verificationの報告状態を個別表示します。",
        ],
      },
      {
        eyebrow: "安全なApply",
        title: "検出、承認、進捗、ロールバック",
        items: [
          "信頼済みDiscoveryが望ましい状態との差分を作り、create/update/no-op/conflictを分類して互換性のない既存リソースを変更前に停止します。",
          "Billing、License、Workspace、テストOU、API、デプロイヤーID、権限、private connectivity、証明書、Chrome signalをAPI確認/自動/手動/ブロックに分類します。",
          "承認は正確な構成ハッシュに紐付き、有効期限・1回限り・編集時無効化を持ちます。ブラウザ入力の監査actorは拒否します。",
          "Applyは操作checkpointとビジュアル進捗を記録し、同時実行を1件に制限。中断を検出し、共有リソースとIAM/Chrome Policyの正確なbefore-imageを守りつつ所有変更だけを逆順に戻します。",
          "Deployタブでサニタイズ済みSecure Gateway/Nginxログ、Gateway logging有効化、所有/共有リソース一覧、正確な確認文付きの所有範囲限定逆順削除を提供します。",
        ],
      },
      {
        eyebrow: "検証とローカル保護",
        title: "Acceptance証跡とオペレーター保護",
        items: [
          "永続T01～T09記録でVM/runtime probe、正確なGoogle API route、各選択OSのHTTPS、request相関、必須negative testを扱い、証跡をJSON出力します。",
          "SHA-256監査チェーン、デプロイ履歴、サニタイズ済みログ、request ID、query/credential除去で秘密を残さず追跡性を確保します。",
          "アプリはloopback専用で、Host/Origin検査、起動ごとのnonce、CSP、no-store、0600 SQLiteを強制します。",
          "鍵なしADCのSA impersonationを必須とし、SA JSON鍵とAWS/Azure認証情報は受け付けません。ワークフローと設定UI全体は日本語/英語に対応します。",
        ],
      },
    ],
    stepLabel: (step) => `ステップ ${step}`,
    steps: [
      {
        title: "モード",
        summary: "クラウド情報を入力する前にPoCの境界を決めます。",
        actions: [
          "迅速なPoCモードを維持し、テストする管理対象Chromeプラットフォームをすべて選択します。",
          "専用の新規VPCまたは既存VPCと、エンタープライズ・公開・管理コンソール配布ローカルCAの証明書方式を選択します。",
          "ローカルCAは非本番専用テストOUだけで使用します。",
        ],
      },
      {
        title: "ID",
        summary: "鍵を保存せず、ローカルアプリが両方の管理面を参照できることを確認します。",
        actions: [
          "デプロイヤーサービスアカウントを偽装するキーレスApplication Default Credentialsを検証します。",
          "Google CloudプロジェクトとWorkspace顧客のChrome Policyへの読み取り専用アクセスを確認します。",
          "接続確認と、「適用」で必要になる強い権限を分離します。",
        ],
      },
      {
        title: "環境",
        summary: "Nginx HTTPオフロード、または独立したプライベートHTTPS直接方式を選択します。",
        actions: [
          "プロジェクト、リージョン、ゾーン、デプロイ名、ネットワーク、サブネット、プライベートホスト名を入力します。",
          "HTTPでは管理対象サンプルまたは既存HTTPバックエンドを選びます。Secure GatewayはHTTPSのNginxを対象にし、NginxがHTTP転送します。",
          "既存HTTPSアプリでは［プライベートHTTPSアプリへ直接接続］を選びます。アプリのhostname:portがSecure Gateway matcherとなり、Nginxリソースは除外されます。",
          "AWS・Azure・オンプレミスのアプリでは、選択GCP VPCをVPN/Interconnectで接続し、Cloud DNS転送を先に設定します。このPoCは第三者クラウド認証情報を保存せず、そのトンネルも作成しません。",
          "HTTPオフロードはNginxからbackendへのHTTPをT02で検証します。直接HTTPSは136.124.16.0/20からのTCP許可と戻り経路を必要とし、Gatewayのhostname:port/VPC経路をT05で検証します。",
          "プライベートNginx VM、Cloud NAT、オフロード証明書、管理Aレコードを作成するのはHTTPオフロードだけです。",
        ],
      },
      {
        title: "証明書",
        summary: "選択したアーキテクチャでTLSをどこが所有するかを定義します。",
        actions: [
          "Nginxオフロードでは、Nginxが提示する証明書を作成または参照します。",
          "直接HTTPSでは既存アプリがTLS終端と秘密鍵を保持し、Secure Gatewayはそれらをコピーしません。",
          "エンタープライズCA Serviceリソースまたは公開信頼済み証明書のシークレットを参照します。",
          "ローカルCAのPoCでは、Applyが公開PEMルート証明書を生成します。ダウンロードに秘密鍵は含まれません。",
          "Google管理コンソールで1回限りの手動操作を行います。[すべてのブラウザとデバイス] > [Chrome] > [コネクタ] > [新しいプロバイダの設定] > [Chrome Root Store] と進みます。",
          "構成名を入力し、ダウンロードしたPEMを追加して種類を [ルート] に設定します。[証明書を追加]、続いて構成を追加します。",
          "専用テストOUを選択し、[証明書コネクタ] > [Chrome Root Store] で新しい構成を選んで保存します。",
          "公開APIではRoot Store構成、アップロード済み証明書、OUバインドを確実に参照できません。端末へ信頼が届いた証拠は、各プラットフォームのT07 HTTPSテストです。",
          "T07実行前にChromeを再起動し、chrome://certificate-manager > [ローカル証明書] でルートを確認します。",
          "秘密鍵はブラウザ保存領域や起動スクリプトではなくSecret Managerに保持します。",
        ],
      },
      {
        title: "アクセス",
        summary: "Secure Gatewayポリシーとアプリへのアクセスをテスト対象だけに制限します。",
        actions: [
          "Workspace顧客と非本番専用OUを指定します。",
          "PoCに必要な最小限のユーザー、グループ、またはドメインを追加します。",
          "ポリシー変更を計画する前にテストOUの境界を確認します。",
        ],
      },
      {
        title: "確認",
        summary: "承認前に現在の状態を検出し、正確な変更内容を生成します。",
        actions: [
          "ID、API、権限、既存リソースについて読み取り専用の事前確認を実行します。",
          "ブロッキング安全ゲート付きの決定的かつマスク済みの望ましい状態プランを生成します。",
          "人による承認を正確な構成ハッシュに紐付け、後の編集で承認を無効化します。",
        ],
      },
      {
        title: "適用",
        summary: "承認済み操作だけを実行し、PoCの証跡を収集します。",
        actions: [
          "所有権チェックポイントを記録しながら、依存順にリソースを作成・更新します。",
          "失敗時は停止し、このデプロイが作成したリソースだけをロールバックします。",
          "このPoCはSecure GatewayのService Discoveryを有効化し、拡張機能の管理対象設定を配布するためPACファイルは作成しません。PACによるルーティングはService Discoveryがない旧方式だけで使用します。",
          "事前確認で継承中の旧PACを検出した場合、Applyは選択したテストOUだけを［ユーザーによる設定を許可］で上書きします。親OUとPAC本体は変更せず、ロールバック時は継承へ戻します。",
          "BYODのT07ではChromeブラウザ本体は管理対象外のままでよく、Chrome Enterprise Companionも不要です。Chrome自体へ対象組織のアカウントでログインし、クラウドのユーザーポリシーを受け取る仕事用プロファイルを使用します。Googleサイトへ別アカウントとしてログインしただけでは不十分です。",
          "Endpoint Verificationの強制インストール後は、一度拡張機能を開き、求められた場合は会社アカウントを追加して［今すぐ同期］を実行してからAccess Context Managerレベルをテストします。",
          "監査ハッシュチェーンを記録し、管理対象Chromeのアクセスと拒否ケースを含むT01〜T09を検証します。",
        ],
      },
    ],
  },
};

export function getMessages(locale: Locale): Messages {
  return locale === "ja" ? ja : en;
}
