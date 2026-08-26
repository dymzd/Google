import { useEffect, useMemo, useState } from "react";
import { AppShell, type AppView } from "./components/AppShell";
import { UserDataDisclosure } from "./components/UserDataDisclosure";
import {
  AccessStep,
  ApplyStep,
  CertificateStep,
  EnvironmentStep,
  IdentitiesStep,
  isAccessReady,
  isCertificateReady,
  isConfigurationReady,
  isEnvironmentReady,
  isIdentitiesReady,
  ReviewStep,
} from "./features/setup/ConfigurationSteps";
import { ModeStep } from "./features/setup/ModeStep";
import { WizardLayout } from "./features/setup/WizardLayout";
import {
  OperationsPage,
} from "./features/operations/OperationsPage";
import { GuidePage } from "./features/guide/GuidePage";
import { CepDeployerPage } from "./features/cep/CepDeployerPage";
import { getMessages, type Messages } from "./i18n/messages";
import {
  applyApprovedPlan,
  ApiError,
  approvePlan,
  bootstrapGoogleCloudDeployer,
  type ApprovedPlan,
  type DeployerBootstrapResult,
  type DeploymentSpec,
  type DeploymentRun,
  getApprovedPlan,
  getDeploymentRun,
  getPreparedPlan,
  getRecommendedPocSourceImage,
  listDeploymentRuns,
  preparePlan,
  type PreparedPlan,
  runtimeCapabilities,
  resumeDeploymentRun,
  saveExtensionClientState,
  signOutSession,
  validateGoogleCloudConnection,
  validateWorkspaceConnection,
} from "./lib/api";
import {
  defaultSetupState,
  loadLocale,
  loadSetupState,
  restoreSetupState,
  requiresCloudConnectionRevalidation,
  saveLocale,
  saveSetupState,
  toDeploymentSpec,
  type CertificateStrategy,
  type ChromePlatform,
  type DeploymentMode,
  type Locale,
  type NetworkStrategy,
  type SetupState,
  constrainSetupStateToRuntime,
  countSelectedPlatforms,
  isPublicTrustedHostnameCandidate,
} from "./lib/setup-state";
import {
  clearWorkflowRefs,
  emptyWorkflowRefs,
  loadWorkflowRefs,
  restoreWorkflowRefs,
  saveWorkflowRefs,
  type WorkflowRefs,
} from "./lib/workflow-refs";
import {
  acceptAndMigrateExtensionState,
  loadPreviouslyAcceptedExtensionState,
} from "./lib/extension-state";

const NON_CONFIGURATION_SETUP_KEYS = new Set<keyof SetupState>([
  "approvalConfirmed",
  "currentStep",
  "updatedAt",
]);

function canonicalJsonValue(value: unknown, key = ""): unknown {
  if (Array.isArray(value)) {
    const items = key === "platforms" ? [...value].sort() : value;
    return items.map((item) => canonicalJsonValue(item));
  }
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== null && item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([itemKey, item]) => [itemKey, canonicalJsonValue(item, itemKey)]),
  );
}

function normalizedSpecificationForComparison(specification: DeploymentSpec): DeploymentSpec {
  return {
    ...specification,
    private_hostname: specification.private_hostname.trim().toLowerCase().replace(/\.$/, ""),
    principals: specification.principals.map((principal) => ({
      ...principal,
      value: principal.value.trim().toLowerCase(),
    })),
  };
}

export function specificationsMatch(left: DeploymentSpec, right: DeploymentSpec): boolean {
  return JSON.stringify(canonicalJsonValue(normalizedSpecificationForComparison(left))) ===
    JSON.stringify(canonicalJsonValue(normalizedSpecificationForComparison(right)));
}

const RECOVERABLE_RUN_STATUSES = new Set<DeploymentRun["status"]>([
  "pending",
  "running",
  "rolling_back",
  "interrupted",
  "failed",
  "rollback_failed",
  "rollback_unavailable",
]);

export function findRecoverableDeploymentRun(
  runs: readonly DeploymentRun[],
): DeploymentRun | null {
  return runs.find((candidate) => RECOVERABLE_RUN_STATUSES.has(candidate.status)) ?? null;
}

export function workflowErrorText(
  error: unknown,
  workflow: Messages["workflow"],
): string {
  if (!(error instanceof ApiError)) return workflow.connectionFailed;
  if (error.code === "adc-unavailable") return workflow.adcUnavailable;
  if (error.code === "preflight-validation-failed") {
    return workflow.cloudValidationFailed;
  }
  if (error.code === "approval-invalid") return workflow.planBlocked;
  if (error.code === "spec-invalid") {
    return error.message
      ? `${workflow.specInvalid}: ${error.message}`
      : workflow.specInvalid;
  }
  return error.message || workflow.connectionFailed;
}

export function connectionErrorText(
  error: unknown,
  provider: "cloud" | "workspace",
  workflow: Messages["workflow"],
): string {
  if (!(error instanceof ApiError)) return workflow.connectionFailed;
  if (error.code === "adc-unavailable") return workflow.adcUnavailable;
  if (error.code === "cloud-validation-failed") {
    return workflow.cloudValidationFailed;
  }
  if (error.code === "workspace-validation-failed") {
    return workflow.workspaceValidationFailed;
  }
  return error.message || (provider === "cloud"
    ? workflow.cloudValidationFailed
    : workflow.workspaceValidationFailed);
}

/**
 * IAM policy changes are eventually consistent. Keep the setup action busy
 * through the typical propagation window, while bounding each wait so the UI
 * can be interrupted naturally if the extension page closes.
 */
export const POST_BOOTSTRAP_VALIDATION_DELAYS_MS = [
  0,
  2_000,
  5_000,
  10_000,
  20_000,
  30_000,
  30_000,
  30_000,
] as const;

export function isTransientPostBootstrapCloudValidationError(error: unknown): boolean {
  if (!(error instanceof ApiError)) return false;
  if (
    error.code === "impersonation-denied" ||
    error.code === "google-api-403" ||
    error.code === "deployer-permissions-not-ready" ||
    error.code === "deployer-dns-readiness-failed" ||
    error.code === "deployer-dns-permission-denied" ||
    error.code === "deployer-dns-network-failed"
  ) {
    return true;
  }
  return error.code === "request-failed" &&
    /cannot impersonate|token exchange failed/i.test(error.message);
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => globalThis.setTimeout(resolve, milliseconds));
}

export function App() {
  const extensionPersistentState = runtimeCapabilities.userDataDisclosure;
  const [userDataDisclosureAccepted, setUserDataDisclosureAccepted] = useState<boolean>(
    !extensionPersistentState,
  );
  const [consentBusy, setConsentBusy] = useState<boolean>(extensionPersistentState);
  const [clientStateHydrated, setClientStateHydrated] = useState<boolean>(!extensionPersistentState);
  const [persistedWorkflow, setPersistedWorkflow] = useState<WorkflowRefs | null>(() =>
    extensionPersistentState ? null : loadWorkflowRefs()
  );
  const [locale, setLocale] = useState<Locale>(loadLocale);
  const [setup, setSetup] = useState<SetupState>(() =>
    constrainSetupStateToRuntime(
      extensionPersistentState ? defaultSetupState : loadSetupState(),
      runtimeCapabilities.internalHttpsLbArchitecture,
    )
  );
  const [preparedPlan, setPreparedPlan] = useState<PreparedPlan | null>(null);
  const [approval, setApproval] = useState<ApprovedPlan | null>(null);
  const [run, setRun] = useState<DeploymentRun | null>(null);
  const [workflowBusy, setWorkflowBusy] = useState(false);
  const [workflowError, setWorkflowError] = useState("");
  const [workflowRestored, setWorkflowRestored] = useState(false);
  const [activeView, setActiveView] = useState<AppView>("setup");
  const messages = useMemo(() => getMessages(locale), [locale]);

  useEffect(() => {
    if (!extensionPersistentState) return;
    let cancelled = false;
    async function hydrateAcceptedState() {
      try {
        const stored = await loadPreviouslyAcceptedExtensionState();
        if (cancelled) return;
        if (stored === null) {
          setConsentBusy(false);
          return;
        }
        const invalidateWorkflow = requiresCloudConnectionRevalidation(stored.setup);
        setSetup(
          constrainSetupStateToRuntime(
            restoreSetupState(stored.setup),
            runtimeCapabilities.internalHttpsLbArchitecture,
          ),
        );
        setPersistedWorkflow(
          invalidateWorkflow ? emptyWorkflowRefs : restoreWorkflowRefs(stored.workflow),
        );
        setClientStateHydrated(true);
        setUserDataDisclosureAccepted(true);
      } catch {
        if (!cancelled) setConsentBusy(false);
      }
    }
    void hydrateAcceptedState();
    return () => {
      cancelled = true;
    };
  }, [extensionPersistentState]);

  useEffect(() => {
    document.documentElement.lang = locale === "ja" ? "ja" : "en";
    saveLocale(locale);
  }, [locale]);

  useEffect(() => {
    if (!userDataDisclosureAccepted || !clientStateHydrated) return;
    if (extensionPersistentState) {
      void saveExtensionClientState({ setup }).catch(() => {
        setWorkflowError(messages.workflow.connectionFailed);
      });
      return;
    }
    saveSetupState(setup);
  }, [clientStateHydrated, extensionPersistentState, messages.workflow.connectionFailed, setup, userDataDisclosureAccepted]);

  useEffect(() => {
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
  }, [activeView]);

  useEffect(() => {
    if (!userDataDisclosureAccepted || !clientStateHydrated || persistedWorkflow === null) return;
    const refs = persistedWorkflow;
    let cancelled = false;
    async function restoreWorkflow() {
      const [planResult, approvalResult, runResult, runsResult] = await Promise.allSettled([
        refs.planId ? getPreparedPlan(refs.planId) : Promise.resolve(null),
        refs.approvalId ? getApprovedPlan(refs.approvalId) : Promise.resolve(null),
        refs.runId ? getDeploymentRun(refs.runId) : Promise.resolve(null),
        extensionPersistentState ? listDeploymentRuns() : Promise.resolve([]),
      ]);
      if (cancelled) return;
      if (planResult.status === "fulfilled") setPreparedPlan(planResult.value);
      if (approvalResult.status === "fulfilled") setApproval(approvalResult.value);
      const restoredRun = runResult.status === "fulfilled" ? runResult.value : null;
      const recoverableRun = restoredRun !== null &&
          RECOVERABLE_RUN_STATUSES.has(restoredRun.status)
        ? restoredRun
        : runsResult.status === "fulfilled"
          ? findRecoverableDeploymentRun(runsResult.value)
          : null;
      if (recoverableRun !== null) {
        setRun(recoverableRun);
        setSetup((current) => ({
          ...current,
          approvalConfirmed: false,
          currentStep: 6,
          updatedAt: new Date().toISOString(),
        }));
      } else if (restoredRun !== null) {
        setRun(restoredRun);
      }
      setWorkflowRestored(true);
    }
    void restoreWorkflow();
    return () => {
      cancelled = true;
    };
  }, [clientStateHydrated, persistedWorkflow, userDataDisclosureAccepted]);

  useEffect(() => {
    if (!workflowRestored) return;
    const refs = {
      planId: preparedPlan?.plan_id ?? "",
      approvalId: approval?.approval_id ?? "",
      runId: run?.run_id ?? "",
    };
    if (extensionPersistentState) {
      void saveExtensionClientState({ workflow: refs }).catch(() => {
        setWorkflowError(messages.workflow.connectionFailed);
      });
      return;
    }
    if (refs.planId || refs.approvalId || refs.runId) saveWorkflowRefs(refs);
    else clearWorkflowRefs();
  }, [approval, extensionPersistentState, messages.workflow.connectionFailed, preparedPlan, run, workflowRestored]);

  useEffect(() => {
    if (!run || !["pending", "running", "rolling_back"].includes(run.status)) return;
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      try {
        const refreshed = await getDeploymentRun(run.run_id);
        if (!cancelled) setRun(refreshed);
      } catch (error) {
        if (!cancelled) setWorkflowError(localizedWorkflowError(error));
      }
    }, 1500);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [run]);

  function updateSetup(updater: (current: SetupState) => SetupState) {
    setSetup((current) => ({
      ...updater(current),
      updatedAt: new Date().toISOString(),
    }));
  }

  function invalidatePreparedWorkflow() {
    setPreparedPlan(null);
    setApproval(null);
    setRun(null);
    setWorkflowError("");
    if (!extensionPersistentState) clearWorkflowRefs();
  }

  function updateConfiguration(updater: (current: SetupState) => SetupState) {
    invalidatePreparedWorkflow();
    updateSetup((current) => ({
      ...updater(current),
      approvalConfirmed: false,
    }));
  }

  function patchSetup(patch: Partial<SetupState>) {
    const changesConfiguration = Object.keys(patch).some(
      (key) => !NON_CONFIGURATION_SETUP_KEYS.has(key as keyof SetupState),
    );
    if (changesConfiguration) {
      updateConfiguration((current) => ({ ...current, ...patch }));
      return;
    }
    updateSetup((current) => ({
      ...current,
      ...patch,
      approvalConfirmed:
        Object.keys(patch).every((key) =>
          NON_CONFIGURATION_SETUP_KEYS.has(key as keyof SetupState),
        )
          ? (patch.approvalConfirmed ?? current.approvalConfirmed)
          : false,
    }));
  }

  function handleModeChange(mode: DeploymentMode) {
    // This release is intentionally scoped to rapid PoC deployments. ModeStep and loadSetupState share this invariant.
    if (mode === "production") return;
    if (mode === setup.mode) return;
    updateConfiguration((current) => ({
      ...current,
      mode,
    }));
  }

  function handlePlatformToggle(platform: ChromePlatform) {
    updateConfiguration((current) => {
      const platforms = {
        ...current.platforms,
        [platform]: !current.platforms[platform],
      };
      return {
        ...current,
        platforms,
      };
    });
  }

  function handleNetworkChange(networkStrategy: NetworkStrategy) {
    if (networkStrategy === setup.networkStrategy) return;
    updateConfiguration((current) => ({
      ...current,
      networkStrategy,
      backendKind:
        networkStrategy === "dedicated" && current.backendKind === "direct_https"
          ? "managed_sample"
          : current.backendKind,
    }));
  }

  function handleCertificateChange(certificateStrategy: CertificateStrategy) {
    if (
      certificateStrategy === setup.certificateStrategy ||
      (setup.mode === "production" && certificateStrategy === "local_poc")
    ) {
      return;
    }
    updateConfiguration((current) => ({
      ...current,
      certificateStrategy,
      privateHostname:
        certificateStrategy === "public_trusted" &&
        !isPublicTrustedHostnameCandidate(current.privateHostname)
          ? ""
          : current.privateHostname,
    }));
  }

  function handleLocaleChange(nextLocale: Locale) {
    if (nextLocale === locale) return;
    invalidatePreparedWorkflow();
    setLocale(nextLocale);
  }

  function approvalMatchesCurrentConfiguration(): boolean {
    if (preparedPlan === null || approval === null) return false;
    if (approval.configuration_hash !== preparedPlan.plan.configuration_hash) return false;
    if (!specificationsMatch(preparedPlan.specification, toDeploymentSpec(setup, locale))) {
      return false;
    }
    // The server verifies that the prepared plan is fresh when it creates the
    // approval. From that point onward the approval has its own authoritative
    // expiry. Older extension responses omitted the plan timestamps entirely;
    // treating that transport omission as an expired approval left an exact,
    // server-approved plan visibly approved but impossible to continue.
    const approvalExpiry = Date.parse(approval.expires_at);
    return Number.isFinite(approvalExpiry) && approvalExpiry > Date.now();
  }

  function isCurrentStepValid(): boolean {
    switch (setup.currentStep) {
      case 0:
        return countSelectedPlatforms(setup.platforms) > 0;
      case 1:
        return isIdentitiesReady(setup);
      case 2:
        return isEnvironmentReady(
          setup,
          runtimeCapabilities.internalHttpsLbArchitecture,
        );
      case 3:
        return isCertificateReady(setup);
      case 4:
        return isAccessReady(setup);
      case 5:
        return isConfigurationReady(setup) && approvalMatchesCurrentConfiguration();
      case 6:
        return approvalMatchesCurrentConfiguration() && run === null && !workflowBusy;
      default:
        return false;
    }
  }

  function goBack() {
    patchSetup({ currentStep: Math.max(0, setup.currentStep - 1) });
  }

  function goNext() {
    if (setup.currentStep === 6) {
      void handleApply();
      return;
    }
    if (!isCurrentStepValid() || setup.currentStep >= 6) return;
    patchSetup({ currentStep: Math.min(6, setup.currentStep + 1) });
  }

  function localizedWorkflowError(error: unknown): string {
    return workflowErrorText(error, messages.workflow);
  }

  async function handlePreparePlan() {
    setWorkflowBusy(true);
    setWorkflowError("");
    try {
      if (extensionPersistentState) {
        const recoverableRun = findRecoverableDeploymentRun(await listDeploymentRuns());
        if (recoverableRun !== null) {
          setPreparedPlan(null);
          setApproval(null);
          setRun(recoverableRun);
          updateSetup((current) => ({
            ...current,
            approvalConfirmed: false,
            currentStep: 6,
          }));
          return;
        }
      }
      setApproval(null);
      setRun(null);
      updateSetup((current) => ({ ...current, approvalConfirmed: false }));
      let setupForPlan = setup;
      if (
        runtimeCapabilities.recommendedPocSourceImage &&
        setup.mode === "poc" &&
        setup.backendKind !== "direct_https" &&
        !setup.sourceImage.trim()
      ) {
        const recommendedImage = await getRecommendedPocSourceImage(setup.projectId);
        setupForPlan = { ...setup, sourceImage: recommendedImage.value };
        updateSetup((current) => ({
          ...current,
          sourceImage: recommendedImage.value,
          approvalConfirmed: false,
        }));
      }
      const prepared = await preparePlan(toDeploymentSpec(setupForPlan, locale));
      setPreparedPlan(prepared);
    } catch (error) {
      setPreparedPlan(null);
      setWorkflowError(localizedWorkflowError(error));
    } finally {
      setWorkflowBusy(false);
    }
  }

  async function handleApprove(approved: boolean) {
    if (!approved) {
      setApproval(null);
      updateSetup((current) => ({ ...current, approvalConfirmed: false }));
      return;
    }
    if (!preparedPlan) return;
    setWorkflowBusy(true);
    setWorkflowError("");
    try {
      const approvedPlan = await approvePlan(preparedPlan.plan_id);
      setApproval(approvedPlan);
      updateSetup((current) => ({ ...current, approvalConfirmed: true }));
    } catch (error) {
      setApproval(null);
      setWorkflowError(localizedWorkflowError(error));
    } finally {
      setWorkflowBusy(false);
    }
  }

  async function handleApply() {
    if (!approval || workflowBusy || run) return;
    if (!approvalMatchesCurrentConfiguration()) {
      invalidatePreparedWorkflow();
      setWorkflowError(messages.workflow.planBlocked);
      return;
    }
    setWorkflowBusy(true);
    setWorkflowError("");
    try {
      setRun(
        await applyApprovedPlan(approval.approval_id),
      );
    } catch (error) {
      setWorkflowError(localizedWorkflowError(error));
    } finally {
      setWorkflowBusy(false);
    }
  }

  async function handleResumeRun() {
    if (
      !run ||
      !["interrupted", "failed", "rollback_failed", "rollback_unavailable"].includes(
        run.status,
      ) ||
      workflowBusy
    ) return;
    setWorkflowBusy(true);
    setWorkflowError("");
    try {
      setRun(await resumeDeploymentRun(run.run_id));
    } catch (error) {
      setWorkflowError(localizedWorkflowError(error));
    } finally {
      setWorkflowBusy(false);
    }
  }

  async function handleValidateCloud(retryAfterBootstrap = false) {
    patchSetup({
      cloudConnection: "checking",
      cloudConnectionError: "",
      cloudIdentity: "",
      accessPolicyId: "",
    });
    const delays = retryAfterBootstrap ? POST_BOOTSTRAP_VALIDATION_DELAYS_MS : [0];
    for (let attempt = 0; attempt < delays.length; attempt += 1) {
      if (delays[attempt] > 0) await delay(delays[attempt]);
      try {
        const validation = await validateGoogleCloudConnection(setup.projectId);
        patchSetup({
          cloudConnection: "connected",
          cloudIdentity: validation.principal_hint,
          accessPolicyId:
            validation.access_policy_id && /^\d+$/.test(validation.access_policy_id)
              ? validation.access_policy_id
              : "",
        });
        return;
      } catch (error) {
        if (
          retryAfterBootstrap &&
          attempt < delays.length - 1 &&
          isTransientPostBootstrapCloudValidationError(error)
        ) {
          continue;
        }
        patchSetup({
          cloudConnection: "error",
          cloudConnectionError: connectionErrorText(error, "cloud", messages.workflow),
          cloudIdentity: "",
          accessPolicyId: "",
        });
        return;
      }
    }
  }

  async function handleBootstrapCloud(
    migrateExistingDeployer = false,
    createReplacementDeployer = false,
    recreateDeletedDeployer = false,
  ): Promise<DeployerBootstrapResult> {
    const res = await bootstrapGoogleCloudDeployer(
      setup.projectId,
      setup.accessPolicyId || null,
      migrateExistingDeployer,
      createReplacementDeployer,
      recreateDeletedDeployer,
    );
    patchSetup({ accessPolicyId: res.access_policy_id ?? "" });
    return res;
  }

  async function handleValidateWorkspace() {
    patchSetup({
      workspaceConnection: "checking",
      workspaceConnectionError: "",
      workspaceIdentity: "",
    });
    try {
      const validation = await validateWorkspaceConnection(setup.customerId);
      const canonicalCustomerId = validation.resource_id.trim();
      if (!/^C[A-Za-z0-9]+$/.test(canonicalCustomerId)) {
        throw new Error(
          "Workspace validation did not return a canonical customer ID beginning with C.",
        );
      }
      patchSetup({
        customerId: canonicalCustomerId,
        workspaceConnection: "connected",
        workspaceIdentity: validation.principal_hint,
      });
    } catch (error) {
      patchSetup({
        workspaceConnection: "error",
        workspaceConnectionError: connectionErrorText(error, "workspace", messages.workflow),
        workspaceIdentity: "",
      });
    }
  }

  function renderCurrentStep() {
    switch (setup.currentStep) {
      case 1:
        return (
          <IdentitiesStep
            messages={messages}
            onBootstrapCloud={handleBootstrapCloud}
            onPatch={patchSetup}
            onValidateCloud={handleValidateCloud}
            onValidateWorkspace={handleValidateWorkspace}
            state={setup}
          />
        );
      case 2:
        return (
          <EnvironmentStep
            messages={messages}
            onPatch={patchSetup}
            state={setup}
          />
        );
      case 3:
        return (
          <CertificateStep
            messages={messages}
            onPatch={patchSetup}
            state={setup}
          />
        );
      case 4:
        return (
          <AccessStep messages={messages} onPatch={patchSetup} state={setup} />
        );
      case 5:
        return (
          <ReviewStep
            approval={approval}
            busy={workflowBusy}
            error={workflowError}
            messages={messages}
            onApprove={handleApprove}
            onPatch={patchSetup}
            onPrepare={handlePreparePlan}
            preparedPlan={preparedPlan}
            state={setup}
          />
        );
      case 6:
        return (
          <ApplyStep
            approval={approval}
            busy={workflowBusy}
            error={workflowError}
            messages={messages}
            onResume={handleResumeRun}
            preparedPlan={preparedPlan}
            run={run}
            state={setup}
          />
        );
      default:
        return (
          <ModeStep
            messages={messages}
            onCertificateChange={handleCertificateChange}
            onModeChange={handleModeChange}
            onNetworkChange={handleNetworkChange}
            onPlatformToggle={handlePlatformToggle}
            state={setup}
          />
        );
    }
  }

  const nextLabel =
    setup.currentStep === 5
      ? messages.workflow.continueToApply
      : setup.currentStep === 6
        ? messages.workflow.applyChanges
        : undefined;

  async function handleSignOut() {
    if (!window.confirm(messages.signOutConfirm)) {
      return;
    }
    try {
      await signOutSession();
    } catch (e) {
      const message = e instanceof Error ? e.message : messages.workflow.connectionFailed;
      setWorkflowError(message);
      window.alert(message);
      return;
    }
    if (extensionPersistentState) {
      await saveExtensionClientState({ setup: null, workflow: null });
    } else {
      clearWorkflowRefs();
      try {
        localStorage.clear();
        sessionStorage.clear();
      } catch {}
    }
    setPreparedPlan(null);
    setApproval(null);
    setRun(null);
    setWorkflowError("");
    setSetup(extensionPersistentState ? defaultSetupState : loadSetupState());
    window.location.reload();
  }

  async function handleAcceptUserDataDisclosure() {
    setConsentBusy(true);
    try {
      const stored = await acceptAndMigrateExtensionState();
      const invalidateWorkflow = requiresCloudConnectionRevalidation(stored.setup);
      setSetup(restoreSetupState(stored.setup));
      setPersistedWorkflow(
        invalidateWorkflow ? emptyWorkflowRefs : restoreWorkflowRefs(stored.workflow),
      );
      setClientStateHydrated(true);
      setUserDataDisclosureAccepted(true);
    } catch {
      window.alert(messages.workflow.connectionFailed);
    } finally {
      setConsentBusy(false);
    }
  }

  if (!userDataDisclosureAccepted) {
    return (
      <UserDataDisclosure
        busy={consentBusy}
        locale={locale}
        onAccept={() => void handleAcceptUserDataDisclosure()}
      />
    );
  }

  return (
    <AppShell
      activeView={activeView}
      cloudProject={setup.projectId}
      locale={locale}
      messages={messages}
      onLocaleChange={handleLocaleChange}
      onNavigate={setActiveView}
      onSignOut={handleSignOut}
      showCepDeployer={runtimeCapabilities.cepDeployer}
      workspaceAdmin={setup.workspaceIdentity}
    >
      {activeView === "setup" ? (
        <WizardLayout
          activeStep={setup.currentStep}
          messages={messages}
          nextDisabled={!isCurrentStepValid()}
          nextLabel={nextLabel}
          onBack={goBack}
          onNext={goNext}
          state={setup}
        >
          {renderCurrentStep()}
        </WizardLayout>
      ) : activeView === "guide" ? (
        <GuidePage messages={messages} />
      ) : activeView === "cepDeployer" ? (
        runtimeCapabilities.cepDeployer ? (
          <CepDeployerPage
            customerId={setup.customerId}
            messages={messages}
            projectId={setup.projectId}
          />
        ) : null
      ) : (
        <OperationsPage messages={messages} view={activeView} />
      )}
    </AppShell>
  );
}
