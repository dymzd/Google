import { useEffect, useMemo, useState } from "react";
import { AppShell, type AppView } from "./components/AppShell";
import {
  AccessStep,
  ApplyStep,
  CertificateStep,
  EnvironmentStep,
  IdentitiesStep,
  isConfigurationReady,
  ReviewStep,
} from "./features/setup/ConfigurationSteps";
import { ModeStep } from "./features/setup/ModeStep";
import { WizardLayout } from "./features/setup/WizardLayout";
import {
  OperationsPage,
} from "./features/operations/OperationsPage";
import { GuidePage } from "./features/guide/GuidePage";
import { CepDeployerPage } from "./features/cep/CepDeployerPage";
import { getMessages } from "./i18n/messages";
import {
  applyApprovedPlan,
  ApiError,
  approvePlan,
  bootstrapGoogleCloudDeployer,
  type ApprovedPlan,
  type DeployerBootstrapResult,
  type DeploymentRun,
  getApprovedPlan,
  getDeploymentRun,
  getPreparedPlan,
  preparePlan,
  type PreparedPlan,
  validateGoogleCloudConnection,
  validateWorkspaceConnection,
} from "./lib/api";
import {
  loadLocale,
  loadSetupState,
  saveLocale,
  saveSetupState,
  toDeploymentSpec,
  type CertificateStrategy,
  type ChromePlatform,
  type DeploymentMode,
  type Locale,
  type NetworkStrategy,
  type SetupState,
  countSelectedPlatforms,
} from "./lib/setup-state";
import {
  clearWorkflowRefs,
  loadWorkflowRefs,
  saveWorkflowRefs,
} from "./lib/workflow-refs";

export function App() {
  const [locale, setLocale] = useState<Locale>(loadLocale);
  const [setup, setSetup] = useState<SetupState>(loadSetupState);
  const [preparedPlan, setPreparedPlan] = useState<PreparedPlan | null>(null);
  const [approval, setApproval] = useState<ApprovedPlan | null>(null);
  const [run, setRun] = useState<DeploymentRun | null>(null);
  const [workflowBusy, setWorkflowBusy] = useState(false);
  const [workflowError, setWorkflowError] = useState("");
  const [workflowRestored, setWorkflowRestored] = useState(false);
  const [activeView, setActiveView] = useState<AppView>("setup");
  const messages = useMemo(() => getMessages(locale), [locale]);

  useEffect(() => {
    document.documentElement.lang = locale === "ja" ? "ja" : "en";
    saveLocale(locale);
  }, [locale]);

  useEffect(() => {
    saveSetupState(setup);
  }, [setup]);

  useEffect(() => {
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
  }, [activeView]);

  useEffect(() => {
    const refs = loadWorkflowRefs();
    let cancelled = false;
    async function restoreWorkflow() {
      const [planResult, approvalResult, runResult] = await Promise.allSettled([
        refs.planId ? getPreparedPlan(refs.planId) : Promise.resolve(null),
        refs.approvalId ? getApprovedPlan(refs.approvalId) : Promise.resolve(null),
        refs.runId ? getDeploymentRun(refs.runId) : Promise.resolve(null),
      ]);
      if (cancelled) return;
      if (planResult.status === "fulfilled") setPreparedPlan(planResult.value);
      if (approvalResult.status === "fulfilled") setApproval(approvalResult.value);
      if (runResult.status === "fulfilled") setRun(runResult.value);
      setWorkflowRestored(true);
    }
    void restoreWorkflow();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!workflowRestored) return;
    const refs = {
      planId: preparedPlan?.plan_id ?? "",
      approvalId: approval?.approval_id ?? "",
      runId: run?.run_id ?? "",
    };
    if (refs.planId || refs.approvalId || refs.runId) saveWorkflowRefs(refs);
    else clearWorkflowRefs();
  }, [approval, preparedPlan, run, workflowRestored]);

  useEffect(() => {
    if (!run || !["pending", "running"].includes(run.status)) return;
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

  function patchSetup(patch: Partial<SetupState>) {
    const changesConfiguration = Object.keys(patch).some(
      (key) => !["approvalConfirmed", "currentStep", "updatedAt"].includes(key),
    );
    if (changesConfiguration) {
      setPreparedPlan(null);
      setApproval(null);
      setRun(null);
      setWorkflowError("");
      clearWorkflowRefs();
    }
    updateSetup((current) => ({
      ...current,
      ...patch,
      approvalConfirmed:
        Object.keys(patch).every((key) =>
          ["approvalConfirmed", "currentStep", "updatedAt"].includes(key),
        )
          ? (patch.approvalConfirmed ?? current.approvalConfirmed)
          : false,
    }));
  }

  function handleModeChange(mode: DeploymentMode) {
    if (mode === "production") return;
    updateSetup((current) => ({
      ...current,
      mode,
      approvalConfirmed: false,
    }));
  }

  function handlePlatformToggle(platform: ChromePlatform) {
    updateSetup((current) => {
      const platforms = {
        ...current.platforms,
        [platform]: !current.platforms[platform],
      };
      return {
        ...current,
        approvalConfirmed: false,
        platforms,
      };
    });
  }

  function handleNetworkChange(networkStrategy: NetworkStrategy) {
    updateSetup((current) => ({
      ...current,
      networkStrategy,
      backendKind:
        networkStrategy === "dedicated" && current.backendKind === "direct_https"
          ? "managed_sample"
          : current.backendKind,
      approvalConfirmed: false,
    }));
  }

  function handleCertificateChange(certificateStrategy: CertificateStrategy) {
    updateSetup((current) => {
      if (current.mode === "production" && certificateStrategy === "local_poc") {
        return current;
      }
      return { ...current, certificateStrategy, approvalConfirmed: false };
    });
  }

  function isCurrentStepValid(): boolean {
    const minimumReplicas = Number(setup.offloadMinReplicas);
    const maximumReplicas = Number(setup.offloadMaxReplicas);
    const cpuTarget = Number(setup.offloadCpuTarget);
    const scalingIsValid =
      Number.isInteger(minimumReplicas) &&
      Number.isInteger(maximumReplicas) &&
      minimumReplicas >= 2 &&
      maximumReplicas >= minimumReplicas &&
      maximumReplicas <= 1000 &&
      cpuTarget >= 0.1 &&
      cpuTarget <= 0.9;

    switch (setup.currentStep) {
      case 0:
        return countSelectedPlatforms(setup.platforms) > 0;
      case 1:
        return (
          setup.cloudConnection === "connected" &&
          setup.workspaceConnection === "connected"
        );
      case 2:
        return (
          Boolean(
            setup.deploymentName &&
              setup.region &&
              setup.zone &&
              (setup.backendKind === "direct_https" ||
                setup.mode === "poc" ||
                (setup.secondaryZone &&
                  setup.secondaryZone !== setup.zone &&
                  setup.sourceImage &&
                  scalingIsValid)) &&
              (setup.backendKind === "direct_https" || setup.privateHostname),
          ) &&
          (setup.backendKind !== "internal_https_lb" ||
            Boolean(setup.proxySubnetCidr)) &&
          (setup.backendKind === "direct_https"
            ? setup.networkStrategy === "existing" && Boolean(setup.vpcName)
            : setup.networkStrategy === "dedicated" ||
              Boolean(setup.vpcName && setup.subnetName)) &&
          (setup.backendKind === "managed_sample" ||
            setup.backendKind === "internal_https_lb" ||
            (setup.backendKind === "existing_http" &&
              setup.existingBackendUrl.startsWith("http://") &&
              setup.existingBackendConnectivityConfirmed) ||
            (setup.backendKind === "direct_https" &&
              setup.existingBackendUrl.startsWith("https://") &&
              setup.existingBackendConnectivityConfirmed))
        );
      case 3:
        return (
          setup.backendKind === "direct_https" ||
          setup.certificateStrategy === "local_poc" ||
          (setup.certificateStrategy === "enterprise_ca"
            ? Boolean(setup.caPool && setup.caName)
            : Boolean(setup.publicCertificateSecret))
        );
      case 4:
        return (
          Boolean(setup.customerId) &&
          Boolean(setup.targetOuId) &&
          Boolean(setup.managedChromeAccessLevel) &&
          (setup.mode === "poc" ||
            (setup.chromeEnterprisePremiumLicenseConfirmed &&
              setup.workspaceServicesConfirmed &&
              setup.endpointVerificationConfirmed)) &&
          setup.testOuConfirmed &&
          setup.principals.every(
            (principal) => principal.value.trim().length >= 3,
          )
        );
      case 5:
        return isConfigurationReady(setup) && approval !== null;
      case 6:
        return approval !== null && run === null && !workflowBusy;
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

  function localizedConnectionError(error: unknown, provider: "cloud" | "workspace") {
    if (!(error instanceof ApiError)) return messages.workflow.connectionFailed;
    if (error.code === "adc-unavailable") return messages.workflow.adcUnavailable;
    if (error.code === "cloud-validation-failed") {
      return messages.workflow.cloudValidationFailed;
    }
    if (error.code === "workspace-validation-failed") {
      return messages.workflow.workspaceValidationFailed;
    }
    return provider === "cloud"
      ? messages.workflow.cloudValidationFailed
      : messages.workflow.workspaceValidationFailed;
  }

  function localizedWorkflowError(error: unknown): string {
    if (!(error instanceof ApiError)) return messages.workflow.connectionFailed;
    if (error.code === "adc-unavailable") return messages.workflow.adcUnavailable;
    if (error.code === "preflight-validation-failed") {
      return messages.workflow.cloudValidationFailed;
    }
    if (error.code === "approval-invalid") return messages.workflow.planBlocked;
    return messages.workflow.connectionFailed;
  }

  async function handlePreparePlan() {
    setWorkflowBusy(true);
    setWorkflowError("");
    setApproval(null);
    setRun(null);
    updateSetup((current) => ({ ...current, approvalConfirmed: false }));
    try {
      const prepared = await preparePlan(toDeploymentSpec(setup, locale));
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

  async function handleValidateCloud() {
    console.log("[SGS App] Starting cloud validation for projectId:", setup.projectId);
    patchSetup({
      cloudConnection: "checking",
      cloudConnectionError: "",
      cloudIdentity: "",
    });
    try {
      const validation = await validateGoogleCloudConnection(setup.projectId);
      console.log("[SGS App] Cloud validation succeeded:", validation);
      patchSetup({
        cloudConnection: "connected",
        cloudIdentity: validation.principal_hint,
      });
    } catch (error) {
      console.error("[SGS App] Cloud validation error:", error);
      patchSetup({
        cloudConnection: "error",
        cloudConnectionError: localizedConnectionError(error, "cloud"),
        cloudIdentity: "",
      });
    }
  }

  async function handleBootstrapCloud(): Promise<DeployerBootstrapResult> {
    console.log("[SGS App] Starting deployer bootstrap for projectId:", setup.projectId);
    try {
      const res = await bootstrapGoogleCloudDeployer(setup.projectId);
      console.log("[SGS App] Deployer bootstrap succeeded:", res);
      return res;
    } catch (error) {
      console.error("[SGS App] Deployer bootstrap error:", error);
      throw error;
    }
  }

  async function handleValidateWorkspace() {
    console.log("[SGS App] Starting workspace validation for customerId:", setup.customerId);
    patchSetup({
      workspaceConnection: "checking",
      workspaceConnectionError: "",
      workspaceIdentity: "",
    });
    try {
      const validation = await validateWorkspaceConnection(setup.customerId);
      console.log("[SGS App] Workspace validation succeeded:", validation);
      patchSetup({
        workspaceConnection: "connected",
        workspaceIdentity: validation.principal_hint,
      });
    } catch (error) {
      console.error("[SGS App] Workspace validation error:", error);
      patchSetup({
        workspaceConnection: "error",
        workspaceConnectionError: localizedConnectionError(error, "workspace"),
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

  return (
    <AppShell
      activeView={activeView}
      cloudProject={setup.projectId}
      locale={locale}
      messages={messages}
      onLocaleChange={setLocale}
      onNavigate={setActiveView}
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
        <CepDeployerPage
          customerId={setup.customerId}
          messages={messages}
          projectId={setup.projectId}
        />
      ) : (
        <OperationsPage messages={messages} view={activeView} />
      )}
    </AppShell>
  );
}
