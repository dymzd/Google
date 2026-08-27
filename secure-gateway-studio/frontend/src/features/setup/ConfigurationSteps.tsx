import { useCallback, useEffect, useState } from "react";
import {
  CheckIcon,
  CloudIcon,
  CodeIcon,
  InfoIcon,
  LockIcon,
  NetworkIcon,
  ShieldIcon,
  UsersIcon,
} from "../../components/Icons";
import type { Messages } from "../../i18n/messages";
import type {
  ApprovedPlan,
  DeployerBootstrapResult,
  DeploymentGate,
  DeploymentRun,
  PreparedPlan,
  SetupOption,
} from "../../lib/api";
import {
  ApiError,
  downloadLocalPocRootCertificate,
  getRecommendedPocSourceImage,
  listAccessLevelOptions,
  listGroupOptions,
  listOrganizationalUnitOptions,
  listVpcNetworkOptions,
  runtimeCapabilities,
  signInSession,
} from "../../lib/api";
import {
  isPublicTrustedHostnameCandidate,
  isSupportedGoogleCloudProjectId,
  isSupportedManagedChromeAccessLevel,
  type AccessPrincipal,
  type BackendKind,
  type BackendLocation,
  type PrincipalType,
  type SetupState,
} from "../../lib/setup-state";
import { ChoiceCard } from "./ChoiceCard";

interface StepProps {
  messages: Messages;
  onPatch: (patch: Partial<SetupState>) => void;
  state: SetupState;
}

interface IdentitiesStepProps extends StepProps {
  onBootstrapCloud: (
    migrateExistingDeployer?: boolean,
    createReplacementDeployer?: boolean,
    recreateDeletedDeployer?: boolean,
  ) => Promise<DeployerBootstrapResult>;
  onValidateCloud: (retryAfterBootstrap?: boolean) => Promise<void>;
  onValidateWorkspace: () => Promise<void>;
}

interface ReviewStepProps extends StepProps {
  approval: ApprovedPlan | null;
  busy: boolean;
  error: string;
  onApprove: (approved: boolean) => Promise<void>;
  onPrepare: () => Promise<void>;
  preparedPlan: PreparedPlan | null;
}

interface ApplyStepProps {
  approval: ApprovedPlan | null;
  busy: boolean;
  error: string;
  messages: Messages;
  onResume: () => Promise<void>;
  preparedPlan: PreparedPlan | null;
  run: DeploymentRun | null;
  state: SetupState;
}

function Field({
  disabled = false,
  label,
  max,
  min,
  onChange,
  placeholder,
  readOnly = false,
  step,
  type = "text",
  value,
}: {
  disabled?: boolean;
  label: string;
  max?: number;
  min?: number;
  onChange: (value: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  step?: number;
  type?: string;
  value: string;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      <input
        autoComplete="off"
        disabled={disabled}
        max={max}
        min={min}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        readOnly={readOnly}
        spellCheck={false}
        step={step}
        type={type}
        value={value}
      />
    </label>
  );
}

interface CatalogState {
  items: SetupOption[];
  loading: boolean;
  error: string;
}

const emptyCatalog: CatalogState = { items: [], loading: false, error: "" };

function CatalogSelect({
  catalog,
  emptyLabel,
  label,
  loadingLabel,
  onChange,
  onRetry,
  placeholder,
  retryLabel,
  value,
}: {
  catalog: CatalogState;
  emptyLabel: string;
  label: string;
  loadingLabel: string;
  onChange: (value: string) => void;
  onRetry: () => void;
  placeholder: string;
  retryLabel: string;
  value: string;
}) {
  const items = Array.isArray(catalog?.items) ? catalog.items : [];
  const selected = items.find((option) => option.value === value);
  const preservesExistingValue =
    Boolean(value) && !items.some((option) => option.value === value);

  return (
    <div className="catalog-field">
      <label className="field">
        <span>{label}</span>
        <select
          disabled={catalog.loading || (Boolean(catalog.error) && items.length === 0)}
          onChange={(event) => onChange(event.target.value)}
          value={value}
        >
          <option value="">
            {catalog.loading
              ? loadingLabel
              : items.length === 0
                ? emptyLabel
                : placeholder}
          </option>
          {preservesExistingValue && <option value={value}>{value}</option>}
          {items.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      {selected?.description && (
        <small className="field-hint">{selected.description}</small>
      )}
      {catalog.error && (
        <p className="catalog-error" role="alert">
          <span>{catalog.error}</span>
          <button className="text-action" onClick={onRetry} type="button">
            {retryLabel}
          </button>
        </p>
      )}
    </div>
  );
}

function StepHeading({
  description,
  title,
}: {
  description: string;
  title: string;
}) {
  return (
    <header className="step-heading">
      <h2>{title}</h2>
      <p>{description}</p>
    </header>
  );
}

function Notice({
  children,
  tone = "info",
}: {
  children: string;
  tone?: "info" | "security";
}) {
  return (
    <p className={`workflow-notice ${tone}`}>
      {tone === "security" ? <LockIcon size={20} /> : <InfoIcon size={20} />}
      <span>{children}</span>
    </p>
  );
}

export function IdentitiesStep({
  messages,
  onBootstrapCloud,
  onPatch,
  onValidateCloud,
  onValidateWorkspace,
  state,
}: IdentitiesStepProps) {
  const copy = messages.workflow;
  const [bootstrapBusy, setBootstrapBusy] = useState(false);
  const [bootstrapError, setBootstrapError] = useState("");
  const [signInBusy, setSignInBusy] = useState(false);
  const [bootstrapResult, setBootstrapResult] =
    useState<DeployerBootstrapResult | null>(null);

  async function handleBootstrap() {
    if (!globalThis.confirm(copy.bootstrapConfirm)) return;
    setBootstrapBusy(true);
    setBootstrapError("");
    setBootstrapResult(null);
    try {
      let result: DeployerBootstrapResult;
      try {
        result = await onBootstrapCloud(false);
      } catch (error) {
        if (
          error instanceof ApiError &&
          error.code === "service-account-pinned-identity-missing" &&
          globalThis.confirm(copy.bootstrapDeletedDeployerConfirm)
        ) {
          result = await onBootstrapCloud(false, false, true);
          setBootstrapResult(result);
          await onValidateCloud(true);
          return;
        }
        if (
          !(error instanceof ApiError) ||
          error.code !== "service-account-identity-unpinned" ||
          !globalThis.confirm(copy.bootstrapLegacyMigrationConfirm)
        ) {
          throw error;
        }
        // A second, migration-specific confirmation is required. The worker
        // then audits the immutable SA id, exact role, and IAM allowlists
        // before it writes an ownership pin or grants anything.
        try {
          result = await onBootstrapCloud(true);
        } catch (migrationError) {
          if (
            !(migrationError instanceof ApiError) ||
            !migrationError.code.startsWith("legacy-deployer-") ||
            !globalThis.confirm(copy.bootstrapReplacementConfirm)
          ) {
            throw migrationError;
          }
          // The failed legacy audit made no mutation. A third confirmation
          // creates fresh isolated names and leaves the legacy identity intact.
          result = await onBootstrapCloud(false, true);
        }
      }
      setBootstrapResult(result);
      // Newly written service-account and project IAM bindings can be briefly
      // unavailable to token impersonation. Retry only this post-bootstrap
      // validation path; manual validation remains single-shot.
      await onValidateCloud(true);
    } catch (error) {
      // A profile that never granted consent, and an account that is not the
      // one this deployer is bound to, are both recoverable by the operator.
      // Say which it is instead of relaying the transport's wording.
      if (error instanceof ApiError && error.code === "consent-required") {
        setBootstrapError(copy.signInRequired);
      } else if (
        error instanceof ApiError && error.code === "operator-identity-changed"
      ) {
        setBootstrapError(copy.signInOperatorChanged);
      } else {
        setBootstrapError(
          error instanceof ApiError || error instanceof Error
            ? `${copy.bootstrapFailed}: ${error.message}`
            : copy.bootstrapFailed,
        );
      }
    } finally {
      setBootstrapBusy(false);
    }
  }

  async function handleSignIn() {
    setSignInBusy(true);
    setBootstrapError("");
    try {
      await signInSession();
    } catch (error) {
      setBootstrapError(
        error instanceof ApiError && error.code === "operator-identity-changed"
          ? copy.signInOperatorChanged
          : error instanceof Error
          ? `${copy.bootstrapFailed}: ${error.message}`
          : copy.bootstrapFailed,
      );
    } finally {
      setSignInBusy(false);
    }
  }

  function statusLabel(status: SetupState["cloudConnection"]) {
    if (status === "connected") return copy.connected;
    if (status === "checking") return copy.checking;
    if (status === "error") return copy.connectionFailed;
    return copy.connect;
  }

  return (
    <section className="workflow-step">
      <StepHeading description={copy.identitiesIntro} title={copy.identitiesTitle} />
      <div className="connection-grid">
        <article className="connection-card">
          <div className="connection-card-heading">
            <CloudIcon size={27} />
            <span>
              <strong>{copy.cloudAccount}</strong>
              <small>{copy.cloudAccountDescription}</small>
            </span>
          </div>
          <Field
            disabled={bootstrapBusy}
            label={copy.projectId}
            onChange={(projectId) => {
              setBootstrapResult(null);
              setBootstrapError("");
              onPatch({
                projectId,
                accessPolicyId: "",
                cloudConnection: "not_connected",
                cloudConnectionError: "",
              });
            }}
            placeholder="enterprise-secgw-01"
            value={state.projectId}
          />
          {runtimeCapabilities.sessionSignIn && (
            <>
              <button
                className="connection-action secondary"
                disabled={signInBusy || bootstrapBusy}
                onClick={() => void handleSignIn()}
                type="button"
              >
                <ShieldIcon size={18} />
                {signInBusy ? copy.signingInGoogle : copy.signInGoogle}
              </button>
              <small className="connection-help-hint">
                {copy.signInGoogleHint}
              </small>
            </>
          )}
          <button
            className="connection-action secondary"
            disabled={!state.projectId.trim() || bootstrapBusy || signInBusy}
            onClick={() => void handleBootstrap()}
            type="button"
          >
            <ShieldIcon size={18} />
            {bootstrapBusy
              ? (bootstrapResult ? copy.bootstrapValidating : copy.bootstrapWorking)
              : copy.bootstrapDeployer}
          </button>
          <small className="connection-help-hint">
            {copy.bootstrapDeployerHint}
          </small>
          {bootstrapResult && (
            <div className="bootstrap-result" role="status">
              <strong>{copy.bootstrapComplete}</strong>
              <small>{copy.bootstrapNext}</small>
              <code>{bootstrapResult.service_account_email}</code>
            </div>
          )}
          {bootstrapError && (
            <p className="connection-error" role="alert">
              {bootstrapError}
            </p>
          )}
          <Field
            label={copy.operatorIdentity}
            onChange={() => undefined}
            placeholder={copy.notConnected}
            readOnly
            value={state.cloudIdentity}
          />
          <button
            className="connection-action"
            disabled={
              !state.projectId.trim() || state.cloudConnection === "checking"
            }
            onClick={() => void onValidateCloud()}
            type="button"
          >
            {state.cloudConnection === "connected" ? (
              <CheckIcon size={18} />
            ) : (
              <CodeIcon size={18} />
            )}
            {statusLabel(state.cloudConnection)}
          </button>
          {state.cloudConnectionError && (
            <p className="connection-error" role="alert">
              {state.cloudConnectionError}
            </p>
          )}
        </article>

        <article className="connection-card">
          <div className="connection-card-heading">
            <UsersIcon size={27} />
            <span>
              <strong>{copy.workspaceAccount}</strong>
              <small>{copy.workspaceAccountDescription}</small>
            </span>
          </div>
          <Field
            label={copy.customerId}
            onChange={(customerId) =>
              onPatch({
                customerId,
                workspaceConnection: "not_connected",
                workspaceConnectionError: "",
              })
            }
            placeholder="C012abcde"
            value={state.customerId}
          />
          <Field
            label={copy.adminIdentity}
            onChange={() => undefined}
            placeholder={copy.notConnected}
            readOnly
            value={state.workspaceIdentity}
          />
          <button
            className="connection-action"
            disabled={
              !state.customerId.trim() || state.workspaceConnection === "checking"
            }
            onClick={() => void onValidateWorkspace()}
            type="button"
          >
            {state.workspaceConnection === "connected" ? (
              <CheckIcon size={18} />
            ) : (
              <CodeIcon size={18} />
            )}
            {statusLabel(state.workspaceConnection)}
          </button>
          <small className="connection-help-hint">
            {copy.workspaceRequiredRolesHint}
          </small>
          {state.workspaceConnectionError && (
            <p className="connection-error" role="alert">
              {state.workspaceConnectionError}
            </p>
          )}
        </article>
      </div>
      <Notice tone="security">{copy.connectionNotice}</Notice>
    </section>
  );
}

export function EnvironmentStep({ messages, onPatch, state }: StepProps) {
  const copy = messages.workflow;
  const [vpcNetworks, setVpcNetworks] = useState<CatalogState>(emptyCatalog);
  const [sampleImageBusy, setSampleImageBusy] = useState(false);
  const [sampleImageError, setSampleImageError] = useState("");
  const [sampleImageResolved, setSampleImageResolved] = useState("");
  const legacyNginxSelected = ["managed_sample", "existing_http"].includes(
    state.backendKind,
  );
  const usesDeploymentProjectVpc =
    state.backendKind !== "direct_https" || !state.upstreamVpcProjectId.trim();

  const loadVpcNetworks = useCallback(async () => {
    if (
      state.networkStrategy !== "existing" ||
      !runtimeCapabilities.vpcNetworkCatalog ||
      !usesDeploymentProjectVpc ||
      state.cloudConnection !== "connected" ||
      !isSupportedGoogleCloudProjectId(state.projectId)
    ) {
      setVpcNetworks(emptyCatalog);
      return;
    }
    setVpcNetworks({ items: [], loading: true, error: "" });
    try {
      setVpcNetworks({
        items: await listVpcNetworkOptions(state.projectId),
        loading: false,
        error: "",
      });
    } catch (error) {
      setVpcNetworks({
        items: [],
        loading: false,
        error: catalogError(error, copy.vpcOptionsFailed, copy.adcUnavailable),
      });
    }
  }, [
    copy.adcUnavailable,
    copy.vpcOptionsFailed,
    state.cloudConnection,
    state.networkStrategy,
    state.projectId,
    usesDeploymentProjectVpc,
  ]);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadVpcNetworks(), 250);
    return () => window.clearTimeout(timer);
  }, [loadVpcNetworks]);

  async function resolveSampleImage(): Promise<void> {
    if (
      state.sourceImage.trim() ||
      state.mode !== "poc" ||
      !runtimeCapabilities.recommendedPocSourceImage
    ) {
      return;
    }
    if (
      state.cloudConnection !== "connected" ||
      !isSupportedGoogleCloudProjectId(state.projectId)
    ) {
      setSampleImageError(copy.sampleImageConnectionRequired);
      return;
    }
    setSampleImageBusy(true);
    setSampleImageError("");
    setSampleImageResolved("");
    try {
      const option = await getRecommendedPocSourceImage(state.projectId);
      onPatch({ sourceImage: option.value });
      setSampleImageResolved(option.value);
    } catch (error) {
      setSampleImageError(
        catalogError(error, copy.sampleImageResolveFailed, copy.adcUnavailable),
      );
    } finally {
      setSampleImageBusy(false);
    }
  }

  async function selectInternalSampleVm() {
    onPatch({
      backendKind: "internal_https_lb",
      networkStrategy: "dedicated",
      proxySubnetCidr: state.proxySubnetCidr || "10.42.1.0/24",
      privateHostname: state.privateHostname || "secgw-backend.internal",
      deploymentName:
        state.deploymentName === "secure-gateway-http-offload" ||
        state.deploymentName === "secure-gateway-private-https"
          ? "secure-gateway-ilb-https-offload"
          : state.deploymentName,
      existingBackendUrl: "",
      existingBackendConnectivityConfirmed: false,
    });
    await resolveSampleImage();
  }

  async function selectManagedSampleVm() {
    onPatch({
      backendKind: "managed_sample",
      privateHostname: state.privateHostname || "secgw-backend.internal",
      deploymentName:
        state.deploymentName === "secure-gateway-ilb-https-offload" ||
        state.deploymentName === "secure-gateway-private-https"
          ? "secure-gateway-http-offload"
          : state.deploymentName,
      existingBackendUrl: "",
      existingBackendConnectivityConfirmed: false,
    });
    await resolveSampleImage();
  }

  return (
    <section className="workflow-step">
      <StepHeading description={copy.environmentIntro} title={copy.environmentTitle} />
      <div className="field-grid three">
        <Field
          label={copy.deploymentName}
          onChange={(deploymentName) => onPatch({ deploymentName })}
          value={state.deploymentName}
        />
        <label className="field">
          <span>{copy.region}</span>
          <input
            autoComplete="off"
            list="gcp-regions-list"
            onChange={(event) => {
              const newRegion = event.target.value;
              const currentRegion = state.region;
              const patch: Partial<SetupState> = { region: newRegion };
              if (!state.zone || (currentRegion && state.zone.startsWith(`${currentRegion}-`))) {
                patch.zone = `${newRegion}-b`;
              }
              if (!state.secondaryZone || (currentRegion && state.secondaryZone.startsWith(`${currentRegion}-`))) {
                patch.secondaryZone = `${newRegion}-c`;
              }
              onPatch(patch);
            }}
            placeholder="asia-northeast1"
            spellCheck={false}
            value={state.region}
          />
          <datalist id="gcp-regions-list">
            <option value="asia-northeast1">asia-northeast1 (Tokyo / 東京)</option>
            <option value="asia-northeast2">asia-northeast2 (Osaka / 大阪)</option>
            <option value="asia-northeast3">asia-northeast3 (Seoul / ソウル)</option>
            <option value="asia-east1">asia-east1 (Taiwan / 台湾)</option>
            <option value="asia-east2">asia-east2 (Hong Kong / 香港)</option>
            <option value="asia-southeast1">asia-southeast1 (Singapore / シンガポール)</option>
            <option value="us-central1">us-central1 (Iowa)</option>
            <option value="us-east1">us-east1 (South Carolina)</option>
            <option value="us-east4">us-east4 (N. Virginia)</option>
            <option value="us-west1">us-west1 (Oregon)</option>
            <option value="europe-west1">europe-west1 (Belgium)</option>
            <option value="europe-west3">europe-west3 (Frankfurt)</option>
          </datalist>
        </label>
        <label className="field">
          <span>{copy.zone}</span>
          <input
            autoComplete="off"
            list="gcp-zones-list"
            onChange={(event) => onPatch({ zone: event.target.value })}
            placeholder="asia-northeast1-b"
            spellCheck={false}
            value={state.zone}
          />
          <datalist id="gcp-zones-list">
            <option value={`${state.region || "asia-northeast1"}-a`} />
            <option value={`${state.region || "asia-northeast1"}-b`} />
            <option value={`${state.region || "asia-northeast1"}-c`} />
          </datalist>
        </label>
        {state.mode === "production" && (
          <label className="field">
            <span>{copy.secondaryZone}</span>
            <input
              autoComplete="off"
              list="gcp-secondary-zones-list"
              onChange={(event) =>
                onPatch({ secondaryZone: event.target.value })
              }
              placeholder="asia-northeast1-c"
              spellCheck={false}
              value={state.secondaryZone}
            />
            <datalist id="gcp-secondary-zones-list">
              <option value={`${state.region || "asia-northeast1"}-a`} />
              <option value={`${state.region || "asia-northeast1"}-b`} />
              <option value={`${state.region || "asia-northeast1"}-c`} />
            </datalist>
          </label>
        )}
      </div>
      {state.backendKind !== "direct_https" && (
        <div className="field-grid one">
          <Field
            label={copy.sourceImage}
            onChange={(sourceImage) => onPatch({ sourceImage })}
            placeholder="projects/my-image-project/global/images/sgs-nginx-20260730"
            value={state.sourceImage}
          />
          <small className="field-hint">
            {runtimeCapabilities.recommendedPocSourceImage && state.mode === "poc"
              ? copy.sourceImageAutoHint
              : copy.sourceImageHint}
          </small>
        </div>
      )}
      {state.mode === "production" &&
        !["direct_https", "internal_https_lb"].includes(state.backendKind) && (
        <>
          <div className="field-grid three">
            <Field
              label={copy.minimumReplicas}
              min={2}
              onChange={(offloadMinReplicas) =>
                onPatch({ offloadMinReplicas })
              }
              type="number"
              value={state.offloadMinReplicas}
            />
            <Field
              label={copy.maximumReplicas}
              max={1000}
              min={2}
              onChange={(offloadMaxReplicas) =>
                onPatch({ offloadMaxReplicas })
              }
              type="number"
              value={state.offloadMaxReplicas}
            />
            <Field
              label={copy.cpuTarget}
              max={0.9}
              min={0.1}
              onChange={(offloadCpuTarget) => onPatch({ offloadCpuTarget })}
              step={0.05}
              type="number"
              value={state.offloadCpuTarget}
            />
          </div>
          <small className="field-hint">{copy.autoscalingHint}</small>
        </>
      )}

      {state.networkStrategy === "existing" && (
        <>
          <div className="field-grid two">
            {usesDeploymentProjectVpc && runtimeCapabilities.vpcNetworkCatalog ? (
              <CatalogSelect
                catalog={vpcNetworks}
                emptyLabel={copy.noOptions}
                label={copy.vpcName}
                loadingLabel={copy.optionsLoading}
                onChange={(vpcName) =>
                  onPatch(
                    state.backendKind === "direct_https"
                      ? { vpcName, existingBackendConnectivityConfirmed: false }
                      : { vpcName },
                  )
                }
                onRetry={() => void loadVpcNetworks()}
                placeholder={copy.chooseOption}
                retryLabel={copy.retryOptions}
                value={state.vpcName}
              />
            ) : (
              <Field
                label={copy.vpcName}
                onChange={(vpcName) =>
                  onPatch({ vpcName, existingBackendConnectivityConfirmed: false })
                }
                value={state.vpcName}
              />
            )}
            {state.backendKind === "direct_https" ? (
              <Field
                label={copy.upstreamVpcProjectId}
                onChange={(upstreamVpcProjectId) =>
                  onPatch({
                    upstreamVpcProjectId,
                    existingBackendConnectivityConfirmed: false,
                  })
                }
                placeholder={state.projectId || "upstream-network-project"}
                value={state.upstreamVpcProjectId}
              />
            ) : (
              <Field
                label={copy.subnetName}
                onChange={(subnetName) => onPatch({ subnetName })}
                value={state.subnetName}
              />
            )}
          </div>
          {state.backendKind === "direct_https" ? (
            <small className="field-hint">{copy.upstreamVpcProjectIdHint}</small>
          ) : null}
          {usesDeploymentProjectVpc && runtimeCapabilities.vpcNetworkCatalog ? (
            <small className="field-hint">{copy.vpcSameProjectHint}</small>
          ) : null}
          {state.backendKind === "direct_https" &&
          state.upstreamVpcProjectId.trim() ? (
            <Notice tone="security">
              {copy.upstreamVpcCrossProjectPrerequisite}
            </Notice>
          ) : null}
        </>
      )}

      <h3 className="subsection-title">{copy.network}</h3>
      <div className="mode-grid backend-grid">
        <ChoiceCard
          description={copy.directHttpsDescription}
          cost={messages.guide.architectures[0].estimatedCost}
          icon={<ShieldIcon size={27} />}
          onSelect={() =>
            onPatch({
              backendKind: "direct_https",
              networkStrategy: "existing",
              privateHostname: "secgw-backend.internal",
              region: state.region || "asia-northeast1",
              applicationEgressRegion:
                state.applicationEgressRegion || state.region || "asia-northeast1",
              deploymentName:
                state.deploymentName === "secure-gateway-http-offload" ||
                state.deploymentName === "secure-gateway-ilb-https-offload"
                  ? "secure-gateway-private-https"
                  : state.deploymentName,
              existingBackendConnectivityConfirmed: false,
              existingBackendUrl: state.existingBackendUrl.startsWith("https://")
                ? state.existingBackendUrl
                : "https://secgw-backend.internal",
            })
          }
          selected={state.backendKind === "direct_https"}
          title={copy.directHttps}
        />
        {runtimeCapabilities.internalHttpsLbArchitecture && state.mode === "poc" ? (
          <ChoiceCard
            description={copy.internalHttpsLbDescription}
            cost={messages.guide.architectures[1].estimatedCost}
            icon={<ShieldIcon size={27} />}
            onSelect={selectInternalSampleVm}
            selected={state.backendKind === "internal_https_lb"}
            title={copy.internalHttpsLb}
          />
        ) : null}
      </div>

      <details className="legacy-options" open={legacyNginxSelected || undefined}>
        <summary>
          <span>
            <strong>{copy.legacyNginxTitle}</strong>
            <small>{copy.legacyNginxDescription}</small>
          </span>
        </summary>
        <div className="mode-grid legacy-backend-grid">
          <ChoiceCard
            description={copy.managedSampleDescription}
            cost={messages.guide.architectures[2].estimatedCost}
            icon={<NetworkIcon size={27} />}
            onSelect={selectManagedSampleVm}
            selected={state.backendKind === "managed_sample"}
            title={copy.managedSample}
          />
          <ChoiceCard
            description={copy.existingBackendDescription}
            cost={messages.guide.architectures[2].estimatedCost}
            icon={<NetworkIcon size={27} />}
            onSelect={() =>
              onPatch({
                backendKind: "existing_http",
                deploymentName:
                  state.deploymentName === "secure-gateway-ilb-https-offload" ||
                  state.deploymentName === "secure-gateway-private-https"
                    ? "secure-gateway-http-offload"
                    : state.deploymentName,
                existingBackendUrl: state.existingBackendUrl.startsWith("http://")
                  ? state.existingBackendUrl
                  : "",
                existingBackendConnectivityConfirmed: false,
              })
            }
            selected={state.backendKind === "existing_http"}
            title={copy.existingBackend}
          />
        </div>
      </details>

      {(() => {
        const activeArchitecture =
          state.backendKind === "direct_https"
            ? messages.guide.architectures[0]
            : state.backendKind === "internal_https_lb"
              ? messages.guide.architectures[1]
              : messages.guide.architectures[2];
        return (
          <div
            className="step-architecture-preview"
            role="region"
            aria-label={activeArchitecture.title}
          >
            <div className="step-architecture-header">
              <span className="step-architecture-eyebrow">
                {activeArchitecture.eyebrow}
              </span>
              <h4>{activeArchitecture.title}</h4>
              <p>{activeArchitecture.summary}</p>
            </div>
            <div className="step-architecture-cost-pill">
              <strong>💰 {activeArchitecture.estimatedCost}</strong>
              <span>({activeArchitecture.costFixed} · {activeArchitecture.costVariable})</span>
            </div>
            <div className="architecture-flow" role="list">
              {activeArchitecture.nodes.map((node, index) => (
                <div
                  className="architecture-flow-item"
                  key={node.label}
                  role="listitem"
                >
                  <div className="architecture-node">
                    {node.costBadge && (
                      <span className="node-cost-badge">{node.costBadge}</span>
                    )}
                    <strong>{node.label}</strong>
                    <small>{node.detail}</small>
                  </div>
                  {index < activeArchitecture.nodes.length - 1 ? (
                    <span className="architecture-arrow" aria-hidden="true">
                      <i />
                    </span>
                  ) : null}
                </div>
              ))}
            </div>
            <div className="architecture-supports step-architecture-supports">
              {activeArchitecture.supports.map((support) => (
                <div className="architecture-support" key={support.label}>
                  <span aria-hidden="true" />
                  <div>
                    <strong>{support.label}</strong>
                    <small>{support.detail}</small>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })()}

      {state.backendKind === "direct_https" ? (
        <article className="sample-backend-box">
          <div className="sample-backend-header">
            <div>
              <strong>{copy.directSampleVmAction}</strong>
              <p>{copy.directSampleVmDescription}</p>
            </div>
            <button
              className="connection-action"
              disabled={sampleImageBusy}
              onClick={() => void selectInternalSampleVm()}
              type="button"
            >
              {sampleImageBusy ? copy.sampleImageResolving : copy.directSampleVmAction}
            </button>
          </div>
        </article>
      ) : null}
      {state.backendKind === "managed_sample" ? (
        <article className="sample-backend-box">
          <div className="sample-backend-header">
            <div>
              <strong>{copy.managedSampleVmAction}</strong>
              <p>{copy.managedSampleVmDescription}</p>
            </div>
            <button
              className="connection-action"
              disabled={sampleImageBusy}
              onClick={() => void selectManagedSampleVm()}
              type="button"
            >
              {sampleImageBusy ? copy.sampleImageResolving : copy.managedSampleVmAction}
            </button>
          </div>
        </article>
      ) : null}
      {state.backendKind === "existing_http" ? (
        <article className="sample-backend-box">
          <div className="sample-backend-header">
            <div>
              <strong>{copy.managedSampleVmAction}</strong>
              <p>{copy.existingSampleVmDescription}</p>
            </div>
            <button
              className="connection-action"
              disabled={sampleImageBusy}
              onClick={() => void selectManagedSampleVm()}
              type="button"
            >
              {sampleImageBusy ? copy.sampleImageResolving : copy.managedSampleVmAction}
            </button>
          </div>
        </article>
      ) : null}
      {sampleImageResolved ? (
        <p className="plan-result pass" role="status">
          <CheckIcon size={18} />
          <span>
            <strong>{copy.sampleImageResolved}</strong>
            <small>{sampleImageResolved}</small>
          </span>
        </p>
      ) : null}

      <div className="field-grid two">
        {state.backendKind !== "direct_https" ? (
          <Field
            label={copy.hostname}
            onChange={(privateHostname) => onPatch({ privateHostname })}
            value={state.privateHostname}
          />
        ) : null}
        {!["managed_sample", "internal_https_lb"].includes(state.backendKind) ? (
          <label className="field">
            <span>{copy.backendLocation}</span>
            <select
              onChange={(event) =>
                onPatch({
                  existingBackendLocation: event.target.value as BackendLocation,
                  existingBackendConnectivityConfirmed: false,
                })
              }
              value={state.existingBackendLocation}
            >
              <option value="gcp">{copy.backendLocationGcp}</option>
              <option value="aws">{copy.backendLocationAws}</option>
              <option value="azure">{copy.backendLocationAzure}</option>
              <option value="on_prem">{copy.backendLocationOnPrem}</option>
            </select>
          </label>
        ) : null}
      </div>
      {state.backendKind === "existing_http" && (
        <>
          <div className="field-grid one">
            <Field
              label={copy.backendUrl}
              onChange={(existingBackendUrl) => onPatch({ existingBackendUrl })}
              placeholder="http://10.10.0.10:8080"
              value={state.existingBackendUrl}
            />
          </div>
          <label className="confirmation-row">
            <input
              checked={state.existingBackendConnectivityConfirmed}
              onChange={(event) =>
                onPatch({
                  existingBackendConnectivityConfirmed: event.target.checked,
                })
              }
              type="checkbox"
            />
            <span>{copy.confirmBackendConnectivity}</span>
          </label>
          <small className="field-hint">{copy.backendConnectivityHint}</small>
        </>
      )}
      {state.backendKind === "internal_https_lb" && (
        <>
          <article className="sample-backend-box">
            <div className="sample-backend-header">
              <div>
                <strong>{copy.configureSampleVm}</strong>
                <p>{copy.configureSampleVmDescription}</p>
              </div>
              <button
                className="connection-action"
                disabled={sampleImageBusy}
                onClick={() => void selectInternalSampleVm()}
                type="button"
              >
                {sampleImageBusy ? copy.sampleImageResolving : copy.configureSampleVm}
              </button>
            </div>
          </article>
          <div className="field-grid one">
            <Field
              label={copy.proxySubnetCidr}
              onChange={(proxySubnetCidr) => onPatch({ proxySubnetCidr })}
              placeholder="10.42.1.0/24"
              value={state.proxySubnetCidr}
            />
          </div>
        </>
      )}
      {sampleImageError ? (
        <p className="connection-error" role="alert">{sampleImageError}</p>
      ) : null}
      {state.backendKind === "direct_https" ? (
        <>
          <div className="field-grid two">
            <Field
              label={copy.directHttpsUrl}
              onChange={(existingBackendUrl) =>
                onPatch({
                  existingBackendUrl,
                  existingBackendConnectivityConfirmed: false,
                })
              }
              placeholder="https://app.corp.internal:443"
              value={state.existingBackendUrl}
            />
            <Field
              label={copy.applicationEgressRegion}
              onChange={(applicationEgressRegion) =>
                onPatch({ applicationEgressRegion })
              }
              placeholder="asia-east1"
              value={state.applicationEgressRegion}
            />
          </div>
          <small className="field-hint">{copy.applicationEgressRegionHint}</small>
          <label className="confirmation-row">
            <input
              checked={state.existingBackendConnectivityConfirmed}
              onChange={(event) =>
                onPatch({
                  existingBackendConnectivityConfirmed: event.target.checked,
                })
              }
              type="checkbox"
            />
            <span>{copy.directHttpsConnectivity}</span>
          </label>
          <small className="field-hint">{copy.directHttpsConnectivityHint}</small>
        </>
      ) : null}

      {state.backendKind !== "direct_https" ? (
        <Notice tone="security">{copy.noExternalIpNotice}</Notice>
      ) : null}
    </section>
  );
}

export function CertificateStep({ messages, onPatch, state }: StepProps) {
  const copy = messages.workflow;

  return (
    <section className="workflow-step">
      <StepHeading
        description={
          state.backendKind === "direct_https"
            ? copy.directCertificateIntro
            : state.backendKind === "internal_https_lb"
              ? copy.internalLbCertificateIntro
            : copy.certificateIntro
        }
        title={copy.certificateStepTitle}
      />
      <div className="summary-selection">
        <ShieldIcon size={25} />
        <span>
          <small>{messages.certificateStrategy}</small>
          <strong>
            {state.backendKind === "direct_https" &&
            state.certificateStrategy !== "public_trusted"
              ? copy.directPrivateCertificate
              : state.certificateStrategy === "enterprise_ca"
              ? messages.enterpriseCa
              : state.certificateStrategy === "public_trusted"
                ? messages.publicCertificate
                : messages.localPocCa}
          </strong>
        </span>
      </div>
      {state.backendKind === "direct_https" ? (
        <Notice tone="security">{copy.directCertificateNotice}</Notice>
      ) : null}
      {state.backendKind !== "direct_https" &&
        state.certificateStrategy === "enterprise_ca" && (
        <div className="field-grid two">
          <Field
            label={copy.caPool}
            onChange={(caPool) => onPatch({ caPool })}
            placeholder={`projects/${state.projectId || "{projectId}"}/locations/{location}/caPools/{pool}`}
            value={state.caPool}
          />
          <Field
            label={copy.caName}
            onChange={(caName) => onPatch({ caName })}
            placeholder={`projects/${state.projectId || "{projectId}"}/locations/{location}/caPools/{pool}/certificateAuthorities/{authority}`}
            value={state.caName}
          />
        </div>
      )}
      {state.backendKind !== "direct_https" &&
        state.certificateStrategy === "public_trusted" && (
        <>
          <div className="field-grid one">
            <Field
              label={copy.secretName}
              onChange={(publicCertificateSecret) =>
                onPatch({ publicCertificateSecret })
              }
              placeholder="projects/.../secrets/secgw-tls"
              value={state.publicCertificateSecret}
            />
          </div>
          <Notice tone="security">{messages.publicCertificateDescription}</Notice>
        </>
      )}
      {state.backendKind !== "direct_https" &&
        state.certificateStrategy === "local_poc" && (
        <Notice>{messages.localPocCaDescription}</Notice>
      )}
      {state.backendKind !== "direct_https" ? (
        <Notice tone="security">
          {state.backendKind === "internal_https_lb"
            ? copy.internalLbCertificateNotice
            : copy.certificateNotice}
        </Notice>
      ) : null}
    </section>
  );
}

function updatePrincipal(
  principals: AccessPrincipal[],
  id: string,
  patch: Partial<AccessPrincipal>,
) {
  return principals.map((principal) =>
    principal.id === id ? { ...principal, ...patch } : principal,
  );
}

function catalogError(
  reason: unknown,
  fallback: string,
  adcUnavailable: string,
): string {
  return reason instanceof ApiError && reason.code === "adc-unavailable"
    ? adcUnavailable
    : fallback;
}

export function AccessStep({ messages, onPatch, state }: StepProps) {
  const copy = messages.workflow;
  const [organizationalUnits, setOrganizationalUnits] =
    useState<CatalogState>(emptyCatalog);
  const [accessLevels, setAccessLevels] =
    useState<CatalogState>(emptyCatalog);
  const [groups, setGroups] = useState<CatalogState>(emptyCatalog);

  const loadOptions = useCallback(async () => {
    if (
      state.cloudConnection !== "connected" ||
      state.workspaceConnection !== "connected"
    ) {
      return;
    }
    setOrganizationalUnits({ items: [], loading: true, error: "" });
    setAccessLevels({ items: [], loading: true, error: "" });
    setGroups({ items: [], loading: true, error: "" });

    const [ouResult, accessLevelResult, groupResult] = await Promise.allSettled([
      listOrganizationalUnitOptions(state.customerId),
      listAccessLevelOptions(state.projectId),
      listGroupOptions(state.customerId),
    ]);
    if (ouResult.status === "fulfilled") {
      const rootIds = new Set(
        ouResult.value
          .filter(
            (item) =>
              item.label.trim() === "/" || item.description?.trim() === "/",
          )
          .map((item) => item.value),
      );
      if (rootIds.has(state.targetOuId)) {
        onPatch({ targetOuId: "", testOuConfirmed: false });
      }
      setOrganizationalUnits({
        items: ouResult.value.filter((item) => !rootIds.has(item.value)),
        loading: false,
        error: "",
      });
    } else {
      setOrganizationalUnits({
            items: [],
            loading: false,
            error: catalogError(
              ouResult.reason,
              copy.ouOptionsFailed,
              copy.adcUnavailable,
            ),
      });
    }
    const rawAccessLevels =
      accessLevelResult.status === "fulfilled" ? accessLevelResult.value : [];
    const noAccessLevel: SetupOption = {
      value: "NONE",
      label: copy.managedChromeAccessLevelNone,
      description: copy.managedChromeAccessLevelNoneHint,
    };
    const uniqueAccessLevels = Array.from(
      new Map(
        [
          noAccessLevel,
          ...rawAccessLevels.filter(
            (item) =>
              item.value !== "NONE" &&
              isSupportedManagedChromeAccessLevel(item.value),
          ),
        ].map((item) => [item.value, item]),
      ).values(),
    );
    setAccessLevels(
      accessLevelResult.status === "fulfilled"
        ? { items: uniqueAccessLevels, loading: false, error: "" }
        : {
            items: [noAccessLevel],
            loading: false,
            error: catalogError(
              accessLevelResult.reason,
              copy.accessLevelOptionsFailed,
              copy.adcUnavailable,
            ),
          },
    );
    setGroups(
      groupResult.status === "fulfilled"
        ? { items: groupResult.value, loading: false, error: "" }
        : {
            items: [],
            loading: false,
            error: catalogError(
              groupResult.reason,
              copy.groupOptionsFailed,
              copy.adcUnavailable,
            ),
          },
    );
  }, [
    copy.adcUnavailable,
    copy.accessLevelOptionsFailed,
    copy.groupOptionsFailed,
    copy.managedChromeAccessLevelNone,
    copy.managedChromeAccessLevelNoneHint,
    copy.ouOptionsFailed,
    state.cloudConnection,
    state.customerId,
    state.projectId,
    state.workspaceConnection,
  ]);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadOptions(), 250);
    return () => window.clearTimeout(timer);
  }, [loadOptions]);

  function addPrincipal() {
    const principal: AccessPrincipal = {
      id: `principal-${Date.now()}`,
      type: "group",
      value: "",
    };
    onPatch({ principals: [...state.principals, principal] });
  }

  function removePrincipal(id: string) {
    if (state.principals.length === 1) return;
    onPatch({
      principals: state.principals.filter((principal) => principal.id !== id),
    });
  }

  return (
    <section className="workflow-step">
      <StepHeading description={copy.accessIntro} title={copy.accessTitle} />
      <small className="field-hint catalog-intro">{copy.optionsLoadedHint}</small>
      <div className="field-grid one">
        <CatalogSelect
          catalog={organizationalUnits}
          emptyLabel={copy.noOptions}
          label={copy.targetOuId}
          loadingLabel={copy.optionsLoading}
          onChange={(targetOuId) =>
            onPatch({
              targetOuId,
              testOuConfirmed: false,
            })
          }
          onRetry={() => void loadOptions()}
          placeholder={copy.chooseOption}
          retryLabel={copy.retryOptions}
          value={state.targetOuId}
        />
        <CatalogSelect
          catalog={accessLevels}
          emptyLabel={copy.noOptions}
          label={copy.managedChromeAccessLevel}
          loadingLabel={copy.optionsLoading}
          onChange={(managedChromeAccessLevel) =>
            onPatch({ managedChromeAccessLevel })
          }
          onRetry={() => void loadOptions()}
          placeholder={copy.chooseOption}
          retryLabel={copy.retryOptions}
          value={
            isSupportedManagedChromeAccessLevel(state.managedChromeAccessLevel)
              ? state.managedChromeAccessLevel
              : ""
          }
        />
        <small className="field-hint">{copy.managedChromeAccessLevelHint}</small>
      </div>
      <label className="confirmation-row">
        <input
          checked={state.testOuConfirmed}
          disabled={!state.targetOuId.trim()}
          onChange={(event) =>
            onPatch({ testOuConfirmed: event.target.checked })
          }
          type="checkbox"
        />
        <span>{copy.confirmTestOu}</span>
      </label>
      <div className="prerequisite-checks">
        <h3>{copy.prerequisitesTitle}</h3>
        <label className="confirmation-row">
          <input
            checked={state.chromeEnterprisePremiumLicenseConfirmed}
            onChange={(event) =>
              onPatch({
                chromeEnterprisePremiumLicenseConfirmed: event.target.checked,
              })
            }
            type="checkbox"
          />
          <span>{copy.confirmEnterpriseLicense}</span>
        </label>
        <label className="confirmation-row">
          <input
            checked={state.workspaceServicesConfirmed}
            onChange={(event) =>
              onPatch({ workspaceServicesConfirmed: event.target.checked })
            }
            type="checkbox"
          />
          <span>{copy.confirmWorkspaceServices}</span>
        </label>
        {state.mode === "production" && (
          <label className="confirmation-row">
            <input
              checked={state.endpointVerificationConfirmed}
              onChange={(event) =>
                onPatch({ endpointVerificationConfirmed: event.target.checked })
              }
              type="checkbox"
            />
            <span>{copy.confirmEndpointVerification}</span>
          </label>
        )}
      </div>

      <div className="principal-heading">
        <h3>{copy.principalValue}</h3>
        <button className="text-action" onClick={addPrincipal} type="button">
          + {copy.addPrincipal}
        </button>
      </div>
      <div className="principal-list">
        {state.principals.map((principal) => (
          <div className="principal-row" key={principal.id}>
            <label className="field compact">
              <span>{copy.principalType}</span>
              <select
                onChange={(event) =>
                  onPatch({
                    principals: updatePrincipal(
                      state.principals,
                      principal.id,
                      {
                        type: event.target.value as PrincipalType,
                        value: "",
                      },
                    ),
                  })
                }
                value={principal.type}
              >
                <option value="user">{copy.user}</option>
                <option value="group">{copy.group}</option>
                <option value="domain">{copy.domain}</option>
              </select>
            </label>
            {principal.type === "group" ? (
              <CatalogSelect
                catalog={groups}
                emptyLabel={copy.noOptions}
                label={copy.principalValue}
                loadingLabel={copy.optionsLoading}
                onChange={(value) =>
                  onPatch({
                    principals: updatePrincipal(
                      state.principals,
                      principal.id,
                      { value },
                    ),
                  })
                }
                onRetry={() => void loadOptions()}
                placeholder={copy.chooseOption}
                retryLabel={copy.retryOptions}
                value={principal.value}
              />
            ) : (
              <Field
                label={copy.principalValue}
                onChange={(value) =>
                  onPatch({
                    principals: updatePrincipal(
                      state.principals,
                      principal.id,
                      { value },
                    ),
                  })
                }
                placeholder={
                  principal.type === "domain" ? "example.com" : "user@example.com"
                }
                value={principal.value}
              />
            )}
            <button
              className="remove-action"
              disabled={state.principals.length === 1}
              onClick={() => removePrincipal(principal.id)}
              type="button"
            >
              {copy.removePrincipal}
            </button>
          </div>
        ))}
      </div>
      <Notice tone="security">{copy.accessNotice}</Notice>
    </section>
  );
}

export function isIdentitiesReady(state: SetupState): boolean {
  return (
    state.cloudConnection === "connected" &&
    state.workspaceConnection === "connected"
  );
}

export function isEnvironmentReady(
  state: SetupState,
  internalHttpsLbArchitecture = true,
): boolean {
  const minimumReplicas = Number(state.offloadMinReplicas);
  const maximumReplicas = Number(state.offloadMaxReplicas);
  const cpuTarget = Number(state.offloadCpuTarget);
  const scalingIsValid =
    Number.isInteger(minimumReplicas) &&
    Number.isInteger(maximumReplicas) &&
    minimumReplicas >= 2 &&
    maximumReplicas >= minimumReplicas &&
    maximumReplicas <= 1000 &&
    cpuTarget >= 0.1 &&
    cpuTarget <= 0.9;

  return (
    (internalHttpsLbArchitecture || state.backendKind !== "internal_https_lb") &&
    !(state.mode === "production" && state.backendKind === "internal_https_lb") &&
    Boolean(
      state.deploymentName &&
        state.region &&
        state.zone &&
        (state.backendKind === "direct_https" ||
          (state.sourceImage &&
            (state.mode === "poc" ||
              (state.secondaryZone &&
                state.secondaryZone !== state.zone &&
                scalingIsValid)))) &&
        (state.backendKind === "direct_https" || state.privateHostname),
    ) &&
    (state.backendKind !== "internal_https_lb" || Boolean(state.proxySubnetCidr)) &&
    (state.backendKind === "direct_https"
      ? state.networkStrategy === "existing" &&
        Boolean(state.vpcName) &&
        (!state.upstreamVpcProjectId.trim() ||
          isSupportedGoogleCloudProjectId(state.upstreamVpcProjectId))
      : state.networkStrategy === "dedicated" ||
        Boolean(state.vpcName && state.subnetName)) &&
    (state.backendKind === "managed_sample" ||
      state.backendKind === "internal_https_lb" ||
      (state.backendKind === "existing_http" &&
        state.existingBackendUrl.startsWith("http://") &&
        state.existingBackendConnectivityConfirmed) ||
      (state.backendKind === "direct_https" &&
        state.existingBackendUrl.startsWith("https://") &&
        state.existingBackendConnectivityConfirmed))
  );
}

export function isCertificateReady(state: SetupState): boolean {
  return (
    state.backendKind === "direct_https" ||
    state.certificateStrategy === "local_poc" ||
    (state.certificateStrategy === "enterprise_ca"
      ? Boolean(state.caPool && state.caName)
      : Boolean(state.publicCertificateSecret) &&
        isPublicTrustedHostnameCandidate(state.privateHostname))
  );
}

export function isAccessReady(state: SetupState): boolean {
  return (
    Boolean(state.customerId) &&
    Boolean(state.targetOuId) &&
    isSupportedManagedChromeAccessLevel(state.managedChromeAccessLevel) &&
    (state.mode === "poc" ||
      (state.chromeEnterprisePremiumLicenseConfirmed &&
        state.workspaceServicesConfirmed &&
        state.endpointVerificationConfirmed)) &&
    state.testOuConfirmed &&
    state.principals.length > 0 &&
    state.principals.every((principal) => principal.value.trim().length >= 3)
  );
}

export function isConfigurationReady(state: SetupState): boolean {
  return (
    isIdentitiesReady(state) &&
    isEnvironmentReady(state) &&
    isCertificateReady(state) &&
    isAccessReady(state)
  );
}

export function ReviewStep({
  approval,
  busy,
  error,
  messages,
  onApprove,
  onPrepare,
  preparedPlan,
  state,
}: ReviewStepProps) {
  const copy = messages.workflow;
  const gatesReady =
    preparedPlan?.plan.gates.every(
      (gate) =>
        !gate.blocking ||
        gate.gate_id === "human-approval" ||
        gate.status === "pass",
    ) ?? false;

  const [preflightProgress, setPreflightProgress] = useState(0);
  const [preflightStage, setPreflightStage] = useState(1);

  useEffect(() => {
    if (!busy || preparedPlan) {
      if (preparedPlan) {
        setPreflightProgress(100);
      }
      return;
    }
    setPreflightProgress(15);
    setPreflightStage(1);
    const t1 = setTimeout(() => {
      setPreflightProgress(35);
      setPreflightStage(2);
    }, 600);
    const t2 = setTimeout(() => {
      setPreflightProgress(60);
      setPreflightStage(3);
    }, 1300);
    const t3 = setTimeout(() => {
      setPreflightProgress(80);
      setPreflightStage(4);
    }, 2000);
    const t4 = setTimeout(() => {
      setPreflightProgress(92);
      setPreflightStage(5);
    }, 2800);
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
    };
  }, [busy, preparedPlan]);

  const plannedChanges =
    preparedPlan?.plan.changes.filter(
      (change) => change.action === "create" || change.action === "update",
    ) ?? [];

  function isAutomaticOnApply(gate: DeploymentGate): boolean {
    if (gate.gate_id === "required-apis") {
      return gate.detail.includes("must be enabled during Apply");
    }
    if (gate.gate_id === "private-egress") {
      return plannedChanges.some((change) => change.resource_type === "cloud_nat");
    }
    if (gate.gate_id === "no-external-ips") {
      return plannedChanges.some(
        (change) =>
          change.resource_type === "instance" ||
          change.resource_type === "instance_template",
      );
    }
    if (gate.gate_id === "endpoint-verification") {
      return plannedChanges.some(
        (change) =>
          change.resource_type === "extension_install" &&
          change.resource_name === "callobklhcbilhphinckomhgkigmfocg",
      );
    }
    return false;
  }

  function gatePresentation(gate: DeploymentGate): {
    label: string;
    tone: "pass" | "planned" | "manual" | "blocked";
  } {
    if (gate.gate_id === "human-approval") {
      return approval
        ? { label: copy.verified, tone: "pass" }
        : { label: copy.approvalPending, tone: "manual" };
    }
    if (isAutomaticOnApply(gate)) {
      return { label: copy.plannedOnApply, tone: "planned" };
    }
    if (gate.status === "pass") {
      return { label: copy.verified, tone: "pass" };
    }
    if (!gate.blocking) {
      return { label: copy.manualCheck, tone: "manual" };
    }
    return { label: copy.actionRequired, tone: "blocked" };
  }

  function gateLabel(gate: DeploymentGate): string {
    return copy.gateLabels[gate.gate_id] ?? gate.title;
  }

  function gateDescription(gate: DeploymentGate): string {
    const snapshot = preparedPlan?.preflight.snapshot;
    if (gate.gate_id === "managed-chrome-profile" && snapshot) {
      return copy.managedProfileEvidence(
        snapshot.managed_chrome_profile_count ?? 0,
        snapshot.profile_only_count ?? 0,
        snapshot.latest_chrome_policy_sync,
      );
    }
    if (gate.gate_id === "secure-enterprise-browser-client" && snapshot) {
      return copy.clientExtensionEvidence(
        "Secure Enterprise Browser",
        snapshot.secure_enterprise_browser_version,
        snapshot.secure_enterprise_browser_installed === true,
      );
    }
    if (gate.gate_id === "endpoint-verification" && snapshot) {
      return copy.clientExtensionEvidence(
        "Endpoint Verification",
        snapshot.endpoint_verification_version,
        snapshot.endpoint_verification_installed === true,
      );
    }
    if (gate.status !== "pass" && gate.detail) {
      return gate.detail;
    }
    return copy.gateDescriptions[gate.gate_id] ?? gate.detail;
  }

  return (
    <section className="workflow-step">
      <StepHeading description={copy.reviewIntro} title={copy.reviewTitle} />
      <div className="review-grid">
        <article className="review-card">
          <h3>{copy.configuration}</h3>
          <dl className="review-list">
            <div>
              <dt>{messages.mode}</dt>
              <dd>{state.mode === "production" ? messages.production : messages.poc}</dd>
            </div>
            <div>
              <dt>{copy.projectId}</dt>
              <dd>{state.projectId || "—"}</dd>
            </div>
            <div>
              <dt>{messages.infrastructure}</dt>
              <dd>
                {state.networkStrategy === "dedicated"
                  ? messages.dedicatedNetwork
                  : state.vpcName || messages.existingVpc}
              </dd>
            </div>
            {state.backendKind === "direct_https" ? (
              <div>
                <dt>{copy.upstreamVpcProjectId}</dt>
                <dd>{state.upstreamVpcProjectId || state.projectId || "—"}</dd>
              </div>
            ) : null}
            <div>
              <dt>{copy.hostname}</dt>
              <dd>{state.privateHostname}</dd>
            </div>
            <div>
              <dt>{messages.targetOu}</dt>
              <dd>{state.targetOuId || "—"}</dd>
            </div>
          </dl>
        </article>
        <article className="review-card">
          <h3>{copy.safetyGates}</h3>
          <p className="review-gate-legend">{copy.reviewGateLegend}</p>
          <ul className="review-gates">
            {(preparedPlan?.plan.gates ?? []).map((gate) => {
              const presentation = gatePresentation(gate);
              return (
                <li className={presentation.tone} key={gate.gate_id}>
                  {presentation.tone === "pass" ? (
                    <CheckIcon size={18} />
                  ) : (
                    <InfoIcon size={18} />
                  )}
                  <span className="review-gate-copy">
                    <span>{gateLabel(gate)}</span>
                    <small>{gateDescription(gate)}</small>
                  </span>
                  <strong>{presentation.label}</strong>
                </li>
              );
            })}
            {!preparedPlan && (
              <li className="manual">
                <InfoIcon size={18} />
                <span>{copy.preflight}</span>
                <strong>{copy.manualCheck}</strong>
              </li>
            )}
          </ul>
        </article>
      </div>
      {preparedPlan && (
        <section className="plan-review-details" aria-label={copy.plannedChangesTitle}>
          <article className="plan-change-panel">
            <h3>{copy.plannedChangesTitle}</h3>
            <p>{copy.plannedChangesIntro}</p>
            <ul className="planned-change-list">
              {plannedChanges.map((change) => (
                <li
                  key={`${change.provider}:${change.resource_type}:${change.resource_name}`}
                >
                  <div className="planned-change-heading">
                    <code>
                      {change.provider}:{change.resource_type}:{change.resource_name}
                    </code>
                    <span>{copy.changeAction(change.action)}</span>
                    <span className={`risk-${change.risk}`}>
                      {copy.changeRisk(change.risk)}
                    </span>
                  </div>
                  <p>{copy.changeSummary(change.resource_type, change.summary)}</p>
                </li>
              ))}
            </ul>
          </article>
          {preparedPlan.preflight.diagnostics.length > 0 && (
            <aside className="plan-diagnostics">
              <h3>{copy.diagnosticsTitle}</h3>
              <ul>
                {preparedPlan.preflight.diagnostics.map((diagnostic, index) => (
                  <li key={`${diagnostic.code}-${index}`}>
                    <strong>
                      {copy.diagnosticMessage(diagnostic.code, diagnostic.message)}
                    </strong>
                    <p>
                      {copy.diagnosticRemediation(
                        diagnostic.code,
                        diagnostic.remediation,
                      )}
                    </p>
                    <small className="diagnostic-evidence">
                      <span>{copy.apiEvidence}</span>
                      <code>{diagnostic.message}</code>
                    </small>
                  </li>
                ))}
              </ul>
            </aside>
          )}
        </section>
      )}
      {busy && !preparedPlan && (
        <article className="apply-progress apply-progress-spaced" aria-live="polite">
          <div className="apply-progress-heading">
            <span>
              <strong>{copy.preflightProgressTitle}</strong>
              <small>
                {preflightStage === 1
                  ? copy.preflightStage1
                  : preflightStage === 2
                    ? copy.preflightStage2
                    : preflightStage === 3
                      ? copy.preflightStage3
                      : preflightStage === 4
                        ? copy.preflightStage4
                        : copy.preflightStage5}
              </small>
            </span>
            <strong className="apply-progress-percent">{preflightProgress}%</strong>
          </div>
          <progress
            aria-label={copy.preflightProgressTitle}
            aria-valuemax={100}
            aria-valuemin={0}
            aria-valuenow={preflightProgress}
            className="apply-progress-track"
            max={100}
            value={preflightProgress}
          />
          <div className="apply-progress-current">
            <span aria-hidden="true" className="progress-spinner" />
            <span>
              <small>{copy.currentOperation}</small>
              <strong>
                {preflightStage === 1
                  ? "serviceusage.googleapis.com & cloudresourcemanager.googleapis.com"
                  : preflightStage === 2
                    ? "cloudbilling.googleapis.com"
                    : preflightStage === 3
                      ? "beyondcorp.googleapis.com & compute.googleapis.com"
                      : preflightStage === 4
                        ? "chromepolicy.googleapis.com & chromemanagement.googleapis.com"
                        : "diff_plan.compile() & safety_gates.evaluate()"}
              </strong>
            </span>
          </div>
        </article>
      )}

      {preparedPlan && (
        <article className="preflight-completed-banner">
          <CheckIcon size={20} />
          <div>
            <strong>{copy.preflightComplete}</strong>
            <small>
              {copy.changesCount(plannedChanges.length)} | 100% {copy.verified}
            </small>
          </div>
        </article>
      )}

      <div className="plan-actions">
        <button
          className="connection-action"
          disabled={busy}
          onClick={() => void onPrepare()}
          type="button"
        >
          {busy && !preparedPlan ? copy.preparingPlan : copy.runPreflight}
        </button>
        {preparedPlan && (
          <p className={`plan-result ${gatesReady ? "pass" : "blocked"}`}>
            {gatesReady ? <CheckIcon size={18} /> : <InfoIcon size={18} />}
            <span>
              <strong>{gatesReady ? copy.planReady : copy.planBlocked}</strong>
              <small>{copy.changesCount(plannedChanges.length)}</small>
            </span>
          </p>
        )}
      </div>
      {error && <p className="connection-error" role="alert">{error}</p>}
      <label className="approval-card">
        <input
          checked={approval !== null}
          disabled={!gatesReady || busy}
          onChange={(event) => void onApprove(event.target.checked)}
          type="checkbox"
        />
        <span>
          <strong>
            {busy && preparedPlan
              ? copy.approveWorking
              : approval
                ? copy.approvalReady
                : copy.approvePlan}
          </strong>
          <small>{copy.approvePlanDescription}</small>
        </span>
      </label>
    </section>
  );
}

export function ApplyStep({
  approval,
  busy,
  error,
  messages,
  onResume,
  preparedPlan,
  run,
  state,
}: ApplyStepProps) {
  const copy = messages.workflow;
  const [downloadBusy, setDownloadBusy] = useState(false);
  const [downloadError, setDownloadError] = useState("");
  const planReady = preparedPlan !== null;
  const approvalReady = approval !== null;
  const activeRunStatuses = new Set(["pending", "running", "rolling_back"]);
  const runFinished = run !== null && !activeRunStatuses.has(run.status);
  const runFinalized = run?.status === "succeeded" || run?.status === "rolled_back";
  const hasManagedVmTier = state.backendKind !== "direct_https";
  const networkProjectId =
    state.backendKind === "direct_https" && state.upstreamVpcProjectId.trim()
      ? state.upstreamVpcProjectId.trim()
      : state.projectId;
  const effectiveVpcName =
    state.networkStrategy === "dedicated"
      ? `${state.deploymentName}-vpc`
      : state.vpcName || "—";
  const operations = Array.isArray(run?.operations) ? run.operations : [];
  const totalOperations =
    operations.length > 0
      ? operations.length
      : (preparedPlan?.plan.changes.length ?? 0);
  const terminalOperationStatuses = new Set([
    "succeeded",
    "failed",
    "rolled_back",
    "rollback_failed",
    "skipped",
  ]);
  const completedOperations =
    operations.filter((operation) =>
      terminalOperationStatuses.has(operation.status),
    ).length;
  const progressPercent =
    runFinalized
      ? 100
      : totalOperations > 0
        ? Math.round((completedOperations / totalOperations) * 100)
        : 0;
  const failedOperations = operations.filter(
    (operation) =>
      operation.status === "rollback_failed" || operation.status === "failed" ||
      operation.error_code !== null,
  );
  const residualResources = Array.isArray(run?.residual_resources)
    ? run.residual_resources
    : [];
  const retryAvailable = run?.retry_available ?? (
    run !== null && ["interrupted", "failed", "rollback_failed"].includes(run.status)
  );
  const activeOperation = runFinalized
    ? undefined
    : runFinished
    ? operations.at(-1)
    : run?.status === "rolling_back"
      ? [...operations].reverse().find((operation) =>
          ["succeeded", "failed", "rollback_failed"].includes(operation.status),
        ) ?? operations.at(-1)
      : operations.find((operation) => operation.status === "running") ??
        operations.find((operation) => operation.status === "pending") ??
        operations.at(-1);
  const runMessage =
    run?.status === "succeeded"
      ? copy.runSucceeded
      : run?.status === "rolling_back"
        ? copy.runRollingBack
        : run?.status === "rollback_unavailable"
          ? copy.runRollbackUnavailable
          : run?.status === "rollback_failed"
            ? copy.runRollbackFailed
          : run?.status === "rolled_back"
            ? copy.runRolledBack
            : run?.status === "interrupted"
              ? copy.runInterrupted
              : run && ["pending", "running"].includes(run.status)
                ? copy.applying
                : runFinished
                  ? copy.runFailed
                  : busy
                    ? copy.applying
                    : copy.applyLocked;

  async function handleRootCertificateDownload() {
    setDownloadBusy(true);
    setDownloadError("");
    try {
      const certificate = await downloadLocalPocRootCertificate(
        state.deploymentName,
      );
      const url = URL.createObjectURL(certificate);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${state.deploymentName}-poc-root.pem`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch {
      setDownloadError(copy.caDownloadFailed);
    } finally {
      setDownloadBusy(false);
    }
  }

  return (
    <section className="workflow-step">
      <StepHeading description={copy.applyIntro} title={copy.applyTitle} />
      <div className="apply-timeline">
        <article className={planReady ? "apply-stage ready" : "apply-stage pending"}>
          <span className="stage-icon">
            <CodeIcon size={22} />
          </span>
          <span>
            <strong>{copy.preflight}</strong>
            <small>
              {planReady ? copy.ready : copy.applyLocked}
            </small>
          </span>
        </article>
        <article className={approvalReady ? "apply-stage ready" : "apply-stage pending"}>
          <span className="stage-icon">
            <NetworkIcon size={22} />
          </span>
          <span>
            <strong>{copy.desiredStatePlan}</strong>
            <small>{approvalReady ? copy.approvalReady : copy.incomplete}</small>
          </span>
        </article>
        <article className={run?.status === "succeeded" ? "apply-stage ready" : "apply-stage pending"}>
          <span className="stage-icon">
            <ShieldIcon size={22} />
          </span>
          <span>
            <strong>{copy.applyChanges}</strong>
            <small>{runMessage}</small>
          </span>
        </article>
      </div>
      {runFinished && run && (
        <p
          className={`plan-result ${
            run.status === "succeeded"
              ? "pass"
              : run.status === "rolled_back"
                ? "complete"
                : "blocked"
          }`}
          role="status"
        >
          {run.status === "succeeded" ? <CheckIcon size={18} /> : <InfoIcon size={18} />}
          <span>
            <strong>{runMessage}</strong>
            <small>{copy.operationCount(operations.length)}</small>
          </span>
        </p>
      )}
      {run && totalOperations > 0 && (
        <article className="apply-progress" aria-live="polite">
          <div className="apply-progress-heading">
            <span>
              <strong>{copy.progressTitle}</strong>
              <small>
                {runFinalized
                  ? copy.finalizedOperationCount(totalOperations)
                  : copy.progressCount(completedOperations, totalOperations)}
              </small>
            </span>
            <strong className="apply-progress-percent">{progressPercent}%</strong>
          </div>
          <progress
            aria-label={copy.progressTitle}
            aria-valuemax={100}
            aria-valuemin={0}
            aria-valuenow={progressPercent}
            className="apply-progress-track"
            max={100}
            value={progressPercent}
          />
          <div className="apply-progress-current">
            {["pending", "running", "rolling_back"].includes(run.status) && (
              <span aria-hidden="true" className="progress-spinner" />
            )}
            <span>
              {runFinalized ? (
                <>
                  <small>{copy.runFinalized}</small>
                  <strong>{runMessage}</strong>
                  <small>{copy.noActiveOperation}</small>
                </>
              ) : (
                <>
                  {failedOperations.length > 0 ? (
                    <>
                      <small>{copy.failedOperations}</small>
                      <ul className="apply-failure-list">
                        {failedOperations.map((operation) => (
                          <li key={`${operation.operation_id}:${operation.resource_key}`}>
                            <strong>{operation.resource_key}</strong>
                            <code>{operation.error_code ?? operation.status}</code>
                          </li>
                        ))}
                      </ul>
                    </>
                  ) : (
                    <>
                      <small>{copy.currentOperation}</small>
                      <strong>
                        {activeOperation?.resource_key ?? copy.waitingForOperation}
                      </strong>
                      {activeOperation?.error_code && <code>{activeOperation.error_code}</code>}
                    </>
                  )}
                </>
              )}
            </span>
          </div>
        </article>
      )}
      {run?.status === "rollback_unavailable" && residualResources.length > 0 && (
        <article className="manual-cleanup-list" role="alert">
          <h3>{copy.manualCleanupTitle}</h3>
          <p>{copy.manualCleanupDescription}</p>
          <ul>
            {residualResources.map((resource) => (
              <li key={resource.resource_key}>
                <code>{resource.resource_key}</code>
              </li>
            ))}
          </ul>
        </article>
      )}
      {run && retryAvailable && (
        <button
          className="connection-action"
          disabled={busy}
          onClick={() => void onResume()}
          type="button"
        >
          {run.status === "interrupted"
            ? busy ? copy.resumingRun : copy.resumeRun
            : busy ? copy.retryingRollback : copy.retryRollback}
        </button>
      )}
      {run?.status === "succeeded" && state.certificateStrategy === "local_poc" && (
        <article className="ca-handoff">
          <h3>{copy.caHandoffTitle}</h3>
          <p>{copy.caHandoffDescription}</p>
          <ol>
            {copy.caHandoffSteps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          <div className="ca-handoff-actions">
            <button
              className="connection-action"
              disabled={downloadBusy}
              onClick={() => void handleRootCertificateDownload()}
              type="button"
            >
              {downloadBusy ? copy.downloadingRootCa : copy.downloadRootCa}
            </button>
            <a
              href="https://support.google.com/chrome/a/answer/16073278"
              rel="noreferrer"
              target="_blank"
            >
              {copy.openAdminConsoleGuide}
            </a>
          </div>
          {downloadError && (
            <p className="connection-error" role="alert">
              {downloadError}
            </p>
          )}
        </article>
      )}
      {run?.status === "succeeded" && (
        <article className="ca-handoff">
          <h3>{copy.connectionHandoffTitle}</h3>
          <p>
            <strong>{copy.testUrlLabel}: </strong>
            <a href={`https://${state.privateHostname}`} rel="noreferrer" target="_blank">
              https://{state.privateHostname}
            </a>
          </p>
          <p>{copy.sebTroubleshootingHint}</p>
        </article>
      )}
      {error && <p className="connection-error" role="alert">{error}</p>}

      <article className="cloud-console-panel">
        <h3>{copy.cloudConsoleLinks}</h3>
        <div className="cloud-console-grid">
          {hasManagedVmTier && (
            <a
              className="cloud-console-card"
              href={`https://console.cloud.google.com/compute/instances?project=${encodeURIComponent(state.projectId)}`}
              rel="noreferrer"
              target="_blank"
            >
              <CloudIcon size={20} />
              <div>
                <strong>{copy.computeInstancesLink}</strong>
                <small>{copy.computeResourcesHint}</small>
              </div>
            </a>
          )}
          <a
            className="cloud-console-card"
            href={`https://console.cloud.google.com/security/security-gateways?project=${encodeURIComponent(state.projectId)}`}
            rel="noreferrer"
            target="_blank"
          >
            <ShieldIcon size={20} />
            <div>
              <strong>{copy.securityGatewaysLink}</strong>
              <small>{copy.securityGatewayHint}</small>
            </div>
          </a>
          <a
            className="cloud-console-card"
            href={`https://console.cloud.google.com/networking/networks/list?project=${encodeURIComponent(networkProjectId)}`}
            rel="noreferrer"
            target="_blank"
          >
            <NetworkIcon size={20} />
            <div>
              <strong>{copy.vpcNetworksLink}</strong>
              <small>{effectiveVpcName}</small>
            </div>
          </a>
          {hasManagedVmTier && (
            <a
              className="cloud-console-card"
              href={`https://console.cloud.google.com/net-services/nat/list?project=${encodeURIComponent(state.projectId)}`}
              rel="noreferrer"
              target="_blank"
            >
              <LockIcon size={20} />
              <div>
                <strong>{copy.cloudNatLink}</strong>
                <small>{copy.cloudNatHint}</small>
              </div>
            </a>
          )}
          <a
            className="cloud-console-card"
            href="https://admin.google.com/ac/chrome/settings/user"
            rel="noreferrer"
            target="_blank"
          >
            <UsersIcon size={20} />
            <div>
              <strong>{copy.chromeAdminLink}</strong>
              <small>OU: {state.targetOuId || "Root Store / Extensions"}</small>
            </div>
          </a>
        </div>
      </article>

      <Notice tone="security">{copy.evidenceNotice}</Notice>
    </section>
  );
}

export function normalizeBackendKind(value: string): BackendKind {
  if (
    value === "existing_http" ||
    value === "direct_https" ||
    value === "internal_https_lb"
  ) {
    return value;
  }
  return "managed_sample";
}
