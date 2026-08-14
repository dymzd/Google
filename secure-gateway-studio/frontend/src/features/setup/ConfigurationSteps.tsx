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
  listAccessLevelOptions,
  listGroupOptions,
  listOrganizationalUnitOptions,
} from "../../lib/api";
import type {
  AccessPrincipal,
  BackendKind,
  BackendLocation,
  PrincipalType,
  SetupState,
} from "../../lib/setup-state";
import { ChoiceCard } from "./ChoiceCard";

interface StepProps {
  messages: Messages;
  onPatch: (patch: Partial<SetupState>) => void;
  state: SetupState;
}

interface IdentitiesStepProps extends StepProps {
  onBootstrapCloud: () => Promise<DeployerBootstrapResult>;
  onValidateCloud: () => Promise<void>;
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
  preparedPlan: PreparedPlan | null;
  run: DeploymentRun | null;
  state: SetupState;
}

function Field({
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
  const selected = catalog.items.find((option) => option.value === value);
  const preservesExistingValue =
    Boolean(value) && !catalog.items.some((option) => option.value === value);

  return (
    <div className="catalog-field">
      <label className="field">
        <span>{label}</span>
        <select
          disabled={catalog.loading || Boolean(catalog.error)}
          onChange={(event) => onChange(event.target.value)}
          value={value}
        >
          <option value="">
            {catalog.loading
              ? loadingLabel
              : catalog.items.length === 0
                ? emptyLabel
                : placeholder}
          </option>
          {preservesExistingValue && <option value={value}>{value}</option>}
          {catalog.items.map((option) => (
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
  const [bootstrapResult, setBootstrapResult] =
    useState<DeployerBootstrapResult | null>(null);

  async function handleBootstrap() {
    if (!globalThis.confirm(copy.bootstrapConfirm)) return;
    setBootstrapBusy(true);
    setBootstrapError("");
    setBootstrapResult(null);
    try {
      setBootstrapResult(await onBootstrapCloud());
    } catch (error) {
      setBootstrapError(
        error instanceof ApiError
          ? `${copy.bootstrapFailed}: ${error.message}`
          : copy.bootstrapFailed,
      );
    } finally {
      setBootstrapBusy(false);
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
            label={copy.projectId}
            onChange={(projectId) => {
              setBootstrapResult(null);
              setBootstrapError("");
              onPatch({
                projectId,
                cloudConnection: "not_connected",
                cloudConnectionError: "",
              });
            }}
            placeholder="enterprise-secgw-01"
            value={state.projectId}
          />
          <button
            className="connection-action secondary"
            disabled={!state.projectId.trim() || bootstrapBusy}
            onClick={() => void handleBootstrap()}
            type="button"
          >
            <ShieldIcon size={18} />
            {bootstrapBusy ? copy.bootstrapWorking : copy.bootstrapDeployer}
          </button>
          {bootstrapResult && (
            <div className="bootstrap-result" role="status">
              <strong>{copy.bootstrapComplete}</strong>
              <small>{copy.bootstrapNext}</small>
              <code>{bootstrapResult.adc_command}</code>
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
  const legacyNginxSelected = ["managed_sample", "existing_http"].includes(
    state.backendKind,
  );

  return (
    <section className="workflow-step">
      <StepHeading description={copy.environmentIntro} title={copy.environmentTitle} />
      <div className="field-grid three">
        <Field
          label={copy.deploymentName}
          onChange={(deploymentName) => onPatch({ deploymentName })}
          value={state.deploymentName}
        />
        <Field
          label={copy.region}
          onChange={(region) => onPatch({ region })}
          value={state.region}
        />
        <Field
          label={copy.zone}
          onChange={(zone) => onPatch({ zone })}
          value={state.zone}
        />
        {state.mode === "production" && (
          <Field
            label={copy.secondaryZone}
            onChange={(secondaryZone) => onPatch({ secondaryZone })}
            value={state.secondaryZone}
          />
        )}
      </div>
      {state.mode === "production" &&
        !["direct_https", "internal_https_lb"].includes(state.backendKind) && (
        <>
          <div className="field-grid one">
            <Field
              label={copy.sourceImage}
              onChange={(sourceImage) => onPatch({ sourceImage })}
              placeholder="projects/my-image-project/global/images/sgs-nginx-20260730"
              value={state.sourceImage}
            />
            <small className="field-hint">{copy.sourceImageHint}</small>
          </div>
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
        <div className="field-grid two">
          <Field
            label={copy.vpcName}
            onChange={(vpcName) => onPatch({ vpcName })}
            value={state.vpcName}
          />
          {state.backendKind !== "direct_https" ? (
            <Field
              label={copy.subnetName}
              onChange={(subnetName) => onPatch({ subnetName })}
              value={state.subnetName}
            />
          ) : null}
        </div>
      )}

      <h3 className="subsection-title">{copy.network}</h3>
      <div className="mode-grid backend-grid">
        <ChoiceCard
          description={copy.directHttpsDescription}
          icon={<ShieldIcon size={27} />}
          onSelect={() =>
            onPatch({
              backendKind: "direct_https",
              networkStrategy: "existing",
              deploymentName:
                state.deploymentName === "secure-gateway-http-offload" ||
                state.deploymentName === "secure-gateway-ilb-https-offload"
                  ? "secure-gateway-private-https"
                  : state.deploymentName,
              existingBackendConnectivityConfirmed: false,
              existingBackendUrl: state.existingBackendUrl.startsWith("https://")
                ? state.existingBackendUrl
                : "",
            })
          }
          selected={state.backendKind === "direct_https"}
          title={copy.directHttps}
        />
        <ChoiceCard
          description={copy.internalHttpsLbDescription}
          icon={<ShieldIcon size={27} />}
          onSelect={() =>
            onPatch({
              backendKind: "internal_https_lb",
              deploymentName:
                state.deploymentName === "secure-gateway-http-offload" ||
                state.deploymentName === "secure-gateway-private-https"
                  ? "secure-gateway-ilb-https-offload"
                  : state.deploymentName,
              existingBackendUrl: "",
              existingBackendConnectivityConfirmed: false,
            })
          }
          selected={state.backendKind === "internal_https_lb"}
          title={copy.internalHttpsLb}
        />
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
            icon={<NetworkIcon size={27} />}
            onSelect={() =>
              onPatch({
                backendKind: "managed_sample",
                deploymentName:
                  state.deploymentName === "secure-gateway-ilb-https-offload" ||
                  state.deploymentName === "secure-gateway-private-https"
                    ? "secure-gateway-http-offload"
                    : state.deploymentName,
              })
            }
            selected={state.backendKind === "managed_sample"}
            title={copy.managedSample}
          />
          <ChoiceCard
            description={copy.existingBackendDescription}
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
        <div className="field-grid one">
          <Field
            label={copy.proxySubnetCidr}
            onChange={(proxySubnetCidr) => onPatch({ proxySubnetCidr })}
            placeholder="10.42.1.0/24"
            value={state.proxySubnetCidr}
          />
        </div>
      )}
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
            placeholder="projects/.../locations/.../caPools/..."
            value={state.caPool}
          />
          <Field
            label={copy.caName}
            onChange={(caName) => onPatch({ caName })}
            placeholder="projects/.../certificateAuthorities/..."
            value={state.caName}
          />
        </div>
      )}
      {state.backendKind !== "direct_https" &&
        state.certificateStrategy === "public_trusted" && (
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
    setOrganizationalUnits(
      ouResult.status === "fulfilled"
        ? { items: ouResult.value, loading: false, error: "" }
        : {
            items: [],
            loading: false,
            error: catalogError(
              ouResult.reason,
              copy.ouOptionsFailed,
              copy.adcUnavailable,
            ),
          },
    );
    setAccessLevels(
      accessLevelResult.status === "fulfilled"
        ? { items: accessLevelResult.value, loading: false, error: "" }
        : {
            items: [],
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
          value={state.managedChromeAccessLevel}
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

export function isConfigurationReady(state: SetupState): boolean {
  const identitiesReady =
    state.cloudConnection === "connected" &&
    state.workspaceConnection === "connected";
  const environmentReady =
    Boolean(
      state.deploymentName &&
        state.region &&
        state.zone &&
        (state.backendKind === "direct_https" ||
          state.mode === "poc" ||
          (state.secondaryZone &&
            state.secondaryZone !== state.zone &&
            state.sourceImage)) &&
        (state.backendKind === "direct_https" || state.privateHostname),
    ) &&
    (state.backendKind !== "internal_https_lb" || Boolean(state.proxySubnetCidr)) &&
    (state.backendKind === "direct_https"
      ? state.networkStrategy === "existing" && Boolean(state.vpcName)
      : state.networkStrategy === "dedicated" ||
        Boolean(state.vpcName && state.subnetName)) &&
    (state.backendKind === "managed_sample" ||
      state.backendKind === "internal_https_lb" ||
      (state.backendKind === "existing_http" &&
        state.existingBackendUrl.startsWith("http://") &&
        state.existingBackendConnectivityConfirmed) ||
      (state.backendKind === "direct_https" &&
        state.existingBackendUrl.startsWith("https://") &&
        state.existingBackendConnectivityConfirmed));
  const certificateReady =
    state.backendKind === "direct_https" ||
    state.certificateStrategy === "local_poc" ||
    (state.certificateStrategy === "enterprise_ca"
      ? Boolean(state.caPool && state.caName)
      : Boolean(state.publicCertificateSecret));
  const accessReady =
    Boolean(state.customerId) &&
    Boolean(state.targetOuId) &&
    Boolean(state.managedChromeAccessLevel) &&
    (state.mode === "poc" ||
      (state.chromeEnterprisePremiumLicenseConfirmed &&
        state.workspaceServicesConfirmed &&
        state.endpointVerificationConfirmed)) &&
    state.testOuConfirmed &&
    state.principals.length > 0 &&
    state.principals.every((principal) => principal.value.trim().length >= 3);
  return identitiesReady && environmentReady && certificateReady && accessReady;
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
  const ready = isConfigurationReady(state);
  const gatesReady =
    preparedPlan?.plan.gates.every(
      (gate) =>
        !gate.blocking ||
        gate.gate_id === "human-approval" ||
        gate.status === "pass",
    ) ?? false;

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
      return gate.gate_id === "immutable-image"
        ? { label: copy.pocDefault, tone: "manual" }
        : { label: copy.manualCheck, tone: "manual" };
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
    if (gate.gate_id === "apply-permissions") {
      const match = gate.detail.match(/^(\d+) required permissions are missing/);
      if (match) return copy.missingPermissions(Number(match[1]));
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
      <div className="plan-actions">
        <button
          className="connection-action"
          disabled={!ready || busy}
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
  preparedPlan,
  run,
  state,
}: ApplyStepProps) {
  const copy = messages.workflow;
  const [downloadBusy, setDownloadBusy] = useState(false);
  const [downloadError, setDownloadError] = useState("");
  const planReady = preparedPlan !== null;
  const approvalReady = approval !== null;
  const runFinished =
    run !== null && !["pending", "running"].includes(run.status);
  const totalOperations = preparedPlan?.plan.changes.length ?? run?.operations.length ?? 0;
  const terminalOperationStatuses = new Set([
    "succeeded",
    "failed",
    "rolled_back",
    "rollback_failed",
    "skipped",
  ]);
  const completedOperations =
    run?.operations.filter((operation) =>
      terminalOperationStatuses.has(operation.status),
    ).length ?? 0;
  const progressPercent =
    totalOperations > 0
      ? Math.round((completedOperations / totalOperations) * 100)
      : 0;
  const activeOperation =
    run?.operations.find((operation) =>
      ["pending", "running"].includes(operation.status),
    ) ?? run?.operations.at(-1);
  const runMessage =
    run?.status === "succeeded"
      ? copy.runSucceeded
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
      anchor.click();
      URL.revokeObjectURL(url);
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
      {run && totalOperations > 0 && (
        <article className="apply-progress" aria-live="polite">
          <div className="apply-progress-heading">
            <span>
              <strong>{copy.progressTitle}</strong>
              <small>{copy.progressCount(completedOperations, totalOperations)}</small>
            </span>
            <strong className="apply-progress-percent">{progressPercent}%</strong>
          </div>
          <div
            aria-label={copy.progressTitle}
            aria-valuemax={100}
            aria-valuemin={0}
            aria-valuenow={progressPercent}
            className="apply-progress-track"
            role="progressbar"
          >
            <span style={{ width: `${progressPercent}%` }} />
          </div>
          <div className="apply-progress-current">
            {["pending", "running"].includes(run.status) && (
              <span aria-hidden="true" className="progress-spinner" />
            )}
            <span>
              <small>{copy.currentOperation}</small>
              <strong>
                {activeOperation?.resource_key ?? copy.waitingForOperation}
              </strong>
              {activeOperation?.error_code && <code>{activeOperation.error_code}</code>}
            </span>
          </div>
        </article>
      )}
      {runFinished && run && (
        <p className="plan-result pass">
          <CheckIcon size={18} />
          <span>
            <strong>{runMessage}</strong>
            <small>{copy.operationCount(run.operations.length)}</small>
          </span>
        </p>
      )}
      {run?.status === "succeeded" &&
        state.backendKind !== "direct_https" &&
        state.certificateStrategy === "local_poc" && (
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
      {error && <p className="connection-error" role="alert">{error}</p>}
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
