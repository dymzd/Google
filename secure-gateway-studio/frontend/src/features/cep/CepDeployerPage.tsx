import { useEffect, useState } from "react";
import type { Messages } from "../../i18n/messages";
import type {
  CepDataBoundaryMode,
  CepDlpMatrixState,
  CepLicenseAssignResult,
  CepProvisionConfig,
  CepProvisionResult,
  SetupOption,
} from "../../lib/api";
import {
  assignCepLicenses,
  generateCepScript,
  listAccessLevelOptions,
  listOrganizationalUnitOptions,
  provisionCepPolicies,
  signInSession,
  rollbackCepPolicies,
} from "../../lib/api";
import {
  CheckCircleIcon,
  ExclamationCircleIcon,
  ShieldNetworkIcon,
} from "../../components/Icons";
import { DEFAULT_DLP_MATRIX, DlpMatrixTable } from "./DlpMatrixTable";

interface CepDeployerPageProps {
  messages: Messages;
  customerId: string;
  projectId: string;
}

interface ModuleState {
  corePolicies: boolean;
  forceExtensions: boolean;
  connectors: boolean;
  accessLevel: string;
  dlpDetectors: boolean;
  dlpRules: boolean;
  dlpRegion: string;
  dataBoundaryMode: CepDataBoundaryMode;
}

/** Countries whose national identifier Cloud DLP can detect. */
const DLP_REGIONS: Array<{ value: string; label: string }> = [
  { value: "JP", label: "Japan" },
  { value: "US", label: "United States" },
  { value: "GB", label: "United Kingdom" },
  { value: "DE", label: "Germany" },
  { value: "FR", label: "France" },
  { value: "CA", label: "Canada" },
  { value: "AU", label: "Australia" },
  { value: "KR", label: "South Korea" },
  { value: "SG", label: "Singapore" },
  { value: "IN", label: "India" },
];

type PresetName = "full" | "ai" | "endpoint" | "audit";

/**
 * Sentinels the worker understands, shared with the deployment wizard's access
 * step. Anything else in the dropdown is a real access level resource name.
 */
const ACCESS_LEVEL_NONE = "NONE";
const AUTO_CREATE_ANY = "AUTO_CREATE_CHROME_ANY";
const AUTO_CREATE_SENTINELS = [
  AUTO_CREATE_ANY,
  "AUTO_CREATE_PROFILE_MANAGED",
  "AUTO_CREATE_BROWSER_MANAGED",
];

const PRESETS: Record<PresetName, ModuleState> = {
  full: {
    corePolicies: true,
    forceExtensions: true,
    connectors: true,
    accessLevel: AUTO_CREATE_ANY,
    dlpDetectors: false,
    dlpRules: true,
    dlpRegion: "JP",
    dataBoundaryMode: "copy_paste",
  },
  ai: {
    corePolicies: true,
    forceExtensions: false,
    connectors: true,
    accessLevel: ACCESS_LEVEL_NONE,
    dlpDetectors: false,
    dlpRules: true,
    dlpRegion: "JP",
    dataBoundaryMode: "block_non_corp",
  },
  endpoint: {
    corePolicies: true,
    forceExtensions: true,
    connectors: true,
    accessLevel: AUTO_CREATE_ANY,
    dlpDetectors: false,
    dlpRules: false,
    dlpRegion: "JP",
    dataBoundaryMode: "none",
  },
  audit: {
    corePolicies: true,
    forceExtensions: false,
    connectors: true,
    accessLevel: ACCESS_LEVEL_NONE,
    dlpDetectors: false,
    dlpRules: true,
    dlpRegion: "JP",
    dataBoundaryMode: "none",
  },
};

const PRESET_MATRICES: Record<PresetName, CepDlpMatrixState> = {
  full: DEFAULT_DLP_MATRIX,
  ai: {
    ...DEFAULT_DLP_MATRIX,
    genai_block: { ...DEFAULT_DLP_MATRIX.genai_block, paste: "blockContent", upload: "blockContent" },
    national_id: { ...DEFAULT_DLP_MATRIX.national_id, paste: "warnUser" },
  },
  endpoint: {
    universal_upload: { upload: "off" },
    universal_download: { download: "off" },
    payment_card: { upload: "off", paste: "off" },
    national_id: { upload: "off", paste: "off" },
    access_level: { upload: "off" },
    watermark: { watermark: false },
    genai_block: { paste: "off", upload: "off" },
  },
  audit: {
    universal_upload: { upload: "warnUser" },
    universal_download: { download: "warnUser" },
    payment_card: { upload: "warnUser", paste: "warnUser" },
    national_id: { upload: "warnUser", paste: "warnUser" },
    access_level: { upload: "off", download: "off", paste: "off", print: "off", byodOnly: false },
    watermark: { watermark: false },
    genai_block: { paste: "warnUser", upload: "warnUser" },
  },
};

export function CepDeployerPage({
  messages,
  customerId,
  projectId,
}: CepDeployerPageProps) {
  const m = messages.cepDeployer;
  const canonicalCustomerId = /^C[A-Za-z0-9]+$/.test(customerId.trim())
    ? customerId.trim()
    : "";

  const [organizationalUnits, setOrganizationalUnits] = useState<SetupOption[]>([]);
  const [selectedOu, setSelectedOu] = useState<string>("");
  const [targetOuConfirmation, setTargetOuConfirmation] = useState<string>("");
  const [ouError, setOuError] = useState<boolean>(false);
  // This write-capable Directory action must be an affirmative administrator
  // choice; merely opening Easy PoC must not opt the tenant into OU creation.
  const [autoSubOus, setAutoSubOus] = useState<boolean>(false);

  const [modules, setModules] = useState<ModuleState>(PRESETS.full);
  const [dlpMatrix, setDlpMatrix] = useState<CepDlpMatrixState>(DEFAULT_DLP_MATRIX);
  const [internalUrls, setInternalUrls] = useState<string>("");

  const [accessLevels, setAccessLevels] = useState<SetupOption[]>([]);
  const [accessLevelError, setAccessLevelError] = useState<boolean>(false);

  const [assigningLicenses, setAssigningLicenses] = useState<boolean>(false);
  const [licenseResult, setLicenseResult] = useState<CepLicenseAssignResult | null>(null);
  const [licenseError, setLicenseError] = useState<string>("");

  const [busy, setBusy] = useState<"deploy" | "rollback" | null>(null);
  const [actionError, setActionError] = useState<string>("");
  const [actionSuccess, setActionSuccess] = useState<string>("");
  const [lastResult, setLastResult] = useState<CepProvisionResult | null>(null);
  const [copiedSnippet, setCopiedSnippet] = useState<string>("");

  const [ouLoaded, setOuLoaded] = useState<boolean>(false);
  const [loadingOus, setLoadingOus] = useState<boolean>(false);

  const handleLoadOus = async () => {
    // A refresh is a new authorization decision. Never retain or infer a
    // target from the first (normally root) Directory result.
    setSelectedOu("");
    setTargetOuConfirmation("");
    if (canonicalCustomerId === "") {
      setOuError(true);
      setOuLoaded(true);
      return;
    }
    setLoadingOus(true);
    setOuError(false);
    try {
      // The button promises to verify the Google account. Ask for consent
      // first so a profile that never granted it is not told, silently and
      // wrongly, that it has no organizational units.
      await signInSession();
      const options = await listOrganizationalUnitOptions(canonicalCustomerId);
      setOrganizationalUnits(options);
      setOuError(options.length === 0);
      setOuLoaded(true);
      if (projectId) {
        try {
          const accessOptions = await listAccessLevelOptions(projectId);
          const existing = accessOptions.filter(
            (option) =>
              option.value !== ACCESS_LEVEL_NONE &&
              !AUTO_CREATE_SENTINELS.includes(option.value),
          );
          setAccessLevels(existing);
          setAccessLevelError(false);
        } catch {
          setAccessLevelError(true);
        }
      }
    } catch {
      setOuError(true);
      setOuLoaded(true);
    } finally {
      setLoadingOus(false);
    }
  };

  const selectedUnit = organizationalUnits.find((unit) => unit.value === selectedOu);
  const targetOuConfirmed =
    selectedUnit !== undefined &&
    selectedUnit.label !== "/" &&
    targetOuConfirmation === selectedUnit.label;
  const anyModuleSelected =
    modules.corePolicies ||
    modules.forceExtensions ||
    modules.connectors ||
    modules.accessLevel !== ACCESS_LEVEL_NONE ||
    modules.dlpRules ||
    modules.dataBoundaryMode !== "none";
  const canDeploy =
    canonicalCustomerId !== "" &&
    selectedOu !== "" &&
    targetOuConfirmed &&
    anyModuleSelected &&
    busy === null;

  function update<K extends keyof ModuleState>(key: K, value: ModuleState[K]) {
    setModules((current) => ({ ...current, [key]: value }));
  }

  function currentConfig(confirmation = targetOuConfirmation): CepProvisionConfig {
    return {
      customer_id: canonicalCustomerId,
      project_id: projectId,
      target_ou_id: selectedOu,
      target_ou_path: selectedUnit?.label,
      target_ou_confirmation: confirmation,
      create_sub_ous: autoSubOus,
      core_policies: modules.corePolicies,
      force_extensions: modules.forceExtensions,
      connectors: modules.connectors,
      access_level: modules.accessLevel,
      dlp_detectors: false,
      dlp_rules: modules.dlpRules,
      dlp_region: modules.dlpRegion,
      dlp_matrix: dlpMatrix,
      data_boundary_mode: modules.dataBoundaryMode,
      internal_urls: internalUrls
        .split("\n")
        .map((url) => url.trim())
        .filter(Boolean),
    };
  }

  const handleAssignLicenses = async () => {
    if (!selectedOu || canonicalCustomerId === "" || !targetOuConfirmed) return;
    const confirmation = targetOuConfirmation;
    setTargetOuConfirmation("");
    setAssigningLicenses(true);
    setLicenseError("");
    setLicenseResult(null);
    try {
      const res = await assignCepLicenses({
        customer_id: canonicalCustomerId,
        project_id: projectId,
        target_ou_id: selectedOu,
        target_ou_path: selectedUnit?.label,
        target_ou_confirmation: confirmation,
      });
      setLicenseResult(res);
      if (!res.success && res.errors.length > 0) {
        setLicenseError(res.errors.join("; "));
      }
    } catch (err) {
      setLicenseError(err instanceof Error ? err.message : String(err));
    } finally {
      setAssigningLicenses(false);
    }
  };

  const handleCopy = (text: string, key: string) => {
    void navigator.clipboard.writeText(text);
    setCopiedSnippet(key);
    setTimeout(() => setCopiedSnippet(""), 2500);
  };

  const applyResult = (result: CepProvisionResult) => {
    setLastResult(result);
    setActionSuccess(result.success ? result.message : "");
    setActionError(result.success ? "" : result.message);
  };

  const handleDeploy = async () => {
    if (canonicalCustomerId === "" || !targetOuConfirmed) return;
    const config = currentConfig(targetOuConfirmation);
    setTargetOuConfirmation("");
    setBusy("deploy");
    setActionError("");
    setActionSuccess("");
    try {
      applyResult(await provisionCepPolicies(config));
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  const handleRollback = async () => {
    if (canonicalCustomerId === "") return;
    if (!window.confirm(m.confirmRollback)) return;
    setBusy("rollback");
    setActionError("");
    setActionSuccess("");
    try {
      applyResult(
        await rollbackCepPolicies({
          customer_id: canonicalCustomerId,
          project_id: projectId,
          target_ou_id: selectedOu,
          target_ou_path: selectedUnit?.label,
          access_level: modules.accessLevel,
        }),
      );
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  const handleDownloadScript = async () => {
    if (canonicalCustomerId === "") return;
    setActionError("");
    try {
      const result = await generateCepScript(currentConfig());
      const url = URL.createObjectURL(new Blob([result.script], { type: "text/x-python" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = result.filename || "cep_configure.py";
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
    } catch (error) {
      setActionError(
        `${m.downloadFailed}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  };

  const samples = [
    {
      key: "pii",
      label: m.dummyPiiLabel,
      value: m.dummyPiiValue,
      hint: m.dummyPiiHint,
    },
    {
      key: "card",
      label: m.dummyCreditCardLabel,
      value: m.dummyCreditCardValue,
      hint: m.dummyCreditCardHint,
    },
    {
      key: "code",
      label: m.dummySourceCodeLabel,
      value: m.dummySourceCodeValue,
      hint: m.dummySourceCodeHint,
    },
  ];

  const moduleToggles: Array<{
    key: keyof Omit<
      ModuleState,
      "dataBoundaryMode" | "accessLevel" | "dlpRegion" | "dlpRuleActions"
    >;
    label: string;
    description: string;
    beta?: boolean;
  }> = [
    {
      key: "corePolicies",
      label: m.moduleCorePolicies,
      description: m.moduleCorePoliciesDesc,
    },
    {
      key: "forceExtensions",
      label: m.moduleForceExtensions,
      description: m.moduleForceExtensionsDesc,
    },
    { key: "connectors", label: m.moduleConnectors, description: m.moduleConnectorsDesc },
    {
      key: "dlpRules",
      label: m.moduleDlpRules,
      description: m.moduleDlpRulesDesc,
      beta: true,
    },
  ];

  const anyDlpSelected = modules.dlpRules;

  const boundaryModes: Array<{
    value: CepDataBoundaryMode;
    label: string;
    description: string;
  }> = [
    {
      value: "copy_paste",
      label: m.dataBoundaryModeCopyPaste,
      description: m.dataBoundaryModeCopyPasteDesc,
    },
    {
      value: "block_non_corp",
      label: m.dataBoundaryModeBlockNonCorp,
      description: m.dataBoundaryModeBlockNonCorpDesc,
    },
    {
      value: "none",
      label: m.dataBoundaryModeNone,
      description: m.dataBoundaryModeNoneDesc,
    },
  ];

  const presets: Array<{ name: PresetName; label: string; description: string }> = [
    { name: "full", label: m.presetFullPoc, description: m.presetFullPocDesc },
    { name: "ai", label: m.presetAiProtection, description: m.presetAiProtectionDesc },
    { name: "endpoint", label: m.presetEndpoint, description: m.presetEndpointDesc },
    { name: "audit", label: m.presetAudit, description: m.presetAuditDesc },
  ];

  return (
    <main className="cep-page">
      <header className="cep-heading">
        <span className="cep-heading-mark" aria-hidden="true">
          <ShieldNetworkIcon size={26} />
        </span>
        <div>
          <h1>{m.title}</h1>
          <p className="cep-subtitle">{m.subtitle}</p>
        </div>
      </header>
      <p className="cep-intro">{m.intro}</p>

      <section className="cep-section" aria-labelledby="cep-ou-title">
        <h2 id="cep-ou-title">{m.targetOuCardTitle}</h2>
        <p>{m.targetOuCardSubtitle}</p>
        {canonicalCustomerId === "" && (
          <p className="cep-inline-error" role="alert">
            {m.canonicalCustomerIdRequired}
          </p>
        )}

        {!ouLoaded ? (
          <div className="cep-verify-box">
            <button
              className="cep-btn cep-btn-primary"
              disabled={canonicalCustomerId === "" || loadingOus}
              onClick={() => void handleLoadOus()}
              type="button"
            >
              {loadingOus ? m.verifyingGoogleAccount : m.verifyGoogleAccount}
            </button>
            <p className="cep-verify-hint">
              {m.verifyGoogleAccountHint}
            </p>
          </div>
        ) : ouError ? (
          <div>
            <p className="cep-inline-error" role="alert">
              {m.ouLoadFailed}
            </p>
            <button
              className="cep-btn cep-btn-secondary cep-retry-action"
              disabled={loadingOus}
              onClick={() => void handleLoadOus()}
              type="button"
            >
              {m.retry}
            </button>
          </div>
        ) : (
          <div className="cep-field">
            <div className="cep-field-heading">
              <label htmlFor="cep-target-ou">{m.selectTargetOu}</label>
              <button
                className="text-action cep-refresh-action"
                disabled={loadingOus}
                onClick={() => void handleLoadOus()}
                type="button"
              >
                {loadingOus ? m.reloading : m.refreshOus}
              </button>
            </div>
            <select
              id="cep-target-ou"
              onChange={(event) => {
                setSelectedOu(event.target.value);
                setTargetOuConfirmation("");
              }}
              value={selectedOu}
            >
              <option value="">{m.selectTargetOuPlaceholder}</option>
              {organizationalUnits.map((unit) => (
                <option disabled={unit.label === "/"} key={unit.value} value={unit.value}>
                  {unit.label === "/" ? `${unit.label} (${m.rootOuUnavailable})` : unit.label}
                </option>
              ))}
            </select>
          </div>
        )}

        {selectedUnit !== undefined && selectedUnit.label !== "/" && (
          <div className="cep-license-warning-box">
            <div className="cep-license-warning-header">
              <ExclamationCircleIcon size={20} />
              <strong>{m.targetOuImpact}</strong>
            </div>
            <div className="cep-field">
              <label htmlFor="cep-target-ou-confirmation">
                {m.targetOuConfirmationLabel}
              </label>
              <code>{selectedUnit.label}</code>
              <input
                autoComplete="off"
                id="cep-target-ou-confirmation"
                onChange={(event) => setTargetOuConfirmation(event.target.value)}
                placeholder={selectedUnit.label}
                spellCheck={false}
                type="text"
                value={targetOuConfirmation}
              />
              <small>{m.targetOuConfirmationHint}</small>
            </div>
          </div>
        )}

        <label className="cep-check">
          <input
            checked={autoSubOus}
            onChange={(event) => setAutoSubOus(event.target.checked)}
            type="checkbox"
          />
          <span>
            <strong>{m.autoCreateSubOus}</strong>
            <small>{m.autoCreateSubOusHint}</small>
          </span>
        </label>
      </section>

      <section className="cep-section cep-license-section" aria-labelledby="cep-license-title">
        <h2 id="cep-license-title">{m.licenseCardTitle}</h2>
        <p>{m.licenseCardSubtitle}</p>
        <p className="cep-inline-note">{m.licensePilotLimitNotice}</p>

        <div className="cep-license-warning-box">
          <div className="cep-license-warning-header">
            <ExclamationCircleIcon size={20} />
            <strong>{m.licenseAutoAssignWarning}</strong>
          </div>
          <ol className="cep-license-steps">
            {m.licenseAutoAssignSteps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          <a
            className="cep-license-link"
            href="https://admin.google.com/ac/billing/licensesettings"
            rel="noreferrer"
            target="_blank"
          >
            {m.licenseAutoAssignWarningLink} ↗
          </a>
        </div>

        <div className="cep-license-action-row">
          <button
            className="secondary-action cep-license-btn"
            disabled={
              canonicalCustomerId === "" ||
              selectedOu === "" ||
              !targetOuConfirmed ||
              assigningLicenses
            }
            onClick={handleAssignLicenses}
            type="button"
          >
            {assigningLicenses ? m.btnAssigningLicenses : m.btnAssignLicensesToOu}
          </button>
        </div>

        {licenseResult !== null && (
          <div className={licenseResult.success ? "cep-banner cep-banner-ok" : "cep-banner cep-banner-error"}>
            <CheckCircleIcon size={18} />
            <div>
              <strong>{licenseResult.message}</strong>
              {licenseResult.errors.length > 0 && (
                <ul className="cep-license-err-list">
                  {licenseResult.errors.map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
        {licenseError !== "" && licenseResult === null && (
          <p className="cep-inline-error" role="alert">
            {licenseError}
          </p>
        )}
      </section>

      <section className="cep-section" aria-labelledby="cep-presets-title">
        <h2 id="cep-presets-title">{m.presetsTitle}</h2>
        <p>{m.presetsSubtitle}</p>
        <div className="cep-preset-grid">
          {presets.map((preset) => (
            <button
              className="cep-preset"
              key={preset.name}
              onClick={() => {
                setModules(PRESETS[preset.name]);
                setDlpMatrix(PRESET_MATRICES[preset.name]);
              }}
              type="button"
            >
              <strong>{preset.label}</strong>
              <span>{preset.description}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="cep-section" aria-labelledby="cep-modules-title">
        <h2 id="cep-modules-title">{m.modulesTitle}</h2>
        <p>{m.modulesSubtitle}</p>

        <div className="cep-module-list">
          {moduleToggles.map((module) => (
            <label className="cep-check cep-module" key={module.key}>
              <input
                checked={modules[module.key]}
                onChange={(event) => update(module.key, event.target.checked)}
                type="checkbox"
              />
              <span>
                <strong>
                  {module.label}
                  {module.beta === true && <em className="cep-badge">{m.betaBadge}</em>}
                </strong>
                <small>{module.description}</small>
              </span>
            </label>
          ))}
        </div>
        {anyDlpSelected && <p className="cep-inline-note">{m.dlpBetaNote}</p>}

        {modules.dlpRules && (
          <DlpMatrixTable
            matrix={dlpMatrix}
            messages={messages}
            onChange={setDlpMatrix}
            onRegionChange={(reg) => update("dlpRegion", reg)}
            region={modules.dlpRegion}
          />
        )}

        <fieldset className="cep-fieldset">
          <legend>{m.accessLevelTitle}</legend>
          <div className="cep-field">
            <label htmlFor="cep-access-level">{m.accessLevelTitle}</label>
            <select
              id="cep-access-level"
              onChange={(event) => update("accessLevel", event.target.value)}
              value={modules.accessLevel}
            >
              <option value={ACCESS_LEVEL_NONE}>{m.accessLevelNone}</option>
              <option value="AUTO_CREATE_CHROME_ANY">{m.accessLevelAutoAny}</option>
              <option value="AUTO_CREATE_PROFILE_MANAGED">{m.accessLevelAutoProfile}</option>
              <option value="AUTO_CREATE_BROWSER_MANAGED">{m.accessLevelAutoBrowser}</option>
              {accessLevels.length > 0 && (
                <optgroup label={m.accessLevelExistingGroup}>
                  {accessLevels.map((level) => (
                    <option key={level.value} value={level.value}>
                      {level.label}
                    </option>
                  ))}
                </optgroup>
              )}
            </select>
            <small>{m.accessLevelHint}</small>
          </div>
          {accessLevelError && accessLevels.length === 0 && (
            <p className="cep-inline-note">{m.accessLevelLoadFailed}</p>
          )}
        </fieldset>

        <fieldset className="cep-fieldset">
          <legend>{m.dataBoundaryModeTitle}</legend>
          <div className="cep-module-list">
            {boundaryModes.map((mode) => (
              <label className="cep-check cep-module" key={mode.value}>
                <input
                  checked={modules.dataBoundaryMode === mode.value}
                  name="cep-data-boundary"
                  onChange={() => update("dataBoundaryMode", mode.value)}
                  type="radio"
                />
                <span>
                  <strong>{mode.label}</strong>
                  <small>{mode.description}</small>
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="cep-field">
          <label htmlFor="cep-internal-urls">{m.internalUrlsTitle}</label>
          <textarea
            id="cep-internal-urls"
            onChange={(event) => setInternalUrls(event.target.value)}
            placeholder={m.internalUrlsPlaceholder}
            rows={3}
            value={internalUrls}
          />
          <small>{m.internalUrlsHint}</small>
        </div>
      </section>

      <section className="cep-section" aria-labelledby="cep-roles-title">
        <h2 id="cep-roles-title">{m.rolesCardTitle}</h2>
        <p>{m.rolesCardSubtitle}</p>

        <div className="cep-role-grid">
          <article className="cep-role">
            <strong>{m.roleAdminLabel}</strong>
            <span>{m.roleAdminDesc}</span>
          </article>
          <article className="cep-role">
            <strong>{m.roleAuditorLabel}</strong>
            <span>{m.roleAuditorDesc}</span>
          </article>
        </div>

        <a
          className="secondary-action cep-role-action"
          href="https://admin.google.com/ac/roles"
          rel="noreferrer"
          target="_blank"
        >
          {m.rolesAdminConsoleLink}
        </a>
        <p className="cep-inline-note">{m.rolesVerificationNote}</p>
      </section>

      <section className="cep-section" aria-labelledby="cep-testing-title">
        <h2 id="cep-testing-title">{m.testingScenariosTitle}</h2>
        <p>{m.testingScenariosSubtitle}</p>

        <div className="cep-sample-list">
          {samples.map((sample) => (
            <div className="cep-sample" key={sample.key}>
              <div>
                <span className="cep-sample-label">{sample.label}</span>
                <code>{sample.value}</code>
                <small>{sample.hint}</small>
              </div>
              <button
                onClick={() => handleCopy(sample.value, sample.key)}
                type="button"
              >
                {copiedSnippet === sample.key ? m.copiedToClipboard : m.copyDummyData}
              </button>
            </div>
          ))}
        </div>

        <ol className="cep-scenarios">
          <li>
            <strong>{m.scenarioGenAiTitle}</strong>
            <p>{m.scenarioGenAiStep}</p>
          </li>
          <li>
            <strong>{m.scenarioDataBoundaryTitle}</strong>
            <p>{m.scenarioDataBoundaryStep}</p>
          </li>
          <li>
            <strong>{m.scenarioWatermarkTitle}</strong>
            <p>{m.scenarioWatermarkStep}</p>
          </li>
        </ol>
      </section>

      <section className="cep-section cep-manual" aria-labelledby="cep-manual-title">
        <h2 id="cep-manual-title">{m.manualChecklistTitle}</h2>
        <p>{m.manualChecklistSubtitle}</p>
        <ul className="cep-manual-list">
          {m.manualChecklistItems.map((item) => (
            <li key={item.title}>
              <a href={item.href} rel="noreferrer" target="_blank">
                {item.title}
              </a>
              <span>{item.detail}</span>
            </li>
          ))}
        </ul>
      </section>

      <div className="cep-actions">
        <button
          className="primary-action"
          disabled={!canDeploy}
          onClick={handleDeploy}
          type="button"
        >
          {busy === "deploy" ? m.btnDeploying : m.btnDeploy}
        </button>
        <button
          className="secondary-action"
          disabled={canonicalCustomerId === "" || selectedOu === "" || busy !== null}
          onClick={handleDownloadScript}
          type="button"
        >
          {m.btnDownloadScript}
        </button>
        <button
          className="danger-action cep-rollback"
          disabled={canonicalCustomerId === "" || selectedOu === "" || busy !== null}
          onClick={handleRollback}
          type="button"
        >
          {busy === "rollback" ? m.btnRollingBack : m.btnRollback}
        </button>
      </div>
      {!anyModuleSelected && <p className="cep-inline-note">{m.noModulesSelected}</p>}

      {actionSuccess !== "" && (
        <p className="cep-banner cep-banner-ok">
          <CheckCircleIcon size={18} />
          <span>{actionSuccess}</span>
        </p>
      )}
      {actionError !== "" && (
        <p className="cep-banner cep-banner-error" role="alert">
          <ExclamationCircleIcon size={18} />
          <span>{actionError}</span>
        </p>
      )}

      {lastResult !== null && lastResult.created_items.length > 0 && (
        <section className="cep-outcome" aria-labelledby="cep-applied-title">
          <h3 id="cep-applied-title">{m.appliedTitle}</h3>
          <ul>
            {lastResult.created_items.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>
      )}

      {lastResult !== null && lastResult.skipped_items.length > 0 && (
        <section className="cep-outcome cep-outcome-skipped" aria-labelledby="cep-skipped-title">
          <h3 id="cep-skipped-title">{m.skippedTitle}</h3>
          <ul>
            {lastResult.skipped_items.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>
      )}

      <section className="cep-outcome" aria-labelledby="cep-trace-title">
        <h3 id="cep-trace-title">{m.statusLogTitle}</h3>
        {lastResult !== null && lastResult.debug_trace.length > 0 ? (
          <ul className="cep-trace">
            {lastResult.debug_trace.map((entry, index) => (
              <li className={entry.ok ? "ok" : "failed"} key={`${entry.label}-${index}`}>
                <span>
                  {entry.method} {entry.label}
                </span>
                <small>{entry.error ?? `HTTP ${entry.status}`}</small>
              </li>
            ))}
          </ul>
        ) : (
          <p>{m.noActionYet}</p>
        )}
      </section>
    </main>
  );
}
