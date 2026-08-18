import { useEffect, useState } from "react";
import type { Messages } from "../../i18n/messages";
import type {
  CepDataBoundaryMode,
  CepDlpAction,
  CepDlpRuleId,
  CepProvisionConfig,
  CepProvisionResult,
  SetupOption,
} from "../../lib/api";
import {
  createCepCustomRoles,
  generateCepScript,
  listAccessLevelOptions,
  listOrganizationalUnitOptions,
  provisionCepPolicies,
  rollbackCepPolicies,
} from "../../lib/api";
import {
  CheckCircleIcon,
  ExclamationCircleIcon,
  ShieldNetworkIcon,
} from "../../components/Icons";

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
  dlpRuleActions: Record<CepDlpRuleId, CepDlpAction>;
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

/** Audit first: an evaluation that starts by blocking gets switched off. */
const DEFAULT_RULE_ACTIONS: Record<CepDlpRuleId, CepDlpAction> = {
  payment_card: "auditOnly",
  national_id: "auditOnly",
  access_level: "auditOnly",
  watermark: "auditOnly",
};

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
    dlpDetectors: true,
    dlpRules: true,
    dlpRegion: "JP",
    dlpRuleActions: DEFAULT_RULE_ACTIONS,
    dataBoundaryMode: "copy_paste",
  },
  ai: {
    corePolicies: true,
    forceExtensions: false,
    connectors: true,
    accessLevel: ACCESS_LEVEL_NONE,
    dlpDetectors: true,
    dlpRules: true,
    dlpRegion: "JP",
    dlpRuleActions: DEFAULT_RULE_ACTIONS,
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
    dlpRuleActions: DEFAULT_RULE_ACTIONS,
    dataBoundaryMode: "none",
  },
  audit: {
    corePolicies: true,
    forceExtensions: false,
    connectors: true,
    accessLevel: ACCESS_LEVEL_NONE,
    dlpDetectors: true,
    dlpRules: true,
    dlpRegion: "JP",
    dlpRuleActions: DEFAULT_RULE_ACTIONS,
    dataBoundaryMode: "none",
  },
};

export function CepDeployerPage({
  messages,
  customerId,
  projectId,
}: CepDeployerPageProps) {
  const m = messages.cepDeployer;

  const [organizationalUnits, setOrganizationalUnits] = useState<SetupOption[]>([]);
  const [selectedOu, setSelectedOu] = useState<string>("");
  const [ouError, setOuError] = useState<boolean>(false);
  const [autoSubOus, setAutoSubOus] = useState<boolean>(true);

  const [modules, setModules] = useState<ModuleState>(PRESETS.full);
  const [internalUrls, setInternalUrls] = useState<string>("");

  const [accessLevels, setAccessLevels] = useState<SetupOption[]>([]);
  const [accessLevelError, setAccessLevelError] = useState<boolean>(false);

  const [assignUserEmail, setAssignUserEmail] = useState<string>("");
  const [rolesBusy, setRolesBusy] = useState<boolean>(false);
  const [rolesMessage, setRolesMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const [busy, setBusy] = useState<"deploy" | "rollback" | null>(null);
  const [actionError, setActionError] = useState<string>("");
  const [actionSuccess, setActionSuccess] = useState<string>("");
  const [lastResult, setLastResult] = useState<CepProvisionResult | null>(null);
  const [copiedSnippet, setCopiedSnippet] = useState<string>("");

  useEffect(() => {
    let active = true;
    async function loadOus() {
      try {
        const options = await listOrganizationalUnitOptions(customerId || "my_customer");
        if (!active) return;
        setOrganizationalUnits(options);
        setOuError(options.length === 0);
        if (options.length > 0) setSelectedOu(options[0].value);
      } catch {
        // The previous version fell back to `my_customer`, which is not a valid
        // policy target, so Apply failed later with an opaque Google error.
        if (active) setOuError(true);
      }
    }
    void loadOus();
    return () => {
      active = false;
    };
  }, [customerId]);

  useEffect(() => {
    let active = true;
    async function loadAccessLevels() {
      if (!projectId) {
        setAccessLevels([]);
        setAccessLevelError(true);
        return;
      }
      try {
        const options = await listAccessLevelOptions(projectId);
        if (!active) return;
        // The endpoint prepends its own sentinels for the deployment wizard;
        // this page renders localized ones, so keep only the real levels.
        const existing = options.filter(
          (option) =>
            option.value !== ACCESS_LEVEL_NONE &&
            !AUTO_CREATE_SENTINELS.includes(option.value),
        );
        setAccessLevels(existing);
        setAccessLevelError(false);
      } catch {
        if (active) {
          setAccessLevels([]);
          setAccessLevelError(true);
        }
      }
    }
    void loadAccessLevels();
    return () => {
      active = false;
    };
  }, [projectId]);

  const selectedUnit = organizationalUnits.find((unit) => unit.value === selectedOu);
  const anyModuleSelected =
    modules.corePolicies ||
    modules.forceExtensions ||
    modules.connectors ||
    modules.accessLevel !== ACCESS_LEVEL_NONE ||
    modules.dlpDetectors ||
    modules.dlpRules ||
    modules.dataBoundaryMode !== "none";
  const canDeploy = selectedOu !== "" && anyModuleSelected && busy === null;

  function update<K extends keyof ModuleState>(key: K, value: ModuleState[K]) {
    setModules((current) => ({ ...current, [key]: value }));
  }

  function currentConfig(): CepProvisionConfig {
    return {
      customer_id: customerId || "my_customer",
      project_id: projectId,
      target_ou_id: selectedOu,
      target_ou_path: selectedUnit?.label,
      create_sub_ous: autoSubOus,
      core_policies: modules.corePolicies,
      force_extensions: modules.forceExtensions,
      connectors: modules.connectors,
      access_level: modules.accessLevel,
      dlp_detectors: modules.dlpDetectors,
      dlp_rules: modules.dlpRules,
      dlp_region: modules.dlpRegion,
      dlp_rule_actions: modules.dlpRuleActions,
      data_boundary_mode: modules.dataBoundaryMode,
      internal_urls: internalUrls
        .split("\n")
        .map((url) => url.trim())
        .filter(Boolean),
    };
  }

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
    setBusy("deploy");
    setActionError("");
    setActionSuccess("");
    try {
      applyResult(await provisionCepPolicies(currentConfig()));
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  const handleRollback = async () => {
    if (!window.confirm(m.confirmRollback)) return;
    setBusy("rollback");
    setActionError("");
    setActionSuccess("");
    try {
      applyResult(
        await rollbackCepPolicies({
          customer_id: customerId || "my_customer",
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

  const handleProvisionRoles = async () => {
    if (!projectId) {
      setRolesMessage({ ok: false, text: m.rolesProjectRequired });
      return;
    }
    setRolesBusy(true);
    setRolesMessage(null);
    try {
      const result = await createCepCustomRoles({
        project_id: projectId,
        customer_id: customerId || "my_customer",
        role_type: "both",
        assigned_user_email: assignUserEmail.trim() || undefined,
      });
      setRolesMessage({ ok: result.success, text: result.message });
    } catch (error) {
      setRolesMessage({
        ok: false,
        text: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setRolesBusy(false);
    }
  };

  const handleDownloadScript = async () => {
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
      key: "dlpDetectors",
      label: m.moduleDlpDetectors,
      description: m.moduleDlpDetectorsDesc,
      beta: true,
    },
    {
      key: "dlpRules",
      label: m.moduleDlpRules,
      description: m.moduleDlpRulesDesc,
      beta: true,
    },
  ];

  const anyDlpSelected = modules.dlpDetectors || modules.dlpRules;

  const dlpRuleRows: Array<{ id: CepDlpRuleId; label: string }> = [
    { id: "payment_card", label: m.dlpRulePaymentCard },
    { id: "national_id", label: m.dlpRuleNationalId },
    { id: "access_level", label: m.dlpRuleAccessLevel },
    { id: "watermark", label: m.dlpRuleWatermark },
  ];

  const dlpActions: Array<{ value: CepDlpAction; label: string }> = [
    { value: "off", label: m.dlpActionOff },
    { value: "auditOnly", label: m.dlpActionAudit },
    { value: "warnUser", label: m.dlpActionWarn },
    { value: "blockContent", label: m.dlpActionBlock },
  ];

  function setRuleAction(id: CepDlpRuleId, action: CepDlpAction) {
    setModules((current) => ({
      ...current,
      dlpRuleActions: { ...current.dlpRuleActions, [id]: action },
    }));
  }

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

        {ouError ? (
          <p className="cep-inline-error" role="alert">
            {m.ouLoadFailed}
          </p>
        ) : (
          <div className="cep-field">
            <label htmlFor="cep-target-ou">{m.selectTargetOu}</label>
            <select
              id="cep-target-ou"
              onChange={(event) => setSelectedOu(event.target.value)}
              value={selectedOu}
            >
              {organizationalUnits.map((unit) => (
                <option key={unit.value} value={unit.value}>
                  {unit.label}
                </option>
              ))}
            </select>
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

      <section className="cep-section" aria-labelledby="cep-presets-title">
        <h2 id="cep-presets-title">{m.presetsTitle}</h2>
        <p>{m.presetsSubtitle}</p>
        <div className="cep-preset-grid">
          {presets.map((preset) => (
            <button
              className="cep-preset"
              key={preset.name}
              onClick={() => setModules(PRESETS[preset.name])}
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
          <fieldset className="cep-fieldset">
            <legend>{m.dlpRulesTableTitle}</legend>
            <div className="cep-field">
              <label htmlFor="cep-dlp-region">{m.dlpRegionTitle}</label>
              <select
                id="cep-dlp-region"
                onChange={(event) => update("dlpRegion", event.target.value)}
                value={modules.dlpRegion}
              >
                {DLP_REGIONS.map((region) => (
                  <option key={region.value} value={region.value}>
                    {region.label}
                  </option>
                ))}
              </select>
              <small>{m.dlpRegionHint}</small>
            </div>

            <p className="cep-inline-note">{m.dlpRulesTableHint}</p>
            <ul className="cep-rule-list">
              {dlpRuleRows.map((rule) => (
                <li key={rule.id}>
                  <label htmlFor={`cep-rule-${rule.id}`}>{rule.label}</label>
                  <select
                    id={`cep-rule-${rule.id}`}
                    onChange={(event) =>
                      setRuleAction(rule.id, event.target.value as CepDlpAction)
                    }
                    value={modules.dlpRuleActions[rule.id]}
                  >
                    {dlpActions.map((action) => (
                      <option key={action.value} value={action.value}>
                        {action.label}
                      </option>
                    ))}
                  </select>
                </li>
              ))}
            </ul>
          </fieldset>
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

        <div className="cep-role-form">
          <div className="cep-field">
            <label htmlFor="cep-assign-email">{m.assignUserEmailLabel}</label>
            <input
              id="cep-assign-email"
              onChange={(event) => setAssignUserEmail(event.target.value)}
              placeholder={m.assignUserEmailPlaceholder}
              type="email"
              value={assignUserEmail}
            />
          </div>
          <button
            className="secondary-action cep-role-action"
            disabled={rolesBusy}
            onClick={handleProvisionRoles}
            type="button"
          >
            {rolesBusy ? m.provisioningRoles : m.provisionRolesButton}
          </button>
        </div>
        {rolesMessage !== null && (
          <p
            className={rolesMessage.ok ? "cep-inline-note" : "cep-inline-error"}
            role={rolesMessage.ok ? undefined : "alert"}
          >
            {rolesMessage.text}
          </p>
        )}
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
          disabled={selectedOu === "" || busy !== null}
          onClick={handleDownloadScript}
          type="button"
        >
          {m.btnDownloadScript}
        </button>
        <button
          className="danger-action cep-rollback"
          disabled={selectedOu === "" || busy !== null}
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
