import { useCallback, useEffect, useState } from "react";
import { CheckIcon, CloudIcon, InfoIcon, ShieldIcon } from "../../components/Icons";
import type { OperationsMessages } from "../../i18n/messages";
import {
  type DeploymentDetails,
  type GatewayLogCategory,
  type GatewayLogsResponse,
  type SetupOption,
  type TeardownPlan,
  type TeardownRun,
  enableGatewayLogging,
  getDeploymentDetails,
  getTeardownPlan,
  getTeardownRun,
  listAccessLevelOptions,
  listGatewayLogs,
  startTeardown,
  updateAccessLevel,
  cleanState,
  bootstrapSampleBackend,
  diagnoseGcp,
  type SampleBackendResult,
} from "../../lib/api";

type ManagerTab = "overview" | "logs" | "resources" | "delete";

interface DeploymentManagerProps {
  copy: OperationsMessages;
  runId: string;
  onClose: () => void;
}

const LOG_CATEGORIES: GatewayLogCategory[] = [
  "access",
  "connection",
  "admin",
  "nginx",
];

export function DeploymentManager({ copy, runId, onClose }: DeploymentManagerProps) {
  const [details, setDetails] = useState<DeploymentDetails | null>(null);
  const [teardownPlan, setTeardownPlan] = useState<TeardownPlan | null>(null);
  const [tab, setTab] = useState<ManagerTab>("overview");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [accessLevel, setAccessLevel] = useState<string>("");
  const [principals, setPrincipals] = useState<string>("user:admin@test-domain.dev");
  const [accessLevelOptions, setAccessLevelOptions] = useState<SetupOption[]>([]);
  const [accessLevelBusy, setAccessLevelBusy] = useState(false);
  const [accessLevelSuccess, setAccessLevelSuccess] = useState(false);
  const [accessLevelError, setAccessLevelError] = useState("");
  const [logCategory, setLogCategory] = useState<GatewayLogCategory>("access");
  const [logHours, setLogHours] = useState(24);
  const [logs, setLogs] = useState<GatewayLogsResponse | null>(null);
  const [logsBusy, setLogsBusy] = useState(false);
  const [logsError, setLogsError] = useState("");
  const [loggingBusy, setLoggingBusy] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const [teardown, setTeardown] = useState<TeardownRun | null>(null);
  const [teardownError, setTeardownError] = useState("");
  const [cleanBusy, setCleanBusy] = useState(false);
  const [cleanLogs, setCleanLogs] = useState<string[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    Promise.all([
      getDeploymentDetails(runId),
      getTeardownPlan(runId).catch(() => null),
    ])
      .then(([nextDetails, nextPlan]) => {
        if (cancelled) return;
        setDetails(nextDetails);
        setTeardownPlan(nextPlan);
      })
      .catch(() => {
        if (!cancelled) setError(copy.loadFailed);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [copy.loadFailed, runId]);

  const refreshLogs = useCallback(async () => {
    setLogsBusy(true);
    setLogsError("");
    try {
      setLogs(await listGatewayLogs(runId, logCategory, logHours));
    } catch {
      setLogsError(copy.logQueryFailed);
    } finally {
      setLogsBusy(false);
    }
  }, [copy.logQueryFailed, logCategory, logHours, runId]);

  useEffect(() => {
    if (tab === "logs" && logs === null && !logsBusy && !logsError) {
      void refreshLogs();
    }
  }, [logs, logsBusy, logsError, refreshLogs, tab]);

  useEffect(() => {
    if (!teardown || !["pending", "running"].includes(teardown.status)) return;
    let cancelled = false;
    const timeout = window.setTimeout(() => {
      getTeardownRun(teardown.teardown_id)
        .then((next) => {
          if (!cancelled) setTeardown(next);
        })
        .catch(() => {
          if (!cancelled) setTeardownError(copy.teardownActionFailed);
        });
    }, 1500);
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [copy.teardownActionFailed, teardown]);

  async function handleEnableLogging() {
    setLoggingBusy(true);
    setLogsError("");
    try {
      await enableGatewayLogging(runId);
      await refreshLogs();
    } catch {
      setLogsError(copy.logQueryFailed);
    } finally {
      setLoggingBusy(false);
    }
  }

  useEffect(() => {
    if (details?.managed_chrome_access_level) {
      setAccessLevel(details.managed_chrome_access_level);
    }
    if (details?.target_group_email) {
      setPrincipals(`group:${details.target_group_email}`);
    }
    if (details?.project_id) {
      listAccessLevelOptions(details.project_id)
        .then((options) => setAccessLevelOptions(options))
        .catch(() => setAccessLevelOptions([]));
    }
  }, [details]);

  async function handleUpdateAccessLevel() {
    setAccessLevelBusy(true);
    setAccessLevelError("");
    setAccessLevelSuccess(false);
    try {
      const principalList = principals
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      await updateAccessLevel(runId, accessLevel, principalList);
      setAccessLevelSuccess(true);
      setDetails((prev) => (prev ? { ...prev, managed_chrome_access_level: accessLevel } : prev));
    } catch (err: any) {
      setAccessLevelError(err?.message || "Failed to update access level");
    } finally {
      setAccessLevelBusy(false);
    }
  }

  async function handleTeardown() {
    if (!teardownPlan || confirmation !== teardownPlan.confirmation) return;
    setTeardownError("");
    try {
      setTeardown(await startTeardown(runId, teardownPlan, confirmation));
    } catch {
      setTeardownError(copy.teardownActionFailed);
    }
  }

  async function handleCleanStateAll() {
    const targetProject = details?.project_id || "";
    if (!targetProject) {
      setCleanLogs(["エラー: 対象の Google Cloud プロジェクト ID が特定できません。"]);
      return;
    }
    if (
      !window.confirm(
        `Google Cloud プロジェクト（${targetProject}）上にデプロイされている BeyondCorp Security Gateway、Application、サンプルVM、VPC、Cloud DNS、およびローカル実行履歴をすべて完全に削除します。よろしいですか？`,
      )
    ) {
      return;
    }
    setCleanBusy(true);
    setCleanLogs(null);
    try {
      const res = await cleanState(targetProject);
      setCleanLogs(res.log);
    } catch (err: any) {
      setCleanLogs([`エラーが発生しました: ${err?.message || err}`]);
    } finally {
      setCleanBusy(false);
    }
  }

  const [bootstrapBusy, setBootstrapBusy] = useState(false);
  const [bootstrapResult, setBootstrapResult] = useState<SampleBackendResult | null>(null);
  const [bootstrapError, setBootstrapError] = useState("");

  async function handleBootstrapSampleBackend() {
    const targetProject = details?.project_id || "";
    if (!targetProject) {
      setBootstrapError("対象の Google Cloud プロジェクト ID が設定されていません。");
      return;
    }
    setBootstrapBusy(true);
    setBootstrapError("");
    try {
      const res = await bootstrapSampleBackend(targetProject);
      setBootstrapResult(res);
    } catch (err: any) {
      setBootstrapError(err?.message || "バックエンドの起動に失敗しました");
    } finally {
      setBootstrapBusy(false);
    }
  }

  const [diagnoseBusy, setDiagnoseBusy] = useState(false);
  const [diagnoseResult, setDiagnoseResult] = useState<Record<string, any> | null>(null);
  const [diagnoseError, setDiagnoseError] = useState("");

  async function handleDiagnoseGcp() {
    const targetProject = details?.project_id || "";
    if (!targetProject) {
      setDiagnoseError("対象の Google Cloud プロジェクト ID が設定されていません。");
      return;
    }
    setDiagnoseBusy(true);
    setDiagnoseError("");
    try {
      const res = await diagnoseGcp(targetProject);
      setDiagnoseResult(res.report);
    } catch (err: any) {
      setDiagnoseError(err?.message || "GCPリソースの診断に失敗しました");
    } finally {
      setDiagnoseBusy(false);
    }
  }

  function changeLogCategory(category: GatewayLogCategory) {
    setLogCategory(category);
    setLogs(null);
    setLogsError("");
  }

  function changeLogHours(hours: number) {
    setLogHours(hours);
    setLogs(null);
    setLogsError("");
  }

  const completedTeardownOperations =
    teardown?.operations.filter((operation) =>
      ["succeeded", "failed", "skipped"].includes(operation.status),
    ).length ?? 0;

  const isDeleted = Boolean(teardown?.status === "succeeded" || cleanLogs !== null);

  return (
    <section className="deployment-manager" aria-label={copy.manage}>
      <header className="deployment-manager-heading">
        <div>
          <span>{copy.deploymentName}</span>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "4px" }}>
            <h2 style={{ margin: 0 }}>{details?.deployment_name ?? runId.slice(0, 12)}</h2>
            <span className={`status-pill status-${isDeleted ? "deleted" : "succeeded"}`}>
              {isDeleted ? (copy.statusDeleted || "Deleted") : (copy.statusSucceeded || "Success")}
            </span>
          </div>
          <code>{runId}</code>
        </div>
        <button className="secondary-action" onClick={onClose} type="button">
          {copy.close}
        </button>
      </header>

      <nav className="deployment-manager-tabs" aria-label={copy.manage}>
        {(
          [
            ["overview", copy.overviewTab],
            ["logs", copy.logsTab],
            ["resources", copy.resourcesTab],
            ["delete", copy.deleteTab],
          ] as const
        ).map(([value, label]) => (
          <button
            aria-pressed={tab === value}
            key={value}
            onClick={() => setTab(value)}
            type="button"
          >
            {label}
          </button>
        ))}
      </nav>

      {loading ? <p className="empty-state">{copy.loading}</p> : null}
      {error ? <p className="connection-error" role="alert">{error}</p> : null}

      {!loading && !error && details && tab === "overview" ? (
        <>
          <div className="deployment-overview-grid">
            <article><small>{copy.project}</small><strong>{details.project_id}</strong></article>
            <article><small>{copy.gateway}</small><strong>{details.gateway_id}</strong></article>
            <article>
              <small>{copy.application}</small>
              <strong>{details.application_hostname}:{details.application_port}</strong>
            </article>
            <article>
              <small>{copy.architecture}</small>
              <strong>{copy.architectureLabel(details.backend_kind)}</strong>
            </article>
            {details.ownership_run_id ? (
              <article>
                <small>{copy.ownershipRun}</small>
                <strong>{details.ownership_run_id.slice(0, 12)}</strong>
              </article>
            ) : null}
          </div>

          <div className="access-level-control-panel">
            <div className="access-level-header">
              <div className="access-level-title-group">
                <ShieldIcon size={20} />
                <div>
                  <h3>{copy.accessLevelControlTitle}</h3>
                  <p>{copy.accessLevelControlIntro}</p>
                </div>
              </div>
              {accessLevelSuccess && (
                <span className="access-level-saved-badge">
                  <CheckIcon size={16} /> {copy.accessLevelSaved}
                </span>
              )}
            </div>

            <div className="access-level-form">
              <div className="access-level-field">
                <label htmlFor="select-access-level">
                  <strong>{copy.selectAccessLevelLabel}</strong>
                </label>
                {accessLevelOptions.length > 0 ? (
                  <select
                    id="select-access-level"
                    value={accessLevel}
                    onChange={(e) => {
                      setAccessLevel(e.target.value);
                      setAccessLevelSuccess(false);
                    }}
                    disabled={accessLevelBusy}
                  >
                    <option value="">{copy.noAccessLevelRequired}</option>
                    {accessLevelOptions.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label} ({opt.value.split("/").pop()})
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    id="select-access-level"
                    type="text"
                    placeholder="accessPolicies/.../accessLevels/browser_is_managed_..."
                    value={accessLevel}
                    onChange={(e) => {
                      setAccessLevel(e.target.value);
                      setAccessLevelSuccess(false);
                    }}
                    disabled={accessLevelBusy}
                  />
                )}
                {details.target_group_email && (
                  <small className="access-level-helper">
                    {copy.boundGroup}: <code>group:{details.target_group_email}</code>
                  </small>
                )}
              </div>

              <div className="access-level-field" style={{ minWidth: "280px" }}>
                <label htmlFor="input-principals">
                  <strong>{copy.principalsLabel}</strong>
                </label>
                <input
                  id="input-principals"
                  type="text"
                  placeholder="user:admin@test-domain.dev, domain:test-domain.dev"
                  value={principals}
                  onChange={(e) => {
                    setPrincipals(e.target.value);
                    setAccessLevelSuccess(false);
                  }}
                  disabled={accessLevelBusy}
                />
                <small className="access-level-helper">{copy.principalsHelper}</small>
              </div>

              <button
                type="button"
                className="primary-action"
                disabled={accessLevelBusy}
                onClick={() => void handleUpdateAccessLevel()}
              >
                {accessLevelBusy ? copy.updatingAccessLevel : copy.updateAccessLevelButton}
              </button>
            </div>

            {accessLevelError && (
              <p className="connection-error" role="alert">{accessLevelError}</p>
            )}
          </div>

          <div className="summary-card" style={{ marginTop: "1rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <strong>🚀 テスト用バックエンドVM &amp; Cloud DNS</strong>
                <p style={{ margin: "4px 0 0", fontSize: "0.85rem", color: "var(--color-text-secondary)" }}>
                  Google Cloud VPC (<code>secgw-test-vpc</code>) 内に NGINX バックエンドVM (<code>10.10.0.2</code>) とプライベート DNS ゾーン (<code>secgw-backend.internal</code>) をプロビジョニングします。
                </p>
              </div>
              <button
                type="button"
                className="primary-action"
                disabled={bootstrapBusy}
                onClick={() => void handleBootstrapSampleBackend()}
              >
                {bootstrapBusy ? "プロビジョニング中..." : "サンプルバックエンドを起動"}
              </button>
            </div>
            {bootstrapResult && (
              <div style={{ marginTop: "12px" }}>
                <div className="sample-backend-success">
                  <strong>✅ バックエンド起動状況 ({bootstrapResult.hostname})</strong>
                  <p style={{ margin: "4px 0 0", fontSize: "0.85rem" }}>
                    VM: <code>{bootstrapResult.vm_name}</code> (IP: <code>{bootstrapResult.internal_ip}</code>) | VPC: <code>{bootstrapResult.vpc_name}</code>
                  </p>
                </div>
                {bootstrapResult.log && bootstrapResult.log.length > 0 && (
                  <pre style={{
                    background: "#070a12",
                    border: "1px solid #22304d",
                    borderRadius: "8px",
                    padding: "0.8rem",
                    marginTop: "8px",
                    maxHeight: "260px",
                    overflowY: "auto",
                    fontSize: "0.78rem",
                    color: "#34d399",
                    lineHeight: "1.4",
                  }}>
                    {bootstrapResult.log.join("\n")}
                  </pre>
                )}
              </div>
            )}
            {bootstrapError && (
              <p className="connection-error" style={{ marginTop: "8px" }} role="alert">
                {bootstrapError}
              </p>
            )}
          </div>

          <div className="summary-card" style={{ marginTop: "1rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <strong>🔍 GCP リソース完全診断 (リアルタイム)</strong>
                <p style={{ margin: "4px 0 0", fontSize: "0.85rem", color: "var(--color-text-secondary)" }}>
                  サービスアカウント権限を使って、GCP上の BeyondCorp Gateway、Application、IAM、VPC、サブネット、VM、ファイアウォール、Cloud DNS の実態を直接取得します。
                </p>
              </div>
              <button
                type="button"
                className="secondary-action"
                disabled={diagnoseBusy}
                onClick={() => void handleDiagnoseGcp()}
              >
                {diagnoseBusy ? "診断中..." : "GCPリソース診断を実行"}
              </button>
            </div>
            {diagnoseResult && (
              <div style={{ marginTop: "12px" }}>
                <pre style={{
                  background: "#070a12",
                  border: "1px solid #22304d",
                  borderRadius: "8px",
                  padding: "1rem",
                  maxHeight: "360px",
                  overflowY: "auto",
                  fontSize: "0.8rem",
                  color: "#38bdf8",
                  lineHeight: "1.4",
                }}>
                  {JSON.stringify(diagnoseResult, null, 2)}
                </pre>
              </div>
            )}
            {diagnoseError && (
              <p className="connection-error" style={{ marginTop: "8px" }} role="alert">
                {diagnoseError}
              </p>
            )}
          </div>
        </>
      ) : null}

      {!loading && !error && tab === "logs" ? (
        <div className="deployment-log-panel">
          <div className="deployment-panel-intro">
            <div><h3>{copy.logsTitle}</h3><p>{copy.logsIntro}</p></div>
            <div className="deployment-log-actions">
              {logs?.logging_enabled === false ? (
                <button
                  className="secondary-action"
                  disabled={loggingBusy}
                  onClick={() => void handleEnableLogging()}
                  type="button"
                >
                  {loggingBusy ? copy.enablingLogging : copy.enableLogging}
                </button>
              ) : null}
              <button
                className="primary-action"
                disabled={logsBusy}
                onClick={() => void refreshLogs()}
                type="button"
              >
                {logsBusy ? copy.refreshingLogs : copy.refreshLogs}
              </button>
            </div>
          </div>
          <div className="log-filter-row">
            <div className="log-category-tabs">
              {LOG_CATEGORIES.map((category) => (
                <button
                  aria-pressed={logCategory === category}
                  key={category}
                  onClick={() => changeLogCategory(category)}
                  type="button"
                >
                  {copy.logCategory(category)}
                </button>
              ))}
            </div>
            <select
              aria-label={copy.started}
              onChange={(event) => changeLogHours(Number(event.target.value))}
              value={logHours}
            >
              <option value={24}>{copy.hours24}</option>
              <option value={168}>{copy.hours168}</option>
            </select>
          </div>
          {logs?.logging_enabled === true ? (
            <p className="inline-status success"><CheckIcon size={17} />{copy.loggingEnabled}</p>
          ) : logs?.logging_enabled === false ? (
            <p className="inline-status warning"><InfoIcon size={17} />{copy.loggingNotEnabled}</p>
          ) : null}
          {logs?.data_access_notice ? <p className="deployment-notice">{copy.dataAccessNotice}</p> : null}
          {logs?.setup_notice ? <p className="deployment-notice">{logs.setup_notice}</p> : null}
          {logCategory === "nginx" ? <p className="deployment-notice">{copy.nginxNotice}</p> : null}
          {logsError ? <p className="connection-error" role="alert">{logsError}</p> : null}
          {logsBusy ? <p className="empty-state">{copy.refreshingLogs}</p> : null}
          {!logsBusy && logs && logs.entries.length === 0 ? (
            <p className="empty-state">{copy.noLogs}</p>
          ) : null}
          <div className="gateway-log-list">
            {logs?.entries.map((entry) => (
              <article key={entry.insert_id}>
                <header>
                  <span className={`log-severity severity-${entry.severity.toLowerCase()}`}>
                    {entry.severity}
                  </span>
                  <time>{entry.timestamp ? new Date(entry.timestamp).toLocaleString() : copy.notAvailable}</time>
                </header>
                <strong>{entry.summary}</strong>
                <dl>
                  {entry.principal ? <><dt>{copy.principal}</dt><dd>{entry.principal}</dd></> : null}
                  {entry.method ? <><dt>{copy.method}</dt><dd>{entry.method}</dd></> : null}
                  {entry.request_id ? <><dt>{copy.requestId}</dt><dd><code>{entry.request_id}</code></dd></> : null}
                </dl>
                <details><summary>{copy.payload}</summary><pre>{JSON.stringify(entry.payload, null, 2)}</pre></details>
              </article>
            ))}
          </div>
        </div>
      ) : null}

      {!loading && !error && details && tab === "resources" ? (
        <div className="resource-inventory-grid">
          <ResourceList
            copy={copy}
            resources={details.resources.filter((resource) => resource.teardown_action !== "retain")}
            title={copy.ownedResources}
          />
          <ResourceList
            copy={copy}
            resources={details.resources.filter((resource) => resource.teardown_action === "retain")}
            title={copy.retainedResources}
          />
        </div>
      ) : null}

      {!loading && !error && details && tab === "delete" ? (
        <div className="teardown-panel">
          <div className="teardown-warning">
            <ShieldIcon size={24} />
            <div><h3>{copy.teardownTitle}</h3><p>{copy.teardownIntro}</p></div>
          </div>
          <p className="deployment-notice">{copy.teardownSharedNotice}</p>
          {!teardownPlan?.can_destroy ? (
            <p className="empty-state">{copy.teardownUnavailable}</p>
          ) : (
            <>
              <ResourceList copy={copy} resources={teardownPlan.resources} title={copy.ownedResources} />
              <label className="teardown-confirmation">
                <span>{copy.teardownConfirmation}</span>
                <code>{teardownPlan.confirmation}</code>
                <input
                  disabled={Boolean(teardown && ["pending", "running", "succeeded"].includes(teardown.status))}
                  onChange={(event) => setConfirmation(event.target.value)}
                  placeholder={copy.teardownConfirmationHint}
                  value={confirmation}
                />
              </label>
              {teardown ? (
                <div className={`teardown-progress status-${teardown.status}`}>
                  <CloudIcon size={22} />
                  <div>
                    <strong>
                      {["pending", "running"].includes(teardown.status)
                        ? copy.teardownRunning
                        : teardown.status === "succeeded"
                          ? copy.teardownSucceeded
                          : copy.teardownFailed}
                    </strong>
                    <small>{copy.teardownProgress(completedTeardownOperations, teardown.operations.length)}</small>
                    <progress max={Math.max(teardown.operations.length, 1)} value={completedTeardownOperations} />
                  </div>
                </div>
              ) : null}
              {teardownError ? <p className="connection-error" role="alert">{teardownError}</p> : null}
              <button
                className="danger-action"
                disabled={
                  confirmation !== teardownPlan.confirmation ||
                  Boolean(teardown && ["pending", "running", "succeeded"].includes(teardown.status))
                }
                onClick={() => void handleTeardown()}
                type="button"
              >
                {teardown && ["pending", "running"].includes(teardown.status)
                  ? copy.teardownRunning
                  : copy.startTeardown}
              </button>
            </>
          )}

          <div
            className="clean-state-all-box"
            style={{
              marginTop: "28px",
              padding: "16px 20px",
              background: "rgba(239, 68, 68, 0.06)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              borderRadius: "8px",
            }}
          >
            <h4 style={{ margin: "0 0 8px", color: "var(--color-danger, #ef4444)", display: "flex", alignItems: "center", gap: "8px" }}>
              💥 全インフラ・SGWを完全クリーン削除 (Clean State All)
            </h4>
            <p style={{ margin: "0 0 14px", fontSize: "13px", color: "var(--color-text-secondary)", lineHeight: "1.6" }}>
              Google Cloud プロジェクト（<code>{details?.project_id || "対象プロジェクト"}</code>）に作成された SGW・Application・サンプルVM（10.10.0.2）・VPC（secgw-test-vpc）・Cloud DNS・ローカルDBをすべて一括削除し、初期クリーン状態に戻します。
            </p>
            <button
              className="danger-action"
              disabled={cleanBusy}
              onClick={() => void handleCleanStateAll()}
              type="button"
            >
              {cleanBusy ? "完全クリーン削除中..." : "全インフラ・SGWを一括完全削除"}
            </button>
            {cleanLogs ? (
              <div
                style={{
                  marginTop: "14px",
                  padding: "12px 16px",
                  background: "#111827",
                  color: "#10b981",
                  borderRadius: "6px",
                  fontSize: "12px",
                  fontFamily: "monospace",
                  maxHeight: "220px",
                  overflowY: "auto",
                }}
              >
                <strong>削除ログ:</strong>
                <ul style={{ margin: "6px 0 0", paddingLeft: "18px" }}>
                  {cleanLogs.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </section>
  );
}

function ResourceList({
  copy,
  resources,
  title,
}: {
  copy: OperationsMessages;
  resources: DeploymentDetails["resources"];
  title: string;
}) {
  return (
    <section className="resource-list-card">
      <h3>{title}</h3>
      {resources.length === 0 ? <p className="empty-state">—</p> : null}
      <ul>
        {resources.map((resource) => (
          <li key={resource.resource_key}>
            <div><strong>{resource.resource_name}</strong><small>{resource.summary}</small></div>
            <span className={`resource-action action-${resource.teardown_action}`}>
              {copy.resourceAction(resource.teardown_action)}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
