import { useCallback, useEffect, useState } from "react";
import { CheckIcon, CloudIcon, InfoIcon, ShieldIcon } from "../../components/Icons";
import type { OperationsMessages } from "../../i18n/messages";
import {
  type DeploymentDetails,
  type GatewayLogCategory,
  type GatewayLogsResponse,
  type TeardownPlan,
  type TeardownRun,
  enableGatewayLogging,
  getDeploymentDetails,
  getTeardownPlan,
  getTeardownRun,
  listGatewayLogs,
  startTeardown,
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
  const [logCategory, setLogCategory] = useState<GatewayLogCategory>("access");
  const [logHours, setLogHours] = useState(24);
  const [logs, setLogs] = useState<GatewayLogsResponse | null>(null);
  const [logsBusy, setLogsBusy] = useState(false);
  const [logsError, setLogsError] = useState("");
  const [loggingBusy, setLoggingBusy] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const [teardown, setTeardown] = useState<TeardownRun | null>(null);
  const [teardownError, setTeardownError] = useState("");

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

  async function handleTeardown() {
    if (!teardownPlan || confirmation !== teardownPlan.confirmation) return;
    setTeardownError("");
    try {
      setTeardown(await startTeardown(runId, teardownPlan, confirmation));
    } catch {
      setTeardownError(copy.teardownActionFailed);
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

  return (
    <section className="deployment-manager" aria-label={copy.manage}>
      <header className="deployment-manager-heading">
        <div>
          <span>{copy.deploymentName}</span>
          <h2>{details?.deployment_name ?? runId.slice(0, 12)}</h2>
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
