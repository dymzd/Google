import { type FormEvent, useEffect, useState } from "react";
import type { Messages } from "../../i18n/messages";
import {
  type AcceptanceReadiness,
  type AcceptanceTestId,
  type AuditEvent,
  type AuditIntegrity,
  type DeploymentRun,
  getAcceptanceReadiness,
  getAuditIntegrity,
  listAuditEvents,
  listDeploymentRuns,
  recordOperatorAcceptance,
  verifySystemAcceptance,
} from "../../lib/api";
import { CheckIcon, DocumentIcon, ShieldIcon } from "../../components/Icons";
import { DeploymentManager } from "./DeploymentManager";

export type OperationsView = "deployments" | "evidence";

interface OperationsPageProps {
  messages: Messages;
  view: OperationsView;
}

export function OperationsPage({ messages, view }: OperationsPageProps) {
  const [runs, setRuns] = useState<DeploymentRun[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [integrity, setIntegrity] = useState<AuditIntegrity | null>(null);
  const [acceptance, setAcceptance] = useState<AcceptanceReadiness | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const [actionMessage, setActionMessage] = useState("");
  const [testId, setTestId] = useState<AcceptanceTestId>("T07");
  const [caseKey, setCaseKey] = useState("macos");
  const [evidenceStatus, setEvidenceStatus] = useState<
    "user_confirmed" | "failed" | "skipped"
  >("user_confirmed");
  const [summary, setSummary] = useState("");
  const [evidence, setEvidence] = useState("");
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const copy = messages.operations;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    Promise.all([listDeploymentRuns(), listAuditEvents(), getAuditIntegrity()])
      .then(async ([nextRuns, nextEvents, nextIntegrity]) => {
        if (cancelled) return;
        setRuns(nextRuns);
        setEvents(nextEvents);
        setIntegrity(nextIntegrity);
        if (view === "evidence") {
          const latestSuccessfulRun = nextRuns.find(
            (run) => run.status === "succeeded",
          );
          if (latestSuccessfulRun) {
            const nextAcceptance = await getAcceptanceReadiness(
              latestSuccessfulRun.run_id,
            );
            if (!cancelled) {
              setAcceptance(nextAcceptance);
              const firstCase =
                nextAcceptance.operator_confirmable_cases[0];
              setTestId(firstCase?.test_id ?? "T07");
              setCaseKey(firstCase?.case_key ?? "macos");
            }
          } else {
            setAcceptance(null);
          }
        }
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
  }, [copy.loadFailed, view]);

  const title =
    view === "deployments" ? copy.deploymentsTitle : copy.evidenceTitle;
  const intro =
    view === "deployments" ? copy.deploymentsIntro : copy.evidenceIntro;
  const resultByCase = new Map(
    acceptance?.results.map((result) => [
      `${result.test_id}:${result.case_key}`,
      result,
    ]) ?? [],
  );
  const showT07Diagnostics =
    acceptance?.missing_cases.some((item) => item.test_id === "T07") ?? false;

  async function refreshAuditEvidence() {
    const [nextEvents, nextIntegrity] = await Promise.all([
      listAuditEvents(),
      getAuditIntegrity(),
    ]);
    setEvents(nextEvents);
    setIntegrity(nextIntegrity);
  }

  async function handleSystemVerification() {
    if (!acceptance) return;
    setActionBusy(true);
    setActionMessage("");
    try {
      const nextAcceptance = await verifySystemAcceptance(acceptance.run_id);
      await refreshAuditEvidence();
      setAcceptance(nextAcceptance);
    } catch {
      setActionMessage(copy.acceptanceActionFailed);
    } finally {
      setActionBusy(false);
    }
  }

  async function handleRecordEvidence(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!acceptance) return;
    setActionBusy(true);
    setActionMessage("");
    try {
      await recordOperatorAcceptance(acceptance.run_id, {
        test_id: testId,
        case_key: caseKey,
        status: evidenceStatus,
        summary,
        evidence,
      });
      const [nextAcceptance] = await Promise.all([
        getAcceptanceReadiness(acceptance.run_id),
        refreshAuditEvidence(),
      ]);
      setAcceptance(nextAcceptance);
      setSummary("");
      setEvidence("");
      setActionMessage(copy.evidenceRecorded);
    } catch {
      setActionMessage(copy.acceptanceActionFailed);
    } finally {
      setActionBusy(false);
    }
  }

  return (
    <main className="operations-page">
      <header className="operations-heading">
        <div>
          <p className="eyebrow">{messages.productName}</p>
          <h1>{title}</h1>
          <p>{intro}</p>
        </div>
        {view === "evidence" && (
          <a
            className="primary-action evidence-download"
            download
            href="/api/v1/evidence/export"
          >
            <DocumentIcon size={19} />
            {copy.exportEvidence}
          </a>
        )}
      </header>

      {loading && <p className="empty-state">{copy.loading}</p>}
      {error && <p className="connection-error" role="alert">{error}</p>}

      {!loading && !error && view === "deployments" && (
        <section className="operations-panel">
          {runs.length === 0 ? (
            <p className="empty-state">{copy.noRuns}</p>
          ) : (
            <div className="run-table-wrap">
              <table className="run-table">
                <thead>
                  <tr>
                    <th>{copy.runId}</th>
                    <th>{copy.status}</th>
                    <th>{copy.started}</th>
                    <th>{copy.operationsCount}</th>
                    <th><span className="sr-only">{copy.manage}</span></th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((run) => (
                    <tr key={run.run_id}>
                      <td><code>{run.run_id.slice(0, 12)}</code></td>
                      <td>
                        <span className={`status-pill status-${run.status}`}>
                          {run.status}
                        </span>
                      </td>
                      <td>{new Date(run.started_at).toLocaleString()}</td>
                      <td>{run.operations.length}</td>
                      <td>
                        <button
                          className="table-action"
                          onClick={() => setSelectedRunId(run.run_id)}
                          type="button"
                        >
                          {copy.manage}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {!loading && !error && view === "deployments" && selectedRunId ? (
        <DeploymentManager
          copy={copy}
          onClose={() => setSelectedRunId(null)}
          runId={selectedRunId}
        />
      ) : null}

      {!loading && !error && view === "evidence" && (
        <>
          <section className="integrity-grid">
            <article className="integrity-card">
              <span className={integrity?.valid ? "integrity-pass" : "integrity-fail"}>
                {integrity?.valid ? <CheckIcon size={22} /> : <ShieldIcon size={22} />}
              </span>
              <div>
                <strong>
                  {integrity?.valid ? copy.integrityValid : copy.integrityInvalid}
                </strong>
                <small>{copy.eventCount(integrity?.event_count ?? 0)}</small>
              </div>
            </article>
            <article className="integrity-card chain-card">
              <DocumentIcon size={22} />
              <div>
                <strong>{copy.chainHead}</strong>
                <code>{integrity?.chain_head_hash ?? copy.notAvailable}</code>
              </div>
            </article>
          </section>
          <section className="operations-panel acceptance-panel">
            <div className="acceptance-heading">
              <div>
                <h2>{copy.acceptanceTitle}</h2>
                <p>{copy.acceptanceIntro}</p>
              </div>
              {acceptance && (
                <button
                  className="secondary-action"
                  disabled={actionBusy}
                  onClick={() => void handleSystemVerification()}
                  type="button"
                >
                  {actionBusy
                    ? copy.runningSystemChecks
                    : copy.runSystemChecks}
                </button>
              )}
            </div>
            {!acceptance ? (
              <p className="empty-state">{copy.noSuccessfulRun}</p>
            ) : (
              <>
                <div
                  className={`acceptance-readiness ${
                    acceptance.acceptance_complete ? "ready" : "pending"
                  }`}
                >
                  <ShieldIcon size={20} />
                  <span>
                    <strong>
                      {acceptance.acceptance_complete
                        ? copy.acceptanceComplete
                        : copy.acceptancePending}
                    </strong>
                    <small>
                      {copy.requiredProgress(
                        acceptance.satisfied_cases.length,
                        acceptance.required_cases.length,
                      )}
                    </small>
                  </span>
                </div>
                <div className="acceptance-grid">
                  {acceptance.required_cases.map((requiredCase) => {
                    const result = resultByCase.get(
                      `${requiredCase.test_id}:${requiredCase.case_key}`,
                    );
                    const status = result?.status ?? "missing";
                    return (
                      <article
                        className="acceptance-test"
                        key={`${requiredCase.test_id}:${requiredCase.case_key}`}
                      >
                        <div>
                          <code>{requiredCase.test_id}</code>
                          <strong>
                            {copy.acceptanceTest(requiredCase.test_id)}
                          </strong>
                          {requiredCase.case_key !== "default" && (
                            <em>
                              {copy.acceptanceScope(requiredCase.case_key)}
                            </em>
                          )}
                        </div>
                        <span className={`status-pill status-${status}`}>
                          {copy.acceptanceStatus(status)}
                        </span>
                        <p>{result?.summary ?? copy.missingEvidence}</p>
                        {result && (
                          <>
                            <small>
                              {copy.evidenceSource(result.source)} ·{" "}
                              {new Date(result.recorded_at).toLocaleString()}
                            </small>
                            <details>
                              <summary>{copy.viewEvidence}</summary>
                              <pre>{result.evidence}</pre>
                            </details>
                          </>
                        )}
                      </article>
                    );
                  })}
                </div>
                {showT07Diagnostics && (
                  <aside
                    aria-labelledby="t07-diagnostics-title"
                    className="t07-diagnostics"
                  >
                    <div>
                      <h3 id="t07-diagnostics-title">{copy.t07DiagnosticsTitle}</h3>
                      <p>{copy.t07DiagnosticsIntro}</p>
                    </div>
                    <div className="t07-diagnostic-grid">
                      {copy.t07Diagnostics.map((diagnostic) => (
                        <details key={diagnostic.symptom}>
                          <summary>{diagnostic.symptom}</summary>
                          <p>{diagnostic.meaning}</p>
                          <ol>
                            {diagnostic.actions.map((action) => (
                              <li key={action}>{action}</li>
                            ))}
                          </ol>
                        </details>
                      ))}
                    </div>
                  </aside>
                )}
                {acceptance.operator_confirmable_cases.length > 0 && (
                  <form
                    className="acceptance-form"
                    onSubmit={(event) => void handleRecordEvidence(event)}
                  >
                    <div>
                      <h3>{copy.operatorEvidenceTitle}</h3>
                      <p>{copy.operatorEvidenceIntro}</p>
                    </div>
                    <label>
                      <span>{copy.testCase}</span>
                      <select
                        onChange={(event) => {
                          const [nextTestId, nextCaseKey] =
                            event.target.value.split(":");
                          setTestId(nextTestId as AcceptanceTestId);
                          setCaseKey(nextCaseKey);
                        }}
                        value={`${testId}:${caseKey}`}
                      >
                        {acceptance.operator_confirmable_cases.map((item) => (
                          <option
                            key={`${item.test_id}:${item.case_key}`}
                            value={`${item.test_id}:${item.case_key}`}
                          >
                            {item.test_id} — {copy.acceptanceTest(item.test_id)} —{" "}
                            {copy.acceptanceScope(item.case_key)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <p className="acceptance-form-wide acceptance-case-instruction">
                      {copy.testInstruction(testId, caseKey)}
                    </p>
                    <label>
                      <span>{copy.evidenceOutcome}</span>
                      <select
                        onChange={(event) =>
                          setEvidenceStatus(
                            event.target.value as
                              | "user_confirmed"
                              | "failed"
                              | "skipped",
                          )
                        }
                        value={evidenceStatus}
                      >
                        <option value="user_confirmed">{copy.outcomePassed}</option>
                        <option value="failed">{copy.outcomeFailed}</option>
                        <option value="skipped">{copy.outcomeSkipped}</option>
                      </select>
                    </label>
                    <label className="acceptance-form-wide">
                      <span>{copy.evidenceSummary}</span>
                      <input
                        maxLength={500}
                        minLength={3}
                        onChange={(event) => setSummary(event.target.value)}
                        required
                        value={summary}
                      />
                    </label>
                    <label className="acceptance-form-wide">
                      <span>{copy.evidenceDetail}</span>
                      <textarea
                        maxLength={4000}
                        minLength={3}
                        onChange={(event) => setEvidence(event.target.value)}
                        required
                        rows={3}
                        value={evidence}
                      />
                    </label>
                    <button
                      className="primary-action"
                      disabled={actionBusy}
                      type="submit"
                    >
                      {actionBusy ? copy.recordingEvidence : copy.recordEvidence}
                    </button>
                  </form>
                )}
                {actionMessage && (
                  <p className="acceptance-action-message" role="status">
                    {actionMessage}
                  </p>
                )}
              </>
            )}
          </section>
          <section className="operations-panel">
            <h2>{copy.recentEvents}</h2>
            {events.length === 0 ? (
              <p className="empty-state">{copy.noEvents}</p>
            ) : (
              <ol className="audit-list">
                {events.map((event) => (
                  <li key={event.event_id}>
                    <span>
                      <strong>{event.event_type}</strong>
                      <small>{event.actor}</small>
                    </span>
                    <time dateTime={event.created_at}>
                      {new Date(event.created_at).toLocaleString()}
                    </time>
                  </li>
                ))}
              </ol>
            )}
          </section>
        </>
      )}
    </main>
  );
}
