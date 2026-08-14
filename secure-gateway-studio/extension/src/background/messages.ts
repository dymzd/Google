/**
 * Message contract between the extension page and the service worker.
 *
 * The UI does not talk to Google. Discovery, planning, and Apply all run in the
 * service worker, because Apply must survive the page being closed and must be
 * resumable by an alarm. The page sends a request and polls for state, exactly
 * as it previously polled a local HTTP API -- which is why the React layer
 * needs only its transport replaced, not its logic.
 *
 * Every message is a discriminated union member so an unhandled kind is a type
 * error rather than a silent no-op.
 */

import type { DeploymentPlan, DiscoverySnapshot } from "../domain/planner.ts";
import type { PreflightDiagnostic } from "../providers/discovery.ts";
import type { RunRecord } from "../runtime/run-engine.ts";

export interface HealthResponse {
  status: "ok";
  version: string;
  /** Reported so the UI can distinguish "not signed in" from "not installed". */
  authenticated: boolean;
}

export type Request =
  | { kind: "health" }
  | { kind: "signIn" }
  | { kind: "signOut" }
  | { kind: "preflight"; spec: Record<string, unknown> }
  | { kind: "plan"; spec: Record<string, unknown> }
  | { kind: "approve"; planHash: string; confirmation: string }
  | { kind: "apply"; approvalId: string }
  | { kind: "runState"; runId: string }
  | { kind: "auditChain" }
  | { kind: "exportEvidence" };

export type Response<T> = { ok: true; value: T } | { ok: false; code: string; message: string };

export interface PreflightPayload {
  snapshot: DiscoverySnapshot;
  diagnostics: PreflightDiagnostic[];
}

export interface PlanPayload {
  plan: DeploymentPlan;
  snapshot: DiscoverySnapshot;
}

export interface RunPayload {
  run: RunRecord;
}

export function ok<T>(value: T): Response<T> {
  return { ok: true, value };
}

export function err(code: string, message: string): Response<never> {
  return { ok: false, code, message };
}
