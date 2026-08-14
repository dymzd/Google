/**
 * Transport bridge between the extension page and the service worker.
 *
 * This is the seam the migration was designed around. The local application's
 * React layer talked to `http://127.0.0.1:8787` through two helpers in
 * `frontend/src/lib/api.ts`; here the same calls become messages. The React
 * components above it do not change, because what they consume is still
 * "async function, typed result, typed error".
 *
 * Nothing privileged happens on this side: the page holds no token, issues no
 * Google request, and cannot reach storage. If this file were compromised it
 * could ask the worker to do things, but it could not do them itself.
 */

import type { Request, Response } from "../background/messages.ts";

export class AgentError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "AgentError";
    this.code = code;
  }
}

async function send<T>(request: Request): Promise<T> {
  let response: Response<T> | undefined;
  try {
    response = (await chrome.runtime.sendMessage(request)) as Response<T>;
  } catch (error) {
    // The worker was asleep and failed to wake, or the extension was reloaded
    // mid-call. Both are transient and worth naming distinctly.
    throw new AgentError("worker-unavailable", (error as Error).message);
  }
  if (response === undefined) {
    throw new AgentError("worker-silent", "The background worker returned no response.");
  }
  if (!response.ok) throw new AgentError(response.code, response.message);
  return response.value;
}

export const agent = {
  health: () => send<{ status: string; version: string; authenticated: boolean }>({ kind: "health" }),
  signIn: () => send<{ authenticated: boolean }>({ kind: "signIn" }),
  signOut: () => send<{ authenticated: boolean }>({ kind: "signOut" }),
  preflight: (spec: Record<string, unknown>) => send<unknown>({ kind: "preflight", spec }),
  plan: (spec: Record<string, unknown>) => send<unknown>({ kind: "plan", spec }),
  apply: (approvalId: string) => send<{ runId: string }>({ kind: "apply", approvalId }),
  runState: (runId: string) => send<unknown>({ kind: "runState", runId }),
  auditChain: () => send<unknown[]>({ kind: "auditChain" }),
};
