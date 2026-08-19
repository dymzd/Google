/**
 * Service worker: the extension's only privileged context.
 *
 * Everything that touches Google or storage happens here. The page renders and
 * sends messages; it holds no token and issues no API call. That split is what
 * lets Apply keep running after the page is closed, and lets an alarm resume it
 * after the worker itself is torn down.
 *
 * A service worker starts cold on every wake. Nothing may be assumed to survive
 * in module scope: `onStartup` reconciles interrupted runs, and the alarm
 * handler reloads the run from storage rather than trusting a variable.
 */

import { chromeIdentity, DeployerCredentials } from "../auth/tokens.ts";
import { buildPlan, type DeploymentPlan } from "../domain/planner.ts";
import { parseDeploymentSpec, SpecValidationError } from "../domain/spec.ts";
import { GoogleDiscoveryProvider } from "../providers/discovery.ts";
import { GoogleResourceExecutor, type Transport } from "../providers/executor.ts";
import { openDatabase, StateRepository, STORE } from "../storage/repository.ts";
import { RunEngine, planRun, isActive, type RunRecord, type RunStore } from "../runtime/run-engine.ts";
import { err, ok, type Request, type Response } from "./messages.ts";
import { route, RouteError } from "./router.ts";

const VERSION = chrome.runtime.getManifest().version;
const ALARM_PREFIX = "sgs-run:";

/** Set once the operator has chosen a deployer service account to impersonate. */
async function operatorEmail(): Promise<string> {
  const profileEmail = await new Promise<string>((resolve) => {
    // The typings model this as an ambient enum, which has no runtime value to
    // reference; the wire format the API expects is the plain string.
    chrome.identity.getProfileUserInfo({ accountStatus: "ANY" as chrome.identity.AccountStatus }, (info) =>
      resolve(info?.email ?? ""),
    );
  });
  if (profileEmail && profileEmail.includes("@")) {
    console.log("[SGS Auth] Operator email from Chrome profile:", profileEmail);
    return profileEmail;
  }

  // Fallback: check if already consented silently (interactive: false)
  try {
    const token = await chromeIdentity.getAuthToken(false);
    const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(token)}`);
    if (res.ok) {
      const payload = (await res.json()) as { email?: string };
      if (payload.email) {
        console.log("[SGS Auth] Resolved operator email from OAuth tokeninfo:", payload.email);
        return payload.email;
      }
    }
  } catch (err) {
    console.log("[SGS Auth] Operator email not yet consented (silent check):", err);
  }
  return "";
}


let credentials: DeployerCredentials | null = null;

/**
 * The token to call Google with.
 *
 * Impersonation is the steady state, but it cannot be the only state: the
 * deployer service account does not exist until bootstrap creates it, and
 * bootstrap is itself a Google call. Before that point the administrator's own
 * token is the only credential there is, and the operations that run then --
 * project lookup, Chrome Policy access, and bootstrap itself -- are exactly the
 * ones that legitimately belong to the administrator.
 *
 * Once a deployer exists every mutation runs as that account, which is the
 * least-privilege property the local application had and the port had to keep.
 */
async function accessToken(): Promise<string> {
  if (credentials !== null) return credentials.accessToken();
  return chromeIdentity.getAuthToken(true);
}

/**
 * Transport factory. The token source is a parameter because not every Google
 * API the product calls will accept the same credential.
 *
 * The token is fetched per request rather than held, because the worker may
 * have restarted since the last call and a stale closure would carry a token
 * that no longer exists.
 */
function makeTransport(token: () => Promise<string>, invalidate: () => Promise<void>): Transport {
  return {
    async requestJson(method, url, options = {}) {
      const send = async (bearer: string): Promise<globalThis.Response> => {
        const target = new URL(url);
        for (const [key, value] of Object.entries(options.params ?? {})) {
          target.searchParams.set(key, String(value));
        }
        console.log(`[SGS Google API Request] ${method} ${target.toString()}`);
        return fetch(target, {
          method,
          headers: {
            Authorization: `Bearer ${bearer}`,
            ...(options.jsonBody ? { "Content-Type": "application/json" } : {}),
          },
          body: options.jsonBody ? JSON.stringify(options.jsonBody) : undefined,
        });
      };

      let response = await send(await token());
      if (response.status === 401) {
        console.warn(`[SGS Google API 401] Retrying once after token refresh for ${url}`);
        await invalidate();
        response = await send(await token());
      }

      const text = await response.text();
      let payload: Record<string, unknown> = {};
      if (text !== "") {
        try {
          payload = JSON.parse(text) as Record<string, unknown>;
        } catch {
          payload = { error: { message: text } };
        }
      }
      console.log(`[SGS Google API Response] ${method} ${url} -> ${response.status}`, payload);
      return { status: response.status, payload };
    },
  };
}

async function dropCachedAdministratorToken(): Promise<void> {
  try {
    const cachedToken = await chromeIdentity.getAuthToken(false);
    await chromeIdentity.removeCachedAuthToken(cachedToken);
  } catch {
    // No cached token to remove; the next mint will re-consent.
  }
}

/** Google Cloud calls: the deployer service account once one exists. */
const transport: Transport = makeTransport(accessToken, async () => {
  if (credentials !== null) {
    await credentials.invalidate();
    return;
  }
  await dropCachedAdministratorToken();
});

/**
 * Workspace calls: always the signed-in administrator.
 *
 * Directory, Chrome Policy, and Cloud Identity authorize against a Workspace
 * user and its admin roles. The deployer token has neither: it is minted by
 * `generateAccessToken`, which cannot carry a `subject`, so it is not a
 * Workspace identity at all and these APIs reject it. Routing them through the
 * administrator is not a loosening of the least-privilege model -- the
 * alternative is not a narrower credential, it is a 403.
 */
const administratorTransport: Transport = makeTransport(
  () => chromeIdentity.getAuthToken(true),
  dropCachedAdministratorToken,
);

/** Run records live in the same database as everything else. */
class IndexedDbRunStore implements RunStore {
  async load(runId: string): Promise<RunRecord | null> {
    const db = await openDatabase();
    const transactionScope = db.transaction([STORE.runs], "readonly");
    const store = transactionScope.objectStore(STORE.runs);
    return new Promise((resolve, reject) => {
      const request = store.get(runId);
      request.onsuccess = () => {
        const res = request.result as any;
        if (!res) return resolve(null);
        if (res.status && !res.state) res.state = res.status;
        if (!res.steps) res.steps = [];
        resolve(res as RunRecord);
      };
      request.onerror = () => reject(request.error);
    });
  }

  async save(record: RunRecord): Promise<void> {
    const db = await openDatabase();
    const transactionScope = db.transaction([STORE.runs], "readwrite");
    const store = transactionScope.objectStore(STORE.runs);
    const existing = await new Promise<any>((resolve) => {
      const getReq = store.get(record.runId);
      getReq.onsuccess = () => resolve(getReq.result);
      getReq.onerror = () => resolve(null);
    });
    const merged = {
      ...(existing || {}),
      ...record,
      status: record.state,
      state: record.state,
      startedAt: existing?.startedAt || new Date().toISOString(),
      finishedAt:
        record.state === "succeeded" || record.state === "failed"
          ? existing?.finishedAt || new Date().toISOString()
          : null,
    };
    await new Promise<void>((resolve, reject) => {
      const request = store.put(merged);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }
}

const runStore = new IndexedDbRunStore();

const scheduler = {
  async schedule(runId: string): Promise<void> {
    // The minimum period is coarser than the old in-process poll interval.
    // Google's long-running operations are not sensitive to that; what matters
    // is that the wake-up survives the worker being torn down.
    await chrome.alarms.create(`${ALARM_PREFIX}${runId}`, { periodInMinutes: 1 });
  },
  async cancel(runId: string): Promise<void> {
    await chrome.alarms.clear(`${ALARM_PREFIX}${runId}`);
  },
};

function engine(): RunEngine {
  return new RunEngine(runStore, new GoogleResourceExecutor(transport), scheduler);
}

async function handle(request: Request): Promise<Response<unknown>> {
  switch (request.kind) {
    case "health":
      return ok({ status: "ok", version: VERSION, authenticated: credentials !== null });

    case "signIn": {
      // Establishes the administrator session. Impersonation starts later, once
      // bootstrap has created the deployer; until then this token is what the
      // setup calls use.
      const stored = await chrome.storage.local.get("deployerServiceAccount");
      const deployer = stored.deployerServiceAccount;
      if (typeof deployer === "string" && deployer !== "") {
        credentials = new DeployerCredentials({ serviceAccountEmail: deployer });
        await credentials.accessToken();
      } else {
        await chromeIdentity.getAuthToken(true);
      }
      return ok({ authenticated: true, operator: await operatorEmail() });
    }

    case "signOut": {
      await credentials?.invalidate();
      credentials = null;
      return ok({ authenticated: false });
    }

    case "preflight": {
      const spec = parseDeploymentSpec(request.spec);
      const provider = new GoogleDiscoveryProvider(transport, {
        cloudIdentity: await resolveDeployerEmail(),
      });
      return ok(await provider.preflight(spec));
    }

    case "plan": {
      const spec = parseDeploymentSpec(request.spec);
      const provider = new GoogleDiscoveryProvider(transport, {
        cloudIdentity: await resolveDeployerEmail(),
      });
      const preflight = await provider.preflight(spec);
      const plan: DeploymentPlan = buildPlan(spec, preflight.snapshot);
      return ok({ plan, snapshot: preflight.snapshot });
    }

    case "apply": {
      const db = await openDatabase();
      const repository = new StateRepository(db);
      // Approval consumption and Apply-slot acquisition are one transaction;
      // a second caller cannot observe the approval as unconsumed.
      const { approval, run } = await repository.consumeApprovalAndCreateRun(
        request.approvalId,
      );
      const plan = JSON.parse(approval.planJson) as DeploymentPlan;
      const initialRun = planRun({
        runId: run.runId,
        approvalId: approval.approvalId,
        configurationHash: approval.configurationHash,
        changes: plan.changes,
      });
      await runStore.save(initialRun);
      await scheduler.schedule(run.runId);

      // Execute non-blocking continuous tick loop immediately so apply finishes in seconds
      void (async () => {
        try {
          const spec = await specForRun(initialRun);
          let current: RunRecord | null = await runStore.load(run.runId);
          while (current !== null && isActive(current.state)) {
            current = await engine().tick(run.runId, spec);
          }
        } catch (error) {
          console.error("[SGS Engine] Apply execution error:", error);
        }
      })();

      return ok({ runId: run.runId });
    }

    case "runState": {
      const record = await runStore.load(request.runId);
      return record === null
        ? err("run-not-found", `Unknown run ${request.runId}`)
        : ok({ run: record });
    }

    case "auditChain": {
      const db = await openDatabase();
      return ok(await new StateRepository(db).auditEvents());
    }

    default:
      return err("unsupported-request", `Unsupported request ${JSON.stringify(request)}`);
  }
}

/**
 * The identity recorded as the audit actor.
 *
 * Before bootstrap that is the signed-in administrator, because no deployer
 * exists yet and the setup calls really are theirs. Afterwards it is the
 * deployer, matching the local application, where the actor was always taken
 * from the credential rather than supplied by the browser.
 */
async function resolveDeployerEmail(): Promise<string> {
  const stored = await chrome.storage.local.get("deployerServiceAccount");
  const email = stored.deployerServiceAccount;
  if (typeof email === "string" && email !== "") return email;
  const operator = await operatorEmail();
  if (operator === "") {
    throw new Error("Sign in to Chrome with the administrator account first.");
  }
  return operator;
}

async function accessPolicyId(): Promise<string | undefined> {
  const stored = await chrome.storage.local.get("accessPolicyId");
  const value = stored.accessPolicyId;
  return typeof value === "string" && value !== "" ? value : undefined;
}

const routeContext = {
  transport,
  administratorTransport,
  cloudIdentity: resolveDeployerEmail,
  operatorEmail,
  accessPolicyId,
  rememberDeployer: async (email: string) => {
    await chrome.storage.local.set({ deployerServiceAccount: email });
    // Impersonation targets this account from here on; a stale credential
    // object would keep minting tokens for the previous one.
    credentials = new DeployerCredentials({ serviceAccountEmail: email });
  },
  startApply: async (approvalId: string) => {
    const reply = (await handle({ kind: "apply", approvalId })) as {
      ok: true;
      value: { runId: string };
    };
    const db = await openDatabase();
    const run = await new StateRepository(db).run(reply.value.runId);
    return {
      run_id: reply.value.runId,
      approval_id: approvalId,
      configuration_hash: run?.configurationHash ?? "",
      status: run?.status ?? "running",
      started_at: run?.startedAt ?? new Date().toISOString(),
      completed_at: run?.finishedAt ?? null,
      operations: [],
    };
  },
  runState: async (runId: string) => {
    const record = await runStore.load(runId);
    if (record === null) {
      const db = await openDatabase();
      const run = await new StateRepository(db).run(runId);
      if (run === undefined) throw new RouteError(404, "run-not-found", `Unknown run ${runId}`);
      return {
        run_id: run.runId,
        approval_id: run.approvalId,
        configuration_hash: run.configurationHash,
        status: run.status,
        started_at: run.startedAt,
        completed_at: run.finishedAt,
        operations: [],
      };
    }
    return {
      run_id: record.runId,
      approval_id: record.approvalId,
      configuration_hash: record.configurationHash,
      status: record.state,
      started_at: new Date().toISOString(),
      completed_at:
        record.state === "succeeded" || record.state === "failed"
          ? new Date().toISOString()
          : null,
      operations: (record.steps ?? []).map((step) => ({
        operation_id: step.requestId,
        resource_key: `${step.change.provider}:${step.change.resource_type}:${step.change.resource_name}`,
        action: step.change.action,
        status: step.status === "done" ? "succeeded" : step.status,
        error_code: step.error,
      })),
    };
  },
};

interface ApiMessage {
  kind: "api";
  method: "GET" | "POST";
  path: string;
  body?: unknown;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const incoming = message as Request | ApiMessage;
  console.log("[SGS Service Worker] Received message:", incoming);

  // Two shapes share the channel: the small typed control messages the shell
  // page uses, and the path-based API the ported React layer speaks.
  const work =
    (incoming as ApiMessage).kind === "api"
      ? route(
          routeContext,
          (incoming as ApiMessage).method,
          (incoming as ApiMessage).path,
          (incoming as ApiMessage).body,
        ).then((value) => {
          console.log("[SGS Service Worker] Route succeeded:", (incoming as ApiMessage).path, value);
          return { ok: true as const, value };
        })
      : handle(incoming as Request);

  work.then(sendResponse).catch((error: unknown) => {
    console.error("[SGS Service Worker] Route error:", incoming, error);
    if (error instanceof RouteError) {
      sendResponse({ ok: false, status: error.status, code: error.code, message: error.message });
      return;
    }
    const code = error instanceof SpecValidationError ? "spec-invalid" : "request-failed";
    sendResponse({ ok: false, status: 500, code, message: (error as Error).message });
  });
  // Keep the message channel open for the async reply.
  return true;
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (!alarm.name.startsWith(ALARM_PREFIX)) return;
  const runId = alarm.name.slice(ALARM_PREFIX.length);
  void (async () => {
    const record = await runStore.load(runId);
    if (record === null || !isActive(record.state)) {
      await scheduler.cancel(runId);
      return;
    }
    // The spec is reconstructed from the approval rather than held in memory;
    // this handler may be the first thing a cold worker runs.
    const db = await openDatabase();
    const repository = new StateRepository(db);
    void repository;
    await engine().tick(runId, await specForRun(record));
  })();
});

async function specForRun(record: RunRecord) {
  const stored = await chrome.storage.local.get(`spec:${record.approvalId}`);
  return parseDeploymentSpec(stored[`spec:${record.approvalId}`] as Record<string, unknown>);
}

chrome.runtime.onStartup.addListener(() => {
  // A run left `running` by a terminated worker is reconciled here, matching
  // the desktop application's startup interrupted-run detection.
  void (async () => {
    const db = await openDatabase();
    await new StateRepository(db).reconcileInterruptedRuns();
  })();
});

// The action opens the wizard in a full tab rather than a popup: the plan and
// evidence views need the room, and a popup closes on focus loss, which would
// interrupt an operator mid-approval.
chrome.action.onClicked.addListener(() => {
  void chrome.tabs.create({ url: chrome.runtime.getURL("src/ui/index.html") });
});
