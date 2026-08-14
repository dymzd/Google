/**
 * Extension page entry.
 *
 * A deliberately small shell that proves the whole chain is wired: page ->
 * message -> service worker -> ported domain modules -> storage. The existing
 * React wizard is mounted here once its `api.ts` transport is repointed at
 * `bridge.ts`; that is the remainder of E3-5 and is tracked in the plan rather
 * than stubbed behind a fake.
 *
 * What this page must never do is call Google directly. Everything goes
 * through the worker, so the page holds no credential.
 */

import { agent, AgentError } from "./bridge.ts";

const root = document.getElementById("root");

function line(label: string, value: string, tone: "ok" | "warn" | "bad" = "ok"): HTMLElement {
  const row = document.createElement("div");
  row.className = `row ${tone}`;
  const key = document.createElement("span");
  key.className = "key";
  key.textContent = label;
  const val = document.createElement("span");
  val.className = "val";
  val.textContent = value;
  row.append(key, val);
  return row;
}

async function render(): Promise<void> {
  if (root === null) return;
  root.replaceChildren();

  const heading = document.createElement("h1");
  heading.textContent = "Secure Gateway Studio";
  root.append(heading);

  try {
    const health = await agent.health();
    root.append(line("Background worker", "reachable"));
    root.append(line("Version", health.version));
    root.append(
      health.authenticated
        ? line("Google authorization", "granted")
        : line("Google authorization", "not granted", "warn"),
    );

    const events = await agent.auditChain();
    root.append(line("Audit events recorded", String(events.length)));
  } catch (error) {
    const failure = error as AgentError;
    root.append(line("Background worker", failure.code ?? "unreachable", "bad"));
    root.append(line("Detail", failure.message, "bad"));
  }

  const note = document.createElement("p");
  note.className = "note";
  note.textContent =
    "The deployment wizard mounts here once the React transport is repointed at the " +
    "message bridge. Discovery, planning, and Apply already run in the background worker.";
  root.append(note);
}

void render();
