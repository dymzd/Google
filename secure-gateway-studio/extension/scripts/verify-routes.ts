/**
 * Endpoint coverage: every path the UI calls must be served by the worker.
 *
 * This check exists because its absence hid a real failure. The domain parity
 * checks all passed while the wizard could not get past its first step: they
 * verified the modules that were ported, and nothing verified that the
 * application was reachable through them. Seven of the twenty-five endpoints
 * `api.ts` calls had routes; the rest returned `route-not-ported`, so the
 * operator saw generic failures on almost every action.
 *
 * The lesson is that "the pieces are correct" and "the product works" are
 * different claims, and only the first had a test.
 *
 * Extraction is textual on purpose. Importing `api.ts` would pull in the React
 * tree and a DOM; reading the call sites is enough to answer the only question
 * that matters here, and it cannot drift from the source it reads.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-routes.ts
 */

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const apiPath = resolve(here, "../../frontend/src/lib/api.ts");
const routerPath = resolve(here, "../src/background/router.ts");
const frontendSrc = resolve(here, "../../frontend/src");

/** Collapse `${expr}` and query strings so paths compare as templates. */
function templatise(path: string): string {
  return path
    .split("?")[0]
    .replace(/\$\{[^}]*\}/g, "{}")
    .replace(/\/$/, "");
}

/**
 * Scan UI source files to ensure no direct `/api/v1/...` href/src/action
 * references bypass the background transport.
 */
function rawApiReferences(dir: string): string[] {
  const hits: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      hits.push(...rawApiReferences(full));
      continue;
    }
    if (!/\.tsx?$/.test(entry.name) || full === apiPath) continue;
    const lines = readFileSync(full, "utf8").split("\n");
    for (const [index, line] of lines.entries()) {
      if (/(href|src|action)\s*=\s*["'`]\/api\/v1\//.test(line)) {
        hits.push(`${full}:${index + 1}: ${line.trim()}`);
      }
    }
  }
  return hits;
}

/**
 * Every `/api/v1/...` literal in `api.ts`, paired with the verb of the helper
 * that issues it. `postJson`/`putJson` imply POST/PUT; `getJson`, `getBlob`,
 * and bare `fetch` GETs imply GET.
 */
function callsFromUi(source: string): Set<string> {
  const calls = new Set<string>();
  const pattern = /(postJson|putJson|getJson|getBlob|agentFetch|fetch)\s*(?:<[^>]*>)?\s*\(\s*[`"']([^`"']*\/api\/v1\/[^`"']*)[`"']/g;
  for (const match of source.matchAll(pattern)) {
    const helper = match[1];
    const method = helper === "postJson" ? "POST" : helper === "putJson" ? "PUT" : "GET";
    calls.add(`${method} ${templatise(match[2])}`);
  }
  return calls;
}

/**
 * Every route the worker declares in `PORTED`.
 *
 * Reading the declaration rather than the control flow is deliberate. Parsing
 * `if` chains and regex literals was fragile and produced false positives, and
 * a checker that cries wolf gets ignored. `PORTED` is also what the router
 * itself dispatches against, so a route present in one and absent from the
 * other cannot happen.
 */
function routesFromWorker(source: string): Set<string> {
  const block = source.match(/const PORTED = new Set\(\[([\s\S]*?)\]\)/);
  if (block === null) {
    console.error("FAIL could not find the PORTED declaration in router.ts.");
    process.exit(1);
  }
  const served = new Set<string>();
  for (const match of block[1].matchAll(/["'`]([A-Z]+ [^"'`]+)["'`]/g)) {
    served.add(templatise(match[1]));
  }
  return served;
}

function isServed(call: string, served: Set<string>): boolean {
  return served.has(call);
}

const raw = rawApiReferences(frontendSrc);
if (raw.length > 0) {
  console.error(
    `FAIL ${raw.length} raw /api/v1 references bypass the extension transport:\n`,
  );
  for (const hit of raw) console.error(`    ${hit}`);
  process.exit(1);
}

const apiSource = readFileSync(apiPath, "utf8");
const routerSource = readFileSync(routerPath, "utf8");

if (!routerSource.includes("specification: specToJson(spec)")) {
  console.error(
    "FAIL the plan POST route must return the JSON deployment specification, not its Set-backed domain object.",
  );
  process.exit(1);
}

const calls = callsFromUi(apiSource);
const served = routesFromWorker(routerSource);

if (calls.size === 0) {
  console.error("FAIL extracted no calls from api.ts; the extraction pattern is stale.");
  process.exit(1);
}

const missing = [...calls].filter((call) => !isServed(call, served)).sort();

if (missing.length > 0) {
  console.error(
    `FAIL ${missing.length} of ${calls.size} endpoints the UI calls have no route.\n`,
  );
  console.error("  The wizard will fail on every action that reaches one of these:\n");
  for (const call of missing) console.error(`    ${call}`);
  console.error(
    "\n  Add the route in src/background/router.ts, or remove the call from the UI.",
  );
  process.exit(1);
}

console.log(`OK all ${calls.size} endpoints the UI calls are served by the worker.`);
