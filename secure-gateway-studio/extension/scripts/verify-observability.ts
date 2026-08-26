import { strict as assert } from "node:assert";
import { GatewayObservability } from "../src/providers/observability.ts";
import type { DeploymentSpec } from "../src/domain/spec.ts";
import type { Transport } from "../src/providers/executor.ts";

const requests: Array<{ method: string; url: string; body?: Record<string, unknown> }> = [];
const forbiddenText = "GET /payroll?token=secret";
const transport: Transport = {
  async requestJson(method, url, options) {
    requests.push({ method, url, body: options?.jsonBody });
    if (method === "GET" && url.includes("/securityGateways/")) {
      return { status: 200, payload: { logging: {} } };
    }
    return {
      status: 200,
      payload: {
        entries: [{
          insertId: "entry-1",
          timestamp: "2026-08-24T00:00:00Z",
          severity: "NOTICE",
          textPayload: forbiddenText,
          jsonPayload: {
            method: "GET",
            uri: "/payroll?token=secret",
            status: 200,
            request_id: "request-1",
          },
          protoPayload: {
            methodName: "google.cloud.beyondcorp.v1.AuthorizeUser",
            serviceName: "beyondcorp.googleapis.com",
            resourceName: "projects/example/locations/global/securityGateways/gateway",
            authenticationInfo: { principalEmail: "employee@example.com" },
            requestMetadata: { callerIp: "203.0.113.9" },
          },
        }],
      },
    };
  },
};

const spec = {
  project_id: "example-project",
  gateway_id: "default",
  backend_kind: "direct_https",
  zone: "asia-northeast1-a",
  name: "gateway",
} as DeploymentSpec;

const response = await new GatewayObservability(transport).listLogs(spec, {
  runId: "run-1",
  category: "connection",
});

assert.equal(requests.length, 2);
const gatewayRequest = requests.find((request) => request.url.includes("/securityGateways/"))!;
assert.equal(gatewayRequest.method, "GET");
assert.equal(
  gatewayRequest.url,
  "https://beyondcorp.googleapis.com/v1/projects/example-project/locations/global/" +
    "securityGateways/default?fields=logging",
);
const request = requests.find((candidate) => candidate.url.includes("entries:list"))!;
assert.equal(request.method, "POST");
const decodedUrl = decodeURIComponent(request.url);
assert.match(decodedUrl, /entries:list\?fields=entries\(/);
for (const forbiddenField of [
  "textPayload",
  "uri",
  "authenticationInfo",
  "principalEmail",
  "requestMetadata",
  "callerIp",
]) {
  assert.equal(decodedUrl.includes(forbiddenField), false, `partial response requested ${forbiddenField}`);
}

assert.equal(response.entries.length, 1);
const entry = response.entries[0]!;
assert.equal(entry.summary, "google.cloud.beyondcorp.v1.AuthorizeUser");
assert.equal(entry.principal, null);
assert.equal(entry.caller_ip, null);
assert.equal(entry.request_id, "request-1");
const serialized = JSON.stringify(response);
for (const forbiddenValue of [forbiddenText, "/payroll", "token=secret", "employee@example.com", "203.0.113.9"]) {
  assert.equal(serialized.includes(forbiddenValue), false, `output leaked ${forbiddenValue}`);
}
assert.deepEqual(Object.keys(entry.payload).sort(), ["method_name", "service_name", "status"]);
assert.equal(response.logging_enabled, true);

let loggingCalls = 0;
const malformedTransport: Transport = {
  async requestJson(method, url) {
    if (url.includes("/securityGateways/")) {
      return { status: 200, payload: { logging: { enabled: true } } };
    }
    loggingCalls += 1;
    return { status: 200, payload: { entries: [] } };
  },
};
await assert.rejects(
  () => new GatewayObservability(malformedTransport).listLogs(spec, {
    runId: "run-2",
    category: "connection",
  }),
  /security-gateway-logging-state-invalid/,
);
assert.equal(loggingCalls, 0);

const disabledResponse = await new GatewayObservability({
  async requestJson(method, url) {
    if (url.includes("/securityGateways/")) return { status: 200, payload: {} };
    return { status: 200, payload: { entries: [] } };
  },
}).listLogs(spec, { runId: "run-3", category: "connection" });
assert.equal(disabledResponse.logging_enabled, false);

const pagedBodies: Array<Record<string, unknown> | undefined> = [];
let pagedCall = 0;
const pagedResponse = await new GatewayObservability({
  async requestJson(_method, url, options) {
    assert.match(url, /entries:list/);
    pagedBodies.push(options?.jsonBody);
    pagedCall += 1;
    return pagedCall === 1
      ? { status: 200, payload: { entries: [], nextPageToken: "page-2" } }
      : {
          status: 200,
          payload: {
            entries: [{ insertId: "later-entry", severity: "INFO" }],
          },
        };
  },
}).listLogs(spec, { runId: "run-4", category: "admin" });
assert.equal(pagedResponse.entries[0]?.insert_id, "later-entry");
assert.equal(pagedBodies[0]?.pageToken, undefined);
assert.equal(pagedBodies[1]?.pageToken, "page-2");

for (const malformedToken of [null, 7]) {
  await assert.rejects(
    () => new GatewayObservability({
      async requestJson() {
        return { status: 200, payload: { entries: [], nextPageToken: malformedToken } };
      },
    }).listLogs(spec, { runId: "run-malformed", category: "admin" }),
    /cloud-logging-page-token-invalid/,
  );
}

let repeatedPageCalls = 0;
await assert.rejects(
  () => new GatewayObservability({
    async requestJson() {
      repeatedPageCalls += 1;
      return { status: 200, payload: { entries: [], nextPageToken: "repeat" } };
    },
  }).listLogs(spec, { runId: "run-repeat", category: "admin" }),
  /cloud-logging-page-token-invalid/,
);
assert.equal(repeatedPageCalls, 2);

let cappedPageCalls = 0;
await assert.rejects(
  () => new GatewayObservability({
    async requestJson() {
      cappedPageCalls += 1;
      return {
        status: 200,
        payload: { entries: [], nextPageToken: `page-${cappedPageCalls}` },
      };
    },
  }).listLogs(spec, { runId: "run-cap", category: "admin" }),
  /cloud-logging-pagination-incomplete/,
);
assert.equal(cappedPageCalls, 100);

await assert.rejects(
  () => new GatewayObservability({
    async requestJson() {
      return { status: 200, payload: { entries: [null] } };
    },
  }).listLogs(spec, { runId: "run-items", category: "admin" }),
  /cloud-logging-entries-invalid/,
);

console.log("Observability minimization and gateway logging-state checks passed");
