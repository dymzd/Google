import assert from "node:assert/strict";

import {
  InvalidGoogleJsonResponseError,
  parseGoogleJsonResponse,
} from "../src/background/google-response.ts";

let checks = 0;
function check(name: string, assertion: () => void): void {
  assertion();
  checks += 1;
  console.log(`  OK  ${name}`);
}

check("JSON object responses are preserved", () => {
  assert.deepEqual(parseGoogleJsonResponse('{"items":[]}', 200), { items: [] });
});

check("HTTP 204 is the only empty-body contract", () => {
  assert.deepEqual(parseGoogleJsonResponse("", 204), {});
  for (const status of [200, 201, 202, 404]) {
    assert.throws(
      () => parseGoogleJsonResponse("", status),
      (error: unknown) =>
        error instanceof InvalidGoogleJsonResponseError &&
        error.code === "invalid-google-json-response" &&
        error.status === status,
    );
  }
});

check("non-empty invalid JSON fails closed without retaining its raw body", () => {
  const raw = "<html>upstream proxy failure tenant-secret</html>";
  assert.throws(
    () => parseGoogleJsonResponse(raw, 200),
    (error: unknown) =>
      error instanceof InvalidGoogleJsonResponseError &&
      error.code === "invalid-google-json-response" &&
      !error.message.includes(raw) &&
      !JSON.stringify(error).includes("tenant-secret"),
  );
});

check("JSON arrays, primitives, and null cannot become provider payloads", () => {
  for (const raw of ["[]", "null", "true", '"text"', "42"]) {
    assert.throws(
      () => parseGoogleJsonResponse(raw, 200),
      (error: unknown) => error instanceof InvalidGoogleJsonResponseError,
    );
  }
});

check("malformed Google error bodies are sanitized before provider handling", () => {
  const raw = "not-json operator@example.com";
  assert.throws(
    () => parseGoogleJsonResponse(raw, 403),
    (error: unknown) =>
      error instanceof InvalidGoogleJsonResponseError &&
      error.status === 403 &&
      !error.message.includes("operator@example.com"),
  );
});

console.log(`\n${checks} Google JSON transport checks passed.`);
