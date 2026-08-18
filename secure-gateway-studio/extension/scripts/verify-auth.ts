/**
 * Authentication behaviour checks.
 *
 * These run without a browser: `chrome.identity` and `fetch` are substituted,
 * so the impersonation contract can be exercised in CI. What they cannot prove
 * is that Chrome issues a token for the real OAuth client -- that needs a
 * loaded extension and a signed-in profile, and belongs to the live
 * verification pass.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-auth.ts
 */

import {
  AuthenticationError,
  DEFAULT_SCOPES,
  DeployerCredentials,
  redactCredentials,
} from "../src/auth/tokens.ts";

const results: string[] = [];
const failures: string[] = [];

function check(name: string, condition: boolean, detail = ""): void {
  if (condition) results.push(name);
  else failures.push(`${name}${detail ? `\n      ${detail}` : ""}`);
}

async function expectError(name: string, run: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await run();
    failures.push(`${name}: expected ${code} but nothing was thrown`);
  } catch (error) {
    const actual = error instanceof AuthenticationError ? error.code : "(not AuthenticationError)";
    check(name, actual === code, `expected ${code}, got ${actual}`);
  }
}

function identityStub(token = "administrator-token") {
  let calls = 0;
  return {
    backend: {
      getAuthToken: async () => {
        calls += 1;
        return token;
      },
      removeCachedAuthToken: async () => {},
    },
    get calls() {
      return calls;
    },
  };
}

function tokenResponse(accessToken: string, expiresInMs: number, now: number): Response {
  return new Response(
    JSON.stringify({
      accessToken,
      expireTime: new Date(now + expiresInMs).toISOString(),
    }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

async function main(): Promise<void> {
  const now = 1_800_000_000_000;

  // -- the impersonation hop actually happens -------------------------------
  {
    let requestedUrl = "";
    let requestedBody: Record<string, unknown> = {};
    let authorizationHeader = "";
    const credentials = new DeployerCredentials({
      serviceAccountEmail: "secure-gateway-deployer@prj.iam.gserviceaccount.com",
      identity: identityStub().backend,
      now: () => now,
      fetchImpl: async (url, init) => {
        requestedUrl = String(url);
        requestedBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
        authorizationHeader = (init?.headers as Record<string, string>).Authorization;
        return tokenResponse("deployer-token", 3_600_000, now);
      },
    });

    const token = await credentials.accessToken();
    check("mints a deployer token rather than using the administrator token", token === "deployer-token");
    check(
      "calls generateAccessToken on the deployer service account",
      requestedUrl.includes("iamcredentials.googleapis.com") &&
        requestedUrl.includes("secure-gateway-deployer%40prj.iam.gserviceaccount.com") &&
        requestedUrl.endsWith(":generateAccessToken"),
      requestedUrl,
    );
    check(
      "presents the administrator token to the exchange only",
      authorizationHeader === "Bearer administrator-token",
    );
    check(
      "requests exactly the product scopes",
      JSON.stringify(requestedBody.scope) === JSON.stringify([...DEFAULT_SCOPES]),
    );
  }

  // -- caching and concurrency ----------------------------------------------
  {
    let mints = 0;
    const credentials = new DeployerCredentials({
      serviceAccountEmail: "deployer@prj.iam.gserviceaccount.com",
      identity: identityStub().backend,
      now: () => now,
      fetchImpl: async () => {
        mints += 1;
        return tokenResponse("deployer-token", 3_600_000, now);
      },
    });

    await credentials.accessToken();
    await credentials.accessToken();
    check("reuses a live token instead of minting again", mints === 1, `mints=${mints}`);

    const parallel = new DeployerCredentials({
      serviceAccountEmail: "deployer@prj.iam.gserviceaccount.com",
      identity: identityStub().backend,
      now: () => now,
      fetchImpl: async () => {
        mints += 1;
        return tokenResponse("deployer-token", 3_600_000, now);
      },
    });
    const before = mints;
    await Promise.all([parallel.accessToken(), parallel.accessToken(), parallel.accessToken()]);
    check(
      "collapses concurrent callers onto one mint",
      mints - before === 1,
      `mints=${mints - before}`,
    );
  }

  // -- expiry margin ---------------------------------------------------------
  {
    let mints = 0;
    let clock = now;
    const credentials = new DeployerCredentials({
      serviceAccountEmail: "deployer@prj.iam.gserviceaccount.com",
      identity: identityStub().backend,
      now: () => clock,
      fetchImpl: async () => {
        mints += 1;
        return tokenResponse(`token-${mints}`, 180_000, clock);
      },
    });

    await credentials.accessToken();
    clock += 100_000; // 80s of life left, inside the 120s renewal margin
    const second = await credentials.accessToken();
    check(
      "renews before expiry rather than at it",
      mints === 2 && second === "token-2",
      `mints=${mints}`,
    );
  }

  // -- failure modes ---------------------------------------------------------
  await expectError(
    "reports impersonation-denied on 403 with remediation",
    async () =>
      new DeployerCredentials({
        serviceAccountEmail: "deployer@prj.iam.gserviceaccount.com",
        identity: identityStub().backend,
        now: () => now,
        fetchImpl: async () => new Response("", { status: 403 }),
      }).accessToken(),
    "impersonation-denied",
  );

  await expectError(
    "reports impersonation-failed on an unparseable expiry",
    async () =>
      new DeployerCredentials({
        serviceAccountEmail: "deployer@prj.iam.gserviceaccount.com",
        identity: identityStub().backend,
        now: () => now,
        fetchImpl: async () =>
          new Response(JSON.stringify({ accessToken: "t", expireTime: "not-a-date" }), {
            status: 200,
          }),
      }).accessToken(),
    "impersonation-failed",
  );

  // -- credentials never reach storage or evidence ---------------------------
  {
    const redacted = redactCredentials({
      accessToken: "ya29.secret",
      nested: { authorization: "Bearer x", project_id: "prj" },
      list: [{ refresh_token: "1//abc" }],
      harmless: "value",
    }) as Record<string, unknown>;
    const serialised = JSON.stringify(redacted);
    check(
      "redacts token-shaped fields at any depth",
      !serialised.includes("ya29.secret") &&
        !serialised.includes("Bearer x") &&
        !serialised.includes("1//abc"),
      serialised,
    );
    check("leaves non-sensitive fields intact", serialised.includes("prj") && serialised.includes("value"));
  }

  if (failures.length > 0) {
    console.error(`FAIL ${failures.length} of ${failures.length + results.length} checks\n`);
    for (const failure of failures) console.error(`  ${failure}`);
    process.exit(1);
  }
  console.log(`OK ${results.length} authentication checks passed.`);
}

await main();
