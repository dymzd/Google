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
  ADMINISTRATOR_SCOPES,
  AuthenticationError,
  chromeIdentity,
  DEPLOYER_SCOPES,
  DeployerCredentials,
  googleOperatorIdentity,
  redactCredentials,
} from "../src/auth/tokens.ts";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
  const interactiveCalls: boolean[] = [];
  return {
    backend: {
      getAuthToken: async (interactive: boolean) => {
        calls += 1;
        interactiveCalls.push(interactive);
        return token;
      },
      removeCachedAuthToken: async () => {},
      clearAllCachedAuthTokens: async () => {},
    },
    get calls() {
      return calls;
    },
    get interactiveCalls() {
      return [...interactiveCalls];
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

  // -- Chrome cache/session wrapper semantics --------------------------------
  {
    const chromeGlobal = globalThis as unknown as { chrome?: unknown };
    const previousChrome = chromeGlobal.chrome;
    let authorized = false;
    let removeFailure = false;
    let clearFailure = false;
    let lastError: { message: string } | undefined;
    const interactiveCalls: boolean[] = [];
    chromeGlobal.chrome = {
      runtime: {
        get lastError() {
          return lastError;
        },
      },
      identity: {
        getAuthToken(
          options: { interactive?: boolean },
          callback: (token?: string) => void,
        ) {
          interactiveCalls.push(options.interactive === true);
          if (options.interactive === true) authorized = true;
          lastError = authorized ? undefined : { message: "OAuth grant unavailable" };
          callback(authorized ? "administrator-token" : undefined);
          lastError = undefined;
        },
        removeCachedAuthToken(
          _options: { token: string },
          callback: () => void,
        ) {
          lastError = removeFailure ? { message: "cache backend failed" } : undefined;
          callback();
          lastError = undefined;
        },
        clearAllCachedAuthTokens(callback: () => void) {
          lastError = clearFailure ? { message: "session clear failed" } : undefined;
          if (!clearFailure) authorized = false;
          callback();
          lastError = undefined;
        },
      },
    };
    try {
      await chromeIdentity.getAuthToken(true);
      removeFailure = true;
      await expectError(
        "removeCachedAuthToken rejects chrome.runtime.lastError",
        () => chromeIdentity.removeCachedAuthToken("administrator-token"),
        "token-cache-remove-failed",
      );
      removeFailure = false;

      clearFailure = true;
      await expectError(
        "clearAllCachedAuthTokens rejects instead of reporting a false sign-out",
        () => chromeIdentity.clearAllCachedAuthTokens(),
        "administrator-signout-failed",
      );
      clearFailure = false;
      await chromeIdentity.clearAllCachedAuthTokens();
      await expectError(
        "sign-out makes a noninteractive token request require consent",
        () => chromeIdentity.getAuthToken(false),
        "consent-required",
      );
      await chromeIdentity.getAuthToken(true);
      check(
        "only an explicit interactive sign-in restores the cleared OAuth session",
        interactiveCalls.join(",") === "true,false,true",
        interactiveCalls.join(","),
      );
    } finally {
      chromeGlobal.chrome = previousChrome;
    }
  }

  // -- the actor comes from the exact cached OAuth token --------------------
  {
    const interactiveCalls: boolean[] = [];
    const removed: string[] = [];
    let claims: Record<string, unknown> = {
      email: "Admin@Example.com",
      email_verified: true,
      sub: "subject-alice-123",
    };
    const identity = {
      getAuthToken: async (interactive: boolean) => {
        interactiveCalls.push(interactive);
        return "administrator-token";
      },
      removeCachedAuthToken: async (token: string) => { removed.push(token); },
      clearAllCachedAuthTokens: async () => {},
    };
    const fetchImpl = async (_url: RequestInfo | URL, init?: RequestInit) => {
      check(
        "UserInfo receives only the cached administrator bearer token",
        (init?.headers as Record<string, string>)?.Authorization ===
          "Bearer administrator-token",
      );
      return new Response(JSON.stringify(claims), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const alice = await googleOperatorIdentity({ identity, fetchImpl });
    check(
      "OIDC UserInfo supplies the normalized approval actor",
      alice.email === "admin@example.com" && alice.subject === "subject-alice-123",
      JSON.stringify(alice),
    );
    claims = { email: "bob@example.com", email_verified: true, sub: "subject-bob-456" };
    const bob = await googleOperatorIdentity({ identity, fetchImpl });
    check(
      "a changed token subject and email cannot inherit the prior actor binding",
      bob.email !== alice.email && bob.subject !== alice.subject,
      JSON.stringify({ alice, bob }),
    );
    check(
      "background actor attestation never opens an interactive prompt",
      interactiveCalls.every((interactive) => interactive === false),
      interactiveCalls.join(","),
    );

    claims = { email: "unverified@example.com", email_verified: false, sub: "subject-123" };
    await expectError(
      "unverified UserInfo claims fail closed without a profile fallback",
      () => googleOperatorIdentity({ identity, fetchImpl }),
      "operator-identity-unavailable",
    );
    await expectError(
      "a UserInfo transport failure fails closed",
      () => googleOperatorIdentity({
        identity,
        fetchImpl: async () => { throw new Error("network unavailable"); },
      }),
      "operator-identity-unavailable",
    );
    await expectError(
      "a UserInfo 401 removes the rejected token and requires explicit consent",
      () => googleOperatorIdentity({
        identity,
        fetchImpl: async () => new Response("", { status: 401 }),
      }),
      "consent-required",
    );
    check(
      "a rejected UserInfo token is removed from Chrome's cache",
      removed.join(",") === "administrator-token",
      removed.join(","),
    );
  }

  // -- the impersonation hop actually happens -------------------------------
  {
    let requestedUrl = "";
    let requestedBody: Record<string, unknown> = {};
    let authorizationHeader = "";
    const identity = identityStub();
    const credentials = new DeployerCredentials({
      serviceAccountEmail: "secure-gateway-deployer@prj.iam.gserviceaccount.com",
      identity: identity.backend,
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
      "steady-state impersonation renewal never opens an interactive consent prompt",
      identity.interactiveCalls.join(",") === "false",
      identity.interactiveCalls.join(","),
    );
    check(
      "requests only the Google Cloud deployer scope",
      JSON.stringify(requestedBody.scope) === JSON.stringify([...DEPLOYER_SCOPES]),
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
      unlabelled: "-----BEGIN PRIVATE KEY-----\nsecret",
      harmless: "value",
    }) as Record<string, unknown>;
    const serialised = JSON.stringify(redacted);
    check(
      "redacts token-shaped fields at any depth",
      !serialised.includes("ya29.secret") &&
        !serialised.includes("Bearer x") &&
        !serialised.includes("1//abc") &&
        !serialised.includes("PRIVATE KEY"),
      serialised,
    );
    check("leaves non-sensitive fields intact", serialised.includes("prj") && serialised.includes("value"));
  }

  // -- mutation entrypoints cannot fall back to the administrator ------------
  {
    const here = dirname(fileURLToPath(import.meta.url));
    const manifest = JSON.parse(
      readFileSync(resolve(here, "../manifest.json"), "utf8"),
    ) as {
      key?: string;
      permissions?: string[];
      host_permissions?: string[];
      oauth2?: { client_id?: string; scopes?: string[] };
    };
    const worker = readFileSync(
      resolve(here, "../src/background/service-worker.ts"),
      "utf8",
    );
    const authentication = readFileSync(
      resolve(here, "../src/auth/tokens.ts"),
      "utf8",
    );
    const router = readFileSync(resolve(here, "../src/background/router.ts"), "utf8");
    const publicHomepage = readFileSync(resolve(here, "../../../docs/index.md"), "utf8");
    const publicPrivacy = readFileSync(resolve(here, "../../../docs/privacy.md"), "utf8");
    const publicLayout = readFileSync(
      resolve(here, "../../../docs/_layouts/default.html"),
      "utf8",
    );
    const publicTailwind = readFileSync(
      resolve(here, "../../../docs/assets/css/tailwind.css"),
      "utf8",
    );
    const publicThirdPartyNotices = readFileSync(
      resolve(here, "../../../docs/THIRD_PARTY_NOTICES.txt"),
      "utf8",
    );
    const userDataDisclosure = readFileSync(
      resolve(here, "../../frontend/src/components/UserDataDisclosure.tsx"),
      "utf8",
    );
    const submissionGuide = readFileSync(
      resolve(here, "../docs/WEB_STORE_SUBMISSION.md"),
      "utf8",
    );
    const permissionGuide = readFileSync(
      resolve(here, "../docs/PERMISSIONS.md"),
      "utf8",
    );
    const rootReadme = readFileSync(resolve(here, "../../README.md"), "utf8");
    const infrastructureIamGuide = readFileSync(
      resolve(here, "../../infrastructure/iam/README.md"),
      "utf8",
    );
    const upstreamRole = readFileSync(
      resolve(here, "../../infrastructure/iam/secure-gateway-upstream-role.yaml"),
      "utf8",
    );
    const singleBoxJustification = submissionGuide.match(
      /#### Single box \(1000 characters, the cap is 1000\)\r?\n\r?\n([\s\S]*?)\r?\n\r?\n#### If the form asks per scope/,
    )?.[1]
      .split(/\r?\n/)
      .map((line) => line.replace(/^    /, ""))
      .join("\n")
      .trim() ?? "";
    const strictToken = worker.match(
      /async function deployerAccessToken\(\): Promise<string> \{([\s\S]*?)\n\}/,
    )?.[1] ?? "";
    const apply = worker.match(
      /case "apply": \{([\s\S]*?)\n    case "runState":/,
    )?.[1] ?? "";
    const signIn = worker.match(
      /async function establishAdministratorSession\(\)[\s\S]*?\r?\n\}\r?\n/,
    )?.[0] ?? "";
    const engine = worker.match(
      /async function engineFor\([\s\S]*?\n\}/,
    )?.[0] ?? "";
    const hosts = manifest.host_permissions ?? [];
    const permissions = manifest.permissions ?? [];
    const oauthScopes = manifest.oauth2?.scopes ?? [];
    const keyDigest = manifest.key === undefined
      ? Buffer.alloc(0)
      : createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest().subarray(0, 16);
    const extensionId = Array.from(keyDigest)
      .flatMap((byte) => [byte >>> 4, byte & 0x0f])
      .map((nibble) => String.fromCharCode("a".charCodeAt(0) + nibble))
      .join("");
    const expectedHosts = [
      "https://accesscontextmanager.googleapis.com/*",
      "https://admin.googleapis.com/*",
      "https://beyondcorp.googleapis.com/*",
      "https://chromemanagement.googleapis.com/*",
      "https://chromepolicy.googleapis.com/*",
      "https://cloudbilling.googleapis.com/*",
      "https://cloudidentity.googleapis.com/*",
      "https://cloudresourcemanager.googleapis.com/*",
      "https://compute.googleapis.com/*",
      "https://dns.googleapis.com/*",
      "https://iam.googleapis.com/*",
      "https://iamcredentials.googleapis.com/*",
      "https://licensing.googleapis.com/*",
      "https://logging.googleapis.com/*",
      "https://openidconnect.googleapis.com/*",
      "https://privateca.googleapis.com/*",
      "https://secretmanager.googleapis.com/*",
      "https://serviceusage.googleapis.com/*",
    ].sort();
    check(
      "worker preserves actionable authentication failures across the UI boundary",
      /error instanceof AuthenticationError[\s\S]{0,500}?code: error\.code[\s\S]{0,120}?message: error\.message/.test(worker) &&
        /error\.code === "impersonation-denied"[\s\S]{0,80}?403/.test(worker),
      "impersonation-denied must not collapse into request-failed",
    );
    check(
      "worker preserves actionable connection failures across the UI boundary",
      /error instanceof ConnectionError[\s\S]{0,300}?status: 409[\s\S]{0,200}?code: error\.code[\s\S]{0,120}?message: error\.message/.test(worker),
      "deployer-permissions-not-ready must not collapse into request-failed",
    );
    check(
      "manifest declares the exact reviewed Chrome permission set",
      JSON.stringify([...permissions].sort()) ===
        JSON.stringify(["alarms", "downloads", "identity", "storage", "unlimitedStorage"]),
      JSON.stringify(permissions),
    );
    check(
      "unlimitedStorage is limited to eviction-safe encrypted workflow state",
      /`unlimitedStorage`[\s\S]{0,300}?encrypted IndexedDB[\s\S]{0,300}?automatic quota eviction[\s\S]{0,350}?not used to retain unrelated data/.test(permissionGuide) &&
        /\*\*unlimitedStorage\*\*[\s\S]{0,500}?encrypted IndexedDB[\s\S]{0,250}?automatic quota eviction[\s\S]{0,350}?not used to retain[\s\S]{0,80}?unrelated data/.test(submissionGuide) &&
        /requests `unlimitedStorage` solely[\s\S]{0,250}?encrypted[\s\S]{0,200}?automatic quota eviction[\s\S]{0,350}?not used to retain unrelated data/.test(publicPrivacy) &&
        /unlimitedStorage permission protects only this safety ledger from automatic quota eviction[\s\S]{0,150}?does not collect browsing data/.test(userDataDisclosure) &&
        /unlimitedStorage 権限[\s\S]{0,120}?安全台帳[\s\S]{0,160}?自動削除[\s\S]{0,180}?閲覧データの収集/.test(userDataDisclosure),
    );
    check(
      "manifest declares only the reviewed Google API hosts",
      JSON.stringify([...hosts].sort()) === JSON.stringify(expectedHosts),
      JSON.stringify(hosts),
    );
    check(
      "manifest permits the exact OIDC UserInfo host and no obsolete www.googleapis.com wildcard",
      hosts.includes("https://openidconnect.googleapis.com/*") &&
        !hosts.includes("https://www.googleapis.com/*") &&
        /fetchImpl\("https:\/\/openidconnect\.googleapis\.com\/v1\/userinfo"/.test(authentication) &&
        /googleOperatorIdentity\(\)/.test(worker) &&
        !/getProfileUserInfo/.test(worker) &&
        !/fetch(?:Impl)?\("https:\/\/www\.googleapis\.com/.test(authentication),
      JSON.stringify(hosts),
    );
    check(
      "Web Store justification requests no duplicate identity.email permission",
      !submissionGuide.includes("**identity.email**"),
    );
    check(
      "downloads permission is limited to the automatic Apply-time public-root handoff",
      /Apply-time public root PEM/.test(permissionGuide) &&
        /Evidence JSON, CEP scripts, and later manual certificate exports use in-page Blob downloads and do not use this permission/.test(permissionGuide) &&
        /Apply-time public root PEM/.test(submissionGuide) &&
        /Evidence JSON, CEP scripts, and later manual root[\s\S]{0,20}?exports use in-page Blob object URLs/.test(submissionGuide) &&
        !/downloads[^\n]*evidence bundle/i.test(permissionGuide) &&
        !/Saves two files[\s\S]{0,300}?JSON evidence export/.test(submissionGuide),
    );
    check(
      "direct HTTPS permission guide discloses its read-only Compute probes",
      /Path B \(direct private HTTPS\) makes no Compute mutation/.test(permissionGuide) &&
        /reads the selected[\s\S]{0,80}?VPC/.test(permissionGuide) &&
      /reads regional forwarding rules[\s\S]{0,100}?Global Access/.test(permissionGuide) &&
        /Direct HTTPS uses read-only probes for the selected VPC[\s\S]{0,160}?regional forwarding rule and Global Access/.test(permissionGuide) &&
        /does not call the DNS, Secret Manager, or CA Service/.test(permissionGuide) &&
        !/Path B \(direct private HTTPS\) does not call the Compute/.test(permissionGuide),
    );
    const exactUpstreamPermissions = [
      "compute.networks.get",
      "compute.networks.use",
      "resourcemanager.projects.get",
      "resourcemanager.projects.getIamPolicy",
      "resourcemanager.projects.setIamPolicy",
    ].sort();
    const checkedInUpstreamPermissions = [...upstreamRole.matchAll(/^\s+- ([a-zA-Z0-9.]+)\s*$/gm)]
      .map(([, permission]) => permission)
      .sort();
    check(
      "checked-in upstream-project role has exactly the five reviewed permissions",
      JSON.stringify(checkedInUpstreamPermissions) === JSON.stringify(exactUpstreamPermissions),
      JSON.stringify(checkedInUpstreamPermissions),
    );
    check(
      "operator docs require the manual cross-project grant before validation",
      [rootReadme, infrastructureIamGuide, permissionGuide, submissionGuide].every(
        (document) =>
          exactUpstreamPermissions.every((permission) => document.includes(permission)) &&
          /before\s+(?:(?:connection|cross-project)\s+)?validation/i.test(document) &&
          /cross-project/i.test(document) &&
          /bootstrap/i.test(document) &&
          /deployment project/i.test(document),
      ) &&
        /optional explicitly selected upstream VPC[\s\S]{0,1200}?Bootstrap changes only[\s\S]{0,300}?manual/i.test(publicPrivacy),
    );
    check(
      "manifest requests both OpenID subject and verified-email scopes",
      JSON.stringify([...oauthScopes].sort()) ===
        JSON.stringify([...ADMINISTRATOR_SCOPES].sort()),
      JSON.stringify(oauthScopes),
    );
    check(
      "public homepage accounts for the OIDC host and openid scope",
      /`openidconnect\.googleapis\.com`/.test(publicHomepage) &&
        /\| `openid` \| Core \|/.test(publicHomepage),
    );
    check(
      "public privacy policy discloses the immutable account identifier and bootstrap boundary",
      /immutable OpenID Connect account identifier/.test(publicPrivacy) &&
        /After bootstrap,[\s\S]{0,180}?never fall back to administrator authority/.test(publicPrivacy),
    );
    check(
      "public policy and Web Store declaration disclose existing-secret private-key handling",
      /existing public-certificate secret[\s\S]{0,500}?numeric Secret Manager version[\s\S]{0,700}?private key is held in memory only[\s\S]{0,300}?never persisted[\s\S]{0,200}?saved as a file[\s\S]{0,150}?chrome\.downloads[\s\S]{0,150}?retransmitted/i.test(publicPrivacy) &&
        /existing public-certificate[\s\S]{0,500}?numeric SecretVersion[\s\S]{0,500}?private key stays in memory[\s\S]{0,300}?never persisted[\s\S]{0,200}?saved as a file[\s\S]{0,150}?chrome\.downloads[\s\S]{0,150}?retransmitted/i.test(submissionGuide),
    );
    check(
      "prominent, public, and Web Store disclosures explain Secure Gateway connection logging",
      /approve Security Gateway creation[\s\S]{0,350}?enables full Secure Gateway connection records in Cloud Logging[\s\S]{0,350}?contents, retention, and access follow your Google Cloud configuration[\s\S]{0,200}?developer receives none of them/i.test(userDataDisclosure) &&
        /approve creation of a[\s\S]{0,100}?Security Gateway[\s\S]{0,350}?enables full Secure Gateway connection[\s\S]{0,30}?records in Cloud Logging[\s\S]{0,350}?contents,[\s\S]{0,30}?retention, and access are governed by the customer's Google Cloud[\s\S]{0,30}?configuration[\s\S]{0,200}?developer receives none/i.test(publicPrivacy) &&
        /approves Security Gateway creation[\s\S]{0,350}?enable full Secure Gateway connection[\s\S]{0,30}?records in Cloud Logging[\s\S]{0,350}?contents,[\s\S]{0,30}?retention, and access follow the customer's Google Cloud[\s\S]{0,30}?configuration[\s\S]{0,200}?developer receives none/i.test(submissionGuide),
    );
    check(
      "privacy and permission texts disclose the non-sensitive cleartext locale exception",
      /UI language \(`en` or `ja`\)[\s\S]{0,80}?Unencrypted page `localStorage`/.test(publicPrivacy) &&
        /non-sensitive UI locale \(`en` or `ja`\) alone remains unencrypted in page `localStorage`/.test(permissionGuide) &&
        /only unencrypted durable UI value[\s\S]{0,100}?locale preference[\s\S]{0,100}?no tenant, authentication, configuration, or[\s\S]{0,30}?audit data/.test(submissionGuide),
    );
    check(
      "public OAuth-review pages load no remote script, stylesheet, font, or image",
      !/<script\b/i.test(publicLayout) &&
        !/<link\b[^>]*href=["']https?:\/\//i.test(publicLayout) &&
        !/<img\b[^>]*src=["']https?:\/\//i.test(publicLayout) &&
        /script-src 'none'/.test(publicLayout) &&
        /connect-src 'none'/.test(publicLayout) &&
        publicTailwind.length > 10_000,
    );
    check(
      "published Tailwind output preserves a discoverable full MIT notice",
      /tailwindcss v3\.4\.17 \| MIT License/.test(publicTailwind) &&
        /THIRD_PARTY_NOTICES\.txt/.test(publicLayout) &&
        /tailwindcss 3\.4\.17 \(MIT\)[\s\S]*?Copyright \(c\) Tailwind Labs, Inc\.[\s\S]*?Permission is hereby granted/.test(publicThirdPartyNotices),
    );
    check(
      "Web Store review text describes administrator bootstrap and deployer-only later mutations",
      /explicitly confirmed initial creation and pinning/.test(submissionGuide) &&
        /After that bootstrap, every Cloud mutation executes as the pinned account/.test(submissionGuide),
    );
    check(
      "Web Store requirements disclose optional Directory OU creation authority",
      /Directory read privileges for groups,[\s\S]{0,100}?users, and customer metadata/.test(submissionGuide) &&
        /automatic CEP sub-OU creation[\s\S]{0,100}?permission to create Organizational Units/.test(submissionGuide) &&
        !/Directory-read, and License Management privileges/.test(submissionGuide),
    );
    check(
      "Web Store Compute host justification includes direct-HTTPS read probes",
      /compute\.googleapis\.com[ \t]+read the selected VPC and IP-target forwarding-rule Global Access/.test(submissionGuide) &&
        /create offload network, subnet, firewall, load balancer, and instance group resources/.test(submissionGuide),
    );
    check(
      "combined OAuth scope justification fits the documented 1000-character console cap",
      singleBoxJustification.length > 0 && singleBoxJustification.length <= 1000,
      `characters=${singleBoxJustification.length}`,
    );
    check(
      "fixed manifest key preserves the uploaded Secure Gateway Studio item ID",
      extensionId === "dpoipoafmkanaideagfiflihnbgbeffk",
      extensionId || "manifest key missing",
    );
    check(
      "manifest remains bound to the reviewed Chrome-extension OAuth client",
      manifest.oauth2?.client_id ===
        "414812060045-iglmi996pf852aivcd417iqru5iug3ep.apps.googleusercontent.com",
      manifest.oauth2?.client_id ?? "OAuth client missing",
    );
    check(
      "Cloud mutation transport requires impersonation and has no administrator fallback",
      /makeTransport\(deployerAccessToken/.test(worker) &&
        /throw new AuthenticationError/.test(strictToken) &&
        !/chromeIdentity|getAuthToken/.test(strictToken),
    );
    check(
      "Apply verifies current operator and immutable deployer before atomic consumption",
      /operatorEmail\(\)/.test(apply) &&
        /requireDeployerIdentity/.test(apply) &&
        /consumeApprovalAndCreateRun\([\s\S]*?operator: currentOperator[\s\S]*?deployerIdentity/.test(apply),
    );
    check(
      "cold Apply and rollback resume revalidate the run-bound deployer",
      /requireDeployerIdentity/.test(engine) && /deployerIdentity/.test(engine),
    );
    check(
      "all routed Cloud mutation families require the project-bound deployer",
      (router.match(/context\.requireDeployer\(/g)?.length ?? 0) >= 6 &&
        /POST \/api\/v1\/runs\/\{\}\/teardowns/.test(router) &&
        /POST \/api\/v1\/runs\/\{\}\/update-access-level/.test(router) &&
        /POST \/api\/v1\/cep\/provision/.test(router),
    );
    check(
      "sign-out removes the immutable deployer credential binding",
      /persistentRemove\(\[[\s\S]{0,300}?"deployerServiceAccountUniqueId"/.test(worker),
    );
    check(
      "sign-out awaits Chrome's full OAuth session reset and health requires a live silent grant",
      /async function signOutSafely[\s\S]{0,1800}?await chromeIdentity\.clearAllCachedAuthTokens\(\)/.test(worker) &&
        /case "health":[\s\S]{0,300}?authenticated: await hasAdministratorSession\(\)/.test(worker) &&
        !/case "health":[\s\S]{0,300}?operatorEmail\(\)/.test(worker),
    );
    check(
      "only explicit sign-in may request interactive Chrome consent",
      (worker.match(/getAuthToken\(true\)/g)?.length ?? 0) === 1 &&
        signIn.includes("getAuthToken(true)") &&
        signIn.indexOf("getAuthToken(true)") < signIn.indexOf("operatorIdentity()") &&
        signIn.indexOf("operatorIdentity()") < signIn.indexOf("credentials.accessToken()") &&
        signIn.includes("deployerOperatorSubject") &&
        signIn.includes("operator-identity-changed") &&
        /interruptRunForAuthentication[\s\S]{0,900}?scheduler\.cancel\(runId\)/.test(worker),
      "background transport and alarm resume must use cached noninteractive credentials",
    );
  }

  if (failures.length > 0) {
    console.error(`FAIL ${failures.length} of ${failures.length + results.length} checks\n`);
    for (const failure of failures) console.error(`  ${failure}`);
    process.exit(1);
  }
  console.log(`OK ${results.length} authentication checks passed.`);
}

await main();
