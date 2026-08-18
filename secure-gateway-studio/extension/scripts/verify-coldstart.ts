/**
 * Cold start: the setup phase must work before a deployer exists.
 *
 * This check exists because its absence hid a second real failure, of the same
 * shape as the first. Endpoint coverage proved every route was reachable;
 * nothing proved the routes could actually run in the state a new operator is
 * in. The impersonation chain assumed the deployer service account already
 * existed, but bootstrap is what creates it — so bootstrap could never run,
 * and the two calls before it failed on a credential that could not yet be
 * minted.
 *
 * The pattern is worth naming: parity checks compare a working system against
 * a reference. They say nothing about reaching the working state.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-coldstart.ts
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const read = (relative: string): string =>
  readFileSync(resolve(here, relative), "utf8");

const worker = read("../src/background/service-worker.ts");
const manifest = JSON.parse(read("../manifest.json")) as { permissions: string[] };

const failures: string[] = [];
let passed = 0;

function check(name: string, condition: boolean, detail = ""): void {
  if (condition) passed += 1;
  else failures.push(`${name}${detail ? `\n      ${detail}` : ""}`);
}

// `chrome.identity.getProfileUserInfo` returns an empty email without this
// permission, and bootstrap needs the administrator's address to grant them
// Token Creator on the account it creates.
check(
  "manifest requests identity.email",
  manifest.permissions.includes("identity.email"),
  `permissions: ${manifest.permissions.join(", ")}`,
);

// The transport must fall back to the administrator's own token. Requiring an
// impersonated one makes the first Google call impossible.
check(
  "the transport can obtain a token before a deployer exists",
  /if \(credentials !== null\) return credentials\.accessToken\(\);/.test(worker) &&
    /getAuthToken/.test(worker),
  "accessToken() should fall back to the administrator token",
);

check(
  "no code path demands a deployer before bootstrap",
  !/requireCredentials\(\)/.test(worker),
  "requireCredentials() throws until a deployer is stored, which bootstrap creates",
);

// The audit actor has to resolve to something in both states.
check(
  "the audit actor resolves before bootstrap",
  /if \(typeof email === "string" && email !== ""\) return email;/.test(worker) &&
    /operatorEmail\(\)/.test(worker),
  "resolveDeployerEmail() should fall back to the signed-in administrator",
);

check(
  "sign-in does not require a deployer",
  /typeof deployer === "string" && deployer !== ""/.test(worker),
  "signIn should establish an administrator session when no deployer is stored",
);

// Once bootstrap has run, impersonation must actually take effect; otherwise
// every later mutation keeps the administrator's broader authority.
check(
  "bootstrap switches the session to the deployer",
  /rememberDeployer[\s\S]{0,400}?new DeployerCredentials\(/.test(worker),
  "rememberDeployer() should replace the credential with the new deployer",
);

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} cold-start checks\n`);
  for (const failure of failures) console.error(`  ${failure}`);
  console.error(
    "\n  A new operator starts with no deployer service account. Every step up to\n" +
      "  and including bootstrap has to work in that state.",
  );
  process.exit(1);
}
console.log(`OK ${passed} cold-start checks passed.`);
