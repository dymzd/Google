/**
 * Authentication. Replaces `providers/google_rest.py`'s ADC lookup.
 *
 * The local application used keyless ADC with `--impersonate-service-account`.
 * The extension cannot read `~/.config/gcloud`, so consent moves to
 * `chrome.identity`, but the impersonation step is deliberately preserved:
 * mutations must run as the pinned product-scoped deployer service account, not as
 * the administrator who happened to sign in.
 *
 *   administrator token (chrome.identity)
 *     -> iamcredentials.generateAccessToken
 *       -> deployer service-account token (short-lived)
 *         -> every Google *Cloud* API call
 *
 * Dropping the second hop would hand the administrator's own authority to
 * every request, which is a real reduction in blast radius from the local
 * application. Losing that was the main cost the migration had to avoid.
 *
 * Workspace APIs are the exception, and not by choice: Directory, Chrome
 * Policy, and Cloud Identity authorize against a Workspace user and its admin
 * roles. `generateAccessToken` cannot carry a `subject`, so the token it mints
 * is not a Workspace identity and those APIs reject it outright. They run as
 * the administrator instead -- see `administratorTransport` in the service
 * worker. The alternative is not a narrower credential, it is a 403.
 *
 * Tokens live in memory only. `providers/google_rest.py` rejects long-lived
 * service-account key ADC; the equivalent rule here is that nothing
 * token-shaped is ever written to IndexedDB, logged, or placed in an audit
 * event or evidence export.
 */

/** Scopes the product requests, mirroring `google_rest.DEFAULT_SCOPES`. */
export const DEFAULT_SCOPES = [
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/admin.directory.group.readonly",
  // Write, not readonly: the CEP deployer creates the "CEP Users" and
  // "CEP Browsers" sub OUs. Read access is included in the write scope.
  "https://www.googleapis.com/auth/admin.directory.orgunit",
  // Resolves the tenant's primary domain for the data-boundary policies.
  "https://www.googleapis.com/auth/admin.directory.customer.readonly",
  "https://www.googleapis.com/auth/admin.directory.user.readonly",
  // DLP rules and detectors through the Cloud Identity policy API.
  "https://www.googleapis.com/auth/cloud-identity.policies",
  "https://www.googleapis.com/auth/cloud-platform",
  "https://www.googleapis.com/auth/chrome.management.policy",
  "https://www.googleapis.com/auth/chrome.management.profiles.readonly",
  "https://www.googleapis.com/auth/apps.licensing",
] as const;

/**
 * The impersonated deployer only calls Google Cloud APIs. Workspace APIs use
 * the administrator token directly, so carrying their scopes on the deployer
 * token would add authority that can never be used legitimately.
 */
export const DEPLOYER_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"] as const;

/** Chrome administrator token additionally carries OIDC identity claims. */
export const ADMINISTRATOR_SCOPES = ["openid", ...DEFAULT_SCOPES] as const;

/** Refresh a delegated token this many seconds before it actually expires. */
const RENEW_MARGIN_SECONDS = 120;

export class AuthenticationError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "AuthenticationError";
    this.code = code;
  }
}

/**
 * The problem the local application reported as `adc-unavailable`.
 *
 * Kept as a distinct code so the UI can reuse the existing re-consent flow
 * rather than showing a generic failure.
 */
export function consentRequired(detail: string): AuthenticationError {
  return new AuthenticationError(
    "consent-required",
    `Google authorization is unavailable or was revoked. ${detail}`,
  );
}

export interface DelegatedToken {
  token: string;
  /** Epoch milliseconds. */
  expiresAt: number;
}

export interface IdentityBackend {
  getAuthToken(interactive: boolean): Promise<string>;
  removeCachedAuthToken(token: string): Promise<void>;
  clearAllCachedAuthTokens(): Promise<void>;
}

/** `chrome.identity` wrapped so tests can substitute a fake. */
export const chromeIdentity: IdentityBackend = {
  getAuthToken(interactive: boolean): Promise<string> {
    return new Promise((resolve, reject) => {
      chrome.identity.getAuthToken({ interactive, scopes: [...ADMINISTRATOR_SCOPES] }, (token) => {
        const error = chrome.runtime.lastError;
        if (error || !token) {
          reject(consentRequired(error?.message ?? "No token was returned."));
          return;
        }
        // Older Chrome hands back a bare string, newer a `{ token }` object.
        resolve(typeof token === "string" ? token : (token as { token: string }).token);
      });
    });
  },
  removeCachedAuthToken(token: string): Promise<void> {
    return new Promise((resolve, reject) => {
      chrome.identity.removeCachedAuthToken({ token }, () => {
        const error = chrome.runtime.lastError;
        if (error !== undefined) {
          reject(new AuthenticationError(
            "token-cache-remove-failed",
            `Chrome could not invalidate the cached administrator token: ${error.message}`,
          ));
          return;
        }
        resolve();
      });
    });
  },
  clearAllCachedAuthTokens(): Promise<void> {
    return new Promise((resolve, reject) => {
      chrome.identity.clearAllCachedAuthTokens(() => {
        const error = chrome.runtime.lastError;
        if (error !== undefined) {
          reject(new AuthenticationError(
            "administrator-signout-failed",
            `Chrome could not clear the administrator OAuth session: ${error.message}`,
          ));
          return;
        }
        resolve();
      });
    });
  },
};

export interface GoogleOperatorIdentity {
  email: string;
  /** Immutable OpenID Connect subject for the token's Google account. */
  subject: string;
}

export interface GoogleOperatorIdentityOptions {
  identity?: IdentityBackend;
  fetchImpl?: typeof fetch;
}

/**
 * Resolve the actor attested by the current administrator OAuth token.
 *
 * This deliberately does not fall back to the Chrome profile account. A
 * profile identifier is stable, but asking UserInfo with the very token used
 * for administrator calls proves that the approval/mutation actor and the
 * immutable subject are the same Google account. Background wakes are always
 * non-interactive; only the explicit sign-in route is allowed to prompt.
 */
export async function googleOperatorIdentity(
  options: GoogleOperatorIdentityOptions = {},
): Promise<GoogleOperatorIdentity> {
  const identity = options.identity ?? chromeIdentity;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const token = await identity.getAuthToken(false);
  let response: Response;
  try {
    response = await fetchImpl("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch (error) {
    throw new AuthenticationError(
      "operator-identity-unavailable",
      `Google UserInfo could not attest the administrator token: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (response.status === 401) {
    // Do not let a stale/revoked token keep looking like a live session. The
    // next explicit sign-in is the only place Chrome may prompt again.
    await identity.removeCachedAuthToken(token);
    throw consentRequired("Google UserInfo rejected the cached administrator token.");
  }
  if (!response.ok) {
    throw new AuthenticationError(
      "operator-identity-unavailable",
      `Google UserInfo could not attest the administrator token (HTTP ${response.status}).`,
    );
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new AuthenticationError(
      "operator-identity-unavailable",
      "Google UserInfo returned malformed JSON.",
    );
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new AuthenticationError(
      "operator-identity-unavailable",
      "Google UserInfo returned a malformed identity.",
    );
  }
  const claims = payload as Record<string, unknown>;
  const email = typeof claims.email === "string" ? claims.email.trim().toLowerCase() : "";
  const subject = typeof claims.sub === "string" ? claims.sub : "";
  if (
    claims.email_verified !== true ||
    !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) ||
    !/^[A-Za-z0-9_-]{6,255}$/.test(subject)
  ) {
    throw new AuthenticationError(
      "operator-identity-unavailable",
      "Google UserInfo did not return a verified email and immutable subject.",
    );
  }
  return { email, subject };
}

export interface DeployerCredentialsOptions {
  serviceAccountEmail: string;
  identity?: IdentityBackend;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

/**
 * Short-lived deployer credentials, minted by impersonation and cached until
 * shortly before expiry.
 */
export class DeployerCredentials {
  private readonly serviceAccountEmail: string;
  private readonly identity: IdentityBackend;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private cached: DelegatedToken | null = null;
  private inFlight: Promise<DelegatedToken> | null = null;

  constructor(options: DeployerCredentialsOptions) {
    this.serviceAccountEmail = options.serviceAccountEmail;
    this.identity = options.identity ?? chromeIdentity;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.now = options.now ?? Date.now;
  }

  /** Bearer token for Google API calls, minting or reusing as needed. */
  async accessToken(): Promise<string> {
    const cached = this.cached;
    if (cached !== null && cached.expiresAt - RENEW_MARGIN_SECONDS * 1000 > this.now()) {
      return cached.token;
    }
    // Collapse concurrent callers onto one mint; the service worker may run
    // several operations at once and each extra mint is a wasted round trip.
    this.inFlight ??= this.mint().finally(() => {
      this.inFlight = null;
    });
    const token = await this.inFlight;
    return token.token;
  }

  /** Drop cached tokens. Call after a 401 so the next attempt re-consents. */
  async invalidate(): Promise<void> {
    this.cached = null;
    try {
      const administrator = await this.identity.getAuthToken(false);
      await this.identity.removeCachedAuthToken(administrator);
    } catch (error) {
      if (error instanceof AuthenticationError && error.code === "consent-required") {
        // No usable cached grant remains. The next explicit sign-in action is
        // responsible for consent; background renewal must never prompt.
        return;
      }
      throw error;
    }
  }

  private async mint(): Promise<DelegatedToken> {
    // Token renewal happens from alarms and cold workers too. Chrome permits
    // interactive consent only from an explicit explanatory UI action; the
    // sign-in handler performs that action and leaves a cached token here.
    const administrator = await this.identity.getAuthToken(false);
    const url =
      "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" +
      `${encodeURIComponent(this.serviceAccountEmail)}:generateAccessToken`;

    const response = await this.fetchImpl(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${administrator}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ scope: [...DEPLOYER_SCOPES], lifetime: "3600s" }),
    });

    if (response.status === 401 || response.status === 403) {
      throw new AuthenticationError(
        "impersonation-denied",
        `The signed-in administrator cannot impersonate ${this.serviceAccountEmail}. ` +
          "Grant them roles/iam.serviceAccountTokenCreator on that service account.",
      );
    }
    if (!response.ok) {
      throw new AuthenticationError(
        "impersonation-failed",
        `Token exchange failed with status ${response.status}.`,
      );
    }

    const payload = (await response.json()) as { accessToken?: string; expireTime?: string };
    if (!payload.accessToken || !payload.expireTime) {
      throw new AuthenticationError(
        "impersonation-failed",
        "Token exchange returned no credential.",
      );
    }

    const expiresAt = Date.parse(payload.expireTime);
    if (!Number.isFinite(expiresAt)) {
      throw new AuthenticationError(
        "impersonation-failed",
        `Token exchange returned an unparseable expiry: ${payload.expireTime}`,
      );
    }

    this.cached = { token: payload.accessToken, expiresAt };
    return this.cached;
  }
}

/**
 * Redact anything token-shaped before it reaches a log, an audit event, or an
 * evidence export.
 *
 * The local application enforced this by never putting credentials in SQLite.
 * Here the same guarantee has to survive objects being serialised for storage,
 * so the check is explicit and applied at the boundary.
 */
const SENSITIVE_KEY = /(token|secret|password|credential|authorization|assertion)/i;

export function redactCredentials(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactCredentials);
  if (value !== null && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      output[key] = SENSITIVE_KEY.test(key) ? "[redacted]" : redactCredentials(item);
    }
    return output;
  }
  if (
    typeof value === "string" &&
    (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value) ||
      /\bBearer\s+[A-Za-z0-9._~+/-]{12,}/i.test(value) ||
      /\bya29\.[A-Za-z0-9_-]+/.test(value))
  ) {
    return "[redacted]";
  }
  return value;
}
