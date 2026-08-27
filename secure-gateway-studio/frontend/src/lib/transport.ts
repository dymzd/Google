/**
 * HTTP transport for the local application.
 *
 * Extracted from `api.ts` so the Chrome extension can substitute its own
 * implementation at build time. The extension has no HTTP endpoint to call:
 * discovery, planning, and Apply run in its service worker, so its transport
 * routes the same paths over `chrome.runtime.sendMessage` instead.
 *
 * Everything above this file -- `api.ts` and the whole React layer -- is
 * identical in both builds. Keeping the seam here is what makes that true.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

/** Features implemented by this concrete transport. */
export const runtimeCapabilities = {
  bootstrapAccessPolicyId: false,
  cepDeployer: false,
  internalHttpsLbArchitecture: true,
  postDeploymentAccessUpdate: false,
  sessionSignIn: false,
  sessionSignOut: false,
  recommendedPocSourceImage: false,
  userDataDisclosure: false,
  vpcNetworkCatalog: false,
} as const;

export async function postJson<TResponse>(
  path: string,
  body: unknown,
): Promise<TResponse> {
  const serializedBody = JSON.stringify(body);
  const response = await fetchWithSessionRetry(path, (sessionNonce) => ({
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "SecureGatewayStudio",
      "X-SGS-Session": sessionNonce,
    },
    body: serializedBody,
    credentials: "omit",
  }));
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    let code = "request-failed";
    try {
      const payload = (await response.json()) as {
        detail?: string | { code?: string; message?: string };
      };
      if (typeof payload.detail === "string") message = payload.detail;
      if (payload.detail && typeof payload.detail === "object") {
        if (typeof payload.detail.code === "string") code = payload.detail.code;
        if (typeof payload.detail.message === "string") {
          message = payload.detail.message;
        }
      }
    } catch {
      // Keep the safe generic message for non-JSON responses.
    }
    throw new ApiError(response.status, code, message);
  }
  return (await response.json()) as TResponse;
}

let sessionNoncePromise: Promise<string> | null = null;

function getSessionNonce(): Promise<string> {
  if (sessionNoncePromise === null) {
    sessionNoncePromise = fetch("/api/v1/health", {
      method: "GET",
      headers: { "X-Requested-With": "SecureGatewayStudio" },
      credentials: "omit",
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new ApiError(
            response.status,
            "session-bootstrap-failed",
            `Session bootstrap failed (${response.status})`,
          );
        }
        const payload = (await response.json()) as { session_nonce?: string };
        if (!payload.session_nonce) {
          throw new ApiError(
            500,
            "session-bootstrap-failed",
            "The local API did not return a session nonce",
          );
        }
        return payload.session_nonce;
      })
      .catch((error) => {
        sessionNoncePromise = null;
        throw error;
      });
  }
  return sessionNoncePromise;
}

async function fetchWithSessionRetry(
  path: string,
  init: (sessionNonce: string) => RequestInit,
): Promise<Response> {
  const request = async () => fetch(path, init(await getSessionNonce()));
  let response = await request();
  if (response.status !== 403) return response;
  try {
    const payload = (await response.clone().json()) as {
      detail?: { code?: string };
    };
    if (payload.detail?.code !== "session-invalid") return response;
  } catch {
    return response;
  }

  // A backend restart rotates the in-memory loopback session nonce. The 403
  // above is emitted by the session dependency before the endpoint body runs,
  // so refreshing and retrying this exact request cannot duplicate a mutation.
  sessionNoncePromise = null;
  response = await request();
  return response;
}

export async function getJson<TResponse>(path: string): Promise<TResponse> {
  const response = await fetchWithSessionRetry(path, (sessionNonce) => ({
    method: "GET",
    headers: {
      "X-Requested-With": "SecureGatewayStudio",
      "X-SGS-Session": sessionNonce,
    },
    credentials: "omit",
  }));
  if (!response.ok) {
    throw new ApiError(response.status, "request-failed", `Request failed (${response.status})`);
  }
  return (await response.json()) as TResponse;
}


export async function getBlob(path: string, failureCode: string): Promise<Blob> {
  const response = await fetchWithSessionRetry(path, (sessionNonce) => ({
    method: "GET",
    headers: {
      "X-Requested-With": "SecureGatewayStudio",
      "X-SGS-Session": sessionNonce,
    },
    credentials: "omit",
  }));
  if (!response.ok) {
    throw new ApiError(response.status, failureCode, `Request failed (${response.status})`);
  }
  return response.blob();
}
