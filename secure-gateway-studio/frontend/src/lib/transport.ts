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

export async function postJson<TResponse>(
  path: string,
  body: unknown,
): Promise<TResponse> {
  const sessionNonce = await getSessionNonce();
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "SecureGatewayStudio",
      "X-SGS-Session": sessionNonce,
    },
    body: JSON.stringify(body),
    credentials: "omit",
  });
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

export async function getJson<TResponse>(path: string): Promise<TResponse> {
  const sessionNonce = await getSessionNonce();
  const response = await fetch(path, {
    method: "GET",
    headers: {
      "X-Requested-With": "SecureGatewayStudio",
      "X-SGS-Session": sessionNonce,
    },
    credentials: "omit",
  });
  if (!response.ok) {
    throw new ApiError(response.status, "request-failed", `Request failed (${response.status})`);
  }
  return (await response.json()) as TResponse;
}


export async function getBlob(path: string, failureCode: string): Promise<Blob> {
  const sessionNonce = await getSessionNonce();
  const response = await fetch(path, {
    method: "GET",
    headers: {
      "X-Requested-With": "SecureGatewayStudio",
      "X-SGS-Session": sessionNonce,
    },
    credentials: "omit",
  });
  if (!response.ok) {
    throw new ApiError(response.status, failureCode, `Request failed (${response.status})`);
  }
  return response.blob();
}
