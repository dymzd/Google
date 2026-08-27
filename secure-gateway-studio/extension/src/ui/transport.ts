/**
 * Extension transport. Build-time replacement for `frontend/src/lib/transport.ts`.
 *
 * Exposes the same four helpers with the same signatures, so `api.ts` and every
 * React component above it compile and behave identically in both builds. The
 * difference is entirely below this line: instead of an HTTP request to a local
 * FastAPI process, each call becomes a message to the service worker, which
 * routes it to the ported domain modules.
 *
 * The session nonce is gone. It existed to bind a browser tab to one launch of
 * the local server; inside an extension the page and the worker already share
 * an origin no other code can reach, so there is nothing to bind.
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
  bootstrapAccessPolicyId: true,
  cepDeployer: true,
  internalHttpsLbArchitecture: true,
  postDeploymentAccessUpdate: true,
  sessionSignIn: true,
  sessionSignOut: true,
  recommendedPocSourceImage: true,
  userDataDisclosure: true,
  vpcNetworkCatalog: true,
} as const;

interface ApiRequest {
  kind: "api";
  method: "GET" | "POST";
  path: string;
  body?: unknown;
}

type ApiReply =
  | { ok: true; value: unknown }
  | { ok: false; status: number; code: string; message: string };

async function call(request: ApiRequest): Promise<unknown> {
  let reply: ApiReply | undefined;
  try {
    reply = (await chrome.runtime.sendMessage(request)) as ApiReply;
  } catch (error) {
    // The worker failed to wake, or the extension was reloaded mid-call.
    throw new ApiError(0, "worker-unavailable", (error as Error).message);
  }
  if (reply === undefined) {
    throw new ApiError(0, "worker-silent", "The background worker returned no response.");
  }
  if (!reply.ok) {
    throw new ApiError(reply.status, reply.code, reply.message);
  }
  return reply.value;
}

export async function postJson<TResponse>(path: string, body: unknown): Promise<TResponse> {
  return (await call({ kind: "api", method: "POST", path, body })) as TResponse;
}

export async function getJson<TResponse>(path: string): Promise<TResponse> {
  return (await call({ kind: "api", method: "GET", path })) as TResponse;
}

export async function getBlob(path: string, failureCode: string): Promise<Blob> {
  try {
    const value = (await call({ kind: "api", method: "GET", path })) as {
      content: string;
      contentType: string;
    };
    // Artefacts cross the message boundary base64-encoded; structured clone
    // does not carry a Blob between contexts.
    const bytes = Uint8Array.from(atob(value.content), (character) => character.charCodeAt(0));
    return new Blob([bytes], { type: value.contentType });
  } catch (error) {
    if (error instanceof ApiError && error.code === "request-failed") {
      throw new ApiError(error.status, failureCode, error.message);
    }
    throw error;
  }
}
