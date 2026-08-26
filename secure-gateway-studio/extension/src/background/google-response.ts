/** A Google REST response violated the transport's JSON object contract. */
export class InvalidGoogleJsonResponseError extends Error {
  readonly code = "invalid-google-json-response";
  readonly status: number;

  constructor(status: number) {
    super(`Google returned an invalid JSON object response (HTTP ${status}).`);
    this.name = "InvalidGoogleJsonResponseError";
    this.status = status;
  }
}

/**
 * Parse a Google REST body without allowing malformed success responses to
 * masquerade as empty list/read results. Google protobuf empty messages are
 * encoded as `{}`; a genuinely empty body is accepted only for HTTP 204.
 */
export function parseGoogleJsonResponse(
  text: string,
  status: number,
): Record<string, unknown> {
  if (text === "") {
    if (status === 204) return {};
    throw new InvalidGoogleJsonResponseError(status);
  }
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new InvalidGoogleJsonResponseError(status);
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new InvalidGoogleJsonResponseError(status);
  }
  return payload as Record<string, unknown>;
}
