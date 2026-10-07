/**
 * Errors the proxy itself produces. The `code` is stable and machine-readable;
 * callers (the Player API) branch on it, never on the message.
 */
export type ProxyErrorCode =
  | "unauthorized"
  | "forbidden_source"
  | "rate_limited"
  | "payload_too_large"
  | "unsupported_media_type"
  | "invalid_request"
  | "query_not_allowed"
  | "unknown_provider"
  | "unknown_operation"
  | "method_not_allowed"
  | "provider_disabled"
  | "circuit_open"
  | "upstream_timeout"
  | "upstream_unreachable"
  | "upstream_blocked_destination"
  | "upstream_redirect_blocked"
  | "upstream_response_too_large"
  | "upstream_malformed_response"
  | "callback_rejected"
  | "callback_conflict"
  | "not_found"
  | "internal_error";

const STATUS: Record<ProxyErrorCode, number> = {
  unauthorized: 401,
  forbidden_source: 403,
  rate_limited: 429,
  payload_too_large: 413,
  unsupported_media_type: 415,
  invalid_request: 400,
  query_not_allowed: 400,
  unknown_provider: 404,
  unknown_operation: 404,
  method_not_allowed: 405,
  provider_disabled: 503,
  circuit_open: 503,
  upstream_timeout: 504,
  upstream_unreachable: 502,
  upstream_blocked_destination: 502,
  upstream_redirect_blocked: 502,
  upstream_response_too_large: 502,
  upstream_malformed_response: 502,
  callback_rejected: 400,
  callback_conflict: 409,
  not_found: 404,
  internal_error: 500,
};

export class ProxyError extends Error {
  readonly code: ProxyErrorCode;
  readonly status: number;
  /** Short, non-sensitive detail safe to return to the caller. */
  readonly detail: string | undefined;
  readonly retryAfterSeconds: number | undefined;

  constructor(code: ProxyErrorCode, detail?: string, options: { status?: number; retryAfterSeconds?: number; cause?: unknown } = {}) {
    super(detail ? `${code}: ${detail}` : code, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "ProxyError";
    this.code = code;
    this.status = options.status ?? STATUS[code];
    this.detail = detail;
    this.retryAfterSeconds = options.retryAfterSeconds;
  }
}

export function isProxyError(value: unknown): value is ProxyError {
  return value instanceof ProxyError;
}

/** Body the proxy returns for its own errors. `message` mirrors the provider error shape the Player API already reads. */
export function errorBody(err: ProxyError, requestId: string) {
  return {
    error: err.code,
    message: err.detail ? `${err.code}: ${err.detail}` : err.code,
    requestId,
  };
}
