import type { ProxyError } from "../core/errors.js";
import type { UpstreamResponse } from "../core/httpClient.js";
import type { IpMatcher } from "../core/ipList.js";
import type { DestinationPolicy } from "../core/ssrf.js";
import type { AppEnv, EnvReader } from "../config/env.js";

/**
 * Contract between the generic proxy engine and one provider. The engine
 * owns transport, auth, SSRF, retries, persistence and observability; an
 * adapter only declares where its API lives, which operations exist, how a
 * request and response are mapped, and how its callbacks are recognised.
 * Adding a provider = one new adapter + one line in `providers/index.ts`.
 */

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export type RetryPolicy = {
  /** Total attempts, first one included. */
  maxAttempts: number;
  /** Retry when nothing reached the provider (connect refused, DNS, connect timeout). Always safe. */
  onConnectFailure: boolean;
  /**
   * Retry after timeouts, mid-request network errors and `retryStatuses`.
   * Only for operations that are safe to repeat at the provider.
   */
  onAmbiguousFailure: boolean;
  retryStatuses: readonly number[];
  baseDelayMs: number;
  /** All attempts together must finish within this budget. */
  deadlineMs: number;
};

export type UpstreamTarget = {
  baseUrl: URL;
  policy: DestinationPolicy;
  connectTimeoutMs: number;
  timeoutMs: number;
  maxResponseBytes: number;
};

export type RelayInput = {
  body: Buffer;
  contentType: string | undefined;
  headers: Record<string, string | string[] | undefined>;
};

export type BuiltRequest = { headers: Record<string, string>; body: Buffer | string | undefined };

export type RelayResult = { status: number; contentType: string; body: Buffer };

export type OperationDef = {
  /** Operation name within the provider, e.g. `payment.create` (full name `parscoin.payment.create`). */
  name: string;
  /** Internal route below `/v1/providers/<provider>/`. Fixed; never derived from input. */
  route: { method: HttpMethod; path: string };
  /** Provider endpoint, appended to the configured base URL. Fixed; never derived from input. */
  upstream: { method: HttpMethod; path: string };
  /** Accepted request media types. */
  contentTypes: readonly string[];
  maxBodyBytes: number;
  retry: RetryPolicy;
  /** Validates the caller's body and returns the provider request (credentials added here). Throws `ProxyError`. */
  buildRequest(input: RelayInput): BuiltRequest;
  /** Validates and maps the provider response. Throws `ProxyError("upstream_malformed_response")`. */
  mapResponse(res: UpstreamResponse): RelayResult;
};

export type CallbackRequest = {
  method: string;
  headers: Record<string, string | string[] | undefined>;
  /** Raw query string without `?`, "" when none. */
  query: string;
  body: Buffer;
  sourceIp: string | undefined;
};

export type CallbackValidation =
  | {
      ok: true;
      /** Identity of this provider event; the same event delivered twice has the same key. */
      dedupeKey: string;
      /** Provider transaction reference, for lookup. Not secret. */
      reference: string | null;
    }
  | { ok: false; error: ProxyError; reason: string };

export type CallbackDef = {
  /** Public path segment: `/callback/<slug>`. */
  slug: string;
  methods: readonly HttpMethod[];
  contentTypes: readonly string[];
  maxBodyBytes: number;
  /** Source IPs allowed to call; empty = any (the signature still has to verify). */
  allowedIps: IpMatcher;
  /** Main backend URL the callback is relayed to (query string from the provider is appended). */
  target: URL;
  /** Provider headers passed to the backend; everything else is dropped. */
  forwardHeaders: readonly string[];
  /** When the backend cannot be reached: answer 202 (we own the retry) or 503 (provider retries too). */
  ackWhenQueued: boolean;
  /** Backend statuses that mean "this payload will never be accepted" — not retried. */
  nonRetryableStatuses: readonly number[];
  rateLimitPerMinute: number;
  /** Transport-level validation only. Never decides that a payment succeeded. */
  validate(req: CallbackRequest): CallbackValidation;
};

export type CredentialInfo = { name: string; configured: boolean; fingerprint: string | null };

export type ProviderAdapter = {
  id: string;
  upstream: UpstreamTarget;
  operations: readonly OperationDef[];
  callback: CallbackDef | null;
  circuit: { failureThreshold: number; resetMs: number };
  /** Presence and fingerprints of credentials — never their values. */
  credentials(): CredentialInfo[];
};

export type ProviderContext = {
  appEnv: AppEnv;
  /** `http:` destinations allowed (development/test only). */
  allowHttp: boolean;
  backendBaseUrl: URL;
};

export type ProviderFactory = {
  id: string;
  /** Env prefix, e.g. `PARSCOIN_`; `<PREFIX>ENABLED` switches the provider on. */
  envPrefix: string;
  fromEnv(env: EnvReader, ctx: ProviderContext): ProviderAdapter | null;
};
