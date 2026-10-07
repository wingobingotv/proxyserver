import { createHmac } from "node:crypto";
import { ProxyError } from "../../core/errors.js";
import { headerValue } from "../../core/headers.js";
import { ipMatcher } from "../../core/ipList.js";
import { safeEqual } from "../../core/hmac.js";
import { hostOf, policyFor } from "../../core/ssrf.js";
import type { EnvReader } from "../../config/env.js";
import { fingerprint, mapJsonResponse, parseJsonObject, requireHttpUrl, requirePositiveInteger, requireString, strictJsonBody } from "../json.js";
import type { CallbackRequest, CallbackValidation, OperationDef, ProviderAdapter, ProviderContext, ProviderFactory } from "../types.js";

/**
 * ParsCoin — the Player API's Iranian card gateway adapter `gw_a`
 * (`backend/src/services/irCardGateways/gatewayA.js`). Only what that
 * adapter uses exists here; nothing is assumed beyond it:
 *
 * - create: POST /v1/transactions/createNewTransaction
 *     { total_amount, description, client_ip, userid, redirect_url }
 * - verify: POST /v1/transactions/verifyTransaction  { transaction_uuid }
 *   Both authenticate with the `X-API-TOKEN` header.
 * - webhook: JSON body with `event`, `uuid`, `event_timestamp`, …;
 *   `X-Sign-Hash` = hex(HMAC-SHA512(key = merchantId[0..16], uuid + event_timestamp)).
 *
 * ParsCoin documents no idempotency key, so create is never retried once a
 * byte may have reached it. Verify is a read the Player API already repeats
 * (site return poll, reconcile cron, admin button), so it is retried on
 * transport errors.
 */

export const PARSCOIN_ID = "parscoin";

const UUID = /^[0-9A-Za-z-]{8,64}$/;
const CREATE_FIELDS = ["total_amount", "description", "client_ip", "userid", "redirect_url"] as const;
const VERIFY_FIELDS = ["transaction_uuid"] as const;
const SIGN_HEADER = "x-sign-hash";

/** Same algorithm as `gatewayA.verifyWebhookSignature`. */
export function parscoinWebhookSignature(merchantId: string, uuid: string, eventTimestamp: string | number): string {
  return createHmac("sha512", merchantId.substring(0, 16)).update(`${uuid}${eventTimestamp}`).digest("hex");
}

function joinPath(base: URL, path: string): URL {
  const url = new URL(base.href);
  url.pathname = `${base.pathname.replace(/\/+$/, "")}${path}`;
  return url;
}

export function validateParscoinCallback(req: CallbackRequest, merchantId: string): CallbackValidation {
  const body = parseJsonObject(req.body);
  if (!body) return { ok: false, reason: "malformed_body", error: new ProxyError("callback_rejected", "body must be a JSON object") };
  const uuid = typeof body.uuid === "string" ? body.uuid : "";
  if (!UUID.test(uuid)) return { ok: false, reason: "invalid_uuid", error: new ProxyError("callback_rejected", "invalid uuid") };
  const event = typeof body.event === "string" ? body.event : "";
  if (!event || event.length > 64 || /[^\w.-]/.test(event)) {
    return { ok: false, reason: "invalid_event", error: new ProxyError("callback_rejected", "invalid event") };
  }
  const ts = body.event_timestamp;
  if (!((typeof ts === "string" && ts.length > 0 && ts.length <= 64) || (typeof ts === "number" && Number.isFinite(ts)))) {
    return { ok: false, reason: "invalid_timestamp", error: new ProxyError("callback_rejected", "invalid event_timestamp") };
  }
  const signature = headerValue(req.headers, SIGN_HEADER);
  if (!signature) return { ok: false, reason: "missing_signature", error: new ProxyError("unauthorized", "missing signature") };
  const expected = parscoinWebhookSignature(merchantId, uuid, ts);
  if (!safeEqual(expected, signature.trim().toLowerCase())) {
    return { ok: false, reason: "bad_signature", error: new ProxyError("unauthorized", "invalid signature") };
  }
  return { ok: true, dedupeKey: `${event}:${uuid}:${String(ts)}`, reference: uuid };
}

export const parscoinFactory: ProviderFactory = {
  id: PARSCOIN_ID,
  envPrefix: "PARSCOIN_",
  fromEnv(env: EnvReader, ctx: ProviderContext): ProviderAdapter | null {
    if (!env.bool("PARSCOIN_ENABLED", false)) return null;

    const baseUrl = env.url("PARSCOIN_BASE_URL", { required: true, allowHttp: ctx.allowHttp, originOnly: true });
    const allowedHosts = env.list("PARSCOIN_ALLOWED_HOSTS").map((h) => h.toLowerCase());
    if (allowedHosts.length === 0) env.problem("PARSCOIN_ALLOWED_HOSTS is required (the host of PARSCOIN_BASE_URL)");
    if (baseUrl && allowedHosts.length > 0 && !allowedHosts.includes(hostOf(baseUrl))) {
      env.problem("PARSCOIN_BASE_URL host is not listed in PARSCOIN_ALLOWED_HOSTS");
    }
    const apiToken = env.secret("PARSCOIN_API_TOKEN", { required: true, minLength: 16 });
    const merchantId = env.secret("PARSCOIN_MERCHANT_ID", { required: true, minLength: 16 });
    const slug = env.string("PARSCOIN_CALLBACK_SLUG", {
      required: true,
      pattern: /^[a-z0-9][a-z0-9-]{1,39}$/,
      hint: "lower-case letters, digits and dashes, e.g. gw-a",
    });
    const callbackPath = env.string("PARSCOIN_CALLBACK_PATH", {
      required: true,
      pattern: /^\/[A-Za-z0-9/_-]{1,200}$/,
      hint: "Player API webhook path, e.g. /webhooks/ir-card",
    });
    let callbackIps = ipMatcher([]);
    try {
      callbackIps = ipMatcher(env.list("PARSCOIN_CALLBACK_ALLOWED_IPS"));
    } catch (err) {
      env.problem(`PARSCOIN_CALLBACK_ALLOWED_IPS: ${(err as Error).message}`);
    }
    const ackWhenQueued = env.bool("PARSCOIN_CALLBACK_ACK_WHEN_QUEUED", true);
    const callbackRate = env.int("PARSCOIN_CALLBACK_RATE_LIMIT_PER_MINUTE", 600, { min: 10, max: 100_000 });
    const timeoutMs = env.int("PARSCOIN_TIMEOUT_MS", 15_000, { min: 1_000, max: 60_000 });
    const connectTimeoutMs = env.int("PARSCOIN_CONNECT_TIMEOUT_MS", 5_000, { min: 500, max: 30_000 });
    const deadlineMs = env.int("PARSCOIN_DEADLINE_MS", 18_000, { min: 1_000, max: 120_000 });
    if (deadlineMs < timeoutMs) env.problem("PARSCOIN_DEADLINE_MS must be at least PARSCOIN_TIMEOUT_MS");
    const verifyRetries = env.int("PARSCOIN_VERIFY_RETRIES", 2, { min: 0, max: 5 });
    const maxResponseBytes = env.int("PARSCOIN_MAX_RESPONSE_BYTES", 1_048_576, { min: 1_024, max: 10_485_760 });
    const allowPrivateNetwork = env.bool("PARSCOIN_ALLOW_PRIVATE_NETWORK", false);
    const failureThreshold = env.int("PARSCOIN_CIRCUIT_FAILURE_THRESHOLD", 5, { min: 1, max: 1_000 });
    const resetMs = env.int("PARSCOIN_CIRCUIT_RESET_MS", 30_000, { min: 1_000, max: 600_000 });

    if (!baseUrl || !apiToken || !merchantId || !slug || !callbackPath) return null;

    const jsonHeaders = () => ({ accept: "application/json", "content-type": "application/json", "x-api-token": apiToken });

    const create: OperationDef = {
      name: "payment.create",
      route: { method: "POST", path: "payment/create" },
      upstream: { method: "POST", path: "/v1/transactions/createNewTransaction" },
      contentTypes: ["application/json"],
      maxBodyBytes: 16_384,
      retry: {
        maxAttempts: 2,
        onConnectFailure: true,
        onAmbiguousFailure: false,
        retryStatuses: [],
        baseDelayMs: 250,
        deadlineMs,
      },
      buildRequest({ body }) {
        const input = strictJsonBody(body, CREATE_FIELDS);
        const out = {
          total_amount: requirePositiveInteger(input, "total_amount"),
          description: requireString(input, "description", { min: 1, max: 255 }),
          client_ip: requireString(input, "client_ip", { min: 0, max: 64 }),
          userid: requireString(input, "userid", { min: 1, max: 64 }),
          redirect_url: requireHttpUrl(input, "redirect_url", 2_048),
        };
        return { headers: jsonHeaders(), body: JSON.stringify(out) };
      },
      mapResponse: mapJsonResponse,
    };

    const verify: OperationDef = {
      name: "payment.verify",
      route: { method: "POST", path: "payment/verify" },
      upstream: { method: "POST", path: "/v1/transactions/verifyTransaction" },
      contentTypes: ["application/json"],
      maxBodyBytes: 4_096,
      retry: {
        maxAttempts: 1 + verifyRetries,
        onConnectFailure: true,
        onAmbiguousFailure: true,
        retryStatuses: [502, 503, 504],
        baseDelayMs: 300,
        deadlineMs,
      },
      buildRequest({ body }) {
        const input = strictJsonBody(body, VERIFY_FIELDS);
        const out = { transaction_uuid: requireString(input, "transaction_uuid", { min: 8, max: 64, pattern: UUID }) };
        return { headers: jsonHeaders(), body: JSON.stringify(out) };
      },
      mapResponse: mapJsonResponse,
    };

    return {
      id: PARSCOIN_ID,
      upstream: {
        baseUrl,
        policy: policyFor(baseUrl, { allowHttp: ctx.allowHttp, allowPrivateNetwork }),
        connectTimeoutMs,
        timeoutMs,
        maxResponseBytes,
      },
      operations: [create, verify],
      callback: {
        slug,
        methods: ["POST"],
        contentTypes: ["application/json"],
        maxBodyBytes: 65_536,
        allowedIps: callbackIps,
        target: joinPath(ctx.backendBaseUrl, callbackPath),
        forwardHeaders: ["content-type", SIGN_HEADER],
        ackWhenQueued,
        // The Player API answers 401 for a signature it cannot check (e.g. merchant ID not yet saved)
        // and 503 when the gateway is not configured: both are configuration states worth retrying.
        nonRetryableStatuses: [400, 404, 405, 409, 410, 413, 415, 422],
        rateLimitPerMinute: callbackRate,
        validate: (req) => validateParscoinCallback(req, merchantId),
      },
      circuit: { failureThreshold, resetMs },
      credentials: () => [
        { name: "PARSCOIN_API_TOKEN", configured: true, fingerprint: fingerprint(apiToken) },
        { name: "PARSCOIN_MERCHANT_ID", configured: true, fingerprint: fingerprint(merchantId) },
      ],
    };
  },
};
