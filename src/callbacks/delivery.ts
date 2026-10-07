import type { Logger } from "pino";
import type { Config } from "../config/config.js";
import { backoffMs, retryAfterMs } from "../core/backoff.js";
import type { Encryptor } from "../core/crypto.js";
import { headerValue } from "../core/headers.js";
import { signedHeaders } from "../core/hmac.js";
import { HttpClient, UpstreamError, type UpstreamResponse } from "../core/httpClient.js";
import type { Metrics } from "../core/metrics.js";
import { REQUEST_ID_HEADER } from "../core/requestId.js";
import { safeErrorText } from "../core/redact.js";
import type { ProviderRegistry } from "../providers/registry.js";
import type { CallbackRecord, Store } from "../store/store.js";

/**
 * Delivers one stored callback to the main backend. At-least-once: a
 * delivery cut off half-way is repeated after its lock expires, so the
 * backend must stay idempotent per provider event — which the Player API
 * is (it credits a deposit through one atomic claim, and re-verifies with
 * the provider before crediting anything).
 */

export type StoredPayload = {
  /** base64 */
  body: string;
  query: string;
  headers: Record<string, string>;
};

export type DeliveryOutcome =
  | { kind: "delivered" | "rejected"; httpStatus: number; body: Buffer; contentType: string }
  | { kind: "retry" | "exhausted"; httpStatus: number | null; error: string };

export const MAX_BACKEND_RESPONSE_BYTES = 262_144;
const LOCK_MARGIN_MS = 30_000;

export const payloadAad = (id: string) => `callback:${id}:payload`;
export const responseAad = (id: string) => `callback:${id}:response`;

export class CallbackDelivery {
  constructor(
    private readonly deps: {
      store: Store;
      encryptor: Encryptor;
      registry: ProviderRegistry;
      backend: HttpClient;
      config: Config;
      metrics: Metrics;
      logger: Logger;
      now?: () => number;
    },
  ) {}

  private now(): number {
    return (this.deps.now ?? Date.now)();
  }

  /** Attempts one delivery. Null when another attempt holds the lock, or the record cannot be delivered now. */
  async attempt(id: string): Promise<DeliveryOutcome | null> {
    const { store, config } = this.deps;
    const current = store.getCallback(id);
    if (!current) return null;
    const provider = this.deps.registry.get(current.provider);
    const cb = provider?.callback;
    const log = this.deps.logger.child({ requestId: current.requestId, callbackId: id, provider: current.provider, direction: "callback" });
    if (!provider || !cb) {
      log.warn("provider of stored callback is not enabled; delivery postponed");
      return null;
    }

    const started = this.now();
    if (!store.claim(id, started, started + config.callbacks.forwardTimeoutMs + LOCK_MARGIN_MS)) return null;
    const rec = store.getCallback(id)!;

    let payload: StoredPayload;
    try {
      if (!rec.payloadEnc) throw new Error("payload was purged");
      payload = JSON.parse(this.deps.encryptor.decrypt(rec.payloadEnc, payloadAad(id)).toString("utf8")) as StoredPayload;
    } catch (err) {
      const error = `payload unreadable: ${safeErrorText(err, 120)}`;
      store.markFailed(id, { kind: "rejected", error, httpStatus: null, responseEnc: null, contentType: null, now: this.now() });
      this.deps.metrics.callbackDeliveries.inc({ provider: rec.provider, outcome: "unreadable" });
      log.error({ attempt: rec.attempts }, "stored callback payload cannot be read");
      return { kind: "exhausted", httpStatus: null, error };
    }

    const body = Buffer.from(payload.body, "base64");
    const url = new URL(rec.destination);
    url.search = payload.query ? `?${payload.query}` : "";
    const contentType = payload.headers["content-type"];
    const headers: Record<string, string> = {
      ...payload.headers,
      "user-agent": "wingobingo-proxy",
      [REQUEST_ID_HEADER]: rec.requestId,
      "x-wingo-callback-id": rec.id,
      "x-wingo-callback-attempt": String(rec.attempts),
      ...(rec.sourceIp ? { "x-wingo-provider-ip": rec.sourceIp } : {}),
      ...signedHeaders(config.backend.signingKey, {
        method: rec.method,
        target: url.pathname + url.search,
        contentType,
        body,
      }),
    };

    let res: UpstreamResponse | null = null;
    let failure: UpstreamError | null = null;
    try {
      res = await this.deps.backend.send({
        url,
        method: rec.method,
        headers,
        ...(body.length > 0 ? { body } : {}),
        timeoutMs: config.callbacks.forwardTimeoutMs,
        maxResponseBytes: MAX_BACKEND_RESPONSE_BYTES,
      });
    } catch (err) {
      failure = err instanceof UpstreamError ? err : new UpstreamError("network", safeErrorText(err, 120), { beforeSend: false });
    }
    const now = this.now();
    this.deps.metrics.callbackDeliveryDuration.observe({ provider: rec.provider }, (now - started) / 1000);

    if (res && res.status >= 200 && res.status < 300) {
      const ct = headerValue(res.headers, "content-type") ?? "application/json";
      store.markDelivered(id, { httpStatus: res.status, responseEnc: this.encryptResponse(id, res.body), contentType: ct, now });
      this.deps.metrics.callbackDeliveries.inc({ provider: rec.provider, outcome: "delivered" });
      log.info({ attempt: rec.attempts, backendStatus: res.status, durationMs: now - started }, "callback delivered");
      return { kind: "delivered", httpStatus: res.status, body: res.body, contentType: ct };
    }

    if (res && cb.nonRetryableStatuses.includes(res.status)) {
      const ct = headerValue(res.headers, "content-type") ?? "application/json";
      const error = `backend rejected the callback (HTTP ${res.status})`;
      store.markFailed(id, {
        kind: "rejected",
        error,
        httpStatus: res.status,
        responseEnc: this.encryptResponse(id, res.body),
        contentType: ct,
        now,
      });
      this.deps.metrics.callbackDeliveries.inc({ provider: rec.provider, outcome: "rejected" });
      log.warn({ attempt: rec.attempts, backendStatus: res.status }, "callback rejected by backend (final)");
      return { kind: "rejected", httpStatus: res.status, body: res.body, contentType: ct };
    }

    const httpStatus = res?.status ?? null;
    const error = res
      ? res.status >= 300 && res.status < 400
        ? `backend redirect (HTTP ${res.status}) not followed`
        : `backend answered HTTP ${res.status}`
      : `backend unreachable: ${failure?.kind ?? "network"}${failure?.causeCode ? ` (${failure.causeCode})` : ""}`;

    if (rec.attempts >= config.callbacks.maxAttempts) {
      store.markFailed(id, { kind: "exhausted", error, httpStatus, responseEnc: null, contentType: null, now });
      this.deps.metrics.callbackDeliveries.inc({ provider: rec.provider, outcome: "exhausted" });
      log.error({ attempt: rec.attempts, backendStatus: httpStatus, error }, "callback delivery exhausted — needs operator action");
      return { kind: "exhausted", httpStatus, error };
    }

    const delay = Math.max(
      backoffMs(rec.attempts, config.callbacks.retryBaseMs, config.callbacks.retryMaxMs),
      Math.min(config.callbacks.retryMaxMs, retryAfterMs(res ? headerValue(res.headers, "retry-after") : undefined, now) ?? 0),
    );
    store.markRetry(id, { error, httpStatus, nextAttemptAt: now + delay, now });
    this.deps.metrics.callbackDeliveries.inc({ provider: rec.provider, outcome: "retry" });
    log.warn({ attempt: rec.attempts, backendStatus: httpStatus, error, retryInMs: delay }, "callback delivery failed, will retry");
    return { kind: "retry", httpStatus, error };
  }

  /** Stored backend answer for a duplicate callback, or null when it was purged. */
  storedResponse(rec: CallbackRecord): { status: number; body: Buffer; contentType: string } | null {
    if (rec.responseStatus == null || !rec.responseEnc) return null;
    try {
      return {
        status: rec.responseStatus,
        body: this.deps.encryptor.decrypt(rec.responseEnc, responseAad(rec.id)),
        contentType: rec.responseContentType ?? "application/json",
      };
    } catch {
      return null;
    }
  }

  private encryptResponse(id: string, body: Buffer): string | null {
    return body.length > 0 ? this.deps.encryptor.encrypt(body, responseAad(id)) : null;
  }
}
