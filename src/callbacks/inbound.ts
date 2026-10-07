import { randomUUID } from "node:crypto";
import type { Logger } from "pino";
import type { Config } from "../config/config.js";
import type { Encryptor } from "../core/crypto.js";
import { ProxyError, errorBody } from "../core/errors.js";
import { headerValue, pickHeaders } from "../core/headers.js";
import { mediaType, sha256Hex } from "../core/hmac.js";
import type { Metrics } from "../core/metrics.js";
import type { RateLimiter } from "../core/rateLimiter.js";
import type { ProviderRegistry } from "../providers/registry.js";
import type { ProviderAdapter } from "../providers/types.js";
import type { Store } from "../store/store.js";
import { payloadAad, type CallbackDelivery, type DeliveryOutcome, type StoredPayload } from "./delivery.js";

/**
 * Provider → proxy → main backend.
 *
 * The proxy checks what can be checked at the transport layer (route,
 * source, size, media type, the provider's signature), stores the callback
 * durably, and relays it. It never decides that a payment succeeded: the
 * backend still looks the transaction up, re-verifies it with the provider
 * (through this proxy) and applies its own idempotent crediting.
 *
 * Duplicates — the same provider event identity — are not relayed again
 * once delivered; the provider gets the stored answer. A duplicate whose
 * body differs from the stored one is refused (409): with a signature that
 * covers only some fields, that is what a tampered replay looks like.
 */

export type CallbackHttpRequest = {
  slug: string;
  method: string;
  headers: Record<string, string | string[] | undefined>;
  query: string;
  body: Buffer;
  ip: string | undefined;
  requestId: string;
};

export type CallbackHttpResponse = {
  status: number;
  contentType: string;
  body: Buffer | string;
  headers?: Record<string, string>;
};

const json = (status: number, value: unknown, headers?: Record<string, string>): CallbackHttpResponse => ({
  status,
  contentType: "application/json",
  body: JSON.stringify(value),
  ...(headers ? { headers } : {}),
});

export class CallbackIntake {
  constructor(
    private readonly deps: {
      registry: ProviderRegistry;
      store: Store;
      encryptor: Encryptor;
      delivery: CallbackDelivery;
      config: Config;
      metrics: Metrics;
      logger: Logger;
      providerLimiters: Map<string, RateLimiter>;
      ipLimiter: RateLimiter;
      now?: () => number;
    },
  ) {}

  private now(): number {
    return (this.deps.now ?? Date.now)();
  }

  async handle(req: CallbackHttpRequest): Promise<CallbackHttpResponse> {
    const { registry, metrics } = this.deps;
    const provider = registry.byCallbackSlug(req.slug);
    if (!provider || !provider.callback) {
      metrics.rejectedRequests.inc({ surface: "callback", reason: "unknown_callback" });
      return json(404, errorBody(new ProxyError("not_found"), req.requestId));
    }
    const cb = provider.callback;
    const log = this.deps.logger.child({ requestId: req.requestId, provider: provider.id, direction: "callback" });
    const reject = (err: ProxyError, result: string, extraHeaders?: Record<string, string>) => {
      metrics.callbacksReceived.inc({ provider: provider.id, result });
      log.warn({ result, sourceIp: req.ip, status: err.status }, "callback refused");
      return json(err.status, errorBody(err, req.requestId), extraHeaders);
    };

    if (!(cb.methods as readonly string[]).includes(req.method)) {
      return reject(new ProxyError("method_not_allowed"), "method_not_allowed", { allow: cb.methods.join(", ") });
    }

    const wait = this.deps.providerLimiters.get(provider.id)?.take(provider.id) || this.deps.ipLimiter.take(`${provider.id}:${req.ip ?? "?"}`);
    if (wait) return reject(new ProxyError("rate_limited"), "rate_limited", { "retry-after": String(wait) });

    if (!cb.allowedIps.matches(req.ip)) return reject(new ProxyError("forbidden_source"), "rejected_ip");

    if (!cb.contentTypes.includes(mediaType(headerValue(req.headers, "content-type")))) {
      return reject(new ProxyError("unsupported_media_type"), "unsupported_media_type");
    }
    if (req.body.length > cb.maxBodyBytes) return reject(new ProxyError("payload_too_large"), "payload_too_large");

    const validation = cb.validate({ method: req.method, headers: req.headers, query: req.query, body: req.body, sourceIp: req.ip });
    if (!validation.ok) return reject(validation.error, `rejected_${validation.reason}`);

    const id = randomUUID();
    const receivedAt = this.now();
    const payload: StoredPayload = {
      body: req.body.toString("base64"),
      query: req.query,
      headers: pickHeaders(req.headers, cb.forwardHeaders),
    };
    const payloadHash = sha256Hex(req.body);
    const stored = this.deps.store.insertCallback({
      id,
      provider: provider.id,
      dedupeKey: validation.dedupeKey,
      reference: validation.reference,
      requestId: req.requestId,
      receivedAt,
      sourceIp: req.ip ?? null,
      method: req.method,
      contentType: mediaType(headerValue(req.headers, "content-type")) || null,
      payloadHash,
      payloadEnc: this.deps.encryptor.encrypt(JSON.stringify(payload), payloadAad(id)),
      destination: cb.target.href,
      // The inline attempt below claims it first; the worker only picks it up if this process dies.
      nextAttemptAt: receivedAt + this.deps.config.callbacks.forwardTimeoutMs + 5_000,
    });

    if (stored.inserted) {
      metrics.callbacksReceived.inc({ provider: provider.id, result: "accepted" });
      log.info({ callbackId: id, reference: validation.reference, sourceIp: req.ip }, "callback stored");
      return this.respond(provider, await this.deps.delivery.attempt(id), req.requestId);
    }

    const existing = stored.record;
    if (existing.payloadHash !== payloadHash) {
      return reject(new ProxyError("callback_conflict", "same event identity with a different body"), "conflict");
    }
    metrics.callbacksReceived.inc({ provider: provider.id, result: "duplicate" });
    log.info({ callbackId: existing.id, status: existing.status, duplicates: existing.duplicateCount }, "duplicate callback");

    switch (existing.status) {
      case "delivered":
      case "failed": {
        if (existing.status === "failed" && existing.failureKind === "exhausted") {
          // The provider is still retrying after we gave up: deliver again with a fresh budget.
          this.deps.store.rearm(existing.id, this.now(), { includeRejected: false });
          return this.respond(provider, await this.deps.delivery.attempt(existing.id), existing.requestId);
        }
        const answer = this.deps.delivery.storedResponse(existing);
        if (answer) return { status: answer.status, contentType: answer.contentType, body: answer.body };
        return json(existing.status === "delivered" ? 200 : (existing.responseStatus ?? 400), {
          status: existing.status === "delivered" ? "OK" : "REJECTED",
          duplicate: true,
          requestId: existing.requestId,
        });
      }
      case "validated":
      case "retry_pending":
        return this.respond(provider, await this.deps.delivery.attempt(existing.id), existing.requestId);
      case "forwarding":
      default:
        return this.queued(provider, existing.requestId);
    }
  }

  private respond(provider: ProviderAdapter, outcome: DeliveryOutcome | null, requestId: string): CallbackHttpResponse {
    if (outcome && (outcome.kind === "delivered" || outcome.kind === "rejected")) {
      return { status: outcome.httpStatus, contentType: outcome.contentType, body: outcome.body };
    }
    return this.queued(provider, requestId);
  }

  /** Stored, but the backend has not taken it yet. */
  private queued(provider: ProviderAdapter, requestId: string): CallbackHttpResponse {
    if (provider.callback?.ackWhenQueued) return json(202, { status: "accepted", requestId });
    return json(503, { status: "retry_later", requestId }, { "retry-after": "30" });
  }
}
