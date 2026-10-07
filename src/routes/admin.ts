import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AuthResult } from "../auth/internalAuth.js";
import type { CallbackDelivery } from "../callbacks/delivery.js";
import type { Config, Scope } from "../config/config.js";
import { ProxyError, errorBody } from "../core/errors.js";
import type { ProviderRegistry } from "../providers/registry.js";
import type { OutboundRelay } from "../relay/outbound.js";
import type { CallbackRecord, CallbackStatus, Store } from "../store/store.js";

/**
 * Read-mostly operations API for the WingoBingo admin side (Admin API →
 * proxy, HMAC key with the `admin` scope). Returns configuration and
 * delivery state, never secrets, payloads or provider responses.
 */

const STATUSES: CallbackStatus[] = ["validated", "forwarding", "delivered", "retry_pending", "failed"];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function publicRecord(r: CallbackRecord) {
  return {
    id: r.id,
    provider: r.provider,
    reference: r.reference,
    requestId: r.requestId,
    status: r.status,
    failureKind: r.failureKind,
    attempts: r.attempts,
    duplicates: r.duplicateCount,
    lastError: r.lastError,
    lastHttpStatus: r.lastHttpStatus,
    receivedAt: new Date(r.receivedAt).toISOString(),
    nextAttemptAt: r.nextAttemptAt ? new Date(r.nextAttemptAt).toISOString() : null,
    deliveredAt: r.deliveredAt ? new Date(r.deliveredAt).toISOString() : null,
    payloadStored: r.payloadEnc != null,
  };
}

export function registerAdminRoutes(
  app: FastifyInstance,
  deps: {
    registry: ProviderRegistry;
    store: Store;
    relay: OutboundRelay;
    delivery: CallbackDelivery;
    config: Config;
    authenticate: (req: FastifyRequest, reply: FastifyReply, scope: Scope) => AuthResult & { replied?: boolean };
    now: () => number;
  },
): void {
  const { registry, store, relay, config } = deps;
  const guard = (req: FastifyRequest, reply: FastifyReply) => {
    req.wbSurface = "admin";
    return deps.authenticate(req, reply, "admin").replied === true;
  };
  const fail = (reply: FastifyReply, req: FastifyRequest, err: ProxyError) =>
    reply.code(err.status).send(errorBody(err, req.wbRequestId));

  app.get("/v1/admin/providers", async (req, reply) => {
    if (guard(req, reply)) return reply;
    const counts = store.countsByStatus();
    return reply.send({
      providers: registry.list().map((p) => ({
        id: p.id,
        enabled: true,
        upstreamHost: p.upstream.baseUrl.host,
        circuit: relay.circuit(p.id),
        operations: p.operations.map((o) => ({
          name: `${p.id}.${o.name}`,
          method: o.route.method,
          path: `/v1/providers/${p.id}/${o.route.path}`,
          maxAttempts: o.retry.maxAttempts,
          retriesAmbiguousFailures: o.retry.onAmbiguousFailure,
        })),
        callback: p.callback
          ? {
              publicUrl: new URL(`/callback/${p.callback.slug}`, config.publicBaseUrl).href,
              methods: p.callback.methods,
              destination: p.callback.target.href,
              ipRestricted: !p.callback.allowedIps.empty,
              ackWhenQueued: p.callback.ackWhenQueued,
            }
          : null,
        credentials: p.credentials(),
        callbacks: Object.fromEntries(STATUSES.map((s) => [s, counts.find((c) => c.provider === p.id && c.status === s)?.count ?? 0])),
      })),
      disabled: registry.disabledIds(),
      internalKeys: config.internal.keys.map((k) => ({ id: k.id, scopes: [...k.scopes] })),
    });
  });

  app.get("/v1/admin/callbacks", async (req, reply) => {
    if (guard(req, reply)) return reply;
    const q = req.query as Record<string, string | undefined>;
    const status = q.status as CallbackStatus | undefined;
    if (status && !STATUSES.includes(status)) return fail(reply, req, new ProxyError("invalid_request", "unknown status"));
    if (q.provider && !registry.get(q.provider)) return fail(reply, req, new ProxyError("unknown_provider"));
    if (q.reference && !/^[0-9A-Za-z-]{1,64}$/.test(q.reference)) return fail(reply, req, new ProxyError("invalid_request", "bad reference"));
    const limit = Math.min(200, Math.max(1, Number(q.limit) || 50));
    const before = q.before ? Date.parse(q.before) : undefined;
    const rows = store.listCallbacks({
      limit,
      ...(q.provider ? { provider: q.provider } : {}),
      ...(status ? { status } : {}),
      ...(q.reference ? { reference: q.reference } : {}),
      ...(before && Number.isFinite(before) ? { before } : {}),
    });
    return reply.send({ callbacks: rows.map(publicRecord) });
  });

  app.get("/v1/admin/callbacks/:id", async (req, reply) => {
    if (guard(req, reply)) return reply;
    const id = (req.params as { id: string }).id;
    const rec = UUID.test(id) ? store.getCallback(id) : null;
    if (!rec) return fail(reply, req, new ProxyError("not_found"));
    return reply.send({ callback: publicRecord(rec) });
  });

  /** Puts a failed callback back in the queue (after fixing whatever made the backend refuse it). */
  app.post("/v1/admin/callbacks/:id/redeliver", async (req, reply) => {
    if (guard(req, reply)) return reply;
    const id = (req.params as { id: string }).id;
    const rec = UUID.test(id) ? store.getCallback(id) : null;
    if (!rec) return fail(reply, req, new ProxyError("not_found"));
    if (!store.rearm(id, deps.now(), { includeRejected: true })) {
      return fail(reply, req, new ProxyError("invalid_request", "only failed callbacks with a stored payload can be redelivered", { status: 409 }));
    }
    req.log.info({ requestId: req.wbRequestId, callbackId: id }, "callback re-queued by operator");
    return reply.code(202).send({ callback: publicRecord(store.getCallback(id)!) });
  });
}
