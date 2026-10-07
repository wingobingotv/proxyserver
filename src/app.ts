import Fastify, { LogController, type FastifyBaseLogger, type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import type { Logger } from "pino";
import { InternalAuthenticator, type AuthResult } from "./auth/internalAuth.js";
import { CallbackDelivery } from "./callbacks/delivery.js";
import { CallbackIntake } from "./callbacks/inbound.js";
import { RetryWorker } from "./callbacks/worker.js";
import type { Config, Scope } from "./config/config.js";
import type { Encryptor } from "./core/crypto.js";
import { ProxyError, errorBody, isProxyError } from "./core/errors.js";
import { headerValue } from "./core/headers.js";
import { mediaType, safeEqual } from "./core/hmac.js";
import { HttpClient } from "./core/httpClient.js";
import type { Metrics } from "./core/metrics.js";
import { RateLimiter } from "./core/rateLimiter.js";
import { REQUEST_ID_HEADER, newRequestId, resolveRequestId } from "./core/requestId.js";
import type { ProviderRegistry } from "./providers/registry.js";
import type { ProviderAdapter } from "./providers/types.js";
import { OutboundRelay } from "./relay/outbound.js";
import { registerAdminRoutes } from "./routes/admin.js";
import type { Store } from "./store/store.js";

export type AppDeps = {
  config: Config;
  registry: ProviderRegistry;
  store: Store;
  encryptor: Encryptor;
  metrics: Metrics;
  logger: Logger;
  /** Overrides for tests: HTTP clients per provider and for the backend. */
  providerClient?: (p: ProviderAdapter) => HttpClient;
  backendClient?: HttpClient;
  now?: () => number;
};

export type App = {
  app: FastifyInstance;
  worker: RetryWorker;
  delivery: CallbackDelivery;
  relay: OutboundRelay;
  close(): Promise<void>;
};

declare module "fastify" {
  interface FastifyRequest {
    wbRequestId: string;
    wbSurface: "relay" | "callback" | "admin" | "ops" | "other";
    wbProvider?: string;
    wbOperation?: string;
  }
}

const PROVIDER_SEGMENT = /^[a-z0-9-]{1,32}$/;
const OPERATION_PATH = /^[a-z0-9_-]{1,32}(?:\/[a-z0-9_-]{1,32}){0,3}$/;

function rawTarget(req: FastifyRequest): string {
  return req.raw.url ?? req.url;
}

function rawQuery(req: FastifyRequest): string {
  const target = rawTarget(req);
  const i = target.indexOf("?");
  return i === -1 ? "" : target.slice(i + 1);
}

function bodyOf(req: FastifyRequest): Buffer {
  return Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
}

function sendError(reply: FastifyReply, err: ProxyError, requestId: string): FastifyReply {
  if (err.retryAfterSeconds) reply.header("retry-after", String(err.retryAfterSeconds));
  return reply.code(err.status).header("content-type", "application/json").send(JSON.stringify(errorBody(err, requestId)));
}

export function buildApp(deps: AppDeps): App {
  const { config, registry, store, encryptor, metrics, logger } = deps;
  const now = deps.now ?? Date.now;

  const maxCallbackBody = Math.max(0, ...registry.list().map((p) => p.callback?.maxBodyBytes ?? 0));
  const app = Fastify({
    loggerInstance: logger as FastifyBaseLogger,
    logController: new LogController({ disableRequestLogging: true }),
    trustProxy: config.trustedProxies.length > 0 ? config.trustedProxies : false,
    bodyLimit: Math.max(config.internal.maxBodyBytes, maxCallbackBody, 1_024),
    genReqId: () => newRequestId(),
    requestIdHeader: false,
    return503OnClosing: true,
    routerOptions: { caseSensitive: true, ignoreTrailingSlash: false, maxParamLength: 128 },
  });

  // Every body is kept as raw bytes: signatures are computed over exactly what was sent.
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("*", { parseAs: "buffer" }, (_req, body, done) => done(null, body));

  const backend =
    deps.backendClient ?? new HttpClient(config.backend.policy, { connectTimeoutMs: config.backend.connectTimeoutMs });
  const relay = new OutboundRelay(registry.list(), metrics, logger, deps.providerClient);
  const delivery = new CallbackDelivery({ store, encryptor, registry, backend, config, metrics, logger, now });
  const providerLimiters = new Map(
    registry
      .list()
      .filter((p) => p.callback)
      .map((p) => [p.id, new RateLimiter(p.callback!.rateLimitPerMinute)] as const),
  );
  const ipLimiter = new RateLimiter(config.callbacks.rateLimitPerIpPerMinute);
  const internalLimiter = new RateLimiter(config.internal.rateLimitPerMinute);
  const authFailureLimiter = new RateLimiter(config.internal.authFailuresPerMinute);
  const intake = new CallbackIntake({ registry, store, encryptor, delivery, config, metrics, logger, providerLimiters, ipLimiter, now });
  const worker = new RetryWorker({
    store,
    delivery,
    config,
    metrics,
    logger,
    limiters: [...providerLimiters.values(), ipLimiter, internalLimiter, authFailureLimiter],
    now,
  });
  const auth = new InternalAuthenticator(config.internal.keys, store, config.internal, now);

  app.addHook("onRequest", async (req) => {
    req.wbRequestId = newRequestId();
    req.wbSurface = "other";
  });

  app.addHook("onSend", async (req, reply, payload) => {
    reply.header(REQUEST_ID_HEADER, req.wbRequestId);
    reply.header("cache-control", "no-store");
    reply.header("x-content-type-options", "nosniff");
    reply.removeHeader("x-powered-by");
    return payload;
  });

  app.addHook("onResponse", async (req, reply) => {
    if (req.wbSurface === "ops") return;
    logger.info(
      {
        requestId: req.wbRequestId,
        surface: req.wbSurface,
        provider: req.wbProvider,
        operation: req.wbOperation,
        method: req.method,
        path: req.routeOptions.url ?? rawTarget(req).split("?")[0],
        status: reply.statusCode,
        durationMs: Math.round(reply.elapsedTime),
        sourceIp: req.ip,
      },
      "request",
    );
  });

  app.setErrorHandler((err, req, reply) => {
    const id = req.wbRequestId ?? newRequestId();
    if (isProxyError(err)) return sendError(reply, err, id);
    const status = (err as { statusCode?: number }).statusCode ?? 500;
    if (status === 413) return sendError(reply, new ProxyError("payload_too_large"), id);
    if (status === 415) return sendError(reply, new ProxyError("unsupported_media_type"), id);
    if (status >= 400 && status < 500) return sendError(reply, new ProxyError("invalid_request", undefined, { status }), id);
    logger.error({ requestId: id, err: { name: (err as Error).name, message: (err as Error).message } }, "unhandled error");
    return sendError(reply, new ProxyError("internal_error"), id);
  });

  app.setNotFoundHandler((req, reply) => {
    metrics.rejectedRequests.inc({ surface: "any", reason: "not_found" });
    return sendError(reply, new ProxyError("not_found"), req.wbRequestId);
  });

  /** Authenticates an internal call; on failure counts it, slows repeated failures, and replies. */
  const authenticate = (req: FastifyRequest, reply: FastifyReply, scope: Scope): AuthResult & { replied?: boolean } => {
    const blockedFor = authFailureLimiter.peek(`fail:${req.ip}`);
    if (blockedFor) {
      metrics.authFailures.inc({ reason: "throttled" });
      sendError(reply, new ProxyError("rate_limited", undefined, { retryAfterSeconds: blockedFor }), req.wbRequestId);
      return { ok: false, reason: "forbidden_source", replied: true };
    }
    const result = auth.verify({ method: req.method, target: rawTarget(req), headers: req.headers, body: bodyOf(req), ip: req.ip }, scope);
    if (!result.ok) {
      metrics.authFailures.inc({ reason: result.reason });
      const wait = authFailureLimiter.take(`fail:${req.ip}`);
      logger.warn({ requestId: req.wbRequestId, reason: result.reason, sourceIp: req.ip, path: rawTarget(req).split("?")[0] }, "internal auth failed");
      if (wait) sendError(reply, new ProxyError("rate_limited", undefined, { retryAfterSeconds: wait }), req.wbRequestId);
      else if (result.reason === "forbidden_source") sendError(reply, new ProxyError("forbidden_source"), req.wbRequestId);
      else sendError(reply, new ProxyError("unauthorized", result.reason), req.wbRequestId);
      return { ...result, replied: true };
    }
    req.wbRequestId = resolveRequestId(req.headers[REQUEST_ID_HEADER], true);
    return result;
  };

  // ---- operations --------------------------------------------------------

  app.get("/healthz", async (req, reply) => {
    req.wbSurface = "ops";
    return reply.send({ status: "ok" });
  });

  app.get("/readyz", async (req, reply) => {
    req.wbSurface = "ops";
    let ok = false;
    try {
      ok = store.ping() && worker.isRunning;
    } catch {
      ok = false;
    }
    return reply.code(ok ? 200 : 503).send({ status: ok ? "ready" : "not_ready" });
  });

  app.get("/metrics", async (req, reply) => {
    req.wbSurface = "ops";
    const token = config.metricsToken;
    const given = headerValue(req.headers, "authorization")?.replace(/^Bearer\s+/i, "") ?? "";
    if (!token || !safeEqual(token, given)) return sendError(reply, new ProxyError("not_found"), req.wbRequestId);
    worker.refreshBacklog();
    return reply.header("content-type", metrics.registry.contentType).send(await metrics.registry.metrics());
  });

  // ---- incoming callbacks ------------------------------------------------

  app.route({
    method: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    url: "/callback/:slug",
    handler: async (req, reply) => {
      req.wbSurface = "callback";
      const slug = (req.params as { slug: string }).slug;
      req.wbProvider = registry.byCallbackSlug(slug)?.id;
      const res = await intake.handle({
        slug,
        method: req.method,
        headers: req.headers,
        query: rawQuery(req),
        body: bodyOf(req),
        ip: req.ip,
        requestId: req.wbRequestId,
      });
      for (const [k, v] of Object.entries(res.headers ?? {})) reply.header(k, v);
      return reply.code(res.status).header("content-type", res.contentType).send(res.body);
    },
  });

  // ---- outgoing relay ----------------------------------------------------

  app.route({
    method: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    url: "/v1/providers/*",
    handler: async (req, reply) => {
      req.wbSurface = "relay";
      if (authenticate(req, reply, "relay").replied) return reply;

      const wait = internalLimiter.take("relay");
      if (wait) return sendError(reply, new ProxyError("rate_limited", undefined, { retryAfterSeconds: wait }), req.wbRequestId);

      const target = rawTarget(req);
      const [path] = target.split("?") as [string];
      if (rawQuery(req)) {
        metrics.rejectedRequests.inc({ surface: "relay", reason: "query_not_allowed" });
        return sendError(reply, new ProxyError("query_not_allowed", "relay operations take no query string"), req.wbRequestId);
      }
      const rest = path.slice("/v1/providers/".length);
      const slash = rest.indexOf("/");
      const providerId = slash === -1 ? rest : rest.slice(0, slash);
      const opPath = slash === -1 ? "" : rest.slice(slash + 1);
      if (!PROVIDER_SEGMENT.test(providerId)) {
        metrics.rejectedRequests.inc({ surface: "relay", reason: "unknown_provider" });
        return sendError(reply, new ProxyError("unknown_provider"), req.wbRequestId);
      }
      req.wbProvider = providerId;
      const provider = registry.get(providerId);
      if (!provider) {
        const disabled = registry.isDisabled(providerId);
        metrics.rejectedRequests.inc({ surface: "relay", reason: disabled ? "provider_disabled" : "unknown_provider" });
        return sendError(reply, new ProxyError(disabled ? "provider_disabled" : "unknown_provider"), req.wbRequestId);
      }
      const op = OPERATION_PATH.test(opPath) ? registry.operation(providerId, req.method, opPath) : undefined;
      if (!op) {
        const wrongMethod = OPERATION_PATH.test(opPath) && registry.hasPath(providerId, opPath);
        metrics.rejectedRequests.inc({ surface: "relay", reason: wrongMethod ? "method_not_allowed" : "unknown_operation" });
        return sendError(reply, new ProxyError(wrongMethod ? "method_not_allowed" : "unknown_operation"), req.wbRequestId);
      }
      req.wbOperation = op.name;
      const body = bodyOf(req);
      if (body.length > op.maxBodyBytes) return sendError(reply, new ProxyError("payload_too_large"), req.wbRequestId);
      const contentType = headerValue(req.headers, "content-type");
      if (op.contentTypes.length > 0 && !op.contentTypes.includes(mediaType(contentType))) {
        return sendError(reply, new ProxyError("unsupported_media_type"), req.wbRequestId);
      }

      const out = await relay.execute(provider, op, { body, contentType, headers: req.headers }, req.wbRequestId);
      return reply
        .code(out.status)
        .header("content-type", out.contentType)
        .header("x-wingo-upstream-status", String(out.upstreamStatus))
        .header("x-wingo-upstream-attempts", String(out.attempts))
        .send(out.body);
    },
  });

  registerAdminRoutes(app, { registry, store, relay, delivery, config, authenticate, now });

  return {
    app,
    worker,
    delivery,
    relay,
    async close() {
      await worker.stop();
      await app.close();
      await relay.close();
      await backend.close();
    },
  };
}
