import { Agent, request, type Dispatcher } from "undici";
import { assertAllowedUrl, BLOCKED_DESTINATION, BlockedDestinationError, safeLookup, type DestinationPolicy, type Resolver } from "./ssrf.js";
import { stripHopByHop } from "./headers.js";

/**
 * The only way the proxy opens an outbound HTTP connection. Every request:
 * - is checked against its destination policy (host, port, scheme, address),
 * - resolves DNS through the policy at connect time,
 * - follows no redirects (a 3xx comes back as a 3xx),
 * - is bounded by a connect timeout, a total timeout and a response size cap.
 */

export type FailureKind = "timeout" | "connect" | "network" | "blocked" | "too_large";

export class UpstreamError extends Error {
  readonly kind: FailureKind;
  /** True when the failure happened before any request byte could reach the server. */
  readonly beforeSend: boolean;
  readonly causeCode: string | undefined;

  constructor(kind: FailureKind, message: string, options: { beforeSend: boolean; causeCode?: string }) {
    super(message);
    this.name = "UpstreamError";
    this.kind = kind;
    this.beforeSend = options.beforeSend;
    this.causeCode = options.causeCode;
  }
}

export type UpstreamRequest = {
  url: URL;
  method: string;
  headers: Record<string, string>;
  body?: Buffer | string;
  timeoutMs: number;
  maxResponseBytes: number;
};

export type UpstreamResponse = {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  durationMs: number;
};

/** Errors raised while connecting: nothing was sent, so a retry cannot duplicate an operation. */
const CONNECT_PHASE = new Set([
  "ECONNREFUSED",
  "ENOTFOUND",
  "EAI_AGAIN",
  "ENETUNREACH",
  "EHOSTUNREACH",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_CONNECT",
]);

function errorCode(err: unknown): string | undefined {
  let cur: unknown = err;
  for (let i = 0; i < 4 && cur && typeof cur === "object"; i += 1) {
    const code = (cur as { code?: unknown }).code;
    if (typeof code === "string") return code;
    cur = (cur as { cause?: unknown }).cause;
  }
  return undefined;
}

function classify(err: unknown): UpstreamError {
  if (err instanceof UpstreamError) return err;
  const code = errorCode(err);
  if (code === BLOCKED_DESTINATION || err instanceof BlockedDestinationError) {
    return new UpstreamError("blocked", (err as Error).message, { beforeSend: true, causeCode: code });
  }
  if (code === "UND_ERR_HEADERS_TIMEOUT" || code === "UND_ERR_BODY_TIMEOUT") {
    return new UpstreamError("timeout", "upstream did not answer in time", { beforeSend: false, causeCode: code });
  }
  if (code && CONNECT_PHASE.has(code)) {
    return new UpstreamError("connect", `could not connect (${code})`, { beforeSend: true, causeCode: code });
  }
  return new UpstreamError("network", `network error (${code ?? "unknown"})`, { beforeSend: false, causeCode: code });
}

export class HttpClient {
  private readonly policy: DestinationPolicy;
  private readonly dispatcher: Dispatcher;
  private readonly ownsDispatcher: boolean;

  constructor(policy: DestinationPolicy, options: { connectTimeoutMs: number; dispatcher?: Dispatcher; resolver?: Resolver }) {
    this.policy = policy;
    if (options.dispatcher) {
      this.dispatcher = options.dispatcher;
      this.ownsDispatcher = false;
    } else {
      this.dispatcher = new Agent({
        connect: {
          lookup: safeLookup(policy, options.resolver),
          timeout: options.connectTimeoutMs,
          rejectUnauthorized: true,
        },
        keepAliveTimeout: 10_000,
        connections: 32,
      });
      this.ownsDispatcher = true;
    }
  }

  async send(req: UpstreamRequest): Promise<UpstreamResponse> {
    try {
      assertAllowedUrl(req.url, this.policy);
    } catch (err) {
      throw classify(err);
    }
    const started = performance.now();
    const controller = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        const err = new UpstreamError("timeout", `no complete answer within ${req.timeoutMs} ms`, { beforeSend: false });
        controller.abort(err);
        reject(err);
      }, req.timeoutMs);
    });

    const work = (async () => {
      const res = await request(req.url, {
        method: req.method as Dispatcher.HttpMethod,
        headers: stripHopByHop(req.headers),
        body: req.body ?? null,
        dispatcher: this.dispatcher,
        signal: controller.signal,
        headersTimeout: req.timeoutMs,
        bodyTimeout: req.timeoutMs,
      });
      const declared = Number(res.headers["content-length"]);
      if (Number.isFinite(declared) && declared > req.maxResponseBytes) {
        res.body.destroy();
        throw new UpstreamError("too_large", `response of ${declared} bytes exceeds ${req.maxResponseBytes}`, { beforeSend: false });
      }
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of res.body) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
        size += buf.length;
        if (size > req.maxResponseBytes) {
          res.body.destroy();
          throw new UpstreamError("too_large", `response exceeds ${req.maxResponseBytes} bytes`, { beforeSend: false });
        }
        chunks.push(buf);
      }
      return {
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks),
        durationMs: performance.now() - started,
      } satisfies UpstreamResponse;
    })();
    work.catch(() => undefined);

    try {
      return await Promise.race([work, timeout]);
    } catch (err) {
      if (controller.signal.aborted && controller.signal.reason instanceof UpstreamError) throw controller.signal.reason;
      throw classify(err);
    } finally {
      clearTimeout(timer);
    }
  }

  async close(): Promise<void> {
    if (this.ownsDispatcher) await this.dispatcher.close();
  }
}
