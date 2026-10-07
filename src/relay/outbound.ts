import type { Logger } from "pino";
import { backoffMs, sleep } from "../core/backoff.js";
import { CircuitBreaker } from "../core/circuitBreaker.js";
import { ProxyError } from "../core/errors.js";
import { HttpClient, UpstreamError, type UpstreamResponse } from "../core/httpClient.js";
import type { Metrics } from "../core/metrics.js";
import type { OperationDef, ProviderAdapter, RelayInput, RelayResult } from "../providers/types.js";

/**
 * Player API → proxy → provider. The destination is the provider's
 * configured base URL plus the operation's fixed path; nothing in the
 * caller's request can change it.
 */

export type RelayOutcome = RelayResult & { attempts: number; upstreamStatus: number; durationMs: number };

function upstreamUrl(provider: ProviderAdapter, op: OperationDef): URL {
  const url = new URL(provider.upstream.baseUrl.href);
  url.pathname = `${url.pathname.replace(/\/+$/, "")}${op.upstream.path}`;
  return url;
}

function toProxyError(err: UpstreamError): ProxyError {
  switch (err.kind) {
    case "timeout":
      return new ProxyError("upstream_timeout", "provider did not answer in time", { cause: err });
    case "blocked":
      return new ProxyError("upstream_blocked_destination", "destination refused by policy", { cause: err });
    case "too_large":
      return new ProxyError("upstream_response_too_large", "provider response too large", { cause: err });
    default:
      return new ProxyError("upstream_unreachable", `provider unreachable (${err.causeCode ?? err.kind})`, { cause: err });
  }
}

const statusClass = (s: number) => `${Math.floor(s / 100)}xx`;

export class OutboundRelay {
  private readonly clients = new Map<string, HttpClient>();
  private readonly breakers = new Map<string, CircuitBreaker>();

  constructor(
    providers: readonly ProviderAdapter[],
    private readonly metrics: Metrics,
    private readonly logger: Logger,
    clientFor: (p: ProviderAdapter) => HttpClient = (p) => new HttpClient(p.upstream.policy, { connectTimeoutMs: p.upstream.connectTimeoutMs }),
  ) {
    for (const p of providers) {
      this.clients.set(p.id, clientFor(p));
      this.breakers.set(p.id, new CircuitBreaker(p.circuit.failureThreshold, p.circuit.resetMs));
      metrics.circuitState.set({ provider: p.id }, 0);
    }
  }

  circuit(providerId: string): string {
    return this.breakers.get(providerId)?.current ?? "closed";
  }

  async execute(provider: ProviderAdapter, op: OperationDef, input: RelayInput, requestId: string): Promise<RelayOutcome> {
    const client = this.clients.get(provider.id);
    const breaker = this.breakers.get(provider.id);
    if (!client || !breaker) throw new ProxyError("unknown_provider");
    const labels = { provider: provider.id, operation: op.name };
    const built = op.buildRequest(input);
    const url = upstreamUrl(provider, op);
    const started = performance.now();
    const deadline = Date.now() + op.retry.deadlineMs;
    const log = this.logger.child({ requestId, provider: provider.id, operation: op.name, direction: "outbound" });

    let attempt = 0;
    for (;;) {
      attempt += 1;
      if (!breaker.tryAcquire()) {
        this.metrics.circuitState.set({ provider: provider.id }, 1);
        this.metrics.outboundRequests.inc({ ...labels, outcome: "circuit_open", status_class: "none" });
        throw new ProxyError("circuit_open", "provider temporarily unavailable", { retryAfterSeconds: breaker.retryAfterSeconds() });
      }
      const remaining = deadline - Date.now();
      let res: UpstreamResponse;
      try {
        if (remaining <= 0) throw new UpstreamError("timeout", "deadline reached", { beforeSend: true });
        res = await client.send({
          url,
          method: op.upstream.method,
          headers: built.headers,
          ...(built.body !== undefined ? { body: built.body } : {}),
          timeoutMs: Math.min(provider.upstream.timeoutMs, remaining),
          maxResponseBytes: provider.upstream.maxResponseBytes,
        });
      } catch (err) {
        const e = err instanceof UpstreamError ? err : new UpstreamError("network", String(err), { beforeSend: false });
        if (e.kind === "blocked") breaker.neutral();
        else breaker.failure();
        this.syncCircuit(provider.id, breaker);
        this.metrics.upstreamFailures.inc({ ...labels, kind: e.kind });
        const retryable =
          e.kind !== "blocked" &&
          e.kind !== "too_large" &&
          ((e.beforeSend && op.retry.onConnectFailure) || (!e.beforeSend && op.retry.onAmbiguousFailure));
        log.warn({ attempt, kind: e.kind, code: e.causeCode, retryable }, "provider request failed");
        if (retryable && (await this.waitForRetry(op, attempt, deadline))) {
          this.metrics.outboundRetries.inc(labels);
          continue;
        }
        this.metrics.outboundRequests.inc({ ...labels, outcome: `error_${e.kind}`, status_class: "none" });
        this.metrics.outboundDuration.observe(labels, (performance.now() - started) / 1000);
        throw toProxyError(e);
      }

      if (res.status >= 300 && res.status < 400) {
        breaker.neutral();
        this.metrics.outboundRequests.inc({ ...labels, outcome: "redirect_blocked", status_class: "3xx" });
        log.warn({ attempt, upstreamStatus: res.status }, "provider redirect refused");
        throw new ProxyError("upstream_redirect_blocked", `provider answered HTTP ${res.status}`);
      }
      if (res.status >= 500) breaker.failure();
      else breaker.success();
      this.syncCircuit(provider.id, breaker);

      if (op.retry.onAmbiguousFailure && op.retry.retryStatuses.includes(res.status) && (await this.waitForRetry(op, attempt, deadline))) {
        this.metrics.outboundRetries.inc(labels);
        log.warn({ attempt, upstreamStatus: res.status }, "provider error, retrying");
        continue;
      }

      const durationMs = performance.now() - started;
      this.metrics.outboundDuration.observe(labels, durationMs / 1000);
      let mapped: RelayResult;
      try {
        mapped = op.mapResponse(res);
      } catch (err) {
        this.metrics.outboundRequests.inc({ ...labels, outcome: "malformed_response", status_class: statusClass(res.status) });
        log.warn({ attempt, upstreamStatus: res.status, bytes: res.body.length }, "provider response malformed");
        throw err;
      }
      this.metrics.outboundRequests.inc({
        ...labels,
        outcome: res.status < 400 ? "ok" : "provider_error",
        status_class: statusClass(res.status),
      });
      log.info({ attempt, upstreamStatus: res.status, durationMs: Math.round(durationMs) }, "provider request done");
      return { ...mapped, attempts: attempt, upstreamStatus: res.status, durationMs };
    }
  }

  private async waitForRetry(op: OperationDef, attempt: number, deadline: number): Promise<boolean> {
    if (attempt >= op.retry.maxAttempts) return false;
    const delay = backoffMs(attempt, op.retry.baseDelayMs, op.retry.baseDelayMs * 8);
    if (Date.now() + delay >= deadline) return false;
    await sleep(delay);
    return true;
  }

  private syncCircuit(providerId: string, breaker: CircuitBreaker): void {
    this.metrics.circuitState.set({ provider: providerId }, breaker.current === "closed" ? 0 : 1);
  }

  async close(): Promise<void> {
    await Promise.all([...this.clients.values()].map((c) => c.close()));
  }
}
