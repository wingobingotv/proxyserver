import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from "prom-client";

/**
 * Prometheus metrics. Labels are low-cardinality on purpose: provider,
 * operation and short outcome codes only — never ids, IPs or amounts.
 */
export class Metrics {
  readonly registry = new Registry();

  readonly callbacksReceived = new Counter({
    name: "wbproxy_callbacks_received_total",
    help: "Inbound provider callbacks by result",
    labelNames: ["provider", "result"] as const,
    registers: [this.registry],
  });

  readonly callbackDeliveries = new Counter({
    name: "wbproxy_callback_deliveries_total",
    help: "Callback delivery attempts to the main backend by outcome",
    labelNames: ["provider", "outcome"] as const,
    registers: [this.registry],
  });

  readonly callbackDeliveryDuration = new Histogram({
    name: "wbproxy_callback_delivery_duration_seconds",
    help: "Time to deliver a callback to the main backend",
    labelNames: ["provider"] as const,
    buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20],
    registers: [this.registry],
  });

  readonly callbackBacklog = new Gauge({
    name: "wbproxy_callback_backlog",
    help: "Stored callbacks by delivery status",
    labelNames: ["status"] as const,
    registers: [this.registry],
  });

  readonly outboundRequests = new Counter({
    name: "wbproxy_outbound_requests_total",
    help: "Relayed requests to providers by outcome",
    labelNames: ["provider", "operation", "outcome", "status_class"] as const,
    registers: [this.registry],
  });

  readonly outboundDuration = new Histogram({
    name: "wbproxy_outbound_duration_seconds",
    help: "Provider request latency (all attempts)",
    labelNames: ["provider", "operation"] as const,
    buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30],
    registers: [this.registry],
  });

  readonly outboundRetries = new Counter({
    name: "wbproxy_outbound_retries_total",
    help: "Provider request retries",
    labelNames: ["provider", "operation"] as const,
    registers: [this.registry],
  });

  readonly upstreamFailures = new Counter({
    name: "wbproxy_upstream_failures_total",
    help: "Provider transport failures by kind",
    labelNames: ["provider", "operation", "kind"] as const,
    registers: [this.registry],
  });

  readonly authFailures = new Counter({
    name: "wbproxy_auth_failures_total",
    help: "Rejected internal authentication attempts by reason",
    labelNames: ["reason"] as const,
    registers: [this.registry],
  });

  readonly rejectedRequests = new Counter({
    name: "wbproxy_rejected_requests_total",
    help: "Requests rejected before reaching any destination, by reason",
    labelNames: ["surface", "reason"] as const,
    registers: [this.registry],
  });

  readonly circuitState = new Gauge({
    name: "wbproxy_circuit_open",
    help: "1 while a provider circuit is open or half-open",
    labelNames: ["provider"] as const,
    registers: [this.registry],
  });

  constructor(options: { defaultMetrics: boolean } = { defaultMetrics: true }) {
    if (options.defaultMetrics) collectDefaultMetrics({ register: this.registry, prefix: "wbproxy_" });
  }
}
