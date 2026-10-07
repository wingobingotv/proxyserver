import type { Logger } from "pino";
import type { Config } from "../config/config.js";
import type { Metrics } from "../core/metrics.js";
import type { RateLimiter } from "../core/rateLimiter.js";
import type { CallbackStatus, Store } from "../store/store.js";
import type { CallbackDelivery } from "./delivery.js";

const STATUSES: CallbackStatus[] = ["validated", "forwarding", "delivered", "retry_pending", "failed"];
const MAINTENANCE_EVERY_MS = 10 * 60_000;

/**
 * Background redelivery: picks up callbacks whose retry time has come and
 * callbacks whose delivery lock expired (the process stopped mid-delivery),
 * and does the periodic housekeeping.
 */
export class RetryWorker {
  private timer: NodeJS.Timeout | null = null;
  private running: Promise<void> | null = null;
  private stopped = true;
  private lastMaintenance = 0;

  constructor(
    private readonly deps: {
      store: Store;
      delivery: CallbackDelivery;
      config: Config;
      metrics: Metrics;
      logger: Logger;
      limiters: RateLimiter[];
      now?: () => number;
    },
  ) {}

  private now(): number {
    return (this.deps.now ?? Date.now)();
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.schedule(0);
  }

  get isRunning(): boolean {
    return !this.stopped;
  }

  private schedule(ms: number): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.running = this.tick()
        .then(() => undefined)
        .catch((err: unknown) => this.deps.logger.error({ err }, "retry worker tick failed"))
        .finally(() => {
          this.running = null;
          this.schedule(this.deps.config.callbacks.workerIntervalMs);
        });
    }, ms);
    this.timer.unref?.();
  }

  /** One pass: deliver what is due, then maintenance when it is time. Public for tests. */
  async tick(): Promise<number> {
    const ids = this.deps.store.dueCallbacks(this.now(), this.deps.config.callbacks.workerBatchSize);
    let attempted = 0;
    for (const id of ids) {
      if (this.stopped && attempted > 0) break;
      const outcome = await this.deps.delivery.attempt(id);
      if (outcome) attempted += 1;
    }
    if (this.now() - this.lastMaintenance >= MAINTENANCE_EVERY_MS) this.maintenance();
    return attempted;
  }

  maintenance(): void {
    const now = this.now();
    this.lastMaintenance = now;
    const nonces = this.deps.store.purgeNonces(now);
    const purged = this.deps.store.purgePayloads(now - this.deps.config.callbacks.payloadRetentionDays * 86_400_000);
    for (const l of this.deps.limiters) l.sweep();
    this.refreshBacklog();
    if (nonces || purged) this.deps.logger.info({ noncesPurged: nonces, payloadsPurged: purged }, "maintenance");
  }

  refreshBacklog(): void {
    const totals = new Map<CallbackStatus, number>(STATUSES.map((s) => [s, 0]));
    for (const row of this.deps.store.countsByStatus()) totals.set(row.status, (totals.get(row.status) ?? 0) + row.count);
    for (const [status, count] of totals) this.deps.metrics.callbackBacklog.set({ status }, count);
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (this.running) await this.running;
  }
}
