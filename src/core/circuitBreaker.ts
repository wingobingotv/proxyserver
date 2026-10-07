/**
 * Per-provider circuit breaker. Opens after `failureThreshold` consecutive
 * upstream failures (connect errors, timeouts, 5xx — never 4xx), rejects
 * fast while open, then lets one trial request through (half-open).
 */
export type CircuitState = "closed" | "open" | "half_open";

export class CircuitBreaker {
  private state: CircuitState = "closed";
  private failures = 0;
  private openedAt = 0;
  private trialInFlight = false;

  constructor(
    private readonly failureThreshold: number,
    private readonly resetMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  get current(): CircuitState {
    if (this.state === "open" && this.now() - this.openedAt >= this.resetMs) return "half_open";
    return this.state;
  }

  /** Whether a request may go out now. Must be followed by `success()` or `failure()` when it returns true. */
  tryAcquire(): boolean {
    const state = this.current;
    if (state === "closed") return true;
    if (state === "open") return false;
    if (this.trialInFlight) return false;
    this.state = "half_open";
    this.trialInFlight = true;
    return true;
  }

  /** Releases a slot from `tryAcquire()` without counting it (e.g. a 4xx). */
  neutral(): void {
    this.trialInFlight = false;
    if (this.state === "half_open") this.state = "closed";
    this.failures = 0;
  }

  success(): void {
    this.neutral();
  }

  failure(): void {
    this.trialInFlight = false;
    if (this.state === "half_open") {
      this.trip();
      return;
    }
    this.failures += 1;
    if (this.failures >= this.failureThreshold) this.trip();
  }

  retryAfterSeconds(): number {
    return Math.max(1, Math.ceil((this.resetMs - (this.now() - this.openedAt)) / 1000));
  }

  private trip(): void {
    this.state = "open";
    this.openedAt = this.now();
    this.failures = 0;
  }
}
