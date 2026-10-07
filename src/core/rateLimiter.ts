/**
 * In-memory token buckets, keyed by caller. The proxy runs as a single
 * instance (one fixed egress IP), so process memory is the right scope.
 * A limited callback gets 429 + Retry-After: providers redeliver, nothing is
 * dropped silently.
 */
type Bucket = { tokens: number; updatedAt: number };

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly ratePerMs: number;

  constructor(
    private readonly perMinute: number,
    private readonly burst: number = perMinute,
    private readonly now: () => number = Date.now,
  ) {
    this.ratePerMs = perMinute / 60_000;
  }

  /** Takes one token; returns 0 when allowed, else seconds until a token is available. */
  take(key: string): number {
    if (this.perMinute <= 0) return 0;
    const t = this.now();
    const b = this.buckets.get(key) ?? { tokens: this.burst, updatedAt: t };
    b.tokens = Math.min(this.burst, b.tokens + (t - b.updatedAt) * this.ratePerMs);
    b.updatedAt = t;
    if (b.tokens >= 1) {
      b.tokens -= 1;
      this.buckets.set(key, b);
      return 0;
    }
    this.buckets.set(key, b);
    return Math.max(1, Math.ceil((1 - b.tokens) / this.ratePerMs / 1000));
  }

  /** Seconds until `key` has a token, without taking one; 0 when available. */
  peek(key: string): number {
    if (this.perMinute <= 0) return 0;
    const b = this.buckets.get(key);
    if (!b) return 0;
    const tokens = Math.min(this.burst, b.tokens + (this.now() - b.updatedAt) * this.ratePerMs);
    return tokens >= 1 ? 0 : Math.max(1, Math.ceil((1 - tokens) / this.ratePerMs / 1000));
  }

  /** Drops buckets that are full again, so memory stays bounded. */
  sweep(): void {
    const t = this.now();
    for (const [key, b] of this.buckets) {
      if (b.tokens + (t - b.updatedAt) * this.ratePerMs >= this.burst) this.buckets.delete(key);
    }
  }
}
