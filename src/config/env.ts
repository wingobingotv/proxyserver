/**
 * Typed environment reader. Collects every problem before failing, and
 * names variables — never values — in its messages.
 */
export class ConfigError extends Error {
  constructor(readonly problems: string[]) {
    super(`invalid configuration:\n  - ${problems.join("\n  - ")}`);
    this.name = "ConfigError";
  }
}

export type AppEnv = "production" | "staging" | "development" | "test";

export const MIN_SECRET_LENGTH = 32;

export class EnvReader {
  readonly problems: string[] = [];

  constructor(private readonly env: Record<string, string | undefined>) {}

  raw(name: string): string | undefined {
    const v = this.env[name];
    return v === undefined ? undefined : v.trim();
  }

  has(name: string): boolean {
    return Boolean(this.raw(name));
  }

  problem(message: string): void {
    this.problems.push(message);
  }

  string(name: string, options: { required: true; pattern?: RegExp; hint?: string }): string;
  string(name: string, options?: { required?: false; default?: string; pattern?: RegExp; hint?: string }): string | undefined;
  string(name: string, options: { required?: boolean; default?: string; pattern?: RegExp; hint?: string } = {}): string | undefined {
    const value = this.raw(name) || options.default;
    if (!value) {
      if (options.required) this.problem(`${name} is required${options.hint ? ` (${options.hint})` : ""}`);
      return undefined;
    }
    if (options.pattern && !options.pattern.test(value)) {
      this.problem(`${name} has an invalid format${options.hint ? ` (${options.hint})` : ""}`);
      return undefined;
    }
    return value;
  }

  secret(name: string, options: { required: boolean; minLength?: number }): string | undefined {
    const value = this.raw(name);
    if (!value) {
      if (options.required) this.problem(`${name} is required`);
      return undefined;
    }
    const min = options.minLength ?? MIN_SECRET_LENGTH;
    if (value.length < min) {
      this.problem(`${name} must be at least ${min} characters`);
      return undefined;
    }
    return value;
  }

  int(name: string, fallback: number, range: { min: number; max: number }): number {
    const text = this.raw(name);
    if (!text) return fallback;
    const n = Number(text);
    if (!Number.isInteger(n) || n < range.min || n > range.max) {
      this.problem(`${name} must be an integer between ${range.min} and ${range.max}`);
      return fallback;
    }
    return n;
  }

  bool(name: string, fallback: boolean): boolean {
    const text = this.raw(name)?.toLowerCase();
    if (!text) return fallback;
    if (["1", "true", "yes", "on"].includes(text)) return true;
    if (["0", "false", "no", "off"].includes(text)) return false;
    this.problem(`${name} must be true or false`);
    return fallback;
  }

  list(name: string): string[] {
    return (this.raw(name) ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  /** Absolute URL; `https:` unless `allowHttp`. Path must be empty or `/` when `originOnly`. */
  url(name: string, options: { required: boolean; allowHttp: boolean; originOnly?: boolean }): URL | undefined {
    const text = this.raw(name);
    if (!text) {
      if (options.required) this.problem(`${name} is required`);
      return undefined;
    }
    let url: URL;
    try {
      url = new URL(text);
    } catch {
      this.problem(`${name} is not a valid URL`);
      return undefined;
    }
    if (url.protocol !== "https:" && !(options.allowHttp && url.protocol === "http:")) {
      this.problem(`${name} must use https`);
      return undefined;
    }
    if (url.username || url.password) {
      this.problem(`${name} must not contain credentials`);
      return undefined;
    }
    if (url.search || url.hash) {
      this.problem(`${name} must not contain a query or fragment`);
      return undefined;
    }
    if (options.originOnly && url.pathname !== "/" && url.pathname !== "") {
      this.problem(`${name} must be an origin without a path`);
      return undefined;
    }
    return url;
  }
}
