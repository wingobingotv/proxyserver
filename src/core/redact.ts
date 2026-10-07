/**
 * Redaction for anything that may reach a log line or the database in
 * clear text. Keys are matched by name; string values are scanned for card
 * numbers and bearer tokens.
 */

export const REDACTED = "[REDACTED]";

const SENSITIVE_KEY =
  /(pass(word|phrase)?|secret|token|api[-_]?key|authorization|^auth$|cookie|signature|sign[-_]?hash|private[-_]?key|credential|card[-_]?number|^pan$|cvv|cvc|^pin$|merchant[-_]?id|^otp$)/i;

/** Header names that are never logged, whatever their value. */
export const SENSITIVE_HEADERS = [
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-token",
  "x-api-key",
  "x-sign-hash",
  "x-wingo-signature",
  "x-wingo-nonce",
] as const;

const CARD_LIKE = /\b\d(?:[ -]?\d){12,18}\b/g;
const BEARER = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi;

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY.test(key);
}

/** Masks card-like digit runs and bearer credentials inside free text. */
export function redactText(text: string): string {
  return text.replace(BEARER, "$1 " + REDACTED).replace(CARD_LIKE, (m) => {
    const digits = m.replace(/\D/g, "");
    return digits.length >= 13 ? `${digits.slice(0, 6)}******${digits.slice(-4)}` : m;
  });
}

/** Deep copy with sensitive keys replaced and strings scanned. Cycles and depth are bounded. */
export function redact(value: unknown, depth = 0, seen: WeakSet<object> = new WeakSet()): unknown {
  if (value == null) return value;
  if (typeof value === "string") return redactText(value);
  if (typeof value !== "object") return value;
  if (depth > 8) return "[TRUNCATED]";
  if (seen.has(value)) return "[CIRCULAR]";
  seen.add(value);
  if (Buffer.isBuffer(value)) return `[${value.length} bytes]`;
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1, seen));
  if (value instanceof Error) {
    return { name: value.name, message: redactText(value.message), code: (value as { code?: unknown }).code };
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = isSensitiveKey(k) ? REDACTED : redact(v, depth + 1, seen);
  }
  return out;
}

/** Headers safe to log: sensitive ones replaced, values truncated. */
export function redactHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, raw] of Object.entries(headers)) {
    if (raw === undefined) continue;
    const lower = name.toLowerCase();
    const value = Array.isArray(raw) ? raw.join(", ") : raw;
    out[lower] =
      (SENSITIVE_HEADERS as readonly string[]).includes(lower) || isSensitiveKey(lower) ? REDACTED : redactText(value).slice(0, 256);
  }
  return out;
}

/** Short error text for storage: no secrets, bounded length. */
export function safeErrorText(err: unknown, max = 300): string {
  const text = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
  return redactText(text).slice(0, max);
}
