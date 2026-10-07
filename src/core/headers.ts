/**
 * Header handling. Nothing is forwarded by default: each hop builds its
 * outgoing headers from an explicit allowlist.
 */

/** Never forwarded or accepted from a caller; the HTTP client sets its own framing. */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "expect",
  "forwarded",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-real-ip",
]);

export function isHopByHop(name: string): boolean {
  return HOP_BY_HOP.has(name.toLowerCase());
}

export function stripHopByHop(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) if (!isHopByHop(k)) out[k.toLowerCase()] = v;
  return out;
}

export function headerValue(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
  const raw = headers[name.toLowerCase()];
  if (Array.isArray(raw)) return raw[0];
  return raw;
}

/** Only the named headers, lower-cased, single-valued, CR/LF-free. */
export function pickHeaders(
  headers: Record<string, string | string[] | undefined>,
  allow: readonly string[],
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of allow) {
    const lower = name.toLowerCase();
    if (isHopByHop(lower)) continue;
    const value = headerValue(headers, lower);
    if (typeof value === "string" && !/[\r\n]/.test(value)) out[lower] = value;
  }
  return out;
}
