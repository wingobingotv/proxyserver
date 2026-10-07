import { createHash } from "node:crypto";
import { ProxyError } from "../core/errors.js";
import type { UpstreamResponse } from "../core/httpClient.js";
import type { RelayResult } from "./types.js";

/** Shared helpers for JSON providers. */

export function parseJsonObject(body: Buffer): Record<string, unknown> | null {
  if (body.length === 0) return null;
  try {
    const value: unknown = JSON.parse(body.toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Caller body → object with only `allowed` keys; anything else is refused rather than silently forwarded. */
export function strictJsonBody(body: Buffer, allowed: readonly string[]): Record<string, unknown> {
  const obj = parseJsonObject(body);
  if (!obj) throw new ProxyError("invalid_request", "body must be a JSON object");
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) throw new ProxyError("invalid_request", `unexpected field "${key}"`);
  }
  return obj;
}

function hasControlChars(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

export function requireString(obj: Record<string, unknown>, key: string, options: { min: number; max: number; pattern?: RegExp }): string {
  const value = obj[key];
  if (typeof value !== "string") throw new ProxyError("invalid_request", `"${key}" must be a string`);
  if (value.length < options.min || value.length > options.max) {
    throw new ProxyError("invalid_request", `"${key}" must be ${options.min}–${options.max} characters`);
  }
  if (hasControlChars(value)) throw new ProxyError("invalid_request", `"${key}" contains control characters`);
  if (options.pattern && !options.pattern.test(value)) throw new ProxyError("invalid_request", `"${key}" has an invalid format`);
  return value;
}

export function requirePositiveInteger(obj: Record<string, unknown>, key: string): number {
  const value = obj[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new ProxyError("invalid_request", `"${key}" must be a positive integer`);
  }
  return value;
}

export function requireHttpUrl(obj: Record<string, unknown>, key: string, max: number): string {
  const value = requireString(obj, key, { min: 1, max });
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ProxyError("invalid_request", `"${key}" must be an absolute URL`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new ProxyError("invalid_request", `"${key}" must be an http(s) URL`);
  return value;
}

/**
 * Provider response → relay result. A 2xx must be a JSON object; a non-2xx
 * keeps its status (callers branch on 4xx vs 5xx) and its JSON body, or gets
 * a neutral JSON body when the provider sent something else (an HTML error page).
 */
export function mapJsonResponse(res: UpstreamResponse): RelayResult {
  const parsed = parseJsonObject(res.body);
  if (res.status >= 200 && res.status < 300) {
    if (!parsed) throw new ProxyError("upstream_malformed_response", "provider returned a body that is not a JSON object");
    return { status: res.status, contentType: "application/json", body: res.body };
  }
  if (parsed) return { status: res.status, contentType: "application/json", body: res.body };
  return {
    status: res.status,
    contentType: "application/json",
    body: Buffer.from(JSON.stringify({ error: "upstream_non_json", message: `provider returned HTTP ${res.status}` })),
  };
}

/** First 12 hex chars of SHA-256: tells credential versions apart without revealing them. */
export function fingerprint(secret: string | undefined): string | null {
  return secret ? createHash("sha256").update(secret).digest("hex").slice(0, 12) : null;
}
