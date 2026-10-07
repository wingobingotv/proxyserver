import type { InternalKey, Scope } from "../config/config.js";
import { headerValue } from "../core/headers.js";
import { NONCE_PATTERN, SIGNATURE_HEADERS, safeEqual, sign } from "../core/hmac.js";
import type { IpMatcher } from "../core/ipList.js";
import type { Store } from "../store/store.js";

/**
 * Authentication of server-to-server calls from the Player API (relay and
 * admin endpoints). A request must carry a known key id, a timestamp inside
 * the allowed skew, a nonce never seen before, and a valid HMAC over the
 * canonical request (method, path + query, content type, timestamp, nonce,
 * body hash). Several keys may be active at once, so a key is rotated by
 * adding the new id, switching the caller, then removing the old id.
 */

export type AuthFailureReason =
  | "forbidden_source"
  | "missing_headers"
  | "unknown_key"
  | "bad_timestamp"
  | "expired_timestamp"
  | "bad_nonce"
  | "bad_signature"
  | "insufficient_scope"
  | "replayed_nonce";

export type AuthResult = { ok: true; key: InternalKey } | { ok: false; reason: AuthFailureReason };

export type AuthRequest = {
  method: string;
  /** Path + raw query exactly as received. */
  target: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  ip: string | undefined;
};

export class InternalAuthenticator {
  private readonly keys: Map<string, InternalKey>;

  constructor(
    keys: readonly InternalKey[],
    private readonly store: Store,
    private readonly options: { maxSkewSeconds: number; allowedIps: IpMatcher },
    private readonly now: () => number = Date.now,
  ) {
    this.keys = new Map(keys.map((k) => [k.id, k]));
  }

  verify(req: AuthRequest, scope: Scope): AuthResult {
    if (!this.options.allowedIps.matches(req.ip)) return { ok: false, reason: "forbidden_source" };

    const keyId = headerValue(req.headers, SIGNATURE_HEADERS.keyId);
    const timestampText = headerValue(req.headers, SIGNATURE_HEADERS.timestamp);
    const nonce = headerValue(req.headers, SIGNATURE_HEADERS.nonce);
    const signature = headerValue(req.headers, SIGNATURE_HEADERS.signature);
    if (!keyId || !timestampText || !nonce || !signature) return { ok: false, reason: "missing_headers" };

    const key = this.keys.get(keyId);
    if (!key) return { ok: false, reason: "unknown_key" };

    if (!/^\d{9,11}$/.test(timestampText)) return { ok: false, reason: "bad_timestamp" };
    const timestamp = Number(timestampText);
    const nowSeconds = Math.floor(this.now() / 1000);
    if (Math.abs(nowSeconds - timestamp) > this.options.maxSkewSeconds) return { ok: false, reason: "expired_timestamp" };

    if (!NONCE_PATTERN.test(nonce)) return { ok: false, reason: "bad_nonce" };

    const expected = sign(key.secret, {
      method: req.method,
      target: req.target,
      contentType: headerValue(req.headers, "content-type"),
      timestamp,
      nonce,
      body: req.body,
    });
    if (!safeEqual(expected, signature.trim())) return { ok: false, reason: "bad_signature" };

    if (!key.scopes.has(scope)) return { ok: false, reason: "insufficient_scope" };

    // Only a correctly signed request may consume a nonce, so forged traffic cannot fill the table.
    const expiresAt = (timestamp + this.options.maxSkewSeconds) * 1000 + 60_000;
    if (!this.store.rememberNonce(key.id, nonce, expiresAt)) return { ok: false, reason: "replayed_nonce" };

    return { ok: true, key };
  }
}
