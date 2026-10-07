import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Server-to-server request signature (scheme `v1`), used in both directions:
 * Player API → proxy (relay calls) and proxy → Player API (forwarded
 * callbacks). The Player API carries a byte-identical copy of this algorithm
 * in `backend/src/services/PaymentProxyClient.js`.
 *
 *   canonical = "v1\n" + METHOD + "\n" + REQUEST_TARGET + "\n" +
 *               CONTENT_TYPE + "\n" + TIMESTAMP + "\n" + NONCE + "\n" +
 *               hex(SHA-256(body))
 *   signature = "v1=" + hex(HMAC-SHA256(secret, canonical))
 *
 * REQUEST_TARGET is the path plus the raw query exactly as sent
 * (`/v1/providers/parscoin/payment/create`). CONTENT_TYPE is the lower-cased
 * media type without parameters, or "" when there is no body.
 */

export const SIGNATURE_HEADERS = {
  keyId: "x-wingo-key-id",
  timestamp: "x-wingo-timestamp",
  nonce: "x-wingo-nonce",
  signature: "x-wingo-signature",
} as const;

export const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
export const KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

export type SignInput = {
  method: string;
  target: string;
  contentType: string | undefined;
  timestamp: number;
  nonce: string;
  body: Buffer | string | undefined;
};

export function mediaType(contentType: string | undefined): string {
  return (contentType ?? "").split(";")[0]!.trim().toLowerCase();
}

export function sha256Hex(body: Buffer | string | undefined): string {
  return createHash("sha256")
    .update(body ?? "")
    .digest("hex");
}

export function canonicalString(input: SignInput): string {
  return [
    "v1",
    input.method.toUpperCase(),
    input.target,
    mediaType(input.contentType),
    String(input.timestamp),
    input.nonce,
    sha256Hex(input.body),
  ].join("\n");
}

export function sign(secret: string, input: SignInput): string {
  return "v1=" + createHmac("sha256", secret).update(canonicalString(input)).digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export function newNonce(): string {
  return randomBytes(24).toString("base64url");
}

/** Headers for a signed request. */
export function signedHeaders(
  key: { id: string; secret: string },
  input: Omit<SignInput, "timestamp" | "nonce"> & { timestamp?: number; nonce?: string },
): Record<string, string> {
  const timestamp = input.timestamp ?? Math.floor(Date.now() / 1000);
  const nonce = input.nonce ?? newNonce();
  return {
    [SIGNATURE_HEADERS.keyId]: key.id,
    [SIGNATURE_HEADERS.timestamp]: String(timestamp),
    [SIGNATURE_HEADERS.nonce]: nonce,
    [SIGNATURE_HEADERS.signature]: sign(key.secret, { ...input, timestamp, nonce }),
  };
}
