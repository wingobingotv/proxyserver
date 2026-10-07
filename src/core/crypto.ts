import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * AES-256-GCM envelope for callback payloads at rest:
 *   "v1." + keyId + "." + base64url(iv) + "." + base64url(tag) + "." + base64url(ciphertext)
 * The first configured key encrypts; every configured key can decrypt, so
 * keys rotate by putting the new one first and keeping the old one until
 * stored records have aged out.
 */
export type DataKey = { id: string; key: Buffer };

export class Encryptor {
  private readonly active: DataKey;
  private readonly byId: Map<string, Buffer>;

  constructor(keys: DataKey[]) {
    const first = keys[0];
    if (!first) throw new Error("at least one data encryption key is required");
    this.active = first;
    this.byId = new Map(keys.map((k) => [k.id, k.key]));
  }

  get activeKeyId(): string {
    return this.active.id;
  }

  encrypt(plain: Buffer | string, aad: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.active.key, iv);
    cipher.setAAD(Buffer.from(aad, "utf8"));
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag = cipher.getAuthTag();
    return ["v1", this.active.id, iv.toString("base64url"), tag.toString("base64url"), ct.toString("base64url")].join(".");
  }

  decrypt(envelope: string, aad: string): Buffer {
    const parts = envelope.split(".");
    if (parts.length !== 5 || parts[0] !== "v1") throw new Error("unknown envelope format");
    const [, keyId, ivB64, tagB64, ctB64] = parts as [string, string, string, string, string];
    const key = this.byId.get(keyId);
    if (!key) throw new Error(`no data key "${keyId}" configured`);
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64url"));
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
    return Buffer.concat([decipher.update(Buffer.from(ctB64, "base64url")), decipher.final()]);
  }
}
