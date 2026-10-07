import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config/config.js";
import { ConfigError } from "../src/config/env.js";
import { CircuitBreaker } from "../src/core/circuitBreaker.js";
import { Encryptor } from "../src/core/crypto.js";
import { canonicalString, sign } from "../src/core/hmac.js";
import { HttpClient, UpstreamError } from "../src/core/httpClient.js";
import { ipMatcher } from "../src/core/ipList.js";
import { RateLimiter } from "../src/core/rateLimiter.js";
import { REDACTED, redact, redactHeaders, redactText, safeErrorText } from "../src/core/redact.js";
import { assertAllowedUrl, blockedReason, policyFor, safeLookup, type DestinationPolicy } from "../src/core/ssrf.js";
import { testEnv } from "./helpers.js";

const policy: DestinationPolicy = policyFor(new URL("https://api.parscoin.test"), { allowHttp: false, allowPrivateNetwork: false });

describe("request signature (v1)", () => {
  const input = {
    method: "post",
    target: "/v1/providers/parscoin/payment/verify",
    contentType: "application/json; charset=utf-8",
    timestamp: 1791370000,
    nonce: "n0nce-0123456789abcdef",
    body: '{"transaction_uuid":"3f2a9c1e-7b4d-4e8a-9f10-2c3d4e5f6a7b"}',
  };

  it("binds method, target, media type, time, nonce and body", () => {
    expect(canonicalString(input).split("\n")).toEqual([
      "v1",
      "POST",
      "/v1/providers/parscoin/payment/verify",
      "application/json",
      "1791370000",
      "n0nce-0123456789abcdef",
      "ecb3fa1ec1690c908cce8e0d9009bd37e8714b24017ef5935546a946e76375b9",
    ]);
    const base = sign("k".repeat(40), input);
    expect(base).toMatch(/^v1=[0-9a-f]{64}$/);
    expect(sign("k".repeat(40), { ...input, body: input.body.replace("3f2a", "3f2b") })).not.toBe(base);
    expect(sign("k".repeat(40), { ...input, target: "/v1/providers/parscoin/payment/create" })).not.toBe(base);
    expect(sign("k".repeat(40), { ...input, nonce: "other-0123456789abcdef" })).not.toBe(base);
    expect(sign("x".repeat(40), input)).not.toBe(base);
  });

  it("matches the fixed vector the Player API client is checked against", () => {
    expect(sign("vector-secret-0123456789-abcdefghijklmn", input)).toBe(
      "v1=579e7b32894de575af73e53fc43db09be98c90a321475ca74d2a7a1a81846d74",
    );
  });
});

describe("SSRF guard", () => {
  it("blocks loopback, private, link-local, metadata and mapped addresses", () => {
    for (const ip of [
      "127.0.0.1",
      "127.10.0.3",
      "0.0.0.0",
      "10.1.2.3",
      "172.16.0.9",
      "192.168.1.1",
      "100.64.0.1",
      "169.254.169.254",
      "100.100.100.200",
      "::1",
      "::",
      "fe80::1",
      "fd00:ec2::254",
      "::ffff:127.0.0.1",
      "::ffff:7f00:1",
      "::ffff:a9fe:a9fe",
      "64:ff9b::7f00:1",
      "2002:7f00:1::",
      "224.0.0.1",
      "255.255.255.255",
    ]) {
      expect(blockedReason(ip, false), ip).not.toBeNull();
    }
    expect(blockedReason("93.184.216.34", false)).toBeNull();
    expect(blockedReason("2606:4700::1111", false)).toBeNull();
    expect(blockedReason("10.1.2.3", true)).toBeNull();
    expect(blockedReason("127.0.0.1", true)).not.toBeNull();
    expect(blockedReason("169.254.169.254", true)).not.toBeNull();
  });

  it("only allows the configured host, port and scheme", () => {
    expect(() => assertAllowedUrl(new URL("https://api.parscoin.test/v1/x"), policy)).not.toThrow();
    for (const url of [
      "https://evil.example/v1/x",
      "https://api.parscoin.test.evil.example/",
      "https://api.parscoin.test:8443/",
      "http://api.parscoin.test/",
      "https://user:pw@api.parscoin.test/",
      "https://127.0.0.1/",
      "https://[::1]/",
      "https://169.254.169.254/latest/meta-data/",
      "file:///etc/passwd",
      "gopher://api.parscoin.test/",
    ]) {
      expect(() => assertAllowedUrl(new URL(url), policy), url).toThrow(/destination blocked/);
    }
  });

  it("checks the resolved address at connect time (DNS rebinding)", async () => {
    const lookup = (answers: string[]) =>
      new Promise<{ err: NodeJS.ErrnoException | null; address: unknown }>((resolve) => {
        const fn = safeLookup(policy, async () => answers.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })));
        fn("api.parscoin.test", { all: true }, (err, address) => resolve({ err, address }));
      });
    expect((await lookup(["93.184.216.34"])).err).toBeNull();
    expect((await lookup(["127.0.0.1"])).err?.message).toMatch(/blocked/);
    expect((await lookup(["93.184.216.34", "10.0.0.7"])).err?.message).toMatch(/blocked/);
    expect((await lookup(["::ffff:169.254.169.254"])).err?.message).toMatch(/blocked/);
    const other = await new Promise<NodeJS.ErrnoException | null>((resolve) =>
      safeLookup(policy, async () => [{ address: "93.184.216.34", family: 4 }])("evil.example", {}, (err) => resolve(err)),
    );
    expect(other?.message).toMatch(/not configured/);
  });

  it("refuses to connect when the configured host resolves to a private address", async () => {
    const client = new HttpClient(policy, { connectTimeoutMs: 500, resolver: async () => [{ address: "10.0.0.5", family: 4 }] });
    const err = await client
      .send({ url: new URL("https://api.parscoin.test/v1/x"), method: "POST", headers: {}, body: "{}", timeoutMs: 2000, maxResponseBytes: 1024 })
      .catch((e: unknown) => e);
    await client.close();
    expect(err).toBeInstanceOf(UpstreamError);
    expect((err as UpstreamError).kind).toBe("blocked");
  });

  it("refuses a URL outside the policy before any connection", async () => {
    const client = new HttpClient(policy, { connectTimeoutMs: 500 });
    const err = await client
      .send({ url: new URL("https://169.254.169.254/latest/meta-data/"), method: "GET", headers: {}, timeoutMs: 1000, maxResponseBytes: 1024 })
      .catch((e: unknown) => e);
    await client.close();
    expect((err as UpstreamError).kind).toBe("blocked");
  });
});

describe("secret redaction", () => {
  it("masks credentials by key and card numbers in text", () => {
    const out = redact({
      apiToken: "abc",
      headers: { authorization: "Bearer xyz", "x-api-token": "t", accept: "json" },
      nested: { merchantId: "M", card_number: "6037991234567890", note: "paid with 6037 9912 3456 7890" },
      password: "p",
      ok: 5,
    }) as Record<string, Record<string, unknown>>;
    expect(out.apiToken).toBe(REDACTED);
    expect(out.password).toBe(REDACTED);
    expect(out.headers!.authorization).toBe(REDACTED);
    expect(out.headers!["x-api-token"]).toBe(REDACTED);
    expect(out.headers!.accept).toBe("json");
    expect(out.nested!.merchantId).toBe(REDACTED);
    expect(out.nested!.card_number).toBe(REDACTED);
    expect(out.nested!.note).toBe("paid with 603799******7890");
    expect(out.ok).toBe(5);
  });

  it("redacts sensitive headers and bearer tokens in free text", () => {
    expect(redactHeaders({ "X-Sign-Hash": "abc", "X-Wingo-Signature": "v1=..", "Content-Type": "application/json" })).toEqual({
      "x-sign-hash": REDACTED,
      "x-wingo-signature": REDACTED,
      "content-type": "application/json",
    });
    expect(redactText("failed with Bearer abc.def-123")).toBe(`failed with Bearer ${REDACTED}`);
    expect(safeErrorText(new Error("card 4111111111111111 declined"))).toBe("Error: card 411111******1111 declined");
  });
});

describe("encryption at rest", () => {
  it("round-trips, binds the record id, and keeps old keys readable", () => {
    const oldKey = { id: "k0", key: Buffer.alloc(32, 7) };
    const newKey = { id: "k1", key: Buffer.alloc(32, 9) };
    const before = new Encryptor([oldKey]).encrypt("payload", "callback:a");
    const rotated = new Encryptor([newKey, oldKey]);
    expect(rotated.decrypt(before, "callback:a").toString()).toBe("payload");
    expect(rotated.encrypt("x", "aad").split(".")[1]).toBe("k1");
    expect(() => rotated.decrypt(before, "callback:b")).toThrow();
    expect(() => new Encryptor([newKey]).decrypt(before, "callback:a")).toThrow(/no data key/);
  });
});

describe("ip lists, circuit breaker, rate limiter", () => {
  it("matches IPs and CIDRs, including mapped IPv4", () => {
    const m = ipMatcher(["203.0.113.7", "198.51.100.0/24", "2001:db8::/48"]);
    expect(m.matches("203.0.113.7")).toBe(true);
    expect(m.matches("::ffff:198.51.100.20")).toBe(true);
    expect(m.matches("2001:db8::5")).toBe(true);
    expect(m.matches("203.0.113.8")).toBe(false);
    expect(m.matches(undefined)).toBe(false);
    expect(ipMatcher([]).matches("1.2.3.4")).toBe(true);
    expect(() => ipMatcher(["300.1.1.1"])).toThrow();
  });

  it("opens after consecutive failures and half-opens after the reset time", () => {
    let t = 0;
    const cb = new CircuitBreaker(2, 1000, () => t);
    expect(cb.tryAcquire()).toBe(true);
    cb.failure();
    expect(cb.tryAcquire()).toBe(true);
    cb.failure();
    expect(cb.current).toBe("open");
    expect(cb.tryAcquire()).toBe(false);
    t = 1000;
    expect(cb.tryAcquire()).toBe(true);
    expect(cb.tryAcquire()).toBe(false);
    cb.success();
    expect(cb.current).toBe("closed");
  });

  it("limits per key and refills", () => {
    let t = 0;
    const rl = new RateLimiter(60, 2, () => t);
    expect(rl.take("a")).toBe(0);
    expect(rl.take("a")).toBe(0);
    expect(rl.take("a")).toBeGreaterThan(0);
    expect(rl.take("b")).toBe(0);
    t = 1000;
    expect(rl.peek("a")).toBe(0);
    expect(rl.take("a")).toBe(0);
  });
});

describe("configuration", () => {
  const problems = (over: Record<string, string>) => {
    try {
      loadConfig(testEnv(over));
      return [];
    } catch (err) {
      return (err as ConfigError).problems;
    }
  };

  it("accepts the test configuration", () => {
    const { registry } = loadConfig(testEnv());
    expect(registry.get("parscoin")?.operations.map((o) => o.name)).toEqual(["payment.create", "payment.verify"]);
  });

  it("rejects destinations and secrets that are not explicitly safe", () => {
    expect(problems({ PARSCOIN_ALLOWED_HOSTS: "other.test" })).toContain("PARSCOIN_BASE_URL host is not listed in PARSCOIN_ALLOWED_HOSTS");
    expect(problems({ PARSCOIN_ALLOWED_HOSTS: "" })[0]).toMatch(/PARSCOIN_ALLOWED_HOSTS is required/);
    expect(problems({ PARSCOIN_BASE_URL: "https://api.parscoin.test/v1?x=1" }).join()).toMatch(/PARSCOIN_BASE_URL/);
    expect(problems({ INTERNAL_HMAC_KEYS: "short:abc" }).join()).toMatch(/at least 32/);
    expect(problems({ DATA_ENCRYPTION_KEYS: "k1:abcd" }).join()).toMatch(/DATA_ENCRYPTION_KEYS/);
    expect(problems({ PARSCOIN_MERCHANT_ID: "short" }).join()).toMatch(/PARSCOIN_MERCHANT_ID/);
  });

  it("requires https and a source allowlist in production", () => {
    const prod = problems({
      APP_ENV: "production",
      MAIN_BACKEND_BASE_URL: "http://api.backend.test",
      PARSCOIN_BASE_URL: "http://api.parscoin.test",
    }).join("\n");
    expect(prod).toMatch(/MAIN_BACKEND_BASE_URL must use https/);
    expect(prod).toMatch(/PARSCOIN_BASE_URL must use https/);
    expect(prod).toMatch(/INTERNAL_ALLOWED_IPS is required in production/);
  });

  it("never prints secret values in problems", () => {
    const text = problems({ PARSCOIN_API_TOKEN: "tiny-secret" }).join("\n");
    expect(text).toMatch(/PARSCOIN_API_TOKEN/);
    expect(text).not.toMatch(/tiny-secret/);
  });

  it("leaves a provider out unless it is switched on", () => {
    const { registry } = loadConfig(testEnv({ PARSCOIN_ENABLED: "false" }));
    expect(registry.get("parscoin")).toBeUndefined();
    expect(registry.isDisabled("parscoin")).toBe(true);
  });
});
