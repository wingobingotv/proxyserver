import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ADMIN_KEY, API_TOKEN, MERCHANT_ID, RELAY_KEY, harness, type Harness } from "./helpers.js";

const CREATE = "/v1/providers/parscoin/payment/create";
const VERIFY = "/v1/providers/parscoin/payment/verify";
const UUID = "3f2a9c1e-7b4d-4e8a-9f10-2c3d4e5f6a7b";

const createBody = {
  total_amount: 12_500_000,
  description: "Wallet top-up",
  client_ip: "198.51.100.23",
  userid: "u-1001",
  redirect_url: "https://wingobingo.test/payment/return?ref=42",
};

type Captured = { path: string; method: string; headers: Record<string, string>; body: string };
const json = (data: unknown) => ({ statusCode: 200, data: JSON.stringify(data), responseOptions: { headers: { "content-type": "application/json" } } });

let h: Harness;
beforeEach(async () => {
  h = await harness();
});
afterEach(async () => {
  await h.teardown();
});

function capture(path: string, answer: (c: Captured) => { statusCode: number; data: string; responseOptions?: { headers: Record<string, string> } }, times = 1) {
  const seen: Captured[] = [];
  h.parscoin
    .intercept({ path, method: "POST" })
    .reply((opts) => {
      const c: Captured = {
        path: opts.path,
        method: opts.method,
        headers: opts.headers as Record<string, string>,
        body: String(opts.body ?? ""),
      };
      seen.push(c);
      return answer(c);
    })
    .times(times);
  return seen;
}

describe("internal relay — authentication", () => {
  it("relays a correctly signed create to the configured ParsCoin endpoint", async () => {
    const seen = capture("/v1/transactions/createNewTransaction", () => json({ uuid: UUID, payment_url: "https://pay.parscoin.test/t/abc" }));
    const res = await h.relay(CREATE, createBody, { headers: { "x-wingo-request-id": "req-create-0001" } });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ uuid: UUID, payment_url: "https://pay.parscoin.test/t/abc" });
    expect(res.headers["x-wingo-request-id"]).toBe("req-create-0001");
    expect(res.headers["x-wingo-upstream-status"]).toBe("200");
    expect(res.headers["x-wingo-upstream-attempts"]).toBe("1");
    expect(seen).toHaveLength(1);
    expect(seen[0]!.headers["x-api-token"]).toBe(API_TOKEN);
    expect(seen[0]!.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(seen[0]!.body)).toEqual(createBody);
    // Nothing of the caller's own authentication reaches the provider.
    expect(Object.keys(seen[0]!.headers).filter((k) => k.startsWith("x-wingo-"))).toEqual([]);
  });

  it("refuses a request whose body changed after signing", async () => {
    const res = await h.relay(CREATE, createBody, { tamper: (raw) => raw.replace("12500000", "99") });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ error: "unauthorized" });
    expect(await h.metrics.registry.getSingleMetricAsString("wbproxy_auth_failures_total")).toMatch(/reason="bad_signature"} 1/);
  });

  it("refuses a request signed with an unknown secret", async () => {
    const res = await h.relay(CREATE, createBody, { key: { id: RELAY_KEY.id, secret: "not-the-secret-0123456789-abcdefghijk" } });
    expect(res.statusCode).toBe(401);
  });

  it("refuses an expired timestamp", async () => {
    const res = await h.relay(CREATE, createBody, { timestamp: Math.floor(h.clock.t / 1000) - 301 });
    expect(res.statusCode).toBe(401);
    expect(await h.metrics.registry.getSingleMetricAsString("wbproxy_auth_failures_total")).toMatch(/reason="expired_timestamp"} 1/);
  });

  it("refuses a reused nonce", async () => {
    capture("/v1/transactions/createNewTransaction", () => json({ uuid: UUID }));
    const nonce = "fixed-nonce-0123456789abcdef";
    expect((await h.relay(CREATE, createBody, { nonce })).statusCode).toBe(200);
    const replay = await h.relay(CREATE, createBody, { nonce });
    expect(replay.statusCode).toBe(401);
    expect(await h.metrics.registry.getSingleMetricAsString("wbproxy_auth_failures_total")).toMatch(/reason="replayed_nonce"} 1/);
  });

  it("refuses an unsigned request and a key without the relay scope", async () => {
    const unsigned = await h.app.inject({ method: "POST", url: CREATE, headers: { "content-type": "application/json" }, payload: JSON.stringify(createBody) });
    expect(unsigned.statusCode).toBe(401);
    const adminOnly = await h.relay(CREATE, createBody, { key: ADMIN_KEY });
    expect(adminOnly.statusCode).toBe(401);
  });

  it("refuses callers outside INTERNAL_ALLOWED_IPS before checking anything else", async () => {
    await h.teardown();
    h = await harness({ INTERNAL_ALLOWED_IPS: "203.0.113.10" });
    const res = await h.relay(CREATE, createBody);
    expect(res.statusCode).toBe(403);
  });

  it("throttles a source that keeps failing authentication", async () => {
    await h.teardown();
    h = await harness({ INTERNAL_AUTH_FAILURES_PER_MINUTE: "2" });
    for (let i = 0; i < 2; i += 1) expect((await h.relay(CREATE, createBody, { tamper: (r) => `${r} ` })).statusCode).toBe(401);
    const blocked = await h.relay(CREATE, createBody);
    expect(blocked.statusCode).toBe(429);
    expect(blocked.headers["retry-after"]).toBeDefined();
  });
});

describe("internal relay — routing is explicit", () => {
  it("rejects an unknown provider", async () => {
    const res = await h.relay("/v1/providers/stripe/payment/create", createBody);
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe("unknown_provider");
  });

  it("rejects an operation the provider does not have, and the wrong method", async () => {
    const res = await h.relay("/v1/providers/parscoin/payment/refund", { transaction_uuid: UUID });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe("unknown_operation");
    const get = await h.relay(CREATE, undefined, { method: "GET" });
    expect(get.statusCode).toBe(405);
  });

  it("has no generic URL relay: url parameters, absolute targets and smuggled fields go nowhere", async () => {
    const generic = await h.relay("/proxy?url=https%3A%2F%2Fevil.example%2F", { url: "https://evil.example" });
    expect(generic.statusCode).toBe(404);
    const query = await h.relay(`${CREATE}?url=http%3A%2F%2F169.254.169.254%2F`, createBody);
    expect(query.statusCode).toBe(400);
    expect(query.json().error).toBe("query_not_allowed");
    const field = await h.relay(CREATE, { ...createBody, url: "http://169.254.169.254/latest/meta-data/" });
    expect(field.statusCode).toBe(400);
    expect(field.json().message).toMatch(/unexpected field "url"/);
    const seen = capture("/v1/transactions/verifyTransaction", () => json({ uuid: UUID }));
    const hostHeader = await h.relay(VERIFY, { transaction_uuid: UUID }, { headers: { host: "169.254.169.254", "x-forwarded-host": "evil.example" } });
    // Host headers never select a destination: MockAgent only answers for the ParsCoin origin.
    expect(hostHeader.statusCode).toBe(200);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.headers.host).toBeUndefined();
  });

  it("validates the body for the operation", async () => {
    expect((await h.relay(VERIFY, { transaction_uuid: "../../admin" })).statusCode).toBe(400);
    expect((await h.relay(CREATE, { ...createBody, total_amount: -5 })).statusCode).toBe(400);
    expect((await h.relay(CREATE, { ...createBody, redirect_url: "javascript:alert(1)" })).statusCode).toBe(400);
    expect((await h.relay(CREATE, "not json")).statusCode).toBe(400);
    expect((await h.relay(CREATE, createBody, { contentType: "text/plain" })).statusCode).toBe(415);
  });

  it("refuses an oversized body", async () => {
    const res = await h.relay(CREATE, { ...createBody, description: "x".repeat(20_000) });
    expect(res.statusCode).toBe(413);
  });

  it("returns 503 for a provider that is configured off", async () => {
    await h.teardown();
    h = await harness({ PARSCOIN_ENABLED: "false" });
    const res = await h.relay(CREATE, createBody);
    expect(res.statusCode).toBe(503);
    expect(res.json().error).toBe("provider_disabled");
  });
});

describe("internal relay — upstream behaviour", () => {
  it("maps an upstream timeout to 504 and never retries a create after it was sent", async () => {
    await h.teardown();
    h = await harness({ PARSCOIN_TIMEOUT_MS: "1000", PARSCOIN_DEADLINE_MS: "4000" });
    let calls = 0;
    h.parscoin
      .intercept({ path: "/v1/transactions/createNewTransaction", method: "POST" })
      .reply(() => {
        calls += 1;
        return json({ uuid: UUID });
      })
      .delay(2_000)
      .persist();
    const res = await h.relay(CREATE, createBody);
    expect(res.statusCode).toBe(504);
    expect(res.json().error).toBe("upstream_timeout");
    expect(calls).toBe(1);
  });

  it("retries a verify that timed out, within the deadline", async () => {
    await h.teardown();
    h = await harness({ PARSCOIN_TIMEOUT_MS: "1000", PARSCOIN_DEADLINE_MS: "4000" });
    h.parscoin.intercept({ path: "/v1/transactions/verifyTransaction", method: "POST" }).reply(200, "{}").delay(2_000);
    capture("/v1/transactions/verifyTransaction", () => json({ uuid: UUID, transaction_status: "completed" }));
    const res = await h.relay(VERIFY, { transaction_uuid: UUID });
    expect(res.statusCode).toBe(200);
    expect(res.headers["x-wingo-upstream-attempts"]).toBe("2");
  });

  it("maps a non-JSON success answer to 502 malformed", async () => {
    h.parscoin
      .intercept({ path: "/v1/transactions/verifyTransaction", method: "POST" })
      .reply(200, "<html>maintenance</html>", { headers: { "content-type": "text/html" } });
    const res = await h.relay(VERIFY, { transaction_uuid: UUID });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("upstream_malformed_response");
  });

  it("passes a provider 4xx through unchanged and does not retry it", async () => {
    const seen = capture(
      "/v1/transactions/createNewTransaction",
      () => ({ statusCode: 422, data: JSON.stringify({ message: "amount below minimum" }), responseOptions: { headers: { "content-type": "application/json" } } }),
      2,
    );
    const res = await h.relay(CREATE, createBody);
    expect(res.statusCode).toBe(422);
    expect(res.json()).toEqual({ message: "amount below minimum" });
    expect(res.headers["x-wingo-upstream-status"]).toBe("422");
    expect(seen).toHaveLength(1);
  });

  it("passes a provider 5xx through for create, without retrying the payment creation", async () => {
    const seen = capture(
      "/v1/transactions/createNewTransaction",
      () => ({ statusCode: 500, data: JSON.stringify({ message: "internal" }), responseOptions: { headers: { "content-type": "application/json" } } }),
      3,
    );
    const res = await h.relay(CREATE, createBody);
    expect(res.statusCode).toBe(500);
    expect(seen).toHaveLength(1);
  });

  it("retries a verify on 503 and returns the successful answer", async () => {
    let n = 0;
    capture(
      "/v1/transactions/verifyTransaction",
      () => {
        n += 1;
        return n < 3
          ? { statusCode: 503, data: JSON.stringify({ message: "busy" }), responseOptions: { headers: { "content-type": "application/json" } } }
          : json({ uuid: UUID, transaction_status: "completed" });
      },
      3,
    );
    const res = await h.relay(VERIFY, { transaction_uuid: UUID });
    expect(res.statusCode).toBe(200);
    expect(res.headers["x-wingo-upstream-attempts"]).toBe("3");
    expect(await h.metrics.registry.getSingleMetricAsString("wbproxy_outbound_retries_total")).toMatch(/operation="payment.verify"} 2/);
  });

  it("retries a create only when the connection was never made", async () => {
    h.parscoin
      .intercept({ path: "/v1/transactions/createNewTransaction", method: "POST" })
      .replyWithError(Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }));
    const seen = capture("/v1/transactions/createNewTransaction", () => json({ uuid: UUID }));
    const res = await h.relay(CREATE, createBody);
    expect(res.statusCode).toBe(200);
    expect(seen).toHaveLength(1);
    expect(res.headers["x-wingo-upstream-attempts"]).toBe("2");
  });

  it("does not retry a create whose connection broke after sending", async () => {
    h.parscoin
      .intercept({ path: "/v1/transactions/createNewTransaction", method: "POST" })
      .replyWithError(Object.assign(new Error("other side closed"), { code: "UND_ERR_SOCKET" }));
    const seen = capture("/v1/transactions/createNewTransaction", () => json({ uuid: UUID }));
    const res = await h.relay(CREATE, createBody);
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("upstream_unreachable");
    expect(seen).toHaveLength(0);
  });

  it("never follows a redirect", async () => {
    h.parscoin
      .intercept({ path: "/v1/transactions/verifyTransaction", method: "POST" })
      .reply(302, "", { headers: { location: "http://169.254.169.254/latest/meta-data/" } });
    const res = await h.relay(VERIFY, { transaction_uuid: UUID });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("upstream_redirect_blocked");
  });

  it("opens the circuit after repeated provider failures", async () => {
    await h.teardown();
    h = await harness({ PARSCOIN_CIRCUIT_FAILURE_THRESHOLD: "2", PARSCOIN_VERIFY_RETRIES: "0" });
    h.parscoin
      .intercept({ path: "/v1/transactions/verifyTransaction", method: "POST" })
      .reply(500, JSON.stringify({ message: "down" }), { headers: { "content-type": "application/json" } })
      .times(2);
    expect((await h.relay(VERIFY, { transaction_uuid: UUID })).statusCode).toBe(500);
    expect((await h.relay(VERIFY, { transaction_uuid: UUID })).statusCode).toBe(500);
    const open = await h.relay(VERIFY, { transaction_uuid: UUID });
    expect(open.statusCode).toBe(503);
    expect(open.json().error).toBe("circuit_open");
    expect(open.headers["retry-after"]).toBeDefined();
  });

  it("caps the provider response size", async () => {
    await h.teardown();
    h = await harness({ PARSCOIN_MAX_RESPONSE_BYTES: "1024" });
    h.parscoin
      .intercept({ path: "/v1/transactions/verifyTransaction", method: "POST" })
      .reply(200, JSON.stringify({ blob: "x".repeat(5_000) }), { headers: { "content-type": "application/json" } });
    const res = await h.relay(VERIFY, { transaction_uuid: UUID });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("upstream_response_too_large");
  });
});

describe("observability", () => {
  it("propagates the caller's request id into logs and the response", async () => {
    capture("/v1/transactions/verifyTransaction", () => json({ uuid: UUID }));
    const res = await h.relay(VERIFY, { transaction_uuid: UUID }, { headers: { "x-wingo-request-id": "req-trace-0042" } });
    expect(res.headers["x-wingo-request-id"]).toBe("req-trace-0042");
    const lines = h.logs.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.requestId === "req-trace-0042");
    expect(lines.length).toBeGreaterThan(0);
  });

  it("does not trust a request id from an unauthenticated caller", async () => {
    const res = await h.app.inject({ method: "GET", url: "/healthz", headers: { "x-wingo-request-id": "attacker-chosen-id" } });
    expect(res.headers["x-wingo-request-id"]).not.toBe("attacker-chosen-id");
    expect(res.headers["x-wingo-request-id"]).toMatch(/^[A-Za-z0-9._:-]{8,128}$/);
  });

  it("never writes credentials, signatures or card numbers to the log", async () => {
    capture("/v1/transactions/verifyTransaction", () =>
      json({ uuid: UUID, card_number: "6037991234567890", transaction_status: "completed" }),
    );
    await h.relay(VERIFY, { transaction_uuid: UUID });
    await h.relay(CREATE, createBody, { tamper: (r) => `${r} ` });
    const all = h.logs.join("\n");
    expect(all.length).toBeGreaterThan(0);
    for (const secret of [API_TOKEN, MERCHANT_ID, RELAY_KEY.secret, "6037991234567890"]) expect(all).not.toContain(secret);
    expect(all).not.toMatch(/v1=[0-9a-f]{64}/);
  });
});
