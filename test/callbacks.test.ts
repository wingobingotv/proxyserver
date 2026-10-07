import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { safeEqual, sign } from "../src/core/hmac.js";
import { parscoinWebhookSignature } from "../src/providers/parscoin/index.js";
import { BACKEND_SIGNING, MERCHANT_ID, confirmation, harness, type Harness } from "./helpers.js";

type Seen = { headers: Record<string, string>; body: string };
const ok = (data: unknown = { status: "OK" }) => ({
  statusCode: 200,
  data: JSON.stringify(data),
  responseOptions: { headers: { "content-type": "application/json" } },
});

let h: Harness;
beforeEach(async () => {
  h = await harness();
});
afterEach(async () => {
  await h.teardown();
});

function backendAnswers(answer: () => { statusCode: number; data: string; responseOptions?: { headers: Record<string, string> } }, times = 1) {
  const seen: Seen[] = [];
  h.backend
    .intercept({ path: "/webhooks/ir-card", method: "POST" })
    .reply((opts) => {
      seen.push({ headers: opts.headers as Record<string, string>, body: String(opts.body ?? "") });
      return answer();
    })
    .times(times);
  return seen;
}

const backendDown = (times = 1) =>
  h.backend
    .intercept({ path: "/webhooks/ir-card", method: "POST" })
    .replyWithError(Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }))
    .times(times);

const only = () => {
  const [rec, ...rest] = h.store.listCallbacks({ limit: 10 });
  expect(rest).toHaveLength(0);
  return rec!;
};

describe("incoming callback relay", () => {
  it("validates, stores and forwards a correctly signed callback, returning the backend's answer", async () => {
    const seen = backendAnswers(() => ok({ status: "OK" }));
    const body = confirmation();
    const res = await h.callback(body);

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "OK" });
    expect(seen).toHaveLength(1);
    const fwd = seen[0]!;
    // Byte-identical body and the provider's own signature, so the backend still verifies it itself.
    expect(fwd.body).toBe(JSON.stringify(body));
    expect(fwd.headers["x-sign-hash"]).toBe(parscoinWebhookSignature(MERCHANT_ID, body.uuid, body.event_timestamp));
    expect(fwd.headers["content-type"]).toBe("application/json");
    // And the proxy's signature over the forwarded request.
    const expected = sign(BACKEND_SIGNING.secret, {
      method: "POST",
      target: "/webhooks/ir-card",
      contentType: "application/json",
      timestamp: Number(fwd.headers["x-wingo-timestamp"]),
      nonce: fwd.headers["x-wingo-nonce"]!,
      body: fwd.body,
    });
    expect(fwd.headers["x-wingo-key-id"]).toBe(BACKEND_SIGNING.id);
    expect(safeEqual(fwd.headers["x-wingo-signature"]!, expected)).toBe(true);

    const rec = only();
    expect(rec.status).toBe("delivered");
    expect(rec.attempts).toBe(1);
    expect(rec.lastHttpStatus).toBe(200);
    expect(rec.reference).toBe(body.uuid);
    expect(rec.payloadHash).toMatch(/^[0-9a-f]{64}$/);
    expect(rec.destination).toBe("https://api.backend.test/webhooks/ir-card");
  });

  it("refuses a callback with an invalid signature and stores nothing", async () => {
    const seen = backendAnswers(() => ok());
    const res = await h.callback(confirmation(), { signature: "0".repeat(128) });
    expect(res.statusCode).toBe(401);
    expect(seen).toHaveLength(0);
    expect(h.store.listCallbacks({ limit: 10 })).toHaveLength(0);
    expect(await h.metrics.registry.getSingleMetricAsString("wbproxy_callbacks_received_total")).toMatch(/result="rejected_bad_signature"} 1/);
  });

  it("refuses a callback signed for different fields (tampered amount keeps the old signature)", async () => {
    // The ParsCoin signature covers uuid + event_timestamp only, so a changed uuid must fail.
    const sigFor = parscoinWebhookSignature(MERCHANT_ID, "other-uuid", 1791370000);
    const res = await h.callback(confirmation(), { signature: sigFor });
    expect(res.statusCode).toBe(401);
  });

  it("does not forward a duplicate again and replays the stored answer", async () => {
    const seen = backendAnswers(() => ok({ status: "OK", credited: true }));
    const first = await h.callback(confirmation());
    const second = await h.callback(confirmation());
    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
    expect(second.json()).toEqual({ status: "OK", credited: true });
    expect(seen).toHaveLength(1);
    expect(only().duplicateCount).toBe(1);
  });

  it("refuses a duplicate event identity that carries a different body", async () => {
    backendAnswers(() => ok());
    await h.callback(confirmation());
    const res = await h.callback(confirmation({ amount: 99_000_000 }));
    expect(res.statusCode).toBe(409);
    expect(only().status).toBe("delivered");
  });

  it("forwards concurrent copies of the same callback once", async () => {
    const seen = backendAnswers(() => ok(), 5);
    const results = await Promise.all([h.callback(confirmation()), h.callback(confirmation()), h.callback(confirmation())]);
    expect(seen).toHaveLength(1);
    for (const r of results) expect([200, 202]).toContain(r.statusCode);
    expect(only().status).toBe("delivered");
  });

  it("treats different events for the same transaction as separate callbacks", async () => {
    const seen = backendAnswers(() => ok(), 2);
    await h.callback(confirmation({ event: "transaction_confirmation", event_timestamp: 1791370000 }));
    await h.callback(confirmation({ event: "transaction_failure", event_timestamp: 1791370100 }));
    expect(seen).toHaveLength(2);
    expect(h.store.listCallbacks({ limit: 10 })).toHaveLength(2);
  });

  it("keeps the callback when the backend is unavailable and acknowledges it as queued", async () => {
    backendDown();
    const res = await h.callback(confirmation());
    expect(res.statusCode).toBe(202);
    expect(res.json()).toMatchObject({ status: "accepted" });
    const rec = only();
    expect(rec.status).toBe("retry_pending");
    expect(rec.attempts).toBe(1);
    expect(rec.lastError).toMatch(/backend unreachable: connect \(ECONNREFUSED\)/);
    expect(rec.nextAttemptAt).toBeGreaterThan(h.clock.t);
  });

  it("asks the provider to retry instead, when ack-when-queued is off", async () => {
    await h.teardown();
    h = await harness({ PARSCOIN_CALLBACK_ACK_WHEN_QUEUED: "false" });
    backendDown();
    const res = await h.callback(confirmation());
    expect(res.statusCode).toBe(503);
    expect(res.headers["retry-after"]).toBe("30");
  });

  it("delivers a queued callback on a later retry", async () => {
    backendDown();
    await h.callback(confirmation());
    const seen = backendAnswers(() => ok());
    await h.worker.tick();
    expect(seen).toHaveLength(0); // not due yet

    h.clock.t = only().nextAttemptAt! + 1;
    await h.worker.tick();
    expect(seen).toHaveLength(1);
    expect(seen[0]!.headers["x-wingo-callback-attempt"]).toBe("2");
    const rec = only();
    expect(rec.status).toBe("delivered");
    expect(rec.attempts).toBe(2);
  });

  it("marks the callback failed after the last attempt, and delivers it again when the provider retries", async () => {
    backendDown(3);
    await h.callback(confirmation());
    for (let i = 0; i < 2; i += 1) {
      h.clock.t = only().nextAttemptAt! + 1;
      await h.worker.tick();
    }
    let rec = only();
    expect(rec.status).toBe("failed");
    expect(rec.failureKind).toBe("exhausted");
    expect(rec.attempts).toBe(3);
    expect(rec.nextAttemptAt).toBeNull();
    expect(await h.metrics.registry.getSingleMetricAsString("wbproxy_callback_deliveries_total")).toMatch(/outcome="exhausted"} 1/);

    const seen = backendAnswers(() => ok());
    const again = await h.callback(confirmation());
    expect(again.statusCode).toBe(200);
    expect(seen).toHaveLength(1);
    rec = only();
    expect(rec.status).toBe("delivered");
  });

  it("stops retrying when the backend refuses the callback outright", async () => {
    const seen = backendAnswers(() => ({
      statusCode: 422,
      data: JSON.stringify({ error: "unknown transaction" }),
      responseOptions: { headers: { "content-type": "application/json" } },
    }));
    const res = await h.callback(confirmation());
    expect(res.statusCode).toBe(422);
    expect(seen).toHaveLength(1);
    const rec = only();
    expect(rec.status).toBe("failed");
    expect(rec.failureKind).toBe("rejected");
    h.clock.t += 3_600_000;
    await h.worker.tick();
    expect(seen).toHaveLength(1);
  });

  it("keeps retrying while the backend answers 401/503 (configuration not ready)", async () => {
    backendAnswers(() => ({ statusCode: 503, data: JSON.stringify({ error: "gateway not configured" }), responseOptions: { headers: { "content-type": "application/json" } } }));
    const res = await h.callback(confirmation());
    expect(res.statusCode).toBe(202);
    expect(only().status).toBe("retry_pending");
  });

  it("restarts a delivery whose process died mid-flight once its lock expires", async () => {
    backendDown();
    await h.callback(confirmation());
    const rec = only();
    // Simulate a crash while forwarding: claimed, never finished.
    expect(h.store.claim(rec.id, h.clock.t, h.clock.t + 1_000)).toBe(true);
    expect(only().status).toBe("forwarding");
    const seen = backendAnswers(() => ok());
    h.clock.t += 1_001;
    await h.worker.tick();
    expect(seen).toHaveLength(1);
    expect(only().status).toBe("delivered");
  });

  it("propagates one request id from the provider-facing answer to the backend and the logs", async () => {
    const seen = backendAnswers(() => ok());
    const res = await h.callback(confirmation(), { headers: { "x-wingo-request-id": "provider-chosen-id" } });
    const rid = res.headers["x-wingo-request-id"] as string;
    expect(rid).toMatch(/^[A-Za-z0-9._:-]{8,128}$/);
    expect(rid).not.toBe("provider-chosen-id");
    expect(seen[0]!.headers["x-wingo-request-id"]).toBe(rid);
    expect(only().requestId).toBe(rid);
    expect(h.logs.some((l) => (JSON.parse(l) as { requestId?: string }).requestId === rid)).toBe(true);
  });

  it("stores the payload encrypted and never logs it", async () => {
    backendAnswers(() => ok());
    const body = confirmation();
    await h.callback(body);
    const rec = only();
    expect(rec.payloadEnc).toMatch(/^v1\.k1\./);
    expect(rec.payloadEnc).not.toContain(body.uuid);
    const all = h.logs.join("\n");
    expect(all).not.toContain(body.card_number);
    expect(all).not.toContain(MERCHANT_ID);
    expect(all).not.toMatch(/[0-9a-f]{128}/);
  });
});

describe("callback endpoint hardening", () => {
  it("answers 404 for an unknown slug, including the provider's real name when a neutral slug is used", async () => {
    expect((await h.callback(confirmation(), { slug: "parscoin" })).statusCode).toBe(404);
    expect((await h.callback(confirmation(), { slug: "anything" })).statusCode).toBe(404);
  });

  it("enforces the provider IP allowlist when one is configured", async () => {
    await h.teardown();
    h = await harness({ PARSCOIN_CALLBACK_ALLOWED_IPS: "203.0.113.0/24" });
    const seen = backendAnswers(() => ok());
    expect((await h.callback(confirmation(), { remoteAddress: "198.51.100.9" })).statusCode).toBe(403);
    expect((await h.callback(confirmation(), { remoteAddress: "203.0.113.20" })).statusCode).toBe(200);
    expect(seen).toHaveLength(1);
  });

  it("rejects wrong methods, media types and oversized bodies", async () => {
    const get = await h.app.inject({ method: "GET", url: "/callback/gw-a" });
    expect(get.statusCode).toBe(405);
    const form = await h.app.inject({ method: "POST", url: "/callback/gw-a", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: "a=1" });
    expect(form.statusCode).toBe(415);
    const big = await h.callback({ ...confirmation(), padding: "x".repeat(70_000) });
    expect(big.statusCode).toBe(413);
  });

  it("rate-limits per source without dropping silently", async () => {
    await h.teardown();
    h = await harness({ CALLBACK_RATE_LIMIT_PER_IP_PER_MINUTE: "10" });
    backendAnswers(() => ok(), 20);
    const results = [];
    for (let i = 0; i < 25; i += 1) results.push(await h.callback(confirmation({ event_timestamp: 1791370000 + i })));
    const limited = results.filter((r) => r.statusCode === 429);
    expect(limited.length).toBeGreaterThan(0);
    for (const r of limited) expect(r.headers["retry-after"]).toBeDefined();
    expect(await h.metrics.registry.getSingleMetricAsString("wbproxy_callbacks_received_total")).toMatch(/result="rate_limited"/);
  });
});
