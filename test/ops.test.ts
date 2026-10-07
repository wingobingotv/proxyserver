import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ADMIN_KEY, API_TOKEN, BACKEND_SIGNING, MERCHANT_ID, METRICS_TOKEN, RELAY_KEY, confirmation, harness, type Harness } from "./helpers.js";

let h: Harness;
beforeEach(async () => {
  h = await harness();
});
afterEach(async () => {
  await h.teardown();
});

const SECRETS = [API_TOKEN, MERCHANT_ID, RELAY_KEY.secret, ADMIN_KEY.secret, BACKEND_SIGNING.secret, METRICS_TOKEN];

describe("health and metrics", () => {
  it("serves liveness and readiness without internal detail", async () => {
    const live = await h.app.inject({ method: "GET", url: "/healthz" });
    expect(live.statusCode).toBe(200);
    expect(live.json()).toEqual({ status: "ok" });
    h.worker.start();
    const ready = await h.app.inject({ method: "GET", url: "/readyz" });
    expect(ready.statusCode).toBe(200);
    expect(Object.keys(ready.json())).toEqual(["status"]);
  });

  it("reports not ready when the retry worker is not running", async () => {
    const res = await h.app.inject({ method: "GET", url: "/readyz" });
    expect(res.statusCode).toBe(503);
  });

  it("serves Prometheus metrics only with the metrics token", async () => {
    expect((await h.app.inject({ method: "GET", url: "/metrics" })).statusCode).toBe(404);
    expect((await h.app.inject({ method: "GET", url: "/metrics", headers: { authorization: "Bearer wrong" } })).statusCode).toBe(404);
    const res = await h.app.inject({ method: "GET", url: "/metrics", headers: { authorization: `Bearer ${METRICS_TOKEN}` } });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/plain/);
    expect(res.body).toContain("wbproxy_callbacks_received_total");
  });

  it("adds the request id and no-store to every answer", async () => {
    const res = await h.app.inject({ method: "GET", url: "/nowhere" });
    expect(res.statusCode).toBe(404);
    expect(res.headers["x-wingo-request-id"]).toBeDefined();
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["x-powered-by"]).toBeUndefined();
  });
});

describe("admin API", () => {
  it("requires a key with the admin scope", async () => {
    expect((await h.relay("/v1/admin/providers", undefined, { method: "GET" })).statusCode).toBe(401);
    expect((await h.app.inject({ method: "GET", url: "/v1/admin/providers" })).statusCode).toBe(401);
  });

  it("describes providers and keys without any secret", async () => {
    const res = await h.relay("/v1/admin/providers", undefined, { method: "GET", key: ADMIN_KEY });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.providers[0]).toMatchObject({
      id: "parscoin",
      upstreamHost: "api.parscoin.test",
      circuit: "closed",
      callback: { publicUrl: "https://proxy.test/callback/gw-a", destination: "https://api.backend.test/webhooks/ir-card" },
    });
    expect(body.providers[0].operations.map((o: { path: string }) => o.path)).toEqual([
      "/v1/providers/parscoin/payment/create",
      "/v1/providers/parscoin/payment/verify",
    ]);
    expect(body.providers[0].credentials[0]).toMatchObject({ name: "PARSCOIN_API_TOKEN", configured: true });
    expect(body.internalKeys).toEqual([
      { id: RELAY_KEY.id, scopes: ["relay"] },
      { id: ADMIN_KEY.id, scopes: ["admin"] },
    ]);
    for (const s of SECRETS) expect(res.body).not.toContain(s);
  });

  it("lists callbacks as metadata only and re-queues a rejected one", async () => {
    h.backend
      .intercept({ path: "/webhooks/ir-card", method: "POST" })
      .reply(422, JSON.stringify({ error: "unknown transaction" }), { headers: { "content-type": "application/json" } });
    const body = confirmation();
    await h.callback(body);

    const list = await h.relay(`/v1/admin/callbacks?status=failed&reference=${body.uuid}`, undefined, { method: "GET", key: ADMIN_KEY });
    // The query is part of what is signed, so filters cannot be swapped in transit.
    expect(list.statusCode).toBe(200);
    const [item] = list.json().callbacks;
    expect(item).toMatchObject({ provider: "parscoin", status: "failed", failureKind: "rejected", reference: body.uuid, payloadStored: true });
    expect(list.body).not.toContain(body.card_number);
    expect(list.body).not.toContain("payloadEnc");

    h.backend.intercept({ path: "/webhooks/ir-card", method: "POST" }).reply(200, JSON.stringify({ status: "OK" }), { headers: { "content-type": "application/json" } });
    const requeued = await h.relay(`/v1/admin/callbacks/${item.id}/redeliver`, undefined, { method: "POST", key: ADMIN_KEY });
    expect(requeued.statusCode).toBe(202);
    expect(requeued.json().callback.status).toBe("retry_pending");
    await h.worker.tick();
    const after = await h.relay(`/v1/admin/callbacks/${item.id}`, undefined, { method: "GET", key: ADMIN_KEY });
    expect(after.json().callback.status).toBe("delivered");

    const again = await h.relay(`/v1/admin/callbacks/${item.id}/redeliver`, undefined, { method: "POST", key: ADMIN_KEY });
    expect(again.statusCode).toBe(409);
  });

  it("rejects bad filters and unknown ids", async () => {
    expect((await h.relay("/v1/admin/callbacks?status=weird", undefined, { method: "GET", key: ADMIN_KEY })).statusCode).toBe(400);
    expect((await h.relay("/v1/admin/callbacks/not-a-uuid", undefined, { method: "GET", key: ADMIN_KEY })).statusCode).toBe(404);
  });
});
