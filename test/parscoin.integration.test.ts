import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parscoinWebhookSignature } from "../src/providers/parscoin/index.js";
import { API_TOKEN, MERCHANT_ID, confirmation, harness, type Harness } from "./helpers.js";

/**
 * The whole ParsCoin path as the Player API uses it today, with only the
 * transport moved behind the proxy: create → player pays → webhook →
 * backend re-verifies → credit. The payload shapes come from
 * backend/src/services/irCardGateways/gatewayA.js.
 */

// Produced by the Player API's own gatewayA.verifyWebhookSignature algorithm for MERCHANT_ID,
// confirmation().uuid and event_timestamp 1791370000 (and accepted by it).
const BACKEND_VECTOR =
  "5f1197852d5f5f3085989439f3f0b74b22aaa95147114e383286b12febdd349f8b5b0c33a628c0ae99d70e3ed41ed5db1e173ad437b0924f85ead1c04095c7f3";

let h: Harness;
beforeEach(async () => {
  h = await harness();
});
afterEach(async () => {
  await h.teardown();
});

describe("ParsCoin through the proxy", () => {
  it("computes the webhook signature exactly like the Player API", () => {
    const body = confirmation();
    expect(parscoinWebhookSignature(MERCHANT_ID, body.uuid, body.event_timestamp)).toBe(BACKEND_VECTOR);
    expect(parscoinWebhookSignature(MERCHANT_ID, body.uuid, String(body.event_timestamp))).toBe(BACKEND_VECTOR);
  });

  it("runs create, webhook and verify end to end without the proxy deciding the outcome", async () => {
    const body = confirmation();
    let upstreamToken: string | undefined;
    h.parscoin
      .intercept({ path: "/v1/transactions/createNewTransaction", method: "POST" })
      .reply((opts) => {
        upstreamToken = (opts.headers as Record<string, string>)["x-api-token"];
        return {
          statusCode: 200,
          data: JSON.stringify({
            data: {
              transaction: { uuid: body.uuid, transaction_number: "TN-778899", transaction_status: "pending", total_amount: body.amount },
              payment_url: "https://pay.parscoin.test/t/abc",
            },
          }),
          responseOptions: { headers: { "content-type": "application/json" } },
        };
      });
    const created = await h.relay("/v1/providers/parscoin/payment/create", {
      total_amount: body.amount,
      description: "Wallet top-up",
      client_ip: "",
      userid: "u-1001",
      redirect_url: "https://wingobingo.test/payment/return",
    });
    expect(created.statusCode).toBe(200);
    expect(created.json().data.payment_url).toBe("https://pay.parscoin.test/t/abc");
    expect(created.json().data.transaction.uuid).toBe(body.uuid);
    expect(upstreamToken).toBe(API_TOKEN);

    // ParsCoin calls the proxy; the backend receives it, and before crediting
    // it re-verifies through the proxy (as IrCardGatewayService does today).
    let backendGot: string | undefined;
    h.backend
      .intercept({ path: "/webhooks/ir-card", method: "POST" })
      .reply((opts) => {
        backendGot = String(opts.body);
        return { statusCode: 200, data: JSON.stringify({ status: "OK" }), responseOptions: { headers: { "content-type": "application/json" } } };
      });
    const hook = await h.callback(body, { signature: BACKEND_VECTOR });
    expect(hook.statusCode).toBe(200);
    expect(backendGot).toBe(JSON.stringify(body));

    h.parscoin
      .intercept({ path: "/v1/transactions/verifyTransaction", method: "POST", body: JSON.stringify({ transaction_uuid: body.uuid }) })
      .reply(200, JSON.stringify({ data: { is_verified: true, transaction_number: "TN-778899", last_activity: "2026-10-07T10:00:00Z" } }), {
        headers: { "content-type": "application/json" },
      });
    const verified = await h.relay("/v1/providers/parscoin/payment/verify", { transaction_uuid: body.uuid });
    expect(verified.statusCode).toBe(200);
    expect(verified.json()).toEqual({ data: { is_verified: true, transaction_number: "TN-778899", last_activity: "2026-10-07T10:00:00Z" } });
  });

  it("forwards a 'completed' callback the backend refuses, without treating it as paid", async () => {
    h.backend
      .intercept({ path: "/webhooks/ir-card", method: "POST" })
      .reply(409, JSON.stringify({ error: "amount mismatch" }), { headers: { "content-type": "application/json" } });
    const res = await h.callback(confirmation({ transaction_status: "completed", is_completed: true }));
    expect(res.statusCode).toBe(409);
    const [rec] = h.store.listCallbacks({ limit: 1 });
    expect(rec!.status).toBe("failed");
  });

  it("requires the fields the signature covers", async () => {
    const res = await h.callback({ event: "transaction_confirmation", amount: 1 }, { signature: "a".repeat(128) });
    expect(res.statusCode).toBe(400);
  });

  it("uses only the configured ParsCoin host", () => {
    const p = h.registry.get("parscoin")!;
    expect([...p.upstream.policy.allowedHosts]).toEqual(["api.parscoin.test"]);
    expect(p.upstream.baseUrl.href).toBe("https://api.parscoin.test/");
  });
});
