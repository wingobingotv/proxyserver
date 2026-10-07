import { Writable } from "node:stream";
import { MockAgent } from "undici";
import { buildApp } from "../src/app.js";
import { loadConfig } from "../src/config/config.js";
import { Encryptor } from "../src/core/crypto.js";
import { signedHeaders } from "../src/core/hmac.js";
import { HttpClient } from "../src/core/httpClient.js";
import { createLogger } from "../src/core/logger.js";
import { Metrics } from "../src/core/metrics.js";
import { parscoinWebhookSignature } from "../src/providers/parscoin/index.js";
import { Store } from "../src/store/store.js";

export const RELAY_KEY = { id: "backend-a", secret: "relay-secret-0123456789-abcdefghijklmnop" };
export const ADMIN_KEY = { id: "ops-a", secret: "admin-secret-0123456789-abcdefghijklmnop" };
export const BACKEND_SIGNING = { id: "proxy-a", secret: "callback-signing-0123456789-abcdefghijk" };
export const API_TOKEN = "pc-api-token-0123456789-SECRET";
export const MERCHANT_ID = "MERCHANT0123456789ABCDEF";
export const METRICS_TOKEN = "metrics-token-0123456789-abcdefghijklm";

export const PARSCOIN_ORIGIN = "https://api.parscoin.test";
export const BACKEND_ORIGIN = "https://api.backend.test";

export function testEnv(over: Record<string, string> = {}): Record<string, string> {
  return {
    APP_ENV: "test",
    PORT: "8080",
    PUBLIC_BASE_URL: "https://proxy.test",
    DATABASE_PATH: ":memory:",
    DATA_ENCRYPTION_KEYS: `k1:${"11".repeat(32)}`,
    INTERNAL_HMAC_KEYS: `${RELAY_KEY.id}:${RELAY_KEY.secret},${ADMIN_KEY.id}:${ADMIN_KEY.secret}:admin`,
    MAIN_BACKEND_BASE_URL: BACKEND_ORIGIN,
    BACKEND_CALLBACK_SIGNING_KEY_ID: BACKEND_SIGNING.id,
    BACKEND_CALLBACK_SIGNING_SECRET: BACKEND_SIGNING.secret,
    METRICS_TOKEN,
    CALLBACK_FORWARD_TIMEOUT_MS: "1000",
    CALLBACK_RETRY_BASE_MS: "1000",
    CALLBACK_MAX_ATTEMPTS: "3",
    PARSCOIN_ENABLED: "true",
    PARSCOIN_BASE_URL: PARSCOIN_ORIGIN,
    PARSCOIN_ALLOWED_HOSTS: "api.parscoin.test",
    PARSCOIN_API_TOKEN: API_TOKEN,
    PARSCOIN_MERCHANT_ID: MERCHANT_ID,
    PARSCOIN_CALLBACK_SLUG: "gw-a",
    PARSCOIN_CALLBACK_PATH: "/webhooks/ir-card",
    PARSCOIN_TIMEOUT_MS: "1000",
    PARSCOIN_DEADLINE_MS: "3000",
    ...over,
  };
}

export type Harness = Awaited<ReturnType<typeof harness>>;

export async function harness(over: Record<string, string> = {}) {
  const { config, registry } = loadConfig(testEnv(over));
  const agent = new MockAgent();
  agent.disableNetConnect();
  const store = new Store(":memory:");
  const logs: string[] = [];
  const sink = new Writable({
    write(chunk: Buffer, _enc, cb) {
      logs.push(chunk.toString("utf8"));
      cb();
    },
  });
  const logger = createLogger({ level: "debug", destination: sink });
  const metrics = new Metrics({ defaultMetrics: false });
  const clock = { t: Date.now() };
  const now = () => clock.t;
  const encryptor = new Encryptor(config.dataKeys);
  const proxy = buildApp({
    config,
    registry,
    store,
    encryptor,
    metrics,
    logger,
    now,
    providerClient: (p) => new HttpClient(p.upstream.policy, { connectTimeoutMs: 500, dispatcher: agent }),
    backendClient: new HttpClient(config.backend.policy, { connectTimeoutMs: 500, dispatcher: agent }),
  });
  await proxy.app.ready();

  let torn = false;

  const relay = (
    path: string,
    body: unknown,
    options: {
      method?: "GET" | "POST";
      key?: { id: string; secret: string };
      timestamp?: number;
      nonce?: string;
      headers?: Record<string, string>;
      tamper?: (raw: string) => string;
      contentType?: string;
    } = {},
  ) => {
    const method = options.method ?? "POST";
    const raw = body === undefined ? "" : typeof body === "string" ? body : JSON.stringify(body);
    const contentType = raw ? (options.contentType ?? "application/json") : undefined;
    const signed = signedHeaders(options.key ?? RELAY_KEY, {
      method,
      target: path,
      contentType,
      body: raw,
      timestamp: options.timestamp ?? Math.floor(clock.t / 1000),
      ...(options.nonce ? { nonce: options.nonce } : {}),
    });
    const payload = options.tamper ? options.tamper(raw) : raw;
    return proxy.app.inject({
      method,
      url: path,
      headers: { ...(contentType ? { "content-type": contentType } : {}), ...signed, ...(options.headers ?? {}) },
      ...(payload ? { payload } : {}),
    });
  };

  const callback = (
    body: Record<string, unknown> | string,
    options: { signature?: string; slug?: string; headers?: Record<string, string>; remoteAddress?: string } = {},
  ) => {
    const raw = typeof body === "string" ? body : JSON.stringify(body);
    const obj = typeof body === "string" ? {} : body;
    const sig =
      options.signature ?? parscoinWebhookSignature(MERCHANT_ID, String(obj.uuid ?? ""), (obj.event_timestamp as string | number) ?? "");
    return proxy.app.inject({
      method: "POST",
      url: `/callback/${options.slug ?? "gw-a"}`,
      headers: { "content-type": "application/json", "x-sign-hash": sig, ...(options.headers ?? {}) },
      payload: raw,
      ...(options.remoteAddress ? { remoteAddress: options.remoteAddress } : {}),
    });
  };

  return {
    ...proxy,
    config,
    registry,
    store,
    agent,
    logs,
    metrics,
    clock,
    encryptor,
    parscoin: agent.get(PARSCOIN_ORIGIN),
    backend: agent.get(BACKEND_ORIGIN),
    relay,
    callback,
    async teardown() {
      if (torn) return;
      torn = true;
      await proxy.close();
      store.close();
      await agent.close();
    },
  };
}

export const confirmation = (over: Record<string, unknown> = {}) => ({
  event: "transaction_confirmation",
  uuid: "3f2a9c1e-7b4d-4e8a-9f10-2c3d4e5f6a7b",
  event_timestamp: 1791370000,
  amount: 12_500_000,
  currency: "IRR",
  transaction_status: "completed",
  is_completed: true,
  transaction_number: "TN-778899",
  card_number: "6037991234567890",
  ...over,
});

export const jsonHeaders = { headers: { "content-type": "application/json" } };
