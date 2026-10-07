import { isIP } from "node:net";
import type { DataKey } from "../core/crypto.js";
import { KEY_ID_PATTERN } from "../core/hmac.js";
import { ipMatcher, parseIpEntry, type IpMatcher } from "../core/ipList.js";
import { policyFor, type DestinationPolicy } from "../core/ssrf.js";
import { PROVIDER_FACTORIES } from "../providers/index.js";
import { ProviderRegistry } from "../providers/registry.js";
import type { ProviderAdapter, ProviderFactory } from "../providers/types.js";
import { ConfigError, EnvReader, MIN_SECRET_LENGTH, type AppEnv } from "./env.js";

export type Scope = "relay" | "admin";

export type InternalKey = { id: string; secret: string; scopes: ReadonlySet<Scope> };

export type Config = {
  appEnv: AppEnv;
  host: string;
  port: number;
  publicBaseUrl: URL;
  /** Addresses whose X-Forwarded-For is believed (the reverse proxy). Empty = trust none. */
  trustedProxies: string[];
  logLevel: string;
  databasePath: string;
  dataKeys: DataKey[];
  internal: {
    keys: InternalKey[];
    maxSkewSeconds: number;
    allowedIps: IpMatcher;
    maxBodyBytes: number;
    rateLimitPerMinute: number;
    authFailuresPerMinute: number;
  };
  callbacks: {
    rateLimitPerIpPerMinute: number;
    forwardTimeoutMs: number;
    maxAttempts: number;
    retryBaseMs: number;
    retryMaxMs: number;
    workerIntervalMs: number;
    workerBatchSize: number;
    payloadRetentionDays: number;
  };
  backend: {
    baseUrl: URL;
    policy: DestinationPolicy;
    connectTimeoutMs: number;
    signingKey: { id: string; secret: string };
  };
  metricsToken: string | null;
};

const APP_ENVS: AppEnv[] = ["production", "staging", "development", "test"];
const SECRET_CHARS = /^[A-Za-z0-9_\-+/=.~]+$/;

function parseInternalKeys(env: EnvReader): InternalKey[] {
  const entries = env.list("INTERNAL_HMAC_KEYS");
  if (entries.length === 0) {
    env.problem("INTERNAL_HMAC_KEYS is required (id:secret[:relay+admin], comma separated)");
    return [];
  }
  const keys: InternalKey[] = [];
  entries.forEach((entry, i) => {
    const [id, secret, scopeText] = entry.split(":");
    const where = `INTERNAL_HMAC_KEYS entry ${i + 1}`;
    if (!id || !KEY_ID_PATTERN.test(id)) return env.problem(`${where}: key id must match ${KEY_ID_PATTERN}`);
    if (!secret || secret.length < MIN_SECRET_LENGTH || !SECRET_CHARS.test(secret)) {
      return env.problem(`${where} (${id}): secret must be at least ${MIN_SECRET_LENGTH} URL-safe characters`);
    }
    const scopes = new Set<Scope>();
    for (const s of (scopeText || "relay").split("+")) {
      if (s !== "relay" && s !== "admin") return env.problem(`${where} (${id}): unknown scope "${s}"`);
      scopes.add(s);
    }
    if (keys.some((k) => k.id === id)) return env.problem(`${where}: duplicate key id "${id}"`);
    keys.push({ id, secret, scopes });
  });
  return keys;
}

function parseDataKeys(env: EnvReader): DataKey[] {
  const entries = env.list("DATA_ENCRYPTION_KEYS");
  if (entries.length === 0) {
    env.problem("DATA_ENCRYPTION_KEYS is required (id:<64 hex chars>, newest first)");
    return [];
  }
  const keys: DataKey[] = [];
  entries.forEach((entry, i) => {
    const [id, hex] = entry.split(":");
    if (!id || !KEY_ID_PATTERN.test(id) || !hex || !/^[0-9a-fA-F]{64}$/.test(hex)) {
      env.problem(`DATA_ENCRYPTION_KEYS entry ${i + 1}: expected id:<64 hex chars>`);
      return;
    }
    keys.push({ id, key: Buffer.from(hex, "hex") });
  });
  return keys;
}

function parseIpListVar(env: EnvReader, name: string): IpMatcher {
  try {
    return ipMatcher(env.list(name));
  } catch (err) {
    env.problem(`${name}: ${(err as Error).message}`);
    return ipMatcher([]);
  }
}

export type LoadedConfig = { config: Config; registry: ProviderRegistry };

/** Reads and validates everything. Throws `ConfigError` listing every problem. */
export function loadConfig(
  rawEnv: Record<string, string | undefined>,
  factories: readonly ProviderFactory[] = PROVIDER_FACTORIES,
): LoadedConfig {
  const env = new EnvReader(rawEnv);

  const appEnvText = env.string("APP_ENV", { required: true, hint: APP_ENVS.join("|") });
  const appEnv = (APP_ENVS as string[]).includes(appEnvText ?? "") ? (appEnvText as AppEnv) : undefined;
  if (appEnvText && !appEnv) env.problem(`APP_ENV must be one of ${APP_ENVS.join(", ")}`);
  const allowHttp = appEnv === "development" || appEnv === "test";

  const port = env.int("PORT", 0, { min: 1, max: 65_535 });
  if (!env.has("PORT")) env.problem("PORT is required");
  const host = env.string("HOST", { default: "0.0.0.0" })!;
  const publicBaseUrl = env.url("PUBLIC_BASE_URL", { required: true, allowHttp, originOnly: true });

  const trustedProxies = env.list("TRUSTED_PROXIES");
  for (const p of trustedProxies) if (!parseIpEntry(p)) env.problem(`TRUSTED_PROXIES: "${p}" is not an IP or CIDR`);

  const databasePath = env.string("DATABASE_PATH", { required: true, hint: "e.g. /data/proxy.db" })!;
  const dataKeys = parseDataKeys(env);

  const keys = parseInternalKeys(env);
  const internal = {
    keys,
    maxSkewSeconds: env.int("INTERNAL_AUTH_MAX_SKEW_SECONDS", 300, { min: 30, max: 900 }),
    allowedIps: parseIpListVar(env, "INTERNAL_ALLOWED_IPS"),
    maxBodyBytes: env.int("INTERNAL_MAX_BODY_BYTES", 65_536, { min: 1_024, max: 1_048_576 }),
    rateLimitPerMinute: env.int("INTERNAL_RATE_LIMIT_PER_MINUTE", 1_200, { min: 10, max: 100_000 }),
    authFailuresPerMinute: env.int("INTERNAL_AUTH_FAILURES_PER_MINUTE", 30, { min: 1, max: 10_000 }),
  };
  if (appEnv === "production" && internal.allowedIps.empty) {
    env.problem("INTERNAL_ALLOWED_IPS is required in production (the Player API server's public IP)");
  }

  const callbacks = {
    rateLimitPerIpPerMinute: env.int("CALLBACK_RATE_LIMIT_PER_IP_PER_MINUTE", 300, { min: 10, max: 100_000 }),
    forwardTimeoutMs: env.int("CALLBACK_FORWARD_TIMEOUT_MS", 10_000, { min: 1_000, max: 60_000 }),
    maxAttempts: env.int("CALLBACK_MAX_ATTEMPTS", 20, { min: 1, max: 200 }),
    retryBaseMs: env.int("CALLBACK_RETRY_BASE_MS", 5_000, { min: 100, max: 600_000 }),
    retryMaxMs: env.int("CALLBACK_RETRY_MAX_MS", 900_000, { min: 1_000, max: 86_400_000 }),
    workerIntervalMs: env.int("CALLBACK_WORKER_INTERVAL_MS", 2_000, { min: 100, max: 60_000 }),
    workerBatchSize: env.int("CALLBACK_WORKER_BATCH_SIZE", 20, { min: 1, max: 500 }),
    payloadRetentionDays: env.int("CALLBACK_PAYLOAD_RETENTION_DAYS", 30, { min: 1, max: 3_650 }),
  };

  const backendBaseUrl = env.url("MAIN_BACKEND_BASE_URL", { required: true, allowHttp });
  const backendKeyId = env.string("BACKEND_CALLBACK_SIGNING_KEY_ID", { required: true, pattern: KEY_ID_PATTERN });
  const backendSecret = env.secret("BACKEND_CALLBACK_SIGNING_SECRET", { required: true });
  const backendAllowPrivate = env.bool("MAIN_BACKEND_ALLOW_PRIVATE_NETWORK", false);
  const backendConnectTimeoutMs = env.int("MAIN_BACKEND_CONNECT_TIMEOUT_MS", 5_000, { min: 500, max: 30_000 });
  if (backendBaseUrl && isIP(backendBaseUrl.hostname.replace(/^\[|\]$/g, "")) && backendBaseUrl.protocol === "https:") {
    env.problem("MAIN_BACKEND_BASE_URL must use a hostname so its TLS certificate can be verified");
  }

  const metricsToken = env.secret("METRICS_TOKEN", { required: false }) ?? null;

  // Providers.
  const adapters: ProviderAdapter[] = [];
  const disabled: string[] = [];
  if (appEnv) {
    // A placeholder keeps provider settings validated in the same run; the config is refused below anyway.
    const backendForValidation = backendBaseUrl ?? new URL("https://backend.invalid/");
    for (const factory of factories) {
      const adapter = factory.fromEnv(env, { appEnv, allowHttp, backendBaseUrl: backendForValidation });
      if (adapter) adapters.push(adapter);
      else if (!env.bool(`${factory.envPrefix}ENABLED`, false)) disabled.push(factory.id);
    }
  }

  if (env.problems.length > 0 || !appEnv || !publicBaseUrl || !backendBaseUrl || !backendKeyId || !backendSecret) {
    throw new ConfigError(env.problems.length > 0 ? env.problems : ["configuration incomplete"]);
  }

  let registry: ProviderRegistry;
  try {
    registry = new ProviderRegistry(adapters, disabled);
  } catch (err) {
    throw new ConfigError([(err as Error).message]);
  }

  return {
    config: {
      appEnv,
      host,
      port,
      publicBaseUrl,
      trustedProxies,
      logLevel: env.string("LOG_LEVEL", { default: "info", pattern: /^(fatal|error|warn|info|debug|trace)$/ }) ?? "info",
      databasePath,
      dataKeys,
      internal,
      callbacks,
      backend: {
        baseUrl: backendBaseUrl,
        policy: policyFor(backendBaseUrl, { allowHttp, allowPrivateNetwork: backendAllowPrivate }),
        connectTimeoutMs: backendConnectTimeoutMs,
        signingKey: { id: backendKeyId, secret: backendSecret },
      },
      metricsToken,
    },
    registry,
  };
}
