import { buildApp } from "./app.js";
import { loadConfig } from "./config/config.js";
import { ConfigError } from "./config/env.js";
import { Encryptor } from "./core/crypto.js";
import { createLogger } from "./core/logger.js";
import { Metrics } from "./core/metrics.js";
import { Store } from "./store/store.js";

const SHUTDOWN_GRACE_MS = 25_000;

async function main(): Promise<void> {
  let loaded;
  try {
    loaded = loadConfig(process.env);
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`wingobingo-proxy: ${err.message}\n`);
      process.exit(78);
    }
    throw err;
  }
  const { config, registry } = loaded;
  const logger = createLogger({ level: config.logLevel });
  const store = new Store(config.databasePath);
  const encryptor = new Encryptor(config.dataKeys);
  const metrics = new Metrics();

  const proxy = buildApp({ config, registry, store, encryptor, metrics, logger });
  await proxy.app.listen({ host: config.host, port: config.port });
  proxy.worker.start();
  logger.info(
    {
      appEnv: config.appEnv,
      providers: registry.list().map((p) => ({ id: p.id, operations: p.operations.map((o) => o.name), callback: Boolean(p.callback) })),
      disabled: registry.disabledIds(),
    },
    "wingobingo-proxy started",
  );

  let stopping = false;
  const shutdown = (signal: string) => {
    if (stopping) return;
    stopping = true;
    logger.info({ signal }, "shutting down");
    const force = setTimeout(() => {
      logger.error("shutdown grace period exceeded");
      process.exit(1);
    }, SHUTDOWN_GRACE_MS);
    force.unref();
    proxy
      .close()
      .then(() => store.close())
      .then(() => {
        logger.info("stopped");
        process.exit(0);
      })
      .catch((err: unknown) => {
        logger.error({ err }, "shutdown failed");
        process.exit(1);
      });
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("unhandledRejection", (reason) => logger.error({ err: reason }, "unhandled rejection"));
}

main().catch((err: unknown) => {
  process.stderr.write(`wingobingo-proxy failed to start: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
