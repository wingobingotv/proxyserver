import { pino, type Logger } from "pino";
import { REDACTED, SENSITIVE_HEADERS } from "./redact.js";

/**
 * Structured JSON logs. Fields that may carry credentials are removed by
 * path, and call sites pass already-redacted objects (`redact()`); bodies,
 * payloads and provider responses are never logged.
 */
const headerPaths = SENSITIVE_HEADERS.flatMap((h) => [`headers["${h}"]`, `req.headers["${h}"]`, `res.headers["${h}"]`]);

export const REDACT_PATHS = [
  ...headerPaths,
  "body",
  "payload",
  "secret",
  "apiToken",
  "merchantId",
  "*.secret",
  "*.apiToken",
  "*.merchantId",
  "*.password",
  "*.token",
  "*.authorization",
  "*.card_number",
];

export function createLogger(options: { level: string; destination?: NodeJS.WritableStream }): Logger {
  return pino(
    {
      level: options.level,
      base: { service: "wingobingo-proxy" },
      timestamp: pino.stdTimeFunctions.isoTime,
      redact: { paths: REDACT_PATHS, censor: REDACTED },
      formatters: { level: (label) => ({ level: label }) },
    },
    options.destination as pino.DestinationStream | undefined,
  );
}

export type { Logger };
