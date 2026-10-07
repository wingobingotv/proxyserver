import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config/config.js";

function parseEnvFile(path: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (m) out[m[1]!] = m[2]!;
  }
  return out;
}

const fill = (value: string) =>
  value
    .replace(/<64-hex-chars>/g, "ab".repeat(32))
    .replace(/<secret-32\+>/g, () => `s${Math.random().toString(36).slice(2)}${"x".repeat(40)}`.slice(0, 44));

describe(".env.example", () => {
  const example = parseEnvFile(new URL("../.env.example", import.meta.url).pathname);

  it("loads in production once placeholders are filled", () => {
    const env = Object.fromEntries(Object.entries(example).map(([k, v]) => [k, fill(v)]));
    Object.assign(env, {
      DATABASE_PATH: ":memory:",
      PARSCOIN_ENABLED: "true",
      PARSCOIN_API_TOKEN: "example-api-token-0123456789",
      PARSCOIN_MERCHANT_ID: "EXAMPLEMERCHANT0123456789",
    });
    const { config, registry } = loadConfig(env);
    expect(config.appEnv).toBe("production");
    expect(registry.get("parscoin")?.callback?.slug).toBe("gw-a");
    expect(config.internal.keys.map((k) => [k.id, [...k.scopes]])).toEqual([
      ["backend-1", ["relay"]],
      ["admin-1", ["admin"]],
    ]);
  });

  it("documents every variable the code reads", () => {
    const src = ["config/config.ts", "providers/parscoin/index.ts"]
      .map((f) => readFileSync(new URL(`../src/${f}`, import.meta.url), "utf8"))
      .join("\n");
    const read = new Set([...src.matchAll(/\.(?:string|secret|int|bool|list|url|raw|has)\(\s*"([A-Z0-9_]+)"/g)].map((m) => m[1]!));
    read.add("INTERNAL_ALLOWED_IPS");
    read.add("PARSCOIN_CALLBACK_ALLOWED_IPS");
    const documented = new Set(Object.keys(example));
    // Set by docker-compose.yml for the container.
    const composeOwned = new Set(["HOST", "DATABASE_PATH"]);
    const missing = [...read].filter((k) => !documented.has(k) && !composeOwned.has(k));
    expect(missing).toEqual([]);
  });
});
