# Architecture

## Goals and non-goals

* **Goal:** move provider transport (outbound calls and inbound callbacks) to a
  separate server with a fixed IP, with no change to WingoBingo's payment
  rules.
* **Non-goals:** deciding payment outcomes, holding balances, generic proxying,
  or calling anything that is not explicitly configured.

## Layout

```
src/
  main.ts                 process entry: config → store → app → listen → worker; graceful shutdown
  app.ts                  Fastify app: raw-body parsing, request ids, auth, routes, error mapping
  config/                 env reader (validates, never prints secrets) and full config load
  core/                   reusable mechanisms, provider-agnostic
    hmac.ts               v1 request signature (canonical string, sign, verify helpers)
    ssrf.ts               destination policy, blocked ranges, connect-time DNS check
    httpClient.ts         undici client: policy check, safe lookup, timeouts, size cap, no redirects
    circuitBreaker.ts     per-provider closed/open/half-open
    rateLimiter.ts        token buckets
    crypto.ts             AES-256-GCM envelopes with key rotation
    redact.ts, logger.ts  redaction rules and pino setup
    metrics.ts            Prometheus registry (wbproxy_*)
    headers.ts            hop-by-hop stripping, header allowlists
    requestId.ts          X-Wingo-Request-ID
    errors.ts             error codes → HTTP status, uniform error body
  auth/internalAuth.ts    HMAC v1 verification, scopes, IP allowlist, nonce replay store
  providers/
    types.ts              ProviderAdapter / OperationDef / CallbackDef contracts
    registry.ts           explicit route registry (provider × method × path)
    json.ts               strict body validation and response mapping helpers
    parscoin/             first adapter
  relay/outbound.ts       executes one operation: retries per policy, deadline, breaker, metrics
  callbacks/
    inbound.ts            intake: route → source → size/type → provider validation → store → deliver
    delivery.ts           one delivery attempt to the backend, signed; outcome → state
    worker.ts             durable retry loop + maintenance (purges, backlog gauge)
  store/store.ts          SQLite (WAL, synchronous=FULL): callbacks, nonces, schema_migrations
  routes/admin.ts         read-mostly operations API
```

## Outbound relay

1. `app.ts` authenticates (HMAC v1, `relay` scope, source IP), applies the
   relay rate limit, and refuses any query string.
2. The registry resolves `(provider, method, path)` to an `OperationDef`.
   Anything unknown is 404, and a known path with the wrong method is 405.
3. The operation's `buildRequest` validates the body strictly (unknown fields
   refused) and builds the provider request. Credentials come from the
   adapter's config, never from the caller.
4. `OutboundRelay` runs it under the operation's retry policy and deadline,
   behind the provider's circuit breaker:
   * `onConnectFailure`: retry only when the connection was never made
     (nothing reached the provider). This is the only retry allowed for
     non-idempotent operations such as ParsCoin create.
   * `onAmbiguousFailure`: also retry timeouts and broken connections
     (idempotent reads, e.g. verify).
   * `retryStatuses`: retry these provider statuses (verify: 502/503/504).
5. `mapResponse` passes the provider status and JSON body through. A 2xx that
   is not a JSON object becomes 502 `upstream_malformed_response`. A
   redirect is never followed (502 `upstream_redirect_blocked`).

## Inbound callbacks

```
provider → /callback/<slug>
  ├─ unknown slug → 404
  ├─ method / rate limit (429 + Retry-After) / IP allowlist (403) / media type (415) / size (413)
  ├─ adapter.validate → signature, required fields, dedupe key, reference
  ├─ store (UNIQUE(provider, dedupe_key)); payload encrypted
  │     duplicate → same body: stored answer / resume / re-arm when exhausted
  │               → different body: 409
  └─ inline delivery attempt → answer the provider with the backend's answer,
                               or 202 queued (or 503 when ack-when-queued is off)
worker (every CALLBACK_WORKER_INTERVAL_MS): due retry_pending + expired forwarding locks → deliver
```

States: `validated` (stored, not yet tried) → `forwarding` (claimed with a
lock) → `delivered` | `retry_pending` | `failed` (`rejected` = backend final
4xx; `exhausted` = attempts used up). Claiming is a conditional `UPDATE`, so
two attempts cannot deliver the same record concurrently. A lock that
expires (crashed process) makes the record claimable again.

Delivery is **at-least-once**. The Player API is idempotent per payment: it
credits through one atomic claim, and only after its own verify call says the
payment is verified.

Stored per callback: id, provider, dedupe key, reference, request id,
received time, source IP, method, content type, payload hash (SHA-256),
encrypted payload, destination, status, attempts, duplicate count, last
error, last HTTP status, next attempt, lock, delivered time, failure kind, and
the encrypted backend response (replayed to duplicates).

## Trust boundaries

| Boundary | Control |
|---|---|
| Internet → proxy | Nginx TLS, route allowlist, per-route IP `allow`, body size |
| Player API → proxy | HMAC v1 + nonce + timestamp + scope + `INTERNAL_ALLOWED_IPS` |
| provider → proxy | adapter signature check + optional IP allowlist + rate limits |
| proxy → provider | fixed base URL, host allowlist, SSRF guard, TLS verification |
| proxy → Player API | fixed base URL + configured path, HMAC v1 signed, SSRF guard |
| disk | payloads and responses AES-256-GCM, bound to record id; retention purge |

## Persistence

One SQLite file on the `proxy-data` volume. WAL with `synchronous=FULL`, so an
acknowledged callback survives a crash. Migrations are numbered and additive,
recorded in `schema_migrations`. The nonce table is pruned once nonces can no
longer be inside the time window. A single instance is assumed. To run more
than one, move the store to a shared database first, since claims and nonces
must be shared.

## Observability

* Logs: JSON lines (pino) with `requestId`, `provider`, `operation`,
  `direction`; redaction by key and pattern.
* Metrics (`/metrics`, token-protected): `wbproxy_callbacks_received_total`,
  `wbproxy_callback_deliveries_total`, `wbproxy_callback_delivery_duration_seconds`,
  `wbproxy_callback_backlog`, `wbproxy_outbound_requests_total`,
  `wbproxy_outbound_duration_seconds`, `wbproxy_outbound_retries_total`,
  `wbproxy_upstream_failures_total`, `wbproxy_auth_failures_total`,
  `wbproxy_rejected_requests_total`, `wbproxy_circuit_open`, plus Node process metrics.
* Suggested alerts: `wbproxy_callback_backlog{status="failed"} > 0`;
  `wbproxy_callback_backlog{status="retry_pending"}` growing for 15 min;
  `wbproxy_circuit_open == 1`; a spike in `wbproxy_auth_failures_total`.

## Future admin panel

The Admin API can call `/v1/admin/*` with an `admin`-scoped key, from an IP
listed in `INTERNAL_ALLOWED_IPS`. Responses carry no secrets. Note that the
proxy identifies providers by their real id (`parscoin`). A panel page must
map ids to the neutral labels the panel already uses (`gw_a` → "Gateway A")
and must not show `upstreamHost`.
