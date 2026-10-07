# wingobingo-proxy

A secure application-level relay between WingoBingo and payment providers.
It runs on its own server, domain, IP and release cycle. It is **not** a
generic HTTP proxy: every destination, route and operation is fixed in code
and switched on by configuration. A caller can never choose a host or URL.

```
             ┌──────────────── wingobingo-proxy (own server, fixed IP) ───────────────┐
Player API ──┤ POST /v1/providers/<provider>/<operation>   HMAC v1 · IP allowlist     ├──► provider API
(backend)    │      route registry → adapter → SSRF-guarded client → circuit breaker  │   (whitelisted IP)
             │                                                                         │
provider ────┤ POST /callback/<slug>   provider signature · rate limit · idempotency  ├──► Player API
             │      SQLite (encrypted payload) → delivery + durable retry → HMAC v1    │   /webhooks/…
             └─────────────────────────────────────────────────────────────────────────┘
```

* The proxy **never decides that a payment succeeded.** Callbacks are
  validated at the transport level and relayed. The Player API still checks
  the provider's signature, re-verifies the payment with the provider
  (through this proxy), and credits once.
* First provider: **ParsCoin**, the Player API's Iranian card gateway
  (`gw_a`). Only the calls that integration already makes exist: create,
  verify and the webhook. See
  [`docs/CURRENT_DIRECT_PARSCOIN_CALLS.md`](docs/CURRENT_DIRECT_PARSCOIN_CALLS.md).

More detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) ·
Player API changes: [`docs/WINGOBINGO_BACKEND_CHANGES.md`](docs/WINGOBINGO_BACKEND_CHANGES.md) ·
Firewall and IP whitelisting: [`docs/FIREWALL.md`](docs/FIREWALL.md) ·
Nginx: [`deploy/nginx/wingobingo-proxy.conf`](deploy/nginx/wingobingo-proxy.conf)

## Endpoints

| Method | Path | Who | Auth |
|---|---|---|---|
| `POST` | `/callback/<slug>` | provider | provider strategy (ParsCoin: `X-Sign-Hash`), optional IP allowlist |
| `POST` | `/v1/providers/parscoin/payment/create` | Player API | HMAC v1, `relay` scope, `INTERNAL_ALLOWED_IPS` |
| `POST` | `/v1/providers/parscoin/payment/verify` | Player API | same |
| `GET` | `/v1/admin/providers` | Admin API (future panel page) | HMAC v1, `admin` scope |
| `GET` | `/v1/admin/callbacks?provider=&status=&reference=&limit=&before=` | Admin API | same |
| `GET` | `/v1/admin/callbacks/<id>` | Admin API | same |
| `POST` | `/v1/admin/callbacks/<id>/redeliver` | Admin API | same |
| `GET` | `/healthz` | anyone | none, no detail |
| `GET` | `/readyz` | orchestration | none, no detail (database + retry worker) |
| `GET` | `/metrics` | Prometheus | `Authorization: Bearer $METRICS_TOKEN`, otherwise 404 |

Everything else answers 404. Query strings on relay routes are refused, and
request bodies are checked field by field against what the provider takes,
so there is no field through which to pass a URL.

The admin API returns configuration, circuit state, key ids, credential
fingerprints and callback metadata. It never returns secrets, stored
payloads or provider responses.

Errors always look like `{"error": "<code>", "message": "…", "requestId": "…"}`.

## Request signature (HMAC v1)

Used by the Player API to call the proxy, and by the proxy to deliver callbacks.

```
canonical = "v1"            + "\n" +
            METHOD          + "\n" +   upper case
            path?query      + "\n" +   exactly as sent
            media type      + "\n" +   Content-Type without parameters, lower case ("" if none)
            unix seconds    + "\n" +
            nonce           + "\n" +   16–128 of A–Z a–z 0–9 _ -
            hex(sha256(body))

X-Wingo-Key-Id:    <key id>
X-Wingo-Timestamp: <unix seconds>
X-Wingo-Nonce:     <nonce>
X-Wingo-Signature: v1=hex(HMAC-SHA256(secret, canonical))
X-Wingo-Request-ID: <optional, 8–128 of A–Z a–z 0–9 . _ : ->
```

Checks: known key id, timestamp within `INTERNAL_AUTH_MAX_SKEW_SECONDS`,
signature, scope, then the nonce is stored. A reused nonce is refused, and
nonces outlive the time window, so a captured request cannot be replayed.
Several keys can be active at once for rotation. The implementations are
`src/core/hmac.ts` here and `backend/src/services/PaymentProxyClient.js`,
and both are tested against the same fixed vector.

## Install (new server)

Requirements: Docker Engine with the compose plugin, Nginx, certbot, and NTP
time sync (signatures carry timestamps).

```bash
git clone <repo-url> /opt/wingobingo-proxy && cd /opt/wingobingo-proxy
cp .env.example .env && chmod 600 .env
# fill in .env (see below), then:
./scripts/docker-deploy.sh        # same as: docker compose up -d --build
```

Then install the Nginx site (HTTP only; certbot adds https) and apply the
firewall rules in `docs/FIREWALL.md`:

```bash
sudo cp deploy/nginx/wingobingo-proxy.conf /etc/nginx/sites-available/wingobingo-proxy
sudo ln -s /etc/nginx/sites-available/wingobingo-proxy /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d payment.api.wingobingo.tv --redirect
curl https://payment.api.wingobingo.tv/healthz    # {"status":"ok"}
```

## Configuration

Everything is in `.env`. `.env.example` lists and explains every variable.
At start the proxy validates the whole file and exits with the full list of
problems (`docker compose logs proxy`). It never prints secret values.
Unsafe settings are refused rather than corrected: http in production, a
provider host missing from its allowlist, short secrets, missing
`INTERNAL_ALLOWED_IPS` in production.

Three URLs are kept separate:

| What | Variable |
|---|---|
| this proxy's public origin | `PUBLIC_BASE_URL` |
| main backend (Player API) | `MAIN_BACKEND_BASE_URL` |
| ParsCoin API | `PARSCOIN_BASE_URL` (+ `PARSCOIN_ALLOWED_HOSTS`) |

Secrets to generate: `INTERNAL_HMAC_KEYS` secrets, `BACKEND_CALLBACK_SIGNING_SECRET`,
`METRICS_TOKEN` (each ≥ 32 characters) and `DATA_ENCRYPTION_KEYS` (64 hex).
The commands are at the top of `.env.example`.

## Deploy, update, rollback

```bash
# deploy / update
git pull && docker compose up -d --build

# rollback to a known commit
git checkout <commit> && docker compose up -d --build
```

The SQLite database lives in the named volume `proxy-data` and survives
rebuilds. Schema migrations are additive and run at start. Never use
`docker compose down -v`: it deletes the callback history and the retry queue.

Backup: `docker run --rm -v wingobingo-proxy_proxy-data:/data -v "$PWD":/backup alpine sh -c 'cp /data/proxy.db* /backup/'`
(stop the container first, or copy all three files `proxy.db`, `-wal`, `-shm` together).

## Callback setup (ParsCoin)

1. Set `PARSCOIN_ENABLED=true`, the credentials, `PARSCOIN_CALLBACK_SLUG` and
   `PARSCOIN_CALLBACK_PATH=/webhooks/ir-card`.
2. Public callback URL: `https://<PUBLIC_BASE_URL host>/callback/<PARSCOIN_CALLBACK_SLUG>`.
   The slug is configurable (default suggestion `gw-a`), so the provider's
   name never shows up in URLs the admin panel displays. If you prefer
   `/callback/parscoin`, set the slug to `parscoin`.
3. Give that URL to ParsCoin (merchant panel) and set the same value as
   `IR_CARD_WEBHOOK_URL` in the Admin API, so the panel shows it.
4. If ParsCoin publishes its callback source IPs, put them in
   `PARSCOIN_CALLBACK_ALLOWED_IPS`. Without it any source may call, but the
   signature is still required.

Callback lifecycle: `validated → forwarding → delivered`, or
`retry_pending` (backend down, 5xx, 401/503) with exponential backoff up to
`CALLBACK_MAX_ATTEMPTS`, then `failed` (`exhausted`, or `rejected` when the
backend answered a final 4xx). A duplicate (same `event:uuid:event_timestamp`)
is never forwarded twice: the provider gets the stored answer. If the
provider retries after the proxy gave up, the delivery restarts. A duplicate
with a different body is refused with 409.

## Provider setup (adding a provider)

1. Create `src/providers/<id>/index.ts` exporting a `ProviderFactory`. It reads
   its own `<ID>_*` variables, declares its operations (route, upstream path,
   body schema, retry policy, response mapping) and optionally a callback
   (slug, validation strategy, target path).
2. Add it to `src/providers/index.ts`.
3. Add its variables to `.env.example` (the `envExample` test enforces this)
   and tests to `test/`.

Never add an operation the provider's documentation and our existing
integration do not confirm. Never retry a non-idempotent operation after
bytes may have reached the provider, unless the provider supports
idempotency keys.

## WingoBingo integration

See [`docs/WINGOBINGO_BACKEND_CHANGES.md`](docs/WINGOBINGO_BACKEND_CHANGES.md). In short:

* The Player API gets `PAYMENT_PROXY_URL`, `PAYMENT_PROXY_KEY_ID`, `PAYMENT_PROXY_SECRET`,
  `PAYMENT_PROXY_CALLBACK_KEYS`, `IR_CARD_GATEWAY_TRANSPORT` and `IR_CARD_WEBHOOK_REQUIRE_PROXY`.
* `IR_CARD_GATEWAY_TRANSPORT=proxy` sends create and verify through the proxy;
  `direct` (the default) is unchanged behaviour and the rollback.
* The ParsCoin API token used for requests is then the proxy's
  `PARSCOIN_API_TOKEN`. Rotate it there. The merchant ID must match on both
  sides: the Player API still checks webhook signatures itself.

## IP whitelisting

`WINGOBINGO_PROXY_PUBLIC_IP` is this server's public egress IP. Give it to
ParsCoin so they whitelist our API calls. The Player API's IP no longer needs
whitelisting there once `IR_CARD_GATEWAY_TRANSPORT=proxy`. The full rule list
is in [`docs/FIREWALL.md`](docs/FIREWALL.md).

## Security summary

* No open proxy: fixed route registry; destination = adapter's base URL; host allowlist.
* SSRF guard: https only (outside development/test), configured host and port
  only, no credentials in URLs, no redirects followed. Loopback, RFC 1918,
  CGNAT, link-local, cloud metadata, multicast and IPv4-mapped/NAT64 forms
  are blocked. DNS answers are checked at connect time, and the whole answer
  is refused if any address is blocked (DNS rebinding).
* Header allowlist both ways; hop-by-hop and forwarding headers stripped;
  `X-Wingo-Request-ID` generated at the edge, propagated to the backend and
  in every log line.
* Secrets only in `.env`; structured JSON logs with automatic redaction
  (credentials, signatures, card numbers); callback payloads AES-256-GCM
  encrypted at rest, bound to their record, and purged after
  `CALLBACK_PAYLOAD_RETENTION_DAYS`.
* Separate rate limits: per provider and per source IP for callbacks
  (answering 429 with `Retry-After`, never silently dropping), and for the
  internal relay and for failed authentication.
* Container: non-root `node` user, read-only root filesystem, all
  capabilities dropped, `no-new-privileges`, port bound to 127.0.0.1.

## Troubleshooting

| Symptom | Look at |
|---|---|
| Container restarts at once | `docker compose logs proxy`: the config problems are listed. |
| Player API gets 401 `unauthorized` | proxy log `internal auth failed` with `reason`. `expired_timestamp` → clock (NTP); `bad_signature` → secret, or something rewrote the path (Nginx must not), or the body changed. |
| Player API gets 403 | its IP is not in `INTERNAL_ALLOWED_IPS`. With Nginx in front, `TRUSTED_PROXIES` must cover the compose network or every request looks like it comes from the gateway. |
| 503 `circuit_open` | provider failing; `wbproxy_circuit_open`, `wbproxy_upstream_failures_total`. |
| 502 `upstream_blocked_destination` | provider host resolved to a blocked address, or not in the allowlist. |
| Callbacks stuck in `retry_pending` | `GET /v1/admin/callbacks?status=retry_pending`, `lastError`. The Player API answers 401 when `PAYMENT_PROXY_CALLBACK_KEYS` does not match. |
| Callback `failed` / `rejected` | backend refused it (final 4xx). After fixing the cause: `POST /v1/admin/callbacks/<id>/redeliver`. |
| Trace one payment | search both servers' logs for the `requestId` (proxy) / `request=` (Player API). |

## Development

No running services are needed for the checks:

```bash
npm ci
npm run check      # typecheck + eslint + tests (undici MockAgent, in-memory SQLite)
```
