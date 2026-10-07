# WingoBingo changes for the proxy

The payment logic is unchanged: amounts, statuses, crediting, reconcile cron,
admin verify and webhook processing. Only the transport of the ParsCoin calls
moved, and the webhook can additionally be checked for the proxy's signature.
Every change is off by default.

## Player API (`backend`)

| File | Change |
|---|---|
| `src/services/PaymentProxyClient.js` (new) | `post(path, payload, { timeoutMs })` signs with HMAC v1 and posts via axios (no redirects); it resolves and rejects like `axios.post`. `verifyForwardedCallback(req)` checks the proxy's signature on a relayed webhook: key, ±300 s, nonce replay, exact raw body and URL. |
| `src/services/irCardGateways/gatewayA.js` | One `post()` helper. With `IR_CARD_GATEWAY_TRANSPORT=proxy`, create and verify go to `${PAYMENT_PROXY_URL}/v1/providers/parscoin/payment/{create,verify}` with the same body and no `X-API-TOKEN`. The response parsing and error shape are untouched, so every caller (website return, cron reconcile, admin verify, webhook re-verify) moves at once. |
| `server.js` | Keeps the raw body for `/webhooks/ir-card` too (as for `/webhooks/riverpe`). |
| `src/controllers/PaymentController.js` `irCardWebhook` | If proxy headers are present, they must verify (else 401, which the proxy retries). With `IR_CARD_WEBHOOK_REQUIRE_PROXY=true`, a webhook without them is refused. The provider's `X-Sign-Hash` check and everything after it are unchanged. Logs carry the relay `request=` id. |
| `src/config/environment.js` | `Environment.paymentProxy`. |
| `.env.example` | New variables below. |
| `src/services/PaymentProxyClient.test.js` (new) | Shared signature vector, relay verification, both transports. |

New variables:

| Variable | Value |
|---|---|
| `PAYMENT_PROXY_URL` | proxy origin, e.g. `https://<proxy-domain>` |
| `PAYMENT_PROXY_KEY_ID` / `PAYMENT_PROXY_SECRET` | one `relay` entry of the proxy's `INTERNAL_HMAC_KEYS` |
| `PAYMENT_PROXY_CALLBACK_KEYS` | `id:secret` = the proxy's `BACKEND_CALLBACK_SIGNING_KEY_ID:BACKEND_CALLBACK_SIGNING_SECRET` (comma-separate old and new while rotating) |
| `IR_CARD_GATEWAY_TRANSPORT` | `direct` (default) or `proxy` |
| `IR_CARD_WEBHOOK_REQUIRE_PROXY` | `false` (default) or `true` |

Credentials: in proxy mode the API token sent to ParsCoin is the proxy's
`PARSCOIN_API_TOKEN`. The token saved in the admin panel stays required (it
marks the gateway as configured) and is used again if you switch back to
`direct`. The merchant ID must be identical in the panel and in the proxy:
both check webhook signatures with it.

## Admin API (`wingobingiadminapi`)

`services/irCardSettings.service.ts`: the settings response gains `webhookUrl`,
taken from `IR_CARD_WEBHOOK_URL` (https only; `null` when unset).

| Variable | Value |
|---|---|
| `IR_CARD_WEBHOOK_URL` | `https://<proxy-domain>/callback/<PARSCOIN_CALLBACK_SLUG>` |

## Admin panel (`wingibingoadminpanel`)

Finance → Iranian payments → Settings shows `webhookUrl` when set (otherwise
the Player API URL as before). The hint then says to give the provider the
payment proxy server's IP, and that the request token is the one on the proxy.

## Rollout (each step reversible)

1. Deploy the proxy with `PARSCOIN_ENABLED=true`. Check `/readyz`.
2. Ask ParsCoin to whitelist `WINGOBINGO_PROXY_PUBLIC_IP` (keep the Player API IP for now).
3. Player API: set the `PAYMENT_PROXY_*` variables and
   `IR_CARD_GATEWAY_TRANSPORT=proxy`, then deploy. Make one small test
   deposit. Rollback: `IR_CARD_GATEWAY_TRANSPORT=direct`.
4. Admin API: set `IR_CARD_WEBHOOK_URL`, then deploy. Change the callback URL
   in the ParsCoin merchant panel to the value now shown in the admin panel.
   Confirm a callback shows as `delivered` (proxy log or `/v1/admin/callbacks`).
5. Player API: `IR_CARD_WEBHOOK_REQUIRE_PROXY=true`, then deploy. Rollback:
   `false`, and point the callback URL back to the Player API.
6. Optionally ask ParsCoin to remove the Player API IP from their whitelist.
