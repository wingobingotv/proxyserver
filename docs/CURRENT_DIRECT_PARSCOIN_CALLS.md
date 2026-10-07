# Current direct ParsCoin calls (audit before migration)

Audited on 2026-10-07 across every repository in the WingoBingo workspace:
`backend` (Player API), `wingobingiadminapi`, `wingibingoadminpanel`,
`WingoBingo`, `wingobingo-telegram`, `wingobingostudio`, `bingo`,
`streaming`, `wingobingoaipresentor`.

Search terms: `parscoin`, `parscoinpay`, `createNewTransaction`,
`verifyTransaction`, `X-API-TOKEN`, `X-Sign-Hash`, `ir-card`, `irCard`,
`IrCardGateway`.

## Result

ParsCoin is integrated in **one place only**: the Player API (`backend`),
as the neutral adapter `gw_a` of the "Iranian card gateway"
(Visa/Mastercard pay-in for players whose country is Iran). No other
repository opens a connection to ParsCoin.

- `wingobingiadminapi` stores the adapter settings
  (`ir_card_gateway_settings`) and asks the Player API to verify a payment
  (`POST /internal/ir-card/payments/:id/verify`). It never calls ParsCoin.
- `wingibingoadminpanel` shows the settings and the callback URL. It never
  calls ParsCoin.
- The website and the Mini App only follow the `payment_url` that the
  Player API returns (a browser redirect, not a server-to-server call).

The ParsCoin host is hard-coded in the adapter
(`BASE_URL = "https://api.parscoinpay.org"`); credentials come from the
`ir_card_gateway_settings` row (`apiToken`, `merchantId`), not from env.

Only two ParsCoin API operations exist in our code, plus one inbound
webhook. No status, refund or cancel operation is used or documented in
the repository, so none is implemented in the proxy.

## Network touch points

| # | File | Function | ParsCoin endpoint | Purpose | Direction | Proxy operation | Migration risk |
|---|---|---|---|---|---|---|---|
| 1 | `backend/src/services/irCardGateways/gatewayA.js` | `createTransaction()` | `POST https://api.parscoinpay.org/v1/transactions/createNewTransaction` (header `X-API-TOKEN`; body `total_amount`, `description`, `client_ip`, `userid`, `redirect_url`) | Create the pay-in and get `payment_url` | Outgoing | `parscoin.payment.create` → `POST /v1/providers/parscoin/payment/create` | **High.** Not idempotent at ParsCoin (no idempotency key is documented). The proxy must never retry it after bytes were sent. The caller's "4xx → retry with the website return URL" fallback relies on the 4xx status coming back unchanged. |
| 2 | `backend/src/services/irCardGateways/gatewayA.js` | `verifyTransaction()` | `POST https://api.parscoinpay.org/v1/transactions/verifyTransaction` (header `X-API-TOKEN`; body `transaction_uuid`) | Ask whether the payment is verified (`is_verified`, `transaction_number`, `card_number`) | Outgoing | `parscoin.payment.verify` → `POST /v1/providers/parscoin/payment/verify` | **Medium.** Already called repeatedly by our code (see 2a–2d), so safe to retry on transport errors. `card_number` is payer card data: the proxy must never log it. |
| 2a | `backend/src/services/PaymentService.js` | `_verifyIrCardRow()` ← `applyIrCardWebhook()` | via #2 | Confirm a `transaction_confirmation` webhook before crediting | Outgoing (triggered by callback) | `parscoin.payment.verify` | Covered by #2. Must not bypass the proxy. |
| 2b | `backend/src/services/PaymentService.js` | `_verifyIrCardRow()` ← `_getIrCardPaymentStatus()` | via #2 | Player returns to the site / Mini App and the page polls `getPayment` (at most every 10 s) | Outgoing | `parscoin.payment.verify` | Covered by #2. |
| 2c | `backend/src/services/PaymentService.js` | `_verifyIrCardRow()` ← `reconcileIrCardPayments()` (cron `paymentReconcileCron.js`) | via #2 | Safety net for lost webhooks: open IR card pay-ins from the last 24 h | Outgoing | `parscoin.payment.verify` | Covered by #2. Keeps working while callbacks are being migrated. |
| 2d | `backend/src/services/PaymentService.js` | `_verifyIrCardRow()` ← `verifyIrCardPayment()` ← `PaymentController.internalVerifyIrCardPayment` / `verifyTransaction` | via #2 | Admin panel "Verify" and `/verifyTransaction` | Outgoing | `parscoin.payment.verify` | Covered by #2. |
| 3 | `backend/src/controllers/PaymentController.js` (route `POST /webhooks/ir-card` in `backend/src/routes/index.js`) | `irCardWebhook()` → `gatewayA.verifyWebhookSignature()` → `PaymentService.applyIrCardWebhook()` | Inbound from ParsCoin. JSON body with `event`, `uuid`, `event_timestamp`, `amount`, `currency`, `transaction_status`, `is_completed`, `transaction_number`, `card_number`. Header `X-Sign-Hash` = hex(HMAC-SHA512(key = first 16 chars of merchant ID, data = `uuid + event_timestamp`)) | Payment callback | Incoming | `/callback/<PARSCOIN_CALLBACK_SLUG>` on the proxy → forwarded to `MAIN_BACKEND_BASE_URL + PARSCOIN_CALLBACK_PATH` (`/webhooks/ir-card`) | **High.** The signature covers only `uuid` and `event_timestamp`, not the amount or status. The proxy de-duplicates on `event:uuid:event_timestamp` and rejects a replay whose body differs (409). Backend response codes carry meaning: 200 is final, 502 means "verification pending, redeliver", 401 means bad signature, 503 means not configured. Crediting stays in the backend (`_creditDepositOnce`, an atomic claim). |
| 4 | `wingibingoadminpanel/src/app/(main)/finance/iranian-payments/settings/page.tsx` | `WEBHOOK_URL` constant | Displays `${NEXT_PUBLIC_PLAYER_API_BASE_URL}/webhooks/ir-card` | Tells admins which callback URL to give the provider | Display only | Show the proxy callback URL from the Admin API (`IR_CARD_WEBHOOK_URL`) | Low. If left alone, admins would hand ParsCoin the direct Player API URL. |

## Not ParsCoin traffic (no change)

- `redirect_url` / `payment_url`: the player's browser goes to ParsCoin and
  comes back to the website or the Mini App. This is not server-to-server
  and stays as it is.
- `IrCardGatewayService.getSettings()`: database only.

## Migration order

1. Deploy `wingobingo-proxy` and register its public IP with ParsCoin (IP whitelist).
2. Backend: set `IR_CARD_GATEWAY_TRANSPORT=proxy` (#1, #2 and every path in 2a–2d).
   Roll back with `IR_CARD_GATEWAY_TRANSPORT=direct`.
3. Admin API: set `IR_CARD_WEBHOOK_URL`, so the panel shows the proxy URL (#4).
4. In the ParsCoin merchant panel, change the callback URL to that proxy URL (#3).
   The backend keeps accepting signed direct callbacks until step 5.
5. Backend: set `IR_CARD_WEBHOOK_REQUIRE_PROXY=true`, so a callback that did
   not come through the proxy is refused.

Detailed steps and rollbacks: [`WINGOBINGO_BACKEND_CHANGES.md`](WINGOBINGO_BACKEND_CHANGES.md).
