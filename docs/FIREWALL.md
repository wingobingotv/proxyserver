# Firewall and IP whitelisting

Names used below:

| Name | What |
|---|---|
| `WINGOBINGO_PROXY_PUBLIC_IP` | public egress IP of the proxy server (what providers see) |
| `PLAYER_API_IP` | public egress IP of the Player API server (`INTERNAL_ALLOWED_IPS`) |
| `ADMIN_API_IP` | public egress IP of the Admin API (only if it uses an admin key) |
| `PARSCOIN_CALLBACK_IPS` | ParsCoin's callback source IPs, if they publish them |
| `MONITORING_IP` | Prometheus host |

## Proxy server — inbound

| Port | Source | Purpose |
|---|---|---|
| 443/tcp | any | provider callbacks (`/callback/…`); Nginx limits `/v1/…` to the IPs below |
| 80/tcp | any | ACME challenge and redirect to https only |
| 22/tcp | admin IPs / VPN only | SSH |
| everything else | — | deny |

The container port (`PROXY_HOST_PORT`) is bound to 127.0.0.1 and must never be
opened. If ParsCoin publishes callback IPs, you can restrict 443 to
`PARSCOIN_CALLBACK_IPS`, `PLAYER_API_IP`, `ADMIN_API_IP` and `MONITORING_IP`.
Set `PARSCOIN_CALLBACK_ALLOWED_IPS` as well, since the proxy checks it too.

```bash
ufw default deny incoming
ufw default allow outgoing     # or the egress list below
ufw allow from <admin-ip> to any port 22 proto tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

Docker publishes ports through iptables and bypasses ufw. That is why the
compose file binds to 127.0.0.1 only.

## Proxy server — outbound (if egress is restricted)

| Destination | Port | Purpose |
|---|---|---|
| ParsCoin API host (`PARSCOIN_BASE_URL`) | 443 | create / verify |
| Player API host (`MAIN_BACKEND_BASE_URL`) | 443 | callback delivery |
| DNS resolvers | 53 | name resolution |
| NTP | 123/udp | clock (signatures have a ±300 s window) |
| OS / Docker registries | 443 | updates and image builds only |

## Whitelists at other parties

| Where | Add | Remove |
|---|---|---|
| ParsCoin merchant panel (API IP whitelist) | `WINGOBINGO_PROXY_PUBLIC_IP` | `PLAYER_API_IP` once `IR_CARD_GATEWAY_TRANSPORT=proxy` is stable |
| ParsCoin merchant panel (callback URL) | `https://<proxy-domain>/callback/<slug>` | the old `…/webhooks/ir-card` URL |
| Player API firewall / WAF | allow `WINGOBINGO_PROXY_PUBLIC_IP` to `POST /webhooks/ir-card` | — |
| Proxy `.env` `INTERNAL_ALLOWED_IPS` | `PLAYER_API_IP` (+ `ADMIN_API_IP`) | — |
| Proxy Nginx `allow` | same as above, per location | — |
