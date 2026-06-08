# webshop deployment architecture

## single-merchant (this example)

```
hetzner CAX11 ($4.50/mo, arm64, 2 vCPU, 4GB)
├── zcli merchant watch     30MB, syncs every 5min
├── caddy                   15MB, auto-TLS, static files
└── /srv/shop/
    ├── static/             checkout HTML/JS
    ├── data/requests.json  written atomically by zcli watch
    └── id_zcli             ssh key (0600)
```

no docker needed. two systemd services. ~50MB total RAM.
works for a single shop accepting zcash.

## multi-merchant (zk.bot cloud)

for hosting many merchants on one VPS, use hwpay instead of zcli.
zcli syncs once per wallet. hwpay syncs once for ALL merchants — one
FVK covers every diversified address, so trial decryption is O(actions)
not O(actions * merchants).

```
hetzner CAX21 ($8/mo, arm64, 4 vCPU, 8GB)
├── hwpay (1 process)
│   ├── zcash listener      single sync, all merchants
│   ├── checkout API         /v1/checkout/sessions
│   ├── webhook delivery     HMAC-SHA256 signed
│   └── SQLite               sessions, deposits, merchants
├── caddy
│   ├── api.zk.bot          → proxy to hwpay:3000
│   ├── *.shop.zk.bot       → /srv/shops/{merchant}/static/
│   └── auto HTTPS
└── /srv/shops/
    ├── merchant1/          static checkout HTML
    ├── merchant2/
    └── ...
```

each merchant gets: subdomain, API key, webhook URL.
one $8/mo VPS handles hundreds of merchants.

## why not docker per merchant

each container would run its own zcash sync — same chain data
downloaded and decrypted N times. on a $10 VPS with 10 merchants
that's 10x the CPU and bandwidth for no isolation benefit (the
merchants already share a VPS).

docker makes sense as a deployment interface (reproducible builds,
easy updates), not as an isolation boundary. if you need tenant
isolation, use separate VPS per merchant, not containers.

## webhook vs file push

- same-machine: `--dir /srv/shop/data` writes requests.json atomically
  (tmpfile + fsync + rename, mode 0600). frontend reads the file.
  zero network surface.

- remote: `--webhook-url https://... --webhook-secret <secret>`
  outbound HTTPS POST only. no listening port on zcli.
  HMAC-SHA256 signature: `X-Signature: t=<unix_ts>,v1=<hex_hmac>`
  stripe-compatible format. body is full state dump (idempotent).

both can run simultaneously. belt and suspenders.
