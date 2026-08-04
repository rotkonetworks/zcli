#!/bin/sh
# deploy single-merchant zcash webshop on a fresh hetzner VPS
# no docker — systemd + caddy + zcli binary
#
# usage: ssh root@vps 'bash -s' < deploy.sh
#
# assumes: zcli binary already copied to /usr/local/bin/zcli
#          ssh identity key at /srv/shop/id_zcli
#
# total resource usage: ~30MB RAM, ~0 CPU between syncs
# a $4.50/mo CAX11 (arm64) handles this easily

set -eu

SHOP_DIR="/srv/shop"
SHOP_USER="shop"
DOMAIN="${SHOP_DOMAIN:-shop.example.com}"
FORWARD="${FORWARD_ADDRESS:-}"

# create unprivileged user
id -u "$SHOP_USER" >/dev/null 2>&1 || useradd -r -s /bin/false -d "$SHOP_DIR" "$SHOP_USER"

# directory structure
mkdir -p "$SHOP_DIR"/{static,data}
chown -R "$SHOP_USER:$SHOP_USER" "$SHOP_DIR"

# install caddy (debian/ubuntu)
if ! command -v caddy >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y -qq caddy
fi

# caddyfile
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    root * $SHOP_DIR/static
    file_server

    handle /requests.json {
        root * $SHOP_DIR/data
        file_server
    }

    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy no-referrer
    }
}
EOF

systemctl enable caddy
systemctl restart caddy

# zcli watch service
cat > /etc/systemd/system/zcli-merchant.service <<EOF
[Unit]
Description=zcli merchant watch
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SHOP_USER
ExecStart=/usr/local/bin/zcli merchant watch --dir $SHOP_DIR/data --interval 300
Environment=ZCLI_IDENTITY=$SHOP_DIR/id_zcli
Environment=ZCLI_FORWARD=$FORWARD
Environment=HOME=$SHOP_DIR
Restart=always
RestartSec=30

# hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$SHOP_DIR
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictRealtime=true
MemoryDenyWriteExecute=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable zcli-merchant
systemctl start zcli-merchant

echo "deployed: https://$DOMAIN"
echo "zcli-merchant: $(systemctl is-active zcli-merchant)"
echo ""
echo "next steps:"
echo "  1. copy zcli binary to /usr/local/bin/zcli"
echo "  2. copy ssh key to $SHOP_DIR/id_zcli"
echo "  3. copy static files to $SHOP_DIR/static/"
echo "  4. pre-create addresses: zcli merchant create 0.001 --json"
echo "  5. systemctl restart zcli-merchant"
