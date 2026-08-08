#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y caddy
install -m 644 /tmp/Caddyfile /etc/caddy/Caddyfile
systemctl enable caddy
systemctl restart caddy
sleep 2
systemctl --no-pager --full status caddy | head -25
ss -lntp | grep -E ':80|:443' || true
curl -sI -m 15 https://fire.birolbenli.com/health || true
