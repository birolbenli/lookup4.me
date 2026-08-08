#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y nginx certbot python3-certbot-nginx

cat > /etc/nginx/sites-available/lookup4me <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name tools.birolbenli.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
EOF

ln -sfn /etc/nginx/sites-available/lookup4me /etc/nginx/sites-enabled/lookup4me
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl restart nginx

# Obtain/renew certificate and auto-configure HTTPS
certbot --nginx -d tools.birolbenli.com --non-interactive --agree-tos -m birolbenli@gmail.com --redirect

systemctl reload nginx
sleep 2
systemctl --no-pager --full status nginx | head -20
ss -lntp | grep -E ':80|:443' || true
curl -sS -m 20 https://tools.birolbenli.com/health || true
echo
