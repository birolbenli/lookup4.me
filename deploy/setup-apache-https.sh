#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y certbot python3-certbot-apache

a2enmod proxy proxy_http headers rewrite ssl
systemctl stop nginx 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true

cat > /etc/apache2/sites-available/lookup4me.conf <<'EOF'
<VirtualHost *:80>
    ServerName fire.birolbenli.com

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "http"
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    ErrorLog ${APACHE_LOG_DIR}/lookup4me-error.log
    CustomLog ${APACHE_LOG_DIR}/lookup4me-access.log combined
</VirtualHost>
EOF

a2ensite lookup4me.conf
a2dissite 000-default.conf 2>/dev/null || true
apache2ctl configtest
systemctl reload apache2

certbot --apache -d fire.birolbenli.com --non-interactive --agree-tos -m birolbenli@gmail.com --redirect

# Ensure forwarded proto is https behind SSL vhost
if ! grep -q 'X-Forwarded-Proto "https"' /etc/apache2/sites-enabled/*lookup4me* 2>/dev/null; then
  sed -i 's/RequestHeader set X-Forwarded-Proto "http"/RequestHeader set X-Forwarded-Proto "https"/' /etc/apache2/sites-available/lookup4me*.conf || true
fi

apache2ctl configtest
systemctl reload apache2
sleep 2
ss -lntp | grep -E ':80|:443' || true
curl -sS -m 20 https://fire.birolbenli.com/health || true
echo
curl -sI -m 20 https://fire.birolbenli.com/tools/headers | head -15 || true
