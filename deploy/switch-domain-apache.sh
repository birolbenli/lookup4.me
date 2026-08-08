#!/bin/bash
# Point Apache + Let's Encrypt at tools.birolbenli.com (run after DNS A record is live).
set -euo pipefail
DOMAIN=tools.birolbenli.com

a2enmod proxy proxy_http headers rewrite ssl

# Remove old fire.* site configs if present
rm -f /etc/apache2/sites-enabled/*fire* 2>/dev/null || true
rm -f /etc/apache2/sites-available/*fire* 2>/dev/null || true

cat > /etc/apache2/sites-available/lookup4me.conf <<EOF
<VirtualHost *:80>
    ServerName ${DOMAIN}

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "http"
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    ErrorLog \${APACHE_LOG_DIR}/lookup4me-error.log
    CustomLog \${APACHE_LOG_DIR}/lookup4me-access.log combined
</VirtualHost>
EOF

a2ensite lookup4me.conf
a2dissite 000-default.conf 2>/dev/null || true
a2dissite lookup4me-le-ssl.conf 2>/dev/null || true

apache2ctl configtest
systemctl reload apache2

certbot --apache -d "${DOMAIN}" --non-interactive --agree-tos -m birolbenli@gmail.com --redirect --reinstall

# Ensure https proto on SSL vhost(s)
for f in /etc/apache2/sites-available/lookup4me*.conf; do
  [ -f "$f" ] || continue
  sed -i 's/RequestHeader set X-Forwarded-Proto "http"/RequestHeader set X-Forwarded-Proto "https"/' "$f" || true
  # Keep http vhost on http; fix only SSL file below
done

# http vhost should stay http; ssl vhost should be https
if [ -f /etc/apache2/sites-available/lookup4me.conf ]; then
  sed -i 's/RequestHeader set X-Forwarded-Proto "https"/RequestHeader set X-Forwarded-Proto "http"/' \
    /etc/apache2/sites-available/lookup4me.conf || true
fi
if [ -f /etc/apache2/sites-available/lookup4me-le-ssl.conf ]; then
  sed -i 's/RequestHeader set X-Forwarded-Proto "http"/RequestHeader set X-Forwarded-Proto "https"/' \
    /etc/apache2/sites-available/lookup4me-le-ssl.conf || true
  # Ensure ServerName is tools
  sed -i "s/ServerName .*/ServerName ${DOMAIN}/" /etc/apache2/sites-available/lookup4me-le-ssl.conf || true
fi

a2ensite lookup4me-le-ssl.conf 2>/dev/null || true
apache2ctl configtest
systemctl reload apache2
sleep 2
echo "OK https://${DOMAIN}/health"
curl -sS -m 20 "https://${DOMAIN}/health" || true
echo
curl -sI -m 15 "https://${DOMAIN}/" | head -20 || true
