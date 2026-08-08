#!/bin/bash
# Point Apache + Let's Encrypt at tools.birolbenli.com (run after DNS A record is live).
set -euo pipefail
DOMAIN=tools.birolbenli.com

a2enmod proxy proxy_http headers rewrite ssl

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
# Disable old fire vhost / leftover ssl names if present
a2dissite lookup4me-le-ssl.conf 2>/dev/null || true
rm -f /etc/apache2/sites-enabled/*fire* 2>/dev/null || true

apache2ctl configtest
systemctl reload apache2

certbot --apache -d "${DOMAIN}" --non-interactive --agree-tos -m birolbenli@gmail.com --redirect --reinstall

# Force https proto on SSL vhost(s)
sed -i 's/RequestHeader set X-Forwarded-Proto "http"/RequestHeader set X-Forwarded-Proto "https"/' \
  /etc/apache2/sites-available/lookup4me*.conf 2>/dev/null || true

apache2ctl configtest
systemctl reload apache2
echo "OK https://${DOMAIN}/health"
curl -sS -m 20 "https://${DOMAIN}/health" || true
echo
