#!/bin/bash
set -e
# Clean HTTP vhost: only redirect to HTTPS (no proxy).
cat > /tmp/lookup4me-http.conf <<'EOF'
<VirtualHost *:80>
    ServerName tools.birolbenli.com
    ServerAlias fire.birolbenli.com
    RewriteEngine on
    RewriteRule ^ https://tools.birolbenli.com%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>
EOF

# SSL vhost only on 443
cat > /tmp/lookup4me-ssl.conf <<'EOF'
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName tools.birolbenli.com
    ServerAlias fire.birolbenli.com

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-For "%{REMOTE_ADDR}s"
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    ErrorLog ${APACHE_LOG_DIR}/lookup4me-error.log
    CustomLog ${APACHE_LOG_DIR}/lookup4me-access.log combined

    Include /etc/letsencrypt/options-ssl-apache.conf
    SSLCertificateFile /etc/letsencrypt/live/tools.birolbenli.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/tools.birolbenli.com/privkey.pem
</VirtualHost>
</IfModule>
EOF

cp /tmp/lookup4me-http.conf /etc/apache2/sites-available/lookup4me.conf
cp /tmp/lookup4me-ssl.conf /etc/apache2/sites-available/lookup4me-le-ssl.conf
a2enmod rewrite headers proxy proxy_http ssl >/dev/null
a2ensite lookup4me.conf lookup4me-le-ssl.conf >/dev/null
apache2ctl configtest
systemctl reload apache2
echo "Apache HTTPS redirect OK"
curl -sI -m 15 http://tools.birolbenli.com/ | head -15
echo "----"
curl -sI -m 15 https://tools.birolbenli.com/health | head -10
