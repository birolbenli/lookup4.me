#!/bin/bash
set -e
cd /home/birolbenli/apps/lookup4.me
git pull
sed -i '/^ADMIN_USER=/d' .env
sed -i '/^ADMIN_PASSWORD=/d' .env
sed -i '/^ADMIN_SETUP_TOKEN=/d' .env
printf 'ADMIN_USER=admin\nADMIN_PASSWORD=1bKPkei7zEUcuZ\n' >> .env
echo Bb12345 | sudo -S docker compose up --build -d
sleep 5
echo Bb12345 | sudo -S docker compose exec -T lookup4me python -c "import sqlite3; c=sqlite3.connect('/app/instance/admin.db'); c.execute(\"DELETE FROM settings WHERE key IN ('totp_secret','totp_active')\"); c.commit(); print('totp reset')"
echo "LOGIN user=admin pass=1bKPkei7zEUcuZ"
curl -sS -m 10 http://127.0.0.1:8080/health; echo