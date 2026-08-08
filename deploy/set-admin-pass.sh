#!/bin/bash
# Run ON the VPS only. Never commit real passwords into this file.
# Usage: ADMIN_PASSWORD='...' bash deploy/set-admin-pass.sh
#    or: bash deploy/set-admin-pass.sh   # generates a random password
set -euo pipefail
cd /home/birolbenli/apps/lookup4.me

PASS="${ADMIN_PASSWORD:-${1:-}}"
if [ -z "$PASS" ]; then
  PASS="$(python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(16)))')"
fi

sed -i '/^ADMIN_USER=/d' .env
sed -i '/^ADMIN_PASSWORD=/d' .env
sed -i '/^ADMIN_SETUP_TOKEN=/d' .env
printf 'ADMIN_USER=admin\nADMIN_PASSWORD=%s\n' "$PASS" >> .env

sudo docker compose up -d --force-recreate
sleep 3
sudo docker compose exec -T lookup4me python -c \
  "import sqlite3; c=sqlite3.connect('/app/instance/admin.db'); c.execute(\"DELETE FROM settings WHERE key IN ('totp_secret','totp_active')\"); c.commit(); print('totp reset')"

echo "ADMIN_USER=admin"
echo "ADMIN_PASSWORD=$PASS"
curl -sS -m 10 -H 'X-Forwarded-Proto: https' http://127.0.0.1:8080/health || true
echo
