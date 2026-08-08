#!/bin/bash
set -e
cd /home/birolbenli/apps/lookup4.me
git pull
sudo docker compose up --build -d
sleep 6
# Drop old 2048-bit keys so a DNS-friendly 1024-bit pair is generated
sudo docker exec lookup4me rm -f \
  /app/instance/feedback_dkim_private.pem \
  /app/instance/feedback_dkim_public.pem
sudo docker exec lookup4me python3 -c "
from tools.feedback_dkim import ensure_dkim_keys, dkim_dns_value, SELECTOR
ensure_dkim_keys()
v = dkim_dns_value()
print('SELECTOR', SELECTOR)
print('LEN', len(v or ''))
print('DNS_VALUE')
print(v)
"
curl -sS -X POST http://127.0.0.1:8080/api/feedback \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/feedback-test.json
echo
