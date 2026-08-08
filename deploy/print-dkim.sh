#!/bin/bash
set -e
cd /home/birolbenli/apps/lookup4.me
git pull
echo 'Bb12345' | sudo -S docker compose up --build -d
sleep 6
echo 'Bb12345' | sudo -S docker exec lookup4me python3 - <<'PY'
from tools.feedback_dkim import ensure_dkim_keys, dkim_dns_value, SELECTOR
ensure_dkim_keys()
print("SELECTOR", SELECTOR)
print(dkim_dns_value())
PY
curl -sS -X POST http://127.0.0.1:8080/api/feedback -H 'Content-Type: application/json' --data-binary @/tmp/feedback-test.json
echo
