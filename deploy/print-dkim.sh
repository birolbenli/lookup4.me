#!/bin/bash
# Run ON the VPS only. Do not embed sudo/login passwords here.
set -euo pipefail
cd /home/birolbenli/apps/lookup4.me
git pull
sudo docker compose up --build -d
sleep 6
sudo docker exec lookup4me python3 - <<'PY'
from tools.feedback_dkim import ensure_dkim_keys, dkim_dns_value, SELECTOR
ensure_dkim_keys()
print("SELECTOR", SELECTOR)
print(dkim_dns_value())
PY
curl -sS -X POST http://127.0.0.1:8080/api/feedback -H 'Content-Type: application/json' --data-binary @/tmp/feedback-test.json
echo
