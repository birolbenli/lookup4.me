#!/bin/bash
set -e
cd /home/birolbenli/apps/lookup4.me
git pull
sudo docker compose up --build -d
sleep 5
curl -sS -m 10 http://127.0.0.1:8080/health
echo
curl -sS -m 10 http://127.0.0.1:8080/ | head -c 400
echo
