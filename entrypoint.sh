#!/bin/sh
set -e
mkdir -p /app/instance
chmod 777 /app/instance 2>/dev/null || true
exec gunicorn --bind 0.0.0.0:8080 --workers 1 --threads 4 --timeout 120 app:app
