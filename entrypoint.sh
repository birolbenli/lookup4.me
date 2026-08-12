#!/bin/sh
set -e
mkdir -p /app/instance
chmod 777 /app/instance 2>/dev/null || true

# Single worker + threads fits 300–512MB. max-requests recycles leaked memory.
# timeout must exceed longest external probe; busy tools are concurrency-limited in-app.
exec gunicorn \
  --bind 0.0.0.0:8080 \
  --workers 1 \
  --threads "${GUNICORN_THREADS:-6}" \
  --worker-class gthread \
  --timeout "${GUNICORN_TIMEOUT:-90}" \
  --graceful-timeout 25 \
  --keep-alive 5 \
  --max-requests "${GUNICORN_MAX_REQUESTS:-120}" \
  --max-requests-jitter 30 \
  --access-logfile - \
  --error-logfile - \
  app:app
