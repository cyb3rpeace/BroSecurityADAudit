#!/bin/sh
set -eu
mkdir -p /opt/ad-audit/certs /opt/ad-audit/data /opt/ad-audit/reports
crt="${SSL_CERTFILE:-/opt/ad-audit/certs/server.crt}"
key="${SSL_KEYFILE:-/opt/ad-audit/certs/server.key}"
if [ ! -s "$crt" ] || [ ! -s "$key" ]; then
  openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$crt" -days 825 -nodes -subj "/CN=brosec-audit"
  chmod 600 "$key" || true
fi
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers \
  --ssl-certfile "$crt" --ssl-keyfile "$key"
