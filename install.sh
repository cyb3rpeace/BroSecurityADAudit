#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
command -v docker >/dev/null || { echo "Install Docker Engine and Docker Compose v2 first." >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker daemon is unavailable or permission is denied." >&2; exit 1; }
docker compose version >/dev/null || { echo "Docker Compose v2 is required." >&2; exit 1; }
compose_version=$(docker compose version --short | tr -d v)
IFS=. read -r major minor rest <<< "$compose_version"
if (( major < 2 || (major == 2 && minor < 20) )); then
  echo "Docker Compose 2.20+ is required for readiness waits." >&2; exit 1
fi
if [[ ! -e .env ]]; then
  # Generate entropy inside the build runtime; no host Python/OpenSSL required.
  secret=$(docker run --rm --entrypoint python python:3.11-slim -c 'import secrets; print(secrets.token_hex(32))')
  [[ "$secret" =~ ^[a-f0-9]{64}$ ]] || { echo "Secret generation failed" >&2; exit 1; }
  printf 'SESSION_SECRET=%s\nINITIAL_ADMIN_PASSWORD=\nHTTPS_PORT=9443\nLDAP_TLS_VERIFY=true\nWINRM_TLS_VERIFY=true\nUSE_LOCAL_LLM=false\n' "$secret" > .env
fi
chmod 600 .env
if ! docker compose config --environment | grep -Eq '^SESSION_SECRET=[[:alnum:]_-]{32,}$'; then
  echo "Set a random SESSION_SECRET (at least 32 characters) in .env. Existing configuration was not overwritten." >&2
  exit 1
fi
if grep -Eqi 'change-me|GENERATE_WITH_INSTALL_SH' .env; then
  echo "Replace placeholder secrets in .env; existing configuration was not overwritten." >&2
  exit 1
fi
docker compose config --quiet
port=$(docker compose config --environment | sed -n "s/^HTTPS_PORT=//p")
docker compose up -d --build --wait --wait-timeout 240
printf '\nInstallation ready. Open https://SERVER_ADDRESS:%s (default 9443).\n' "${port:-9443}"
printf 'Login: admin. Retrieve the generated password securely:\n  docker compose exec ad-security-core cat /opt/ad-audit/data/initial-admin.txt\n'
printf 'Keep this password private and change it after login. Configure company/LDAPS and optional AI API in Settings.\n'
