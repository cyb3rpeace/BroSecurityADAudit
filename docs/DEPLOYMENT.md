# Production Deployment Guide

## Baseline

Linux x86-64, Ubuntu 22.04/24.04, Docker Engine 24+, Docker Compose 2.20+, Git and Bash. Documented minimum 4 CPU/8 GB RAM/40 GB disk; recommended 8 CPU/16 GB/80 GB. These are baseline estimates, not guaranteed sizing. Plan TCP 9443 (or custom port), controlled host access, outbound HTTPS for build dependencies and required outbound directory/WinRM routes.

## Pre-deployment

1. Approve change window, owner, rollback window, firewall and monitoring.
2. Plan DNS and trusted TLS certificate; replace initial self-signed certificate before broad use.
3. Validate LDAP/LDAPS and WinRM reachability, least-privilege accounts and CA trust. Do not bypass TLS verification to hide certificate errors.
4. Verify host backup/disk monitoring and restrict Docker daemon membership (Docker access is effectively root).
5. Review release provenance, release notes and [source coverage](THREAT_HUNTING_COVERAGE.md).

## Fresh installation

```bash
git clone https://github.com/cyb3rpeace/BroSecurityADAudit.git
cd BroSecurityADAudit
bash install.sh
```

Installer validates Docker/Compose, creates `.env` and random `SESSION_SECRET` if absent, builds image, initializes named volumes and starts API and worker. It does not install Docker, change firewall, join domain or execute collectors. Never commit `.env`.

```bash
docker compose ps
docker compose logs --tail=100 ad-security-core ad-security-pipeline-worker
curl -kfsS https://127.0.0.1:9443/health/ready
```

Open `https://<server>:9443`. Read initial admin password on-host with `docker compose exec ad-security-core cat /opt/ad-audit/data/initial-admin.txt` unless set before initial empty DB. Rotate it. Create tenant/users and configure directory and integrations in authenticated UI.

`HTTPS_PORT` sets host port; `BIND_ADDRESS` controls published address (`0.0.0.0` default, `127.0.0.1` for local reverse proxy). `/health/ready` indicates application readiness, not successful LDAP/WinRM or every integration. Monitor worker separately.

## Upgrade

1. Record current release/image digest, compose/config and rollback image.
2. Perform and verify coordinated backup of `data`, `reports`, `certs` and separately protected `.env` per [DR runbook](OPERATIONS_DR.md).
3. Review release notes, schema effects and collector allowlist. Deploy a reviewed release/tag, not an unreviewed branch.
4. Preserve Compose project and named volumes.
5. Verify service health, readiness, worker progress, SPA, authenticated login, tenant list, approved profile/package/import workflow and existing report.
6. Monitor logs, disk, DB and queue for the change window; record final digest and result.

`docker compose down` preserves named volumes. **Never run `docker compose down -v` for upgrade or rollback** unless permanent volume/key deletion is explicitly intended and backups verified.

## Rollback and evidence

Stop new services without deleting volumes. Re-deploy the prior release against the same DB only after schema compatibility is confirmed. Otherwise restore the coordinated pre-upgrade backup to an isolated/approved path before switching traffic. Never run two versions concurrently against the same SQLite file. Record change ID, approval, release/image digest, backup hash, pre/post tenant counts, health and authenticated smoke results, worker state, monitoring period and rollback decision. Exclude secrets/evidence.
