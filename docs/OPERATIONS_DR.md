# Operations, Runbooks and Disaster Recovery

Set organization-specific availability objectives, RPO/RTO, retention and escalation owners; the product does not promise numeric SLOs. Restrict SSH/sudo/Docker, and assign owners for platform, DB/evidence, tenant access, TLS, directory connectivity and recovery.

## Routine monitoring

```bash
docker compose ps
docker compose logs --since=15m ad-security-core ad-security-pipeline-worker
docker system df
df -h
curl -kfsS https://127.0.0.1:9443/health/ready
```

Monitor core/worker restarts, readiness, auth anomalies, queued/running/stale/failed job counts, disk and volume growth, SQLite errors/locking, backup age/restore drill, TLS expiry, LDAP/LDAPS and WinRM reachability, notification/AI failures. Readiness is not an end-to-end integration check. Keep evidence, passwords, keys and request bodies out of logs/tickets.

## Runbook: service not ready

1. Inspect `docker compose ps -a` and recent core/worker logs; identify init, core, DB or worker failure.
2. Check disk/memory, Docker daemon, port, mount and file ownership.
3. Probe local `/health/ready`; separate platform readiness from directory integration checks.
4. Verify DNS, routing, service account, target policy and trusted CA for LDAP/WinRM. Do not disable TLS verification as a workaround.
5. For backlog, inspect worker health/job state/shared `data` mount. Retry only verified failed/stale jobs via supported UI/API; never edit live SQLite manually.
6. Preserve volumes and redacted logs before invasive recovery; escalate with timestamp and release digest.

## Runbook: failed/stuck hunting job

Record tenant, job/result/profile IDs and UTC time. Check job status, worker, age, source errors, profile/package and original archive/hash. Confirm no active worker owns task before retry. Avoid duplicate imports; import identity is tenant/hash scoped. Preserve encrypted archive and logs if recurring; restore only under DR process.

## Consistent backup

1. Announce maintenance; stop writers: `docker compose stop ad-security-core ad-security-pipeline-worker`.
2. Back up `.env` separately, encrypted and access controlled.
3. Resolve actual project-prefixed volume names with `docker volume ls`/`docker inspect`; archive `data`, `reports`, `certs` as one coordinated set while quiesced. Preserve ownership/permissions, DB/WAL state, tenant private keys, reports and TLS material. Do not copy only the live SQLite main file.
4. Include compose/config and exact release/image digest separately.
5. Compute SHA-256; check archive readability and expected contents; encrypt at rest and transfer to approved storage.
6. Restart using `docker compose start`; verify readiness and worker health.
7. Rehearse restore on an isolated host on an agreed cadence and record actual RPO/RTO.

## Disaster recovery / restore

1. Declare incident, isolate affected host and preserve logs/snapshots. Do not overwrite the only evidence copy.
2. Provision compatible clean Linux/Docker host; retrieve matching release, Compose config, `.env` and tenant keys through approved secret recovery.
3. Ensure all application processes are stopped. Restore `data`, `reports`, `certs` from the same point-in-time set with ownership and permissions intact. Never pair DB and keys from different backup points.
4. Start matching release in isolated network first. Verify DB opens, tenant/company/user counts, keys, reports, profiles/imports/results and backup hashes.
5. Test readiness, authenticated login, tenant-scoped read-only reports/imports and worker state. Reconcile jobs only with supported operations.
6. Obtain approval to switch traffic; monitor, record actual recovery point/time and retain original host/backup isolated until released by incident owner.

Lost tenant private keys may make encrypted archives unrecoverable. If database, key and report set is inconsistent, stop and escalate rather than guessing.

## Security incident / routine care

For suspected compromise, restrict network, preserve logs/volumes, rotate secrets from a clean admin environment and follow organizational IR; avoid destructive container/volume cleanup. Routine care includes supported security updates, restore drills, TLS/disk/account review, queue/retention review and keeping candidate-source claims synchronized with accepted coverage. This tool is not a forensic imaging system.
