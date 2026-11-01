# Final Threat Hunting delivery and acceptance

**Recorded:** 2026-11-01
**Production status:** ready and operational in the verified, bounded scope.

## Verified delivery

- Tenant-scoped profiles and encrypted archive import with SHA-256 integrity checks.
- Asynchronous analysis through the pipeline worker and status polling.
- Deterministic triage for packaged host/process/network and Windows service/task/startup sources; Linux fixed-path services/timers, cron and SUID/SGID inventory.
- Evidence-linked findings with source status, missing/empty/truncated indicators, timeline and host/process/endpoint graph.
- RU/EN Markdown and PDF reports; optional AI reports use bounded context and citation validation and remain advisory.
- Acceptance-only external campaign labels safely imported without production campaign binding.
- Production cutover smoke checks passed; existing tenant data, tenant keys, SQLite WAL, reports and non-hunting functions preserved.

## Final verification in this repository revision

- Full suite in disposable test environment: **280 passed, 15 skipped** (2026-11-01).
- FastAPI OpenAPI generated from source and validated: OpenAPI 3.1.0, **91 paths / 101 operations**.
- Documentation internal links and `git diff --check` pass.
- Production health/readiness, SPA assets and unauthenticated route checks passed during cutover. Readiness does not assert successful LDAP/WinRM integration on every tenant.

## Explicit Windows acceptance gate

Windows Security EVTX, PowerShell events, Defender events, RDP events, WMI persistence and Registry Run/RunOnce have **not** been tested on a live Windows endpoint. These sources remain `candidate` and are not included in production collector packages. Synthetic query/analyzer tests do not qualify as endpoint acceptance. Admission requires supported Windows version/build execution, privilege and policy coverage, positive/negative fixtures, success/empty/denied/error/truncated states, archive-to-UI verification and regression tests. Other Windows candidates listed in the coverage matrix remain gated as well.

Therefore “production-ready” means the currently packaged and verified capability set, not completion of every roadmap item or unrestricted DFIR. The module is bounded live-response triage: no memory capture, full-disk imaging or complete forensic chain-of-custody ledger. Missing/empty data never proves absence of compromise.

## Safe operation

Before upgrades, back up `.env` separately and take a consistent protected backup of `data`, `reports` and `certs` together; verify SHA-256 and restore readability. Preserve tenant private keys. Never use `docker compose down -v` during routine upgrades. Run an approved one-host pilot and review source states, evidence citations and data gaps before relying on reports.

See [BRD/FRD](BRD_FRD.md), [SAD](SAD.md), [Deployment Guide](DEPLOYMENT.md), [Operations/DR](OPERATIONS_DR.md), [API/DB reference](API_DATABASE.md), [OpenAPI snapshot](openapi.json), and [source coverage matrix](THREAT_HUNTING_COVERAGE.md).
