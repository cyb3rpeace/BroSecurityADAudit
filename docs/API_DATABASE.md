# API, OpenAPI and Database Reference

## OpenAPI and authentication

FastAPI serves the live contract at `/openapi.json`, Swagger UI at `/docs` and ReDoc at `/redoc` if enabled in the deployed build. This describes registered REST paths/models but not binary collector formats, all integration behavior or internal worker persistence. The checked-in `openapi.json` is a source-version snapshot; refresh it for each API contract release. Authenticated clients use the login/session cookie flow and tenant authorization. Do not put credentials in URL parameters; verify TLS.

## Principal route groups

| Group | Representative use | Boundary |
| --- | --- | --- |
| `/health`, `/health/ready` | Liveness/readiness | Not a directory integration certification. |
| `/api/login`, `/logout`, `/me` | Session/profile | Authentication/session controls. |
| `/api/companies`, `/api/users` | Tenant/account administration | Administrative roles and company scope. |
| `/api/dashboard`, `/api/run-task`, `/api/scans` | Directory scan/history | Authenticated tenant. |
| `/api/threat-hunting/catalog`, `/profiles` | Catalog/profile lifecycle | Tenant-scoped. |
| `/api/threat-hunting/profiles/{id}/package` | Collector package | Owner/profile and allowlist validation. |
| `/api/threat-hunting/import` | Encrypted archive import | Authenticated tenant key. |
| `/api/threat-hunting/pipeline/jobs` | Async job status/retry | Tenant/operator authorization. |
| `/api/threat-hunting/results` | List, rows, analysis, export, retention | Tenant-scoped evidence access. |
| `/api/threat-hunting/campaigns`, `/workers/*` | Campaign/task orchestration | Authorized state transitions. |
| `/api/threat-hunting/*/ai-report`, `/external-analysis/*` | Optional analysis | Tenant and external-data policy. |

Use generated OpenAPI as authority for exact method, parameters, models and status codes. Handle 401/403/404/409/validation errors deliberately. Retry only idempotent operations or after verifying job/import state; use bounded backoff for transient failures. Redact diagnostics before tickets.

## SQLite data model

SQLite is stored in the persistent application `data` volume. Core directory/account/scan schema is initialized by `app/database.py`. Hunting modules initialize tables in the same DB:

| Table | Module | Representative fields / purpose |
| --- | --- | --- |
| `profiles` | `hunting_profiles.py` | `id`, `company_id`, `created_at`, serialized `body`. |
| `imports` | `hunting_results.py` | `id`, `company_id`, `sha256`, `size`, timestamp, summary; unique tenant/hash. |
| `reviews` | `hunting_results.py` | Finding disposition/note keyed by company/result/finding. |
| `jobs` | `hunting_pipeline.py` | Durable pipeline state, owner and timestamps. |
| `events` | `hunting_pipeline.py` | Pipeline/job transition and diagnostic history. |

Other result, campaign, worker task, audit, notification and core tables vary by release. Use source initializers for exact deployed schema; do not edit production schema manually. Back up DB with tenant keys and reports.

SHA-256 checks byte consistency against the stored digest; it does not prove origin, endpoint identity or completeness. DB/volumes may contain personal data, security findings, tenant private keys and encrypted evidence; restrict access and encrypt backups.
