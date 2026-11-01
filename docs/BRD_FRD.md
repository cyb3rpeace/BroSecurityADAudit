# BRD / FRD: Business and Functional Requirements

**Purpose.** BroSecurityADAudit is a self-hosted platform for authorized Active Directory posture assessment and bounded, evidence-based host triage. It gives security teams repeatable checks, tenant-separated workflows, reviewable evidence and reports without requiring external AI. It complements, but does not replace, EDR, SIEM, full incident response, forensic imaging or organizational case management.

## Stakeholders

- Platform administrator: tenant, user and platform administration.
- Tenant administrator / analyst: directory settings, scans, hunting profiles, evidence review and reports within an authorized company.
- Directory/endpoint operator: provisions approved LDAP/LDAPS and WinRM access; executes authorized collector packages.
- Platform operator: deployment, monitoring, backup, restore, upgrades and incident escalation.

## Business requirements

| ID | Requirement | Verification |
| --- | --- | --- |
| BR-01 | Enforce tenant data isolation. | Tenant authorization tests and scoped API reads. |
| BR-02 | Run configured directory posture checks. | Scan history, findings and logs. |
| BR-03 | Collect bounded host evidence and import encrypted results. | Package allowlist, integrity/import tests. |
| BR-04 | Make findings reviewable against source evidence. | Source/row citations, source status and archive hash. |
| BR-05 | Keep deterministic workflows functional without AI. | No-AI analysis tests. |
| BR-06 | Recover DB, reports and tenant keys. | Coordinated backup and isolated restore rehearsal. |
| BR-07 | Deploy in customer-controlled Linux/Docker environment. | Fresh-install guide and readiness checks. |

## Functional requirements

| ID | Capability | Requirement |
| --- | --- | --- |
| FR-01 | Identity | Authenticated sessions, roles, tenant scope and account controls. |
| FR-02 | Directory audit | LDAP/LDAPS and authorized WinRM checks; TLS verification enabled by default. |
| FR-03 | Profiles | Validate OS, artifact allowlist and bounds; generate package/spec/guide. |
| FR-04 | Import | Validate encrypted tenant archive, format/size and SHA-256 integrity. |
| FR-05 | Pipeline | Persist async jobs; expose status/retry and recover stale jobs. |
| FR-06 | Triage | Deterministic evidence-linked findings, timeline and graph; absence of data is not evidence of safety. |
| FR-07 | Reports | RU/EN Markdown/PDF; optional bounded AI remains advisory and citation-checked. |
| FR-08 | Operations | Readiness, persistent volumes, monitoring, backup, restore and rollback. |

## Non-functional requirements

Least privilege, verified TLS, tenant authorization, protected credentials/volumes, encrypted backups, bounded collector behavior, localized outputs, testable releases and documented source coverage. A single-host Compose deployment does not provide HA. Configured row/time limits do not bound every endpoint scan cost or OS impact.

## Production scope and acceptance

The platform is **production-ready in the verified, packaged scope** stated in [README](../README.md#production-readiness-statement), [Threat Hunting final record](THREAT_HUNTING_FINAL.md) and [coverage matrix](THREAT_HUNTING_COVERAGE.md). Windows Security/PowerShell/Defender/RDP EVTX, WMI persistence and Registry Run/RunOnce have not passed live Windows acceptance; they remain `candidate` and are excluded from production packages. Memory capture, full disk imaging, complete DFIR and complete Linux log/account/SSH/PAM collection are out of scope.

Admit a candidate source only after supported-version endpoint execution, privilege/error/empty/truncated state checks, positive/negative fixtures, archive-to-UI validation and regression tests. Each production change requires approved backup, build/source provenance, readiness and authenticated workflow smoke checks, tenant/data preservation, monitoring and rollback record.
