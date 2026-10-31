# Threat Hunting Source Coverage Audit

**Audit date:** 2026-10-31
**Audited revision:** `083a1da38e63e513aea00366b409905b940ef080`
**Scope:** profile catalog, package compiler, Linux and Windows query modules, ingest/provenance, analysis, tests, and documentation in this repository.

This is a source-tree inventory, not a forensic completeness claim. A catalog item, query string, synthetic fixture, package build, or parser test does not prove execution on a target OS. `execution_verified` remains false unless a real-engine collection acceptance on the stated target is recorded.

## Status definitions

- **Packaged:** admitted by profile compiler into an offline collector. This does not establish target execution or completeness.
- **Linux disposable acceptance:** packaged executable ran in an isolated Linux container against inert fixtures, followed by encrypted import, analysis, and evidence-row resolution. This is not a distribution/version/privilege matrix.
- **Synthetic contract:** query/projection/parser behavior tested with synthetic rows or fixtures; no acquisition on the relevant target OS was verified.
- **Candidate / not packaged:** catalog or server-side query exists, intentionally excluded from executable packages.
- **Not implemented:** no acquisition source found in the audited profile/query/package path.

Privilege entries below are expectations, not measured per-source outcomes. Windows package invocation adds Velociraptor `--require_admin`; this is not a test of UAC elevation on each host. Linux instructions require an approved administrative session/root, but the executable does not enforce root for every source. Row limits cap output; they are not general limits on bytes, scan work, memory, or endpoint impact.

## Packaged source matrix

| Artifact | OS / status | Source and method | Privilege expectation | Test evidence | Limits and blind spots |
|---|---|---|---|---|---|
| Host (`host`, source `Host`) | Windows + Linux / packaged | Velociraptor `info()` projection: hostname, FQDN, OS, platform, architecture; 1 row | Windows admin package; approved Linux admin session | Profile/compiler, ingest, archive and analysis tests; Linux disposable acceptance | Snapshot only; no clock-offset measurement or authenticated host identity |
| Processes (`processes`, source `Processes`) | Windows + Linux / packaged | `pslist()`: PID, PPID, name, executable, username, command line, creation time; 10,000 rows | Elevated access expected for completeness | Contract tests; Linux disposable packaged acceptance and evidence resolution | Does not guarantee full ancestry, handles, memory, socket attribution, deleted-open executable detail, or atomic snapshot; command lines can contain secrets |
| Network (`network`, source `Network`) | Windows + Linux / packaged | `netstat()`; 20,000 rows | Elevated access expected for completeness | Contract tests; Linux disposable packaged acceptance | Current state, not history; process attribution/DNS history are not guaranteed |
| Services (`services`, source `Services`) | Windows / packaged | Normalized Windows service query plus built-in `Windows.System.Services` | Admin required by packaged runner | Compiler/parser tests; no Windows endpoint acceptance | Duplicate paths possible; built-in output cap not enforced by our source contract; hash/certificate enrichment disabled |
| Tasks (`tasks`, source `Tasks`) | Windows / packaged | Normalized query plus built-in `Windows.System.TaskScheduler` | Admin required | Compiler/parser tests; no Windows endpoint acceptance | Duplicate paths possible; uploads disabled; source/OS coverage unverified |
| Startup (`startup`, source `Startup`) | Windows / packaged | Normalized startup query plus `Windows.Sys.StartupItems` | Admin required | Compiler/parser tests; no Windows endpoint acceptance | User hives/startup folders can be incomplete; not full registry-hive acquisition |
| Linux services/timers (`linux_services`, source `LinuxServices`) | Linux / packaged | Regular files only at fixed systemd service/timer paths; content up to 64 KiB/file; query output cap 1,000 rows, not a guaranteed scan count | Root/approved elevated session expected | Query contracts and Linux disposable acceptance | No active systemd state or drop-ins; symlinked parents skipped; path check is not atomic |
| Linux cron (`linux_crontab`, source `LinuxCrontab`) | Linux / packaged | Fixed system/user cron files and script directories; content up to 64 KiB/file; query output cap 1,000 rows, not a guaranteed scan count | Root/approved elevated session expected for spool visibility | Query contracts and Linux disposable acceptance | Fixed paths, no complete home traversal; content can contain secrets or be truncated |
| Linux SUID/SGID (`linux_suid`, source `LinuxSUID`) | Linux / packaged | Metadata under `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`; 10,000 rows | Elevated session recommended | Query/analysis tests and Linux disposable acceptance | Metadata only; no file content/hash/package ownership; not a whole-filesystem scan; special bits alone do not indicate compromise |

## Candidate Windows sources

| Artifact | Source and method | Privilege expectation | Test evidence | Status and limitations |
|---|---|---|---|---|
| Local accounts / Administrators (`accounts`, source `Accounts`) | Fixed SAM `Enriched` query; shared 2,000-row cap | Elevated SAM access expected; unmeasured | Synthetic VQL projection/parameter tests | Candidate, not packaged; direct built-in Administrators membership only; user rows can exhaust cap; OS behavior unverified |
| Security events (`security_events`, source `SecurityEvents`) | Fixed EVTX channel/event-ID metadata; 50,000 rows | Depends on token, policy, and log ACLs | Query contracts and synthetic analyzer tests | Candidate, not packaged/executed; payload excluded; EVTX access, retention, and ordering unverified |
| PowerShell events (`powershell_events`, source `PowerShellEvents`) | Operational EVTX metadata for selected IDs; 25,000 rows | Depends on logging configuration and ACLs | Query contracts and synthetic analyzer tests | Candidate; ScriptBlock/message excluded; logging may be disabled or expired |
| Defender events (`defender_events`, source `DefenderEvents`) | Defender Operational metadata; 20,000 rows | Depends on Defender/channel state and access | Query contracts and synthetic analyzer tests | Candidate; payload excluded; provider/channel availability varies |
| RDP events (`rdp_events`, source `RDPEvents`) | LocalSessionManager metadata; 20,000 rows | Depends on RDP configuration, retention, and ACLs | Query contracts and synthetic analyzer tests | Candidate; payload excluded; channel may be absent or disabled |
| WMI persistence (`wmi_persistence`, source `WMIPersistence`) | Metadata from `root/subscription` and `root/default`; 5,000 rows | Elevated WMI namespace access expected | Synthetic installed-Linux-engine query fixtures and analyzer tests | Candidate; not packaged; orphan objects and payload excluded; Windows runtime/access unverified |
| Registry Run/RunOnce (`registry_run_keys`, source `RegistryRunKeys`) | Fixed `StartupItems` globs across HKLM/HKU and WOW6432Node; 10,000 rows | Elevated registry access expected | Synthetic projection/parameter and analyzer tests | Candidate; mounted HKU only, unloaded user hives absent; no hive preservation; details may contain incidental secrets |

## Requested evidence not acquired

| Evidence family | Windows | Linux | Result |
|---|---|---|---|
| Sessions / logged-on identities | Not implemented as distinct source | Not implemented | No source/parser/acceptance contract |
| Loaded drivers / kernel modules | Not implemented | Not implemented | SUID inventory is not module inventory |
| Open files / handles | Not implemented | Not implemented | Process snapshot is not handle enumeration |
| BPF programs/maps | Not implemented | Not implemented | No source or permission test |
| Deleted-but-running executables | Not implemented | Not implemented | No `/proc` exe-link or Windows equivalent acquisition |
| Event and journal history | Windows candidate metadata only | journald, auditd, auth/sudo/SSH logs absent | No packaged Linux log source; Windows candidates not packaged |
| Registry hives, Prefetch, Amcache, Shimcache, SRUM, LNK/Jump Lists | Not implemented | N/A | No bounded file-evidence profile, parser, or acceptance fixture |
| NTFS `$MFT`, USN Journal, VSS | Not implemented | N/A | No acquisition path or volume/version acceptance |
| authorized_keys, shell config, PAM, `ld.so.preload`, packages, mounts | N/A | Not implemented | Existing fixed cron/systemd/SUID paths do not cover these |
| Memory acquisition / full disk image | Not implemented | Not implemented | No mode is present; do not infer it from engine capability |

## Collection controls and provenance

- Profiles validate OS, artifact allowlist, aggregate configured row budget, timeout (60–3,600 seconds), and requested event days. The event-day field is not applied to current snapshots; event candidates are excluded from package compilation.
- VQL baseline queries are emitted in operator-selected profile order; built-in Windows collectors follow the normalized baseline. This is not a volatile-first policy. No staged expansion, resumable checkpoint, or per-artifact measured start/end, duration, bytes, and errors exists.
- Collector timeout, CPU and concurrency settings exist. Row caps do not establish bounds on all source scanning, serialized archive bytes, memory, or operating-system impact.
- Metadata includes a claimed start UTC, campaign/profile contract, and initial untrusted status. Ingest records SHA-256 and bytes per result JSON file and validates the encrypted container; endpoint claims remain untrusted. There is no signed acquisition manifest, measured clock offset, operator/case ID in collector manifest, tamper-evident action/transfer ledger, or per-row hash chain.
- This is live response, not bitwise forensic imaging. Process execution, file reads, and result creation change endpoint state; not every state change is measured or logged.
- Missing, empty, denied, or unsupported evidence does not establish that activity did not occur. Availability depends on OS/build, configuration, enabled logging/audit, privilege, retention, and concurrent state.

## Analysis and quality

- Current analysis is bounded rule-based triage with source/row citations, Linux SUID inventory context, and synthetic Windows candidate rules. It is not a validated compromise verdict.
- Correlation and graph views join artifacts currently imported; they cannot provide missing telemetry or guarantee reliable cross-host/time joins.
- No Sigma import/schema compiler, rule versioning, positive/negative Sigma fixture harness, or release-linked Detection-as-Code catalog was found.
- Avoid a single module-completion percentage. Measure by OS/version/privilege: collection success, denied/unsupported/error rates, freshness, truncation, parser validation, archive-to-UI fidelity, duration/resource impact, and labeled detection quality with explicit denominators.

## Test evidence map

- `tests/test_hunting_builder.py`: profile compilation, bounded query contracts, event query text, candidate exclusion.
- `tests/test_hunting_windows_queries.py`: synthetic projections/parameters evaluated with Linux Velociraptor; explicitly not Windows endpoint execution.
- `tests/test_hunting_windows_analysis.py`: synthetic analyzer positives/negatives, row evidence, malformed fields, non-compromise semantics.
- `tests/test_hunting_linux_sources.py` and `tests/test_hunting_linux_analysis.py`: Linux fixed path/query constraints and analysis.
- `tests/test_hunting_linux_acceptance.py` and `tests/test_hunting_linux_e2e.py`: disposable Linux packaged collection/import/analysis; not a production distribution matrix.
- `tests/test_hunting_ingest.py` and `tests/test_hunting_results.py`: container parsing, file-level SHA-256, row bounds, evidence paging and integrity behavior.

## Acceptance sequence

1. Freeze a disposable Windows VM matrix by supported build and privilege. Record logging/policy state and benign control artifacts before collection.
2. Validate volatile Windows sources first: process ancestry, sockets, sessions, services/tasks, modules, and clock context; then approved event and persistence sources. Record per-source access/error/time/bytes/rows and state-change notes.
3. Build Linux VM coverage by supported distribution/kernel and privilege. Add sockets, sessions, open files, modules, BPF and deleted-open process contracts, then logs and persistence/config sources.
4. For each source require archive import, hash verification, visible success/empty/denied/unsupported/failure/truncated states, exact row resolution, and positive and negative controls.
5. After collection contracts stabilize, implement hypothesis lifecycle, ATT&CK telemetry sufficiency, time normalization, Sigma-compatible detection-as-code, and cross-host rarity/frequency tests.
