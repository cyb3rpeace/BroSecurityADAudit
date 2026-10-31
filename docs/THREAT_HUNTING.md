# Threat Hunting Technical Reference

## Release status

This module is a bounded, evidence-oriented investigation workflow, not a complete disk-imaging or endpoint-response suite. Configured profile coverage does not prove endpoint execution or completeness. Assess each imported archive using observed source status, missing/empty data, truncation indicators, and collection logs.

The current platform supports bounded host, process, network, Windows service/task/startup, and Linux fixed-path service/cron/SUID sources according to each release's catalog and package allowlist. Linux SUID/SGID is now recognized in analysis as low-severity inventory context; it is not interpreted as suspicious by permission bits alone. Windows Security, PowerShell, Defender, RDP events, WMI persistence, Run/RunOnce and local accounts remain gated candidates until a signed-off Windows real-engine acceptance is recorded for supported OS versions.

## Workflow

1. Select the authorized tenant and create an OS-specific profile using only packageable sources.
2. Review profile-specific PDF instructions and the JSON specification. The PDF is generated from the saved profile and lists each requested source and its limitations.
3. Verify package provenance and SHA-256 against the manifest from a trusted download path. Run a one-host pilot under the approved privilege and change window.
4. Preserve the original encrypted result archive, its SHA-256, collector logs, host identity, profile ID and UTC collection window.
5. Import into the correct tenant. Inspect host identity, source coverage, endpoint claims, observed source rows, missing/empty sources and caps before interpreting findings.
6. Correlate finding evidence to exact source and row numbers. Record analyst decisions with rationale. Keep facts, hypotheses and data gaps separate.
7. Export reports only after analyst review; preserve original evidence and chain-of-custody metadata under organizational retention rules.

## Collector constraints

- `host`, `processes`, and `network` are bounded snapshots; network data is not historical connection telemetry.
- Linux service/timer and cron collection is restricted to fixed paths and bounded file counts/content sizes. SUID/SGID is metadata-only for fixed binary directories, not a full filesystem scan; matching rows are reviewed as low-severity inventory context, never as compromise evidence based on permission bits alone.
- Windows service/task/startup sources have bounded outputs and may duplicate normalized and built-in data.
- Candidate sources are disabled for packaging. Catalog presence or a generated PDF is not evidence of execution.
- Row caps constrain output, not all query scan cost, bytes read, memory, or endpoint operating-system overhead.
- Missing or empty sources do not establish absence of malicious activity. Hash integrity establishes byte consistency, not source authenticity or acquisition completeness.

## AI and evidence citations

External AI receives bounded server-selected context and must cite exact `[evidence:source#row_number]` references. Citation auditing checks membership against the bounded context; it does not prove that a row semantically supports a claim. One correction attempt is allowed. If invalid references remain, the answer is rejected. AI output is advisory, may be incomplete, and must be reviewed against source rows. Public research is contextual reference material, not proof of tenant activity.

## Operational security

Use tenant-specific access, least privilege, protected temporary directories, encrypted evidence transport, verified TLS, and approved retention. Protect tenant decryption keys with tested backups. Do not place credentials in scripts, command lines, GPO preferences, shared folders, or AI prompts. External model data handling must be approved before sending sensitive evidence.

## Production acceptance gates

Before unrestricted incident-response use, record passing results for: supported Windows versions and collector execution, candidate source execution where admitted, Linux real-engine collection, archive integrity/import/analysis/UI, tenant authorization, AI citation rejection behavior, package reproducibility, worker health/recovery, load/cap behavior, backup restoration, and rollback. This checklist does not replace customer-specific change approval, legal authorization, or forensic chain-of-custody procedures.

## Coverage development roadmap

The objective is verifiable investigation coverage, not a claim to collect everything. A source is not production-ready merely because it is present in the catalog or query code.

### Evidence acquisition priorities

1. **Collection trust and completeness:** capture UTC start/end, endpoint clock offset when measurable, collector/build identity, profile and source IDs, per-source start/end status, access-denied/unsupported/error states, row and byte truncation, timeout, and hashes in a signed or otherwise tamper-evident manifest. Distinguish `not_collected`, `unsupported`, `permission_denied`, `failed`, `empty`, `truncated`, and `collected`; never infer success from an empty table.
2. **Windows high-value sources:** validate Security, PowerShell Operational, Defender Operational and RDP channels on supported Windows builds; test event IDs and field normalization against generated benign and controlled test fixtures. Add WMI permanent subscriptions, Run/RunOnce, local accounts/groups and additional persistence locations only after execution and coverage contracts pass. Evaluate registry hives, Prefetch, Amcache, SRUM, LNK/Jump Lists, scheduled tasks, services, `$MFT`/USN and VSS as a separately bounded file-evidence profile; document privilege, OS/version and volume constraints.
3. **Linux high-value sources:** expand from fixed-path service/cron/SUID metadata to supported collection of persistent and volatile journald, auditd, auth/sudo/SSH logs, systemd units/timers/drop-ins, accounts/groups, SSH authorized keys, PAM and loader configuration, package inventory, mounts, kernel modules, and deleted-but-running executable metadata. Keep sensitive content opt-in and disclose redaction/secret exposure behavior.
4. **Volatile-response tier:** make process ancestry, command lines, sockets-to-process attribution, logged-on users, open files, mounts, loaded modules and clock context an explicit first collection tier. Memory acquisition and full disk imaging must be separate, operator-approved workflows with platform compatibility checks and preservation procedures, not silent profile defaults.
5. **Analysis and hunts:** add a hypothesis workflow that specifies required telemetry, known data gaps, expected positive/negative observations, ATT&CK technique mapping and analyst disposition. Introduce versioned Sigma-compatible detection-as-code with schema/lint checks and positive/negative regression fixtures. Correlate identity, process, network, file and event timelines only where join keys and timestamps are reliable.

### Release admission gate for each source

Record a source contract containing platform/version, exact query or fixed paths, required privileges, expected fields, privacy classification, maximum rows/bytes/time, truncation semantics, known blind spots, parser version, and ATT&CK/data-source rationale. Require: query compilation with the installed engine; synthetic positive and negative fixtures; execution on a disposable supported endpoint; result archive integrity/import; UI visibility of success, empty, unsupported, permission denied, failure and truncation; and regression tests. Until all gates pass, keep the source visibly marked candidate and exclude it from executable packages.

### Program-level acceptance metrics

Track measured results by OS release and privilege profile: source execution success rate, unsupported/denied/error rates, truncation rates, parser field-validation results, archive-to-UI integrity, package reproducibility, collection duration/bytes, and detector precision on labeled fixtures. Report denominators and test environment; do not turn configured catalog counts or ATT&CK mappings into a coverage percentage. Validate resource limits and user-visible failures before fleet rollout.

### Operational boundaries

Use isolated, authorized test hosts and benign or controlled test artifacts. Do not disable endpoint defenses or conduct activity against third-party systems. Live collection is state-changing; acquire volatile evidence promptly, preserve originals, hash outputs, document operator actions and protect chain-of-custody records. Send evidence to external AI only under an approved data-handling policy.

