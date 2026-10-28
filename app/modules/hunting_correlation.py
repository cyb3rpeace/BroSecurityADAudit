"""Bounded multi-result evidence correlation; no attribution, AI or report writes.

API: correlate_results(base, key_root, company_id, result_ids) -> JSON dict.
The caller MUST resolve company_id using authenticated tenant authorization.
Missing and foreign IDs deliberately share KeyError("Result not found").
"""
import hashlib
import re
from pathlib import Path

from app.modules.hunting_analysis import BaselineReview
from app.modules.hunting_ingest import MAX_UPLOAD, summarize_container
from app.modules.hunting_results import analyze_result, get_result

MAX_RESULTS = 20
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_TOTAL_ROWS = 200000
MAX_NODES = 2000
MAX_EDGES = 2000
MAX_REFS = 12
MAX_INDICATORS = 2000
MAX_VALUE = 512


def _shared_identity(value, hostname):
    """Reject local/built-in principals, even when their names are qualified."""
    if '\\' not in value:
        return True
    authority, _ = value.split('\\', 1)
    local = {'.', 'localhost', 'builtin', 'nt authority', 'nt service',
             'window manager', 'font driver host'}
    host = hostname.casefold().rstrip('.')
    return authority.casefold() not in local and authority.casefold().rstrip('.') not in {host, host.split('.')[0]}


class CorrelationLimitError(ValueError):
    """Request exceeds a hard input/processing budget; no partial response."""


def _text(row, *keys):
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and 0 < len(value.strip()) <= MAX_VALUE:
            return value.strip()
    return None


def _refs(items):
    unique = {(x['result_id'], x['source'], x['row_number']): x for x in items}
    return [unique[k] for k in sorted(unique)]


def correlate_results(base, key_root, company_id, result_ids):
    """All-or-nothing archive validation, deterministic bounded evidence graph.

    Host nodes represent individual collection scopes, NOT verified assets.
    Cross-host edges require one unambiguous Host-source hostname per scope,
    different declared hostnames, and a shared exact SHA256 or qualified user
    identity observed in supported telemetry with citations on BOTH sides.
    Matching IPs, PIDs, paths and unqualified usernames never link hosts.
    """
    if type(company_id) is not int or company_id <= 0:
        raise ValueError('Invalid company')
    if not isinstance(result_ids, list) or not 1 <= len(result_ids) <= MAX_RESULTS:
        raise CorrelationLimitError('Expected 1 to 20 result IDs')
    if any(not isinstance(x, str) or not re.fullmatch(r'[0-9a-f]{32}', x) for x in result_ids):
        raise ValueError('Invalid result ID')
    if len(set(result_ids)) != len(result_ids):
        raise ValueError('Duplicate result IDs')
    base, key_root = Path(base), Path(key_root)
    ids = sorted(result_ids)
    # Authorize EVERY ID before touching archives or doing expensive analysis.
    metadata = []
    for rid in ids:
        item = get_result(base, company_id, rid)
        if item is None:
            raise KeyError('Result not found')
        metadata.append(item)
    total_bytes = total_rows = 0
    for item in metadata:
        size = item['size']
        rows = item['summary'].get('total_rows')
        if type(size) is not int or not 0 <= size <= MAX_UPLOAD:
            raise CorrelationLimitError('Archive byte limit exceeded')
        if type(rows) is not int or rows < 0:
            raise ValueError('Invalid archive row metadata')
        total_bytes += size
        total_rows += rows
    if total_bytes > MAX_TOTAL_BYTES or total_rows > MAX_TOTAL_ROWS:
        raise CorrelationLimitError('Aggregate input budget exceeded')

    nodes, hosts, indicators = {}, {}, {}
    truncated = False
    limitations = {
        'Evidence correlation only; no attack classification or compromise verdict.',
        'Archives are tenant-key decrypted and checksum checked; authorship is not verified.',
        'Host nodes are collection scopes, not verified asset identities; collection times may differ.',
        'Cross-host edges mean shared observed evidence, not communication or lateral movement.',
        'IP addresses alone, PIDs, paths and unqualified usernames never link hosts.',
        'Built-in and host-local qualified identities do not link hosts; domain identity ownership is not verified.',
        'Endpoint matching is intentionally disabled: address ownership and time are not verified.',
        'Only known baseline sources are supported; missing evidence is not negative evidence.',
        'SHA256 text occurrence does not establish file ownership or maliciousness.',
    }
    processed_rows = 0
    for item in metadata:
        rid = item['id']
        path = base / 'archives' / str(company_id) / (rid + '.zip')
        current = base
        for part in Path('archives', str(company_id), rid + '.zip').parts:
            current = current / part
            if current.is_symlink():
                raise ValueError('Unsafe archive path')
        try:
            if not path.is_file() or path.stat().st_size != item['size']:
                raise ValueError('Archive unavailable or size mismatch')
            # Existing analysis performs the tenant-scoped checksum/decryption checks.
            analysis = analyze_result(base, key_root, company_id, rid)
            if analysis['import_id'] != rid or analysis['sha256'] != item['sha256']:
                raise ValueError('Archive metadata changed')
            # Read a bounded immutable snapshot for citation extraction; recheck hash.
            with path.open('rb') as stream:
                data = stream.read(MAX_UPLOAD + 1)
            if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('Archive integrity mismatch')
        except OSError as exc:
            raise ValueError('Archive unavailable') from exc
        if analysis.get('truncated') or analysis.get('graph', {}).get('truncated'):
            truncated = True
        host_id = 'host:' + rid
        host = {'id': host_id, 'kind': 'host', 'result_id': rid,
                'label': 'Unresolved collection ' + rid, 'confidence': 'collection_scope',
                'evidence_refs': []}
        nodes[host_id] = host
        names = set()
        host_refs = []
        rows_seen = 0

        def consume(source, index, row):
            nonlocal truncated, processed_rows, rows_seen
            processed_rows += 1
            rows_seen += 1
            if processed_rows > MAX_TOTAL_ROWS:
                raise CorrelationLimitError('Actual row budget exceeded')
            kind = BaselineReview.source_kind(source)
            ref = {'result_id': rid, 'source': source, 'row_number': index + 1}
            if kind == 'Host':
                name = _text(row, 'Hostname', 'Fqdn', 'Host')
                if name:
                    names.add(name.casefold().rstrip('.'))
                    if len(host_refs) < MAX_REFS:
                        host_refs.append(ref)
                    else:
                        truncated = True
                return
            entity_kind = {'Processes': 'process', 'Network': 'network',
                           'Services': 'persistence', 'Tasks': 'persistence',
                           'Startup': 'persistence'}.get(kind)
            if not entity_kind:
                return
            node_id = rid + ':' + source + ':' + str(index + 1)
            if len(nodes) < MAX_NODES - MAX_RESULTS:
                nodes[node_id] = {'id': node_id, 'kind': entity_kind, 'host_id': host_id,
                                 'result_id': rid, 'label': (_text(row, 'Exe', 'Name', 'TaskName', 'RemoteIP') or kind),
                                 'confidence': 'observed_row', 'evidence_refs': [ref]}
            else:
                truncated = True
            matches = set()
            for value in row.values():
                if isinstance(value, str) and len(value) <= 2048:
                    matches.update(('sha256', h.lower()) for h in re.findall(r'(?i)\b[a-f0-9]{64}\b', value))
            identity = _text(row, 'Username', 'UserName')
            if identity and (re.fullmatch(r'[^\\\s]+\\[^\\\s]+', identity) or
                             re.fullmatch(r'[^@\s]+@[^@\s]+', identity)):
                matches.add(('qualified_identity', identity.casefold()))
            for indicator in sorted(matches):
                if indicator not in indicators:
                    if len(indicators) >= MAX_INDICATORS:
                        truncated = True
                        continue
                    indicators[indicator] = {}
                refs = indicators[indicator].setdefault(host_id, [])
                if len(refs) < MAX_REFS:
                    refs.append(ref)
                else:
                    truncated = True

        parsed = summarize_container(data, key_root, company_id, row_callback=consume)
        if rows_seen != item['summary']['total_rows']:
            raise ValueError('Archive row metadata mismatch')
        del data
        if len(names) == 1:
            name = next(iter(names))
            host.update(label=name, declared_identity=name, confidence='declared_host_identity',
                        evidence_refs=_refs(host_refs))
            hosts[host_id] = name
        else:
            limitations.add('Some collections lack one unambiguous Host-source identity; cross-host links suppressed.')
        if any(not BaselineReview.source_kind(x['source']) for x in parsed['sources']):
            limitations.add('Unsupported sources were validated but excluded from correlation.')

    edges = []
    for (kind, value), occurrences in sorted(indicators.items()):
        participating = sorted(h for h in occurrences if h in hosts and
                               (kind != 'qualified_identity' or _shared_identity(value, hosts[h])))
        for i, left in enumerate(participating):
            for right in participating[i + 1:]:
                if hosts[left] == hosts[right]:
                    continue  # Do not call repeat collections of the same declared name cross-host.
                if len(edges) >= MAX_EDGES:
                    truncated = True
                    break
                edges.append({'source': left, 'target': right, 'relation': 'shared_' + kind,
                              'indicator': {'type': kind, 'value': value},
                              'confidence': 'explicit_shared_evidence',
                              'evidence_refs': _refs(occurrences[left] + occurrences[right]),
                              'host_evidence_refs': _refs(nodes[left]['evidence_refs'] + nodes[right]['evidence_refs'])})
    return {'version': 'hunting-correlation-1', 'company_id': company_id, 'result_ids': ids,
            'graph': {'nodes': [nodes[k] for k in sorted(nodes)], 'edges': edges},
            'limits': {'results': MAX_RESULTS, 'total_bytes': MAX_TOTAL_BYTES,
                       'total_rows': MAX_TOTAL_ROWS, 'nodes': MAX_NODES, 'edges': MAX_EDGES,
                       'indicators': MAX_INDICATORS, 'refs_per_indicator_host': MAX_REFS},
            'limitations': sorted(limitations), 'truncated': truncated}
