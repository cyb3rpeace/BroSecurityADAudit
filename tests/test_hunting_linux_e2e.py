"""Real installed-engine Linux collection, not a synthetic attack/detection test.

Run only in a disposable root Docker container: --network none --read-only,
--tmpfs /tmp:rw,nosuid,nodev,size=512m, and writable tmpfs mounts at
/etc/cron.d, /etc/systemd/system and /usr/sbin. Mount app/tests and the
installed engine read-only; set PYTHONDONTWRITEBYTECODE=1,
HUNTING_LINUX_E2E_DISPOSABLE=1 and HUNTING_VQL_ENGINE (or HUNTING_TEST_ENGINE).
No daemon is started and none of the inert fixture files is executed. All
keys, archives and SQLite indexes live in TemporaryDirectory, never app data.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
from urllib.parse import unquote
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.modules.hunting_builder import compile_config
from app.modules.hunting_ingest import summarize_container
from app.modules.hunting_results import (
    analyze_result, get_result, history, read_page, save_result, verify_integrity,
)


class LinuxEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        engine = os.environ.get('HUNTING_VQL_ENGINE') or os.environ.get('HUNTING_TEST_ENGINE')
        if not engine or not Path(engine).is_file():
            raise unittest.SkipTest('Installed engine missing: set HUNTING_VQL_ENGINE or HUNTING_TEST_ENGINE')
        if platform.system() != 'Linux':
            raise unittest.SkipTest('Real Linux engine collection requires Linux')
        if os.environ.get('HUNTING_LINUX_E2E_DISPOSABLE') != '1':
            raise unittest.SkipTest('Requires explicitly opted-in disposable Docker fixture filesystem')
        if not Path('/.dockerenv').is_file() or os.geteuid() != 0:
            raise RuntimeError('E2E fixtures require a disposable root Docker container')
        # Fail closed before writing fixed paths: no host bind mounts or image
        # filesystem may be used as the fixture target.
        mounts = {line.split()[1]: line.split()[2] for line in Path('/proc/mounts').read_text().splitlines()}
        for directory in ('/etc/cron.d', '/etc/systemd/system', '/usr/sbin'):
            if mounts.get(directory) != 'tmpfs':
                raise RuntimeError('Required dedicated disposable tmpfs missing: ' + directory)
        cls.engine = str(Path(engine).resolve())

    def test_real_collection_encryption_persistence_analysis_and_evidence(self):
        marker = hashlib.sha256(b'linux-e2e-inert-fixture-not-a-malware-hash').hexdigest()
        fixture_contents = {
            '/etc/cron.d/hunting-linux-e2e': '# inert evidence marker ' + marker + '\n',
            '/etc/systemd/system/hunting-linux-e2e.service':
                '# inert evidence marker ' + marker + '\n[Unit]\nDescription=Offline evidence fixture\n',
            '/usr/sbin/hunting-linux-e2e-suid': 'INERT DATA ONLY; never execute\n',
        }
        for filename, content in fixture_contents.items():
            path = Path(filename)
            # Exclusive creation prevents accidentally replacing any existing file.
            with path.open('x') as stream:
                stream.write(content)
            self.addCleanup(path.unlink, missing_ok=True)
            path.chmod(0o4755 if filename.endswith('-suid') else 0o644)

        with tempfile.TemporaryDirectory(prefix='hunting-linux-e2e-') as temp:
            root = Path(temp)
            base, keys = root / 'results', root / 'keys'
            tenant = 1
            private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable Linux E2E only')])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                    .public_key(private.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(minutes=1))
                    .not_valid_after(now + datetime.timedelta(days=1))
                    .sign(private, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
            keydir = keys / str(tenant)
            keydir.mkdir(parents=True, mode=0o700)
            keypath = keydir / 'offline-keypair.pem'
            keypath.write_bytes(private.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            keypath.chmod(0o600)
            profile = dict(id='e' * 32, platform='linux',
                           artifacts=['host', 'linux_services', 'linux_crontab', 'linux_suid'],
                           timeout_seconds=120, event_days=7)
            config, manifest = compile_config(profile, cert)
            definition = json.loads(config)['autoexec']['artifact_definitions'][0]
            self.assertEqual([s['name'] for s in definition['sources']],
                             ['Host', 'LinuxServices', 'LinuxCrontab', 'LinuxSUID'])
            self.assertNotIn(b'PRIVATE KEY', config)
            self.assertEqual(manifest['config_sha256'], hashlib.sha256(config).hexdigest())
            configpath = root / 'collector.json'
            configpath.write_bytes(config)
            run = subprocess.run([self.engine, '--config', str(configpath), 'artifacts',
                                  'collect', 'Collector', '--nobanner'], cwd=root,
                                 capture_output=True, text=True, timeout=150)
            self.assertEqual(run.returncode, 0, run.stderr[-6000:])
            archives = list(root.glob('BroSec-*.zip'))
            self.assertEqual(len(archives), 1, run.stderr[-6000:])
            archive = archives[0]
            with zipfile.ZipFile(archive) as outer:
                self.assertIn('metadata.json', outer.namelist())
                self.assertTrue(outer.getinfo('data.zip').flag_bits & 1)
                metadata = json.loads(outer.read('metadata.json'))
                if isinstance(metadata, list):
                    self.assertEqual(len(metadata), 1)
                    metadata = metadata[0]
                self.assertEqual(metadata['Scheme'], 'X509')
                self.assertTrue(metadata['EncryptedPass'])
                with self.assertRaises(RuntimeError):
                    outer.read('data.zip')  # No password cannot read encrypted data.

            observed = {}
            def capture(source, index, row):
                observed.setdefault(source, []).append((index, row))
            summary = summarize_container(archive, keys, tenant, row_callback=capture)
            self.assertEqual(summary['status'], 'parsed')
            self.assertEqual(summary['collector_schema'], 'brosec.result.v1')
            labels = {unquote(s['source']).rsplit('/', 1)[-1]: s for s in summary['sources']}
            self.assertEqual(set(labels), {'Host.json', 'LinuxServices.json', 'LinuxCrontab.json', 'LinuxSUID.json'})
            self.assertEqual(summary['total_rows'], sum(s['rows'] for s in summary['sources']))
            for source in summary['sources']:
                rows = observed[source['source']]
                self.assertGreater(source['rows'], 0, source)
                self.assertEqual([index for index, _ in rows], list(range(source['rows'])))
            host = observed[labels['Host.json']['source']][0][1]
            self.assertTrue(host.get('Hostname'))
            self.assertIn(host['Hostname'], summary['hostnames'])
            for label, filename in [('LinuxServices.json', '/etc/systemd/system/hunting-linux-e2e.service'),
                                    ('LinuxCrontab.json', '/etc/cron.d/hunting-linux-e2e'),
                                    ('LinuxSUID.json', '/usr/sbin/hunting-linux-e2e-suid')]:
                rows = [row for _, row in observed[labels[label]['source']] if row.get('OSPath') == filename]
                self.assertEqual(len(rows), 1, label)
                row = rows[0]
                if label != 'LinuxSUID.json':
                    self.assertEqual(row['Content'], fixture_contents[filename])
                    self.assertFalse(row['ContentTruncated'])
                else:
                    self.assertTrue(row['Mode'].startswith('u'), row)
                    self.assertIs(type(row['OwnerID']), int)
                    self.assertIs(type(row['GroupID']), int)
                    self.assertEqual((row['OwnerID'], row['GroupID']), (0, 0))
            provenance = summary['collection_provenance']
            self.assertFalse(provenance['claims_verified'])
            self.assertFalse(provenance['claims_trusted'])
            requested = {s['id']: s for s in provenance['requested_sources']}
            self.assertEqual(set(requested), set(profile['artifacts']))
            for source in requested.values():
                self.assertEqual(source['observed_status'], 'present')
                self.assertEqual(source['limit_reached'],
                                 source['observed_rows'] >= source['configured_row_limit'])
                # Host's intentional one-row cap is reached on every collection;
                # provenance conservatively calls even that possibly truncated.
                if source['id'] != 'host':
                    self.assertFalse(source['limit_reached'])

            saved = save_result(base, tenant, archive, summary)
            identifier = saved['id']
            self.assertFalse(saved['duplicate'])
            self.assertEqual(saved['sha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(saved['size'], archive.stat().st_size)
            stored = base / 'archives' / str(tenant) / (identifier + '.zip')
            self.assertEqual(stored.read_bytes(), archive.read_bytes())
            self.assertEqual(get_result(base, tenant, identifier)['summary'], summary)
            self.assertTrue(save_result(base, tenant, archive, summary)['duplicate'])
            self.assertEqual(history(base, tenant)['total'], 1)
            self.assertEqual(history(base, 2)['total'], 0)
            self.assertIsNone(get_result(base, 2, identifier))
            integrity = verify_integrity(base, tenant)
            self.assertEqual((integrity['checked'], integrity['valid'], integrity['invalid']), (1, 1, []))
            archive.unlink()  # Every subsequent read must use the persisted encrypted copy.
            analysis = analyze_result(base, keys, tenant, identifier)
            self.assertEqual(analysis['import_id'], identifier)
            self.assertEqual(analysis['sha256'], saved['sha256'])
            # Current analyzer has no Linux persistence rules: collection success
            # must never be reported as attack detection or a clean-host verdict.
            linux_sources = {labels[name]['source'] for name in ('LinuxServices.json', 'LinuxCrontab.json', 'LinuxSUID.json')}
            self.assertTrue(linux_sources.issubset(set(analysis['unsupported_sources'])))
            self.assertEqual(analysis['verdict'], 'not_determined')

            # Retrieve *every* observed source through the real evidence API.
            for source in summary['sources']:
                name, count = source['source'], source['rows']
                retrieved = []
                for offset in range(0, count, 100):
                    page = read_page(base, keys, tenant, identifier, name, offset, 100)
                    self.assertEqual((page['source'], page['total'], page['offset']), (name, count, offset))
                    retrieved.extend(page['rows'])
                self.assertEqual(retrieved, [row for _, row in observed[name]])
                self.assertEqual(read_page(base, keys, tenant, identifier, name, count, 1)['rows'], [])
            # Harmless hash comments guarantee non-vacuous analyzer citations.
            # They are test markers, not threat intelligence or attack payloads.
            marker_ioc = next(ioc for ioc in analysis['iocs'] if ioc['value'] == marker)
            self.assertEqual(marker_ioc['type'], 'sha256')
            self.assertEqual({ref['source'] for ref in marker_ioc['evidence_refs']},
                             {labels['LinuxServices.json']['source'], labels['LinuxCrontab.json']['source']})
            refs = []
            def collect_refs(value):
                if isinstance(value, dict):
                    if 'evidence_refs' in value:
                        refs.extend(value['evidence_refs'])
                    for child in value.values():
                        collect_refs(child)
                elif isinstance(value, list):
                    for child in value:
                        collect_refs(child)
            collect_refs(analysis)
            self.assertGreaterEqual(len(refs), 2)
            cache = {}
            for ref in refs:
                name, number = ref['source'], ref['row_number']
                self.assertIn(name, observed)
                self.assertIs(type(number), int)
                self.assertGreaterEqual(number, 1)
                self.assertLessEqual(number, len(observed[name]))
                key = (name, number)
                if key not in cache:
                    page = read_page(base, keys, tenant, identifier, name, number - 1, 1)
                    self.assertEqual(len(page['rows']), 1)
                    cache[key] = page['rows'][0]
                self.assertEqual(cache[key], observed[name][number - 1][1])
                if ref in marker_ioc['evidence_refs']:
                    self.assertIn(marker, cache[key][ref['field']])
            with self.assertRaises(KeyError):
                analyze_result(base, keys, 2, identifier)
            with self.assertRaises(KeyError):
                read_page(base, keys, 2, identifier, labels['Host.json']['source'])
            # Mutation is confined to a temporary copy and proves integrity gates.
            stored.write_bytes(stored.read_bytes() + b'tampered')
            with self.assertRaises(ValueError):
                analyze_result(base, keys, tenant, identifier)
            with self.assertRaises(ValueError):
                read_page(base, keys, tenant, identifier, labels['Host.json']['source'])
            print('LINUX_E2E ' + json.dumps({
                'real_engine_collection': True, 'synthetic_attacks': False,
                'sources': {name: item['rows'] for name, item in labels.items()},
                'total_rows': summary['total_rows'], 'resolved_evidence_refs': len(refs),
                'unsupported_linux_analysis_sources': sorted(linux_sources),
                'verdict': analysis['verdict'], 'ui_acceptance': False,
            }, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
