import base64
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyzipper
from app.modules.hunting_packager import tenant_certificate
from app.modules.hunting_ingest import summarize_container, checked_members, collection_provenance


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cert = tenant_certificate(self.root, 1)

    def container(self, name='results/BroSec.json', body=b'{"Pid": 123}\n'):
        password = b'random-test-password'
        inner = io.BytesIO()
        with pyzipper.AESZipFile(inner,'w',encryption=pyzipper.WZ_AES) as z:
            z.setpassword(password); z.writestr(name,body)
        cert = x509.load_pem_x509_certificate(self.cert.encode())
        enc = cert.public_key().encrypt(password,padding.OAEP(mgf=padding.MGF1(hashes.SHA512()),algorithm=hashes.SHA512(),label=None))
        outer = io.BytesIO()
        with pyzipper.AESZipFile(outer,'w',encryption=pyzipper.WZ_AES) as z:
            z.setencryption(None)
            z.writestr('metadata.json',json.dumps([{'Scheme':'X509','EncryptedPass':base64.b64encode(enc).decode()}]))
            z.setencryption(pyzipper.WZ_AES)
            z.setpassword(password)
            z.writestr('data.zip',inner.getvalue())
        return outer.getvalue()

    def test_real_crypto_and_summary(self):
        result = summarize_container(self.container(),self.root,1)
        self.assertEqual(result['total_rows'],1)
        self.assertEqual(result['sources'],[{'source':'results/BroSec.json','rows':1,
            'sha256':hashlib.sha256(b'{"Pid": 123}\n').hexdigest(),
            'bytes':13, 'status':'present', 'completeness':'unknown'}])
        self.assertNotIn('Pid',json.dumps(result))

    def test_empty_source_not_claimed_complete(self):
        result = summarize_container(self.container(body=b''), self.root, 1)
        source = result['sources'][0]
        self.assertEqual(source['status'], 'empty')
        self.assertEqual(source['bytes'], 0)
        self.assertEqual(source['sha256'], hashlib.sha256(b'').hexdigest())
        self.assertEqual(source['completeness'], 'unknown')

    def test_source_hash_preserves_original_bytes(self):
        body = b'  {"Pid": 1}\r\n\n'
        result = summarize_container(self.container(body=body), self.root, 1)
        self.assertEqual(result['sources'][0]['sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(result['sources'][0]['bytes'], len(body))
        self.assertEqual(result['sources'][0]['rows'], 1)

    def test_collection_provenance_does_not_claim_success(self):
        metadata = {'CaptureStartedUTC': '2026-10-27T00:00:00Z', 'CollectionContract': {
            'configured_source_row_limits': {'host': 1, 'processes': 10000, 'network': 20000},
            'event_window': {'applied': False}}}
        sources = [{'source': 'results/BroSec.Offline.Baseline%2FHost.json', 'rows': 1, 'bytes': 42},
                   {'source': 'results/BroSec.Offline.Baseline%2FProcesses.json', 'rows': 0, 'bytes': 0}]
        result = collection_provenance(metadata, sources)
        self.assertFalse(result['claims_verified'])
        self.assertEqual(result['completeness'], 'unknown')
        self.assertEqual([r['observed_status'] for r in result['requested_sources']], ['present', 'empty', 'missing'])
        self.assertEqual([r['status'] for r in result['requested_sources']], ['present', 'empty', 'missing'])
        self.assertFalse(result['requested_sources'][0]['limit_reached'])
        self.assertEqual(result['requested_sources'][0]['completeness'], 'unknown')
        self.assertEqual(result['requested_sources'][0]['observed_bytes'], 42)
        self.assertEqual(result['requested_sources'][0]['observed_bytes_status'], 'present')
        self.assertEqual(result['requested_sources'][1]['observed_bytes'], 0)

    def test_collection_status_claims_are_separate_and_untrusted(self):
        metadata = {'CollectionContract': {'configured_source_row_limits': {'host': 10}},
                    'CollectionStatus': {'version': 1, 'sources': {
                        'host': {'status': 'success', 'error': 'secret'},
                        'unknown': {'status': 'success'},
                        'processes': {'status': 'bogus'}}}}
        result = collection_provenance(metadata, [{'source': 'results/x%2FHost.json', 'rows': 0}])
        source = result['requested_sources'][0]
        self.assertEqual(source['observed_status'], 'empty')
        self.assertEqual(source['claimed_status'], 'success')
        self.assertFalse(result['claims_verified'])
        self.assertEqual(result['completeness'], 'unknown')
        self.assertNotIn('secret', json.dumps(result))

    def test_invalid_and_unknown_claims_do_not_forge_success(self):
        result = collection_provenance({'CollectionContract': {
            'configured_source_row_limits': {'host': 10}},
            'CollectionStatus': {'version': 2, 'sources': {
                'host': {'status': 'success'}}}}, [])
        self.assertEqual(result['requested_sources'][0]['observed_status'], 'missing')
        self.assertIsNone(result['requested_sources'][0]['claimed_status'])

    def test_collection_provenance_untrusted_and_legacy(self):
        self.assertEqual(collection_provenance({}, [])['status'], 'legacy_or_missing')
        result = collection_provenance({'CaptureStartedUTC': 'bad\nclaim', 'CollectionContract': {
            'configured_source_row_limits': {'host': True, 'unknown': 1, 'processes': -1}}}, [])
        self.assertIsNone(result['capture_started_utc_claim'])
        self.assertEqual(result['requested_sources'], [])

    def test_wrong_tenant(self):
        tenant_certificate(self.root,2)
        with self.assertRaises(ValueError):summarize_container(self.container(),self.root,2)

    def test_unsafe_path_and_invalid_json(self):
        for name,body in [('../escape',b'{}'),('results/test.json',b'[]'),('results/test.json',b'bad')]:
            with self.subTest(name=name,body=body),self.assertRaises(ValueError):
                summarize_container(self.container(name,body),self.root,1)

    def test_plain_or_corrupt_zip_rejected(self):
        with self.assertRaises(ValueError):summarize_container(b'bad zip',self.root,1)


if __name__ == '__main__':unittest.main()


class HostileStatusTests(unittest.TestCase):
    def test_unhashable_claim_and_boolean_version_are_ignored(self):
        for version,status in [(1, []),(1, {}),(True, 'success')]:
            result = collection_provenance({'CollectionContract': {'configured_source_row_limits': {'host': 1}}, 'CollectionStatus': {'version': version, 'sources': {'host': {'status': status}}}}, [])
            self.assertIsNone(result['requested_sources'][0]['claimed_status'])
            self.assertEqual(result['requested_sources'][0]['observed_status'], 'missing')
            self.assertTrue(result['warnings'])
            self.assertFalse(result['claims_verified'])
