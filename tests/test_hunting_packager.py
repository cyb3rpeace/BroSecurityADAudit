import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from app.modules.hunting_packager import tenant_certificate, build_package


class PackagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_keys_persist_and_tenants_differ(self):
        first = tenant_certificate(self.root, 1)
        self.assertEqual(first, tenant_certificate(self.root, 1))
        self.assertNotEqual(first, tenant_certificate(self.root, 2))
        self.assertNotIn('PRIVATE KEY', first)
        self.assertIn(b'PRIVATE KEY', (self.root/'1/offline-keypair.pem').read_bytes())

    def test_reject_invalid_tenant(self):
        for value in [0, -1, '../keys', True]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                tenant_certificate(self.root, value)

    def test_hash_failure_never_runs_engine(self):
        engine = self.root/'engine'; engine.write_bytes(b'test')
        with patch('app.modules.hunting_packager.subprocess.run') as run:
            with self.assertRaises(ValueError):
                build_package(dict(platform='linux',artifacts=['host'],timeout_seconds=60,event_days=1), self.root/'keys', engine, engine, '0'*64, '0'*64)
            run.assert_not_called()

    def test_package_uses_only_public_config(self):
        engine = self.root/'engine'; engine.write_bytes(b'test')
        digest = hashlib.sha256(b'test').hexdigest()
        profile = dict(id='a'*32,company_id=1,platform='linux',artifacts=['host'],timeout_seconds=60,event_days=1)
        def repack(argv, **kwargs):
            self.assertNotIn(b'PRIVATE KEY', Path(argv[-2]).read_bytes())
            self.assertNotIn('shell', kwargs)
            self.assertEqual(kwargs['timeout'],120)
            Path(argv[-1]).write_bytes(b'\x7fELFtest')
            return type('Result', (), {'returncode':0})()
        with patch('app.modules.hunting_packager.subprocess.run', side_effect=repack):
            data, manifest = build_package(profile,self.root/'keys',engine,engine,digest,digest)
        self.assertEqual(data,b'\x7fELFtest')
        self.assertFalse(manifest['config_only'])
        self.assertFalse(manifest['execution_verified'])


if __name__ == '__main__':
    unittest.main()
