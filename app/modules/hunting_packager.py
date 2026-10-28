"""Server-side offline packager. No shell, downloads, Docker socket or endpoint execution."""
from __future__ import annotations
import hashlib
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.modules.hunting_builder import compile_config, SUPPORTED
from app.modules.hunting_profiles import validate_profile


def tenant_certificate(key_root: Path, company_id: int):
    """Create an atomic key+certificate bundle; retain it for future decryption."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    if type(company_id) is not int or company_id <= 0:
        raise ValueError('Некорректная компания')
    key_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    tenant = key_root / str(company_id)
    tenant.mkdir(exist_ok=True, mode=0o700)
    bundle = tenant / 'offline-keypair.pem'
    if not bundle.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f'BroSec Offline Tenant {company_id}')])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
                .not_valid_after(now+timedelta(days=365)).sign(key, hashes.SHA256()))
        data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()) + cert.public_bytes(serialization.Encoding.PEM)
        fd, temp = tempfile.mkstemp(prefix='.key-', dir=tenant)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            try:
                os.link(temp, bundle)  # First complete writer wins, never replace an existing key.
            except FileExistsError:
                pass
        finally:
            os.unlink(temp)
    if bundle.is_symlink():
        raise ValueError('Недопустимый путь ключа')
    raw = bundle.read_bytes()
    key = serialization.load_pem_private_key(raw.split(b'-----BEGIN CERTIFICATE-----')[0], password=None)
    pem = b'-----BEGIN CERTIFICATE-----' + raw.split(b'-----BEGIN CERTIFICATE-----', 1)[1]
    cert = x509.load_pem_x509_certificate(pem)
    if key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise ValueError('Ключ и сертификат не соответствуют друг другу')
    return pem.decode('ascii')


def build_package(profile: dict, key_root: Path, engine: Path, target_binary: Path,
                  expected_engine_sha256: str, expected_target_sha256: str):
    """Return executable bytes and manifest; all paths/hashes are operator-controlled.

    Caller must authorize tenant and rate-limit concurrent builds. No binary is
    executed on an endpoint. Repack runs with a 120-second server-side timeout.
    """
    validate_profile(profile['platform'], profile['artifacts'], profile['timeout_seconds'], profile['event_days'])
    if not set(profile['artifacts']) <= SUPPORTED:
        raise ValueError('Для выбранных сборов упаковка ещё не поддерживается')
    for path, expected in [(engine, expected_engine_sha256), (target_binary, expected_target_sha256)]:
        if len(expected) != 64 or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Контрольная сумма доверенного бинарного файла не совпадает')
    pem = tenant_certificate(key_root, profile['company_id'])
    config, manifest = compile_config(profile, pem)
    with tempfile.TemporaryDirectory(prefix='brosec-repack-') as temp:
        work = Path(temp)
        config_path = work / 'collector.config.json'
        config_path.write_bytes(config)
        output = work / ('collector.exe' if profile['platform'] == 'windows' else 'collector')
        result = subprocess.run([str(engine), 'config', 'repack', '--exe', str(target_binary), str(config_path), str(output)],
                                cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=120, check=False,
                                env={'PATH': '/usr/bin:/bin', 'HOME': str(work), 'TMPDIR': str(work)})
        if result.returncode or not output.is_file():
            raise ValueError('Velociraptor не смог упаковать сборщик; проверьте серверные бинарные файлы')
        data = output.read_bytes()
    magic = b'MZ' if profile['platform'] == 'windows' else b'\x7fELF'
    if not data.startswith(magic):
        raise ValueError('Формат сборщика не соответствует выбранной ОС')
    manifest = {**manifest, 'config_only': False, 'executable_sha256': hashlib.sha256(data).hexdigest(),
                'target_binary_sha256': expected_target_sha256, 'engine_sha256': expected_engine_sha256,
                'execution_verified': False}
    return data, manifest
