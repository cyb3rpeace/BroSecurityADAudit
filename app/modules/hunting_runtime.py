"""Operator-provisioned engines only; verify pins before advertising support."""
import hashlib
import json
import re
from pathlib import Path

TOOLS = Path('/opt/ad-audit/tools/hunting')


def verified_binary(path, expected, magic):
    if not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('Некорректная контрольная сумма бинарного файла')
    if path.is_symlink() or not path.is_file():
        raise ValueError('Бинарный файл отсутствует или является ссылкой')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        if stream.read(len(magic)) != magic:
            raise ValueError('Формат бинарного файла не соответствует ОС')
        stream.seek(0)
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError('Контрольная сумма бинарного файла не совпадает')


def trusted_tools(platform):
    if platform not in {'windows', 'linux'}:
        raise ValueError('Неизвестная ОС')
    try:
        manifest_path = TOOLS / 'manifest.json'
        if manifest_path.is_symlink():
            raise ValueError('Недопустимый путь манифеста')
        manifest = json.loads(manifest_path.read_text())
        target = manifest['targets'][platform]
        engine = manifest['engine']
        engine_path = TOOLS / 'velociraptor-linux'
        target_path = TOOLS / ('velociraptor-windows.exe' if platform == 'windows' else 'velociraptor-linux')
        verified_binary(engine_path, engine['sha256'], b'\x7fELF')
        if target_path != engine_path or target['sha256'] != engine['sha256']:
            verified_binary(target_path, target['sha256'], b'MZ' if platform == 'windows' else b'\x7fELF')
        return engine_path, target_path, engine['sha256'], target['sha256']
    except (OSError, KeyError, ValueError, TypeError) as exc:
        raise ValueError('Упаковщик для этой ОС не установлен или не прошёл проверку целостности') from exc


def capabilities():
    platforms = []
    for platform in ['windows', 'linux']:
        try:
            trusted_tools(platform)
            platforms.append(platform)
        except ValueError:
            pass
    return platforms
