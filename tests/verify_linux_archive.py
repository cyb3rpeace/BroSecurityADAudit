import json, subprocess, tempfile
from pathlib import Path
from tests.test_hunting_builder import BuilderTests
from app.modules.hunting_builder import compile_config
from app.modules.hunting_ingest import summarize_container
from cryptography.hazmat.primitives import serialization
BuilderTests.setUpClass()
with tempfile.TemporaryDirectory(prefix='brosec-linux-verify-') as tmp:
    root=Path(tmp); keys=root/'keys'/'1';keys.mkdir(parents=True)
    (keys/'offline-keypair.pem').write_bytes(BuilderTests.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    profile=dict(id='a'*32, platform='linux', artifacts=['host','linux_services','linux_crontab','linux_suid'],timeout_seconds=120,event_days=7)
    data,_=compile_config(profile,BuilderTests.pem)
    config=root/'config.json';config.write_bytes(data)
    run=subprocess.run(['/opt/ad-audit/tools/hunting/velociraptor-linux','--config',str(config),'artifacts','collect','Collector','--nobanner'],cwd=root,capture_output=True,text=True,timeout=150)
    archives=list(root.glob('BroSec-*.zip'))
    if run.returncode or len(archives)!=1: raise RuntimeError('Collection failed: '+run.stderr[-2000:])
    summary=summarize_container(archives[0],root/'keys',1)
    print(json.dumps({'sources':summary['sources'],'provenance':summary.get('collection_provenance',summary.get('provenance'))},default=str))
    sources=summary['sources']
    for name in ['Host','LinuxServices','LinuxCrontab','LinuxSUID']:
        assert any('/'+name+'.json' in __import__('urllib.parse', fromlist=['unquote']).unquote(s['source']) and s['rows']>0 for s in sources),name
    print('PASS: actual encrypted Linux archive decrypted and all requested sources ingested')
