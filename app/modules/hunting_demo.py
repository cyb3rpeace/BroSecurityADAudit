"""Safe, deterministic synthetic Threat Hunting demo archive generator."""
from __future__ import annotations
import base64, hashlib, io, json, os, zipfile
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
import pyzipper
from app.modules.hunting_packager import tenant_certificate
from app.modules.hunting_ingest import summarize_container
from app.modules.hunting_results import save_result

MARKER = "synthetic-demo"

def _rows():
    return {
      "Host": [{"Hostname":"SYNTH-DFIR-01","Fqdn":"SYNTH-DFIR-01.synthetic-demo","OS":"Windows","Platform":"windows","Architecture":"amd64"}],
      "Processes": [
        {"Pid":4120,"Ppid":892,"Name":"powershell.exe","Exe":"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe","Username":"SYNTH\\analyst","CommandLine":"powershell.exe -EncodedCommand UABvAHcAZQByAFMAaABlAGwAbAAgAHMAeQBuAHQAaABlAHQAaQBjAA==","CreateTime":"2026-11-05T10:12:00Z","DemoMarker":MARKER},
        {"Pid":4288,"Ppid":4120,"Name":"rundll32.exe","Exe":"C:/Windows/System32/rundll32.exe","Username":"SYNTH\\analyst","CommandLine":"rundll32.exe C:/Users/Public/synthetic-demo.dll,Start","CreateTime":"2026-11-05T10:12:04Z","DemoMarker":MARKER},
        {"Pid":892,"Ppid":640,"Name":"svchost.exe","Exe":"C:/Windows/System32/svchost.exe","Username":"NT AUTHORITY\\SYSTEM","CommandLine":"svchost.exe -k netsvcs","CreateTime":"2026-11-05T10:00:00Z","DemoMarker":MARKER}],
      "Network": [{"Pid":4288,"LocalAddr":"10.0.0.50:49152","RemoteIP":"198.51.100.44","RemotePort":443,"State":"ESTABLISHED","DemoMarker":MARKER}],
      "Services": [{"Name":"SyntheticUpdate","DisplayName":"Synthetic Update Service","State":"Running","StartMode":"Auto","PathName":"C:/ProgramData/synthetic-demo/update.exe","UserAccount":"LocalSystem","DemoMarker":MARKER}],
      "Tasks": [{"TaskName":"Synthetic\\Telemetry","Command":"C:/Users/Public/synthetic-demo.exe","Arguments":"--demo","UserId":"SYSTEM","RunLevel":"Highest","DemoMarker":MARKER}],
      "Startup": [{"Name":"SyntheticDemo","OSPath":"HKEY_USERS/S-1-5-21-999/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce","Details":"C:/Users/Public/synthetic-demo.exe","DemoMarker":MARKER}],
      "WMIPersistence": [{"Namespace":"root/subscription","ConsumerName":"SyntheticConsumer","ConsumerType":"ActiveScriptEventConsumer","FilterName":"SyntheticFilter","FilterType":"__EventFilter","DemoMarker":MARKER}],
      "SecurityEvents": [{"EventID":4625,"TimeCreated":"2026-11-05T10:15:00Z","Computer":"SYNTH-DFIR-01","Provider":"Microsoft-Windows-Security-Auditing","DemoMarker":MARKER},{"EventID":4697,"TimeCreated":"2026-11-05T10:12:10Z","Computer":"SYNTH-DFIR-01","DemoMarker":MARKER},{"EventID":1102,"TimeCreated":"2026-11-05T10:20:00Z","Computer":"SYNTH-DFIR-01","DemoMarker":MARKER}],
      "PowerShellEvents": [{"EventID":4104,"TimeCreated":"2026-11-05T10:12:00Z","Channel":"PowerShell","Provider":"synthetic-demo","ScriptBlockId":"synthetic-4104","DemoMarker":MARKER}],
      "DefenderEvents": [{"EventID":1116,"TimeCreated":"2026-11-05T10:13:00Z","Channel":"Defender","Provider":"synthetic-demo","ThreatName":"Synthetic.Demo.TestSignal","DemoMarker":MARKER},{"EventID":5001,"TimeCreated":"2026-11-05T10:14:00Z","Channel":"Defender","Provider":"synthetic-demo","DemoMarker":MARKER}],
      "RDPEvents": [{"EventID":4624,"TimeCreated":"2026-11-05T10:05:00Z","Channel":"RDP","User":"SYNTH\\analyst","DemoMarker":MARKER}],
      "Accounts": [{"RecordType":"User","RID":1001,"Username":"synthetic-analyst","IsLocalAdmin":True,"DemoMarker":MARKER}]
    }

def create_demo(base: Path, key_root: Path, company_id: int):
    cert_pem = tenant_certificate(key_root, company_id).encode()
    cert = serialization.load_pem_x509_certificate(cert_pem)
    password = os.urandom(32)
    metadata = {"Scheme":"X509","CampaignId":"synthetic-demo","CollectorSchema":"brosec.result.v1","DemoMarker":MARKER,"PublicKey":cert_pem.decode(),"EncryptedPass":base64.b64encode(cert.public_key().encrypt(password,padding.OAEP(mgf=padding.MGF1(hashes.SHA512()),algorithm=hashes.SHA512(),label=None))).decode()}
    inner = io.BytesIO()
    with pyzipper.AESZipFile(inner,"w",compression=zipfile.ZIP_DEFLATED,encryption=pyzipper.WZ_AES) as z:
        z.setpassword(password)
        for source, rows in _rows().items():
            z.writestr(f"results/{source}.json", "".join(json.dumps(row, ensure_ascii=False)+"\\n" for row in rows).encode())
    outer = io.BytesIO()
    with zipfile.ZipFile(outer,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr("metadata.json", json.dumps(metadata,ensure_ascii=False).encode()); z.writestr("data.zip",inner.getvalue())
    data=outer.getvalue(); summary=summarize_container(data,key_root,company_id); summary.update({"synthetic_demo":True,"demo_marker":MARKER,"sha256":hashlib.sha256(data).hexdigest()})
    return save_result(base,company_id,data,summary)
