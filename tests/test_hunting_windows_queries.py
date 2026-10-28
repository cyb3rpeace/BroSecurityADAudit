"""Server-only contract tests; never execute a Windows artifact collection."""
import json
import os
from pathlib import Path
import re
import subprocess
import unittest

from app.modules import hunting_windows_queries as w


class WindowsQueryContractTests(unittest.TestCase):
    def test_fixed_candidate_contracts_not_enabled(self):
        self.assertFalse(w.WINDOWS_EXECUTION_VERIFIED)
        self.assertFalse(w.AUTOMATICALLY_ENABLED)
        self.assertEqual(w.INSPECTED_ENGINE_VERSION, "0.77.3")
        self.assertEqual(set(w.WINDOWS_QUERIES),
                         {"accounts", "wmi_persistence", "registry_run_keys"})
        for key, (label, query) in w.WINDOWS_QUERIES.items():
            self.assertEqual(w.windows_query(key), (label, query))
            self.assertTrue(query.endswith(f"LIMIT {w.ROW_LIMITS[key]}"))
            for forbidden in ("SELECT *", "upload(", "execve(", "collect(",
                              "EventData", "ScriptText", "_LMHash", "_NTHash", "ParsedV"):
                self.assertNotIn(forbidden, query)
        for key in ("unknown", "accounts()", None, [], True):
            with self.assertRaises(ValueError):
                w.windows_query(key)
        with self.assertRaises(TypeError):
            w.WINDOWS_QUERIES["injected"] = ("x", "x")

    def test_accounts_have_discriminators_and_direct_admin_filter(self):
        q = w.ACCOUNTS_QUERY
        self.assertIn('"User" AS RecordType', q)
        self.assertIn('"AdministratorMembership" AS RecordType', q)
        self.assertIn('WHERE GroupDomain = "Builtin" AND GroupRID = 544', q)
        self.assertEqual(q.count('SAMPath="C:/Windows/System32/Config/SAM"'), 2)
        self.assertEqual(q.count("LIMIT "), 1)
        self.assertIn('source="Users"', q)
        self.assertIn('source="GroupMembers"', q)

    def test_wmi_fixed_namespaces_metadata_only(self):
        q = w.WMI_PERSISTENCE_QUERY
        self.assertIn('AllRootNamespaces=FALSE', q)
        self.assertIn('dict(namespace="root/subscription")', q)
        self.assertIn('dict(namespace="root/default")', q)
        self.assertNotIn('CommandLineTemplate', q)
        self.assertNotIn('ExecutablePath', q)
        self.assertNotIn('SELECT Namespace, ConsumerDetails,', q)

    def test_exact_run_once_globs_and_no_folder_enrichment(self):
        q = w.REGISTRY_RUN_KEYS_QUERY
        self.assertIn('AlsoUpload=FALSE', q)
        self.assertIn('startupFolderDirectories=[]', q)
        self.assertIn('startupApprovedGlobs=[]', q)
        globs = re.findall(r'KeyGlobs="([^"]+)"', q)
        decoded = [json.loads('"' + g + '"') for g in globs]
        expected = {root + suffix + key + r"\*"
                    for root in (r"HKEY_LOCAL_MACHINE", r"HKEY_USERS\*")
                    for suffix in (r"\SOFTWARE\Microsoft\Windows\CurrentVersion" + chr(92),
                                   r"\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion" + chr(92))
                    for key in ("Run", "RunOnce")}
        self.assertEqual(set(decoded), expected)
        self.assertEqual(len(decoded), 8)
        self.assertNotIn("Enabled", q)


class SyntheticInstalledEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = os.environ.get("HUNTING_VQL_ENGINE", "/work/tools/hunting/velociraptor-linux")
        if not Path(cls.engine).is_file():
            raise unittest.SkipTest("Installed Linux VQL engine not available")

    def execute(self, query):
        # Safety guard: all artifact calls must have been replaced by fixtures.
        self.assertNotIn("Artifact.", query)
        result = subprocess.run([self.engine, "query", "--format=json", query],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("ERROR", result.stderr.upper())
        return json.loads(result.stdout)

    def test_accounts_projection_filters_and_excludes_credential_fields(self):
        user_fixture = '''foreach(row=[dict(RID=1001, Username="fixture-user",
            FullName="Fixture", PrimaryGroupID=513, IsLocalAdmin=TRUE,
            Flags="Normal user account", LastLoginDate="2026-01-01T00:00:00Z",
            PasswordResetDate="2026-01-01T00:00:00Z", FailedLoginCount=0,
            LoginCount=1, _LMHash="FORBIDDEN", _NTHash="FORBIDDEN")])'''
        member_fixture = '''foreach(row=[
            dict(GroupDomain="Builtin", GroupRID=544, GroupName="localized",
                 MemberSID="S-1-5-21-1-2-3-1001", MemberRID=1001,
                 MemberClass="Local account", Member="FORBIDDEN"),
            dict(GroupDomain="Builtin", GroupRID=545, MemberSID="exclude-other"),
            dict(GroupDomain="Account", GroupRID=544, MemberSID="exclude-domain")])'''
        q = re.sub(r'Artifact\.Windows\.Forensics\.SAM\.Enriched\(\s*source="Users",[^)]*\)',
                   lambda _: user_fixture, w.ACCOUNTS_QUERY)
        q = re.sub(r'Artifact\.Windows\.Forensics\.SAM\.Enriched\(\s*source="GroupMembers",[^)]*\)',
                   lambda _: member_fixture, q)
        rows = self.execute(q)
        self.assertEqual([r["RecordType"] for r in rows], ["User", "AdministratorMembership"])
        self.assertEqual(rows[0]["Username"], "fixture-user")
        self.assertEqual(rows[1]["GroupRID"], 544)
        self.assertIsNone(rows[0]["MemberSID"])
        self.assertIsNone(rows[1]["Username"])
        self.assertNotIn("FORBIDDEN", json.dumps(rows))
        self.assertNotIn("exclude-", json.dumps(rows))
        self.assertEqual(len(self.execute(q.replace("LIMIT 2000", "LIMIT 1"))), 1)

    def test_wmi_projects_nested_objects_without_payload(self):
        fixture = '''foreach(row=[dict(Namespace="root/subscription",
            ConsumerDetails=dict(Name="consumer", `__CLASS`="ActiveScriptEventConsumer",
                                 ScriptText="FORBIDDEN", CommandLineTemplate="FORBIDDEN"),
            FilterDetails=dict(Name="filter", `__CLASS`="__EventFilter", Query="FORBIDDEN"))])'''
        q = w.WMI_PERSISTENCE_QUERY.split("FROM Artifact.")[0] + "FROM " + fixture + "\nLIMIT 5000"
        rows = self.execute(q)
        self.assertEqual(rows, [dict(Namespace="root/subscription", ConsumerName="consumer",
                                    ConsumerType="ActiveScriptEventConsumer", FilterName="filter",
                                    FilterType="__EventFilter")])

    def test_wmi_fixed_parameter_expression(self):
        params = w.WMI_PERSISTENCE_QUERY.split("PermanentWMIEvents(", 1)[1].rsplit(")\nLIMIT", 1)[0]
        rows = self.execute("SELECT dict(" + params + ") AS Params FROM scope()")
        self.assertEqual(rows[0]["Params"], {
            "AllRootNamespaces": False,
            "Namespaces": [{"namespace": "root/subscription"}, {"namespace": "root/default"}]})

    def test_registry_projection_and_parameter_expression(self):
        fixture = '''foreach(row=[dict(Name="Fixture", OSPath="fixture-path", Details="fixture-command",
                                      Upload="FORBIDDEN", Enabled="FORBIDDEN")])'''
        q = w.REGISTRY_RUN_KEYS_QUERY.split("FROM Artifact.")[0] + "FROM " + fixture + "\nLIMIT 10000"
        self.assertEqual(self.execute(q), [dict(Name="Fixture", OSPath="fixture-path", Details="fixture-command")])
        # Evaluate exact fixed parameter expression without executing StartupItems.
        params = w.REGISTRY_RUN_KEYS_QUERY.split("StartupItems(", 1)[1].rsplit(")\nLIMIT", 1)[0]
        rows = self.execute("SELECT dict(" + params + ") AS Params FROM scope()")
        self.assertFalse(rows[0]["Params"]["AlsoUpload"])
        self.assertEqual(rows[0]["Params"]["startupFolderDirectories"], [])
        self.assertEqual(rows[0]["Params"]["startupApprovedGlobs"], [])
        self.assertEqual(len(rows[0]["Params"]["runKeyGlobs"]), 8)


if __name__ == "__main__":
    unittest.main()
