"""Reviewed Windows query candidates; importing this module enables nothing.

Artifact definitions were inspected in Velociraptor 0.77.3. Windows execution
has NOT been verified. Only use these as projected baseline sources, never add
raw built-ins to collect(artifacts=...). LIMIT caps output, not scan work/bytes.
"""
from types import MappingProxyType

WINDOWS_EXECUTION_VERIFIED = False
AUTOMATICALLY_ENABLED = False
INSPECTED_ENGINE_VERSION = "0.77.3"

# One shared output cap, not 2000 for each branch. Users precede membership;
# reaching the cap can omit membership entirely. Flags/timestamps are metadata;
# neither ParsedV nor the enriched artifact's credential fields are projected.
ACCOUNTS_QUERY = r'''SELECT RecordType, RID, Username, FullName, PrimaryGroupID,
       IsLocalAdmin, Flags, LastLoginDate, PasswordResetDate,
       FailedLoginCount, LoginCount, GroupDomain, GroupRID, GroupName,
       MemberSID, MemberRID, MemberClass
FROM chain(
  users={
    SELECT "User" AS RecordType, RID, Username, FullName, PrimaryGroupID,
           IsLocalAdmin, Flags, LastLoginDate, PasswordResetDate,
           FailedLoginCount, LoginCount,
           NULL AS GroupDomain, NULL AS GroupRID, NULL AS GroupName,
           NULL AS MemberSID, NULL AS MemberRID, NULL AS MemberClass
    FROM Artifact.Windows.Forensics.SAM.Enriched(
      source="Users", SAMPath="C:/Windows/System32/Config/SAM")
  },
  administrators={
    SELECT "AdministratorMembership" AS RecordType,
           GroupDomain, GroupRID, GroupName, MemberSID, MemberRID, MemberClass,
           NULL AS RID, NULL AS Username, NULL AS FullName,
           NULL AS PrimaryGroupID, NULL AS IsLocalAdmin, NULL AS Flags,
           NULL AS LastLoginDate, NULL AS PasswordResetDate,
           NULL AS FailedLoginCount, NULL AS LoginCount
    FROM Artifact.Windows.Forensics.SAM.Enriched(
      source="GroupMembers", SAMPath="C:/Windows/System32/Config/SAM")
    WHERE GroupDomain = "Builtin" AND GroupRID = 544
  })
LIMIT 2000'''

WMI_PERSISTENCE_QUERY = r'''SELECT Namespace,
       ConsumerDetails.Name AS ConsumerName,
       ConsumerDetails.__CLASS AS ConsumerType,
       FilterDetails.Name AS FilterName,
       FilterDetails.__CLASS AS FilterType
FROM Artifact.Windows.Persistence.PermanentWMIEvents(
  AllRootNamespaces=FALSE,
  Namespaces=[dict(namespace="root/subscription"), dict(namespace="root/default")])
LIMIT 5000'''

REGISTRY_RUN_KEYS_QUERY = r'''SELECT Name, OSPath, Details
FROM Artifact.Windows.Sys.StartupItems(
  AlsoUpload=FALSE, startupFolderDirectories=[], startupApprovedGlobs=[],
  runKeyGlobs=[
    dict(KeyGlobs="HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*"),
    dict(KeyGlobs="HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*"),
    dict(KeyGlobs="HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*"),
    dict(KeyGlobs="HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*"),
    dict(KeyGlobs="HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*"),
    dict(KeyGlobs="HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*"),
    dict(KeyGlobs="HKEY_USERS\\*\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*"),
    dict(KeyGlobs="HKEY_USERS\\*\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*")])
LIMIT 10000'''

WINDOWS_QUERIES = MappingProxyType({
    "accounts": ("Accounts", ACCOUNTS_QUERY),
    "wmi_persistence": ("WMIPersistence", WMI_PERSISTENCE_QUERY),
    "registry_run_keys": ("RegistryRunKeys", REGISTRY_RUN_KEYS_QUERY),
})
ROW_LIMITS = MappingProxyType({"accounts": 2000, "wmi_persistence": 5000,
                               "registry_run_keys": 10000})
LIMITATIONS = (
    "Windows artifact execution, access permissions and archive paths unverified",
    "Output row caps do not bound scan work, memory, serialized bytes or success",
    "Accounts cap is shared; earlier user rows may exhaust membership capacity",
    "Administrators membership is direct only; no nested domain group expansion",
    "SAM access may fail; GroupMembers may perform live domain SID name lookups",
    "Projected SAM metadata excludes hashes; underlying artifact still parses SAM",
    "WMI covers linked subscriptions in two fixed namespaces, not orphan objects",
    "WMI binding enumeration is eager and may revisit bindings across namespaces",
    "Run keys cover mounted HKEY_USERS hives only, not all unloaded profiles",
    "Run Details are commands and may contain incidental secrets; no upload occurs",
    "No raw built-in artifact collection, integration or analysis enablement here",
)


def windows_query(source_id: str) -> tuple[str, str]:
    """Return a fixed candidate contract; never accept paths, WQL or user VQL."""
    if not isinstance(source_id, str) or source_id not in WINDOWS_QUERIES:
        raise ValueError("Unknown fixed Windows query source")
    return WINDOWS_QUERIES[source_id]
