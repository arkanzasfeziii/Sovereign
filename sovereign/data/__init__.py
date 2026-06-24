"""Static data for Sovereign modules."""

from __future__ import annotations

from typing import Dict, List

UAC_ACCOUNTDISABLE = 0x00000002
UAC_DONT_REQ_PREAUTH = 0x00400000
UAC_TRUSTED_FOR_DELEGATION = 0x00080000
UAC_NOT_DELEGATED = 0x01000000
UAC_PASSWORD_NEVER_EXPIRES = 0x00010000

ACL_RIGHTS: Dict[str, str] = {
    "00000000-0000-0000-0000-000000000000": "GenericAll",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
}

ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_SELF = 0x00000008
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000

PRIV_GROUPS: List[str] = [
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
    "Server Operators", "Group Policy Creator Owners",
    "DNSAdmins", "Exchange Windows Permissions",
]

LDAP_USERS_WITH_SPN = (
    "(&(objectClass=user)(servicePrincipalName=*)"
    "(!(objectClass=computer))"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
)
LDAP_USERS_NO_PREAUTH = (
    "(&(objectClass=user)"
    "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
)
LDAP_ALL_USERS = (
    "(&(objectClass=user)(objectCategory=person)"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
)
LDAP_COMPUTERS = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
LDAP_UNCONSTRAINED_DELEG = (
    "(&(objectClass=computer)"
    "(userAccountControl:1.2.840.113556.1.4.803:=524288))"
)
LDAP_CONSTRAINED_DELEG = (
    "(&(objectClass=user)"
    "(msDS-AllowedToDelegateTo=*))"
)

HC_KERBEROAST = 13100
HC_ASREPROAST = 18200
