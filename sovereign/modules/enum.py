"""Full LDAP enumeration: users, computers, SPNs, admins, ACLs, trusts, policy."""

from __future__ import annotations

from typing import Dict, List

from sovereign.models import AttackResult, Credential, EngagementContext
from sovereign.logger import log
from sovereign.modules.base import BaseModule
from sovereign.utils.ldap_helpers import ldap_connect, ldap_search
from sovereign.data import (
    UAC_DONT_REQ_PREAUTH,
    UAC_TRUSTED_FOR_DELEGATION,
    UAC_PASSWORD_NEVER_EXPIRES,
    UAC_NOT_DELEGATED,
    PRIV_GROUPS,
    LDAP_ALL_USERS,
    LDAP_USERS_WITH_SPN,
    LDAP_USERS_NO_PREAUTH,
    LDAP_COMPUTERS,
    LDAP_UNCONSTRAINED_DELEG,
    LDAP_CONSTRAINED_DELEG,
)


def _uac_flags(uac: int) -> List[str]:
    flags = []
    if uac & UAC_DONT_REQ_PREAUTH:    flags.append("NO_PREAUTH")
    if uac & UAC_TRUSTED_FOR_DELEGATION: flags.append("UNCONSTRAINED_DELEG")
    if uac & UAC_PASSWORD_NEVER_EXPIRES: flags.append("PWD_NEVER_EXPIRES")
    if uac & UAC_NOT_DELEGATED:       flags.append("NOT_DELEGATED")
    return flags


class EnumModule(BaseModule):
    """Full LDAP enumeration: users, computers, SPNs, admins, ACLs, trusts, policy."""

    name = "enum"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        results: List[AttackResult] = []
        if not ldap_connect(ctx):
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
        entries = ldap_search(ctx, "(objectClass=domain)",
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
        log(f"Domain: {info['dn']} | FL: {info['functional_level']} | "
            f"Lockout: {info['lockout_threshold']}", "INFO")
        return [AttackResult("enum", "domain_info", "INFO", data=info,
                             notes=f"Lockout threshold={info['lockout_threshold']} — spray carefully")]

    def _enum_users(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = ldap_search(ctx, LDAP_ALL_USERS,
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
                log(f"[Enum] Password in description: {sam} → {desc[:60]}", "CRIT")
                ctx.credentials.append(Credential(
                    "ldap_description", ctx.domain, sam, desc,
                    "LDAP description field", f"Possible password in description for {sam}"
                ))
            if admin_count == 1:
                interesting.append({"sam": sam, "reason": "adminCount=1"})

        ctx.loot["users"] = users
        log(f"[Enum] {len(users)} enabled users | {len(interesting)} interesting", "INFO")
        return [AttackResult("enum", "users", "INFO",
                             data={"count": len(users), "interesting": interesting[:10]},
                             severity="HIGH" if interesting else "INFO",
                             notes=f"{len(users)} users enumerated, {len(interesting)} with sensitive info")]

    def _enum_spn_users(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = ldap_search(ctx, LDAP_USERS_WITH_SPN,
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
                log(f"[Enum] HIGH-VALUE SPN: {sam} (member of admin group!) → {spns[0]}", "CRIT")
        ctx.loot["spn_accounts"] = spn_accounts
        log(f"[Enum] {len(spn_accounts)} Kerberoastable accounts found", "WARN" if spn_accounts else "INFO")
        return [AttackResult("enum", "spn_accounts", "SUCCESS" if spn_accounts else "INFO",
                             data=spn_accounts,
                             severity="CRITICAL" if any(a["is_admin"] for a in spn_accounts) else "HIGH",
                             notes=f"{len(spn_accounts)} Kerberoastable accounts. Run: --modules kerberoast")]

    def _enum_asrep_users(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = ldap_search(ctx, LDAP_USERS_NO_PREAUTH,
                              ["sAMAccountName","distinguishedName"])
        accs = [str(getattr(e, "sAMAccountName", "")) for e in entries]
        ctx.loot["asrep_accounts"] = accs
        if accs:
            log(f"[Enum] {len(accs)} AS-REP roastable accounts (no preauth): {accs}", "CRIT")
        return [AttackResult("enum", "asrep_accounts",
                             "SUCCESS" if accs else "INFO",
                             data=accs, severity="CRITICAL" if accs else "INFO",
                             notes=f"{len(accs)} accounts without Kerberos preauth. Run: --modules asreproast")]

    def _enum_computers(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = ldap_search(ctx, LDAP_COMPUTERS,
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
        log(f"[Enum] {len(computers)} domain-joined computers", "INFO")
        return [AttackResult("enum", "computers", "INFO",
                             data={"count": len(computers), "systems": computers[:20]},
                             notes=f"{len(computers)} domain computers (targets for lateral movement)")]

    def _enum_admins(self, ctx: EngagementContext) -> List[AttackResult]:
        results = []
        all_priv: Dict[str, List[str]] = {}
        for grp in PRIV_GROUPS:
            filter_q = f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN={grp},CN=Users,{ctx.base_dn}))"
            entries = ldap_search(ctx, filter_q, ["sAMAccountName"])
            if entries:
                members = [str(getattr(e, "sAMAccountName", "")) for e in entries]
                all_priv[grp] = members
                log(f"[Enum] {grp}: {members}", "WARN" if members else "INFO")
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
        entries = ldap_search(ctx, LDAP_UNCONSTRAINED_DELEG,
                              ["sAMAccountName","dNSHostName"])
        unc = [str(getattr(e, "sAMAccountName", "")) for e in entries]
        if unc:
            log(f"[Enum] UNCONSTRAINED DELEGATION computers: {unc}", "CRIT")
        ctx.loot["unconstrained_delegation"] = unc
        results.append(AttackResult("enum", "unconstrained_delegation",
                                    "SUCCESS" if unc else "INFO",
                                    data=unc, severity="CRITICAL" if unc else "INFO",
                                    notes=f"Unconstrained delegation hosts: {unc}. Printer Bug / SpoolSample attack possible"))

        # Constrained delegation
        entries = ldap_search(ctx, LDAP_CONSTRAINED_DELEG,
                              ["sAMAccountName","msDS-AllowedToDelegateTo"])
        con = []
        for e in entries:
            spns = [str(s) for s in (getattr(e, "msDS-AllowedToDelegateTo", []) or [])]
            con.append({"sam": str(getattr(e, "sAMAccountName", "")), "delegate_to": spns})
        if con:
            log(f"[Enum] CONSTRAINED DELEGATION accounts: {[c['sam'] for c in con]}", "WARN")
        ctx.loot["constrained_delegation"] = con
        results.append(AttackResult("enum", "constrained_delegation",
                                    "SUCCESS" if con else "INFO",
                                    data=con, severity="HIGH" if con else "INFO",
                                    notes=f"{len(con)} constrained delegation accounts"))
        return results

    def _enum_acls(self, ctx: EngagementContext) -> List[AttackResult]:
        """Find dangerous ACLs on privileged objects -- generic approach."""
        interesting_acls = []
        # Get DA group DN
        entries = ldap_search(ctx, f"(cn=Domain Admins)", ["distinguishedName","nTSecurityDescriptor"])
        if not entries:
            return []
        # Without control extension we can still get nTSecurityDescriptor
        # Use raw LDAP attribute to find WriteDACL/GenericAll
        for e in entries:
            raw_sd = getattr(e, "nTSecurityDescriptor", None)
            if raw_sd:
                # Check for suspicious ACEs (simplified -- full parsing requires sddl lib)
                sd_str = str(raw_sd)
                if "GenericAll" in sd_str or "WriteDACL" in sd_str:
                    interesting_acls.append({"object": str(e.distinguishedName), "acl": "suspicious"})

        # Alternative: check current user's effective rights on DA group via ldap3
        current_user_dn_entries = ldap_search(
            ctx, f"(sAMAccountName={ctx.username})", ["distinguishedName"])
        current_dn = str(current_user_dn_entries[0].distinguishedName) if current_user_dn_entries else ""
        ctx.loot["current_user_dn"] = current_dn

        # Find objects where anyone has full control / WriteDACL (broad search)
        entries = ldap_search(ctx,
            "(&(objectClass=group)(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Administrators)))",
            ["distinguishedName","nTSecurityDescriptor"])
        ctx.loot["acl_checks"] = interesting_acls
        return [AttackResult("enum", "acl_scan", "PARTIAL",
                             data={"current_user_dn": current_dn, "interesting": interesting_acls},
                             notes="ACL enumeration requires dacl-mode LDAP or BloodHound for complete analysis. "
                                   "Use: bloodhound-python -u USER -p PASS -d DOMAIN -c ACL")]

    def _enum_trusts(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = ldap_search(ctx, "(objectClass=trustedDomain)",
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
                log(f"[Enum] DOMAIN TRUST (Outbound): {getattr(e, 'trustPartner', '')} — lateral possible", "WARN")
        ctx.loot["domain_trusts"] = trusts
        return [AttackResult("enum", "domain_trusts", "INFO", data=trusts,
                             severity="HIGH" if trusts else "INFO",
                             notes=f"{len(trusts)} domain trust(s). Outbound = attack path to partner domain")]

    def _enum_policy(self, ctx: EngagementContext) -> List[AttackResult]:
        entries = ldap_search(ctx, "(objectClass=domain)",
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
            log("[Enum] NO ACCOUNT LOCKOUT POLICY — unlimited password spray!", "CRIT")
        ctx.loot["password_policy"] = pol
        return [AttackResult("enum", "password_policy", "INFO", data=pol,
                             severity="CRITICAL" if no_lockout else "INFO",
                             notes=f"Lockout threshold={pol['lockout_threshold']} | "
                                   f"Min length={pol['min_length']}"
                                   + (" | ⚠ NO LOCKOUT!" if no_lockout else ""))]
