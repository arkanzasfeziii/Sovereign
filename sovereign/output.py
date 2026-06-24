"""Banner, legal warning, and result formatting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from sovereign.config import AUTHOR, LEGAL_WARNING, TOOL_NAME, VERSION
from sovereign.models import EngagementContext

try:
    import pyfiglet
    HAS_PYFIGLET = True
except ImportError:
    HAS_PYFIGLET = False


def print_banner() -> None:
    if HAS_PYFIGLET:
        print(f"\033[35m{pyfiglet.figlet_format('Sovereign', font='slant')}\033[0m")
    else:
        print(f"\033[35m\n  {TOOL_NAME} v{VERSION}\n\033[0m")
    print(f"\033[36m  Author: {AUTHOR}  |  Windows & AD Offensive Suite\033[0m\n")


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
    success = sum(1 for r in ctx.results if r.status == "SUCCESS")
    crits = sum(1 for r in ctx.results if r.severity == "CRITICAL")
    print(f"\n\033[35m{'═' * 60}\n  AD ENGAGEMENT RESULTS\n{'═' * 60}\033[0m")
    print(f"  Total: {len(ctx.results)} | Success: \033[32m{success}\033[0m | Critical: \033[35m{crits}\033[0m\n")

    icons = {"SUCCESS": "\033[32m[+]", "FAILED": "\033[31m[x]",
             "PARTIAL": "\033[33m[~]", "INFO": "\033[36m[*]"}
    reset = "\033[0m"
    for r in ctx.results:
        c = icons.get(r.status, "   ")
        tgt = f" → {r.target}" if r.target else ""
        print(f"  {c}{reset} [{r.module}] {r.action}{tgt}")
        if r.notes:
            print(f"        {r.notes}")

    if ctx.credentials:
        print(f"\n\033[32m[+] CREDENTIALS ({len(ctx.credentials)})\033[0m")
        for c in ctx.credentials:
            print(f"  [{c.type}] {c.domain}\\{c.username}: {c.secret[:60]}")
            if c.notes:
                print(f"         {c.notes}")

    if output:
        payload = {
            "tool": TOOL_NAME, "version": VERSION,
            "domain": ctx.domain, "dc": ctx.dc_ip,
            "results": [{"module": r.module, "action": r.action, "status": r.status,
                         "severity": r.severity, "notes": r.notes} for r in ctx.results],
            "credentials": [{"type": c.type, "domain": c.domain, "username": c.username,
                             "source": c.source} for c in ctx.credentials],
            "loot": ctx.loot,
        }
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"\n\033[32m[+] Results saved → {output}\033[0m")
