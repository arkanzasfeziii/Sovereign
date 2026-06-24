"""LDAP connection and search helpers."""

from __future__ import annotations

from typing import Any, Dict, List

from sovereign.logger import log
from sovereign.models import EngagementContext

try:
    from ldap3 import Server, Connection, ALL, NTLM, ANONYMOUS, SUBTREE
    from ldap3.core.exceptions import LDAPException
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False


def domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


def ldap_connect(ctx: EngagementContext) -> bool:
    if not HAS_LDAP3:
        log("Install ldap3: pip install ldap3", "ERR")
        return False
    try:
        srv = Server(ctx.dc_ip, port=389, get_info=ALL, connect_timeout=10)
        if ctx.nt_hash:
            lm = ctx.lm_hash or "aad3b435b51404eeaad3b435b51404ee"
            ctx.ldap_conn = Connection(
                srv, user=f"{ctx.domain}\\{ctx.username}",
                password=f"{lm}:{ctx.nt_hash}",
                authentication=NTLM, auto_bind=True,
            )
        elif ctx.password:
            ctx.ldap_conn = Connection(
                srv, user=f"{ctx.domain}\\{ctx.username}",
                password=ctx.password,
                authentication=NTLM, auto_bind=True,
            )
        else:
            ctx.ldap_conn = Connection(srv, authentication=ANONYMOUS, auto_bind=True)

        if not ctx.base_dn:
            ctx.base_dn = domain_to_dn(ctx.domain)
        log(f"LDAP connected to {ctx.dc_ip} as {ctx.username}@{ctx.domain}", "OK")
        return True
    except Exception as exc:
        log(f"LDAP connect failed: {exc}", "ERR")
        return False


def ldap_search(ctx: EngagementContext, search_filter: str,
                attributes: List[str], base: str = "") -> List[Any]:
    base = base or ctx.base_dn
    try:
        ctx.ldap_conn.search(
            search_base=base, search_filter=search_filter,
            search_scope=SUBTREE, attributes=attributes,
        )
        return list(ctx.ldap_conn.entries)
    except Exception as exc:
        log(f"LDAP search failed: {exc}", "WARN")
        return []
