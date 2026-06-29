"""Boundary tests for sovereign.output, sovereign.logger, sovereign.exceptions, sovereign.cli."""

import os
import tempfile

from sovereign.cli import MODULE_REGISTRY, build_parser
from sovereign.exceptions import DependencyError, LDAPConnectionError, SovereignError
from sovereign.logger import log
from sovereign.models import AttackResult, Credential, EngagementContext
from sovereign.output import dump_results


# ── log ─────────────────────────────────────────────────────────────────────

def test_log_empty():
    log("", "INFO")


def test_log_unknown():
    log("msg", "NONEXISTENT")


def test_log_long():
    log("X" * 10000, "CRIT")


def test_log_unicode():
    log("تست فارسی", "OK")


def test_log_all_levels():
    for lv in ("INFO", "OK", "WARN", "ERR", "CRIT"):
        log(f"test {lv}", lv)


# ── dump_results ────────────────────────────────────────────────────────────

def _ctx(**kw):
    defaults = dict(dc_ip="10.0.0.1", domain="corp.local", username="", password="")
    defaults.update(kw)
    return EngagementContext(**defaults)


def test_dump_empty():
    dump_results(_ctx(), None)


def test_dump_with_results():
    ctx = _ctx()
    ctx.results = [AttackResult("enum", "users", "SUCCESS", severity="HIGH", notes="312 users")]
    dump_results(ctx, None)


def test_dump_with_creds():
    ctx = _ctx()
    ctx.credentials = [Credential("ntlm", "corp.local", "admin", "aad3b:hash", "dcsync")]
    dump_results(ctx, None)


def test_dump_to_file():
    ctx = _ctx()
    ctx.results = [AttackResult("test", "test", "SUCCESS")]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    dump_results(ctx, path)
    assert os.path.exists(path)
    os.unlink(path)


def test_dump_many():
    ctx = _ctx()
    ctx.results = [AttackResult(f"m{i}", f"a{i}", "SUCCESS", notes="n") for i in range(200)]
    dump_results(ctx, None)


# ── build_parser ────────────────────────────────────────────────────────────

def test_parser_required():
    args = build_parser().parse_args(["--dc-ip", "10.0.0.1", "--domain", "corp.local"])
    assert args.dc_ip == "10.0.0.1"


def test_parser_hashes():
    args = build_parser().parse_args(["--dc-ip", "x", "--domain", "x", "--hashes", "LM:NT"])
    assert args.hashes == "LM:NT"


def test_parser_modules():
    args = build_parser().parse_args(["--dc-ip", "x", "--domain", "x", "--modules", "all"])
    assert "all" in args.modules


def test_parser_target():
    args = build_parser().parse_args(["--dc-ip", "x", "--domain", "x", "--target", "10.0.0.5"])
    assert args.target == "10.0.0.5"


def test_parser_acl():
    args = build_parser().parse_args(["--dc-ip", "x", "--domain", "x",
                                      "--acl-target", "Domain Admins", "--acl-right", "addmember"])
    assert args.acl_target == "Domain Admins"
    assert args.acl_right == "addmember"


# ── exceptions ──────────────────────────────────────────────────────────────

def test_sovereign_error():
    assert str(SovereignError("test")) == "test"


def test_ldap_error():
    assert isinstance(LDAPConnectionError("fail"), SovereignError)


def test_dep_error():
    e = DependencyError("ldap3")
    assert "ldap3" in str(e)
    assert e.package == "ldap3"


def test_dep_inherits():
    assert isinstance(DependencyError("x"), SovereignError)


def test_registry_complete():
    expected = {"enum", "kerberoast", "asreproast", "dcsync", "acl-abuse", "lateral"}
    assert set(MODULE_REGISTRY.keys()) == expected
