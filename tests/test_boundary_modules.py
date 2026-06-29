"""Boundary tests for all Sovereign attack modules — no crash on edge inputs."""

from sovereign.models import AttackResult, Credential, EngagementContext
from sovereign.modules.enum import EnumModule
from sovereign.modules.kerberoast import KerberoastModule
from sovereign.modules.asreproast import ASREPRoastModule
from sovereign.modules.dcsync import DCsyncModule
from sovereign.modules.aclabuse import ACLAbuseModule
from sovereign.modules.lateral import LateralModule


def _ctx(**kw):
    defaults = dict(dc_ip="192.0.2.1", domain="test.local", username="admin",
                    password="pass", base_dn="DC=test,DC=local")
    defaults.update(kw)
    return EngagementContext(**defaults)


# ── EnumModule ──────────────────────────────────────────────────────────────

def test_enum_no_ldap():
    ctx = _ctx()
    results = EnumModule().run(ctx)
    assert isinstance(results, list)


def test_enum_empty_domain():
    ctx = _ctx(domain="", base_dn="")
    results = EnumModule().run(ctx)
    assert isinstance(results, list)


def test_enum_empty_creds():
    ctx = _ctx(username="", password="")
    results = EnumModule().run(ctx)
    assert isinstance(results, list)


def test_enum_hash_auth():
    ctx = _ctx(password="", nt_hash="aaaa")
    results = EnumModule().run(ctx)
    assert isinstance(results, list)


def test_enum_unreachable_dc():
    ctx = _ctx(dc_ip="192.0.2.254")
    results = EnumModule().run(ctx)
    assert isinstance(results, list)


# ── KerberoastModule ───────────────────────────────────────────────────────

def test_kerberoast_no_ldap():
    ctx = _ctx()
    results = KerberoastModule().run(ctx, output_file="")
    assert isinstance(results, list)


def test_kerberoast_empty_creds():
    ctx = _ctx(username="", password="")
    results = KerberoastModule().run(ctx, output_file="")
    assert isinstance(results, list)


def test_kerberoast_unreachable():
    ctx = _ctx(dc_ip="192.0.2.254")
    results = KerberoastModule().run(ctx, output_file="")
    assert isinstance(results, list)


def test_kerberoast_hash_auth():
    ctx = _ctx(password="", nt_hash="deadbeef")
    results = KerberoastModule().run(ctx, output_file="")
    assert isinstance(results, list)


def test_kerberoast_output_file():
    ctx = _ctx()
    results = KerberoastModule().run(ctx, output_file="/tmp/nonexistent_dir_test/hashes.txt")
    assert isinstance(results, list)


# ── ASREPRoastModule ───────────────────────────────────────────────────────

def test_asrep_no_accounts():
    ctx = _ctx()
    results = ASREPRoastModule().run(ctx, output_file="")
    assert isinstance(results, list)


def test_asrep_with_accounts():
    ctx = _ctx()
    ctx.loot["asrep_accounts"] = ["admin", "svc-backup", "nonexistent"]
    results = ASREPRoastModule().run(ctx, output_file="")
    assert isinstance(results, list)


def test_asrep_empty_accounts():
    ctx = _ctx()
    ctx.loot["asrep_accounts"] = []
    results = ASREPRoastModule().run(ctx, output_file="")
    assert isinstance(results, list)


def test_asrep_unreachable():
    ctx = _ctx(dc_ip="192.0.2.254")
    results = ASREPRoastModule().run(ctx, output_file="")
    assert isinstance(results, list)


def test_asrep_unicode_accounts():
    ctx = _ctx()
    ctx.loot["asrep_accounts"] = ["用户", "ユーザー"]
    results = ASREPRoastModule().run(ctx, output_file="")
    assert isinstance(results, list)


# ── DCsyncModule ───────────────────────────────────────────────────────────

def test_dcsync_no_impacket():
    ctx = _ctx()
    results = DCsyncModule().run(ctx, target_user="", output_file="")
    assert isinstance(results, list)


def test_dcsync_specific_user():
    ctx = _ctx()
    results = DCsyncModule().run(ctx, target_user="Administrator", output_file="")
    assert isinstance(results, list)


def test_dcsync_unreachable():
    ctx = _ctx(dc_ip="192.0.2.254")
    results = DCsyncModule().run(ctx, target_user="", output_file="")
    assert isinstance(results, list)


def test_dcsync_hash_auth():
    ctx = _ctx(password="", nt_hash="deadbeef")
    results = DCsyncModule().run(ctx, target_user="", output_file="")
    assert isinstance(results, list)


def test_dcsync_empty_creds():
    ctx = _ctx(username="", password="")
    results = DCsyncModule().run(ctx, target_user="", output_file="")
    assert isinstance(results, list)


# ── ACLAbuseModule ─────────────────────────────────────────────────────────

def test_acl_no_target():
    ctx = _ctx()
    results = ACLAbuseModule().run(ctx, target_user="", abuse_right="auto")
    assert isinstance(results, list)


def test_acl_auto_right():
    ctx = _ctx()
    results = ACLAbuseModule().run(ctx, target_user="Domain Admins", abuse_right="auto")
    assert isinstance(results, list)


def test_acl_genericall():
    ctx = _ctx()
    results = ACLAbuseModule().run(ctx, target_user="testuser", abuse_right="genericall")
    assert isinstance(results, list)


def test_acl_addmember():
    ctx = _ctx()
    results = ACLAbuseModule().run(ctx, target_user="Domain Admins", abuse_right="addmember")
    assert isinstance(results, list)


def test_acl_unreachable():
    ctx = _ctx(dc_ip="192.0.2.254")
    results = ACLAbuseModule().run(ctx, target_user="admin", abuse_right="auto")
    assert isinstance(results, list)


# ── LateralModule ──────────────────────────────────────────────────────────

def test_lateral_no_target():
    ctx = _ctx()
    results = LateralModule().run(ctx, target="", command="whoami")
    assert isinstance(results, list)


def test_lateral_unreachable():
    ctx = _ctx()
    results = LateralModule().run(ctx, target="192.0.2.254", command="whoami")
    assert isinstance(results, list)


def test_lateral_empty_command():
    ctx = _ctx()
    results = LateralModule().run(ctx, target="192.0.2.1", command="")
    assert isinstance(results, list)


def test_lateral_long_command():
    ctx = _ctx()
    results = LateralModule().run(ctx, target="192.0.2.1", command="A" * 10000)
    assert isinstance(results, list)


def test_lateral_hash_auth():
    ctx = _ctx(password="", nt_hash="deadbeef")
    results = LateralModule().run(ctx, target="192.0.2.1", command="whoami")
    assert isinstance(results, list)
