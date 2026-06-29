"""Boundary tests for sovereign.models dataclasses."""

from sovereign.models import ADObject, AttackResult, Credential, EngagementContext


# ── AttackResult ────────────────────────────────────────────────────────────

def test_result_empty():
    r = AttackResult(module="", action="", status="")
    assert r.severity == "INFO"


def test_result_long_notes():
    r = AttackResult(module="enum", action="users", status="SUCCESS", notes="N" * 50000)
    assert len(r.notes) == 50000


def test_result_unicode():
    r = AttackResult(module="تست", action="عملکرد", status="SUCCESS", notes="فارسی")
    assert r.module == "تست"


def test_result_special_chars():
    r = AttackResult(module="<script>", action="'; DROP TABLE", status="FAILED")
    assert "<script>" in r.module


def test_result_all_statuses():
    for s in ("SUCCESS", "FAILED", "PARTIAL", "INFO"):
        r = AttackResult(module="x", action="x", status=s)
        assert r.status == s


# ── Credential ──────────────────────────────────────────────────────────────

def test_cred_empty_secret():
    c = Credential(type="ntlm", domain="corp.local", username="admin", secret="", source="dcsync")
    assert c.secret == ""


def test_cred_ntlm_hash():
    c = Credential(type="ntlm", domain="corp.local", username="admin",
                   secret="aad3b435b51404ee:8846f7eaee8fb117", source="dcsync")
    assert ":" in c.secret


def test_cred_long_secret():
    c = Credential(type="krb", domain="corp.local", username="svc",
                   secret="$krb5tgs$" + "A" * 10000, source="kerberoast")
    assert len(c.secret) > 10000


def test_cred_unicode_user():
    c = Credential(type="ntlm", domain="ドメイン", username="ユーザー", secret="hash", source="test")
    assert c.domain == "ドメイン"


def test_cred_special_password():
    c = Credential(type="plain", domain="corp.local", username="admin",
                   secret='P@ss"w0rd!<>&', source="ldap_desc")
    assert '"' in c.secret


# ── ADObject ────────────────────────────────────────────────────────────────

def test_adobj_empty():
    obj = ADObject(dn="", sam="", object_class="")
    assert obj.attributes == {}


def test_adobj_long_dn():
    dn = ",".join([f"OU=level{i}" for i in range(50)]) + ",DC=corp,DC=local"
    obj = ADObject(dn=dn, sam="user", object_class="user")
    assert len(obj.dn) > 200


def test_adobj_nested_attrs():
    obj = ADObject(dn="CN=test", sam="test", object_class="user",
                   attributes={"memberOf": ["CN=Admins", "CN=Users"], "uac": 512})
    assert len(obj.attributes["memberOf"]) == 2


def test_adobj_unicode_sam():
    obj = ADObject(dn="CN=テスト", sam="テスト", object_class="user")
    assert obj.sam == "テスト"


def test_adobj_special_chars():
    obj = ADObject(dn="CN=test\\,user,DC=corp", sam="test\\,user", object_class="user")
    assert "\\" in obj.sam


# ── EngagementContext ───────────────────────────────────────────────────────

def test_ctx_defaults():
    ctx = EngagementContext(dc_ip="10.0.0.1", domain="corp.local", username="admin", password="pass")
    assert ctx.delay == 0.3
    assert ctx.results == []
    assert ctx.credentials == []


def test_ctx_empty_password():
    ctx = EngagementContext(dc_ip="10.0.0.1", domain="corp.local", username="admin", password="")
    assert ctx.password == ""


def test_ctx_hash_auth():
    ctx = EngagementContext(dc_ip="10.0.0.1", domain="corp.local", username="admin", password="",
                           lm_hash="aad3b435b51404ee", nt_hash="8846f7eaee8fb117")
    assert ctx.nt_hash == "8846f7eaee8fb117"


def test_ctx_ipv6():
    ctx = EngagementContext(dc_ip="::1", domain="corp.local", username="", password="")
    assert ctx.dc_ip == "::1"


def test_ctx_long_domain():
    ctx = EngagementContext(dc_ip="10.0.0.1", domain="a" * 500 + ".local", username="", password="")
    assert len(ctx.domain) > 500
