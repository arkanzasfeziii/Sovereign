"""Tests for data models."""

from sovereign.models import ADObject, AttackResult, Credential, EngagementContext


def test_attack_result_defaults():
    r = AttackResult(module="enum", action="users", status="SUCCESS")
    assert r.severity == "INFO"


def test_credential():
    c = Credential(type="ntlm", domain="corp.local", username="admin",
                   secret="aad3b:1234", source="dcsync")
    assert c.domain == "corp.local"


def test_ad_object():
    obj = ADObject(dn="CN=admin,DC=corp,DC=local", sam="admin", object_class="user")
    assert obj.sam == "admin"


def test_engagement_context():
    ctx = EngagementContext(dc_ip="10.0.0.1", domain="corp.local",
                           username="admin", password="pass")
    assert ctx.delay == 0.3
    assert ctx.credentials == []
