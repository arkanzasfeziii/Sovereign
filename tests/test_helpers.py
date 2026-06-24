"""Tests for LDAP helpers."""

from sovereign.utils.ldap_helpers import domain_to_dn


def test_domain_to_dn_simple():
    assert domain_to_dn("corp.local") == "DC=corp,DC=local"


def test_domain_to_dn_three_parts():
    assert domain_to_dn("sub.corp.local") == "DC=sub,DC=corp,DC=local"


def test_domain_to_dn_single():
    assert domain_to_dn("local") == "DC=local"
