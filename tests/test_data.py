"""Tests for static data."""

from sovereign.data import (
    ACL_RIGHTS, HC_ASREPROAST, HC_KERBEROAST,
    LDAP_ALL_USERS, PRIV_GROUPS, UAC_DONT_REQ_PREAUTH,
)


def test_uac_preauth_flag():
    assert UAC_DONT_REQ_PREAUTH == 0x00400000


def test_hashcat_modes():
    assert HC_KERBEROAST == 13100
    assert HC_ASREPROAST == 18200


def test_priv_groups_not_empty():
    assert len(PRIV_GROUPS) >= 8
    assert "Domain Admins" in PRIV_GROUPS


def test_acl_rights_has_generic_all():
    assert "GenericAll" in ACL_RIGHTS.values()


def test_ldap_filter_valid():
    assert "objectClass=user" in LDAP_ALL_USERS
