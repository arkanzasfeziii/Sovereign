"""Boundary tests for sovereign.utils.ldap_helpers and sovereign.modules.enum._uac_flags."""

from sovereign.utils.ldap_helpers import domain_to_dn
from sovereign.modules.enum import _uac_flags
from sovereign.data import (
    UAC_DONT_REQ_PREAUTH, UAC_TRUSTED_FOR_DELEGATION,
    UAC_PASSWORD_NEVER_EXPIRES, UAC_NOT_DELEGATED,
)


# ── domain_to_dn ───────────────────────────────────────────────────────────

def test_dn_simple():
    assert domain_to_dn("corp.local") == "DC=corp,DC=local"


def test_dn_three_levels():
    assert domain_to_dn("sub.corp.local") == "DC=sub,DC=corp,DC=local"


def test_dn_single():
    assert domain_to_dn("local") == "DC=local"


def test_dn_empty():
    assert domain_to_dn("") == "DC="


def test_dn_long_domain():
    d = ".".join(["level"] * 20)
    result = domain_to_dn(d)
    assert result.count("DC=") == 20


# ── _uac_flags ──────────────────────────────────────────────────────────────

def test_uac_zero():
    assert _uac_flags(0) == []


def test_uac_preauth():
    flags = _uac_flags(UAC_DONT_REQ_PREAUTH)
    assert "NO_PREAUTH" in flags


def test_uac_delegation():
    flags = _uac_flags(UAC_TRUSTED_FOR_DELEGATION)
    assert "UNCONSTRAINED_DELEG" in flags


def test_uac_combined():
    uac = UAC_DONT_REQ_PREAUTH | UAC_PASSWORD_NEVER_EXPIRES
    flags = _uac_flags(uac)
    assert "NO_PREAUTH" in flags
    assert "PWD_NEVER_EXPIRES" in flags


def test_uac_all_flags():
    uac = UAC_DONT_REQ_PREAUTH | UAC_TRUSTED_FOR_DELEGATION | UAC_PASSWORD_NEVER_EXPIRES | UAC_NOT_DELEGATED
    flags = _uac_flags(uac)
    assert len(flags) == 4


def test_uac_unknown_bit():
    flags = _uac_flags(0x00000001)
    assert flags == []


def test_uac_max_int():
    flags = _uac_flags(0xFFFFFFFF)
    assert len(flags) >= 4


def test_uac_negative():
    flags = _uac_flags(-1)
    assert isinstance(flags, list)
