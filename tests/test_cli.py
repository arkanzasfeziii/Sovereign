"""Tests for CLI."""

from sovereign.cli import MODULE_REGISTRY, build_parser


def test_all_modules_registered():
    expected = {"enum", "kerberoast", "asreproast", "dcsync", "acl-abuse", "lateral"}
    assert set(MODULE_REGISTRY.keys()) == expected


def test_required_args():
    p = build_parser()
    args = p.parse_args(["--dc-ip", "10.0.0.1", "--domain", "corp.local"])
    assert args.dc_ip == "10.0.0.1"
    assert args.domain == "corp.local"


def test_hashes_flag():
    p = build_parser()
    args = p.parse_args(["--dc-ip", "10.0.0.1", "--domain", "corp.local",
                         "--hashes", "aad3b:1234abcd"])
    assert args.hashes == "aad3b:1234abcd"


def test_default_command():
    p = build_parser()
    args = p.parse_args(["--dc-ip", "10.0.0.1", "--domain", "corp.local"])
    assert args.command == "whoami /all"
