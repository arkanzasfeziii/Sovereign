"""Custom exception hierarchy for Sovereign."""

from __future__ import annotations


class SovereignError(Exception):
    """Base exception."""


class ModuleError(SovereignError):
    """Module runtime error."""


class LDAPConnectionError(SovereignError):
    """LDAP connection failed."""


class DependencyError(SovereignError):
    def __init__(self, package: str) -> None:
        super().__init__(f"Missing: {package}. Install with: pip install {package}")
        self.package = package
