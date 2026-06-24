"""Constants and configuration for Sovereign."""

from __future__ import annotations

from sovereign import __version__, __author__

TOOL_NAME = "Sovereign Framework"
VERSION = __version__
AUTHOR = __author__
COMMAND = "sovereign"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║         ⚠   SOVEREIGN — AUTHORIZED RED TEAM USE ONLY   ⚠                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This framework executes REAL Active Directory attacks: Kerberoasting,       ║
║  AS-REP roasting, DCSync (domain hash dump), ACL exploitation, Pass-the-    ║
║  Hash, and remote command execution.                                         ║
║                                                                              ║
║  Requirements before use:                                                   ║
║    ✓ Written authorization from the target organization                     ║
║    ✓ Defined scope (domain / IP range)                                      ║
║    ✓ Rules of engagement signed off                                         ║
║                                                                              ║
║  The author (arkanzasfeziii) accepts NO LIABILITY for misuse.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
