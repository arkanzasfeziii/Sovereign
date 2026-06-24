"""Data models used across all Sovereign modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AttackResult:
    module: str
    action: str
    status: str
    target: str = ""
    data: Any = None
    severity: str = "INFO"
    notes: str = ""


@dataclass
class Credential:
    type: str
    domain: str
    username: str
    secret: str
    source: str
    notes: str = ""


@dataclass
class ADObject:
    dn: str
    sam: str
    object_class: str
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EngagementContext:
    dc_ip: str
    domain: str
    username: str
    password: str
    lm_hash: str = ""
    nt_hash: str = ""
    base_dn: str = ""
    ldap_conn: Any = None
    results: List[AttackResult] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    loot: Dict[str, Any] = field(default_factory=dict)
    delay: float = 0.3
