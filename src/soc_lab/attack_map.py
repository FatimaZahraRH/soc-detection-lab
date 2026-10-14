"""Cartographie des règles sur MITRE ATT&CK, à partir de leurs tags Sigma."""
from __future__ import annotations

import re

from .sigma import Rule

_TECH = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.I)
_TACTIC = re.compile(r"attack\.([a-z_]+)$", re.I)
_TACTICS = {"initial_access", "execution", "persistence", "privilege_escalation",
            "defense_evasion", "credential_access", "discovery",
            "lateral_movement", "collection", "command_and_control",
            "exfiltration", "impact", "reconnaissance", "resource_development"}


def techniques(rule: Rule) -> list[str]:
    return sorted({m.group(1).upper() for t in rule.tags
                   if (m := _TECH.match(t))})


def tactics(rule: Rule) -> list[str]:
    out = []
    for t in rule.tags:
        m = _TACTIC.match(t)
        if m and m.group(1).lower() in _TACTICS:
            out.append(m.group(1).lower())
    return sorted(set(out))


def coverage(rules: list[Rule]) -> dict[str, list[str]]:
    """tactique -> techniques couvertes par au moins une règle."""
    cov: dict[str, set] = {}
    for r in rules:
        for ta in tactics(r):
            cov.setdefault(ta, set()).update(techniques(r))
    return {k: sorted(v) for k, v in sorted(cov.items())}
