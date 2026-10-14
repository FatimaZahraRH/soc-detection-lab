"""Exécution des règles sur les événements, et mesure de la qualité.

Vocabulaire SOC :
- vraie alerte (TP)  : une règle se déclenche sur un événement d'attaque ;
- fausse alerte (FP) : une règle se déclenche sur un événement normal ;
- technique couverte : au moins un événement de cette technique déclenche une règle.

Le « réglage » (tuning) applique à une règle une exclusion : la condition
devient « (condition d'origine) and not filtre ». On mesure le bruit avant/après.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .sigma import Rule, evaluate


@dataclass
class Tuning:
    """Exclusion appliquée à une règle (son id) : un bloc `filter` Sigma."""
    target: str
    name: str
    filter: dict
    source: str = ""


def apply_tuning(rule: Rule, tunings: list[Tuning]) -> Rule:
    relevant = [t for t in tunings if t.target == rule.id]
    if not relevant:
        return rule
    det = dict(rule.detection)
    extra = []
    for i, t in enumerate(relevant):
        key = f"_tuning_{i}"
        det[key] = t.filter
        extra.append(key)
    cond = f"({rule.condition}) and not (" + " or ".join(extra) + ")"
    return Rule(id=rule.id, title=rule.title, level=rule.level, detection=det,
                condition=cond, tags=rule.tags, logsource=rule.logsource,
                path=rule.path)


@dataclass
class RuleStats:
    rule_id: str
    title: str
    tp: int = 0
    fp: int = 0
    techniques: set = field(default_factory=set)   # techniques déclenchées (TP)


@dataclass
class Report:
    rules: dict               # rule_id -> RuleStats
    total_attack: int
    total_benign: int
    attack_techniques: set
    covered_techniques: set
    flagged_attack_events: int
    false_alerts: int

    @property
    def detection_rate(self) -> float:
        n = len(self.attack_techniques)
        return len(self.covered_techniques) / n if n else 0.0


def run(rules: list[Rule], attack: list[dict], benign: list[dict],
        tunings: list[Tuning] | None = None) -> Report:
    tunings = tunings or []
    tuned = [apply_tuning(r, tunings) for r in rules]
    stats = {r.id: RuleStats(r.id, r.title) for r in tuned}

    flagged_attack = set()
    false_alerts = 0
    for r in tuned:
        for idx, ev in enumerate(attack):
            if evaluate(r, ev):
                stats[r.id].tp += 1
                if ev.get("_technique"):
                    stats[r.id].techniques.add(ev["_technique"])
                flagged_attack.add(idx)
        for ev in benign:
            if evaluate(r, ev):
                stats[r.id].fp += 1
                false_alerts += 1

    attack_techs = {e["_technique"] for e in attack if e.get("_technique")}
    covered = set().union(*(s.techniques for s in stats.values())) if stats else set()
    return Report(
        rules=stats,
        total_attack=len(attack), total_benign=len(benign),
        attack_techniques=attack_techs, covered_techniques=covered,
        flagged_attack_events=len(flagged_attack), false_alerts=false_alerts,
    )
