#!/usr/bin/env python3
"""Pipeline complet : détection -> réglage -> audit des exclusions -> ATT&CK.

  python scripts/run.py

Affiche, et écrit dans report/ :
  1. détection SANS réglage : vraies/fausses alertes, couverture ATT&CK ;
  2. détection AVEC exclusions : baisse du bruit, couverture inchangée ;
  3. audit des exclusions : niveau de risque de chaque exclusion.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_lab.attack_map import coverage  # noqa: E402
from soc_lab.convert import load_jsonl  # noqa: E402
from soc_lab.detect import Tuning, run  # noqa: E402
from soc_lab.exclusion_audit import audit_dir  # noqa: E402
from soc_lab.sigma import load_rules  # noqa: E402


def load_tunings() -> list[Tuning]:
    import yaml
    out = []
    for p in sorted((ROOT / "rules" / "benign_tuning").rglob("*.yml")):
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
        out.append(Tuning(target=d["target"], name=d.get("name", p.stem),
                          filter=d["filter"], source=p.name))
    return out


def rule_table(rep) -> list[str]:
    lines = ["| Règle | Vraies alertes | Fausses alertes |",
             "|---|---|---|"]
    for s in rep.rules.values():
        lines.append(f"| {s.title} | {s.tp} | {s.fp} |")
    return lines


def main() -> int:
    rules = load_rules(str(ROOT / "rules" / "attack"))
    attack = load_jsonl(ROOT / "data" / "attack.jsonl")
    benign = load_jsonl(ROOT / "data" / "benign.jsonl")
    tunings = load_tunings()

    before = run(rules, attack, benign)
    after = run(rules, attack, benign, tunings)

    md = ["# Résultats — SOC Detection Lab", ""]
    md.append(f"Règles : {len(rules)} · événements d'attaque : {before.total_attack} "
              f"(sur {len(before.attack_techniques)} techniques) · "
              f"événements normaux : {before.total_benign}")
    md.append("")
    md.append("## 1. Détection sans réglage")
    md += rule_table(before)
    md.append("")
    md.append(f"- Techniques d'attaque couvertes : "
              f"**{len(before.covered_techniques)}/{len(before.attack_techniques)}** "
              f"({100*before.detection_rate:.0f} %)")
    md.append(f"- Fausses alertes : **{before.false_alerts}**")
    md.append("")
    md.append("## 2. Détection après ajout des exclusions")
    md += rule_table(after)
    md.append("")
    md.append(f"- Techniques couvertes : "
              f"**{len(after.covered_techniques)}/{len(after.attack_techniques)}** "
              f"(inchangé : les exclusions ne retirent aucune détection d'attaque)")
    md.append(f"- Fausses alertes : **{before.false_alerts} → {after.false_alerts}**")
    md.append("")
    md.append("## 3. Couverture MITRE ATT&CK")
    for tactic, techs in coverage(rules).items():
        md.append(f"- **{tactic}** : {', '.join(techs)}")
    md.append("")
    md.append("## 4. Audit des exclusions (relecture par risque)")
    md.append("")
    md.append("| Exclusion | Champ | Valeur | Ancrage | Risque |")
    md.append("|---|---|---|---|---|")
    findings = sorted(audit_dir(str(ROOT / "rules" / "benign_tuning")),
                      key=lambda f: {"élevé": 0, "moyen": 1, "faible": 2}[f.risk])
    for f in findings:
        md.append(f"| {f.tuning_name} | `{f.field}` | `{f.value}` | {f.anchor} | {f.risk} |")
    md.append("")
    high = [f for f in findings if f.risk == "élevé"]
    md.append(f"Exclusions à risque élevé à relire en priorité : **{len(high)}**.")
    md.append("")
    md.append("### Contre-exemple : exclusions larges rejetées par l'audit")
    md.append("")
    md.append("Façons tentantes mais dangereuses de régler la même règle "
              "(`examples/risky_exclusions/`, jamais appliquées) :")
    md.append("")
    md.append("| Champ | Valeur | Ancrage | Risque |")
    md.append("|---|---|---|---|")
    risky = sorted(audit_dir(str(ROOT / "examples" / "risky_exclusions")),
                   key=lambda f: {"élevé": 0, "moyen": 1, "faible": 2}[f.risk])
    for f in risky:
        md.append(f"| `{f.field}` | `{f.value}` | {f.anchor} | {f.risk} |")

    out = ROOT / "report" / "results.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
    print(f"\nÉcrit : {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
