"""Moteur de détection Sigma minimal mais fidèle.

Sigma (https://sigmahq.io) est le format de règles de détection partagé entre
SOC. Une règle décrit des `detection:` (des sélections nommées) et une
`condition:` qui les combine. Ce moteur lit une règle YAML et dit si un
événement la déclenche.

Sous-ensemble implémenté (celui qu'utilisent les règles process_creation) :
- sélection = mapping champ -> valeur(s) ; une liste de valeurs = OU, plusieurs
  champs dans un même bloc = ET ;
- une sélection qui est une LISTE de mappings = OU entre les mappings ;
- modificateurs de champ : |contains, |startswith, |endswith, |re, |all ;
- condition : and / or / not, parenthèses, « all of sel* », « 1 of sel* »,
  « all of them », « 1 of them ».

Comparaisons insensibles à la casse (comme Sigma pour Windows). Ce module se
contente d'ÉVALUER des règles ; il ne génère jamais d'attaque.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml


# ------------------------- comparaison d'un champ ------------------------- #
def _match_value(event_val, pattern, modifier: str) -> bool:
    if event_val is None:
        return False
    ev = str(event_val).lower()
    pat = str(pattern).lower()
    if modifier == "contains":
        return pat in ev
    if modifier == "startswith":
        return ev.startswith(pat)
    if modifier == "endswith":
        return ev.endswith(pat)
    if modifier == "re":
        return re.search(str(pattern), str(event_val), re.IGNORECASE) is not None
    # égalité, avec '*' Sigma traité comme joker simple
    if "*" in pat:
        rx = "^" + re.escape(pat).replace(r"\*", ".*") + "$"
        return re.match(rx, ev) is not None
    return ev == pat


def _match_field(event: dict, field_spec: str, values) -> bool:
    """`field_spec` peut porter des modificateurs : 'Image|endswith'."""
    parts = field_spec.split("|")
    name = parts[0]
    mods = parts[1:]
    all_required = "all" in mods           # |all : toutes les valeurs doivent matcher
    core = next((m for m in mods if m in ("contains", "startswith",
                                          "endswith", "re")), "eq")
    ev_val = event.get(name)
    vals = values if isinstance(values, list) else [values]
    results = [_match_value(ev_val, v, core) for v in vals]
    return all(results) if all_required else any(results)


def _match_selection(event: dict, sel) -> bool:
    # Liste de mappings -> OU ; mapping -> ET sur les champs.
    if isinstance(sel, list):
        return any(_match_selection(event, s) for s in sel)
    if isinstance(sel, dict):
        return all(_match_field(event, f, v) for f, v in sel.items())
    return False


# ----------------------------- la condition ----------------------------- #
@dataclass
class Rule:
    id: str
    title: str
    level: str
    detection: dict
    condition: str
    tags: list[str] = field(default_factory=list)
    logsource: dict = field(default_factory=dict)
    path: str = ""

    def selection_names(self) -> list[str]:
        return [k for k in self.detection if k != "condition"]


def _expand_quantifier(cond: str, names: list[str]) -> str:
    """Remplace « all of sel* » / « 1 of them » par une expression and/or."""
    def names_for(patt: str) -> list[str]:
        if patt == "them":
            return names
        if patt.endswith("*"):
            pre = patt[:-1]
            return [n for n in names if n.startswith(pre)]
        return [n for n in names if n == patt]

    def repl(m):
        qty, patt = m.group(1), m.group(2)
        sel = names_for(patt)
        if not sel:
            return "False"
        joiner = " or " if qty == "1" else " and "
        return "(" + joiner.join(sel) + ")"

    return re.sub(r"\b(all|1)\s+of\s+([A-Za-z0-9_*]+|them)", repl, cond)


def evaluate(rule: Rule, event: dict) -> bool:
    names = rule.selection_names()
    results = {n: _match_selection(event, rule.detection[n]) for n in names}

    expr = _expand_quantifier(rule.condition, names)
    # Traduction vers une expression booléenne Python sûre.
    expr = re.sub(r"\bnot\b", " not ", expr)
    expr = re.sub(r"\band\b", " and ", expr)
    expr = re.sub(r"\bor\b", " or ", expr)
    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|True|False|[A-Za-z0-9_]+",
                        expr)
    py = []
    for t in tokens:
        if t in ("and", "or", "not", "(", ")", "True", "False"):
            py.append(t)
        elif t in results:
            py.append(str(results[t]))
        else:
            raise ValueError(f"Jeton de condition inconnu : {t!r} "
                             f"(règle {rule.id})")
    safe = " ".join(py)
    if not re.fullmatch(r"[\sTrueFalsandnot()]*", safe):
        raise ValueError(f"Condition non sûre après traduction : {safe!r}")
    return bool(eval(safe, {"__builtins__": {}}, {}))  # noqa: S307 — espace clos


def load_rule(path: str) -> Rule:
    import pathlib
    data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
    det = data["detection"]
    return Rule(
        id=str(data.get("id", pathlib.Path(path).stem)),
        title=data.get("title", ""),
        level=data.get("level", "medium"),
        detection={k: v for k, v in det.items() if k != "condition"},
        condition=det["condition"],
        tags=data.get("tags", []) or [],
        logsource=data.get("logsource", {}) or {},
        path=str(path),
    )


def load_rules(directory: str) -> list[Rule]:
    import pathlib
    out = []
    for p in sorted(pathlib.Path(directory).rglob("*.yml")):
        out.append(load_rule(str(p)))
    return out
