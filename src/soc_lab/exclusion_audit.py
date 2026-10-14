"""Audit défensif des exclusions d'une règle de détection.

Pourquoi : une exclusion ajoutée pour réduire les fausses alertes peut, si elle
est trop large, créer un angle mort durable. L'étude « The Exclusion Ratchet »
(Dhananjeyan & Kumaran, arXiv:2608.31062, 2026) montre sur 9 ans du corpus
SigmaHQ que les exclusions s'accumulent (ajoutées 5,4x plus souvent que
retirées), persistent (86,7 % encore actives après 3 ans), et que 64,1 % des
exclusions sur des chemins sont « librement atteignables » (un simple nom de
fichier ou un dossier où tout utilisateur peut écrire).

Ce module reprend cette grille d'analyse comme un LINTER : pour chaque valeur
d'exclusion, il estime à quel point elle est facile à satisfaire et la classe
en niveau de risque, afin qu'un analyste relise en priorité les plus larges.
Il ne lit que des règles ; il ne fabrique aucune attaque.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Dossiers où un utilisateur standard peut écrire : une exclusion qui y pointe
# est facile à satisfaire.
_USER_WRITABLE = re.compile(
    r"\\users\\|\\appdata\\|\\temp\\|\\tmp\\|\\downloads\\|\\public\\|"
    r"%temp%|%appdata%|%localappdata%|%userprofile%", re.I)
# Dossiers protégés : y écrire demande des privilèges.
_PROTECTED = re.compile(r"^\*?([a-z]:)?\\?(windows|program files)", re.I)
_ABS = re.compile(r"^\*?[a-z]:\\", re.I)


def anchor(value: str) -> str:
    """Catégorie d'ancrage d'une valeur d'exclusion (d'après l'étude citée)."""
    v = str(value).strip().lower()
    if not v:
        return "vide"
    if _USER_WRITABLE.search(v):
        return "dossier accessible en écriture par l'utilisateur"
    if _PROTECTED.match(v):
        return "dossier protégé"
    if _ABS.match(v):
        return "autre chemin absolu"
    # Pas de séparateur de chemin (hors jokers) : simple nom ou suffixe.
    if v.startswith("*") or "\\" not in v.rstrip("*"):
        return "nom de fichier ou suffixe seul"
    return "autre chemin relatif"


# Un ancrage « librement atteignable » : l'attaquant choisit juste un nom/chemin.
_FREELY_ENTERABLE = {
    "nom de fichier ou suffixe seul",
    "dossier accessible en écriture par l'utilisateur",
}


@dataclass
class Finding:
    rule_target: str
    tuning_name: str
    field: str
    value: str
    anchor: str
    risk: str          # "élevé" | "moyen" | "faible"
    reason: str


def _risk(field: str, value: str, anch: str) -> tuple[str, str]:
    base = field.split("|")[0].lower()
    is_path_field = any(k in base for k in ("image", "path", "parent",
                                            "filename", "application"))
    uses_contains = "|contains" in field or "|startswith" in field
    if not is_path_field:
        return ("moyen", "exclusion sur un champ non-chemin : à vérifier "
                "qu'elle ne retire pas trop d'événements")
    if anch in _FREELY_ENTERABLE:
        return ("élevé", "chemin qu'un utilisateur sans privilège peut créer : "
                "un attaquant peut nommer son fichier pour tomber dedans")
    if uses_contains and anch == "dossier protégé":
        return ("moyen", "sous-chaîne large même si le dossier est protégé : "
                "préférer une fin de chemin complète")
    return ("faible", "chemin dans un dossier protégé, désignant un binaire "
            "précis : difficile à usurper")


def _values(v) -> list[str]:
    return v if isinstance(v, list) else [v]


def audit_filter(target: str, name: str, filt: dict) -> list[Finding]:
    out: list[Finding] = []
    for fld, val in filt.items():
        for item in _values(val):
            a = anchor(item)
            risk, reason = _risk(fld, item, a)
            out.append(Finding(target, name, fld, str(item), a, risk, reason))
    return out


def load_tunings(directory: str):
    """Charge les fichiers d'exclusion (target/name/filter) d'un dossier."""
    import pathlib

    import yaml
    items = []
    for p in sorted(pathlib.Path(directory).rglob("*.yml")):
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
        if isinstance(d, dict) and "filter" in d and "target" in d:
            items.append((d["target"], d.get("name", p.stem), d["filter"]))
    return items


def audit_dir(directory: str) -> list[Finding]:
    out: list[Finding] = []
    for target, name, filt in load_tunings(directory):
        out.extend(audit_filter(target, name, filt))
    return out
