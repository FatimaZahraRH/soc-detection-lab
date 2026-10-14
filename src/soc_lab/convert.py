"""Conversion de journaux Sysmon (.evtx) en événements normalisés (JSONL).

On ne garde que les événements de CRÉATION DE PROCESSUS (Sysmon EventID 1),
aplatis au schéma qu'attendent les règles Sigma `process_creation`
(Image, CommandLine, ParentImage, ...).

Les journaux d'attaque viennent de EVTX-ATTACK-SAMPLES (sbousseaden), qui
rejoue de vraies techniques documentées MITRE ATT&CK. Le nom du fichier porte
souvent l'identifiant de technique (ex. `..._t1098.evtx`) : on l'extrait pour
étiqueter chaque événement.

Important : ce module LIT des journaux déjà enregistrés. Il ne lance aucune
attaque et n'en fabrique aucune.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import evtx

# Champs Sysmon EID 1 utiles aux règles process_creation.
FIELDS = ["Image", "CommandLine", "ParentImage", "ParentCommandLine",
          "OriginalFileName", "CurrentDirectory", "User", "IntegrityLevel",
          "Hashes", "Company", "Description", "Product", "ParentUser"]

_TECH = re.compile(r"(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def technique_from_name(path: Path) -> str | None:
    m = _TECH.search(path.name)
    return m.group(1).upper() if m else None


def _eid(system: dict):
    eid = system.get("EventID")
    return str(eid.get("#text") if isinstance(eid, dict) else eid)


def normalize_file(path: str | Path, label: str, source: str,
                   technique: str | None = None) -> list[dict]:
    """Renvoie la liste des événements process_creation normalisés d'un .evtx."""
    path = Path(path)
    parser = evtx.PyEvtxParser(str(path))
    out: list[dict] = []
    for rec in parser.records_json():
        d = json.loads(rec["data"])["Event"]
        system = d.get("System", {})
        channel = str(system.get("Channel", ""))
        if "Sysmon" not in channel or _eid(system) != "1":
            continue
        ed = d.get("EventData", {}) or {}
        ev = {f: ed[f] for f in FIELDS if ed.get(f) not in (None, "", "-", "?")}
        if "Image" not in ev:
            continue
        ev["_label"] = label                        # "attack" | "benign"
        ev["_source"] = source
        ev["_technique"] = technique or technique_from_name(path)
        out.append(ev)
    return out


def write_jsonl(events: list[dict], out_path: str | Path) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")


def load_jsonl(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
