"""Tests : moteur Sigma, réglage, audit d'exclusions, cartographie ATT&CK."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_lab.attack_map import coverage, tactics, techniques  # noqa: E402
from soc_lab.convert import load_jsonl  # noqa: E402
from soc_lab.detect import Tuning, apply_tuning, run  # noqa: E402
from soc_lab.exclusion_audit import anchor, audit_dir  # noqa: E402
from soc_lab.sigma import Rule, evaluate, load_rules  # noqa: E402

RULES = load_rules(str(ROOT / "rules" / "attack"))
BY_ID = {r.id: r for r in RULES}


def _rule(detection, condition):
    return Rule(id="t", title="t", level="low",
                detection=detection, condition=condition)


# ----------------------------- moteur Sigma ----------------------------- #
def test_endswith_and_contains():
    r = _rule({"selection": {"Image|endswith": "\\wmic.exe",
                             "CommandLine|contains": "process call create"}},
              "selection")
    assert evaluate(r, {"Image": "C:\\X\\WMIC.exe",
                        "CommandLine": "wmic process call create ..."})
    assert not evaluate(r, {"Image": "C:\\X\\cmd.exe",
                            "CommandLine": "process call create"})


def test_value_list_is_or():
    r = _rule({"s": {"CommandLine|contains": ["foo", "bar"]}}, "s")
    assert evaluate(r, {"CommandLine": "xx bar yy"})
    assert not evaluate(r, {"CommandLine": "nothing"})


def test_condition_and_not():
    r = _rule({"sel": {"Image|endswith": ".exe"},
               "filt": {"Image|endswith": "\\good.exe"}},
              "sel and not filt")
    assert evaluate(r, {"Image": "C:\\bad.exe"})
    assert not evaluate(r, {"Image": "C:\\good.exe"})


def test_all_of_them_quantifier():
    r = _rule({"sel_a": {"Image|endswith": "a.exe"},
               "sel_b": {"CommandLine|contains": "x"}},
              "all of sel_*")
    assert evaluate(r, {"Image": "a.exe", "CommandLine": "x"})
    assert not evaluate(r, {"Image": "a.exe", "CommandLine": "y"})


def test_condition_rejects_unknown_token():
    import pytest
    r = _rule({"sel": {"Image": "x"}}, "sel and mystery")
    with pytest.raises(ValueError):
        evaluate(r, {"Image": "x"})


# ------------------------- détection sur données ------------------------- #
def test_rules_detect_real_attacks_without_false_positives_core():
    attack = load_jsonl(ROOT / "data" / "attack.jsonl")
    benign = load_jsonl(ROOT / "data" / "benign.jsonl")
    # Hors règle AppData volontairement bruyante, aucune fausse alerte.
    precise = [r for r in RULES if r.id != "lab-exe-appdata"]
    rep = run(precise, attack, benign)
    assert rep.false_alerts == 0
    assert rep.flagged_attack_events > 0


def test_tuning_removes_false_alerts_but_keeps_detection():
    attack = load_jsonl(ROOT / "data" / "attack.jsonl")
    benign = load_jsonl(ROOT / "data" / "benign.jsonl")
    tuning = [Tuning(target="lab-exe-appdata", name="good",
                     filter={"Image|endswith": ["\\Slack\\slack.exe",
                                                 "\\Zoom\\bin\\Zoom.exe",
                                                 "\\Microsoft\\Teams\\Update.exe"]})]
    before = run(RULES, attack, benign)
    after = run(RULES, attack, benign, tuning)
    assert after.false_alerts < before.false_alerts
    # La couverture des techniques d'attaque ne régresse pas.
    assert after.covered_techniques == before.covered_techniques
    assert after.flagged_attack_events == before.flagged_attack_events


# --------------------------- audit d'exclusions --------------------------- #
def test_anchor_classification():
    assert anchor("update.exe") == "nom de fichier ou suffixe seul"
    assert anchor(r"C:\Users\x\AppData\Roaming\a.exe") == \
        "dossier accessible en écriture par l'utilisateur"
    assert anchor(r"C:\Windows\System32\svchost.exe") == "dossier protégé"


def test_audit_flags_broad_exclusions_high_and_specific_low():
    good = audit_dir(str(ROOT / "rules" / "benign_tuning"))
    bad = audit_dir(str(ROOT / "examples" / "risky_exclusions"))
    assert good and all(f.risk == "faible" for f in good)
    assert any(f.risk == "élevé" for f in bad)


# ---------------------------- ATT&CK mapping ---------------------------- #
def test_attack_mapping_from_tags():
    r = BY_ID["lab-wmic-vss"]
    assert "T1047" in techniques(r)
    assert "execution" in tactics(r)
    assert "execution" in coverage(RULES)
