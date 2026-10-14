#!/usr/bin/env python3
"""Construit le jeu de données du labo à partir des journaux Sysmon réels.

- Journaux d'ATTAQUE : un sous-ensemble varié de EVTX-ATTACK-SAMPLES, couvrant
  plusieurs tactiques MITRE ATT&CK. À placer dans --samples (le dépôt cloné).
- Journaux NORMAUX : générés ici (processus Windows légitimes courants), dont
  certains ressemblent superficiellement à une attaque, pour que la mesure des
  fausses alertes ait du sens.

Sortie : data/attack.jsonl et data/benign.jsonl

  python scripts/build_dataset.py --samples /chemin/EVTX-ATTACK-SAMPLES
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_lab.convert import normalize_file, write_jsonl  # noqa: E402

# Sélection variée (chemin relatif, technique ATT&CK principale), riches en EID 1.
# La technique est indiquée ici car ces noms de fichiers ne la portent pas.
ATTACK_FILES = [
    ("Privilege Escalation/privesc_unquoted_svc_sysmon_1_11.evtx", "T1574.009"),
    ("Privilege Escalation/Sysmon_UACME_22.evtx", "T1548.002"),
    ("Privilege Escalation/sysmon_11_1_15_WScriptBypassUAC.evtx", "T1548.002"),
    ("Persistence/persistence_sysmon_11_13_1_shime_appfix.evtx", "T1546.011"),
    ("Persistence/sysmon_13_1_persistence_via_winlogon_shell.evtx", "T1547.004"),
    ("Execution/sysmon_exec_from_vss_persistence.evtx", "T1059"),
    ("Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx", "T1552.001"),
    ("Defense Evasion/Sysmon 7  Update Session Orchestrator Dll Hijack.evtx", "T1574.001"),
    ("Command and Control/DE_sysmon-3-rdp-tun.evtx", "T1572"),
    ("Lateral Movement/LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx", "T1047"),
]

# Événements NORMAUX : activité courante et légitime d'un poste Windows.
# Quelques-uns (marqués # piège) imitent une forme d'attaque sans en être une :
# ils servent à vérifier qu'une règle ne les signale pas à tort.
BENIGN = [
    {"Image": r"C:\Windows\System32\svchost.exe",
     "CommandLine": r"C:\Windows\system32\svchost.exe -k netsvcs -p",
     "ParentImage": r"C:\Windows\System32\services.exe",
     "User": "NT AUTHORITY\\SYSTEM", "IntegrityLevel": "System"},
    {"Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
     "CommandLine": r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
     "ParentImage": r"C:\Windows\explorer.exe",
     "User": "CORP\\alice", "IntegrityLevel": "Medium"},
    {"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "CommandLine": r'powershell.exe -ExecutionPolicy RemoteSigned -File C:\Scripts\Backup-Daily.ps1',
     "ParentImage": r"C:\Windows\System32\taskeng.exe",   # piège : PowerShell planifié légitime
     "User": "CORP\\svc_backup", "IntegrityLevel": "High"},
    {"Image": r"C:\Windows\System32\cmd.exe",
     "CommandLine": r'cmd.exe /c "C:\Program Files\Acme\build\compile.bat"',
     "ParentImage": r"C:\Program Files\Acme\ide\acme-ide.exe",  # piège : cmd lancé par un IDE
     "User": "CORP\\bob", "IntegrityLevel": "Medium"},
    {"Image": r"C:\Windows\System32\reg.exe",
     "CommandLine": r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"',
     "ParentImage": r"C:\Program Files\Acme\inventory\agent.exe",  # piège : reg query par un agent d'inventaire
     "User": "NT AUTHORITY\\SYSTEM", "IntegrityLevel": "System"},
    {"Image": r"C:\Windows\System32\rundll32.exe",
     "CommandLine": r'rundll32.exe shell32.dll,Control_RunDLL desk.cpl',
     "ParentImage": r"C:\Windows\explorer.exe",
     "User": "CORP\\alice", "IntegrityLevel": "Medium"},
    {"Image": r"C:\Windows\System32\sc.exe",
     "CommandLine": r'sc.exe query type= service state= all',
     "ParentImage": r"C:\Program Files\Acme\monitoring\mon.exe",
     "User": "NT AUTHORITY\\SYSTEM", "IntegrityLevel": "System"},
    {"Image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
     "CommandLine": r'"WINWORD.EXE" /n "C:\Users\alice\Documents\rapport.docx"',
     "ParentImage": r"C:\Windows\explorer.exe",
     "User": "CORP\\alice", "IntegrityLevel": "Medium"},
    {"Image": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
     "CommandLine": r"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding",
     "ParentImage": r"C:\Windows\System32\svchost.exe",
     "User": "NT AUTHORITY\\NETWORK SERVICE", "IntegrityLevel": "System"},
    {"Image": r"C:\Windows\System32\net.exe",
     "CommandLine": r"net use Z: \\fileserver\partage /persistent:yes",
     "ParentImage": r"C:\Windows\explorer.exe",
     "User": "CORP\\bob", "IntegrityLevel": "Medium"},
    # Applications légitimes installées dans AppData\Roaming : ce sont des
    # FAUX POSITIFS pour une règle « .exe dans AppData » non réglée. C'est sur
    # elles qu'on démontre l'ajout d'exclusions.
    {"Image": r"C:\Users\alice\AppData\Roaming\Slack\slack.exe",
     "CommandLine": r'"C:\Users\alice\AppData\Roaming\Slack\slack.exe"',
     "ParentImage": r"C:\Windows\explorer.exe",
     "User": "CORP\\alice", "IntegrityLevel": "Medium"},
    {"Image": r"C:\Users\alice\AppData\Roaming\Zoom\bin\Zoom.exe",
     "CommandLine": r'"C:\Users\alice\AppData\Roaming\Zoom\bin\Zoom.exe"',
     "ParentImage": r"C:\Windows\explorer.exe",
     "User": "CORP\\alice", "IntegrityLevel": "Medium"},
    {"Image": r"C:\Users\bob\AppData\Roaming\Microsoft\Teams\Update.exe",
     "CommandLine": r'"Update.exe" --processStart "Teams.exe"',
     "ParentImage": r"C:\Windows\explorer.exe",
     "User": "CORP\\bob", "IntegrityLevel": "Medium"},
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True,
                    help="dossier EVTX-ATTACK-SAMPLES (dépôt cloné)")
    ap.add_argument("--copies", type=int, default=50,
                    help="nombre de copies du jeu normal (volume réaliste)")
    args = ap.parse_args()

    base = Path(args.samples)
    attack: list[dict] = []
    missing = []
    for rel, tech in ATTACK_FILES:
        f = base / rel
        if not f.exists():
            missing.append(rel); continue
        evs = normalize_file(f, label="attack", source=rel, technique=tech)
        attack.extend(evs)
        print(f"  {len(evs):4d} ev  [{tech}]  {rel}")
    if missing:
        print("Fichiers introuvables (vérifie --samples) :")
        for m in missing:
            print("   -", m)

    benign: list[dict] = []
    for i in range(args.copies):
        for b in BENIGN:
            e = dict(b); e["_label"] = "benign"; e["_source"] = "generated"
            e["_technique"] = None
            benign.append(e)

    write_jsonl(attack, ROOT / "data" / "attack.jsonl")
    write_jsonl(benign, ROOT / "data" / "benign.jsonl")
    techs = sorted({e["_technique"] for e in attack if e["_technique"]})
    print(f"\nAttaque : {len(attack)} événements, techniques : {', '.join(techs)}")
    print(f"Normal  : {len(benign)} événements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
