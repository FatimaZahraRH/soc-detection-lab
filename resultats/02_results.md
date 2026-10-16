# Résultats — SOC Detection Lab

Règles : 5 · événements d'attaque : 402 (sur 9 techniques) · événements normaux : 650

## 1. Détection sans réglage
| Règle | Vraies alertes | Fausses alertes |
|---|---|---|
| Découverte de secrets IIS via appcmd.exe | 18 | 0 |
| Exécutable lancé depuis AppData\Roaming | 2 | 150 |
| rundll32 appelant une DLL non standard (détournement / porte dérobée) | 19 | 0 |
| Exécution via WMIC depuis une copie shadow (VSS) | 1 | 0 |
| Contournement d'UAC via WScript et flux de données alternatif (ADS) | 2 | 0 |

- Techniques d'attaque couvertes : **5/9** (56 %)
- Fausses alertes : **150**

## 2. Détection après ajout des exclusions
| Règle | Vraies alertes | Fausses alertes |
|---|---|---|
| Découverte de secrets IIS via appcmd.exe | 18 | 0 |
| Exécutable lancé depuis AppData\Roaming | 2 | 0 |
| rundll32 appelant une DLL non standard (détournement / porte dérobée) | 19 | 0 |
| Exécution via WMIC depuis une copie shadow (VSS) | 1 | 0 |
| Contournement d'UAC via WScript et flux de données alternatif (ADS) | 2 | 0 |

- Techniques couvertes : **5/9** (inchangé : les exclusions ne retirent aucune détection d'attaque)
- Fausses alertes : **150 → 0**

## 3. Couverture MITRE ATT&CK
- **credential_access** : T1552.001
- **defense_evasion** : T1548.002, T1574.001
- **execution** : T1047
- **persistence** : T1547.004
- **privilege_escalation** : T1548.002

## 4. Audit des exclusions (relecture par risque)

| Exclusion | Champ | Valeur | Ancrage | Risque |
|---|---|---|---|---|
| known_good_appdata_apps | `Image|endswith` | `\Slack\slack.exe` | autre chemin relatif | faible |
| known_good_appdata_apps | `Image|endswith` | `\Zoom\bin\Zoom.exe` | autre chemin relatif | faible |
| known_good_appdata_apps | `Image|endswith` | `\Microsoft\Teams\Update.exe` | autre chemin relatif | faible |

Exclusions à risque élevé à relire en priorité : **0**.

### Contre-exemple : exclusions larges rejetées par l'audit

Façons tentantes mais dangereuses de régler la même règle (`examples/risky_exclusions/`, jamais appliquées) :

| Champ | Valeur | Ancrage | Risque |
|---|---|---|---|
| `Image|endswith` | `update.exe` | nom de fichier ou suffixe seul | élevé |
| `Image|endswith` | `setup.exe` | nom de fichier ou suffixe seul | élevé |
| `Image|contains` | `\AppData\Roaming\` | dossier accessible en écriture par l'utilisateur | élevé |
