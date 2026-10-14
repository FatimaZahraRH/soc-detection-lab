# SOC Detection Lab

**Écrire des règles de détection, les éprouver sur de vraies attaques, réduire
les fausses alertes — et vérifier que réduire le bruit n'ouvre pas d'angle mort.**

Un laboratoire d'analyste SOC (*blue team*), de bout en bout : détection **Sigma**
sur des journaux Windows réels, réglage par exclusions, **audit des exclusions**
inspiré d'un article récent, et cartographie **MITRE ATT&CK**.

> Projet défensif. Il exécute des règles sur des journaux d'attaque **déjà
> enregistrés** (EVTX-ATTACK-SAMPLES) ; il ne lance ni ne fabrique aucune attaque.

---

## L'idée

Un SOC reçoit des milliers d'alertes par jour. Le travail de l'analyste n'est
pas seulement de *détecter*, mais de **détecter sans se noyer sous les fausses
alertes** — tout en gardant les vraies. Ce labo reproduit ce cycle et y ajoute
une question que l'on se pose rarement : **quand on ajoute une exclusion pour
faire taire une fausse alerte, est-ce qu'on n'ouvre pas une porte à
l'attaquant ?**

Cette dernière question vient de l'étude **« The Exclusion Ratchet »**
(Dhananjeyan & Kumaran, arXiv:2608.31062, 2026), qui montre sur 9 ans du corpus
public SigmaHQ que les exclusions **s'accumulent** (ajoutées 5,4× plus souvent
que retirées), **persistent** (86,7 % encore actives après 3 ans), et que
**64,1 %** des exclusions sur des chemins sont « librement atteignables » — un
simple nom de fichier, ou un dossier où n'importe quel utilisateur peut écrire.

## Le pipeline

```
journaux Sysmon réels ─▶ [détection Sigma] ─▶ vraies alertes / fausses alertes
 (attaque + normal)              │
                                 ▼
                          [réglage] ajout d'exclusions ─▶ moins de fausses alertes,
                                 │                          détection d'attaque inchangée
                                 ▼
                          [audit] chaque exclusion classée par risque
                                 │                (inspiré de « The Exclusion Ratchet »)
                                 ▼
                          [ATT&CK] couverture par tactique / technique
```

## Résultats (données du dépôt)

5 règles, **402 événements d'attaque réels** (9 techniques ATT&CK, de
EVTX-ATTACK-SAMPLES) et 650 événements normaux.

| | Fausses alertes | Techniques couvertes |
|---|---|---|
| Sans réglage | **150** | 5/9 |
| Après exclusions | **0** | 5/9 *(inchangé)* |

Le réglage supprime tout le bruit **sans retirer une seule détection
d'attaque**. L'audit confirme que les exclusions utilisées sont précises
(risque faible) et rejette un contre-exemple tentant — exclure par simple nom de
fichier `update.exe` — comme **risque élevé** : un attaquant n'aurait qu'à
nommer ainsi son binaire pour passer sous le radar.

Rapport complet : [`report/results.md`](report/results.md).
Exemple de livrable analyste : [`report/incident_report_example.md`](report/incident_report_example.md).

### Couverture, assumée partielle

5 règles couvrent 5 des 9 techniques du jeu de données. Ce n'est pas un oubli :
l'objectif est de montrer la **démarche** (détecter, régler, auditer), pas de
viser 100 % de couverture. Les techniques non couvertes sont une liste de
travail honnête, pas un résultat caché.

## Lancer le projet

```bash
git clone https://github.com/FatimaZahraRH/soc-detection-lab.git
cd soc-detection-lab
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

python -m pytest -q            # 10 tests
python scripts/run.py          # détection -> réglage -> audit -> ATT&CK

# Reconstruire le jeu de données depuis les journaux bruts (optionnel) :
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
python scripts/build_dataset.py --samples EVTX-ATTACK-SAMPLES
```

Le jeu de données converti (`data/*.jsonl`) est versionné, donc le pipeline et
les tests tournent sans télécharger les `.evtx`.

## Organisation

```
rules/attack/          5 règles de détection Sigma (process_creation)
rules/benign_tuning/   exclusions appliquées (bien formées)
examples/risky_exclusions/  contre-exemple d'exclusion large (audité, jamais appliqué)
src/soc_lab/
  sigma.py             moteur Sigma (sélections, modificateurs, conditions)
  detect.py            exécution, vraies/fausses alertes, application du réglage
  exclusion_audit.py   linter d'exclusions par niveau de risque (article 2026)
  attack_map.py        cartographie MITRE ATT&CK depuis les tags
convert.py             .evtx -> événements normalisés
scripts/build_dataset.py, scripts/run.py
report/                résultats + rapport d'incident type
tests/                 10 tests
```

## Lien avec MITRE ATT&CK et l'esprit « purple team »

Chaque règle porte ses tags ATT&CK, et `scripts/run.py` en dresse la couverture
par tactique. Les journaux proviennent de la **reproduction de techniques
documentées** (EVTX-ATTACK-SAMPLES) : on se sert d'attaques connues pour
**vérifier que la détection tient**, ce qui est le cœur du travail défensif,
sans jamais écrire d'attaque soi-même.

## Limites assumées

- **Un seul type de journal** : création de processus (Sysmon EID 1). Un vrai
  SOC corrèle plusieurs sources (réseau, authentification, EDR).
- **Événements normaux en partie synthétiques** : activité légitime courante,
  écrite pour rendre la mesure des fausses alertes significative, pas une
  capture de trafic d'entreprise.
- **Moteur Sigma volontairement réduit** au sous-ensemble utile ici ; l'outil
  officiel `sigma-cli` couvre toute la spécification.
- **Audit d'exclusions heuristique** : il classe par facilité d'accès du chemin,
  reprise de l'article cité ; c'est une aide à la relecture, pas une preuve.

## Références

- Dhananjeyan & Kumaran, *The Exclusion Ratchet*, arXiv:2608.31062, 2026
  ([code](https://github.com/sudaroli1/coverage-decay)).
- SigmaHQ — format et règles de détection : https://sigmahq.io
- sbousseaden, *EVTX-ATTACK-SAMPLES* : journaux d'attaques réels par technique.
- MITRE ATT&CK : https://attack.mitre.org
