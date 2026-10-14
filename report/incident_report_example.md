# Rapport d'incident — Découverte d'identifiants IIS via appcmd.exe

**Référence :** INC-2026-0142
**Analyste :** Fatima-Zahra Rhoulam
**Gravité :** Élevée
**Statut :** Clôturé — remédié

---

## 1. Résumé pour le client

Sur un serveur web Windows, un processus a été vu en train de lire les
**identifiants d'un pool d'applications IIS** à l'aide de l'outil légitime
`appcmd.exe`. Ce comportement correspond à la technique MITRE ATT&CK
**T1552.001 — Credentials In Files**. Les identifiants d'un pool d'applications
donnent accès à l'application hébergée et parfois à un compte de service : leur
lecture par un processus inattendu est traitée comme une tentative de vol
d'identifiants.

## 2. Détection

- **Règle déclenchée :** « Découverte de secrets IIS via appcmd.exe »
  (Sigma, `rules/attack/appcmd_iis_cred_discovery.yml`).
- **Journal source :** Sysmon, EventID 1 (création de processus).
- **Observable clé :**
  `appcmd.exe list apppool ". )" /text:processmodel.password`

Le motif `/text:processmodel.password` n'apparaît pas dans l'administration
courante d'IIS : c'est ce qui distingue la lecture malveillante d'un simple
inventaire (`list vdir`, `list apppool` sans champ de mot de passe), qui, lui,
ne déclenche pas la règle.

## 3. Chronologie (extrait des événements observés)

| Horodatage | Événement |
|---|---|
| T0 | `appcmd.exe list apppool /text:processmodel.username` |
| T0 + qq s | `appcmd.exe list apppool /text:processmodel.password` |
| T0 + qq s | `appcmd.exe list vdir /text:physicalpath` (reconnaissance des chemins) |

## 4. Évaluation d'impact

- **Confidentialité :** compromise — des identifiants de service ont pu être lus.
- **Intégrité / disponibilité :** pas d'altération observée à ce stade.
- **Portée :** limitée au serveur IIS concerné dans les journaux fournis.

## 5. Remédiation

1. **Rotation immédiate** des mots de passe des pools d'applications IIS du serveur.
2. **Revue des comptes de service** associés et de leurs privilèges (moindre privilège).
3. **Recherche de latéralisation** : connexions sortantes et réutilisation des
   identifiants ailleurs sur le réseau.
4. **Renforcement :** restreindre l'exécution d'`appcmd.exe` aux comptes
   d'administration, et surveiller tout accès au champ `processmodel.password`.

## 6. Note sur la détection (amélioration continue)

La règle a été vérifiée contre de l'activité IIS normale : elle ne se déclenche
pas sur l'inventaire de routine. Aucune exclusion n'a été jugée nécessaire. Si
du bruit apparaissait, toute exclusion serait passée à l'audit
(`scripts/run.py`, section 4) pour éviter d'ouvrir un angle mort.

---

*Rapport d'exemple produit à partir de journaux d'attaque publics
(EVTX-ATTACK-SAMPLES), à des fins de démonstration.*
