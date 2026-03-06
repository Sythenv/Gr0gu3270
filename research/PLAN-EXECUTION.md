# Plan d'exécution — consolidation des 6 RFCs

## Principe

3 phases. Chaque phase est committable et testable indépendamment.
On ne passe à la phase suivante qu'après validation visuelle DVCA.

---

## Phase 1 : Débloquer + fiabiliser (1h, ~80 lignes code + 3 fichiers)

**Objectif** : l'outil donne des résultats fiables et actionnables dès maintenant.

| # | Action | Source RFC | Effort | Impact |
|---|--------|-----------|--------|--------|
| 1.1 | **Hidden fields cliquables** — `if (isInput)` → `if (isInput \|\| isHidden)` | FUZZER-HIDDEN P0 | 5 lignes | Débloque le use case principal |
| 1.2 | **Regex fallback ABEND** — `re.findall(r'ABEND ([A-Z0-9]{4})')` | WORDLISTS-ABENDS / F-0007 | 5 lignes | Zéro faux négatif ABEND |
| 1.3 | **+13 codes ABEND + sévérité** — étendre dict avec CRIT/HIGH/INFO | WORDLISTS-ABENDS | 35 lignes | Triage immédiat |
| 1.4 | **Extraction contexte ABEND** — regex `TRANSACTION x ABEND y IN PROGRAM z` | WORDLISTS-ABENDS | 10 lignes | Findings complets |
| 1.5 | **Sévérité dans l'UI** — couleur par niveau dans Events | WORDLISTS-ABENDS | 15 lignes | Visuel actionnable |
| 1.6 | **3 wordlists** — `ceci-commands.txt`, `cobol-overflow.txt`, `custom-txn-prefixes.txt` | WORDLISTS-ABENDS | 0 code, 3 fichiers | +3 surfaces d'attaque |

**Tests** : adapter ~5 tests existants ABEND + ajouter tests regex fallback.
**Validation** : lancer le fuzzer sur MCGM hidden field + vérifier sévérité ABEND sur DVCA.

---

## Phase 2 : Nettoyer l'UI (1h, ~60 lignes)

**Objectif** : chaque pixel aide l'auditeur à décider. On applique RFC-UI-CLEANUP.

| # | Action | Source RFC | Effort | Impact |
|---|--------|-----------|--------|--------|
| 2.1 | **Fuzz results** — supprimer Size et Sim%, garder Payload + Status | UI-CLEANUP | 5 lignes | Résultats lisibles |
| 2.2 | **AID Scan** — supprimer Status + Similarity, Preview→tooltip | UI-CLEANUP | 10 lignes | R + Key + Category suffit |
| 2.3 | **Events** — supprimer ID et ms | UI-CLEANUP | 5 lignes | 4 colonnes actionnables |
| 2.4 | **Audit** — supprimer ID et Time | UI-CLEANUP | 5 lignes | 3 colonnes actionnables |
| 2.5 | **Screen Map N** — déplacer dans SHOW ALL uniquement | UI-CLEANUP | 10 lignes | Cohérent avec Pos |
| 2.6 | **ABEND Ref** — Seen compteur → puce verte/vide | UI-CLEANUP | 5 lignes | Binaire > compteur |
| 2.7 | **Contexte fuzz** — afficher champs ciblés + touche au-dessus des résultats | FUZZER-HIDDEN P1 | 15 lignes | Résultats actionnables |

**Tests** : aucun changement backend → 0 tests à modifier.
**Validation** : screenshot comparatif avant/après sur DVCA MCOR.

---

## Phase 3 : Restructurer (2h, ~-400 lignes net)

**Objectif** : supprimer le code mort, réorganiser par scope (écran vs système).

| # | Action | Source RFC | Effort | Impact |
|---|--------|-----------|--------|--------|
| 3.1 | **Supprimer Bulk Audit** — onglet, worker, endpoints (le fuzzer le remplace) | AUDIT-FUNCTIONS | -200 lignes | 1 seul chemin d'injection |
| 3.2 | **Absorber Single Scan** — `fingerprint_esm()` dans header Screen Map, supprimer le reste | AUDIT-FUNCTIONS | -150 lignes + 10 | ESM visible sans onglet dédié |
| 3.3 | **Split SCANNING → SCREEN + SYSTEM** — AID Scan dans SCREEN, SPOOL dans SYSTEM | SCOPE-FOCUS | 10 lignes | Séparation sémantique |
| 3.4 | **Confirmation PoC SPOOL** — dialog JS avant `spoolPoc()` | SPOOL-RCE | 5 lignes | Zéro accident |
| 3.5 | **Bouton replay fuzz** — endpoint `/api/inject/replay` + ▶ par ligne résultat | FUZZER-HIDDEN P1 | 25 lignes | PoC rejeu 1-clic |
| 3.6 | **Stats/Method/Help** — hors accordion, `?` dans header | SCOPE-FOCUS | 20 lignes | -3 onglets |

**Tests** : supprimer tests Bulk Audit/Scan endpoints, ajouter test replay.
**Validation** : navigation complète DVCA — tous les outils fonctionnent depuis la nouvelle structure.

---

## Ce qu'on NE fait PAS (hors 80/20)

| Action | Pourquoi non |
|--------|-------------|
| Events → inline last N | Refonte lourde du polling, gain marginal vs suppression colonnes |
| OIA bar → TXN courante | Nécessite détection écran actif, complexe pour le gain |
| Hack Color fusion | Rarement utilisé mais pas gênant |
| Export payload hex | P2, l'auditeur peut lire les Logs |
| Credentials wordlists | Hors scope fuzzer (login flow différent) |
| Dataset names wordlists | Nécessite accès TSO, pas CICS |

---

## Métriques avant/après

| Métrique | Avant | Après Phase 3 |
|----------|-------|---------------|
| LOC web.py | ~2600 | ~2200 |
| LOC libGr0gu3270.py | ~2700 | ~2550 |
| Onglets accordion | 11 | 7 |
| Colonnes total (tous tableaux) | 30 | 17 |
| Endpoints API | 39 | 32 |
| ABEND codes couverts | 20 | 50+ (dict + regex fallback) |
| Wordlists | 16 fichiers | 19 fichiers |
| Surfaces d'attaque couvertes | 3 (txns, SQLi, brute) | 6 (+CECI, +overflow, +custom txn) |
| Hidden fields fuzzables | Non | Oui |
| PoC rejeu | Non | Oui |
| Tests | 146 | ~150 |
