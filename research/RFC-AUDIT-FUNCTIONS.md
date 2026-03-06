# RFC: Fonctions d'audit — redondances, valeur réelle, consolidation

## Les 3 fonctions d'audit actuelles

### 1. Bulk Audit (onglet "Bulk Audit")

**Ce qu'il fait** : charge une wordlist (ex: `cics-default-transactions.txt`, 186 lignes), et pour chaque ligne : `CLEAR → TXN + ENTER → classify_response()`. Résultat : tableau TXN/Status/Preview.

**Pattern I/O** : `build_clear_payload()` → `send` → `recv` → `build_txn_payload()` → `send` → `recv` → `classify_response()`

### 2. Field Fuzzer (dans Screen Map)

**Ce qu'il fait** : charge une wordlist, et pour chaque ligne : `build_multi_field_payload()` → `send` → `recv` → `classify_response()` + `screen_similarity()`. Résultat : tableau Payload/Status.

**Pattern I/O** : `build_multi_field_payload()` → `send` → `recv` → `classify_response()`

### 3. Single TXN Scan (onglet "Scan")

**Ce qu'il fait** : envoie UNE transaction, analyse la réponse en profondeur : `classify_response()` + `detect_abend()` + `parse_screen_map()` + `fingerprint_esm()` + `analyze_screen_fields()`. Résultat : rapport détaillé.

**Pattern I/O** : `build_clear_payload()` → `send` → `recv` → `build_txn_payload()` → `send` → `recv` → `scan_analyze()`

## Analyse des redondances

### Bulk Audit = Fuzzer avec pattern fixe

| Aspect | Bulk Audit | Fuzzer |
|--------|-----------|--------|
| Entrée | Wordlist de TXN codes | Wordlist quelconque |
| Payload | `CLEAR` + `build_txn_payload()` | `build_multi_field_payload()` (champs sélectionnés) |
| Classification | `classify_response()` | `classify_response()` + `screen_similarity()` |
| Résultat | TXN / Status / Preview | Payload / Status |
| Replay/reset | CLEAR implicite avant chaque TXN | Follow-up keys configurable (CLEAR, PF3) |
| Scope | Système (navigue partout) | Écran (teste les champs visibles) |

**Constat** : Bulk Audit est un **cas particulier** du Fuzzer où :
- Le champ cible est le champ de saisie transaction (1er input)
- Le payload est un code transaction
- Le reset est toujours CLEAR
- Il n'y a pas de screen_similarity (on ne revient pas à l'écran de départ)

Le Fuzzer peut déjà faire ça : naviguer sur MCMM, sélectionner le champ "Option ==>", charger `cics-default-transactions.txt`, mode ENTER+CLEAR. Résultat identique.

**Verdict** : Bulk Audit est **100% redondant** avec le Fuzzer. Code dupliqué, UI dupliquée, résultats dans des tables DB différentes.

### Single TXN Scan — valeur unique mais mal positionnée

Le Scan apporte 2 choses que le Fuzzer ne fait pas :
1. **`fingerprint_esm()`** : détecte RACF/ACF2/Top Secret. Valeur réelle — c'est un finding de niveau système.
2. **`analyze_screen_fields()`** : compte les champs input/hidden/protected. **Mais c'est exactement ce que la Screen Map affiche déjà.**

**Constat** : `analyze_screen_fields()` est redondant avec Screen Map. `fingerprint_esm()` a de la valeur mais pourrait être intégré dans `classify_response()` ou dans le Screen Map.

**Verdict** : Scan = ESM fingerprint (unique) + duplicata de Screen Map.

## Proposition de consolidation

### Supprimer : Bulk Audit

- **Onglet** : supprimé de l'accordion
- **Code backend** : `audit_start()`, `audit_stop()`, `audit_next()`, `audit_process_response()`, `_audit_worker()` — supprimés
- **DB table** : `Audit` — conservée pour compatibilité offline mais plus alimentée par le Bulk Audit
- **Wordlists** : restent disponibles — le Fuzzer les charge
- **Le Fuzzer le remplace** à 100% avec le mode ENTER+CLEAR sur le champ transaction

### Absorber : Single TXN Scan → Screen Map

- **`fingerprint_esm()`** : intégrer dans `loadScreenMap()` — à chaque refresh, tenter un fingerprint ESM sur la dernière réponse serveur. Afficher le résultat (RACF/ACF2/TSS/UNKNOWN) dans le header du panel Screen Map.
- **`analyze_screen_fields()`** : supprimé — la Screen Map affiche déjà toutes ces infos visuellement (comptage par couleur de ligne).
- **Onglet Scan** : supprimé de l'accordion.
- **`scan_send_txn()`** : pas nécessaire — l'auditeur navigue manuellement vers la transaction, ce qui est plus fiable que l'envoi automatique CLEAR+TXN.

### Garder tel quel : Fuzzer + AID Scan

Ce sont les 2 outils écran-scoped qui n'ont pas de redondance.

## Étude d'impact

### Code supprimé

| Fichier | Fonction | Lignes (approx) |
|---------|----------|---------|
| `libGr0gu3270.py` | `audit_start()`, `audit_stop()`, `audit_next()`, `audit_process_response()` | ~80 lignes |
| `libGr0gu3270.py` | `scan_send_txn()`, `scan_analyze()`, `analyze_screen_fields()` | ~80 lignes |
| `web.py` | `audit_start()`, `_audit_worker()`, `audit_stop()`, endpoints audit | ~80 lignes |
| `web.py` | `scan_txn()`, `_scan_worker()`, `export_scan_csv()`, endpoints scan | ~60 lignes |
| `web.py` | HTML/JS onglets Bulk Audit + Scan | ~100 lignes |
| **Total** | | **~400 lignes supprimées** |

### Code déplacé

| Fonction | De → Vers |
|----------|-----------|
| `fingerprint_esm()` | `libGr0gu3270.py` → reste, appelé par Screen Map refresh |

### DB impact

| Table | Action |
|-------|--------|
| `Audit` | Conservée (compat offline). Plus alimentée par Bulk Audit. Le Fuzzer écrit dans `Logs`. |
| `ScanResults` | Conservée (compat offline). Plus alimentée par Scan. |
| Autres tables | Aucun changement |

### API endpoints

| Endpoint | Action |
|----------|--------|
| `POST /api/audit/start` | Supprimé |
| `POST /api/audit/stop` | Supprimé |
| `GET /api/audit/results` | Supprimé |
| `GET /api/audit/summary` | Supprimé |
| `POST /api/audit/export` | Supprimé |
| `POST /api/scan` | Supprimé |
| `GET /api/scan/result` | Supprimé |
| `GET /api/scan/export` | Supprimé |

### tk.py

- Tab "Security Audit" (tab 10) utilise les mêmes endpoints → **cassé**
- Tab "Transactions" (tab 9) n'est pas impacté
- **Options** :
  - A) Casser tk.py (personne ne l'utilise pour l'audit ?)
  - B) Garder les endpoints comme wrappers vers le Fuzzer
  - C) Migrer tk.py audit vers le Fuzzer

### Tests impactés

| Test | Action |
|------|--------|
| Tests audit endpoints (`test_web.py`) | Supprimés |
| Tests scan endpoints (`test_web.py`) | Supprimés |
| Tests `classify_response()` | Conservés (utilisé par Fuzzer + AID Scan) |
| Tests `fingerprint_esm()` | Conservés |
| Tests `build_clear_payload()`, `build_txn_payload()` | Conservés (utilisés par Fuzzer follow-up keys) |

### Risques

| Risque | Probabilité | Mitigation |
|--------|------------|------------|
| Un auditeur habitué au Bulk Audit ne retrouve pas la feature | Moyen | Documenter : "utiliser le Fuzzer sur le champ transaction avec mode ENTER+CLEAR" |
| Le Fuzzer n'a pas le CLEAR implicite du Bulk Audit | Faible | Le mode ENTER+CLEAR existe déjà |
| tk.py cassé pour l'audit | Faible | tk.py n'est plus maintenu activement |
| Perte des résultats historiques de Bulk Audit | Nul | Tables DB conservées, mode offline fonctionne |

## Avant / Après

### Onglets SCANNING actuels (4)
```
Scan | Bulk Audit | AID Scan | SPOOL/RCE
```

### Onglets SCREEN proposés (2)
```
AID Scan | SPOOL/RCE
```

Le Fuzzer est déjà dans Screen Map. Le Scan et le Bulk Audit disparaissent.
L'ESM fingerprint s'affiche dans le header de la Screen Map.

## Gain net

- **-400 lignes de code** backend + frontend
- **-2 onglets** dans l'UI
- **-8 endpoints API**
- **Zéro perte fonctionnelle** : le Fuzzer fait tout ce que Bulk Audit faisait, Screen Map fait tout ce que Scan faisait
- **Complexité réduite** : 1 seul chemin d'injection au lieu de 3 (Fuzzer vs Audit vs Scan)
