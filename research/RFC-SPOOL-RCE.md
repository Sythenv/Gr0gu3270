# RFC: SPOOL/RCE — garder, supprimer ou repositionner ?

## Ce que fait SPOOL/RCE

2 fonctions, 2 niveaux :

### Level 1 : `spool_check()` — détection passive
- Envoie `CECI SPOOLOPEN OUTPUT TOKEN(H3TK)` puis `SPOOLCLOSE`
- Si SPOOLOPEN retourne NORMAL → SPOOL API accessible → RCE possible
- **Aucune écriture**, aucun impact sur le mainframe
- Résultat binaire : `SPOOL_OPEN` ou `SPOOL_CLOSED`

### Level 2 : `spool_poc_ftp()` — PoC actif
- Écrit un JCL FTP via SPOOLWRITE + INTRDR
- Soumet un job qui fait un callback FTP vers `listener_ip:port`
- **Écrit sur le mainframe** — c'est une action offensive
- Prouve la RCE concrètement (finding F-0008, CRITIQUE)

## Analyse 80/20

### La question : est-ce que le pentester prend une décision avec SPOOL/RCE ?

**Oui, absolument.** SPOOL/RCE est la seule feature qui prouve un **impact business réel** (RCE = exécution de code arbitraire sur le mainframe). C'est le finding le plus critique possible sur un audit CICS.

Mais il y a un problème de **contexte d'utilisation** :

| Aspect | Problème |
|--------|----------|
| **Prérequis** | Il faut être sur CECI — pas sur l'écran audité |
| **Fréquence** | On le lance **1 fois par audit**, pas par écran |
| **Scope** | Système, pas écran — même constat que Bulk Audit |
| **Danger** | Le PoC FTP écrit du JCL sur le mainframe — un clic accidentel est irréversible |

### Ce qui a de la valeur vs ce qui n'en a pas

| Élément | Valeur | Verdict |
|---------|--------|---------|
| `spool_check()` (Level 1) | **Haute** — détection passive, zéro risque, finding CRITIQUE | **Garder** |
| `spool_poc_ftp()` (Level 2) | **Haute mais situationnelle** — preuve de RCE, mais 1 seule fois par audit | **Garder mais protéger** |
| Onglet dans SCANNING à côté de AID Scan | **Problème** — mélange outil système avec outils écran | **Repositionner** |
| IP + Port dans l'UI | **Problème** — invite à lancer le PoC sans réfléchir | **Séparer du check** |

## Proposition

### Option A : Garder, repositionner (recommandé)

1. **Sortir SPOOL de l'accordion principal** → le mettre dans un groupe SYSTEM dédié (avec Bulk Audit si conservé), clairement séparé des outils écran
2. **Séparer Level 1 et Level 2 visuellement** :
   - CHECK SPOOL = bouton normal, accessible partout
   - FTP PoC = derrière une confirmation explicite ("This will write JCL to the mainframe. Continue?")
3. **Auto-check** : lancer `spool_check()` automatiquement au premier CECI détecté dans les logs de transaction, afficher le résultat dans l'OIA bar ou en toast

### Option B : Réduire au check seul

1. Supprimer le PoC FTP de l'UI — l'auditeur qui veut prouver la RCE peut le faire manuellement via CECI
2. Garder uniquement `spool_check()` comme indicateur passif
3. **Gain** : -100 lignes (poc_ftp + JCL builder + UI), risque zéro d'accident
4. **Perte** : l'auditeur doit taper le JCL à la main pour prouver la RCE

### Option C : Supprimer complètement

Non recommandé. SPOOL/RCE est le seul chemin vers un finding CRITIQUE. Le supprimer serait comme supprimer le module SQLi d'un scanner web.

## Étude d'impact (Option A — repositionnement)

### Code modifié

| Fichier | Changement | Lignes |
|---------|-----------|--------|
| `web.py` | Déplacer SPOOL de SCANNING vers SYSTEM dans GROUPS/ACTIONS | ~5 lignes |
| `web.py` | Ajouter confirmation JS avant `spoolPoc()` | ~5 lignes |
| `libGr0gu3270.py` | Aucun | 0 |
| `tests/` | Aucun | 0 |

### Effort : ~10 lignes modifiées, 0 risque.

## Étude d'impact (Option B — check seul)

### Code supprimé

| Fichier | Fonction | Lignes |
|---------|----------|--------|
| `libGr0gu3270.py` | `spool_poc_ftp()` | ~70 lignes |
| `web.py` | `spool_poc_ftp()` endpoint + handler | ~15 lignes |
| `web.py` | HTML (IP input, Port input, FTP PoC button, résultats JCL) | ~10 lignes |
| `web.py` | JS `spoolPoc()` function | ~20 lignes |
| `tests/test_web.py` | Tests PoC FTP | ~15 lignes |
| **Total** | | **~130 lignes supprimées** |

### Code conservé

| Fonction | Raison |
|----------|--------|
| `spool_check()` | Détection passive — valeur maximale |
| `_spool_send_and_read()` | Utilisé par `spool_check()` |
| `build_ceci_payload()` | Utilisé par `_spool_send_and_read()` |

### tk.py
- Pas d'onglet SPOOL dans tk.py → aucun impact

### DB
- Table `Audit` reçoit les résultats SPOOL → pas de changement de schema

## Recommandation

**Option A** (repositionner) si on veut garder la capacité PoC complète.
**Option B** (check seul) si on veut maximiser le ratio signal/risque.

Dans les 2 cas, le `spool_check()` reste — c'est un one-click finding CRITIQUE, aucune raison de le supprimer.
