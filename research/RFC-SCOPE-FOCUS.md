# RFC: Focus écran — éliminer ce qui sort du périmètre de la transaction auditée

## Constat

L'auditeur observe **un écran** (ex: MCOR). Son périmètre de décision :
- Quels champs sont présents ? (Screen Map)
- Quelles touches font quoi ? (AID Scan)
- Que se passe-t-il si j'injecte ? (Fuzzer)
- Est-ce que le serveur a réagi anormalement ? (ABEND/DENY en réponse à MES actions)

Tout le reste est soit du contexte global (utile en phase de restitution, pas pendant l'audit),
soit du bruit qui dilue l'attention.

## Éléments hors périmètre écran

### 1. Events panel — accumulation globale

**Problème** : les compteurs ABND/TXN/DENY et le tableau événements sont **cumulatifs depuis le début de session**. Quand l'auditeur est sur MCOR, il voit les ABENDs de MCMM, les TXNs de login, etc. Ce bruit augmente avec le temps.

**Ce que le pentester veut** : "qu'est-ce qui s'est passé depuis que je suis sur CET écran ?"

**Proposition** :
- Ajouter un compteur "since last CLEAR" qui se reset quand l'écran change
- Ou filtrer les events par transaction courante
- Ou simplement : ne montrer que les N derniers événements (ex: 10) au lieu de tout

**Impact suppression complète** :
- Perte de la timeline globale de session → acceptable car les données restent dans la DB et l'onglet Logs
- Le panel Events mange ~40% de l'espace vertical → le récupérer pour la Screen Map et le Fuzzer serait un gain énorme
- **tk.py** : pas impacté (tabs séparés)
- **DB** : aucun changement
- **Risque** : l'auditeur perd la vue d'ensemble "en un coup d'œil". Mitigation : garder les compteurs dans l'OIA bar en bas

### 2. OIA bar — compteurs globaux A/T/D

**Problème** : `A:3 T:45 D:2` en bas de l'écran. Même issue — ce sont des compteurs de session, pas d'écran. L'auditeur ne peut pas savoir si le A:3 vient de son action ou de 20 minutes avant.

**Proposition** : remplacer par l'écran courant (nom de transaction détecté) + indicateur "dernière action" (ex: puce verte = OK, rouge = ABEND)

**Impact** :
- Perte des totaux de session → ils restent dans Stats/Logs
- **tk.py** : pas impacté
- **Risque** : faible

### 3. Bulk Audit — outil système, pas écran

**Problème** : le Bulk Audit (186 transactions) **navigue loin de l'écran courant**. Le lancer depuis MCOR = quitter MCOR. Ce n'est pas un outil d'analyse de l'écran observé.

**Proposition** : déplacer dans un groupe "SYSTEM" clairement séparé, ou le rendre accessible uniquement depuis le menu principal (MCMM/CSGM), pas depuis n'importe quel écran.

**Impact** :
- Aucune perte fonctionnelle — juste un repositionnement
- Réduit le groupe SCANNING de 4 à 3 onglets (Scan, AID Scan, SPOOL → Scan, AID Scan)
- **tk.py** : tab Audit existe déjà séparément
- **Risque** : nul

### 4. SPOOL/RCE — outil système, pas écran

**Problème** : SPOOL/RCE nécessite d'être sur CECI (une transaction système). Comme Bulk Audit, ce n'est pas lié à l'écran courant.

**Proposition** : même traitement que Bulk Audit — groupe SYSTEM séparé.

**Impact** :
- Le groupe SCANNING ne contient plus que : Scan + AID Scan (les 2 outils vraiment liés à l'écran)
- **Risque** : nul

### 5. Hack Color — rarement utilisé

**Problème** : Hack Color modifie les attributs couleur des champs. C'est un outil de débogage TN3270, pas d'audit. En 3 ans, combien de fois ça a changé une décision de pentest ?

**Proposition** : fusionner avec Hack Fields sous un seul toggle, ou déplacer dans un menu avancé.

**Impact** :
- 1 onglet en moins dans HACKS (2 → 1+Send Keys)
- **tk.py** : panel séparé, pas impacté
- **Risque** : les rares cas où les attributs couleur masquent un champ → garder en mode avancé

### 6. Statistics — données froides

**Problème** : Stats affiche des métriques de session (bytes transférés, nombre de requêtes). Information post-mortem, pas décisionnelle pendant l'audit.

**Proposition** : disponible uniquement en mode offline (`-o`) ou dans un export. Pas besoin de polluer l'UI live.

**Impact** :
- 1 onglet en moins dans DATA (Logs + Stats → Logs seul)
- **Risque** : nul — les stats sont dans la DB

### 7. Methodology/Help — référence, pas action

**Problème** : 2 onglets de texte statique. Utiles en découverte, encombrants après 2 sessions.

**Proposition** : accessibles via un `?` dans le header, pas via des onglets permanents.

**Impact** :
- Le groupe GUIDE disparaît entièrement de l'accordion
- **Risque** : nouvel utilisateur perd un point d'entrée → mitigation : `?` visible dans le header

## Résumé de l'impact

### Avant (état actuel)

```
HEADER:  Gr0gu3270 | connection | H C A T
SCREEN MAP:  [table ~30% hauteur]
EVENTS:      [table ~40% hauteur]
ACCORDION:   HACKS (3) | SCANNING (4) | DATA (2) | GUIDE (2) = 11 onglets
OIA BAR:     CONNECTED | target | A:3 T:45 D:2 | version
```

### Après (proposition)

```
HEADER:  Gr0gu3270 | connection | H | ?
SCREEN MAP:  [table ~45% hauteur — plus d'espace]
DERNIERS EVENTS: [3-5 derniers, inline sous screen map]
ACCORDION:   HACKS (2) | SCREEN (2) | SYSTEM (2) | DATA (1) = 7 onglets
OIA BAR:     CONNECTED | target | TXN: MCOR | dernière action: ● | version
```

### Delta

| Élément | Avant | Après | Changement |
|---------|-------|-------|------------|
| Onglets accordion | 11 | 7 | -4 onglets |
| Events panel | Table complète (~40% écran) | 3-5 derniers inline | -35% espace récupéré |
| OIA bar | Compteurs globaux | TXN courante + indicateur | Plus actionnable |
| Screen Map | ~30% hauteur | ~45% hauteur | +50% espace |
| Groupes | 4 (HACKS/SCANNING/DATA/GUIDE) | 4 (HACKS/SCREEN/SYSTEM/DATA) | Reorg sémantique |

### Fichiers impactés

| Fichier | Nature du changement | Risque |
|---------|---------------------|--------|
| `web.py` | HTML/CSS/JS uniquement — réorg panels, suppression onglets, OIA refonte | Moyen (beaucoup de lignes) |
| `libGr0gu3270.py` | Aucun | Zero |
| `tk.py` | Aucun — tabs indépendants | Zero |
| `tests/test_web.py` | Endpoints inchangés — tests HTTP passent | Zero |
| `CLAUDE.md` | Mise à jour compteurs onglets | Trivial |

### Compatibilité

- **API** : aucun endpoint supprimé ou modifié → backward compatible
- **DB** : aucun changement de schema
- **tk.py** : indépendant, non impacté
- **Mode offline** : fonctionnel (Stats accessible offline → le déplacer, pas le supprimer)

## Priorité

| Prio | Action | Gain | Effort |
|------|--------|------|--------|
| **P1** | Events → derniers N inline | +35% espace écran, focus sur l'écran courant | Moyen |
| **P1** | SCANNING split → SCREEN (Scan+AID) + SYSTEM (Audit+SPOOL) | Clarté sémantique | Faible |
| **P2** | OIA bar → TXN courante + indicateur action | Feedback immédiat | Faible |
| **P2** | Stats + Method + Help → hors accordion | -3 onglets | Faible |
| **P3** | Hack Color → fusionner avec Hack Fields | -1 onglet | Faible |

## Décision attendue

Validation visuelle sur DVCA avant implémentation. L'auditeur doit confirmer que la vue "focalisée écran" lui suffit pour prendre ses décisions sur la transaction observée.
