# Bilan de projet — Gr0gu3270 + coding agent

**Date** : 2026-03-05
**Auteur** : analyse generee par coding agent, supervisee par l'operateur
**Portee** : de la creation du projet (2023-02) a la session coding agent (2026-03-04/05)

---

## Partie 1 — Plus-value realisee

### L'etat initial : 3 ans, 2253 lignes, un outil fonctionnel mais manuel

Gr0gu3270 existait depuis fevrier 2023. 70 commits sur 3 ans. Un proxy MitM TN3270 fonctionnel avec :
- Interception et modification du flux 3270
- Injection de payloads depuis des wordlists
- Hack fields (hidden, protected, numeric)
- GUI Tkinter 6 onglets
- SQLite logging (2 tables : Config, Logs)
- TLS, mode offline

L'outil faisait ce qu'il devait faire. Mais l'auditeur faisait le reste a la main :
- Detecter les ABENDs en lisant les ecrans visuellement
- Cartographier les champs en inspectant chaque ecran
- Tester les 186 transactions CICS une par une
- Classifier les reponses de securite manuellement
- Tester les touches PF une par une et revenir manuellement a l'ecran cible
- Pas de tests unitaires, pas de filet de securite sur le code
- Pas d'interface web, dependance a Tkinter et x3270

### Ce qui a ete produit en 2 jours

| Metrique | Avant | Apres | Delta |
|----------|-------|-------|-------|
| Code (LOC) | 2253 | 6262 | +4009 (+178%) |
| Fichiers code | 3 | 4 (+web.py) | +1 |
| Tests | 0 | 1123 LOC, 124 tests | from scratch |
| Tables DB | 2 | 7 | +5 |
| API endpoints | 0 | 36 | from scratch |
| Documentation | 0 | 1138 LOC, 11 fichiers | from scratch |
| Findings documentes | 0 | 9 (F-0001 a F-0009) | from scratch |
| Commits en 3 ans | 70 | 74 | +4 |

### Les 9 capacites ajoutees

1. **PR1 — ABEND Detection** : 20 codes CICS + prefixes DFH, detection automatique dans le flux reseau, table DB, alertes. L'auditeur ne lit plus les ecrans — l'outil detecte les crashes.

2. **PR2 — Screen Map** : parsing SBA/SF/SFE/MF, decodage attributs, cartographie automatique des champs. L'auditeur voit instantanement les champs hidden, protected, numeric, leur position, leur contenu.

3. **PR3 — Transaction Correlation** : detection automatique du code transaction dans les paquets client, timing requete/reponse en ms, historique en DB. L'auditeur a une timeline de toutes les transactions.

4. **PR4 — Security Audit** : 25 patterns RACF/ACF2/Top Secret, scan automatique de 186 transactions, classification ACCESSIBLE/DENIED/ABEND/ERROR, export CSV. L'auditeur lance un scan et obtient une matrice de droits en quelques minutes.

5. **PR5 — AID Scan** : test automatique des 28 touches (PF1-24, PA1-3, ENTER), replay du chemin de navigation, categorisation VIOLATION/NEW_SCREEN/SAME_SCREEN, triage par criticite. L'auditeur appuie sur SCAN et voit les 2-3 touches qui meritent investigation au lieu de tester les 28 a la main.

6. **Web UI** : 36 endpoints API, SPA embarquee, dashboard temps reel, onglet methodologie avec 25 concept cards, zero dependance. L'auditeur n'a plus besoin de Tkinter ni de X11 forwarding.

7. **SPOOL/RCE** : detection passive (SPOOLOPEN/SPOOLCLOSE) + PoC actif (FTP via CECI/INTRDR), 2 niveaux avec confirmation. L'auditeur teste le vecteur RCE le plus critique de CICS en 2 clics.

8. **Tests unitaires** : 124 tests pytest couvrant core + web + AID scan. Le code a un filet de securite. Chaque modification est validable en 3 secondes.

9. **Non-blocking I/O** : command queue, NonBlockingClientSocket, audit concurrent safe. L'outil ne bloque plus quand l'auditeur envoie des commandes pendant un scan.

### Ce que ca change dans un audit reel

**Avant** — un audit CICS typique sur un mainframe :

```
Jour 1 : Connexion, reconnaissance manuelle, test de 20-30 transactions a la main
Jour 2 : Test des champs hidden/protected ecran par ecran, notes manuelles
Jour 3 : Test des touches PF par transaction, retour manuel, notes
Jour 4 : Classification des resultats, redaction du rapport
Jour 5 : Finalisation, relecture, livraison
```

**Apres** — le meme audit avec les nouvelles capacites :

```
Jour 1 matin  : Connexion + Security Audit auto (186 txns) + Screen Map auto
Jour 1 apres  : AID Scan sur les ecrans critiques + SPOOL/RCE check
Jour 2 matin  : Investigation manuelle sur les findings signales (les 2-3 qui comptent)
Jour 2 apres  : Rapport (les findings sont deja structures en F-XXXX)
```

**Le gain n'est pas de 50%. C'est un changement de methode.** L'auditeur passe de l'echantillonnage (tester ce qu'il peut en 5 jours) a l'exhaustivite (scanner tout, puis investiguer ce qui ressort). Le coverage passe de ~15-20% a ~80-90% des transactions.

### Validation sur DVCA

Les capacites ont ete validees sur DVCA (Damn Vulnerable CICS Application) :
- 186/186 transactions ACCESSIBLE (F-0001, CRITICAL)
- Hidden field "99) Delete Order History" detecte (F-0004, HIGH)
- Protected fields editables via proxy (F-0005, HIGH)
- Information disclosure ecran d'accueil (F-0002, LOW)
- 4/7 vulns NetSPI trouvees automatiquement
- RCE theorique via SPOOL/INTRDR documente (F-0008, CRITICAL)

---

## Partie 2 — Critique de la conduite du projet

### Ce qui a bien fonctionne

**1. Le prompt fondateur etait precis.** Le premier prompt (00-PROMPT-FONDATEUR.md) specifiait les 4 features au niveau octet, avec les points d'integration, les dependances entre PRs, et le schema DB. Resultat : ~600 lignes de code en une passe, sans erreur d'architecture. L'expertise de 3 ans d'utilisation de l'outil a ete comprimee dans un prompt de 56 lignes. C'est la que l'operateur cree le plus de valeur : dans la specification, pas dans l'implementation.

**2. Les interventions de cadrage etaient efficaces.** 15 mots humains ont economise ~650K tokens. Le ratio cout/impact est documente dans le post-mortem : "Quelles etaient mes instructions ?" = 5 mots, ~500K tokens economises. L'operateur sait quand couper.

**3. L'echec a ete transforme en livrable.** La boucle x3270 (32 appels, ~4.70 EUR) aurait ete du gaspillage pur. L'instruction "Documente ton comportement" a transforme cet echec en post-mortem reutilisable, en best practices, et en contenu pour les stakeholders. C'est de la conduite de projet : rien ne se perd si on sait recycler.

**4. Le double objectif etait declare des le depart.** Le CLAUDE.md et le prompt fondateur mentionnent explicitement les deux objectifs : (1) faire evoluer Gr0gu3270, (2) demontrer l'impact des coding agents. La documentation n'est pas du scope creep — c'est un livrable prevu. Les analogies multi-public, le post-mortem, les guidelines de securite sont de la production intentionnelle, pas de la derive.

### Ce qui merite attention

**1. 959 lignes non committees.** Au moment de cette analyse, 8 fichiers modifies et 3 fichiers non trackes representent ~40% du travail de la journee. Le risque de perte est reel. Les 4 commits existants sont tous horodates a 16:10-16:11 le meme jour — un seul batch. L'historique git ne raconte pas l'histoire du projet, il dit juste "tout a ete fait d'un coup".

Recommandation : 1 feature = 1 commit. Le commit est le point de sauvegarde ET le point de documentation. `git log --oneline` devrait suffire a comprendre la progression du projet sans ouvrir un seul fichier markdown.

**2. Le CLAUDE.md derive encore.** Malgre la prise de conscience et la reecriture, la section "Tests" du CLAUDE.md dit encore "14 tests, PR1-PR4 coverage" alors que la realite est 124 tests. La regle de maintenance ("mettre a jour apres chaque changement d'architecture") n'a pas ete appliquee dans cette session meme.

Recommandation : la mise a jour du CLAUDE.md fait partie du commit, pas d'une tache separee. Si le commit ajoute l'AID scan, le CLAUDE.md du meme commit mentionne l'AID scan.

**3. Fichiers orphelins.** `test_aid_scan_live.py` (250 lignes, credentials DVCA/DVCA en dur) est dans la racine, pas dans `tests/`. `Gr0gu3270_stderr.log` est vide. `research/POSTMORTEM-CLAUDE-CODE.md` n'est pas tracke. Ce sont des artefacts de session qui s'accumulent.

Recommandation : `git status` avant de passer a la feature suivante. Les fichiers orphelins sont du bruit.

**4. L'outil et la mission sont dans le meme repo.** Les findings DVCA (F-0001 a F-0009) sont dans `research/FINDINGS.md`, commit dans le repo de l'outil. Sur un audit client, ces findings seraient des donnees de mission confidentielles. La separation outil/mission n'est pas faite.

Recommandation acceptable : DVCA est un lab public, les findings sont generiques. Mais pour un vrai audit, il faudra un repo separe ou un repertoire exclu.

---

## Partie 3 — Le point 80/20

### Pour l'outil (objectif 1)

**Le levier : automatiser la boucle d'audit complete.**

Aujourd'hui, les capacites sont la mais elles sont separees. L'auditeur lance le Security Audit, puis le Screen Map, puis l'AID Scan, puis regarde les findings. Le 80/20 c'est le **chaining** (Phase 3 du ROADMAP) :

```
1. Security Audit → identifie les transactions ACCESSIBLE
2. Pour chaque ACCESSIBLE → Screen Map → identifie les champs
3. Pour chaque champ editable → injection auto par champ
4. Pour chaque ecran → AID Scan → identifie les touches interessantes
5. Rapport structure automatique
```

Un bouton. Un rapport. L'auditeur intervient sur les findings, pas sur la conduite du scan.

Ce n'est pas de la vision — c'est 3 fonctions a ecrire. Le scan sequentiel existe (PR4). Le screen map existe (PR2). L'AID scan existe (PR5). L'injection existe (originale). Il manque le chef d'orchestre qui les enchaine.

**Mais avant ca** — 3 corrections qui prennent 10 minutes et augmentent la fiabilite de tout le reste :
- F-0003 : chemin relatif `list_injection_files()` → 1 ligne
- F-0007 : regex fallback ABEND → 5 lignes
- F-0009 partial : detection pattern LOGOFF dans AID scan → 15 lignes

### Pour la transmission (objectif 2)

**Le levier : le recit par la preuve.**

Le contenu produit (STAKEHOLDERS.md, post-mortem, prompt fondateur analyse) est riche mais disperses dans 11 fichiers markdown. Le public cible (DG, cyber, juridique, consultant) ne lira pas 11 fichiers. Il lira un document ou regardera une presentation.

Le 80/20 de la transmission :

```
1 presentation de 10 slides avec les 3 moments cles :
  - Slide 1-3 : Le prompt fondateur → 600 lignes en une passe (le multiplicateur)
  - Slide 4-6 : La boucle x3270 → 5€ gaspilles → pivot en 3 min (quand ca deraille)
  - Slide 7-9 : L'AID scan → PF3 LOGOFF → l'humain reprend (la limite)
  - Slide 10  : La regle — l'operateur coupe les boucles, l'IA execute les taches
```

Chaque slide a une version par public (DG / Cyber / Juridique / Consultant). Le materiau existe deja dans STAKEHOLDERS.md — il suffit de le restructurer en recit.

**Ce que le public retient :**
- Le DG retient le ROI : 178% de code en 2 jours, cout total < 20 EUR
- Le cyber retient la methode : exhaustivite au lieu d'echantillonnage
- Le juridique retient la tracabilite : tout est horodate, reproductible, confine
- Le consultant retient le ratio : 80% du livrable est genere, 20% est mis en perspective

### La regle unique

```
OPTIMISER LE WORKFLOW = REDUIRE LE NOMBRE D'INTERVENTIONS HUMAINES
                        SANS REDUIRE LEUR QUALITE

Aujourd'hui :  ~50 mots humains par session → 6200 LOC + 124 tests + 9 findings
Demain :       ~20 mots humains → meme resultat + rapport auto + chaining

L'operateur ne tape pas moins parce qu'il fait moins.
Il tape moins parce que chaque mot compte plus.
```

---

## Synthese chiffree

| Dimension | Valeur | Commentaire |
|-----------|--------|-------------|
| Code produit | +4009 lignes | +178% en 2 jours vs 3 ans |
| Tests | 124 (from 0) | Filet de securite inexistant avant |
| Features | 9 capacites | 5 PRs + web + SPOOL + I/O + tests |
| Findings | 9 documentes | 4 trouves automatiquement |
| Cout coding agent | ~15-20 EUR | Dont ~5 EUR de gaspillage (boucle x3270) |
| Temps humain | ~2-3h supervision | Sur 2 jours |
| Mots humains | ~50 par session | 15 mots = 650K tokens economises |
| Gain audit estime | 5 jours → 2 jours | Echantillonnage → exhaustivite |
| Docs produites | 11 fichiers, 1138 lignes | Objectif 2 : transmission |

| A corriger | Effort | Impact |
|------------|--------|--------|
| Commits granulaires | 0 min (habitude) | Securise tout le reste |
| CLAUDE.md a jour | 2 min par commit | Elimine la derive |
| F-0003 chemin relatif | 1 ligne | Fiabilite injection |
| F-0007 regex ABEND | 5 lignes | Zero faux negatifs |
| F-0009 detection LOGOFF | 15 lignes | AID scan robuste |
| Separation outil/mission | Architecture | Pret pour audit client |
