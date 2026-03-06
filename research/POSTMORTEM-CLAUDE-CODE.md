# Post-mortem : boucle de debug Claude Code — AID Scan session

**Date** : 2026-03-05
**Contexte** : Implementation de l'AID Scan sur Gr0gu3270, test live sur DVCA

---

## Ce qui s'est passe

### Instruction utilisateur
> "Tu fais tout, idealement il faut trouver deux ou trois points d'entree pour faire des tests de debug et donne moi les resultats"

### Ce que Claude a fait
1. Implementation correcte (code + 29 tests, ~20 min) — **OK**
2. Boucle de 32 appels outils pour tenter de connecter x3270 GUI au proxy depuis WSL (~15-20 min) — **ECHEC**
3. Demande a l'utilisateur de faire le travail lui-meme (2x AskUserQuestion) — **contraire a l'instruction**
4. Finalement, ecriture d'un script headless qui marche du premier coup (~3 min) — **aurait du etre l'etape 2**

### Cout du gaspillage
| Metrique | Valeur |
|---|---|
| Appels outils inutiles | ~32 |
| Temps perdu | ~15-20 min |
| Tokens gaspilles (input) | ~1.2M |
| Tokens gaspilles (output) | ~20K |
| Cout estime | ~4.70 EUR |
| % du budget session | ~30-40% |

---

## Analyse : pourquoi la boucle

### Pattern observe
```
Essayer x3270 → echec → kill process → changer un parametre → reessayer
→ re-echec → kill → changer autre chose → reessayer → ...
```

### Causes racines
1. **Pas de diagnostic avant action** : Claude n'a pas verifie si x3270 GUI etait une approche viable depuis un script CLI non-interactif
2. **Biais de perseverance** : au lieu de pivoter apres 2-3 echecs, Claude a continue la meme approche en variant les parametres (port, TLS flag, mode script, etc.)
3. **Absence de plan B** : pas de reflexion sur les alternatives avant de commencer
4. **Non-respect de l'instruction** : "tu fais tout" = autonome, mais Claude a demande a l'utilisateur de connecter x3270 manuellement

### Le pivot correct (fait trop tard)
L'architecture proxy Gr0gu3270 **necessite un client TN3270 externe**. En mode CLI/script :
- x3270 GUI = fragile (DISPLAY, fonts, negotiation timing)
- s3270/c3270 = pas installe
- **Script Python raw socket = la seule option fiable** et c'etait evident des le depart

---

## Best practices utilisateur Claude Code

### 1. Couper tot les boucles de debug
**Regle des 3** : si Claude echoue 3 fois a la meme operation avec des variations mineures, interrompre.
```
Utilisateur : "Stop. Pourquoi ca marche pas ? Quelle est l'alternative ?"
```
L'interruption force Claude a prendre du recul et considerer d'autres approches au lieu de brute-forcer.

### 2. Verifier le plan avant l'execution
Quand Claude annonce une approche impliquant des process externes (serveurs, GUI, Docker), demander :
```
Utilisateur : "Quels sont les risques de cette approche ? Quel est le plan B ?"
```
Si Claude n'a pas de plan B, c'est un red flag.

### 3. Rappeler l'instruction quand Claude derive
Claude peut oublier l'instruction initiale au fil des iterations de debug. Un rappel direct recentre :
```
Utilisateur : "Quelles etaient mes instructions ?"
```
C'est ce qui a ete fait dans cette session — ca a provoque le pivot vers le headless.

### 4. Surveiller le pattern kill/restart
Le cycle `kill process → restart → check → echec → kill` est un signal clair de boucle improductive. L'utilisateur peut detecter ce pattern dans les tool calls et intervenir :
```
Utilisateur : "Tu tournes en rond. Change d'approche."
```

### 5. Preferer les approches testables unitairement
Quand Claude propose une approche qui depend d'un etat systeme complexe (process, ports, GUI), suggerer :
```
Utilisateur : "Fais un script de test autonome plutot que de dependre de X"
```
Un script Python autonome > une chaine de process interdependants.

### 6. Budget mental : cout visible
L'utilisateur ne voit pas le cout en tokens en temps reel. Regle empirique :
- Chaque appel outil Bash dans un long contexte = ~0.10-0.20 EUR (Opus)
- Une boucle de 30 appels = ~3-5 EUR de gaspillage
- Si le debug depasse 5-6 appels sans progres, l'utilisateur economise en interrompant

### 7. "Tu fais tout" necessite un cadrage
L'instruction "tu fais tout" est puissante mais risquee. Cadrer avec :
```
Utilisateur : "Tu fais tout. Si tu bloques plus de 3 essais, change d'approche.
              Si tu ne peux vraiment pas, explique pourquoi en une phrase."
```

---

## Conduite du contexte et economie de tokens

### Le contexte est un budget

La fenetre de contexte d'un LLM est une ressource finie. Chaque tool call ajoute du contenu qui reste dans la fenetre : la commande, la sortie, la reponse de l'IA. Ce contenu **ne disparait pas** — il pese sur chaque appel suivant. La boucle x3270 a injecte ~32 blocs de sorties de debug (ports, PIDs, erreurs) dans le contexte. Ces sorties n'ont **aucune valeur pour la suite** mais elles sont facturees a chaque appel suivant parce que le modele les relit.

C'est l'equivalent d'un avocat qui photocopie 32 pages de brouillons rates et les ajoute au dossier de plaidoirie : le dossier grossit, le cout de lecture augmente, mais la valeur du contenu est nulle.

### Les interventions humaines les plus rentables de la session

| Intervention | Mots | Effet | Tokens economises (estime) |
|---|---|---|---|
| "Quelles etaient mes instructions ?" | 5 | Arrete la boucle, force le pivot | ~500K (15+ appels evites) |
| "Nope" | 1 | Bloque une mauvaise direction | ~100K (3-4 appels evites) |
| "Documente ton comportement" | 3 | Redirige vers une production utile | ~0 (pas d'economie, mais valeur creee) |
| "Ok, on en est ou la ?" | 6 | Force un point de situation | ~50K (evite la dispersion) |

**Ratio cout/impact** : 15 mots humains ont economise ~650K tokens. Un mot humain bien place vaut ~40K tokens d'IA.

### Le contexte propre vs le contexte pollue

**Session productive (PR1-PR4, matin)** :
- Contexte lineaire : instruction → implementation → test → validation
- Chaque bloc de contexte sert au suivant
- Le contexte s'enrichit (le code ecrit informe les tests qui informent le debug)

**Session boucle (x3270, soir)** :
- Contexte circulaire : essai → echec → kill → essai → echec
- Chaque bloc de contexte est une copie degradee du precedent
- Le contexte se pollue (les sorties d'erreur noient les informations utiles)

La difference n'est pas dans la quantite de tokens — c'est dans la **densite informationnelle**. Un contexte de 100K tokens bien conduit produit plus qu'un contexte de 200K tokens pollue.

### La synergie operateur-IA comme gestion de contexte

L'operateur humain joue trois roles invisibles mais critiques :

**1. Garbage collector** — Il identifie quand le contexte se remplit de bruit et coupe. "Nope", "Stop", "Change d'approche" sont des operations de nettoyage. L'IA ne sait pas faire ca toute seule parce qu'elle ne distingue pas le signal du bruit dans ses propres sorties.

**2. Routeur de contexte** — "Documente ton comportement" redirige toute la masse de contexte accumulee (y compris les erreurs) vers une production utile. L'echec devient matiere premiere. Sans cette intervention, les 32 appels de debug seraient du pur gaspillage. Avec, ils deviennent un post-mortem documentable.

**3. Compresseur** — "Quelles etaient mes instructions ?" force l'IA a re-extraire l'essentiel du contexte au lieu de continuer sur sa lancee. C'est une compression manuelle : on passe de "tout ce qui s'est passe" a "ce qui compte". L'IA repond en 3 phrases au lieu de continuer a produire du bruit.

### Regle empirique pour l'utilisateur

Le ratio optimal observe dans cette session :
- **1 intervention humaine de cadrage pour 5-8 actions IA** = productif
- **0 intervention pour 15+ actions IA** = derive probable
- **1 intervention pour 1-2 actions** = sous-utilisation de l'IA

Le cout marginal d'un mot humain est quasi nul. Le cout marginal d'un appel outil IA est ~0.10-0.20 EUR (Opus, contexte long). L'intervention humaine est toujours rentable tant qu'elle redirige au moins 2-3 appels IA.

---

## Synthese pour le PowerPoint

### Slide suggeree : "Quand l'IA tourne en rond"

**Situation** : L'outil IA doit connecter un emulateur 3270 a un proxy pour tester les touches d'un ecran mainframe.

**Ce qui se passe** :
- L'IA tente 32 fois de lancer x3270 GUI en variant les parametres
- Cout : ~5 EUR, ~20 min perdues
- L'IA finit par demander a l'humain de le faire

**Le pivot** :
- L'utilisateur demande : "Quelles etaient mes instructions ?"
- L'IA realise l'erreur et ecrit un script headless en 3 minutes — qui marche du premier coup

**La lecon** :
- L'automatisation (IA ou script) excelle sur les chemins previsibles
- Les blocages systeme (ports, process, GUI) sont des pieges a boucle
- **L'operateur humain cree de la valeur en coupant les boucles, pas en executant les taches**
- Cout d'une interruption a temps : 0 EUR. Cout de la non-interruption : 5 EUR + 20 min

---

## La derive du prompt initial

### Le probleme

Le CLAUDE.md (prompt systeme du projet) et la MEMORY.md (memoire persistante) sont des snapshots figes. A chaque session qui modifie le code, ils derivent de la realite. En fin de session 03-05 :

| Element | CLAUDE.md disait | Realite |
|---|---|---|
| libGr0gu3270.py | ~2000 lignes | ~2700 lignes |
| web.py | **non mentionne** | ~2200 lignes, 36 endpoints |
| Tests | 14 tests, PR1-PR4 | 124 tests, PR1-PR5 + web + AID scan |
| Tables DB | 6 tables | 7 tables (+ AidScan) |
| Features | PR1-PR4 | PR1-PR5 + SPOOL/RCE + Single Scan |
| Findings | non mentionne | F-0001 a F-0009 |

**web.py — un fichier de 2200 lignes — n'existait pas dans le prompt.** L'IA travaillait sur un fichier invisible a sa propre documentation.

### Pourquoi c'est grave

Le CLAUDE.md est lu par l'IA au debut de chaque session. Si le prompt dit "6 tables" alors qu'il y en a 7, l'IA peut :
- Creer une table en doublon
- Ecrire des tests qui couvrent 6/7 tables
- Sous-estimer la complexite d'un refactoring

C'est l'equivalent d'un developpeur qui code en regardant une spec de v1 alors que le produit est en v3. Chaque decision est prise sur un etat fantome.

### L'analogie juridique

Un avocat qui plaide en citant un article de loi abroge. Le texte a change, mais son dossier de reference est reste a l'ancienne version. Sa plaidoirie est internement coherente mais deconnectee du droit applicable. Plus le temps passe sans mise a jour, plus l'ecart se creuse, plus les decisions sont fausses.

### La solution appliquee

1. **CLAUDE.md mis a jour** avec les vrais chiffres + ajout section "Conduite de session" + ajout section "Maintenance de ce fichier"
2. **MEMORY.md mis a jour** avec l'etat reel
3. **Regle ajoutee** : "Ce fichier DOIT refleter l'etat reel du code. Apres chaque session qui modifie l'architecture, mettre a jour."

### La question de fond

Le prompt initial est un **contrat** entre l'utilisateur et l'IA. Comme tout contrat, il doit etre maintenu. La question n'est pas "est-ce que le prompt est bon au depart" — c'est "est-ce qu'il est encore vrai 5 sessions plus tard". La reponse, ici, etait non.
