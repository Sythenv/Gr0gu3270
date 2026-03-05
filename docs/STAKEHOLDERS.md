# Grille d'analogies multi-public — hack3270

Ce document traduit les concepts techniques de hack3270 pour chaque public cible du projet.

## Public cible et analogies metier

| Public | Ce qu'ils connaissent | Analogie hack3270 |
|--------|----------------------|---------------------|
| **DG / DGA** | Risque business, conformite, ROI | hack3270 = audit de controle interne automatise. Chaque transaction CICS testee = un controle verifie. Le rapport d'audit = matrice de risques. Un ABEND detecte = un incident potentiel quantifiable. |
| **Ingenieur Cyber** | Burp Suite, Nmap, OWASP, CVE | hack3270 = Burp Suite pour mainframe. ABEND detection = crash monitor. Screen Map = DevTools. Security Audit = scanner de vulns. Transaction correlation = historique HTTP. |
| **Juridique offensif** (pentest legal) | Cadre d'autorisation, scope, preuves | Chaque action est journalisee en SQLite avec horodatage = tracabilite complete. Le mode audit genere des preuves reproductibles. L'export CSV = piece justificative pour le rapport de mission. |
| **Juridique defensif** (conformite, RSSI) | Normes (ISO 27001, PCI-DSS), controles, remediation | L'audit PR4 = controle d'acces conforme au principe du moindre privilege. Un finding ACCESSIBLE sur une transaction sensible = non-conformite documentee. Le diff multi-profils = preuve de segregation des droits. |

## Exemples d'analogies en situation

> "La detection d'ABEND ASRA apres injection, c'est comme :
> - **DG** : decouvrir qu'un controle interne critique ne fonctionne pas — le programme accepte des donnees qu'il devrait rejeter
> - **Cyber** : un segfault apres fuzzing — le binaire ne valide pas ses inputs, c'est une vuln confirmee
> - **Juridique offensif** : une preuve technique que la transaction est vulnerable, horodatee et reproductible
> - **Juridique defensif** : une non-conformite au controle A.14.2.5 (ISO 27001) — test de securite des applications"

## Contexte du projet de recherche

Ce repository sert un **double objectif** :

1. **Faire evoluer hack3270** en outil d'audit CICS complet (pentest mainframe)
2. **Demontrer l'impact des coding agents** (coding agent) sur le quotidien des professionnels cyber, direction et juridique

### Document fondateur

Le fichier `research/00-PROMPT-FONDATEUR.md` contient le prompt initial qui a lance le projet. C'est la **reference commune** : tout nouveau participant au projet doit le lire en premier.

### Contraintes de securite — analogies par public

- **DG/DGA** : c'est la politique de securite du projet. Comme une charte informatique, elle s'applique a tous, y compris aux agents automatises.
- **Cyber** : c'est le scope d'un pentest. On ne sort JAMAIS du perimetre autorise. La machine WSL locale = le lab isole.
- **Juridique offensif** : ces contraintes documentent le cadre d'execution. Ce fichier prouve que les mesures de confinement etaient definies et appliquees.
- **Juridique defensif** : controle technique garantissant qu'aucune donnee de production n'est exposee. Conforme au principe de minimisation (RGPD art. 5.1.c).

---

## Analogie du projet complet — session 03-04 / 03-05

### DG / DGA

Imaginez que vous confiez un audit de controle interne a un cabinet. En deux jours, le cabinet deploie un outil qui teste automatiquement les 186 portes de votre batiment et decouvre que chacune est ouverte. Il trouve une porte cachee ("option 99") que personne ne connaissait. Il identifie un coffre-fort dont la serrure peut etre crochetee a distance. Tout est documente, horodate, reproductible. Ensuite, vous lui demandez de tester toutes les poignees de chaque piece. L'outil le fait — mais sur une porte, il tourne la poignee et declenche l'alarme incendie, ce qui verrouille tout le batiment. La, l'auditeur humain doit reprendre la main. Pendant ce temps, l'outil a perdu 20 minutes et 5 euros a essayer d'ouvrir une fenetre au lieu de passer par la porte de service. Lecon : l'outil automatise multiplie la capacite de l'auditeur par 10 — mais c'est l'auditeur qui sait quand debrancher l'outil pour eviter de gaspiller du budget.

### Ingenieur Cyber

On a pris hack3270 (le Burp Suite du mainframe), ajoute un crash monitor (ABEND detection), un DevTools (Screen Map), un scanner de vulns (Security Audit) et un fuzzer de touches AID — le tout en ~2500 LOC Python, zero dependance, 124 tests. En 2 jours. Sur DVCA, ca trouve 4/7 vulns NetSPI automatiquement, plus un RCE theorique via SPOOL/INTRDR. L'AID scan teste 28 touches et revient a l'ecran tout seul — sauf quand PF3 fait un LOGOFF CICS qui tue la session. C'est exactement comme un Burp Intruder qui replay un token CSRF expire : l'automatisation marche tant que l'etat de session tient, apres c'est a toi de re-authentifier et relancer. Cote agent IA : Claude a code tout ca proprement, mais quand il a fallu connecter x3270 a un proxy, il a brute-force 32 fois une approche cassee au lieu d'ecrire un client raw socket en 3 minutes. La regle des 3 : si ton outil echoue 3 fois pareil, tu changes d'approche — ca vaut pour l'IA comme pour un scanner de vuln.

### Consultant en droit

Vous faites le meme metier que nous, mais sur un code different. Nous auditons du code informatique, vous auditez du code juridique. Quand un avocat en attaque cherche les failles dans un contrat, il fait exactement ce que notre outil fait sur un ecran mainframe : il teste systematiquement chaque clause (nos 28 touches PF), identifie celles qui menent quelque part d'exploitable (NEW_SCREEN), celles qui sont sans effet (SAME_SCREEN), et celles qui declenchent un refus explicite (VIOLATION). L'AID scan, c'est votre lecture article par article d'un texte de loi en cherchant l'angle. L'avocat en defense fait le chemin inverse : il part du resultat (le finding, la mise en cause) et remonte le chemin de navigation pour verifier que chaque etape est juridiquement solide — c'est notre replay path. Et la lecon de la session est la meme des deux cotes : l'IA peut passer en revue 186 articles en quelques secondes et trier le bruit (les 180 qui ne menent nulle part) pour que le juriste se concentre sur les 6 qui comptent. Mais quand elle tombe sur un article qui change le cadre de la procedure (notre PF3 qui tue la session — votre exception d'incompetence qui renvoie devant une autre juridiction), elle ne sait pas quoi faire. Elle continue de plaider devant un tribunal qui n'est plus le bon. C'est la que le juriste cree sa valeur : pas en lisant les 186 articles, mais en reconnaissant le moment ou le terrain change sous ses pieds.

### Consultant d'analyse (Word / Excel / PowerPoint)

Votre quotidien, c'est transformer de la donnee brute en livrable client. Vous recevez des extractions, des logs, des resultats d'entretien, et vous les transformez en tableaux Excel structures, en documents Word argumentes, en presentations PowerPoint qui racontent une histoire. Nous, on fait exactement la meme chose : on recoit des flux d'octets EBCDIC bruts d'un mainframe, et on les transforme en findings numerotes, en matrices de risques, en exports CSV, en rapports exploitables. Notre FINDINGS.md, c'est votre livrable Word — chaque finding a un titre, une severite, des etapes de reproduction, un impact, une remediation. Notre AID scan qui produit un tableau VIOLATION/NEW_SCREEN/SAME_SCREEN trie par criticite, c'est votre tableau croise dynamique qui fait remonter les ecarts significatifs en haut. Et notre post-mortem de session — ou l'IA a gaspille 5 euros a tourner en rond — c'est exactement le probleme que vous connaissez quand vous passez 2 heures a reformater un tableau Excel au lieu de faire un copier-coller intelligent depuis la source. La lecon est la meme : l'outil (IA, macro VBA, ou template PowerPoint) accelere la production de 80% du livrable. Les 20% restants — la mise en perspective, le choix de ce qu'on montre et ce qu'on cache, la narration qui transforme des donnees en decision — c'est votre expertise. Personne ne paie un consultant pour copier-coller des cellules. On vous paie pour savoir quelle cellule montrer au comite de direction.

---

## Usages de coding agent par profil — ce que chacun peut en faire

### Le point commun

coding agent n'est pas un outil technique reserve aux developpeurs. C'est un **agent de production** qui lit, ecrit, execute, et rend compte. Il prend une instruction en langage naturel et produit un livrable structure. Ce que ce projet demontre, c'est que la boucle instruction → production → correction → livraison est la meme quel que soit le metier. Seul le materiau change.

### DG / DGA — Piloter par l'instruction

Vous ne coderez pas. Mais vous pouvez piloter un agent qui code, audite, et restitue. Ce projet a ete conduit avec ~50 mots d'instructions humaines par session. Le ROI est mesurable : 6200 lignes de code, 124 tests, 9 findings documentes, produits en 2 jours de supervision episodique. L'usage concret : donner une direction strategique ("je veux savoir si nos mainframes sont securises"), recevoir un rapport structure, et poser les bonnes questions de cadrage ("quelles etaient mes instructions ?") quand l'execution derive. Votre valeur : la decision de lancer, la decision d'arreter, la decision de pivoter. L'IA fait le reste.

### Ingenieur Cyber — Multiplier la capacite d'audit

Vous codez deja. coding agent vous fait coder 5 a 10 fois plus vite sur les parties mecaniques (parsing de protocole, endpoints API, tests unitaires) et vous libere du temps pour ce que l'IA ne fait pas : l'intuition de l'attaquant, le choix du vecteur, la creativite dans l'exploitation. L'usage concret : "implemente un scanner de touches AID avec auto-replay" → 300 lignes de code + 29 tests en 20 minutes. Vous gardez la main sur la strategie de test, l'interpretation des resultats, et le moment ou il faut arreter l'automatisation pour investiguer manuellement.

### Consultant en droit — Accelerer la recherche, structurer l'analyse

Vous passez du temps a lire des textes, identifier les articles pertinents, structurer des argumentaires. coding agent peut ingerer un corpus (loi, contrat, jurisprudence), le scanner systematiquement, et produire un premier tri : articles pertinents vs articles sans impact, contradictions entre clauses, references croisees. Votre valeur : l'interpretation. L'IA ne sait pas si un argument est strategiquement opportun — elle sait juste s'il existe dans le texte. Comme notre AID scan qui trouve que PF3 mene "quelque part" mais ne sait pas que ce "quelque part" est un piege.

### Consultant d'analyse — Industrialiser la production de livrables

Vous passez 60% de votre temps sur le formatage et 40% sur l'analyse. coding agent inverse ce ratio. L'usage concret : vous lui donnez vos donnees brutes (CSV, extractions, notes d'entretien) et une instruction ("fais-moi un tableau de synthese avec les ecarts classes par impact, et un executive summary de 5 lignes"). Il produit le brouillon. Vous corrigez, affinez, mettez en perspective. Deux mises en garde de ce projet : (1) surveillez la derive — si l'IA reformate en boucle sans avancer, coupez et reformulez. Chaque minute d'IA qui tourne en rond est une minute de budget client. (2) Maintenez vos templates a jour — un template obsolete (notre CLAUDE.md perime) produit des livrables bases sur un etat qui n'existe plus, exactement comme un modele de rapport annuel de l'an dernier avec les mauvais intitules de BU.

### La regle universelle

Quel que soit le metier, la dynamique est la meme :

```
HUMAIN : direction + cadrage + coupe + interpretation
IA     : volume + vitesse + structure + exhaustivite
```

L'humain qui essaie de faire le travail de l'IA (lire 186 articles, tester 28 touches, reformater 500 lignes) gaspille son expertise. L'IA qui essaie de faire le travail de l'humain (decider quand pivoter, choisir ce qui compte, raconter l'histoire) gaspille des tokens.

**L'operateur cree de la valeur en coupant les boucles, pas en executant les taches.**

---

## Risques, configuration et bonnes pratiques en production

### Les 7 risques identifies

#### 1. Fuite de donnees — le risque numero un

Le coding agent lit, ecrit et execute. Il a acces au filesystem, aux variables d'environnement, aux fichiers de configuration. En contexte professionnel :

- Il peut lire un `.env` contenant des secrets et les inclure dans un commit
- Il peut afficher des donnees de production dans ses sorties de debug
- Il peut envoyer du contexte a une API externe (selon le provider)

**Mesure** : definir un perimetre de fichiers autorises. Exclure explicitement les repertoires sensibles (`.ssh`, `.aws`, configs prod). Utiliser un compte systeme dedie avec des droits restreints. Verifier chaque commit avant push.

**Analogie DG** : c'est un stagiaire brillant mais sans clearance. Il ne faut pas le laisser seul dans la salle des coffres.

#### 2. Execution non controlee — le blast radius

L'agent execute des commandes shell. Un `rm -rf` mal place, un `DROP TABLE`, un `git push --force` sur main — les degats sont immediats et parfois irreversibles.

**Mesure** : activer le mode confirmation pour les commandes destructrices. Configurer les permissions de l'agent (read-only par defaut, write sur demande). Ne jamais donner un acces admin a l'agent en production.

**Analogie Cyber** : c'est la difference entre un pentest en read-only (recon) et un pentest avec exploitation. Le scope doit etre defini avant, pas pendant.

#### 3. Derive du prompt (prompt drift) — l'erosion silencieuse

Le fichier d'instructions (CLAUDE.md) est un snapshot. A chaque session qui modifie le code, l'ecart se creuse. Apres 5 sessions, l'agent travaille sur un etat fantome. Ce projet l'a demontre : web.py (2200 lignes) n'existait pas dans le prompt alors que l'agent travaillait dessus.

**Mesure** : mettre a jour le fichier d'instructions apres chaque session qui modifie l'architecture. Inclure une regle de maintenance dans le prompt lui-meme. Versionner le prompt avec le code.

**Analogie Juridique** : un avocat qui plaide en citant un article abroge. Internement coherent, mais deconnecte du droit applicable.

#### 4. Cout non maitrise — la boucle a 5 euros

Le cout marginal d'un appel outil est invisible pour l'operateur (~0.10-0.20 EUR en contexte long). Une boucle de debug de 30 appels = 3-5 EUR de gaspillage pur. Ce projet a documente une boucle a 4.70 EUR pour un resultat obtenu en 3 minutes par la bonne approche.

**Mesure** : appliquer la regle des 3 (3 echecs = changement d'approche). Surveiller les patterns `kill → restart → echec → kill`. Definir un budget par session. Interrompre les boucles tot.

**Analogie Consultant** : c'est un consultant au forfait qui passerait 2h a reformater un tableau Excel au lieu de 5 minutes a le copier-coller depuis la source. Le client paie la boucle.

#### 5. Pollution du contexte — le bruit qui noie le signal

Le contexte est une ressource finie. Chaque sortie d'erreur, chaque debug inutile reste dans la fenetre et pese sur tous les appels suivants. Un contexte de 100K tokens bien conduit produit plus qu'un contexte de 200K tokens pollue.

**Mesure** : interventions courtes et dirigees ("Stop", "Change d'approche", "Quelles etaient mes instructions ?"). Ratio optimal observe : 1 intervention humaine pour 5-8 actions IA.

**Analogie Juridique** : un dossier de plaidoirie ou chaque brouillon rate est photocopie et ajoute au dossier. Le volume augmente, la valeur non.

#### 6. Sur-ingenierie — la complexite inutile

L'agent a tendance a ajouter de l'abstraction, des fallbacks, de la configurabilite la ou une solution simple suffit. Il peut transformer 3 lignes en un pattern factory avec interface et injection de dependances.

**Mesure** : demander explicitement la solution la plus simple. Preferer "3 lignes dupliquees" a "1 abstraction prematuree". Reviewer chaque ajout : est-ce que ca repond a un besoin reel ou hypothetique ?

#### 7. Fausse confiance — le code qui a l'air correct

L'agent produit du code syntaxiquement correct, bien structure, avec des tests qui passent. Mais il peut introduire des vulnerabilites subtiles (injection, race condition, logique metier inversee) parce qu'il n'a pas le contexte business complet.

**Mesure** : review humain systematique du code genere. Ne jamais deployer sans relecture. Les tests de l'agent testent ce que l'agent a compris — pas necessairement ce que le metier attend.

**Analogie Cyber** : un rapport de scan automatise qui dit "0 vulnerabilites" ne signifie pas "systeme securise". Ca signifie "le scanner n'a rien trouve dans son scope".

---

### Configuration d'un projet en production

#### Le fichier d'instructions (CLAUDE.md)

C'est le **contrat operationnel** entre l'equipe et l'agent. Il doit contenir :

```
1. SECURITE (non negociable)
   - Perimetre d'execution (quels fichiers, quels repertoires)
   - Donnees interdites (secrets, PII, tokens)
   - Politique d'ambiguite (dans le doute = STOP)

2. ARCHITECTURE
   - Fichiers principaux et leurs roles
   - Conventions de nommage et de style
   - Schema de donnees
   - Flux de donnees

3. CONDUITE DE SESSION
   - Regle des 3 (3 echecs = pivot)
   - Interdiction des boucles kill/restart
   - Budget awareness

4. MAINTENANCE
   - Ce fichier DOIT etre mis a jour apres chaque changement d'architecture
   - Qui est responsable de la mise a jour
```

**Regle** : le CLAUDE.md se maintient comme du code. Il se versionne, se review, et se met a jour. Un CLAUDE.md obsolete est pire que pas de CLAUDE.md — il donne de fausses certitudes.

#### La memoire persistante (MEMORY.md)

C'est l'**etat operationnel** de l'agent entre les sessions. Elle doit rester concise (< 200 lignes) et factuelle :

- Metriques reelles (LOC, tests, tables, endpoints)
- Decisions d'architecture et leur justification
- Bugs connus et leur statut
- Preferences de l'equipe

**Anti-pattern** : y stocker des instructions de session, des TODO, ou des speculations. La memoire n'est pas un backlog.

#### Isolation de l'environnement

| Niveau | Configuration | Usage |
|--------|--------------|-------|
| **Dev local** | Agent avec acces filesystem complet, pas de secrets | Developpement quotidien |
| **CI/CD** | Agent en read-only, execution dans container ephemere | Review automatique, generation de tests |
| **Staging** | Agent interdit ou en mode audit (lecture seule) | Validation humaine uniquement |
| **Production** | Aucun agent. Jamais. | — |

L'agent ne doit **jamais** avoir acces a un environnement de production. Meme en lecture seule. Le risque de fuite de donnees est trop eleve et le benefice trop faible par rapport a un acces staging.

---

### Bonnes pratiques par profil

#### DG / DGA — Gouverner l'agent

1. **Definir le scope avant** : "audite ce perimetre, pas plus"
2. **Exiger un rapport structure** : l'agent doit produire un livrable, pas juste du code
3. **Poser les questions de cadrage** : "quelles etaient mes instructions ?" quand ca derive
4. **Fixer un budget** : nombre de sessions, cout max, temps max
5. **Ne pas deleguer la decision de deployer** : l'agent propose, l'humain dispose

#### Ingenieur Cyber — Superviser l'execution

1. **Regle des 3** : 3 echecs identiques = stop + pivot
2. **Separer recon et exploit** : l'agent fait le volume (scan 186 transactions), vous faites l'analyse
3. **Reviewer les payloads** : l'agent peut generer des payloads dangereux sans le savoir
4. **Maintenir le CLAUDE.md** : c'est votre scope document, il doit etre a jour
5. **Logger les sessions** : tracabilite complete pour le rapport de mission

#### Consultant en droit — Cadrer l'usage

1. **Tracabilite** : chaque action de l'agent doit etre journalisee et horodatee
2. **Perimetre contractuel** : definir dans le prompt ce que l'agent peut et ne peut pas faire = clauses du contrat
3. **Preuve de confinement** : le CLAUDE.md + les logs = preuve que les mesures de securite etaient definies et appliquees
4. **Responsabilite** : l'agent ne prend pas de decisions juridiques — il trie, il structure, le juriste interprete
5. **Confidentialite** : verifier que les donnees client ne transitent pas par des API tierces

#### Consultant d'analyse — Optimiser la production

1. **Templates a jour** : un template obsolete produit des livrables faux
2. **Couper les boucles de formatage** : si l'agent reformate en boucle, reformuler l'instruction
3. **Valider le brouillon avant de polir** : l'agent produit le fond, vous faites la forme
4. **Budget client** : chaque minute d'agent qui tourne en rond = budget client consomme
5. **Versionner les livrables** : ne pas ecraser le travail precedent sans backup

---

### Checklist de demarrage projet

```
[ ] CLAUDE.md cree avec sections SECURITE + ARCHITECTURE + CONDUITE
[ ] Repertoires sensibles exclus du scope agent
[ ] Pas de secrets dans les fichiers accessibles a l'agent
[ ] Environnement isole (VM, container, WSL)
[ ] Mode confirmation actif pour commandes destructrices
[ ] Budget session defini (temps et/ou cout)
[ ] Responsable maintenance CLAUDE.md designe
[ ] Convention de review : tout code genere est relu avant merge
[ ] Logs de session conserves pour tracabilite
[ ] Equipe informee : l'agent est un outil, pas un decisionnaire
```

### La regle finale

```
L'agent est un multiplicateur, pas un remplacant.
Il multiplie la competence de l'operateur — y compris son incompetence.
Un operateur qui ne sait pas quand couper une boucle paiera cher.
Un operateur qui sait cadrer, couper et interpreter ira 10x plus vite.
La valeur est dans le cadrage, pas dans l'execution.
```
