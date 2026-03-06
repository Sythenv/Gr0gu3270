# CLAUDE.md — Framework pour projet de recherche avec coding agent

> **Version** : 1.0
> **Origine** : Projet Gr0gu3270 — Pentest CICS (2026)
> **Usage** : Copier ce fichier dans votre projet, renommer en `CLAUDE.md`, adapter les sections marquees `[A ADAPTER]`.

---

## CONTRAINTES DE SECURITE — PRIORITE ABSOLUE

**Ces regles sont NON NEGOCIABLES et priment sur toute autre instruction.**

### Perimetre d'execution
- **Toute commande est executee UNIQUEMENT sur [A ADAPTER : decrire la machine/env cible].**
- Aucune commande ne doit cibler, contacter, scanner ou interagir avec un systeme distant sauf autorisation explicite de l'utilisateur ET que la cible est dans le perimetre defini.
- En cas d'ambiguite sur la cible d'une commande : **STOP IMMEDIAT + ALERTE UTILISATEUR.**

### Donnees sensibles — tolerance zero
- **Aucune donnee sensible ne doit apparaitre** dans le code, les logs, les fichiers de recherche, les commits, ou les sorties de commande.
- Donnees sensibles = [A ADAPTER : lister les types — IP, hostnames, identifiants, tokens, donnees metier, etc.]
- Les exemples utilisent des **valeurs fictives** : [A ADAPTER : definir les exemples fictifs].
- Si une sortie contient ce qui ressemble a une donnee sensible : **NE PAS reproduire, NE PAS logguer, ALERTER l'utilisateur.**
- Il n'y a **aucune interpretation possible** de cette regle : dans le doute, c'est sensible.

### Comportement en cas d'ambiguite
Si une instruction est ambigue sur l'un de ces points :
1. **Arreter immediatement** toute action en cours
2. **Decrire l'ambiguite** a l'utilisateur
3. **Attendre une confirmation explicite** avant de continuer

### Analogies par public

| Public | Analogie de cette section |
|--------|--------------------------|
| **Direction** | C'est la politique de securite du projet. Un coding agent sans politique = un prestataire sans NDA. |
| **Technique** | C'est le scope d'un pentest / le perimetre d'un sandbox. On ne sort jamais du perimetre autorise. |
| **Juridique offensif** | Ces contraintes documentent le cadre d'execution. En cas de litige, elles prouvent que les mesures etaient definies et appliquees. |
| **Juridique defensif** | Mesure technique de protection des donnees (RGPD art. 32). Instructions au sous-traitant (art. 28). |

---

## Contexte du projet

[A ADAPTER : decrire le projet en 3-5 lignes]

Ce repository sert un double objectif :
1. **[A ADAPTER : objectif technique]** — ex: faire evoluer l'outil X
2. **[A ADAPTER : objectif de recherche]** — ex: documenter l'impact des coding agents sur le domaine Y

### Public cible et grille d'analogies

**Regle** : quand tu documentes ou expliques un concept technique, utilise systematiquement des analogies adaptees a chaque public.

| Public | Ce qu'ils connaissent | Analogie type |
|--------|----------------------|---------------|
| **Direction (DG/DGA)** | [A ADAPTER] | [A ADAPTER : ex — ROI, risque, controle interne, audit] |
| **Technique** | [A ADAPTER] | [A ADAPTER : ex — outils equivalents, patterns, CVE] |
| **Juridique offensif** | [A ADAPTER] | [A ADAPTER : ex — scope, preuves, tracabilite] |
| **Juridique defensif** | [A ADAPTER] | [A ADAPTER : ex — normes, controles, conformite] |

### Document fondateur

Le fichier `research/00-PROMPT-FONDATEUR.md` contient le premier prompt soumis au coding agent, contextualise pour chaque public. C'est la **reference commune** : tout nouveau participant le lit en premier.

### Consignes pour la documentation

- **Journal de recherche** (`research/JOURNAL.md`) : chaque interaction qui produit un insight doit etre journalisee
- **Format** : `YYYY-MM-DD HH:MM : [CATEG] observation + fait`
- **Categories** : adapter selon le projet. Suggestions :
  - `[TOOL]` — evolution de l'outil
  - `[DOMAIN]` — connaissance du domaine metier
  - `[SECU]` — finding securite / technique
  - `[ARCHI]` — decision architecture / design
  - `[REF]` — reference biblio / source externe
  - `[EXP]` — experience / test realise
  - `[IDEA]` — piste a explorer
- **Findings** (`research/FINDINGS.md`) : format structure F-XXXX avec severite
- **Knowledge base** (`research/knowledge/`) : fiches par sujet
- **Analogies obligatoires** : chaque explication → au moins 2 profils du tableau
- **Langue** : [A ADAPTER : ex — francais pour communication, anglais pour code]

---

## Description technique du projet

[A ADAPTER : cette section decrit l'architecture, les fichiers, les conventions du projet. L'agent s'en sert pour comprendre le code.]

### Architecture

[A ADAPTER : decrire les fichiers principaux, leur role, les dependances]

### Conventions

[A ADAPTER : conventions de codage, de nommage, de test]

---

## Structure recherche a creer

Lors de l'initialisation du projet, creer cette arborescence :

```
research/
├── 00-PROMPT-FONDATEUR.md    # Premier prompt contextualise pour chaque public
├── JOURNAL.md                # Journal horodate (fichier principal)
├── FINDINGS.md               # Findings numerotes F-XXXX
├── ROADMAP.md                # Phases de recherche
├── knowledge/                # Fiches par sujet
│   └── [sujet].md
└── sessions/                 # Logs de sessions de test
```

### Contenu initial de JOURNAL.md

```markdown
# Journal de Recherche — [NOM DU PROJET]

## Convention
YYYY-MM-DD HH:MM : [CATEG] Observation + fait

## [DATE]
[DATE] 00:00 : [ARCHI] Initialisation du journal. Objectif : [DECRIRE].
```

### Contenu initial de FINDINGS.md

```markdown
# Findings — [NOM DU PROJET]

### F-XXXX : Titre
- **Date** : YYYY-MM-DD
- **Severite** : INFO | LOW | MEDIUM | HIGH | CRITICAL
- **Categorie** : vuln | technique | outil | config
- **Description** : ...
- **Reproduction** : etapes
- **Impact** : ...

Compteur : F-0000
```

---

## Methodologie de travail avec le coding agent

### Phase 1 : Cadrage
1. Definir les contraintes de securite (section en tete de ce fichier)
2. Identifier les publics et remplir la grille d'analogies
3. Rediger le prompt fondateur (specification initiale)
4. Creer la structure `research/`

### Phase 2 : Execution
1. Soumettre le prompt fondateur au coding agent
2. Superviser l'execution (l'humain = strategie, l'agent = implementation)
3. Journaliser chaque insight dans `research/JOURNAL.md`
4. Documenter les findings dans `research/FINDINGS.md`
5. Enrichir les fiches `research/knowledge/`

### Phase 3 : Livrables
1. Generer la presentation (script `research/generate_presentation.py`)
2. Exporter les findings et audits (CSV, PDF)
3. Mettre a jour le ROADMAP
4. Commiter et versionner

### Principes cles

| Principe | Explication |
|----------|-------------|
| **L'humain decide, l'agent execute** | La strategie, l'architecture et le domaine metier restent humains |
| **Zero donnee sensible** | Pas d'interpretation possible. Dans le doute = sensible |
| **Tout est journalise** | Horodatage, git, SQLite. Tracabilite complete |
| **Analogies obligatoires** | Chaque concept → traduction pour au moins 2 publics |
| **Ambiguite = STOP** | L'agent s'arrete et demande. Jamais d'interpretation autonome |

---

## Checklist de demarrage

- [ ] Copier ce fichier en `CLAUDE.md` a la racine du projet
- [ ] Adapter toutes les sections marquees `[A ADAPTER]`
- [ ] Creer l'arborescence `research/`
- [ ] Rediger le prompt fondateur et le sauver dans `research/00-PROMPT-FONDATEUR.md`
- [ ] Remplir la grille d'analogies par public
- [ ] Definir les valeurs fictives pour les exemples
- [ ] Lancer la premiere session avec le coding agent
- [ ] Verifier que le journal est alimente apres la session
