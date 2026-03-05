#!/bin/bash
# Initialise la structure de recherche dans le repertoire courant.
# Usage: bash init-research.sh [nom-du-projet]

PROJECT_NAME="${1:-mon-projet}"

echo "Initialisation structure recherche pour: $PROJECT_NAME"

# Copier le template CLAUDE.md
if [ ! -f "CLAUDE.md" ]; then
    cp "$(dirname "$0")/CLAUDE-TEMPLATE.md" CLAUDE.md
    echo "  [+] CLAUDE.md cree (adapter les sections [A ADAPTER])"
else
    echo "  [!] CLAUDE.md existe deja, pas ecrase"
fi

# Creer l'arborescence
mkdir -p research/knowledge research/sessions

# Journal
if [ ! -f "research/JOURNAL.md" ]; then
    cat > research/JOURNAL.md << EOF
# Journal de Recherche — $PROJECT_NAME

## Convention
YYYY-MM-DD HH:MM : [CATEG] Observation + fait

Categories : [TOOL] [DOMAIN] [SECU] [ARCHI] [REF] [EXP] [IDEA]

---

## $(date +%Y-%m-%d)

$(date +%Y-%m-%d) $(date +%H:%M) : [ARCHI] Initialisation du journal de recherche.
EOF
    echo "  [+] research/JOURNAL.md cree"
fi

# Findings
if [ ! -f "research/FINDINGS.md" ]; then
    cat > research/FINDINGS.md << 'EOF'
# Findings

## Convention
### F-XXXX : Titre
- **Date** : YYYY-MM-DD
- **Severite** : INFO | LOW | MEDIUM | HIGH | CRITICAL
- **Description** : ...
- **Reproduction** : ...
- **Impact** : ...

Compteur : F-0000
EOF
    echo "  [+] research/FINDINGS.md cree"
fi

# Roadmap
if [ ! -f "research/ROADMAP.md" ]; then
    cat > research/ROADMAP.md << EOF
# Roadmap — $PROJECT_NAME

> Document de reference : research/00-PROMPT-FONDATEUR.md

## Phase 1 : Cadrage
- [ ] Adapter CLAUDE.md
- [ ] Rediger le prompt fondateur
- [ ] Remplir la grille d'analogies

## Phase 2 : Execution
- [ ] ...

## Phase 3 : Livrables
- [ ] ...
EOF
    echo "  [+] research/ROADMAP.md cree"
fi

# Prompt fondateur (vide, a remplir)
if [ ! -f "research/00-PROMPT-FONDATEUR.md" ]; then
    cat > research/00-PROMPT-FONDATEUR.md << 'EOF'
# Prompt Fondateur — Base d'Analyse Commune

## Le prompt original

> [COLLER ICI le premier prompt soumis au coding agent]

## Analyse pour chaque public

### Direction
[A REMPLIR]

### Technique
[A REMPLIR]

### Juridique offensif
[A REMPLIR]

### Juridique defensif
[A REMPLIR]
EOF
    echo "  [+] research/00-PROMPT-FONDATEUR.md cree (a remplir)"
fi

touch research/sessions/.gitkeep

echo ""
echo "Structure creee. Prochaine etape :"
echo "  1. Adapter CLAUDE.md (sections [A ADAPTER])"
echo "  2. Rediger research/00-PROMPT-FONDATEUR.md"
echo "  3. Lancer le coding agent"
