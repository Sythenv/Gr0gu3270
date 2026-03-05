# Roadmap Recherche — hack3270 / Pentest CICS

> Document de reference : `research/00-PROMPT-FONDATEUR.md`

## Phase 1 : Fondations (en cours)
- [x] PR1 : Detection ABEND CICS
- [x] PR2 : Parsing Screen Map BMS
- [x] PR3 : Correlation Transaction-Reponse
- [x] PR4 : Audit Securite RACF/ACF2/TSS
- [x] Infrastructure journal de recherche
- [x] Contraintes de securite et gouvernance agents
- [x] Presentation PDF 15 slides multi-audience
- [x] Framework CLAUDE-TEMPLATE.md reutilisable + init-research.sh
- [ ] **PROCHAIN** : Test session DVCA — valider PR1-PR4 en conditions reelles
- [ ] Validation des 4 features en conditions reelles

## Phase 2 : Enrichissement (planifie)
- [ ] Comparaison multi-profils automatisee (diff audit normal vs admin)
- [ ] Fingerprinting ESM automatique (RACF vs ACF2 vs TSS)
- [ ] Replay de sessions depuis SQLite (mode offline enrichi)
- [ ] Export rapport pentest structure (HTML/PDF)

## Phase 3 : Automatisation avancee (exploratoire)
- [ ] Fuzzing cible : PR2 identifie les champs → injection auto par champ
- [ ] Chaining : PR4 trouve transactions accessibles → PR2 cartographie → injection
- [ ] Detection de patterns applicatifs (ecran login, menu, erreur)
- [ ] Scripting Python pour scenarios de pentest reproductibles

## Phase 4 : Contribution communautaire (vision)
- [ ] Documentation etat de l'art pentest CICS
- [ ] Nouvelles wordlists basees sur les findings
- [ ] Integration avec d'autres outils mainframe (tn3270-python, zOS tools)
