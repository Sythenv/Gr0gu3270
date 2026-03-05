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
2. **Demontrer l'impact des coding agents** (Claude Code) sur le quotidien des professionnels cyber, direction et juridique

### Document fondateur

Le fichier `research/00-PROMPT-FONDATEUR.md` contient le prompt initial qui a lance le projet. C'est la **reference commune** : tout nouveau participant au projet doit le lire en premier.

### Contraintes de securite — analogies par public

- **DG/DGA** : c'est la politique de securite du projet. Comme une charte informatique, elle s'applique a tous, y compris aux agents automatises.
- **Cyber** : c'est le scope d'un pentest. On ne sort JAMAIS du perimetre autorise. La machine WSL locale = le lab isole.
- **Juridique offensif** : ces contraintes documentent le cadre d'execution. Ce fichier prouve que les mesures de confinement etaient definies et appliquees.
- **Juridique defensif** : controle technique garantissant qu'aucune donnee de production n'est exposee. Conforme au principe de minimisation (RGPD art. 5.1.c).
