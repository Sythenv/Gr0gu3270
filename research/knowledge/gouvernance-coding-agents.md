# Gouvernance des Coding Agents — Securite et Conformite

## Problematique nouvelle

Un coding agent (Claude Code, Copilot, Cursor, etc.) execute du code avec les
privileges de l'utilisateur. Il a acces au terminal, au reseau, au systeme de
fichiers, a git. C'est fonctionnellement equivalent a un **developpeur junior
avec acces root** qui execute les instructions qu'on lui donne.

Les controles de securite traditionnels (charte informatique, PSSI, controle d'acces)
couvrent les humains et les systemes. Ils ne couvrent pas encore les agents IA autonomes.

## Mecanisme de controle : le fichier CLAUDE.md

Dans ce projet, le `CLAUDE.md` sert de **politique de securite lisible par la machine** :

| Controle traditionnel | Equivalent CLAUDE.md |
|-----------------------|----------------------|
| Charte informatique | Section "Contraintes de securite" |
| Perimetre reseau autorise | "Execution UNIQUEMENT sur cette machine WSL locale" |
| Classification des donnees | "Aucune donnee sensible — pas d'interpretation possible" |
| Procedure d'incident | "En cas d'ambiguite : STOP + ALERTE" |
| Principe de moindre privilege | L'agent ne fait que ce qui est specifie |
| Tracabilite | Journal de recherche horodate, git history |

## Risques specifiques aux coding agents

| Risque | Description | Controle applique |
|--------|-------------|-------------------|
| Exfiltration | L'agent pourrait envoyer des donnees via curl, git push, API | Perimetre local strict |
| Injection de prompt | Un fichier malveillant lu par l'agent modifie son comportement | Vigilance sur les contenus lus |
| Execution hors scope | L'agent lance un scan reseau au lieu d'editer un fichier | Stop + alerte sur ambiguite |
| Donnees en clair | L'agent ecrit une IP reelle dans un fichier commite | Zero donnee sensible, pas d'interpretation |
| Persistance non voulue | L'agent modifie des fichiers systeme | Confinement WSL |

## Analogies par public

- **DG** : un coding agent sans politique de securite, c'est comme embaucher un prestataire
  sans NDA ni clause de confidentialite. Il fait le travail, mais rien ne garantit qu'il
  ne diffuse pas les donnees. Le CLAUDE.md est le NDA de l'agent.

- **Cyber** : c'est le principe du sandbox. L'agent tourne dans un perimetre controle (WSL),
  avec des regles de sortie explicites (aucune connexion externe sans autorisation).
  Comme un malware analysis lab — on ne branche pas le lab sur le reseau de prod.

- **Juridique offensif** : le CLAUDE.md documente les mesures de confinement avant
  l'execution de tout test. En cas de litige, il prouve que le cadre etait defini,
  communique, et applique — y compris a l'agent automatise.

- **Juridique defensif** : c'est une mesure technique de protection des donnees (RGPD art. 32).
  L'agent est un sous-traitant au sens du traitement — les instructions documentees dans
  CLAUDE.md sont l'equivalent d'une clause de sous-traitance art. 28.

## Etat de l'art (2026)

A ce jour, il n'existe pas de standard formel pour la gouvernance des coding agents.
Ce projet documente une approche pragmatique :
1. Politique de securite dans un fichier lu automatiquement par l'agent (CLAUDE.md)
2. Contraintes non negociables en tete de fichier (priorite absolue)
3. Comportement prescrit en cas d'ambiguite (stop + alerte, pas d'interpretation)
4. Tracabilite complete (journal horodate, git, SQLite)
5. Analogies multi-profils pour que chaque partie prenante comprenne les enjeux
