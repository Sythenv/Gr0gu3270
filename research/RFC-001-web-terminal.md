# RFC-001 : Terminal 3270 integre dans la Web UI

## Contexte
Actuellement Gr0gu3270 necessite un emulateur TN3270 externe (x3270) pour interagir avec le mainframe. La Web UI affiche les outils d'audit mais pas l'ecran 3270 lui-meme. L'utilisateur doit jongler entre deux fenetres.

## Proposition
Ajouter un onglet "Terminal" dans la Web UI qui rend l'ecran 3270 directement dans le navigateur. Le proxy Gr0gu3270 devient a la fois l'outil d'audit ET l'emulateur.

## Avantages
- **Un seul outil, un seul ecran** : plus besoin de x3270, tout dans le navigateur
- **Zero dependance supplementaire** : x3270/WSLg plus necessaire, fonctionne sur n'importe quel OS avec un navigateur
- **Workflow simplifie** : double-clic → navigateur → terminal + outils
- **Visibilite unifiee** : voir le terminal et les resultats d'audit cote a cote
- **Portabilite** : fonctionne depuis n'importe quelle machine sur le reseau (pas seulement localhost)
- **Deja la moitie du travail fait** : parse_screen_map() decode les champs, get_ascii() convertit EBCDIC, les donnees serveur passent deja par le proxy

## Inconvenients
- **Complexite du rendu 3270** : le protocole 3270 est field-based, pas character-based. Il faut gerer les attributs de champ (protected, hidden, numeric, intensity), le positionnement curseur (SBA), les ordres (SF/SFE/MF/RA/EUA), les couleurs extended. C'est un mini-emulateur complet.
- **Gestion clavier** : mapper le clavier web vers les AID keys (Enter, PF1-24, PA1-3, Clear, Tab entre champs). Intercepter les touches sans conflit avec le navigateur.
- **Negotiation telnet** : actuellement c'est x3270 qui negocie le handshake TN3270/TN3270E avec le serveur. Sans x3270, Gr0gu3270 devra gerer la negotiation telnet lui-meme (terminal-type, binary mode, EOR).
- **Pas de client_connect()** : plus de socket client a accepter — le proxy doit se connecter directement au serveur et gerer le I/O serveur sans emulateur intermediaire.
- **Saisie dans les champs** : gerer l'edition dans les champs input (insert/delete, curseur, tab entre champs, validation numeric-only, troncature). Simuler le comportement d'un vrai terminal 3270.
- **Fiabilite vs x3270** : x3270 est un emulateur mature de 30 ans. Un rendu maison sera forcement moins robuste au debut (edge cases, ecrans complexes, 3270E extended attributes).
- **Effort estimé** : ~1-2 sessions completes (rendu ecran + gestion clavier + negotiation telnet + tests)

## Architecture proposee

```
Navigateur (Terminal JS)
    |  WebSocket ou polling
    v
web.py (nouveau endpoint /api/screen + /api/input)
    |
    v
libGr0gu3270.py (buffer ecran 80x24 + envoi donnees serveur)
    |  socket direct
    v
Mainframe (DVCA)
```

### Changements necessaires
1. **libGr0gu3270.py** : maintenir un buffer ecran 80x24 caracteres + attributs, mis a jour par parse_screen_map(). Ajouter methode pour construire les paquets client (AID + cursor + field data).
2. **web.py** : endpoint GET /api/screen (retourne grille 80x24 + attributs + position curseur), endpoint POST /api/input (recoit texte + AID key, construit et envoie le paquet client).
3. **Frontend** : grille HTML 80x24 en monospace, gestion focus champs input, event listeners clavier, polling ecran ~100ms.
4. **Gr0gu3270.py** : mode sans client_connect() quand terminal web actif.

## Decision
En attente. Option A (non-blocking connect + auto x3270) implementee en priorite. Cette RFC reste ouverte pour evaluation future.

## Statut
DRAFT — 2026-03-04
