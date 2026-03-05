# Prompt Fondateur — Base d'Analyse Commune

## Contexte

Ce document est le **premier prompt** soumis au coding agent Claude Code le 2026-03-04.
Il constitue la **specification initiale** des 4 features CICS Audit et sert de
**reference commune** pour tous les profils impliques dans le projet.

Ce prompt unique a produit : ~600 lignes de code Python, 4 features fonctionnelles,
3 tables SQLite, integration dans la boucle reseau existante — en une seule passe.

---

## Le prompt original

> Implement the following plan:
>
> # Plan : 4 Features CICS Audit pour hack3270
>
> ## Contexte
> hack3270 opere au niveau protocole TN3270 brut. Pour un audit CICS efficace,
> il manque la comprehension semantique des ecrans, le suivi des transactions,
> la detection d'erreurs, et le test automatise de securite.
> Chaque feature = 1 PR sur une branche dediee.
>
> ## Ordre de merge recommande
> 1. PR1 : ABEND Detection (pas de dependances)
> 2. PR2 : BMS/Screen Map Parsing (fondation pour les autres)
> 3. PR3 : Transaction Correlation (beneficie du screen map)
> 4. PR4 : Security Audit RACF/ACF2/TSS (reutilise ABEND detection + screen map)
>
> ### PR1 : Detection d'ABEND CICS
> - Constantes ABEND_CODES (~20 codes), CICS_ERROR_PREFIXES (DFHxx)
> - Variables d'etat, methodes detect_abend(), write_abend_log(), all_abends()
> - Onglet GUI avec Treeview, toggle ON/OFF
> - Table DB Abends avec FK vers Logs
> - Integration dans handle_server() apres write_database_log()
>
> ### PR2 : Parsing BMS/Screen Map CICS
> - Methodes decode_buffer_address(), decode_field_attribute(), parse_screen_map()
> - Algorithme : skip write cmd + WCC, parcourir SBA/SF/SFE/MF, calculer longueurs
> - Onglet GUI Screen Map (Treeview : Row, Col, Type, Protected, Hidden, Numeric, Length, Content)
> - Pas de table DB (calcule a la volee)
>
> ### PR3 : Correlation Transaction-Reponse
> - detect_transaction_code() : skip AID+SBA, lire EBCDIC, valider pattern 1-8 chars
> - start_transaction(), complete_transaction(), timing en ms
> - Table DB Transactions
> - Integration dans daemon() cote client + cote serveur
>
> ### PR4 : Audit Securite RACF/ACF2/Top Secret
> - SECURITY_VIOLATION_PATTERNS (25 patterns), classify_response()
> - audit_start/next/process_response, driver async GUI avec root.after(500,...)
> - Table DB Audit, export CSV
> - Reutilise detect_abend() de PR1

---

## Analyse du prompt pour chaque public

### Pour le DG / DGA : ce que ce prompt represente

**Analogie** : c'est un **cahier des charges fonctionnel** redige par un expert metier,
soumis a un agent de production automatise.

Ce qu'il faut retenir :
- **Un seul document de specification** a produit 4 modules fonctionnels complets
- **Le temps humain** a ete consacre a la **reflexion strategique** (quoi construire, pourquoi,
  dans quel ordre) — pas a l'execution technique
- **L'ordre de merge** est une decision d'architecture : PR1 d'abord car sans dependance,
  PR4 en dernier car elle reutilise PR1. C'est de la **gestion de risque technique** :
  chaque PR est testable independamment
- **Le ROI** : un expert seul aurait mis 2-5 jours sur ces 4 features.
  Avec le coding agent : ~30 minutes de supervision pour le meme resultat

**Question pour le DG** : si un coding agent multiplie par 10-20x la productivite
de vos experts cyber, quelle est la consequence sur votre programme d'audit SI ?
Reponse : vous passez de l'echantillonnage a l'exhaustivite.

### Pour l'Ingenieur Cyber : ce que ce prompt specifie techniquement

**Analogie** : c'est un **design doc** / RFC interne qui specifie 4 modules
d'un outil de pentest, avec architecture, integration points, et format de donnees.

Points techniques notables dans le prompt :
- **Dependances entre PRs** : PR4 depend de PR1 (`classify_response` appelle `detect_abend`).
  Le prompt le specifie explicitement — l'humain gere l'architecture, l'agent gere l'implementation
- **Integration points precis** : "dans handle_server(), apres write_database_log()" —
  le prompt designe la ligne exacte ou inserer le code
- **Algorithme detaille pour PR2** : skip byte 0 (write cmd) + byte 1 (WCC), parcourir
  SBA(0x11)+2, SF(0x1D)+1, SFE(0x29)+count+pairs — c'est de la specification au niveau octet
- **Pattern async pour PR4** : `root.after(500, ...)` — l'humain connait le pattern
  Tkinter existant (similaire a inject_go) et le prescrit

**Question pour le pentesteur** : quand vous ecrivez un plugin Burp ou un module Metasploit,
combien de temps passez-vous sur le boilerplate (GUI, DB, parsing) vs la logique metier ?
Le coding agent absorbe le boilerplate.

### Pour le Juridique offensif (cadre pentest autorise)

**Analogie** : ce prompt est l'equivalent d'un **plan de test** dans un rapport de mission
de pentest. Il definit le scope (quoi tester), la methodologie (comment), et les livrables
(quelles preuves produire).

Elements de tracabilite dans le prompt :
- **Scope explicite** : 186 transactions CICS par defaut, extensible par fichier
- **Methodologie documentee** : chaque PR decrit exactement ce qui est envoye au serveur
  et comment la reponse est classifiee
- **Journalisation** : tout est ecrit en SQLite avec horodatage — la table Logs, la table
  Abends (avec FK vers le log d'origine), la table Audit
- **Reproductibilite** : le mode offline permet de rejouer et re-analyser sans reconnecter
  au mainframe — les preuves sont preservees

**Question pour le juridique** : ce prompt constitue-t-il un element de la documentation
de mission ? Reponse : oui. Il documente l'intention, la methode, et les limites de l'outil
avant execution. C'est un element du dossier de preuve.

### Pour le Juridique defensif (conformite, RSSI)

**Analogie** : ce prompt definit un **programme de controles automatises** equivalent a un
plan d'audit interne ISO 27001 / PCI-DSS.

Mapping avec les controles de securite :
- **PR1 (ABEND Detection)** → Controle A.12.6.1 (ISO 27001) : gestion des vulnerabilites
  techniques. Detecter les crashes = identifier les defauts logiciels.
- **PR2 (Screen Map)** → Controle A.14.1.2 : securisation des services d'application.
  Cartographier les champs hidden = verifier qu'aucune donnee sensible n'est exposee.
- **PR3 (Transaction Correlation)** → Controle A.12.4.1 : journalisation des evenements.
  Chaque transaction est tracee avec timing et reponse.
- **PR4 (Security Audit)** → Controle A.9.4.1 : restriction d'acces a l'information.
  L'audit verifie le principe du moindre privilege sur chaque transaction CICS.

**Question pour le RSSI** : disposez-vous aujourd'hui d'un outil qui verifie automatiquement
les controles d'acces sur vos transactions CICS ? Si non, chaque transaction non testee
est un risque non mesure.

---

## Observations sur l'interaction humain-agent

| Aspect | Ce que l'humain a fait | Ce que l'agent a fait |
|--------|----------------------|----------------------|
| **Strategie** | Defini les 4 features, leur ordre, leurs dependances | — |
| **Architecture** | Specifie les points d'integration (handle_server, daemon) | Implemente les methodes, gere le wiring |
| **Protocole** | Decrit l'algorithme de parsing au niveau octet | Traduit en code Python fonctionnel |
| **UX** | Specifie les onglets, colonnes, interactions | Genere le code Tkinter complet |
| **DB** | Defini le schema (tables, colonnes, FK) | Genere le SQL, les CRUD, les exports |
| **Qualite** | Supervise, valide la compilation | Ecrit ~600 lignes sans erreur de syntaxe |

**Conclusion** : l'humain opere au niveau **intention et architecture**,
l'agent opere au niveau **implementation et detail**. La valeur de l'humain
est dans le "quoi" et le "pourquoi". La valeur de l'agent est dans le "comment"
et la vitesse d'execution.
