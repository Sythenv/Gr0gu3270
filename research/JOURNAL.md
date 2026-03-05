# Journal de Recherche — hack3270 / Pentest CICS

## Convention
```
YYYY-MM-DD HH:MM : [CATEG] Observation + fait
```

Categories :
- `[TOOL]` — evolution de hack3270
- `[CICS]` — connaissance CICS / mainframe
- `[SECU]` — finding securite / technique d'attaque
- `[ARCHI]` — decision architecture / design
- `[REF]` — reference biblio / source externe
- `[EXP]` — experience / test realise
- `[IDEA]` — piste a explorer

---

## 2026-03-04

2026-03-04 00:01 : [TOOL] Implementation des 4 features CICS audit : PR1 ABEND Detection (20 codes + DFH prefixes), PR2 Screen Map BMS (SBA/SF/SFE decode), PR3 Transaction Correlation (detect txn code + timing), PR4 Security Audit (25 violation patterns RACF/ACF2/TSS, classify_response). ~600 LOC dans libhack3270.py + tk.py.

2026-03-04 00:03 : [CICS] Les ABENDs CICS sont codes sur 4 caracteres. ASRA = program check (equivalent segfault), AEY7 = not authorized, APCT = program not found. Un ASRA lors d'injection = le programme ne valide pas ses inputs = vuln confirmee.

2026-03-04 00:04 : [CICS] CICS possede ~186 transactions par defaut. Transactions sensibles : CEDA (definition ressources), CEMT (gestion region), CESD (securite), CESN (signon).

2026-03-04 00:05 : [SECU] Technique d'audit differentiel multi-profils : lancer PR4 avec compte normal puis admin, comparer les matrices ACCESSIBLE/DENIED. Les ecarts revelent les controles d'acces manquants.

2026-03-04 00:12 : [REF] Ratio productivite coding agent : ~600 LOC Python + 6 fichiers docs + 3 fiches knowledge base en une session. Temps humain : ~30 min de supervision strategique.

2026-03-04 00:22 : [REF] Mapping ISO 27001 : PR1→A.12.6.1 (gestion vulns techniques), PR2→A.14.1.2 (securisation services applicatifs), PR3→A.12.4.1 (journalisation evenements), PR4→A.9.4.1 (restriction d'acces).

2026-03-04 00:30 : [SECU] Contrainte securite projet : zero donnee sensible dans le repo, execution confinee WSL locale, ambiguite = stop immediat. Politique appliquee au coding agent via CLAUDE.md = "charte informatique pour agent IA".

2026-03-04 01:00 : [TOOL] Refacto testabilite : 14 tests unitaires pytest couvrant PR1-PR4 (ABEND detection, buffer address 12/14-bit, field attributes, screen map parsing, transaction code detection, classify_response, build_*_payload). Extraction de build_clear_payload() et build_txn_payload() comme fonctions pures depuis audit_next().

2026-03-04 01:01 : [ARCHI] Refacto CLAUDE.md : 165→74 lignes. Analogies multi-public deplacees vers docs/STAKEHOLDERS.md. CLAUDE.md ne contient plus que ce dont l'agent a besoin pour ecrire du code correct et sur.

2026-03-04 01:10 : [ARCHI] Prochain objectif defini : session de test DVCA pour valider PR1-PR4 en conditions reelles. Les 14 tests unitaires couvrent la logique pure — il manque la validation sur un flux 3270 reel.

## 2026-03-05

2026-03-05 10:50 : [EXP] Premiere session de test DVCA (mainframed767/dvca sur Docker, port 3270). hack3270 lance en mode web (--web-port 1337) avec x3270 connecte au proxy port 3271.

2026-03-05 10:51 : [TOOL] Bug decouvert : list_injection_files() utilise Path('injections') relatif — si le process est lance depuis un autre repertoire, les fichiers ne sont pas trouves. Corrige en relancant depuis le bon CWD.

2026-03-05 10:54 : [EXP] Security Audit lance sur 186 transactions CICS par defaut contre DVCA. Resultat : 186/186 ACCESSIBLE (100%), 0 DENIED, 0 ABEND. DVCA n'a aucun controle d'acces — attendu pour une application volontairement vulnerable.

2026-03-05 10:55 : [CICS] DVCA tourne sur MVS Community Edition v2.0.3 (Hercules 4.7.0), base Jay Moseley MVS3.8j Sysgen. Reponses aux transactions : messages HIKTXLOG TGET avec donnees EBCDIC brutes — le journal CICS loggue les transactions recues.

2026-03-05 10:55 : [TOOL] Validation PR4 (Security Audit) : le module envoie les transactions directement (build_clear_payload + send), classe les reponses correctement (ACCESSIBLE). Export CSV fonctionne (dvca_audit.csv). Le module est independant du proxy — il bypass le flux emulateur.

2026-03-05 10:55 : [TOOL] Validation PR1-PR3 : ABEND detection active mais 0 ABENDs (normal sur DVCA avec transactions standard). Transaction tracking active mais 0 captures (normal — l'audit envoie directement, pas via l'emulateur). Screen Map parse correctement les champs (TSO Logon ===>, INPUT NOT RECOGNIZED).

2026-03-05 10:56 : [SECU] Observation methodologique : l'audit differentiel fonctionne. Sur un vrai mainframe, on lancerait l'audit avec un compte non-privilegie puis un compte admin, et les ecarts ACCESSIBLE/DENIED reveleraient les controles manquants. Sur DVCA tout est ouvert = baseline worst-case.

2026-03-05 10:56 : [IDEA] Ameliorations identifiees : (1) classify_response devrait distinguer ACCESSIBLE avec reponse utile vs ACCESSIBLE avec erreur TGET. (2) Le preview EBCDIC brut dans les resultats d'audit meriterait un decodage plus lisible. (3) list_injection_files() devrait utiliser un chemin absolu relatif au script.

2026-03-05 11:10 : [CICS] DVCA login : LOGON DVCA/DVCA au prompt TSO, lance automatiquement KICKS (CICS-compatible). Puis CSGM pour l'ecran DVCA, PF5 pour le menu principal MCGM. Transaction MCGM = "Mels Cargo Main Menu".

2026-03-05 11:15 : [EXP] Hidden fields trouves dans MCGM : 4 champs avec attribut hidden, dont "99) Delete Order History" — option admin dissimilee. hack3270 avec hack_on expose correctement ces champs dans le screen map et dans x3270. Finding F-0004.

2026-03-05 11:15 : [EXP] Protected fields : hack_on avec prot=1 supprime les bits de protection. Tous les champs PROT deviennent editables dans x3270. Le proxy manipulate() fonctionne correctement sur les ecrans DVCA. Finding F-0005.

2026-03-05 11:18 : [TOOL] ABEND AEI9 capture dans les logs bruts mais pas detecte par PR1 (code absent de ABEND_CODES). KICKS utilise des codes differents de CICS standard. Finding F-0007.

2026-03-05 11:20 : [TOOL] Bug critique : blocage serveur web quand hack_on actif et envoi de commandes via API. Le daemon thread bloque dans client.send() de handle_server() — conflit I/O avec le lock partage. Finding F-0006. Necessité un refacto de l'architecture threading.

2026-03-05 11:25 : [TOOL] Ajouts pendant la session : (1) endpoint /api/send_text pour envoyer du texte arbitraire (2) build_input_payload() avec SBA ciblé (3) encode_buffer_address() pour 12-bit. Fix send_keys pour ne pas appeler tend_server en mode web. Fix SO_SNDTIMEO sur socket client.

2026-03-05 11:25 : [SECU] Bilan des 7 vulns NetSPI testees : 3=Hidden fields TROUVE, 4=Protected fields TROUVE, 5=Admin txns TROUVE (186/186), 6=Unauth access TROUVE. Restent : 2=Weak passwords (hors scope), 7=RCE via CECI (RFC futur).

2026-03-05 12:00 : [TOOL] Fix F-0006 valide : NonBlockingClientSocket wrappe le client socket (non-blocking send + buffer interne), command queue pour send_keys/send_text (HTTP threads ne touchent plus les sockets directement), _inject_worker refactorise pour utiliser la queue, _audit_worker fait select() hors du lock. 82 tests unitaires passent (8 nouveaux : 4 NonBlockingClientSocket, 3 command queue, 1 inject worker).

2026-03-05 12:00 : [EXP] Validation live F-0006 contre DVCA : 6/6 tests passent — T1 proxy basique (9ms), T2 hack_on+send_keys (9ms), T3 hack_on+send_text (9ms), T4 10 envois rapides (9ms), T5 audit concurrent (9ms), T6 inject reset (9ms). Le serveur web reste responsif dans tous les scenarios.

2026-03-05 15:45 : [TOOL] Refacto majeur du dashboard web : remplacement de la grille 4 quadrants par un layout vertical flex (Screen Map en haut, Events timeline en bas). Fusion ABENDs + Transactions en timeline unifiee "Events" avec 3 types color-coded (ABND=jaune, TXN=bleu, DENY=rouge). Compteurs inline (ABND/TXN/DENY) dans le header Events.

2026-03-05 15:45 : [ARCHI] Logs et Security Audit deplaces de quadrants permanents vers l'action bar (on-demand). Nouveaux onglets : Logs (group 3, tall), Methodology (group 4, tall). Les pollers dashboard ne gardent que abends(2s) + txns(2s) + screenMap(5s). Logs/Audit pollent uniquement quand leur panel est ouvert.

2026-03-05 15:45 : [TOOL] Nouvel onglet Methodology : flowchart interactif en 5 phases (RECON→FIELDS→INJECT→ANALYZE→REPORT). 25 concept cards avec format term/explain/analogy/action. Decision trees par phase. Table de reference ABEND (20 codes) avec cross-reference session live (codes detectes surlignés). ~200 LOC JS.

2026-03-05 15:45 : [ARCHI] Data layer Events : rawAbends[] + rawTxns[] accumulent les donnees API, rebuildEvents() merge et trie, renderEvents() reconstruit le DOM. Classification automatique DENY pour codes securite (AEY7/AEYF/AEZD) et status denied. Null guards sur tous les loaders pour elements DOM conditionnels (panels action bar).

2026-03-05 15:45 : [EXP] 82 tests unitaires passent apres refacto (zero regression). Les tests ne dependent pas de la structure HTML DOM — modification HTML-only sans impact backend/API.

2026-03-05 18:00 : [TOOL] SPOOL/RCE detection 2 niveaux. Niveau 1 (passif) : CECI SPOOLOPEN + SPOOLCLOSE sans JCL — detecte si API SPOOL accessible. Niveau 2 (actif) : SPOOLWRITE JCL FTP avec IP/port configurables, soumission via INTRDR. Confirmation obligatoire cote UI.

2026-03-05 18:00 : [SECU] Technique RCE CICS via CECI SPOOLWRITE → INTRDR. Prereqs : CECI accessible + SPOOL=YES dans SIT + autorisations SURROGAT. Non applicable sur KICKS/DVCA (pas d'API SPOOL). PoC = FTP connect vers listener (safe, pas d'exec code).

2026-03-05 18:00 : [ARCHI] 6 nouvelles methodes libhack3270 (build_ceci_payload, _spool_send_and_read, spool_check, spool_poc_ftp). 2 endpoints web (/api/spool/check, /api/spool/poc). UI web + Tkinter. 13 nouveaux tests → 95 total.
