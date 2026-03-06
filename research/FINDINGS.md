# Findings — Pentest CICS / Gr0gu3270

## Convention
Chaque finding suit le format :

```
### F-XXXX : Titre court
- **Date** : YYYY-MM-DD
- **Severite** : INFO | LOW | MEDIUM | HIGH | CRITICAL
- **Categorie** : vuln | technique | outil | config
- **Description** : ...
- **Reproduction** : etapes
- **Impact** : ...
- **Remediation** : ... (si applicable)
- **References** : ...
```

Compteur : F-0009

---

### F-0001 : DVCA — Aucun controle d'acces sur transactions CICS
- **Date** : 2026-03-05
- **Severite** : CRITICAL
- **Categorie** : vuln
- **Description** : Les 186 transactions CICS par defaut sont toutes accessibles sans authentification sur DVCA. Aucun mecanisme ESM (RACF/ACF2/TSS) ne restreint l'acces.
- **Reproduction** : Gr0gu3270 Security Audit avec `cics-default-transactions.txt` → 186/186 ACCESSIBLE
- **Impact** : Acces complet a toutes les transactions d'administration CICS (CEDA, CEMT, CESD, CESN, CECI...) permettant la modification de la region, des ressources, et l'execution de code arbitraire.
- **Remediation** : Implementer des profils RACF sur TCICSTRN pour chaque transaction sensible. Appliquer le principe du moindre privilege.
- **References** : IBM CICS Security Guide, RACF TCICSTRN profile class

### F-0002 : DVCA — Information disclosure dans ecran d'accueil
- **Date** : 2026-03-05
- **Severite** : LOW
- **Categorie** : config
- **Description** : L'ecran d'accueil MVS revele la version Hercules (4.7.0.11032-SDL-DEV), l'OS hote (Linux-6.6.87.2-microsoft-standard-WSL2), et la revision MVS/CE (v2.0.3). Le message invite a se connecter avec "logon username/password".
- **Reproduction** : Connexion TN3270 sur le port 3270 → ecran d'accueil affiche les versions
- **Impact** : Facilite la reconnaissance et l'identification de vulnerabilites specifiques a la version.
- **Remediation** : Personnaliser l'ecran d'accueil pour masquer les versions. Supprimer l'indication sur le format de login.

### F-0003 : Gr0gu3270 — list_injection_files() chemin relatif
- **Date** : 2026-03-05
- **Severite** : INFO
- **Categorie** : outil
- **Description** : `list_injection_files()` utilise `Path('injections')` relatif au CWD du processus. Si Gr0gu3270 est lance depuis un repertoire different, les fichiers d'injection ne sont pas trouves.
- **Reproduction** : Lancer `python3 /path/to/Gr0gu3270.py ...` depuis un autre repertoire → `/api/injection_files` retourne `[]`
- **Impact** : Fonctionnalite d'injection et d'audit inaccessible si CWD != repertoire du script.
- **Remediation** : Utiliser `Path(__file__).parent / 'injections'` au lieu de `Path('injections')`.

### F-0004 : DVCA — Hidden field expose option admin "Delete Order History"
- **Date** : 2026-03-05
- **Severite** : HIGH
- **Categorie** : vuln
- **Description** : Le menu principal MCGM contient une option cachee `99) Delete Order History` dissimilee via l'attribut hidden du champ 3270 (bit 4). Gr0gu3270 avec hack_fields active revele ce champ dans x3270 et dans le screen map.
- **Reproduction** : Login DVCA/DVCA → CSGM → MCGM → PF5 → screen_map montre 4 champs HIDDEN dont `99) Delete Order History` a [11,4]
- **Impact** : Un attaquant peut utiliser l'option 99 pour supprimer l'historique des commandes — fonctionnalite admin accessible a tout utilisateur.
- **Remediation** : Ne jamais compter sur les attributs d'affichage 3270 pour la securite. Implementer des controles cote serveur (CICS RACF).
- **References** : NetSPI "7 Ways to Hack CICS" #3 (Hidden Fields)

### F-0005 : DVCA — Champs proteges editables via proxy MitM
- **Date** : 2026-03-05
- **Severite** : HIGH
- **Categorie** : vuln
- **Description** : Les champs marques "protected" dans les ecrans DVCA sont modifiables par un attaquant utilisant Gr0gu3270 avec `hack_on`. Le proxy intercepte le data stream serveur et supprime les bits de protection (bit 6) avant de relayer vers l'emulateur. L'utilisateur peut alors editer des champs normalement verrouilles.
- **Reproduction** : Gr0gu3270 avec hack_fields {prot:1, sf:1, sfe:1, mf:1} → tous les champs PROT deviennent editables dans x3270
- **Impact** : Modification de donnees supposees en lecture seule, bypass de validations client-side, soumission de valeurs interdites.
- **Remediation** : Toute validation doit etre cote serveur. Les attributs de champs 3270 ne sont pas un controle de securite.
- **References** : NetSPI "7 Ways to Hack CICS" #4 (Protected Fields)

### F-0006 : Gr0gu3270 — Blocage du serveur web lors d'envoi de commandes avec hack_on [CORRIGE]
- **Date** : 2026-03-05
- **Severite** : MEDIUM
- **Categorie** : outil
- **Description** : En mode web, quand hack_on est actif, le daemon thread peut bloquer dans `client.send()` de `handle_server()`. Cela bloque le lock et rend le serveur HTTP non-responsif. Le probleme est un conflit I/O entre le daemon thread (qui lit/ecrit les sockets) et le HTTP thread (qui envoie via `send_text`/`send_keys`).
- **Reproduction** : Activer hack_fields + envoyer du texte via API → le serveur devient non-responsif apres quelques echanges
- **Impact** : L'outil devient inutilisable, necessite un redemarrage.
- **Remediation** : Refactorer pour separer les I/O socket du lock HTTP, ou utiliser une queue pour les commandes sortantes.
- **Resolution** : Implementee le 2026-03-05. (1) NonBlockingClientSocket wrappe le client socket — send() ne bloque jamais, les donnees sont bufferisees. (2) Command queue (queue.Queue) — send_keys/send_text mettent les commandes en queue, le daemon thread les envoie hors du lock. (3) _inject_worker et _audit_worker refactorises pour utiliser la queue et select() hors du lock. Validation : 82 tests unitaires + 6 tests live DVCA (tous < 10ms de latence).

### F-0007 : Gr0gu3270 — ABEND code AEI9 non detecte par PR1
- **Date** : 2026-03-05
- **Severite** : LOW
- **Categorie** : outil
- **Description** : L'ABEND code AEI9 retourne par KICKS n'est pas dans la table ABEND_CODES (20 codes). La detection PR1 n'a pas capture cet ABEND bien que visible dans les logs bruts. KICKS utilise des codes differents de CICS standard.
- **Reproduction** : Provoquer un ABEND sur DVCA (mauvais input) → le log montre "Transaction Abend Code AEI9" mais pas de detection PR1
- **Impact** : Faux negatifs sur la detection d'ABENDs KICKS.
- **Remediation** : Ajouter une detection generique par regex "Abend Code [A-Z0-9]{4}" en complement de la table fixe.

---

### F-0008 : RCE via CECI SPOOLWRITE / INTRDR
- **Date** : 2026-03-05
- **Severite** : CRITICAL
- **Categorie** : technique
- **Description** : Si la transaction CECI est accessible et que SPOOL=YES dans la SIT, un utilisateur peut soumettre du JCL arbitraire via SPOOLOPEN/SPOOLWRITE/SPOOLCLOSE. Le JCL est route vers le JES2 Internal Reader et execute comme un batch job. Equivalent a un RCE complet sur le LPAR.
- **Reproduction** : 1) CECI SPOOLOPEN OUTPUT TOKEN(H3TK) → verifier RESPONSE: NORMAL. 2) SPOOLWRITE lignes JCL (FTP connect vers listener). 3) SPOOLCLOSE → job soumis. 4) Verifier connexion sur le listener (nc -lvp <port>).
- **Impact** : Execution de code arbitraire sur le mainframe. Soumission de jobs batch sous l'identite CICS ou surrogate.
- **Remediation** : Restreindre CECI aux utilisateurs autorises (RACF TCICSTRN). Desactiver SPOOL=NO dans la SIT si non necessaire. Controler les profils SURROGAT.
- **References** : Ayoub Elaassal (mainframe pentest), Phil Young / Soldier of Fortran, Gr0gu3270 spool_check() / spool_poc_ftp()

---

### F-0009 : AID Scan — Touches destructrices de session necessitent operateur
- **Date** : 2026-03-05
- **Severite** : INFO
- **Categorie** : technique
- **Description** : L'AID scan automatise teste les 28 touches (PF1-24, PA1-3, ENTER) depuis un ecran cible et rejoue le chemin de navigation pour revenir a l'ecran apres chaque test. Cependant, certaines touches sont **destructrices de session** : PF3 sur KICKS/CICS execute un LOGOFF, ce qui detruit la session CICS. Le replay automatique echoue car le re-LOGON est bloque par le verrouillage userid TSO (`HIKJ56425I LOGON REJECTED, USERID DVCA IN USE`). Tous les tests suivants s'executent depuis le mauvais ecran (logon TSO au lieu de l'ecran cible).
- **Reproduction** : 1) Connecter a DVCA, naviguer vers MCMM. 2) Lancer AID scan. 3) PF3 declenche un LOGOFF KICKS. 4) Le replay envoie CLEAR + LOGON DVCA/DVCA → echec userid lock. 5) Les 25 touches restantes sont testees depuis l'ecran TSO (faux resultats).
- **Impact** : Faux resultats sur les touches testees apres une touche destructrice. L'operateur doit verifier manuellement les touches marquees NEW_SCREEN apres un LOGOFF.
- **Scenario PowerPoint** : L'automatisation couvre 80% du travail (triage des 28 touches). Les 20% restants sont le jugement de l'operateur :
  1. L'AID scan identifie que PF3 provoque un changement d'ecran radical (similarite < 5%)
  2. L'auditeur reconnait un pattern LOGOFF dans le preview (`LOGON REJECTED`)
  3. Il relance le scan en excluant PF3, ou teste PF3 manuellement en sachant que c'est un LOGOFF
  4. **Lecon** : un outil de pentest automatise ne remplace pas l'expertise humaine — il la multiplie en eliminant le bruit (les 20+ touches "meme ecran") pour que l'auditeur se concentre sur les 2-3 touches qui meritent attention
- **Ameliorations possibles** :
  - Detection de pattern LOGOFF/SIGNOFF dans la reponse → skip automatique du replay et marquage "SESSION_LOST"
  - Option "dry run" : tester d'abord les touches PA (non destructrices) avant les PF
  - Mode "operateur" : pause apres chaque NEW_SCREEN pour confirmation avant replay
