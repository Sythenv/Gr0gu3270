# CLAUDE.md

## SECURITE (non negociable)

- Execution locale WSL uniquement. Aucune cible distante sans ordre explicite.
- Zero donnee sensible dans le code, logs, commits, sorties. Dans le doute = sensible = STOP + alerte.
- Exemples fictifs : `10.10.10.10`, `pentest`, `myproject`.
- Ambiguite → arreter → decrire → attendre confirmation.

## CONDUITE DE SESSION (non negociable)

- Regle des 3 : si une approche echoue 3 fois avec des variations mineures, **arreter et proposer une alternative**. Ne jamais brute-forcer.
- Pas de boucle kill/restart : si un process/port ne repond pas apres 2 tentatives, diagnostiquer le probleme racine au lieu de relancer.
- "Tu fais tout" = autonomie totale. Ne JAMAIS demander a l'utilisateur de faire ce qu'on peut faire soi-meme. En cas de blocage, pivoter, pas deleguer.
- Preferer les approches testables unitairement (script Python autonome) aux chaines de process interdependants (GUI + proxy + emulateur).
- Budget tokens : chaque appel outil dans un long contexte coute ~0.10-0.20 EUR. Si le debug depasse 5-6 appels sans progres, changer d'approche.

## RECHERCHE

- Journal : `research/JOURNAL.md` — format `YYYY-MM-DD HH:MM : [CATEG] fait technique`
- Categories : `[TOOL]` `[CICS]` `[SECU]` `[ARCHI]` `[REF]` `[EXP]` `[IDEA]`
- Findings : `research/FINDINGS.md` — format F-XXXX avec severite (compteur actuel : F-0009)
- Analogies multi-public : voir `docs/STAKEHOLDERS.md`
- Post-mortems : `research/POSTMORTEM-*.md`
- Langue : francais pour communication/docs, anglais pour code/commentaires

## PROJET

hack3270 — TN3270 penetration testing toolkit (v1.2.5-2, GPL-3.0). Proxy MitM entre emulateur TN3270 et mainframe pour audit CICS.

### Execution

```bash
python3 hack3270.py <IP> <PORT>                        # standard (web UI par defaut)
python3 hack3270.py -n myproject 10.10.10.10 3270      # project name
python3 hack3270.py -t 10.10.10.10 3270                # TLS
python3 hack3270.py --ui tk 10.10.10.10 3270           # Tkinter UI
python3 hack3270.py --web-port 1337 10.10.10.10 3270   # web port custom
python3 hack3270.py -o                                 # offline (analyse depuis DB)
python3 -m pytest tests/ -v                            # tests unitaires (124 tests)
```

Python 3.11+ avec tkinter. Zero dependance externe.

### Architecture

- `hack3270.py` — CLI entry point (88 lignes)
- `libhack3270.py` — Core library (~2700 lignes) : protocole 3270, EBCDIC, injection, ABEND detection, screen map, transactions, security audit, AID scan, SPOOL/RCE, SQLite
- `web.py` — Web UI (~2200 lignes) : HTTP server, SPA HTML/JS embarquee, thread-safe state wrapper, 36 endpoints API
- `tk.py` — GUI Tkinter (~1200 lignes), 11 onglets (0-6 originaux, 7 ABEND, 8 Screen Map, 9 Transactions, 10 Security Audit)

### Data Flow

```
TN3270 Emulator <-> Local Proxy (hack3270) <-> TN3270 Server (Mainframe)
                          |
                    SQLite3 DB (project_name.db)
                          |
                    Web UI (HTTP :8080)
```

### Key Internals

- `e2a[]` : table EBCDIC→ASCII 256 elements. Conversion via `get_ascii()`.
- `AIDS` dict : AID byte codes (ENTER=0x7D, CLEAR=0x6D, PF1-24, PA1-3).
- `ABEND_CODES` : 20 codes CICS avec descriptions pentest.
- `SECURITY_VIOLATION_PATTERNS` : 25 patterns RACF/ACF2/TSS.
- Field attributes : bit 4 (hidden), bit 5 (numeric), bit 6 (protected).
- Screen map : `parse_screen_map()` — walk SBA/SF/SFE/MF orders.
- Transaction correlation : `detect_transaction_code()` — extract txn from client data.
- Security audit : `build_clear_payload()` / `build_txn_payload()` (pure) + `audit_next()` (I/O).
- AID scan : `extract_replay_path()` / `aid_scan_next()` / `screen_similarity()` — test 28 touches avec auto-replay.
- SPOOL/RCE : `spool_check()` / `spool_poc_ftp()` — detection passive + PoC actif via INTRDR.
- DB schema : 7 tables — Config, Logs, Abends, Transactions, Audit, ScanResults, AidScan.

### Conventions

- Network data = bytes EBCDIC. Conversion ASCII via `e2a` table.
- Hack state : paired `toggle_*()` / `set_*()` methods.
- Web mode : NonBlockingClientSocket + command queue. Lock pour state, I/O socket hors lock.
- GUI ↔ core sync via Tk IntVar/StringVar.
- TLS server-side only. Proxy→emulateur non chiffre (intentionnel).
- Tab indices : 0-6 original, 7-10 PR features.
- Offline mode : tabs 7-9 actifs, tab 10 desactive.

### Directories

- `injections/` — 16 wordlists fuzzing (alpha, numeric, CICS transactions, DB2 injections)
- `tests/` — 124 tests unitaires pytest (test_core.py + test_web.py)
- `research/` — Journal, findings, knowledge base, post-mortems
- `framework/` — Template CLAUDE.md + script init-research.sh
- `docs/` — Documentation humaine (STAKEHOLDERS.md)

### Maintenance de ce fichier

Ce fichier DOIT refleter l'etat reel du code. Apres chaque session qui modifie l'architecture, les tables DB, le nombre de tests ou les fichiers principaux, mettre a jour les chiffres ci-dessus. Un CLAUDE.md obsolete mene a des decisions basees sur un etat qui n'existe plus.
