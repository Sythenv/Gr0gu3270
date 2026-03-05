# CLAUDE.md

## SECURITE (non negociable)

- Execution locale WSL uniquement. Aucune cible distante sans ordre explicite.
- Zero donnee sensible dans le code, logs, commits, sorties. Dans le doute = sensible = STOP + alerte.
- Exemples fictifs : `10.10.10.10`, `pentest`, `myproject`.
- Ambiguite → arreter → decrire → attendre confirmation.

## RECHERCHE

- Journal : `research/JOURNAL.md` — format `YYYY-MM-DD HH:MM : [CATEG] fait technique`
- Categories : `[TOOL]` `[CICS]` `[SECU]` `[ARCHI]` `[REF]` `[EXP]` `[IDEA]`
- Findings : `research/FINDINGS.md` — format F-XXXX avec severite
- Analogies multi-public : voir `docs/STAKEHOLDERS.md`
- Langue : francais pour communication/docs, anglais pour code/commentaires

## PROJET

hack3270 — TN3270 penetration testing toolkit (v1.2.5-2, GPL-3.0). Proxy MitM entre emulateur TN3270 et mainframe pour audit CICS.

### Execution

```bash
python3 hack3270.py <IP> <PORT>                    # standard
python3 hack3270.py -n myproject -t 10.10.10.10 3270  # TLS + project name
python3 hack3270.py -o                             # offline (analyse depuis DB)
python3 -m pytest tests/ -v                        # tests unitaires
```

Python 3.11+ avec tkinter. Zero dependance externe.

### Architecture

- `hack3270.py` — CLI entry point
- `libhack3270.py` — Core library (~2000 lignes) : protocole 3270, EBCDIC, injection, ABEND detection, screen map, transactions, security audit, SQLite
- `tk.py` — GUI Tkinter (~1100 lignes), 11 onglets (0-6 originaux, 7 ABEND, 8 Screen Map, 9 Transactions, 10 Security Audit)

### Data Flow

```
TN3270 Emulator <-> Local Proxy (hack3270) <-> TN3270 Server (Mainframe)
                          |
                    SQLite3 DB (project_name.db)
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
- DB schema : 6 tables — Config, Logs, Abends, Transactions, Audit.

### Conventions

- Network data = bytes EBCDIC. Conversion ASCII via `e2a` table.
- Hack state : paired `toggle_*()` / `set_*()` methods.
- GUI ↔ core sync via Tk IntVar/StringVar.
- TLS server-side only. Proxy→emulateur non chiffre (intentionnel).
- Tab indices : 0-6 original, 7-10 PR features.
- Offline mode : tabs 7-9 actifs, tab 10 desactive.

### Directories

- `injections/` — Wordlists fuzzing (alpha, numeric, CICS transactions, DB2 injections)
- `tests/` — Tests unitaires pytest (14 tests, PR1-PR4 coverage)
- `research/` — Journal, findings, knowledge base, roadmap
- `framework/` — Template CLAUDE.md + script init-research.sh
- `docs/` — Documentation humaine (STAKEHOLDERS.md)
