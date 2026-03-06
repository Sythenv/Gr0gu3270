# RFC: Wordlists z/OS et gestion ABEND — couverture vs état de l'art

## Partie 1 : Audit des wordlists

### Inventaire actuel (16 fichiers)

| Fichier | Contenu | Lignes | Usage |
|---------|---------|--------|-------|
| `alpha-1` à `alpha-4` | A-Z, AA-ZZ, AAA-ZZZ, AAAA-ZZZZ | 26→456K | Brute-force générique |
| `alphanumeric-1` à `4` | 0-9A-Z combinatoires | 36→233K | Brute-force générique |
| `numeric-1` à `4` | 0-9 combinatoires | 10→10K | Brute-force PIN/codes |
| `cics-default-transactions` | 186 transactions CICS standard | 186 | Enum transactions |
| `db2-injections` | SQL injection DB2 (UNION, ORDER BY) | 1449 | SQLi via CICS |
| `dvca-demo-*` | Demos DVCA spécifiques | 7/25 | Tests locaux |

### Ce qui manque — angles d'attaque z/OS non couverts

#### 1. Transactions système critiques non-CICS

Les 186 transactions sont uniquement CICS (préfixe C/D). Manquent :

| Catégorie | Exemples | Impact |
|-----------|----------|--------|
| **TSO commands** | LOGON, LOGOFF, EXEC, SUBMIT, STATUS | Accès TSO depuis CICS (via CSOL) |
| **ISPF panels** | ISP, PDF, SDSF | Navigation ISPF si accessible |
| **JES2/JES3** | $HASP, $D, $P, $S | Contrôle des jobs |
| **VTAM** | LOGON, LOGOFF, DISPLAY | Réseau SNA |
| **Custom transactions** | Préfixes métier (IN, OU, PA, FI, HR) | Apps métier (les plus critiques) |

**Impact** : les 186 txns CICS sont les "defaults" — sur un mainframe réel, 80% des transactions sont custom. Un wordlist de préfixes métier courants (2 lettres × 2 lettres = 676 combinaisons) couvrirait mieux la surface d'attaque réelle.

#### 2. CICS system commands via CECI

CECI permet d'exécuter des commandes CICS arbitraires. Wordlists manquantes :

| Commande | Ce qu'elle fait | Risque |
|----------|----------------|--------|
| `CECI INQUIRE PROGRAM(*)` | Liste tous les programmes | Enumération |
| `CECI INQUIRE TRANSACTION(*)` | Liste toutes les transactions | Enumération |
| `CECI INQUIRE FILE(*)` | Liste tous les datasets | Fuite de données |
| `CECI SET PROGRAM(x) ENABLE` | Active un programme désactivé | Escalation |
| `CECI LINK PROGRAM(x)` | Exécute un programme | RCE |
| `CECI READQ TS QUEUE(*)` | Lit les queues temporaires | Fuite de données (sessions, tokens) |

#### 3. Injection COBOL/PL1 (pas SQL)

Les applications CICS sont écrites en COBOL. Les injections ne sont pas SQL-like. Manquent :

| Vecteur | Payload | Ce qu'on teste |
|---------|---------|----------------|
| **Buffer overflow** | `A` × 256, `A` × 1024, `A` × 4096 | Dépassement de champ COBOL (PIC X(n)) |
| **Numeric overflow** | `99999999`, `-1`, `0`, `2147483647` | Overflow PIC 9 / COMP-3 |
| **EBCDIC specials** | `¢`, `¬`, `\|`, chars 0x00-0x3F | Caractères hors jeu EBCDIC standard |
| **Field delimiter** | Null bytes, 0x1D (SF), 0x11 (SBA) | Injection d'ordres TN3270 dans le champ |
| **Format string** | `%s`, `%d`, `%x` (si runtime C) | Rare mais possible sur IMS/DB2 stored procs |

#### 4. Credential testing

| Wordlist | Contenu | Usage |
|----------|---------|-------|
| **Default z/OS users** | IBMUSER, SECADM, OPER, SYSPROG, CICSUSER | Login bruteforce |
| **Default passwords** | SYS1, IBMUSER, PASSWORD, CICS, START | Idem |
| **TSO userid patterns** | 7 chars max, lettres+chiffres, commence par lettre | Enum users |

#### 5. Dataset names

| Wordlist | Contenu | Usage |
|----------|---------|-------|
| **System datasets** | SYS1.PARMLIB, SYS1.PROCLIB, SYS1.LINKLIB | Accès datasets critiques |
| **RACF datasets** | SYS1.RACF*, IRR* | Accès config sécurité |
| **Spool datasets** | JESMSGLG, JESJCL, JESYSMSG | Lecture spool |

### Résumé couverture wordlists

| Surface d'attaque | Couverte ? | Priorité |
|-------------------|-----------|----------|
| Transactions CICS standard | ✅ 186 txns | — |
| Transactions custom/métier | ❌ | **P1** — 80% de la surface réelle |
| Commandes CECI | ❌ | **P1** — RCE + enum |
| Buffer overflow COBOL | ❌ | **P1** — crash = finding |
| SQL injection DB2 | ✅ 1449 payloads | — |
| Injection TN3270 (ordres) | ❌ | **P2** — rare mais impactant |
| Numeric overflow | ❌ | **P2** — PIC 9 overflow |
| Credentials default | ❌ | **P2** — hors scope fuzzer (login) |
| Dataset names | ❌ | P3 — nécessite accès TSO/CECI |

---

## Partie 2 : Gestion ABEND — état de l'art vs implémentation

### Ce qu'on détecte aujourd'hui

**20 codes ABEND** hardcodés dans `ABEND_CODES` + regex `DFHxxxx` sur 28 préfixes.

Méthode de détection : recherche textuelle dans la conversion ASCII du flux EBCDIC.

```python
for code, description in ABEND_CODES.items():
    if code in ascii_text:  # ← substring match
```

### Ce que fait l'état de l'art (IBM docs, SoC mainframe, zSecure)

#### 1. ABEND codes manquants — les plus critiques pour un pentester

| Code | Signification | Pourquoi c'est critique | Présent ? |
|------|--------------|------------------------|-----------|
| ASRA | Program check | Buffer overflow, injection | ✅ |
| AEY7 | Not authorized | Escalation | ✅ |
| AEZD | Security violation | Violation ESM | ✅ |
| **AEI0** | **EXEC CICS error** | **Injection EXEC interface** | ❌ |
| **AEI9** | **Invalid data** | **Type confusion, format error** | ❌ (F-0007) |
| **AKCP** | **Temp storage full** | **DoS via queue flooding** | ❌ |
| **AFCF** | **File not open** | **Race condition** | ❌ |
| **AFCB** | **Dataset busy** | **Contention/DoS** | ❌ |
| **ASP2** | **Supervisor service error** | **Kernel-level issue** | ❌ |
| **ATCV** | **Task control violation** | **Privilege escalation** | ❌ |
| **AEXK** | **EXEC interface security** | **Auth bypass** | ❌ |
| **AIIB** | **Invalid interval** | **Timer manipulation** | ❌ |
| **AWDQ** | **Deadlock wait** | **DoS** | ❌ |

On couvre **20 codes sur ~50 pertinents** pour le pentest. Les 13 manquants ci-dessus sont directement actionnables.

#### 2. Détection par substring : faux positifs

```python
if code in ascii_text:  # "ASRA" matche aussi "KASRA", "TRASRA", etc.
```

Sur un écran CICS typique avec des noms d'utilisateur, des identifiants métier, etc., un code ABEND de 4 lettres a une probabilité non-nulle de matcher un mot courant. Exemple :
- `ATNI` pourrait matcher dans un champ contenant "LATNIC" (nom propre)
- `AQRD` pourrait matcher dans "HEADQUARTERS"

L'état de l'art : chercher le pattern complet `DFHxxxx code` ou le format standard `TRANSACTION xxx ABEND code IN PROGRAM yyy`.

#### 3. Pas de contexte d'ABEND

Quand un ABEND est détecté, on stocke :
```python
{'type': 'ABEND', 'code': 'ASRA', 'description': '...'}
```

Manque :
- **La transaction** qui a causé l'ABEND
- **Le programme** qui a ABEND (souvent dans le message DFHxxxx)
- **L'offset** dans le programme (info de debug, présent dans DFH messages)
- **Le lien avec le payload** qui l'a causé (si déclenché par le fuzzer)

Pour un pentester, "ASRA in PROGRAM PAYROLL at OFFSET +0x1A3" est un finding. "ASRA detected" est juste un signal.

#### 4. Pas de classification par sévérité

Tous les ABENDs sont traités pareil dans l'UI (badge ABND). Mais :
- ASRA (program check) = **CRITIQUE** — injection possible
- APCT (pgm not found) = **INFO** — juste une enum
- AEY7 (not authorized) = **HIGH** — mur de sécurité trouvé
- AICA (runaway) = **HIGH** — DoS confirmé

L'auditeur doit interpréter lui-même. 80/20 : ajouter un niveau (CRIT/HIGH/INFO) au dict `ABEND_CODES`.

#### 5. Regex fallback manquant (F-0007)

Si l'ABEND n'est pas dans le dictionnaire, on ne le détecte pas. Le message standard CICS est :
```
DFHAC2001 date time TRANSACTION xxxx ABEND yyyy
```

Un regex `ABEND [A-Z0-9]{4}` attraperait TOUT abend, même inconnu. C'est le bug F-0007 identifié mais jamais fixé.

### Résumé ABEND : état de l'art vs nous

| Aspect | État de l'art | Gr0gu3270 | Gap |
|--------|--------------|-----------|-----|
| Codes couverts | ~50 pentest-relevant | 20 | **-30 codes** |
| Détection | Pattern contextuel (DFH message) | Substring brut | **Faux positifs** |
| Regex fallback | `ABEND [A-Z0-9]{4}` | Absent (F-0007) | **ABENDs inconnus ratés** |
| Contexte (TXN, PGM, offset) | Extrait du message DFH | Non | **Findings incomplets** |
| Sévérité | CRIT/HIGH/MEDIUM/INFO | Tous identiques | **Triage impossible** |
| Corrélation fuzzer | Payload → ABEND | Non | **Pas de PoC** |

---

## Partie 3 : Propositions 80/20

### Wordlists — 3 fichiers à créer

| Fichier | Contenu | Lignes | Effort |
|---------|---------|--------|--------|
| `cici-commands.txt` | CECI INQUIRE/SET/LINK/READQ commands | ~30 | 15 min |
| `cobol-overflow.txt` | Strings longues (128/256/512/1024), numeric overflow, EBCDIC specials | ~50 | 15 min |
| `custom-txn-prefixes.txt` | AA-ZZ (676) — toutes les combinaisons 2 lettres pour découvrir les préfixes métier | 676 | Script 2 lignes |

**Gain** : +3 surfaces d'attaque couvertes, +756 payloads, 30 min de travail.

### ABENDs — 4 fixes

| Fix | Changement | Effort |
|-----|-----------|--------|
| **Ajouter 13 codes** | Étendre `ABEND_CODES` dict | 15 lignes |
| **Regex fallback** (F-0007) | `re.findall(r'ABEND ([A-Z0-9]{4})', ascii_text)` après le dict scan | 5 lignes |
| **Sévérité** | Ajouter `'severity': 'CRIT'/'HIGH'/'INFO'` dans `ABEND_CODES` | 20 lignes (dict) + 5 lignes (UI couleur) |
| **Contexte** | Regex `TRANSACTION (\w+) ABEND (\w+) IN PROGRAM (\w+)` | 10 lignes |

**Gain** : couverture ~50 codes, zéro faux négatif (regex fallback), findings actionnables.

---

## Étude d'impact

### Wordlists

| Fichier | Action | Impact |
|---------|--------|--------|
| `injections/ceci-commands.txt` | Nouveau fichier | Zero impact code — le fuzzer charge n'importe quel .txt |
| `injections/cobol-overflow.txt` | Nouveau fichier | Idem |
| `injections/custom-txn-prefixes.txt` | Nouveau fichier | Idem |
| Code | Aucun changement | L'API `/api/injection_files` liste automatiquement les fichiers |
| Tests | Aucun changement | Les wordlists ne sont pas testées unitairement |

### ABENDs

| Fichier | Changement | Risque |
|---------|-----------|--------|
| `libGr0gu3270.py` | `ABEND_CODES` étendu (13 entrées + sévérité) | **Nul** — ajout pur |
| `libGr0gu3270.py` | `detect_abend()` + regex fallback + extraction contexte | **Faible** — 15 lignes, logique additive |
| `web.py` | Couleur sévérité dans Events (CRIT=rouge, HIGH=orange, INFO=dim) | **Faible** — CSS/JS |
| `tk.py` | Tab ABEND affiche déjà type/code/description → ajouter sévérité | **Faible** |
| `tests/test_core.py` | Adapter les tests `detect_abend` pour sévérité + nouveaux codes | **Moyen** — ~10 tests à mettre à jour |
| DB `Abends` | Ajouter colonne `SEVERITY` (ou parser depuis le code à la lecture) | **Faible** |

### Compatibilité

- **API** : endpoints inchangés, champs ajoutés (backward compat)
- **DB** : nouvelle colonne nullable ou dérivée → compatible ancien schema
- **tk.py** : affiche ce que le core renvoie → automatiquement enrichi
- **Mode offline** : ABENDs historiques sans sévérité → afficher comme INFO par défaut
