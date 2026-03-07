# DVCA Testing Guide — Gr0gu3270

## Transactions DVCA

| Txn | Ecran | Description | Champs input | Interet pentest |
|-----|-------|-------------|--------------|-----------------|
| CSGM | Welcome splash | Page d'accueil DVCA | 1 champ texte | AID Scan (ecran non-formatte, CLEAR obligatoire) |
| MCGM | Mel's Cargo Main | Menu principal reel | Option ==> + **4 champs caches** | Hidden field (option 99 = Delete Order History) |
| MCMM | Main Menu | Menu navigation | Option ==> | Field Fuzzer (tester les txns valides) |
| MCOR | Orders | Gestion commandes | Champ commande + details | Field Fuzzer, Screen Map multi-champs |
| MCSH | Shipping | Adresse livraison | Supervisor Code (****) + adresse | Brute-force code superviseur (4 digits) |

## Transactions CICS systeme (186)

Toutes accessibles sans auth (F-0001). Les plus critiques :

| Txn | Risque | Analogie web |
|-----|--------|-------------|
| CECI | RCE via SPOOL/INTRDR | Equivalent d'un shell web |
| CEMT | Admin monitoring | Panel d'admin sans auth |
| CEDA | Resource definition | Modifier la config serveur |
| CESN | Signon/Security | Bypass auth |
| CEDF | Debug mode | Mode debug en prod |

## Matrice Feature × Transaction

| Feature Gr0gu3270 | Transaction | Ce que ca prouve | Analogie web |
|-------------------|-------------|-----------------|-------------|
| **Screen Map (PR2)** | MCGM | Decode les champs caches (option 99) | Inspect Element → champs `type=hidden` |
| **Screen Map (PR2)** | MCSH | Identifie le champ superviseur + attributs | Cartographier les formulaires |
| **ABEND Detection (PR1)** | MCOR, MCSH | Input invalide → crash CICS (AEI9, APCT) | Stack trace Java / 500 Internal Server Error |
| **Transaction Tracking (PR3)** | Navigation MCGM→MCMM→MCOR | Correle chaque txn avec timing | Access log HTTP avec URL + timestamp |
| **Security Audit (PR4)** | 186 txns CICS | 186/186 accessibles = zero access control | Scan dirb/gobuster : toutes les pages en 200 |
| **AID Scan (PR5)** | MCMM, MCOR | 28 touches testees, PF3 = logout (F-0009) | Tester GET/POST/PUT/DELETE sur chaque endpoint |
| **Field Fuzzer (PR6)** | MCMM | Wordlist de txns → trier ACCESSIBLE/DENIED/ABEND | wfuzz/ffuf sur un parametre |
| **Field Fuzzer (PR6)** | MCSH | Brute-force code superviseur 4 digits | Burp Intruder sur un PIN |
| **Hidden Field (hack_on)** | MCGM | Revele option 99 admin | Modifier `<input type=hidden>` |
| **Protected Field (hack_on)** | MCSH, MCOR | Editer champs read-only via MitM | Supprimer `readonly` sur un input |
| **SPOOL/RCE** | CECI | Detection passive + PoC FTP INTRDR | Webshell upload |

## Cas de test live prioritaires

### 1. Field Fuzzer sur MCMM (validation basique)
- **Wordlist** : `dvca-demo-transactions.txt` (7 entries)
- **Attendu** : MCGM → ACCESSIBLE (ecran change), reste → NOT_FOUND
- **Prouve** : classification des reponses fonctionne

### 2. Field Fuzzer sur MCSH (brute-force superviseur)
- **Wordlist** : `dvca-demo-numeric-4.txt`
- **Attendu** : 1 code valide parmi N → ACCESSIBLE, reste → DENIED/SAME_SCREEN
- **Prouve** : detection de la bonne reponse dans le bruit

### 3. Security Audit 186 txns
- **Wordlist** : `cics-default-transactions.txt`
- **Attendu** : 186/186 ACCESSIBLE (F-0001)
- **Prouve** : absence totale de controle d'acces

### 4. AID Scan sur MCOR
- **Attendu** : 28 touches, PF3 = session kill (F-0009), autres = SAME_SCREEN
- **Prouve** : cartographie des touches actives

### 5. Hidden Field sur MCGM
- **Attendu** : option 99 visible apres hack_on
- **Prouve** : detection de fonctionnalites cachees

## Sequence de navigation

```
CLEAR → LOGON + ENTER → DVCA + ENTER → LOGON + ENTER → TSO READY
→ KICKS + ENTER → CLEAR → CSGM + ENTER → CLEAR → MCMM
→ Option 1 + ENTER → MCOR (commandes)
→ PF3 → retour MCMM
→ MCSH (si accessible depuis MCOR ou menu)
```

## Vulnerabilites connues (Findings)

| ID | Severite | Description | Txn |
|----|----------|-------------|-----|
| F-0001 | CRITIQUE | 186 txns CICS sans auth | Toutes |
| F-0002 | LOW | Banner disclosure Hercules/Linux | Handshake |
| F-0004 | HIGH | Champ cache option 99 (delete orders) | MCGM |
| F-0005 | HIGH | Champs proteges editables via MitM | MCGM, MCOR, MCSH |
| F-0007 | LOW | ABEND AEI9 non detecte | Bug Gr0gu3270 |
| F-0008 | CRITIQUE | RCE via CECI SPOOL/INTRDR | CECI |
| F-0009 | INFO | PF3 tue la session KICKS | MCMM, MCOR |
