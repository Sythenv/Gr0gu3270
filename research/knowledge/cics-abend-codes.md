# CICS ABEND Codes — Reference Pentest

## Codes a impact securite direct

| Code | Signification | Interet pentest |
|------|--------------|-----------------|
| ASRA | Program check exception | Input non valide = injection possible |
| ASRB | Operating system abend | Crash bas niveau, rare mais critique |
| AICA | Runaway task (boucle infinie) | DoS applicatif confirme |
| AEY7 | Not authorized | Transaction protegee = cible escalade |
| AEY9 | Unable to process | Erreur interne exploitable |
| AEYD | Transaction not found | Enumeration |
| AEYF | Resource security check failure | Controle RACF/ACF2/TSS actif |
| APCT | Program not found | Transaction definie sans programme |
| AEZD | Security violation | Violation explicite |

## Codes informationnels

| Code | Signification | Notes |
|------|--------------|-------|
| AFCA | Dataset not found | Peut reveler des noms de datasets |
| AFCR | Dataset read error | Probleme I/O |
| AKCS | TS queue not found | Temporary storage |
| AKCT | TD queue not found | Transient data |
| ABMB | BMS map not found | Map d'ecran manquante |
| ADTC | DL/I call error | Base de donnees IMS |
| AEIP | EXEC CICS error | Erreur programmation |
| AEXL | EXEC interface not found | Programme manquant |
| ASP1 | Supervisor call | Appel systeme |
| ATNI | Node error | Erreur reseau |

## Interpretation pour le pentest

- **ASRA apres injection** = le programme ne sanitize pas les inputs → vuln confirmee
- **AEY7 systematique** = RACF/ACF2/TSS est configure → la transaction existe mais est protegee
- **APCT** = la transaction est dans la table TCT mais le programme n'est pas installe → inventaire
- **AICA** = boucle infinie declenchee → DoS confirme, severite haute
