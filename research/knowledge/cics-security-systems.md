# Systemes de Securite Mainframe — RACF / ACF2 / Top Secret

## Vue d'ensemble

Trois produits de securite (ESM - External Security Manager) controlent l'acces aux ressources mainframe :

| ESM | Editeur | Part de marche | Messages typiques |
|-----|---------|---------------|-------------------|
| RACF | IBM | ~60% | ICH408I, ICH409I, ICH70001I, IRR012I |
| ACF2 | Broadcom | ~25% | ACF2 messages |
| Top Secret | Broadcom | ~15% | TSS7000I, TSS7001I |

## Detection de l'ESM actif

Lors d'une violation de securite, le message retourne identifie l'ESM :
- Prefixes `ICH` ou `IRR` → RACF
- Prefixe `ACF` → ACF2
- Prefixe `TSS` → Top Secret
- Messages CICS `DFHAC20xx` → controle au niveau CICS (independant de l'ESM)

## Messages CICS lies a la securite

| Message | Signification |
|---------|--------------|
| DFHAC2002 | Transaction security check failure |
| DFHAC2008 | Resource security check failure |
| DFHAC2032 | Userid not authorized for transaction |
| DFHAC2034 | Transaction attached but security failed |

## Techniques de pentest

1. **Enumeration de l'ESM** : provoquer une violation intentionnelle, analyser le message
2. **Audit differentiel** : comparer les acces entre profils (PR4 de hack3270)
3. **Escalade horizontale** : trouver des transactions accessibles qui ne devraient pas l'etre
4. **Escalade verticale** : identifier des transactions admin accessibles a un user normal
