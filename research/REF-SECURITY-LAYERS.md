# Référence sécurité mainframe — 3 couches et leurs bypass

## Architecture de sécurité z/OS CICS

```
Requête utilisateur
    │
    ▼
[ESM: RACF/ACF2/TSS]  ← Transaction profilée ? Classe active ? UACC ?
    │ PASS
    ▼
[CICS Security]        ← SEC=YES ? RESSEC ? CMDSEC ? XUSER ?
    │ PASS
    ▼
[Application COBOL]    ← Input validé ? Hidden protégé ? Flow vérifié ?
    │ PASS
    ▼
  Accès accordé
```

Chaque ABEND HIGH (AEY7, AEYF, AEZD, ATCV, AEXK) est un mur d'une couche qui tient.
Le pentester cherche les endroits où le mur ne tient pas.

---

## Couche 1 : ESM (External Security Manager)

Le firewall applicatif du mainframe. Toujours un des trois :

| ESM | Éditeur | Part de marché |
|-----|---------|----------------|
| RACF | IBM | ~60% |
| ACF2 | Broadcom | ~25% |
| Top Secret | Broadcom | ~15% |

Protège : users, datasets, transactions, programmes, commandes CICS, ressources système.
Chaque accès passe par l'ESM qui vérifie le profil de l'utilisateur.

### Bypass ESM

| Bypass | Comment | Détection Gr0gu3270 |
|--------|---------|---------------------|
| Transaction non profilée | Pas de profil RACF → accès par défaut (UACC). F-0001 : 186 txns DVCA sans profil | Fuzzer → ACCESSIBLE |
| SURROGATE user | Job soumis avec USER= différent, pas de profil SURROGAT | SPOOL/RCE → job submission |
| Classe TCICSTRN inactive | Profils existent mais classe non activée → aucune protection | Security Audit → 100% ACCESSIBLE |
| UACC trop permissif | UACC(READ) sur datasets critiques → tout le monde lit | Hors scope (accès dataset = TSO) |
| Profils génériques mal ordonnés | `CICS.TRANS.*` PERMIT(READ) masque `CICS.TRANS.CEMT` PERMIT(NONE) | Tester chaque transaction individuellement |

---

## Couche 2 : CICS Security

Couche propre à CICS au-dessus de l'ESM.

| Contrôle | Protège | Mécanisme |
|----------|---------|-----------|
| Transaction security | Qui exécute quelle transaction | RACF classe TCICSTRN |
| Resource security | Qui accède à quel fichier/programme/queue | RACF classe FCICSFCT/PCICSPSB |
| Command security | Qui exécute quelles commandes CICS | RACF classe CCICSCMD |
| SURROGAT security | Qui agit au nom de qui | RACF classe SURROGAT |

### Bypass CICS Security

| Bypass | Comment | Détection Gr0gu3270 |
|--------|---------|---------------------|
| SEC=NO dans SIT | Toute la sécurité CICS désactivée. Aucun contrôle ESM | Fuzzer → 100% ACCESSIBLE + pas de message RACF |
| RESSEC=NO | Resource security off. Transactions protégées, pas les fichiers qu'elles appellent | Test croisé (accéder fichier TXN B depuis TXN A) |
| CMDSEC=NO | Command security off. CEMT/CEDA/CECI accessibles à tous | Fuzzer sur CEMT/CEDA/CECI → ACCESSIBLE |
| XUSER=NO | Pas de vérification userid sur transactions chaînées. TXN A → RETURN TRANSID(B) bypass le contrôle | Analyse logs de transaction |

---

## Couche 3 : Application

Dernière ligne de défense — le code COBOL/PL1 lui-même.

| Contrôle | Exemple |
|----------|---------|
| Validation d'input | Montant > 0 et < 999999 |
| Contrôle métier | Droit de voir CE dossier client |
| Champs hidden | Option admin dans un champ hidden |
| Enchaînement | Login avant données |

### Bypass Application

| Bypass | Comment | Détection Gr0gu3270 |
|--------|---------|---------------------|
| Champ hidden modifiable | Serveur cache un champ, proxy MitM écrit via SBA. F-0004 | Screen Map + Fuzzer hidden |
| Champ protégé modifiable | Serveur marque `protected`, proxy envoie SBA. F-0005 | Hack Fields + Fuzzer |
| Navigation directe | Taper transaction directement sans passer par le menu | Fuzzer sur champ transaction |
| Pas de validation input | MOVE sans vérif type/taille → ASRA | Fuzzer + cobol-overflow → ABEND |
| COMMAREA non protégée | Transaction B lit COMMAREA de A sans vérifier provenance | CECI LINK avec COMMAREA forgée |

---

## Mapping ABEND → couche de sécurité

| ABEND | Couche qui bloque | Ce que ça confirme |
|-------|-------------------|-------------------|
| AEY7 | ESM (RACF) | Profil RACF actif, accès refusé |
| AEYF | CICS Resource Security | RESSEC actif pour cette ressource |
| AEZD | CICS Command/Transaction Security | SEC actif, commande protégée |
| ATCV | CICS Task Control | Contrôle des tâches actif |
| AEXK | CICS EXEC Interface Security | Commandes EXEC protégées |
| ASRA | Application (crash) | Application vulnérable — aucune couche n'a validé l'input |
| AICA | Application (boucle) | Application vulnérable — DoS possible |

**Règle pour le pentester** : un ABEND HIGH = la couche tient ici. Chercher un autre chemin vers la même ressource. Un ABEND CRITIQUE = la couche applicative ne tient pas. Explorer plus profond.
