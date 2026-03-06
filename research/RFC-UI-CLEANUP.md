# RFC: UI Cleanup — supprimer le bruit, garder les décisions

## Principe

Chaque élément affiché doit répondre à : **"est-ce que ça change la décision du pentester ?"**
Si non → candidat à suppression ou masquage.

## Candidats par panel

### 1. Events — colonnes ID et ms

| Colonne | Décision ? | Verdict |
|---------|-----------|---------|
| ID | Non — c'est un compteur interne SQLite | **Supprimer** |
| Time | Oui — corrélation temporelle avec l'émulateur | Garder |
| Type | Oui — ABND/TXN/DENY = triage immédiat | Garder |
| Code | Oui — ASRA vs AEI9 = sévérités différentes | Garder |
| Detail | Oui — contexte du finding | Garder |
| ms | Rarement — un timing anormal peut indiquer un traitement côté serveur, mais en pratique on ne s'en sert pas | **Supprimer** (ou masquer sous SHOW ALL events) |

**Impact** : 2 colonnes en moins, tableau plus lisible, les 4 colonnes restantes sont toutes actionnables.

### 2. Fuzz Results — colonnes Size et Sim%

| Colonne | Décision ? | Verdict |
|---------|-----------|---------|
| Payload | Oui — c'est ce qu'on a envoyé | Garder |
| Status | Oui — ACCESSIBLE/DENIED/ABEND = la décision | Garder |
| Size | Rarement — utile en web (taille réponse HTTP), mais en TN3270 les écrans font tous ~1920 bytes | **Supprimer** |
| Sim% | Non — métrique interne de classification. Le pentester regarde Status, pas le pourcentage | **Supprimer** |

**Impact** : tableau fuzz réduit à 2 colonnes (Payload + Status). Ultra-lisible, comme un résultat ffuf filtré.

### 3. AID Scan — colonnes Status, Similarity, Preview

| Colonne | Décision ? | Verdict |
|---------|-----------|---------|
| R (replay dot) | Oui — fiabilité du résultat | Garder |
| Key | Oui — quelle touche | Garder |
| Category | Oui — VIOLATION/NEW_SCREEN = action | Garder |
| Status | Redondant avec Category — VIOLATION contient déjà DENIED/ABEND | **Supprimer** |
| Similarity | Non — métrique interne, même logique que Sim% du fuzzer | **Supprimer** |
| Preview | Parfois — utile pour comprendre l'écran destination, mais tronqué et illisible | **Garder mais en tooltip** sur la ligne, pas en colonne |

**Impact** : 3 colonnes → R + Key + Category. Le pentester scanne en 2 secondes.

### 4. Security Audit — colonnes ID et Time

| Colonne | Décision ? | Verdict |
|---------|-----------|---------|
| ID | Non — compteur SQLite | **Supprimer** |
| Time | Non — l'audit est séquentiel, l'ordre suffit | **Supprimer** |
| Txn | Oui — quelle transaction | Garder |
| Status | Oui — ACCESSIBLE/DENIED = la décision | Garder |
| Preview | Oui — confirme visuellement | Garder |

**Impact** : 3 colonnes au lieu de 5.

### 5. Screen Map — colonne N (Numeric)

| Colonne | Décision ? | Verdict |
|---------|-----------|---------|
| H (Hidden) | Oui — champ caché = finding potentiel | Garder |
| N (Numeric) | Rarement — change le choix de wordlist (alpha vs num), mais c'est un détail de config fuzz, pas une décision d'audit | **Déplacer dans tooltip ou SHOW ALL** |
| Len | Oui — détermine si on peut injecter (len=1 vs len=40) | Garder |
| Content | Oui — le contenu visible | Garder |

**Impact** : mineur, mais cohérent avec la philosophie.

### 6. ABEND Reference — colonne Seen

La table de référence ABEND a une colonne "Seen" (nombre de détections). Le pentester veut savoir **si** un ABEND a été vu, pas **combien de fois**. Remplacer le compteur par une puce verte/vide.

## Résumé des suppressions

| Panel | Colonnes à supprimer | Colonnes restantes |
|-------|---------------------|--------------------|
| Events | ID, ms | Time, Type, Code, Detail |
| Fuzz | Size, Sim% | Payload, Status |
| AID Scan | Status, Similarity, Preview→tooltip | R, Key, Category |
| Audit | ID, Time | Txn, Status, Preview |
| Screen Map | N→SHOW ALL only | H, Len, Content |
| ABEND Ref | Seen→puce | Code, Description, Analogy, puce |

## Priorité

1. **Fuzz + AID Scan** — utilisés activement, gain immédiat
2. **Events + Audit** — panels secondaires, gain de lisibilité
3. **Screen Map N + ABEND Ref** — cosmétique

## Risque

Zéro perte de données — tout reste dans l'API et la DB. C'est uniquement de l'affichage. Un futur SHOW ALL par panel pourrait restaurer les colonnes pour les cas edge.
