# RFC: Fuzzer champs cachés — IHM cassée, résultats non actionnables, pas de PoC rejeu

## Problèmes identifiés

### 1. Les champs hidden ne sont PAS fuzzables (bug IHM)

```javascript
// renderScreenMap() — ligne 2167
if (isInput) {           // ← seuls les !protected sont cliquables
  tr.style.cursor = 'pointer';
  tr.onclick = () => toggleFuzzField(tr, f);
}
```

Un champ `hidden` est souvent `protected + hidden` (le serveur le rend invisible ET non-modifiable). Le code ne rend cliquables que les `!protected`. Donc **les champs hidden protégés ne peuvent pas être sélectionnés pour le fuzz**.

C'est exactement le scénario DVCA : sur MCGM, l'option 99 (delete orders) est dans un champ hidden **protégé**. L'auditeur la voit en rouge dans la Screen Map mais ne peut pas la fuzzer.

**L'intérêt principal des champs hidden c'est de les modifier** — et le fuzzer ne le permet pas.

C'est l'équivalent de voir un `<input type="hidden" name="admin" value="false">` dans le DOM mais ne pas pouvoir le modifier avec Burp parce que le champ est `readonly`.

### 2. Hack Fields ne déverrouille pas le fuzz

Le toggle "Hack Fields" (H) dans le header modifie le flux TN3270 pour rendre les champs protected éditables côté émulateur. Mais le fuzzer construit ses propres payloads via `build_multi_field_payload()` — il ne passe pas par l'émulateur. Le hack_on n'a aucun effet sur le fuzzer.

**Le fuzzer bypass déjà la protection au niveau protocole** (il écrit directement en SBA à la position du champ). Il n'a pas besoin de hack_on pour écrire dans un champ protégé. Mais l'IHM l'empêche de le sélectionner.

### 3. Les résultats ne permettent pas le rejeu

Le tableau de résultats fuzz affiche :

```
| Payload | Status |
|---------|--------|
| AAAA    | ACCESSIBLE |
| BBBB    | DENIED |
```

Pour rejouer un finding, l'auditeur a besoin de :
- **Quel(s) champ(s)** ont été injectés (position, contenu original)
- **Quel payload** a été envoyé dans quel champ
- **Quelle touche** a été utilisée (ENTER, PF8, etc.)
- **Le payload TN3270 brut** (pour rejeu exact avec un script)

Actuellement aucune de ces informations n'est dans le résultat. Le payload brut est dans la DB (`Logs` table) mais pas exposé dans l'UI ni dans l'export.

### 4. Pas de contexte multi-champ dans les résultats

Le fuzzer injecte le MÊME texte dans TOUS les champs sélectionnés. Mais le résultat ne dit pas quels champs étaient ciblés. Si l'auditeur a sélectionné 3 champs et que "AAAA" retourne ACCESSIBLE, il ne sait pas si c'est le champ 1, 2 ou 3 qui a causé le résultat.

### 5. Le contenu original du champ hidden est perdu

Quand l'auditeur veut tester un champ hidden, il veut souvent :
- Voir la valeur actuelle (ex: `99`)
- La modifier (ex: `99` → `01`, `99` → `AA`)
- Comparer les réponses

Le fuzzer ne montre pas la valeur originale du champ dans les résultats. L'auditeur doit se souvenir de ce qu'il a vu dans la Screen Map.

## Proposition 80/20

### Fix 1 : Rendre les hidden cliquables (5 lignes)

```javascript
// Remplacer le test isInput par isInput || isHidden
if (isInput || isHidden) {
  tr.style.cursor = 'pointer';
  tr.onclick = () => toggleFuzzField(tr, f);
}
```

Le fuzzer sait déjà écrire à n'importe quelle position via SBA — la protection est un concept d'émulateur, pas de protocole. On n'a pas besoin de hack_on.

**Impact** : 1 condition JS modifiée, 0 changement backend.

### Fix 2 : Afficher le contexte dans les résultats (15 lignes)

Ajouter dans `fuzz_results[]` :
```python
{
    'payload': line,
    'status': classification,
    'fields': [{'row': r, 'col': c, 'len': l, 'original': content} for ...],
    'key': key_mode,
}
```

Et dans l'UI, afficher une ligne de contexte au-dessus du tableau de résultats :
```
Fields: [12,45] "Option ==>" (len=4) | Key: ENTER+CLEAR
```

**Impact** : passer les fields+key dans les résultats, ~15 lignes JS/Python.

### Fix 3 : Bouton REPLAY sur chaque résultat (20 lignes)

Chaque ligne de résultat fuzz contient assez d'info pour reconstruire le payload :
- fields (row, col) + payload text + AID key

Ajouter un bouton/lien "▶" sur chaque ligne qui :
1. Reconstruit le payload via `build_multi_field_payload()`
2. L'envoie au serveur
3. Affiche la réponse dans l'émulateur

C'est le PoC de rejeu : l'auditeur clique, le mainframe reçoit exactement le même payload.

**Impact** : nouveau endpoint `POST /api/inject/replay` + bouton JS, ~20 lignes.

### Fix 4 (optionnel) : Export payload brut

Pour le rapport d'audit, l'auditeur veut souvent inclure le payload brut hexadécimal. Ajouter un bouton "Copy hex" qui expose le payload TN3270 en hex depuis la DB Logs.

## Priorité

| Fix | Gain | Effort | Prio |
|-----|------|--------|------|
| Fix 1 : hidden cliquables | **Débloque le use case principal** | 5 lignes | **P0** |
| Fix 2 : contexte résultats | Résultats actionnables | 15 lignes | **P1** |
| Fix 3 : bouton replay | PoC rejeu en 1 clic | 20 lignes | **P1** |
| Fix 4 : export hex | Rapport d'audit | 10 lignes | P2 |

## Étude d'impact

### Fix 1

| Fichier | Changement |
|---------|-----------|
| `web.py` | JS: `if (isInput)` → `if (isInput \|\| isHidden)` dans `renderScreenMap()` |
| `web.py` | JS: passer `f.length` dans `toggleFuzzField` même pour hidden (déjà le cas) |
| `libGr0gu3270.py` | Aucun — `build_multi_field_payload()` écrit déjà à n'importe quelle position |
| `tests/` | Aucun nouveau test nécessaire (le payload builder est déjà testé) |
| **tk.py** | Pas impacté (pas de Screen Map interactive) |

**Risque** : l'auditeur pourrait injecter dans un champ protégé serveur-side → le mainframe rejette → résultat DENIED. C'est le comportement attendu et c'est exactement ce qu'on veut tester.

### Fix 2

| Fichier | Changement |
|---------|-----------|
| `web.py` | Python: ajouter `fields` et `key` dans `fuzz_results[]` dans `_fuzz_worker()` |
| `web.py` | Python: ajouter `original_content` aux fields (lire depuis `smapData` côté JS ou passer depuis l'API) |
| `web.py` | JS: afficher contexte au-dessus du tableau résultats |
| `libGr0gu3270.py` | Aucun |
| **Risque** : aucun |

### Fix 3

| Fichier | Changement |
|---------|-----------|
| `web.py` | Nouveau endpoint `POST /api/inject/replay` — reconstruit + envoie un payload |
| `web.py` | JS: bouton ▶ sur chaque ligne résultat |
| `libGr0gu3270.py` | Aucun — réutilise `build_multi_field_payload()` + `_aid_scan_send_and_read()` |
| `tests/test_web.py` | 1 test pour le nouvel endpoint |
| **tk.py** | Pas impacté |
| **Risque** : le replay envoie un payload au mainframe → même risque que le fuzz original |

### Compatibilité

- **DB** : aucun changement de schema
- **API** : 1 nouvel endpoint (replay), 0 endpoint modifié
- **tk.py** : non impacté
- **Mode offline** : replay non disponible (pas de connexion), fuzz résultats OK

## Résumé

Le fuzzer construit des payloads qui **bypass la protection protocolaire** (SBA direct), mais l'IHM **respecte la protection** en empêchant de cliquer les hidden. C'est une contradiction : l'outil sait écrire partout, mais l'interface l'en empêche. Fix 1 (5 lignes) débloque le use case principal. Fix 2+3 (~35 lignes) rendent les résultats actionnables avec PoC de rejeu.
