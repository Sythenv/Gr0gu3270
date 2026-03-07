# Benchmark Fuzzer — MCOR (DVCA)

## Date : 2026-03-07

## Contexte

Recovery simplifiee implementee : remplacement du replay generique (`aid_scan_replay()`) par `CLEAR + txn_code`.
Le replay generique echouait car apres un ABEND, le chemin complet (CLEAR→LOGON→DVCA→KICKS→MCOR) ne fonctionne pas — KICKS reste en etat ABEND.

## Configuration

- **Cible** : DVCA (mainframed767/dvca), port 3270
- **Transaction** : MCOR (Mels Cargo Supplies — Order Supply)
- **Proxy** : Gr0gu3270 v1.2.5-2 sur :1337
- **Recovery** : CLEAR + MCOR (nouvelle strategie txn_code)
- **Navigation** : DVCA+ENTER → DVCA+ENTER → PF5 → CLEAR → MCOR+ENTER

## Test 1 : MCOR Input — boundary-values.txt (TRUNCATE)

| Metrique | Valeur |
|----------|--------|
| Champs   | 1 (Order Supply, row=19 col=18 len=1) |
| Wordlist | boundary-values.txt |
| Mode     | TRUNCATE |
| Payloads envoyes | 29/33 (4 skipped > len apres trunc) |
| Resultats | 29 ACCESSIBLE, 0 ABEND, 0 DENIED |
| Recoveries | 0 |
| Similarity | 1.0 pour tous |

## Test 2 : MCOR Hidden — hidden-tampering.txt

| Metrique | Valeur |
|----------|--------|
| Champs   | 1 (Purchaseable Y/N, row=14 col=19 len=1, hidden) |
| Wordlist | hidden-tampering.txt |
| Mode     | TRUNCATE |
| Payloads envoyes | 21/21 |
| Resultats | 21 ACCESSIBLE, 0 ABEND, 0 DENIED |
| Recoveries | 0 |
| Similarity | 1.0 pour tous |

## Observations

1. **Aucun ABEND provoque** — MCOR ne crashe pas sur les payloads testes. Le champ input (len=1) et le champ hidden sont tous deux tolerants.
2. **Similarity 1.0** — L'ecran ne change pas quel que soit le payload envoye dans le champ hidden. L'application ignore la valeur du champ Purchaseable cote serveur.
3. **Recovery non sollicitee** — Le mecanisme CLEAR+txn_code n'a pas ete teste en conditions reelles (pas d'ABEND). Il est valide par les tests unitaires (158 pass).
4. **Performance** — 29 payloads en ~25s (input), 21 payloads en ~40s (hidden). Fonctionnel.

## Conclusion

Le fuzzer fonctionne de bout en bout sur MCOR. La recovery simplifiee est implementee et testee unitairement. Pour valider la recovery en conditions reelles, il faudrait cibler une transaction qui ABEND effectivement (ex: injection longue sur un champ non-protege sans troncature).
