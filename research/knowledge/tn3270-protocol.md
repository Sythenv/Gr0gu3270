# Protocole TN3270 — Reference Technique

## Structure d'un flux 3270

### Commandes d'ecriture (serveur → client)
| Byte | Commande | Description |
|------|----------|-------------|
| 0x01 / 0xF1 | Write (W) | Ecrit dans le buffer |
| 0x05 / 0xF5 | Erase/Write (EW) | Efface puis ecrit |
| 0x7E / 0x6E | Erase/Write Alternate (EWA) | Efface ecran alternatif |

### Orders (commandes dans le flux)
| Byte | Order | Parametres | Description |
|------|-------|-----------|-------------|
| 0x11 | SBA | 2 bytes (adresse buffer) | Positionne le curseur |
| 0x1D | SF | 1 byte (attribut) | Debut de champ |
| 0x29 | SFE | count + pairs type/valeur | Debut de champ etendu |
| 0x2C | MF | count + pairs type/valeur | Modification de champ |
| 0x13 | IC | aucun | Position curseur insertion |
| 0x28 | SA | 2 bytes (type + valeur) | Set Attribute |
| 0x3C | RA | 3 bytes (adresse + char) | Repeat to Address |
| 0x12 | EUA | 2 bytes (adresse) | Erase Unprotected to Address |

### Adressage buffer (SBA)
- **12-bit** : bits 7-6 du 1er octet = 01/10/11, adresse = 6 bits de chaque octet
- **14-bit** : bits 7-6 du 1er octet = 00, adresse = 6 bits 1er + 8 bits 2eme
- Ecran standard : 24 lignes x 80 colonnes = 1920 positions

### Attributs de champ (SF byte)
| Bits | Signification |
|------|--------------|
| Bit 5 (0x20) | Protected |
| Bit 4 (0x10) | Numeric only |
| Bits 3-2 (0x0C) | Display : 00=normal, 01=normal, 10=high intensity, 11=hidden |
| Bit 0 (0x01) | Modified Data Tag |

### TN3270E vs TN3270
- TN3270E ajoute un header de 5 bytes avant chaque PDU
- Detection : byte[2] du premier echange = 0x28 (TN3270E)
- Le header TN3270E : DATA_TYPE(1) + REQUEST(1) + RESPONSE(1) + SEQ(2)

### AID bytes (client → serveur)
| AID | Byte | Notes |
|-----|------|-------|
| ENTER | 0x7D | Soumission standard |
| CLEAR | 0x6D | Efface ecran, short-read (pas de donnees) |
| PA1-3 | 0x6C/0x6E/0x6B | Short-read |
| PF1-12 | 0xF1-0xF9, 0x7A-0x7C | Touches fonction |

## Pertinence pentest

- Les champs hidden (bits 3-2 = 11) sont la cible principale de hack3270
- L'injection se fait en remplacant les donnees entre le preamble et postamble du flux client
- Le parsing screen map (PR2) decode tous les orders pour cartographier les champs
