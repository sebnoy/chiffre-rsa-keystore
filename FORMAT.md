# Ce que produit `chiffre-rsa-keystore`

Ce crate ne définit aucun format de fichier ni de clé — la clé publique
reste, en v1, l'encodage SPKI produit par `chiffre-rsa-core` (voir son
propre `FORMAT.md` §2). Ce document spécifie le contenu du rapport de
classification et le rendu d'empreinte que ce crate ajoute par-dessus.

## 1. `KeyClassificationReport`

| Champ | Type | Origine | Signification |
|---|---|---|---|
| `fingerprint` | `[u8; 32]` | `RsaPublicKey::fingerprint()`, telle quelle | SHA-256 du DER SPKI de la clé seule. |
| `key_size_bits` | `u32` | `RsaPublicKey::key_size_bits()`, telle quelle | Taille du module RSA. 4096 pour toute clé produite par `RsaKeyPair::generate`, mais pas forcément pour une clé chargée depuis un PEM externe. |
| `algorithm` | `&'static str` | Fixe : `"RSA (SPKI rsaEncryption, PKCS#1)"` | Le seul algorithme que `chiffre-rsa-core` sait produire ou charger en v1. |
| `public_key_well_formed` | `bool` | Toujours `true` en v1 | Voir §2. |

Structure `#[non_exhaustive]`, jamais construite par littéral direct chez
l'appelant — seule `classify_public_key` la produit, ce qui permet
d'ajouter des champs sans casser la compatibilité (même pattern que
`ExtractionLimits` côté `chiffre_aes_core`).

## 2. Pourquoi `public_key_well_formed` est toujours `true` en v1

`classify_public_key` prend une `&RsaPublicKey` déjà construite. Or une
`RsaPublicKey` ne peut exister, dans l'API actuelle de
`chiffre-rsa-core`, qu'en sortie de `RsaKeyPair::public_key()` ou de
`RsaPublicKey::from_spki_pem` — et ce dernier a déjà rejeté (via
`RsaKeysError::InvalidEncoding`) tout DER malformé ou toute clé dont
l'exposant public ne satisferait pas les contraintes minimales
qu'impose la crate `rsa` (impair, ≥ 3) lors du parsing. Il n'existe donc,
en v1, aucun chemin qui produirait une `RsaPublicKey` structurellement
défectueuse : le champ est **honnête mais non discriminant** pour
l'instant.

Il devient réellement utile le jour où ce crate gagnera une fonction
d'extraction depuis un document potentiellement corrompu (format JSON à
métadonnées, cahier des charges §6) : cette fonction future pourra
vouloir produire *quand même* un rapport pour une clé partiellement
lisible mais défectueuse (plutôt que de ne rien renvoyer), avec ce champ
à `false` — sans que la signature de `classify_public_key` elle-même
n'ait besoin de changer.

## 3. `fingerprint_display`

```
entrée  : [u8; 32]
sortie  : String, hex majuscule groupé par 4, séparé par des espaces
longueur: 64 caractères hex + 15 espaces = 79 caractères, toujours
```

Exemple (32 octets valant `0xAB`) :
```
ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB
```

Ce format n'est **pas** un contrat de fichier ou d'interopérabilité —
c'est un rendu pour vérification humaine (cahier des charges §8,
Décision 2 : vérification manuelle). Rien n'empêche une application
d'utiliser un autre rendu (groupes de 2, minuscule, style SSH
`SHA256:base64`...) directement à partir de l'empreinte brute ; cette
fonction n'est qu'une commodité par défaut.

## 4. Statut

Document à jour à la date de rédaction (crate v0.1.0). Toute évolution du
format de clé publique vers un document JSON à métadonnées
authentifiées (cahier des charges §6) sera documentée ici le moment
venu — sans jamais modifier l'empreinte elle-même (§7 du cahier des
charges : l'empreinte porte uniquement sur l'encodage SPKI de la clé,
jamais sur l'habillage qui l'entoure).
