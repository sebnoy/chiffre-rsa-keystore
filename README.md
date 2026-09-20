# chiffre-rsa-keystore

Vérification et classification de clés publiques RSA, et
construction/vérification de documents de clé signés (indépendant,
organisation, admin). Dépend uniquement de `chiffre-rsa-core`. **Aucune
persistance de confiance en v1** (cahier des charges du projet, §8,
Décision 3). Conception détaillée : voir `INTERFACES.md` à la racine du
dépôt.

**Ce crate ne parse ni ne construit jamais de JSON.** Il reçoit/rend des
structs Rust typées ; c'est à l'application d'assembler son propre JSON à
partir de ces structs et des constantes publiques exposées ici
(`SCHEMA_VERSION`, `DOCUMENT_TYPE_*`, `SIGNATURE_ALGORITHM`,
`KEY_PUBLIC_FORMAT`) — jamais l'inverse.

# Auteur et statut du projet

Ce crate atteint sa v1.1.0. Il s'appuie sur `chiffre-rsa-core` v1.1.0
(tagué), lui-même dépendant de `chiffre-aes-core` v2.1.0 — voir
[NOTICE.md](./NOTICE.md) pour l'état exact de cette chaîne de
dépendances.

Aucun audit de sécurité externe n'a été réalisé à ce jour. La
conception suit les mêmes principes de rigueur que le reste de
l'écosystème `chiffre-*` (choix documentés et justifiés, tests contre
des vecteurs indépendants), mais ça ne remplace pas une revue par un
tiers qualifié avant tout usage en production.

## Documentation technique

Voir [FORMAT.md](./FORMAT.md) pour l'encodage déterministe utilisé
pour la signature des documents de clé (les trois types : indépendant,
organisation, admin), et `INTERFACES.md` à la racine du dépôt pour la
conception détaillée.

# Ce que ce crate fait — et ne fait pas

**Fait** : produit des **faits observables**, jamais un verdict de
confiance — signature valide/invalide, fenêtre de validité, cohérence
d'empreinte. Construit les documents de clé signés des trois types
(indépendant, organisation, admin) selon l'encodage déterministe fixé
ci-dessous.

**Ne fait pas, et ne fera jamais en v1** :
- **Aucune décision de confiance automatique.** Pas de TOFU, pas de
  mini-PKI, pas d'épinglage. C'est à l'application de lire un
  `KeyClassificationReport` et de décider, en général après vérification
  humaine, avant de construire un `chiffre_rsa_enveloppe::RecipientRef`.
- **Aucun stockage persistant.** Ni des clés, ni des décisions de
  confiance déjà prises.
- **Aucun parsing/écriture JSON.** Voir ci-dessus.

# Les trois types de document

Un champ unique `document_type` (une des trois constantes
`DOCUMENT_TYPE_INDEPENDENT_USER`/`DOCUMENT_TYPE_ORG_USER`/
`DOCUMENT_TYPE_ADMIN`) distingue les documents — jamais une combinaison
de booléens, pour qu'aucun état incohérent ne soit représentable.
Détail complet des champs par type : voir `INTERFACES.md` §1.

## Clé utilisateur indépendant

```rust
let fields = IndependentUserFields { common, role, date_start, date_end };
let signature = sign_independent_user(&fields, &key_pair);
// ... l'app assemble le JSON avec `fields`, la clé publique de `key_pair`
//     (via `key_pair.public_key().to_spki_der()`), et `signature` ...

let report = classify_independent_user(&fields, &public_key, &signature, now);
```

`user_signature` couvre **tous** les champs, y compris `date_start`/
`date_end` — intégrité totale, aucune modification possible sans
invalider la signature.

## Clé utilisateur d'organisation — processus en deux temps

```rust
// 1. Côté utilisateur : signe un document PARTIEL (pas encore de dates,
//    pas encore de champs admin).
let user_fields = OrgUserFields { common, role, organisation };
let user_signature = sign_org_user(&user_fields, &user_key_pair);
// → transmission du document partiel à l'admin (canal hors périmètre)

// 2. Côté admin : complète et signe.
let admin_fields = OrgAdminSigningFields {
    user: user_fields,
    date_start, date_end,
    admin_nom,
    user_signature,           // liée à l'intérieur de admin_signature
};
let admin_signature = sign_org_admin_completion(
    &admin_fields,
    &user_public_key,          // la clé de l'utilisateur, PAS celle de l'admin
    &admin_key_pair,
);
// `admin_fingerprint` est dérivé de `admin_key_pair` elle-même — jamais
// fourni séparément, impossible de le falsifier par construction.

// Lecture/vérification d'un document final :
let record = OrgUserKeyRecord { user, date_start, date_end, admin_fingerprint, admin_nom };
let report = classify_org_user(
    &record, &public_key, &user_signature, &admin_signature,
    Some(&trusted_admin_public_key),  // obtenue hors bande, JAMAIS extraite du document
    now,
);
```

`admin_signature` couvre tout ce que couvrait `user_signature`, plus
`date_start`/`date_end`/`admin_fingerprint`/`admin_nom`, plus
`user_signature` elle-même (lie les deux signatures ensemble).

`trusted_admin_key: Option<&RsaPublicKey>` : si `None`, le rapport
renvoie `admin_signature_valid`/`admin_fingerprint_consistent` à `None`
plutôt que `Some(false)` — l'absence de clé de confiance fournie n'est
pas en soi un défaut du document.

`admin_signature_valid` et `admin_fingerprint_consistent` sont deux
vérifications **distinctes**, pas redondantes : une signature peut être
authentique (produite par une vraie clé admin) tout en portant sur un
`admin_fingerprint` incohérent avec cette même clé, si le document n'a
pas été produit via `sign_org_admin_completion` (qui garantit cette
cohérence par construction) — voir `FORMAT.md` pour l'exemple exact.

## Clé admin

```rust
let fields = AdminKeyFields { common, organisation, date_start, date_end };
let signature = sign_admin_key(&fields, &admin_key_pair);
// auto-signature (preuve de possession), couvre l'intégralité des champs

let report = classify_admin_key(&fields, &admin_public_key, &signature, now);
```

# Encodage déterministe pour signature

Aucune resérialisation JSON n'est utilisée comme message à signer (risque
de canonicalisation — ordre des clés, formatage des nombres, échappement
Unicode). Encodage binaire maison, longueur-préfixée
(`u32be` + octets, pour chaque champ, dans un ordre fixe codé en dur par
fonction interne `encode_*`) — voir `INTERFACES.md` §3 pour la
spécification complète, champ par champ, de chaque portée de signature.
Ces fonctions d'encodage sont **privées** : ce détail n'est jamais exposé
à l'appelant, qui ne manipule que des `RsaKeyPair`/`RsaPublicKey` et les
structs de champs ci-dessus.

# `check_validity_window`

```rust
pub fn check_validity_window(start: i64, end: i64, now: i64) -> ValidityStatus; // NotYetValid | Valid | Expired
```

Fait léger, sans aucune vérification de signature — utilisé en interne
par les fonctions `classify_*`, et directement exposé pour l'usage décrit
dans `INTERFACES.md` §7 : avant de créer une archive, l'application
vérifie la fenêtre de validité de son **propre** document déjà signé,
sans avoir à re-signer quoi que ce soit.

`now` est toujours un paramètre explicite, jamais lu depuis l'horloge
système en interne — rend chaque fonction testable de façon
déterministe.

# `KeyClassificationReport`

`#[non_exhaustive]`, jamais construite par littéral direct chez
l'appelant. Champs de base (toujours renseignés) : `fingerprint`,
`key_size_bits`, `algorithm`, `public_key_well_formed`. Champs liés à un
document (`Option`, `None` quand non applicable — en particulier,
toujours `None` en sortie de `classify_public_key`, qui ne connaît aucun
document) : `signature_valid`, `validity`, `admin_signature_valid`,
`admin_fingerprint_consistent`.

`key_size_bits` n'est **pas** vérifié contre une valeur attendue (4096) :
c'est un fait, pas un verdict. Une application qui veut refuser toute clé
qui ne fait pas 4096 bits applique cette politique elle-même à partir de
ce champ.

Feature `serde` (optionnelle) : dérive `Serialize` pour export/audit —
jamais comme contrat principal.

# Représentation d'une empreinte (`fingerprint_display`)

Hexadécimal majuscule, groupé par 4 caractères façon empreinte PGP :

```
ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB
```

Rendu pour l'humain, pas un format de fichier : le contrat stable reste
l'empreinte brute (`[u8; 32]`).

# Tests

```bash
cargo test                    # sans serde
cargo test --features serde   # avec sérialisation JSON
```

# Compilation

Mêmes prérequis que `chiffre-rsa-core`/`chiffre-rsa-enveloppe` :
toolchain Rust ≥ 1.85 (via la dépendance transitive à `chiffre_aes_core`
côté `chiffre-rsa-core`).

# Transparence et réutilisation

Comme le reste de l'écosystème `chiffre-*`, ce crate documente ses
choix (y compris ceux qu'il ne fait pas, cf. "Ce que ce crate fait — et
ne fait pas" ci-dessus) pour que quiconque l'évalue ou le réutilise
puisse le faire en connaissance de cause, sans avoir à relire le code
source pour en retrouver les hypothèses.

# Licence

MIT OR Apache-2.0.
