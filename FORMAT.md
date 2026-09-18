# Format des documents de clé et de l'encodage de signature

Ce document fait foi sur l'encodage binaire signé par ce crate,
indépendamment de l'implémentation. Voir aussi `INTERFACES.md` à la
racine du dépôt (conception d'origine, avec le contexte de chaque
décision) — ce fichier en est la spécification stabilisée, orientée
implémentation.

## 1. Principe : pas de JSON canonique

Le message signé n'est **jamais** une resérialisation JSON des champs du
document. Deux raisons : (1) aucun format JSON "canonique" n'est
garanti stable entre implémentations (ordre des clés, formatage des
nombres, échappement Unicode) ; (2) une simple concaténation de chaînes
sans délimiteur est ambiguë (`"ab"+"c"` produit les mêmes octets que
`"a"+"bc"`). L'encodage ci-dessous répond aux deux : ordre de champs fixe
codé en dur, chaque champ précédé de sa longueur.

## 2. Encodage d'un champ

```
u32be : longueur du champ encodé, en octets
N octets : le champ lui-même, encodé selon son type :
    - string                    → UTF-8 brut
    - i64 (timestamp Unix)      → 8 octets, big-endian
    - u32 (schema_version)      → 4 octets, big-endian
    - [u8; 16] (document_id)    → 16 octets bruts
    - [u8; 32] (empreinte)      → 32 octets bruts
    - Vec<u8> (DER, signature)  → octets bruts, tels quels
```

Chaque champ, **quel que soit son type**, reçoit ce même préfixe de
longueur (y compris les types de taille fixe comme `[u8; 16]`) — un seul
mécanisme d'encodage, pas de cas particulier.

## 3. `push_common_prefix` — préfixe commun aux trois documents

```
document_id           ([u8; 16])
schema_version         (u32, constante SCHEMA_VERSION = 1)
document_type          (string, une des 3 constantes DOCUMENT_TYPE_*)
signature_algorithm    (string, constante SIGNATURE_ALGORITHM = "RSA-PSS-SHA256")
created_at             (i64)
os                     (string)
version_chiffre_aes_core        (string)
version_chiffre_rsa_core        (string)
version_chiffre_rsa_enveloppe   (string)
version_chiffre_rsa_keystore    (string)
identity_firstname     (string)
identity_lastname      (string)
```

`schema_version`, `signature_algorithm` ne sont **jamais** des champs de
struct fournis par l'appelant — des constantes internes au crate,
incluses automatiquement, pour qu'il soit impossible de signer un
document avec une valeur incohérente. `document_type` est déterminé par
la fonction `encode_*`/`sign_*` appelée, jamais par l'appelant non plus.

## 4. Clé utilisateur indépendant

```
push_common_prefix(..., document_type = DOCUMENT_TYPE_INDEPENDENT_USER)
role                   (string)
key_public_format      (string, constante KEY_PUBLIC_FORMAT = "SPKI-DER-base64")
key_public             (Vec<u8>, DER SPKI — dérivé de la clé qui signe, jamais fourni séparément)
date_start             (i64)
date_end               (i64)
```

`user_signature = RsaKeyPair::sign(message)` où `message` est
l'encodage ci-dessus. Couvre **tous** les champs, y compris les dates.

## 5. Clé utilisateur d'organisation

### 5.1 Phase utilisateur (`user_signature`)

```
push_common_prefix(..., document_type = DOCUMENT_TYPE_ORG_USER)
role                   (string)
organisation           (string)
key_public_format      (string, constante KEY_PUBLIC_FORMAT)
key_public             (Vec<u8>, DER SPKI de la clé utilisateur)
```

Pas de dates, pas de champs admin — inconnus de l'utilisateur à ce stade.

### 5.2 Phase admin (`admin_signature`)

```
<< tout l'encodage §5.1 >>
date_start             (i64)
date_end               (i64)
admin_fingerprint      ([u8; 32] — dérivé de la clé admin qui signe, jamais fourni séparément)
admin_nom              (string)
user_signature         (Vec<u8> — la signature produite en §5.1, telle quelle)
```

`admin_signature = RsaKeyPair::sign(message)` (clé **admin**, pas la clé
utilisateur) où `message` est l'encodage complet ci-dessus. Le fait
d'inclure `user_signature` dans le message signé par l'admin lie les deux
signatures : impossible de faire rejouer une `user_signature` valide dans
un contexte admin différent sans que `admin_signature` ne le révèle
(puisque `user_signature` fait partie de ce qui est signé).

### 5.3 Pourquoi `admin_signature_valid` et `admin_fingerprint_consistent` sont deux vérifications distinctes

`admin_fingerprint` fait partie du message signé (§5.2) — donc si le
document est produit via `sign_org_admin_completion`, falsifier
`admin_fingerprint` après coup casse automatiquement `admin_signature`
(le message reconstruit à la vérification ne correspond plus à ce qui a
été signé). Mais rien n'empêche, en théorie, qu'une implémentation tierce
(bugguée ou malveillante) construise un message avec un
`admin_fingerprint` qui ne correspond **déjà pas**, au moment de signer,
à la clé qui signe réellement — un tel document aurait une signature
parfaitement valide (la clé admin a bien produit cette signature, sur ce
message précis) tout en étant *intrinsèquement* incohérent.

`admin_fingerprint_consistent` détecte précisément ce cas : il compare
`record.admin_fingerprint` (la valeur déclarée, lue telle quelle depuis
le document) à l'empreinte réelle de `trusted_admin_key` (la clé fournie
par l'application, obtenue hors bande). Un document honnête, produit via
`sign_org_admin_completion`, aura toujours les deux vérifications au vert
simultanément — un document construit "à la main" en contournant cette
fonction peut faire diverger les deux (voir le test
`org_user_self_inconsistent_admin_fingerprint_is_detected` dans
`src/lib.rs` pour un exemple construit explicitement).

## 6. Clé admin

```
push_common_prefix(..., document_type = DOCUMENT_TYPE_ADMIN)
organisation           (string)
key_public_format      (string, constante KEY_PUBLIC_FORMAT)
key_public             (Vec<u8>, DER SPKI de la clé admin — nommé "admin_key_public" côté JSON applicatif)
date_start             (i64)
date_end               (i64)
```

`signature = RsaKeyPair::sign(message)` — auto-signature, preuve de
possession de la clé privée admin. Pas de `role`, pas
d'`admin_fingerprint` (n'a pas de sens : la clé admin est elle-même la
racine de confiance).

## 7. Correspondance côté application (rappel)

Ce crate ne construit ni ne lit de JSON — c'est à l'application de
sérialiser les structs `*Fields`/`*Record` et les constantes publiques
(`SCHEMA_VERSION`, `DOCUMENT_TYPE_*`, `SIGNATURE_ALGORITHM`,
`KEY_PUBLIC_FORMAT`) dans son propre schéma JSON, et de désérialiser dans
l'autre sens avant d'appeler `classify_*`. Le nom exact des champs JSON
(`key_public` vs `admin_key_public`, `date.start` vs `date_start`, etc.)
est une décision de l'application, tant que la correspondance avec les
structs Rust ci-dessus reste correcte — ce fichier spécifie l'encodage
*signé*, pas le schéma JSON lui-même.

## 8. Statut

Document à jour à la date de rédaction (crate v1.0.0). Toute
modification de l'ordre des champs, de leur encodage, ou des constantes
(`SCHEMA_VERSION` en particulier) casse la vérification de tout document
déjà signé — un changement de `SCHEMA_VERSION` est donc la bonne façon de
signaler explicitement une évolution de cet encodage, plutôt qu'une
modification silencieuse.
