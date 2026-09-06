# chiffre-rsa-keystore

Vérification et classification de clés publiques RSA. Dépend uniquement
de `chiffre-rsa-core`. **Aucune persistance de confiance en v1** (cahier
des charges du projet, §8, Décision 3).

```rust
pub fn classify_public_key(key: &RsaPublicKey) -> KeyClassificationReport;
pub fn fingerprint_display(fingerprint: &[u8; 32]) -> String;
```

# Ce que ce crate fait — et ne fait pas

**Fait** : produit des **faits observables** sur une clé publique déjà
chargée (empreinte, taille, algorithme, validité structurelle) et un
rendu lisible d'une empreinte pour vérification humaine.

**Ne fait pas, et ne fera jamais en v1** :
- **Aucune décision de confiance automatique.** Pas de TOFU
  (trust-on-first-use), pas de mini-PKI, pas d'épinglage. C'est à
  l'application appelante de lire un `KeyClassificationReport`, en
  général après une vérification humaine (comparaison d'empreinte par un
  canal indépendant — appel téléphonique, QR code en personne, etc.),
  avant de construire un `chiffre_rsa_enveloppe::RecipientRef`.
- **Aucun stockage persistant.** Ni des clés, ni des décisions de
  confiance déjà prises. Conséquence directe de l'absence de TOFU/PKI.
- **Aucune vérification de métadonnées authentifiées.** Le format de clé
  publique reste, en v1, un encodage SPKI nu — voir
  [FORMAT.md](./FORMAT.md) pour l'évolution prévue mais non conçue à ce
  stade.

# `KeyClassificationReport`

```rust
#[non_exhaustive]
pub struct KeyClassificationReport {
    pub fingerprint: [u8; 32],
    pub key_size_bits: u32,
    pub algorithm: &'static str,
    pub public_key_well_formed: bool,
}
```

`#[non_exhaustive]` : impossible à construire par littéral direct chez
l'appelant, uniquement via `classify_public_key`. Ça permet d'ajouter des
champs plus tard (un résultat de vérification de métadonnées, un statut
de révocation, une fois le format JSON futur en place) sans casser le
code appelant existant.

`public_key_well_formed` est **toujours `true` en v1** : une
`RsaPublicKey` n'existe que si `chiffre-rsa-core` a déjà réussi à la
parser et à la valider structurellement (encodage SPKI correct, exposant
public impair et ≥ 3 — voir la validation interne de la crate `rsa`).
Le champ existe dès maintenant plutôt que d'être ajouté après coup, pour
le jour où une extraction depuis un document potentiellement corrompu
(format JSON futur, §6 du cahier des charges) devra produire un rapport
même pour une clé partiellement défectueuse plutôt que de ne rien
renvoyer.

`key_size_bits` n'est **pas** vérifié contre une valeur attendue (4096) :
c'est un fait, pas un verdict. Une application qui veut refuser toute clé
qui ne fait pas 4096 bits applique cette politique elle-même à partir de
ce champ — ce crate ne la lui impose pas.

Feature `serde` (optionnelle) : dérive `Serialize` pour export/audit —
jamais comme contrat principal (voir cahier des charges §9).

# Représentation d'une empreinte (`fingerprint_display`)

Hexadécimal majuscule, groupé par 4 caractères façon empreinte PGP :

```
ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB
```

C'est un rendu pour l'humain, pas un format de fichier : le contrat
stable reste l'empreinte brute (`[u8; 32]`), produite par
`chiffre_rsa_core::RsaPublicKey::fingerprint`.

# Tests

```bash
cargo test                    # sans serde
cargo test --features serde   # avec sérialisation JSON
```

# Compilation

Mêmes prérequis que `chiffre-rsa-core`/`chiffre-rsa-enveloppe` :
toolchain Rust ≥ 1.85 (via la dépendance transitive à `chiffre_aes_core`
côté `chiffre-rsa-core`).

# Licence

MIT OR Apache-2.0.
