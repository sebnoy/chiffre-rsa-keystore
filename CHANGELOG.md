# Changelog

## v1.2.1

Version de maintenance issue d'un audit selon le *Guide de développement
sécurisé en Rust* de l'ANSSI. **Aucun changement de code, de format de
signature ni d'API.**

- **Dépendance : tag `v1.2.1`** de `chiffre-rsa-core`, lui-même sur
  `chiffre-aes-core` v2.1.1. Une application qui utilise plusieurs de ces
  crates doit les prendre aux mêmes tags, faute de quoi les types partagés
  existent en deux versions incompatibles.
- **Dépendances** — `ctutils` 0.4.5 dans `Cargo.lock` (RUSTSEC-2026-0385 :
  opérations qui n'étaient pas en temps constant).
- **RUSTSEC-2023-0071 (« Marvin », crate `rsa`)** — aucune version corrigée
  n'existe. L'avis est ignoré dans `.cargo/audit.toml` avec sa justification
  (les opérations à clé privée s'exécutent sur l'appareil de l'utilisateur).
- **`scripts/verifier.sh`** — enchaîne `clippy` (avertissements refusés),
  `cargo audit` et les tests.
- Tests : les 22 tests passent inchangés ; `clippy` : aucun avertissement.

## v1.2.0

Ajoute une constante publique de version et suit `chiffre-rsa-core` v1.2.0. **Aucun changement de code, de format ni d'API.**

- **`pub const VERSION: &str = env!("CARGO_PKG_VERSION")`** — même raison que `chiffre_rsa_core::VERSION` (v1.2.0) : `enrollement-api`
  peut lire la version compilée au lieu de la recopier à la main.
- **Dépendance : tag `v1.2.0`** de `chiffre-rsa-core`.
- Tests : les 21 tests existants passent inchangés ; `clippy` : aucun avertissement ajouté.

## v1.1.0

Aligne la dépendance sur `chiffre-rsa-core` **v1.1.0** (elle-même sur
`chiffre_aes_core` v2.1.0). **Aucun changement de code, de format ni d'API**
de `chiffre-rsa-keystore`.

- **Dépendance : tag `v1.1.0`** de `chiffre-rsa-core`. Raison : les applications
  qui utilisent ce crate avec `chiffre_aes_core` v2.1.0 n'ont ainsi qu'**une
  seule** version de `chiffre_aes_core` dans leur graphe de dépendances.
- **Vérification** : les 21 tests du crate passent inchangés contre
  `chiffre-rsa-core` v1.1.0.
- `Cargo.lock` mis à jour en conséquence.

## v1.0.0

Première version publiée de `chiffre-rsa-keystore` — vérification et
classification de clés publiques RSA, construction/vérification de
documents de clé signés, sans jamais parser ni construire de JSON
elle-même.

- **Trois types de document de clé** — utilisateur indépendant,
  utilisateur d'organisation (processus en deux temps : signature
  utilisateur puis complétion par un admin), et clé admin.
- **Encodage déterministe pour signature** — un format fixe et
  documenté (voir [FORMAT.md](./FORMAT.md)) construit à partir de
  structs Rust typées, jamais d'une resérialisation JSON comme message
  à signer.
- **`check_validity_window`** — vérifie une fenêtre de validité
  (dates) indépendamment de la validité de la signature elle-même.
- **`KeyClassificationReport`** — produit des faits observables
  (signature valide/invalide, fenêtre de validité, cohérence
  d'empreinte), jamais un verdict de confiance automatique : **aucune
  persistance de confiance en v1** (cahier des charges du projet, §8,
  Décision 3), pas de TOFU.
- **Représentation d'empreinte pour l'humain** (`fingerprint_display`)
  — rendu uniquement, le contrat stable reste l'empreinte brute
  (`[u8; 32]`).
- **Feature `serde` optionnelle** — sérialisation JSON des structs
  exposées, à la charge de l'application appelante (ce crate ne
  construit jamais son propre JSON).
- **Dépendance à `chiffre-rsa-core` v1.0.0** (tag Git), elle-même
  dépendante de `chiffre-aes-core` v2.0.0 — voir
  [NOTICE.md](./NOTICE.md) pour l'état exact de cette chaîne de
  dépendances.
- Aucun audit de sécurité externe réalisé à ce jour.
