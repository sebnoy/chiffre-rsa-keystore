# Changelog

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
