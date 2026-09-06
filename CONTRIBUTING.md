# Contribuer

Merci de l'intérêt porté à ce projet !

## Avant de proposer une PR

- **Ce crate ne doit jamais prendre de décision de confiance
  automatique** (cahier des charges §8, Décision 2). Toute PR qui
  introduirait un mécanisme d'épinglage automatique, de TOFU, ou un
  quelconque stockage persistant de confiance sort du périmètre de la
  v1 (Décision 3) — à discuter d'abord en issue, pas directement en PR.
- `classify_public_key` doit rester **infaillible** et ne rapporter que
  des faits observables, jamais un verdict ("digne de confiance" /
  "pas digne de confiance"). Si votre changement a besoin d'exprimer un
  jugement, c'est probablement à l'application appelante de le faire à
  partir du rapport, pas à ce crate.
- `cargo test` (avec et sans `--features serde`) doit passer.
- `cargo clippy --all-features -- -D warnings` doit passer.
- Toute nouvelle dépendance doit être en licence permissive (MIT,
  Apache-2.0, BSD, Zlib...). Mettez à jour [NOTICE.md](./NOTICE.md).

## `KeyClassificationReport` est `#[non_exhaustive]`

N'importe quel nouveau champ est un ajout non cassant grâce à
`#[non_exhaustive]` — mais gardez à l'esprit qu'un champ existant qui
change de sens (pas seulement de type) reste un changement cassant même
avec cet attribut. Documentez tout changement de sémantique d'un champ
existant aussi clairement que dans [FORMAT.md](./FORMAT.md).

## Format JSON à métadonnées (futur)

Si vous travaillez sur l'extraction depuis un futur document JSON à
métadonnées authentifiées (cahier des charges §6) : cette évolution doit
rester entièrement confinée à ce crate, sans aucun impact sur
`chiffre-rsa-core` ni `chiffre-rsa-enveloppe`. `classify_public_key`
elle-même ne devrait pas avoir besoin de changer de signature — seule une
nouvelle fonction d'extraction en amont (qui produit une `RsaPublicKey`
à partir du document) devrait être nécessaire.

## Licence des contributions

En soumettant une contribution, vous acceptez qu'elle soit publiée sous
la même double licence MIT OR Apache-2.0 que le reste du projet.
