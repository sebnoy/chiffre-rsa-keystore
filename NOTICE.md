# Notices tierces

⚠️ Point de départ manuel, à régénérer à chaque changement de
dépendances (`cargo about` ou `cargo license`).

## Dépendances directes

| Crate | Licence |
|---|---|
| chiffre-rsa-core | MIT OR Apache-2.0 (v1.0.0, tag Git — voir sa propre `NOTICE.md`) |
| serde (optionnelle, feature `serde`) | MIT OR Apache-2.0 |

## Dépendances de développement uniquement (tests)

| Crate | Licence |
|---|---|
| serde_json | MIT OR Apache-2.0 |

## Dépendances transitives

Toutes celles de `chiffre-rsa-core` (voir sa `NOTICE.md`) s'appliquent
par transitivité. Aucune dépendance transitive supplémentaire propre à
ce crate. À reconfirmer avec `cargo about`/`cargo license` avant toute
release.
