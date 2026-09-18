# Politique de sécurité

## Signaler une vulnérabilité

**Merci de ne pas ouvrir d'issue publique** pour toute faille touchant :
- la vérification de signature des documents de clé (indépendant,
  organisation, admin),
- la classification de confiance (risque de faux positif "Fiable"),
- une possibilité de contournement de la fenêtre de validité ou de la
  cohérence d'empreinte.

merci de prendre contact pour inclure :
- une description du problème et son impact potentiel,
- les étapes de reproduction ou un PoC minimal,
- la version/commit concerné.

## Délai de réponse visé

A définir

## Versions supportées

| Version | Supportée |
|---|---|
| dernière version publiée | ✅ |
| versions antérieures | ❌ |

## Périmètre

Ce dépôt couvre `chiffre-rsa-keystore`. Les vulnérabilités touchant
les primitives RSA bas niveau relèvent de
[`chiffre-rsa-core`](https://github.com/sebnoy/chiffre-rsa-core) ;
celles touchant le cœur symétrique relèvent de
[`chiffre-aes-core`](https://github.com/sebnoy/chiffre-aes-core) ;
celles touchant l'orchestration multi-destinataires relèvent de
`chiffre-rsa-enveloppe`, une crate séparée.
