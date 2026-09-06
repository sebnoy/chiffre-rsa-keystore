//! `chiffre-rsa-keystore` — vérification et classification de clés
//! publiques RSA. Dépend uniquement de `chiffre-rsa-core`. Voir le
//! cahier des charges, Partie 2 §5.
//!
//! **Ce crate ne prend et ne prendra jamais de décision de confiance
//! automatique** (cahier des charges §8, Décision 2 : vérification
//! manuelle). `classify_public_key` produit des **faits observables**
//! sur une clé — jamais un verdict "faire confiance ou non". C'est
//! toujours à l'application appelante de lire un
//! [`KeyClassificationReport`] et de décider, en général après une
//! vérification humaine (comparaison d'empreinte par un canal
//! indépendant, par exemple), avant de construire un
//! `chiffre_rsa_enveloppe::RecipientRef`. Aucun stockage persistant de
//! confiance n'existe en v1 (cahier des charges §8, Décision 3).
//!
//! Le format de clé publique lui-même n'évolue pas ici en v1 : c'est un
//! encodage SPKI standard produit par `chiffre-rsa-core`, rien de plus.
//! Une évolution future vers un document JSON à métadonnées authentifiées
//! (identité déclarée, validité, signature) est anticipée mais **pas
//! conçue** dans cette version — voir le cahier des charges §6. Le jour
//! où elle arrivera, elle sera entièrement portée par ce crate : une
//! nouvelle fonction d'extraction en amont produira une `RsaPublicKey` à
//! partir du document, et `classify_public_key` n'aura pas besoin de
//! changer de signature.

use chiffre_rsa_core::RsaPublicKey;

/// Réservé aux opérations futures potentiellement faillibles de ce crate
/// (extraction d'une clé depuis un document JSON à métadonnées,
/// vérification d'authenticité de ces métadonnées — cahier des charges
/// §6). Aucune fonction de la v1 n'en a besoin : `classify_public_key`
/// prend déjà une `RsaPublicKey` garantie structurellement valide par
/// construction (elle n'existe que si `chiffre-rsa-core` a réussi à la
/// parser), et ne peut donc pas échouer. Type non habité pour l'instant,
/// volontairement présent dès maintenant plutôt qu'ajouté après coup, dans
/// le même esprit qu'un enum d'erreur par crate (cahier des charges §6
/// partie 2, "Un enum par crate").
#[derive(Debug)]
#[non_exhaustive]
pub enum KeystoreError {}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}

impl std::error::Error for KeystoreError {}

/// Rapport de classification d'une clé publique — des faits, jamais un
/// verdict. `#[non_exhaustive]` : de nouveaux champs pourront s'ajouter
/// plus tard (par ex. un résultat de vérification de métadonnées une
/// fois le format JSON futur en place) sans casser le code appelant, qui
/// ne peut de toute façon pas construire cette struct par littéral direct
/// — seule [`classify_public_key`] la produit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct KeyClassificationReport {
    /// SHA-256 de l'encodage DER SPKI de la clé — voir
    /// `chiffre_rsa_core::RsaPublicKey::fingerprint`. Stable
    /// indépendamment de toute évolution future du format de
    /// distribution de la clé (cahier des charges §7).
    pub fingerprint: [u8; 32],
    /// Taille en bits du module RSA. Une valeur différente de 4096 (le
    /// seul choix produit par `RsaKeyPair::generate`) n'est **pas**
    /// rejetée ici — voir la doc de
    /// `chiffre_rsa_core::RsaPublicKey::key_size_bits` : ce crate donne
    /// le fait, l'application décide de sa propre politique
    /// d'acceptation.
    pub key_size_bits: u32,
    /// Identifiant textuel de l'algorithme. Fixe en v1 (le seul algorithme
    /// que `chiffre-rsa-core` sait produire ou charger) — champ présent
    /// dès maintenant pour ne pas casser l'appelant le jour où un second
    /// algorithme (ECIES/X25519, explicitement hors périmètre v1, voir
    /// cahier des charges §11) serait ajouté.
    pub algorithm: &'static str,
    /// `true` si la clé a passé les vérifications structurelles propres à
    /// ce crate (voir `classify_public_key`). Dans cette version,
    /// toujours `true` : une `RsaPublicKey` n'existe que si
    /// `chiffre-rsa-core` a déjà réussi à la parser et valider
    /// structurellement (encodage SPKI, exposant public impair et ≥ 3).
    /// Ce champ devient réellement discriminant le jour où une clé
    /// pourra être *rapportée* malgré un défaut plutôt que rejetée
    /// d'emblée — par exemple lors d'une future extraction depuis un
    /// document JSON partiellement corrompu (cahier des charges §6) : on
    /// pourra alors vouloir produire un rapport disant "voici ce qu'on a
    /// pu lire, et voici pourquoi il ne faut pas s'y fier" plutôt que de
    /// ne rien renvoyer du tout.
    pub public_key_well_formed: bool,
}

/// Produit un rapport de classification pour `key` — des faits
/// observables (empreinte, taille, algorithme, validité structurelle),
/// jamais une décision de confiance. Ne peut pas échouer : `key` est déjà
/// une `RsaPublicKey` structurellement valide par construction.
pub fn classify_public_key(key: &RsaPublicKey) -> KeyClassificationReport {
    KeyClassificationReport {
        fingerprint: key.fingerprint(),
        key_size_bits: key.key_size_bits(),
        algorithm: "RSA (SPKI rsaEncryption, PKCS#1)",
        public_key_well_formed: true,
    }
}

/// Représentation lisible d'une empreinte de clé publique, pour
/// affichage à un humain en vue d'une vérification par un canal
/// indépendant (cahier des charges §8, Décision 2). Hexadécimal
/// majuscule, groupé par 4 caractères façon empreinte PGP — ni la seule
/// représentation possible ni un format figé côté fichier (l'empreinte
/// elle-même, `[u8; 32]`, reste le seul contrat stable ; ce n'est qu'un
/// rendu pour l'humain).
///
/// ```
/// # use chiffre_rsa_keystore::fingerprint_display;
/// let fp = [0xABu8; 32];
/// assert_eq!(
///     fingerprint_display(&fp),
///     "ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB"
/// );
/// ```
pub fn fingerprint_display(fingerprint: &[u8; 32]) -> String {
    let hex: String = fingerprint.iter().map(|b| format!("{b:02X}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("hex ASCII valide"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chiffre_rsa_core::RsaKeyPair;
    use std::sync::OnceLock;

    fn test_key_a() -> &'static RsaKeyPair {
        static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
        KEY.get_or_init(|| RsaKeyPair::generate().expect("génération de clé A"))
    }

    fn test_key_b() -> &'static RsaKeyPair {
        static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
        KEY.get_or_init(|| RsaKeyPair::generate().expect("génération de clé B"))
    }

    #[test]
    fn classify_reports_correct_key_size() {
        let report = classify_public_key(&test_key_a().public_key());
        assert_eq!(report.key_size_bits, 4096);
    }

    #[test]
    fn classify_reports_matching_fingerprint() {
        let public = test_key_a().public_key();
        let report = classify_public_key(&public);
        assert_eq!(report.fingerprint, public.fingerprint());
    }

    #[test]
    fn classify_reports_well_formed_for_a_freshly_generated_key() {
        let report = classify_public_key(&test_key_a().public_key());
        assert!(report.public_key_well_formed);
    }

    #[test]
    fn classify_reports_non_empty_algorithm() {
        let report = classify_public_key(&test_key_a().public_key());
        assert!(!report.algorithm.is_empty());
    }

    #[test]
    fn classify_reports_differ_between_distinct_keys() {
        let report_a = classify_public_key(&test_key_a().public_key());
        let report_b = classify_public_key(&test_key_b().public_key());
        assert_ne!(report_a.fingerprint, report_b.fingerprint);
    }

    #[test]
    fn fingerprint_display_is_grouped_uppercase_hex() {
        let fingerprint = test_key_a().public_key().fingerprint();
        let displayed = fingerprint_display(&fingerprint);

        // 32 octets -> 64 caractères hex + 15 espaces (groupes de 4).
        assert_eq!(displayed.len(), 64 + 15);
        assert!(displayed
            .chars()
            .all(|c| c == ' ' || c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));

        // Round-trip : en retirant les espaces et en reparsant le hex, on
        // doit retrouver exactement les octets d'origine.
        let recombined: Vec<u8> = displayed
            .chars()
            .filter(|c| *c != ' ')
            .collect::<String>()
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
            })
            .collect();
        assert_eq!(recombined, fingerprint.to_vec());
    }

    #[test]
    fn fingerprint_display_differs_between_distinct_fingerprints() {
        let fp_a = test_key_a().public_key().fingerprint();
        let fp_b = test_key_b().public_key().fingerprint();
        assert_ne!(fingerprint_display(&fp_a), fingerprint_display(&fp_b));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn key_classification_report_serializes_expected_fields() {
        let report = classify_public_key(&test_key_a().public_key());
        let json = serde_json::to_value(&report).expect("sérialisation JSON");

        assert!(json.get("fingerprint").is_some());
        assert_eq!(json["key_size_bits"], 4096);
        assert_eq!(json["algorithm"], "RSA (SPKI rsaEncryption, PKCS#1)");
        assert_eq!(json["public_key_well_formed"], true);
    }
}
