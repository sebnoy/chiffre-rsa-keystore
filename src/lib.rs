//! `chiffre-rsa-keystore` — vérification et classification de clés
//! publiques RSA, et construction/vérification des documents de clé
//! signés (indépendant, organisation, admin). Dépend uniquement de
//! `chiffre-rsa-core`. Voir le cahier des charges, Partie 2 §5, et
//! `INTERFACES.md` pour la conception détaillée des documents.
//!
//! **Ce crate ne prend et ne prendra jamais de décision de confiance
//! automatique** (cahier des charges §8, Décision 2 : vérification
//! manuelle). Les fonctions `classify_*` produisent des **faits
//! observables** (signature valide, fenêtre de validité, cohérence
//! d'empreinte) — jamais un verdict "faire confiance ou non". C'est
//! toujours à l'application appelante de lire un
//! [`KeyClassificationReport`] et de décider, en général après une
//! vérification humaine (comparaison d'empreinte par un canal
//! indépendant, par exemple), avant de construire un
//! `chiffre_rsa_enveloppe::RecipientRef`. Aucun stockage persistant de
//! confiance n'existe en v1 (cahier des charges §8, Décision 3).
//!
//! **Ce crate ne parse ni ne construit jamais de JSON.** Il reçoit/rend
//! des structs Rust typées ; c'est à l'application de faire l'assemblage
//! JSON de son côté (cahier des charges §9 : jamais du JSON en interface
//! principale). Les constantes publiques (`SCHEMA_VERSION`,
//! `DOCUMENT_TYPE_*`, `SIGNATURE_ALGORITHM`, `KEY_PUBLIC_FORMAT`) donnent
//! à l'application les valeurs exactes à écrire dans son JSON pour rester
//! cohérente avec ce qui a été signé.

use chiffre_rsa_core::{RsaKeyPair, RsaPublicKey};

/// Version de ce crate (`Cargo.toml`) — même usage que `chiffre_rsa_core::VERSION`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version du schéma de document de clé (distincte des versions de
/// crate, qui sont des métadonnées déclaratives parmi d'autres — voir
/// `CommonFields`). Fait partie de l'encodage signé : un changement de
/// structure de document doit s'accompagner d'un changement de cette
/// valeur.
pub const SCHEMA_VERSION: u32 = 1;

pub const DOCUMENT_TYPE_INDEPENDENT_USER: &str = "cle_utilisateur_independant";
pub const DOCUMENT_TYPE_ORG_USER: &str = "cle_utilisateur_organisation";
pub const DOCUMENT_TYPE_ADMIN: &str = "cle_admin";

/// Déclaré explicitement dans chaque document plutôt que supposé fixe
/// par le code d'un vérificateur externe — voir `INTERFACES.md` §1.1.
pub const SIGNATURE_ALGORITHM: &str = "RSA-PSS-SHA256";

/// Format sous lequel `key_public`/`admin_key_public` est encodé dans le
/// JSON (toujours du DER SPKI, en base64 — jamais un PEM avec en-têtes).
pub const KEY_PUBLIC_FORMAT: &str = "SPKI-DER-base64";


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
    /// Résultat de la vérification de signature — `None` quand aucune
    /// signature n'entre en jeu (cas de [`classify_public_key`], qui ne
    /// connaît aucun document). `Some(true)`/`Some(false)` pour les
    /// fonctions `classify_independent_user`/`classify_org_user`/
    /// `classify_admin_key`, qui vérifient toujours une signature.
    pub signature_valid: Option<bool>,
    /// Fenêtre de validité (`date.start`/`date.end`) du document par
    /// rapport à l'instant fourni à la fonction `classify_*` — voir
    /// [`ValidityStatus`]. `None` quand aucune fenêtre n'est applicable
    /// ([`classify_public_key`]).
    pub validity: Option<ValidityStatus>,
    /// Pour un document de clé d'organisation uniquement : résultat de la
    /// vérification de `admin_signature` contre la clé admin de confiance
    /// fournie par l'application. `None` si non applicable (document
    /// indépendant ou admin, ou aucune clé admin de confiance fournie —
    /// ces deux derniers cas ne sont pas distingués ici, l'absence de
    /// clé de confiance n'étant pas en soi un défaut du document).
    pub admin_signature_valid: Option<bool>,
    /// Pour un document de clé d'organisation uniquement : `true` si
    /// l'empreinte de la clé admin de confiance fournie correspond
    /// exactement à `admin_fingerprint` tel que déclaré dans le document.
    /// Vérification distincte de `admin_signature_valid` : une signature
    /// peut être valide (produite par une vraie clé admin) tout en
    /// portant sur un `admin_fingerprint` incohérent avec elle si le
    /// document n'a pas été produit via [`sign_org_admin_completion`]
    /// (qui garantit cette cohérence par construction) — voir
    /// `FORMAT.md`.
    pub admin_fingerprint_consistent: Option<bool>,
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
        signature_valid: None,
        validity: None,
        admin_signature_valid: None,
        admin_fingerprint_consistent: None,
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

/// Statut d'une clé/d'un document par rapport à sa fenêtre de validité
/// déclarée (`date.start`/`date.end`), à un instant donné. Un fait, pas
/// un verdict — voir `check_validity_window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum ValidityStatus {
    NotYetValid,
    Valid,
    Expired,
}

/// Fait léger, sans aucune vérification de signature : où se situe
/// l'instant `now` par rapport à `[start, end]`. Utilisé en interne par
/// les fonctions `classify_*`, et exposé directement pour l'usage décrit
/// dans `INTERFACES.md` §7 ("créer une archive" : l'application vérifie
/// la fenêtre de validité de son propre document déjà signé, sans avoir
/// à re-signer quoi que ce soit).
///
/// `now` est un paramètre explicite plutôt que lu depuis l'horloge
/// système en interne : rend cette fonction, et toutes celles qui
/// l'utilisent, testables de façon déterministe, et évite un état caché
/// dans une fonction par ailleurs pure.
pub fn check_validity_window(start: i64, end: i64, now: i64) -> ValidityStatus {
    if now < start {
        ValidityStatus::NotYetValid
    } else if now > end {
        ValidityStatus::Expired
    } else {
        ValidityStatus::Valid
    }
}

// --- Encodage binaire déterministe pour signature (INTERFACES.md §3) ---
//
// Chaque champ : u32be (longueur en octets) + les octets du champ.
// Aucun ordre dynamique ni dérivé d'une structure JSON — l'ordre est
// fixe et codé en dur dans chaque fonction `encode_*` ci-dessous, une
// par portée de signature. Fonctions privées : ce détail d'encodage
// n'est jamais exposé à l'appelant, qui manipule uniquement des
// `RsaKeyPair`/`RsaPublicKey` et des structs de champs.

fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    push_field(buf, s.as_bytes());
}

fn push_i64(buf: &mut Vec<u8>, v: i64) {
    push_field(buf, &v.to_be_bytes());
}

fn push_u32(buf: &mut Vec<u8>, v: u32) {
    push_field(buf, &v.to_be_bytes());
}

/// Champs communs aux trois types de document — voir `INTERFACES.md`
/// §1.1. `document_id` est un UUID en 16 octets bruts (pas de dépendance
/// à la crate `uuid` ici : l'application convertit depuis
/// `uuid::Uuid::into_bytes()` ou équivalent).
#[derive(Debug, Clone)]
pub struct CommonFields {
    pub document_id: [u8; 16],
    pub created_at: i64,
    pub os: String,
    pub version_chiffre_aes_core: String,
    pub version_chiffre_rsa_core: String,
    pub version_chiffre_rsa_enveloppe: String,
    pub version_chiffre_rsa_keystore: String,
    pub identity_firstname: String,
    pub identity_lastname: String,
}

fn push_common_prefix(buf: &mut Vec<u8>, common: &CommonFields, document_type: &str) {
    push_field(buf, &common.document_id);
    push_u32(buf, SCHEMA_VERSION);
    push_str(buf, document_type);
    push_str(buf, SIGNATURE_ALGORITHM);
    push_i64(buf, common.created_at);
    push_str(buf, &common.os);
    push_str(buf, &common.version_chiffre_aes_core);
    push_str(buf, &common.version_chiffre_rsa_core);
    push_str(buf, &common.version_chiffre_rsa_enveloppe);
    push_str(buf, &common.version_chiffre_rsa_keystore);
    push_str(buf, &common.identity_firstname);
    push_str(buf, &common.identity_lastname);
}

/// Champs propres à une clé utilisateur indépendant — `user_signature`
/// couvre l'intégralité de ces champs, voir `INTERFACES.md` §2.
#[derive(Debug, Clone)]
pub struct IndependentUserFields {
    pub common: CommonFields,
    pub role: String,
    pub date_start: i64,
    pub date_end: i64,
}

fn encode_independent_user(fields: &IndependentUserFields, public_key_der: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_common_prefix(&mut buf, &fields.common, DOCUMENT_TYPE_INDEPENDENT_USER);
    push_str(&mut buf, &fields.role);
    push_str(&mut buf, KEY_PUBLIC_FORMAT);
    push_field(&mut buf, public_key_der);
    push_i64(&mut buf, fields.date_start);
    push_i64(&mut buf, fields.date_end);
    buf
}

/// Signe un document de clé utilisateur indépendant : `user_signature`
/// couvre tous les champs de `fields`, y compris `date_start`/`date_end`
/// — intégrité totale, aucune modification possible sans invalider la
/// signature (`INTERFACES.md` §2). La clé publique intégrée au document
/// est dérivée de `key` elle-même, jamais fournie séparément : il est
/// structurellement impossible de signer un document déclarant une clé
/// différente de celle utilisée pour signer.
pub fn sign_independent_user(fields: &IndependentUserFields, key: &RsaKeyPair) -> Vec<u8> {
    let der = key.public_key().to_spki_der();
    key.sign(&encode_independent_user(fields, &der))
}

/// Vérifie et classifie un document de clé utilisateur indépendant.
/// `now` : voir `check_validity_window`.
pub fn classify_independent_user(
    fields: &IndependentUserFields,
    public_key: &RsaPublicKey,
    signature: &[u8],
    now: i64,
) -> KeyClassificationReport {
    let der = public_key.to_spki_der();
    let message = encode_independent_user(fields, &der);
    let signature_valid = public_key.verify(&message, signature).is_ok();

    let mut report = classify_public_key(public_key);
    report.signature_valid = Some(signature_valid);
    report.validity = Some(check_validity_window(fields.date_start, fields.date_end, now));
    report
}

/// Champs propres à une clé utilisateur d'organisation, **phase
/// utilisateur** (avant complétion par l'admin) — pas encore de
/// `date_start`/`date_end`, l'utilisateur ne les connaît pas à ce stade.
#[derive(Debug, Clone)]
pub struct OrgUserFields {
    pub common: CommonFields,
    pub role: String,
    pub organisation: String,
}

fn encode_org_user(fields: &OrgUserFields, public_key_der: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_common_prefix(&mut buf, &fields.common, DOCUMENT_TYPE_ORG_USER);
    push_str(&mut buf, &fields.role);
    push_str(&mut buf, &fields.organisation);
    push_str(&mut buf, KEY_PUBLIC_FORMAT);
    push_field(&mut buf, public_key_der);
    buf
}

/// Signe la phase utilisateur d'un document de clé d'organisation.
/// `user_signature` couvre tous les champs de `fields` — **sauf**
/// `date_start`/`date_end`/`admin_fingerprint`/`admin_nom`, inconnus de
/// l'utilisateur à ce stade (`INTERFACES.md` §2). Le document partiel
/// résultant doit être transmis à l'admin (canal hors périmètre de ce
/// crate) pour complétion via [`sign_org_admin_completion`].
pub fn sign_org_user(fields: &OrgUserFields, key: &RsaKeyPair) -> Vec<u8> {
    let der = key.public_key().to_spki_der();
    key.sign(&encode_org_user(fields, &der))
}

fn push_admin_completion_suffix(
    buf: &mut Vec<u8>,
    date_start: i64,
    date_end: i64,
    admin_fingerprint: &[u8; 32],
    admin_nom: &str,
    user_signature: &[u8],
) {
    push_i64(buf, date_start);
    push_i64(buf, date_end);
    push_field(buf, admin_fingerprint);
    push_str(buf, admin_nom);
    push_field(buf, user_signature);
}

fn encode_org_admin_completion(
    user_fields: &OrgUserFields,
    public_key_der: &[u8],
    date_start: i64,
    date_end: i64,
    admin_fingerprint: &[u8; 32],
    admin_nom: &str,
    user_signature: &[u8],
) -> Vec<u8> {
    let mut buf = encode_org_user(user_fields, public_key_der);
    push_admin_completion_suffix(
        &mut buf,
        date_start,
        date_end,
        admin_fingerprint,
        admin_nom,
        user_signature,
    );
    buf
}

/// Champs que l'admin ajoute pour compléter et signer un document de clé
/// d'organisation — voir [`sign_org_admin_completion`].
#[derive(Debug, Clone)]
pub struct OrgAdminSigningFields {
    /// Les champs de la phase utilisateur, tels que reçus (pour
    /// reconstruire exactement le message dont `user_signature` fait
    /// foi).
    pub user: OrgUserFields,
    pub date_start: i64,
    pub date_end: i64,
    pub admin_nom: String,
    pub user_signature: Vec<u8>,
}

/// Complète et signe un document de clé d'organisation, côté admin.
/// `admin_signature` couvre tout ce que couvrait `user_signature`, plus
/// `date_start`/`date_end`/`admin_fingerprint`/`admin_nom`, plus
/// `user_signature` elle-même (lie les deux signatures — `INTERFACES.md`
/// §2). `admin_fingerprint` est dérivé de `admin_key` elle-même, jamais
/// fourni séparément — même raison que pour la clé publique dans
/// [`sign_independent_user`] : impossible de signer un document déclarant
/// une empreinte admin différente de celle de la clé qui signe réellement.
pub fn sign_org_admin_completion(
    fields: &OrgAdminSigningFields,
    user_public_key: &RsaPublicKey,
    admin_key: &RsaKeyPair,
) -> Vec<u8> {
    let der = user_public_key.to_spki_der();
    let admin_fingerprint = admin_key.public_key().fingerprint();
    let message = encode_org_admin_completion(
        &fields.user,
        &der,
        fields.date_start,
        fields.date_end,
        &admin_fingerprint,
        &fields.admin_nom,
        &fields.user_signature,
    );
    admin_key.sign(&message)
}

/// Document de clé d'organisation **final**, tel que lu depuis un
/// document reçu — contrairement à [`OrgAdminSigningFields`],
/// `admin_fingerprint` est ici une valeur **déclarée** (lue telle quelle
/// dans le document), pas dérivée d'une clé qu'on posséderait : c'est
/// justement ce que [`classify_org_user`] vérifie, en la comparant à
/// l'empreinte réelle de la clé admin de confiance fournie par
/// l'application.
#[derive(Debug, Clone)]
pub struct OrgUserKeyRecord {
    pub user: OrgUserFields,
    pub date_start: i64,
    pub date_end: i64,
    pub admin_fingerprint: [u8; 32],
    pub admin_nom: String,
}

/// Vérifie et classifie un document de clé utilisateur d'organisation.
///
/// `trusted_admin_key` : la clé admin en laquelle l'application a
/// confiance pour cette organisation, obtenue hors bande — **jamais**
/// extraite du document lui-même (ce serait accepter n'importe quelle
/// clé s'auto-proclamant admin). `None` si l'application n'a pas encore
/// résolu quelle clé admin faire confiance : dans ce cas,
/// `admin_signature_valid`/`admin_fingerprint_consistent` valent `None`
/// dans le rapport plutôt que `Some(false)` — l'absence de clé de
/// confiance fournie n'est pas en soi un défaut du document.
pub fn classify_org_user(
    record: &OrgUserKeyRecord,
    public_key: &RsaPublicKey,
    user_signature: &[u8],
    admin_signature: &[u8],
    trusted_admin_key: Option<&RsaPublicKey>,
    now: i64,
) -> KeyClassificationReport {
    let der = public_key.to_spki_der();

    let user_message = encode_org_user(&record.user, &der);
    let user_signature_valid = public_key.verify(&user_message, user_signature).is_ok();

    let admin_message = encode_org_admin_completion(
        &record.user,
        &der,
        record.date_start,
        record.date_end,
        &record.admin_fingerprint,
        &record.admin_nom,
        user_signature,
    );

    let (admin_signature_valid, admin_fingerprint_consistent) = match trusted_admin_key {
        Some(admin_key) => (
            Some(admin_key.verify(&admin_message, admin_signature).is_ok()),
            Some(admin_key.fingerprint() == record.admin_fingerprint),
        ),
        None => (None, None),
    };

    let mut report = classify_public_key(public_key);
    report.signature_valid = Some(user_signature_valid);
    report.validity = Some(check_validity_window(record.date_start, record.date_end, now));
    report.admin_signature_valid = admin_signature_valid;
    report.admin_fingerprint_consistent = admin_fingerprint_consistent;
    report
}

/// Champs d'un document de clé admin — voir `INTERFACES.md` §1.3. Pas de
/// `role` (n'a pas de sens pour une clé admin), pas de
/// `admin_fingerprint` (la clé admin est elle-même la racine de
/// confiance, s'auto-référencer n'aurait pas de sens).
#[derive(Debug, Clone)]
pub struct AdminKeyFields {
    pub common: CommonFields,
    pub organisation: String,
    pub date_start: i64,
    pub date_end: i64,
}

fn encode_admin_key(fields: &AdminKeyFields, admin_public_key_der: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_common_prefix(&mut buf, &fields.common, DOCUMENT_TYPE_ADMIN);
    push_str(&mut buf, &fields.organisation);
    push_str(&mut buf, KEY_PUBLIC_FORMAT);
    push_field(&mut buf, admin_public_key_der);
    push_i64(&mut buf, fields.date_start);
    push_i64(&mut buf, fields.date_end);
    buf
}

/// Signe un document de clé admin — auto-signature (preuve de possession
/// de la clé privée admin), couvre l'intégralité des champs.
pub fn sign_admin_key(fields: &AdminKeyFields, admin_key: &RsaKeyPair) -> Vec<u8> {
    let der = admin_key.public_key().to_spki_der();
    admin_key.sign(&encode_admin_key(fields, &der))
}

/// Vérifie et classifie un document de clé admin.
pub fn classify_admin_key(
    fields: &AdminKeyFields,
    public_key: &RsaPublicKey,
    signature: &[u8],
    now: i64,
) -> KeyClassificationReport {
    let der = public_key.to_spki_der();
    let message = encode_admin_key(fields, &der);
    let signature_valid = public_key.verify(&message, signature).is_ok();

    let mut report = classify_public_key(public_key);
    report.signature_valid = Some(signature_valid);
    report.validity = Some(check_validity_window(fields.date_start, fields.date_end, now));
    report
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

    // --- check_validity_window --------------------------------------------

    #[test]
    fn validity_window_before_start_is_not_yet_valid() {
        assert_eq!(check_validity_window(100, 200, 50), ValidityStatus::NotYetValid);
    }

    #[test]
    fn validity_window_within_bounds_is_valid() {
        assert_eq!(check_validity_window(100, 200, 150), ValidityStatus::Valid);
        assert_eq!(check_validity_window(100, 200, 100), ValidityStatus::Valid);
        assert_eq!(check_validity_window(100, 200, 200), ValidityStatus::Valid);
    }

    #[test]
    fn validity_window_after_end_is_expired() {
        assert_eq!(check_validity_window(100, 200, 250), ValidityStatus::Expired);
    }

    // --- Documents : helpers de test ---------------------------------------

    fn sample_common() -> CommonFields {
        CommonFields {
            document_id: [0x11; 16],
            created_at: 1_700_000_000,
            os: "linux".to_string(),
            version_chiffre_aes_core: "1.0.0".to_string(),
            version_chiffre_rsa_core: "0.1.0".to_string(),
            version_chiffre_rsa_enveloppe: "0.1.0".to_string(),
            version_chiffre_rsa_keystore: "0.1.0".to_string(),
            identity_firstname: "seb1".to_string(),
            identity_lastname: "no".to_string(),
        }
    }

    // --- Clé utilisateur indépendant -----------------------------------

    #[test]
    fn independent_user_roundtrip_is_valid_and_current() {
        let key = test_key_a();
        let fields = IndependentUserFields {
            common: sample_common(),
            role: "user".to_string(),
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
        };

        let signature = sign_independent_user(&fields, key);
        let report = classify_independent_user(&fields, &key.public_key(), &signature, 1_750_000_000);

        assert_eq!(report.signature_valid, Some(true));
        assert_eq!(report.validity, Some(ValidityStatus::Valid));
    }

    #[test]
    fn independent_user_detects_expired_window() {
        let key = test_key_a();
        let fields = IndependentUserFields {
            common: sample_common(),
            role: "user".to_string(),
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
        };

        let signature = sign_independent_user(&fields, key);
        // now très après date_end.
        let report = classify_independent_user(&fields, &key.public_key(), &signature, 2_000_000_000);

        assert_eq!(report.signature_valid, Some(true));
        assert_eq!(report.validity, Some(ValidityStatus::Expired));
    }

    #[test]
    fn independent_user_tampered_field_invalidates_signature() {
        let key = test_key_a();
        let mut fields = IndependentUserFields {
            common: sample_common(),
            role: "user".to_string(),
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
        };

        let signature = sign_independent_user(&fields, key);

        // Modification d'un champ APRÈS signature (ex. élévation de
        // privilège silencieuse) : la signature doit être détectée comme
        // invalide, prouvant que `role` fait bien partie du périmètre
        // signé.
        fields.role = "admin".to_string();
        let report = classify_independent_user(&fields, &key.public_key(), &signature, 1_750_000_000);

        assert_eq!(report.signature_valid, Some(false));
    }

    #[test]
    fn independent_user_wrong_public_key_invalidates_signature() {
        let key_a = test_key_a();
        let key_b = test_key_b();
        let fields = IndependentUserFields {
            common: sample_common(),
            role: "user".to_string(),
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
        };

        let signature = sign_independent_user(&fields, key_a);
        // Vérifie avec la mauvaise clé publique.
        let report = classify_independent_user(&fields, &key_b.public_key(), &signature, 1_750_000_000);

        assert_eq!(report.signature_valid, Some(false));
    }

    // --- Clé utilisateur d'organisation ---------------------------------

    #[test]
    fn org_user_full_flow_is_valid_and_consistent() {
        let user_key = test_key_a();
        let admin_key = test_key_b();

        let user_fields = OrgUserFields {
            common: sample_common(),
            role: "user".to_string(),
            organisation: "Acme".to_string(),
        };
        let user_signature = sign_org_user(&user_fields, user_key);

        let admin_fields = OrgAdminSigningFields {
            user: user_fields.clone(),
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
            admin_nom: "Admin Acme".to_string(),
            user_signature: user_signature.clone(),
        };
        let admin_signature =
            sign_org_admin_completion(&admin_fields, &user_key.public_key(), admin_key);

        let record = OrgUserKeyRecord {
            user: user_fields,
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
            admin_fingerprint: admin_key.public_key().fingerprint(),
            admin_nom: "Admin Acme".to_string(),
        };

        let report = classify_org_user(
            &record,
            &user_key.public_key(),
            &user_signature,
            &admin_signature,
            Some(&admin_key.public_key()),
            1_750_000_000,
        );

        assert_eq!(report.signature_valid, Some(true));
        assert_eq!(report.admin_signature_valid, Some(true));
        assert_eq!(report.admin_fingerprint_consistent, Some(true));
        assert_eq!(report.validity, Some(ValidityStatus::Valid));
    }

    #[test]
    fn org_user_without_trusted_admin_key_reports_none() {
        let user_key = test_key_a();
        let admin_key = test_key_b();

        let user_fields = OrgUserFields {
            common: sample_common(),
            role: "user".to_string(),
            organisation: "Acme".to_string(),
        };
        let user_signature = sign_org_user(&user_fields, user_key);

        let admin_fields = OrgAdminSigningFields {
            user: user_fields.clone(),
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
            admin_nom: "Admin Acme".to_string(),
            user_signature: user_signature.clone(),
        };
        let admin_signature =
            sign_org_admin_completion(&admin_fields, &user_key.public_key(), admin_key);

        let record = OrgUserKeyRecord {
            user: user_fields,
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
            admin_fingerprint: admin_key.public_key().fingerprint(),
            admin_nom: "Admin Acme".to_string(),
        };

        let report = classify_org_user(
            &record,
            &user_key.public_key(),
            &user_signature,
            &admin_signature,
            None, // application n'a pas encore résolu la clé admin de confiance
            1_750_000_000,
        );

        assert_eq!(report.signature_valid, Some(true)); // la signature user, elle, ne dépend pas de l'admin
        assert_eq!(report.admin_signature_valid, None);
        assert_eq!(report.admin_fingerprint_consistent, None);
    }

    #[test]
    fn org_user_wrong_trusted_admin_key_fails_both_checks() {
        let user_key = test_key_a();
        let real_admin_key = test_key_b();
        let impostor_admin_key = RsaKeyPair::generate().expect("génération clé tierce");

        let user_fields = OrgUserFields {
            common: sample_common(),
            role: "user".to_string(),
            organisation: "Acme".to_string(),
        };
        let user_signature = sign_org_user(&user_fields, user_key);

        let admin_fields = OrgAdminSigningFields {
            user: user_fields.clone(),
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
            admin_nom: "Admin Acme".to_string(),
            user_signature: user_signature.clone(),
        };
        let admin_signature =
            sign_org_admin_completion(&admin_fields, &user_key.public_key(), real_admin_key);

        let record = OrgUserKeyRecord {
            user: user_fields,
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
            admin_fingerprint: real_admin_key.public_key().fingerprint(),
            admin_nom: "Admin Acme".to_string(),
        };

        // L'application fait confiance à la mauvaise clé admin (pas
        // celle qui a réellement signé) : les deux vérifications
        // doivent échouer.
        let report = classify_org_user(
            &record,
            &user_key.public_key(),
            &user_signature,
            &admin_signature,
            Some(&impostor_admin_key.public_key()),
            1_750_000_000,
        );

        assert_eq!(report.admin_signature_valid, Some(false));
        assert_eq!(report.admin_fingerprint_consistent, Some(false));
    }

    #[test]
    fn org_user_self_inconsistent_admin_fingerprint_is_detected() {
        // Simule un document mal construit (pas via sign_org_admin_completion) :
        // la signature admin est authentique (produite par real_admin_key),
        // mais le document DÉCLARE l'empreinte d'une autre clé. Comme
        // admin_fingerprint fait partie du message signé, falsifier ce
        // champ après coup casse aussi la signature — donc pour observer
        // une INCOHÉRENCE sans casser la signature, il faut que la valeur
        // déclarée soit déjà celle utilisée au moment de signer (ce que
        // seule une implémentation bugguée/malveillante ferait, en
        // contournant sign_org_admin_completion).
        let user_key = test_key_a();
        let real_admin_key = test_key_b();
        let wrong_fingerprint = [0x42u8; 32];

        let user_fields = OrgUserFields {
            common: sample_common(),
            role: "user".to_string(),
            organisation: "Acme".to_string(),
        };
        let user_signature = sign_org_user(&user_fields, user_key);
        let der = user_key.public_key().to_spki_der();

        // Construction manuelle (bas niveau, contourne délibérément
        // sign_org_admin_completion) d'un message signé avec une
        // empreinte admin volontairement fausse.
        let message = encode_org_admin_completion(
            &user_fields,
            &der,
            1_700_000_000,
            1_800_000_000,
            &wrong_fingerprint,
            "Admin Acme",
            &user_signature,
        );
        let admin_signature = real_admin_key.sign(&message);

        let record = OrgUserKeyRecord {
            user: user_fields,
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
            admin_fingerprint: wrong_fingerprint, // valeur falsifiée, mais cohérente avec ce qui a été signé
            admin_nom: "Admin Acme".to_string(),
        };

        let report = classify_org_user(
            &record,
            &user_key.public_key(),
            &user_signature,
            &admin_signature,
            Some(&real_admin_key.public_key()),
            1_750_000_000,
        );

        // La signature EST valide (real_admin_key a bien signé ce
        // message précis)...
        assert_eq!(report.admin_signature_valid, Some(true));
        // ...mais l'empreinte déclarée ne correspond pas à la clé de
        // confiance fournie : exactement le cas que ce champ doit
        // détecter.
        assert_eq!(report.admin_fingerprint_consistent, Some(false));
    }

    // --- Clé admin -------------------------------------------------------

    #[test]
    fn admin_key_roundtrip_is_valid() {
        let admin_key = test_key_a();
        let fields = AdminKeyFields {
            common: sample_common(),
            organisation: "Acme".to_string(),
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
        };

        let signature = sign_admin_key(&fields, admin_key);
        let report =
            classify_admin_key(&fields, &admin_key.public_key(), &signature, 1_750_000_000);

        assert_eq!(report.signature_valid, Some(true));
        assert_eq!(report.validity, Some(ValidityStatus::Valid));
    }

    #[test]
    fn admin_key_tampered_organisation_invalidates_signature() {
        let admin_key = test_key_a();
        let mut fields = AdminKeyFields {
            common: sample_common(),
            organisation: "Acme".to_string(),
            date_start: 1_700_000_000,
            date_end: 1_800_000_000,
        };

        let signature = sign_admin_key(&fields, admin_key);
        fields.organisation = "Acme Corp Modifiee".to_string();

        let report =
            classify_admin_key(&fields, &admin_key.public_key(), &signature, 1_750_000_000);
        assert_eq!(report.signature_valid, Some(false));
    }
}
