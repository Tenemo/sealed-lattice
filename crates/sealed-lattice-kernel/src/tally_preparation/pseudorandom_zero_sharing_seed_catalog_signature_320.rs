use core::fmt;

use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, Roster,
};

use super::{
    TallyPreparationError,
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogLayout320, PseudorandomZeroSharingSeedCatalogRootBody320,
    },
};

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const SIGNATURE_BODY_ITEM_COUNT: usize = 7;
const SIGNATURE_ENVELOPE_ITEM_COUNT: usize = 3;
const MAXIMUM_SIGNATURE_CONTROL_OBJECT_BYTE_LENGTH: usize = 8_192;
const MAXIMUM_SIGNATURE_CONTROL_OBJECT_ITEM_COUNT: usize = 16;
const MAXIMUM_SIGNATURE_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 4_096;
const MAXIMUM_SIGNATURE_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 32_768;

pub(crate) const ML_DSA_65_SIGNATURE_BYTE_LENGTH: usize = 3_309;
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/preparation/seed-catalog-root";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-signature-body";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-signature-envelope";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedCatalogSignatureError {
    Canonical(CanonicalCodecError),
    Preparation(TallyPreparationError),
    ObjectMismatch { field: &'static str },
    SignatureByteLength { expected: usize, actual: usize },
    RosterMismatch,
    MalformedSigningVerificationKey,
    InvalidSignature,
}

impl From<CanonicalCodecError> for PseudorandomZeroSharingSeedCatalogSignatureError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<TallyPreparationError> for PseudorandomZeroSharingSeedCatalogSignatureError {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedCatalogSignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => {
                write!(formatter, "canonical seed-catalog signature error: {error}")
            }
            Self::Preparation(error) => write!(
                formatter,
                "seed-catalog signature preparation error: {error}"
            ),
            Self::ObjectMismatch { field } => {
                write!(
                    formatter,
                    "seed-catalog signature object has a wrong {field}"
                )
            }
            Self::SignatureByteLength { expected, actual } => write!(
                formatter,
                "seed-catalog signature has {actual} bytes; expected {expected}"
            ),
            Self::RosterMismatch => formatter.write_str(
                "seed-catalog signature roster does not match the expected preparation context",
            ),
            Self::MalformedSigningVerificationKey => formatter.write_str(
                "seed-catalog signature roster contains a malformed ML-DSA-65 verification key",
            ),
            Self::InvalidSignature => {
                formatter.write_str("seed-catalog root has an invalid ML-DSA-65 signature")
            }
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedCatalogSignatureError {}

/// Canonical message signed by the catalog contributor.
///
/// The state-authorization certificate identity is byte-bound but not verified
/// here. This prevents a direct signature-over-root shortcut while the one-shot
/// state certificate verifier remains a separate predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootSignatureBody320 {
    preparation_context_identity: Hash512,
    participant_count: u16,
    contributor_position: u16,
    root_body_identity: Hash512,
    authorization_certificate_identity: Hash512,
}

impl PseudorandomZeroSharingSeedCatalogRootSignatureBody320 {
    pub(crate) fn new(
        root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
        authorization_certificate_identity: Hash512,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogSignatureError> {
        let layout = root_body.layout();
        Ok(Self {
            preparation_context_identity: layout.preparation_context().identity(),
            participant_count: layout.participant_count(),
            contributor_position: layout.contributor_position(),
            root_body_identity: root_body.identity()?,
            authorization_certificate_identity,
        })
    }

    pub(crate) const fn contributor_position(self) -> u16 {
        self.contributor_position
    }

    pub(crate) const fn root_body_identity(self) -> Hash512 {
        self.root_body_identity
    }

    pub(crate) const fn authorization_certificate_identity(self) -> Hash512 {
        self.authorization_certificate_identity
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogSignatureError> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.preparation_context_identity.into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::unsigned16(self.participant_count),
                CanonicalItem::unsigned16(self.contributor_position),
                CanonicalItem::hash512(self.root_body_identity.into_bytes()),
                CanonicalItem::hash512(self.authorization_certificate_identity.into_bytes()),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
        expected_authorization_certificate_identity: Hash512,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogSignatureError> {
        let expected = Self::new(
            expected_root_body,
            expected_authorization_certificate_identity,
        )?;
        let tuple = CanonicalTuple::decode(bytes, &signature_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_BODY_DOMAIN,
            SIGNATURE_BODY_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected.preparation_context_identity,
            "preparation context identity",
        )?;
        require_u16(
            &tuple.items[2],
            PREPARATION_ATTEMPT_ORDINAL,
            "preparation attempt ordinal",
        )?;
        require_u16(
            &tuple.items[3],
            expected.participant_count,
            "participant count",
        )?;
        require_u16(
            &tuple.items[4],
            expected.contributor_position,
            "contributor position",
        )?;
        require_hash(
            &tuple.items[5],
            expected.root_body_identity,
            "root-body identity",
        )?;
        require_hash(
            &tuple.items[6],
            expected.authorization_certificate_identity,
            "authorization-certificate identity",
        )?;
        Ok(expected)
    }
}

/// Detached ML-DSA-65 envelope over one canonical signature body.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320 {
    signature_body: PseudorandomZeroSharingSeedCatalogRootSignatureBody320,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320 {
    pub(crate) const fn new(
        signature_body: PseudorandomZeroSharingSeedCatalogRootSignatureBody320,
        signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            signature_body,
            signature,
        }
    }

    pub(crate) const fn signature_body(
        &self,
    ) -> PseudorandomZeroSharingSeedCatalogRootSignatureBody320 {
        self.signature_body
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogSignatureError> {
        let signature_body_bytes = self.signature_body.canonical_bytes()?;
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_ENVELOPE_DOMAIN,
                )?,
                CanonicalItem::variable_bytes(signature_body_bytes)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
        expected_authorization_certificate_identity: Hash512,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogSignatureError> {
        let tuple = CanonicalTuple::decode(bytes, &signature_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_ENVELOPE_DOMAIN,
            SIGNATURE_ENVELOPE_ITEM_COUNT,
        )?;
        if tuple.items[1].item_type() != CanonicalItemType::RawBytes {
            return Err(signature_object_mismatch("signature body"));
        }
        let signature_body =
            PseudorandomZeroSharingSeedCatalogRootSignatureBody320::from_canonical_bytes(
                expected_root_body,
                expected_authorization_certificate_identity,
                tuple.items[1].variable_value_bytes()?,
            )?;
        if tuple.items[2].item_type() != CanonicalItemType::RawBytes {
            return Err(signature_object_mismatch("signature"));
        }
        let signature =
            <[u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH]>::try_from(tuple.items[2].canonical_bytes())
                .map_err(|_| {
                    PseudorandomZeroSharingSeedCatalogSignatureError::SignatureByteLength {
                        expected: ML_DSA_65_SIGNATURE_BYTE_LENGTH,
                        actual: tuple.items[2].canonical_bytes().len(),
                    }
                })?;
        Ok(Self {
            signature_body,
            signature,
        })
    }
}

impl fmt::Debug for PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320")
            .field("signature_body", &self.signature_body)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Positive roster-signature result for one root and state-authorization
/// identity.
///
/// It does not verify that the state-authorization identity names a valid
/// certificate and therefore cannot authorize private delivery or seed use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RosterSignatureMatchedPseudorandomZeroSharingSeedCatalogRoot320 {
    root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
    root_body_identity: Hash512,
    authorization_certificate_identity: Hash512,
}

impl RosterSignatureMatchedPseudorandomZeroSharingSeedCatalogRoot320 {
    pub(crate) const fn root_body(self) -> PseudorandomZeroSharingSeedCatalogRootBody320 {
        self.root_body
    }

    pub(crate) const fn root_body_identity(self) -> Hash512 {
        self.root_body_identity
    }

    pub(crate) const fn authorization_certificate_identity(self) -> Hash512 {
        self.authorization_certificate_identity
    }
}

/// Verifies the exact canonical root, signature carrier, fixed ML-DSA purpose,
/// and roster key selected by the catalog contributor position.
///
/// The expected state-authorization identity is only matched to signed bytes. A
/// later verifier must supply its positively verified state certificate before
/// any continuation can consume this result.
pub(crate) fn verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
    expected_layout: PseudorandomZeroSharingSeedCatalogLayout320,
    root_body_bytes: &[u8],
    expected_authorization_certificate_identity: Hash512,
    roster: &Roster,
    signature_envelope_bytes: &[u8],
) -> Result<
    RosterSignatureMatchedPseudorandomZeroSharingSeedCatalogRoot320,
    PseudorandomZeroSharingSeedCatalogSignatureError,
> {
    let root_body = PseudorandomZeroSharingSeedCatalogRootBody320::from_canonical_bytes(
        expected_layout,
        root_body_bytes,
    )?;
    roster
        .validate()
        .map_err(|_| PseudorandomZeroSharingSeedCatalogSignatureError::RosterMismatch)?;
    if roster.entries.len() != usize::from(expected_layout.participant_count())
        || roster
            .roster_hash()
            .map_err(|_| PseudorandomZeroSharingSeedCatalogSignatureError::RosterMismatch)?
            != expected_layout.preparation_context().roster_hash()
    {
        return Err(PseudorandomZeroSharingSeedCatalogSignatureError::RosterMismatch);
    }
    let envelope = PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320::from_canonical_bytes(
        root_body,
        expected_authorization_certificate_identity,
        signature_envelope_bytes,
    )?;
    let contributor_position = expected_layout.contributor_position();
    let roster_entry = roster
        .entries
        .get(usize::from(contributor_position))
        .ok_or(PseudorandomZeroSharingSeedCatalogSignatureError::RosterMismatch)?;
    if roster_entry.roster_position != contributor_position {
        return Err(PseudorandomZeroSharingSeedCatalogSignatureError::RosterMismatch);
    }
    let public_key = ml_dsa_65::PublicKey::try_from_bytes(roster_entry.signing_verification_key)
        .map_err(|_| {
            PseudorandomZeroSharingSeedCatalogSignatureError::MalformedSigningVerificationKey
        })?;
    let signature_body_bytes = envelope.signature_body.canonical_bytes()?;
    if !public_key.verify(
        &signature_body_bytes,
        &envelope.signature,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_CONTEXT,
    ) {
        return Err(PseudorandomZeroSharingSeedCatalogSignatureError::InvalidSignature);
    }
    Ok(
        RosterSignatureMatchedPseudorandomZeroSharingSeedCatalogRoot320 {
            root_body,
            root_body_identity: envelope.signature_body.root_body_identity,
            authorization_certificate_identity: envelope
                .signature_body
                .authorization_certificate_identity,
        },
    )
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), PseudorandomZeroSharingSeedCatalogSignatureError> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(signature_object_mismatch("schema identifier"));
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(signature_object_mismatch("schema version"));
    }
    if tuple.items.len() != expected_item_count {
        return Err(signature_object_mismatch("item count"));
    }
    if tuple.items[0].item_type() != CanonicalItemType::Ascii
        || tuple.items[0].variable_value_bytes()? != expected_domain.as_bytes()
    {
        return Err(signature_object_mismatch("object domain"));
    }
    Ok(())
}

fn read_hash(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<Hash512, PseudorandomZeroSharingSeedCatalogSignatureError> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(signature_object_mismatch(field));
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| signature_object_mismatch(field))?;
    Ok(Hash512::from_bytes(bytes))
}

fn require_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedCatalogSignatureError> {
    if read_hash(item, field)? != expected {
        return Err(signature_object_mismatch(field));
    }
    Ok(())
}

fn read_u16(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u16, PseudorandomZeroSharingSeedCatalogSignatureError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(signature_object_mismatch(field));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| signature_object_mismatch(field))?;
    Ok(u16::from_le_bytes(bytes))
}

fn require_u16(
    item: &CanonicalItem,
    expected: u16,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedCatalogSignatureError> {
    if read_u16(item, field)? != expected {
        return Err(signature_object_mismatch(field));
    }
    Ok(())
}

const fn signature_object_mismatch(
    field: &'static str,
) -> PseudorandomZeroSharingSeedCatalogSignatureError {
    PseudorandomZeroSharingSeedCatalogSignatureError::ObjectMismatch { field }
}

fn signature_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_SIGNATURE_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_SIGNATURE_CONTROL_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_SIGNATURE_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length:
            MAXIMUM_SIGNATURE_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_SIGNATURE_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}

const _: () = assert!(ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH == ml_dsa_65::PK_LEN);
const _: () = assert!(ML_DSA_65_SIGNATURE_BYTE_LENGTH == ml_dsa_65::SIG_LEN);
