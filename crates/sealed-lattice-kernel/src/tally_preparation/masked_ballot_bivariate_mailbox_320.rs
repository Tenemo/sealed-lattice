use core::fmt;

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use fips203::{
    ml_kem_768,
    traits::{Decaps, Encaps, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{SerDes as SignatureSerDes, Verifier},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, Roster,
    StreamingFoundationTupleHash512, hash_foundation_tuple_512,
};

use super::{
    masked_ballot_bivariate_commitment_320::{
        AuthenticatedMaskedBallotBivariatePrivateRow320,
        AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
        MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH, MaskedBallotBivariateCommitmentError320,
        MaskedBallotBivariateCommitmentInventory320, MaskedBallotBivariateCommitmentLayout320,
        MaskedBallotBivariateCommitmentRootBody320,
        masked_ballot_bivariate_private_row_body_byte_length,
        verify_masked_ballot_bivariate_private_row_320,
    },
    private_mailbox_kmac_256::{derive_private_mailbox_key_256, derive_private_mailbox_nonce_96},
};

const MAILBOX_HEADER_ITEM_COUNT: usize = 11;
const MAILBOX_MANIFEST_PREFIX_ITEM_COUNT: usize = 7;
const MAILBOX_SIGNATURE_ENVELOPE_ITEM_COUNT: usize = 3;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;
const MAXIMUM_MAILBOX_CONTROL_OBJECT_BYTE_LENGTH: usize = 64 * 1024;
const MAXIMUM_MAILBOX_CONTROL_OBJECT_ITEM_COUNT: usize = 64;
const MAXIMUM_MAILBOX_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 8 * 1024;
const MAXIMUM_MAILBOX_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 256 * 1024;
const ML_KEM_768_DECAPSULATION_KEY_PUBLIC_KEY_OFFSET: usize = 384 * 3;

pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_ALGORITHM_IDENTIFIER: &str =
    "ml-kem-768+kmac256+aes-256-gcm-siv";
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_HEADER_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-mailbox-header";
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_HEADER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-mailbox-header-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_RECIPIENT_KEY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-mailbox-recipient-key-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_ASSOCIATED_DATA_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-mailbox-associated-data";
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_CARRIER_DIGEST_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-mailbox-carrier-digest";
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_MANIFEST_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-mailbox-manifest";
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_MANIFEST_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-mailbox-manifest-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-mailbox-signature-envelope";
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/ballot/bivariate-private-row-mailbox-manifest";
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_KEY_DERIVATION_LABEL: &[u8] =
    b"sealed-lattice/v1/ballot/bivariate-private-row-mailbox-aead-key";
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_NONCE_DERIVATION_LABEL: &[u8] =
    b"sealed-lattice/v1/ballot/bivariate-private-row-mailbox-aead-nonce";

pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH: usize = 16;
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_ML_KEM_CIPHERTEXT_BYTE_LENGTH: usize =
    ml_kem_768::CT_LEN;
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_HEADER_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + MAILBOX_HEADER_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + MASKED_BALLOT_BIVARIATE_MAILBOX_HEADER_DOMAIN.len()
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + MASKED_BALLOT_BIVARIATE_MAILBOX_ALGORITHM_IDENTIFIER.len()
        + 3 * Hash512::BYTE_LENGTH
        + 3 * size_of::<u16>()
        + MASKED_BALLOT_BIVARIATE_MAILBOX_ML_KEM_CIPHERTEXT_BYTE_LENGTH
        + 2 * size_of::<u64>();
pub(crate) const MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + MAILBOX_SIGNATURE_ENVELOPE_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_ENVELOPE_DOMAIN.len()
        + Hash512::BYTE_LENGTH
        + MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH;

pub(crate) fn masked_ballot_bivariate_mailbox_manifest_body_byte_length(
    participant_count: u16,
) -> Result<usize, MaskedBallotBivariateMailboxError320> {
    if crate::foundation::derive_foundation_roster_parameters(participant_count).is_none() {
        return Err(mailbox_object_mismatch("participant count"));
    }
    let participant_count = usize::from(participant_count);
    let item_count = MAILBOX_MANIFEST_PREFIX_ITEM_COUNT
        .checked_add(
            participant_count
                .checked_mul(2)
                .ok_or(MaskedBallotBivariateMailboxError320::ArithmeticOverflow)?,
        )
        .ok_or(MaskedBallotBivariateMailboxError320::ArithmeticOverflow)?;
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        .checked_add(
            item_count
                .checked_mul(CANONICAL_ITEM_HEADER_BYTE_LENGTH)
                .ok_or(MaskedBallotBivariateMailboxError320::ArithmeticOverflow)?,
        )
        .and_then(|length| length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH))
        .and_then(|length| {
            length.checked_add(MASKED_BALLOT_BIVARIATE_MAILBOX_MANIFEST_DOMAIN.len())
        })
        .and_then(|length| length.checked_add(2 * Hash512::BYTE_LENGTH))
        .and_then(|length| length.checked_add(4 * size_of::<u16>()))
        .and_then(|length| {
            participant_count
                .checked_mul(2 * Hash512::BYTE_LENGTH)
                .and_then(|digest_bytes| length.checked_add(digest_bytes))
        })
        .ok_or(MaskedBallotBivariateMailboxError320::ArithmeticOverflow)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MaskedBallotBivariateMailboxError320 {
    Canonical(CanonicalCodecError),
    Commitment(MaskedBallotBivariateCommitmentError320),
    ObjectMismatch {
        field: &'static str,
    },
    RosterMismatch,
    HolderRosterPositionOutOfRange {
        holder_roster_position: u16,
        participant_count: u16,
    },
    HeaderCount {
        expected: usize,
        actual: usize,
    },
    CarrierCount {
        expected: usize,
        actual: usize,
    },
    EncapsulationRandomnessCount {
        expected: usize,
        actual: usize,
    },
    CarrierByteLength {
        expected: usize,
        actual: usize,
    },
    CarrierDigestMismatch {
        holder_roster_position: u16,
    },
    MalformedEncapsulationKey,
    MalformedEncapsulationCiphertext,
    DecapsulationKeyMismatch,
    DecapsulationFailed,
    AuthenticatedEncryptionFailed,
    AuthenticatedDecryptionFailed,
    MalformedSigningVerificationKey,
    InvalidAuthorSignature,
    SignatureByteLength {
        expected: usize,
        actual: usize,
    },
    IntegerConversion,
    ArithmeticOverflow,
    StreamingHash,
}

impl From<CanonicalCodecError> for MaskedBallotBivariateMailboxError320 {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<MaskedBallotBivariateCommitmentError320> for MaskedBallotBivariateMailboxError320 {
    fn from(error: MaskedBallotBivariateCommitmentError320) -> Self {
        Self::Commitment(error)
    }
}

impl fmt::Display for MaskedBallotBivariateMailboxError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => {
                write!(formatter, "canonical masked-ballot mailbox error: {error}")
            }
            Self::Commitment(error) => {
                write!(formatter, "masked-ballot mailbox source error: {error}")
            }
            Self::ObjectMismatch { field } => {
                write!(
                    formatter,
                    "masked-ballot mailbox object has a wrong {field}"
                )
            }
            Self::RosterMismatch => formatter
                .write_str("masked-ballot mailbox roster does not match the commitment layout"),
            Self::HolderRosterPositionOutOfRange {
                holder_roster_position,
                participant_count,
            } => write!(
                formatter,
                "masked-ballot mailbox holder {holder_roster_position} is outside participant count {participant_count}"
            ),
            Self::HeaderCount { expected, actual } => write!(
                formatter,
                "masked-ballot mailbox manifest has {actual} headers; expected {expected}"
            ),
            Self::CarrierCount { expected, actual } => write!(
                formatter,
                "masked-ballot mailbox package has {actual} carriers; expected {expected}"
            ),
            Self::EncapsulationRandomnessCount { expected, actual } => write!(
                formatter,
                "masked-ballot mailbox has {actual} encapsulation-randomness values; expected {expected}"
            ),
            Self::CarrierByteLength { expected, actual } => write!(
                formatter,
                "masked-ballot mailbox carrier has {actual} bytes; expected {expected}"
            ),
            Self::CarrierDigestMismatch {
                holder_roster_position,
            } => write!(
                formatter,
                "masked-ballot mailbox carrier for holder {holder_roster_position} does not match the signed manifest"
            ),
            Self::MalformedEncapsulationKey => formatter
                .write_str("masked-ballot mailbox roster contains a malformed ML-KEM-768 key"),
            Self::MalformedEncapsulationCiphertext => formatter
                .write_str("masked-ballot mailbox contains a malformed ML-KEM-768 ciphertext"),
            Self::DecapsulationKeyMismatch => formatter.write_str(
                "masked-ballot mailbox decapsulation key does not match the roster holder key",
            ),
            Self::DecapsulationFailed => {
                formatter.write_str("masked-ballot mailbox ML-KEM-768 decapsulation failed")
            }
            Self::AuthenticatedEncryptionFailed => {
                formatter.write_str("masked-ballot mailbox AES-256-GCM-SIV encryption failed")
            }
            Self::AuthenticatedDecryptionFailed => {
                formatter.write_str("masked-ballot mailbox AES-256-GCM-SIV authentication failed")
            }
            Self::MalformedSigningVerificationKey => formatter
                .write_str("masked-ballot mailbox roster contains a malformed ML-DSA-65 key"),
            Self::InvalidAuthorSignature => formatter
                .write_str("masked-ballot mailbox manifest has an invalid author signature"),
            Self::SignatureByteLength { expected, actual } => write!(
                formatter,
                "masked-ballot mailbox signature has {actual} bytes; expected {expected}"
            ),
            Self::IntegerConversion => formatter
                .write_str("masked-ballot mailbox integer does not fit its canonical width"),
            Self::ArithmeticOverflow => {
                formatter.write_str("masked-ballot mailbox arithmetic overflowed")
            }
            Self::StreamingHash => {
                formatter.write_str("masked-ballot mailbox streamed hash framing failed")
            }
        }
    }
}

impl std::error::Error for MaskedBallotBivariateMailboxError320 {}

/// Public root-bound control bytes for one fixed private-row carrier.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateMailboxHeaderBody320 {
    layout_identity: Hash512,
    root_body_identity: Hash512,
    participant_count: u16,
    author_roster_position: u16,
    holder_roster_position: u16,
    recipient_encapsulation_key_identity: Hash512,
    encapsulation_ciphertext: [u8; MASKED_BALLOT_BIVARIATE_MAILBOX_ML_KEM_CIPHERTEXT_BYTE_LENGTH],
    plaintext_byte_length: u64,
    carrier_byte_length: u64,
}

impl MaskedBallotBivariateMailboxHeaderBody320 {
    fn new(
        root_body: &MaskedBallotBivariateCommitmentRootBody320,
        roster: &Roster,
        holder_roster_position: u16,
        encapsulation_ciphertext: [u8;
            MASKED_BALLOT_BIVARIATE_MAILBOX_ML_KEM_CIPHERTEXT_BYTE_LENGTH],
    ) -> Result<Self, MaskedBallotBivariateMailboxError320> {
        let layout = root_body.layout();
        validate_roster_for_layout(layout, roster)?;
        let recipient_entry = require_roster_holder(roster, layout, holder_roster_position)?;
        let plaintext_byte_length = u64::try_from(
            masked_ballot_bivariate_private_row_body_byte_length(layout.participant_count())?,
        )
        .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?;
        let carrier_byte_length = plaintext_byte_length
            .checked_add(
                u64::try_from(MASKED_BALLOT_BIVARIATE_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH)
                    .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?,
            )
            .ok_or(MaskedBallotBivariateMailboxError320::ArithmeticOverflow)?;
        Ok(Self {
            layout_identity: layout.identity(),
            root_body_identity: root_body.identity()?,
            participant_count: layout.participant_count(),
            author_roster_position: layout.author_roster_position(),
            holder_roster_position,
            recipient_encapsulation_key_identity: derive_recipient_encapsulation_key_identity(
                layout,
                holder_roster_position,
                &recipient_entry.mailbox_encapsulation_key,
            )?,
            encapsulation_ciphertext,
            plaintext_byte_length,
            carrier_byte_length,
        })
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, MaskedBallotBivariateMailboxError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(MASKED_BALLOT_BIVARIATE_MAILBOX_HEADER_DOMAIN)?,
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_MAILBOX_ALGORITHM_IDENTIFIER,
                )?,
                CanonicalItem::hash512(self.layout_identity.into_bytes()),
                CanonicalItem::hash512(self.root_body_identity.into_bytes()),
                CanonicalItem::unsigned16(self.participant_count),
                CanonicalItem::unsigned16(self.author_roster_position),
                CanonicalItem::unsigned16(self.holder_roster_position),
                CanonicalItem::hash512(self.recipient_encapsulation_key_identity.into_bytes()),
                CanonicalItem::fixed_bytes(self.encapsulation_ciphertext)?,
                CanonicalItem::unsigned64(self.plaintext_byte_length),
                CanonicalItem::unsigned64(self.carrier_byte_length),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
        roster: &Roster,
        expected_holder_roster_position: u16,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateMailboxError320> {
        let tuple = CanonicalTuple::decode(bytes, &mailbox_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_MAILBOX_HEADER_DOMAIN,
            MAILBOX_HEADER_ITEM_COUNT,
        )?;
        require_ascii(
            &tuple.items[1],
            MASKED_BALLOT_BIVARIATE_MAILBOX_ALGORITHM_IDENTIFIER,
            "algorithm identifier",
        )?;
        let layout = expected_root.root_body().layout();
        validate_roster_for_layout(layout, roster)?;
        require_hash(&tuple.items[2], layout.identity(), "layout identity")?;
        require_hash(
            &tuple.items[3],
            expected_root.root_body_identity(),
            "root-body identity",
        )?;
        require_u16(
            &tuple.items[4],
            layout.participant_count(),
            "participant count",
        )?;
        require_u16(
            &tuple.items[5],
            layout.author_roster_position(),
            "author roster position",
        )?;
        require_u16(
            &tuple.items[6],
            expected_holder_roster_position,
            "holder roster position",
        )?;
        let recipient_entry =
            require_roster_holder(roster, layout, expected_holder_roster_position)?;
        let expected_key_identity = derive_recipient_encapsulation_key_identity(
            layout,
            expected_holder_roster_position,
            &recipient_entry.mailbox_encapsulation_key,
        )?;
        require_hash(
            &tuple.items[7],
            expected_key_identity,
            "recipient encapsulation-key identity",
        )?;
        let encapsulation_ciphertext = read_fixed_bytes::<
            MASKED_BALLOT_BIVARIATE_MAILBOX_ML_KEM_CIPHERTEXT_BYTE_LENGTH,
        >(&tuple.items[8], "encapsulation ciphertext")?;
        let expected_plaintext_byte_length = u64::try_from(
            masked_ballot_bivariate_private_row_body_byte_length(layout.participant_count())?,
        )
        .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?;
        require_u64(
            &tuple.items[9],
            expected_plaintext_byte_length,
            "plaintext byte length",
        )?;
        let expected_carrier_byte_length = expected_plaintext_byte_length
            .checked_add(
                u64::try_from(MASKED_BALLOT_BIVARIATE_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH)
                    .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?,
            )
            .ok_or(MaskedBallotBivariateMailboxError320::ArithmeticOverflow)?;
        require_u64(
            &tuple.items[10],
            expected_carrier_byte_length,
            "carrier byte length",
        )?;
        Ok(Self {
            layout_identity: layout.identity(),
            root_body_identity: expected_root.root_body_identity(),
            participant_count: layout.participant_count(),
            author_roster_position: layout.author_roster_position(),
            holder_roster_position: expected_holder_roster_position,
            recipient_encapsulation_key_identity: expected_key_identity,
            encapsulation_ciphertext,
            plaintext_byte_length: expected_plaintext_byte_length,
            carrier_byte_length: expected_carrier_byte_length,
        })
    }

    pub(crate) fn identity(&self) -> Result<Hash512, MaskedBallotBivariateMailboxError320> {
        Ok(hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_MAILBOX_HEADER_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

impl fmt::Debug for MaskedBallotBivariateMailboxHeaderBody320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateMailboxHeaderBody320")
            .field("layout_identity", &self.layout_identity)
            .field("root_body_identity", &self.root_body_identity)
            .field("participant_count", &self.participant_count)
            .field("author_roster_position", &self.author_roster_position)
            .field("holder_roster_position", &self.holder_roster_position)
            .field(
                "recipient_encapsulation_key_identity",
                &self.recipient_encapsulation_key_identity,
            )
            .field("encapsulation_ciphertext", &"[redacted]")
            .field("plaintext_byte_length", &self.plaintext_byte_length)
            .field("carrier_byte_length", &self.carrier_byte_length)
            .finish()
    }
}

/// One author-signed, roster-ordered inventory for every fixed-shape carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateMailboxManifestBody320 {
    layout_identity: Hash512,
    root_body_identity: Hash512,
    participant_count: u16,
    author_roster_position: u16,
    ordered_header_identities: Box<[Hash512]>,
    ordered_carrier_digests: Box<[Hash512]>,
}

impl MaskedBallotBivariateMailboxManifestBody320 {
    fn new(
        root_body: &MaskedBallotBivariateCommitmentRootBody320,
        headers: &[MaskedBallotBivariateMailboxHeaderBody320],
        carrier_digests: Vec<Hash512>,
    ) -> Result<Self, MaskedBallotBivariateMailboxError320> {
        let layout = root_body.layout();
        let expected_count = usize::from(layout.participant_count());
        if headers.len() != expected_count {
            return Err(MaskedBallotBivariateMailboxError320::HeaderCount {
                expected: expected_count,
                actual: headers.len(),
            });
        }
        if carrier_digests.len() != expected_count {
            return Err(MaskedBallotBivariateMailboxError320::CarrierCount {
                expected: expected_count,
                actual: carrier_digests.len(),
            });
        }
        let root_body_identity = root_body.identity()?;
        let mut ordered_header_identities = Vec::with_capacity(expected_count);
        for (holder_index, header) in headers.iter().enumerate() {
            let holder_roster_position = u16::try_from(holder_index)
                .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?;
            if header.layout_identity != layout.identity()
                || header.root_body_identity != root_body_identity
                || header.participant_count != layout.participant_count()
                || header.author_roster_position != layout.author_roster_position()
                || header.holder_roster_position != holder_roster_position
            {
                return Err(mailbox_object_mismatch("ordered header scope"));
            }
            ordered_header_identities.push(header.identity()?);
        }
        Ok(Self {
            layout_identity: layout.identity(),
            root_body_identity,
            participant_count: layout.participant_count(),
            author_roster_position: layout.author_roster_position(),
            ordered_header_identities: ordered_header_identities.into_boxed_slice(),
            ordered_carrier_digests: carrier_digests.into_boxed_slice(),
        })
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, MaskedBallotBivariateMailboxError320> {
        let mut items = Vec::with_capacity(
            MAILBOX_MANIFEST_PREFIX_ITEM_COUNT
                + self.ordered_header_identities.len()
                + self.ordered_carrier_digests.len(),
        );
        items.extend([
            CanonicalItem::nonempty_ascii(MASKED_BALLOT_BIVARIATE_MAILBOX_MANIFEST_DOMAIN)?,
            CanonicalItem::hash512(self.layout_identity.into_bytes()),
            CanonicalItem::hash512(self.root_body_identity.into_bytes()),
            CanonicalItem::unsigned16(self.participant_count),
            CanonicalItem::unsigned16(self.author_roster_position),
            CanonicalItem::unsigned16(
                u16::try_from(self.ordered_header_identities.len())
                    .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?,
            ),
            CanonicalItem::unsigned16(
                u16::try_from(self.ordered_carrier_digests.len())
                    .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?,
            ),
        ]);
        items.extend(
            self.ordered_header_identities
                .iter()
                .map(|identity| CanonicalItem::hash512(identity.into_bytes())),
        );
        items.extend(
            self.ordered_carrier_digests
                .iter()
                .map(|digest| CanonicalItem::hash512(digest.into_bytes())),
        );
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            items,
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateMailboxError320> {
        let layout = expected_root.root_body().layout();
        let participant_count = layout.participant_count();
        let digest_count = usize::from(participant_count);
        let expected_item_count = MAILBOX_MANIFEST_PREFIX_ITEM_COUNT
            .checked_add(
                digest_count
                    .checked_mul(2)
                    .ok_or(MaskedBallotBivariateMailboxError320::ArithmeticOverflow)?,
            )
            .ok_or(MaskedBallotBivariateMailboxError320::ArithmeticOverflow)?;
        let tuple = CanonicalTuple::decode(bytes, &mailbox_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_MAILBOX_MANIFEST_DOMAIN,
            expected_item_count,
        )?;
        require_hash(&tuple.items[1], layout.identity(), "layout identity")?;
        require_hash(
            &tuple.items[2],
            expected_root.root_body_identity(),
            "root-body identity",
        )?;
        require_u16(&tuple.items[3], participant_count, "participant count")?;
        require_u16(
            &tuple.items[4],
            layout.author_roster_position(),
            "author roster position",
        )?;
        require_u16(&tuple.items[5], participant_count, "header identity count")?;
        require_u16(&tuple.items[6], participant_count, "carrier digest count")?;
        let header_identity_end = MAILBOX_MANIFEST_PREFIX_ITEM_COUNT
            .checked_add(digest_count)
            .ok_or(MaskedBallotBivariateMailboxError320::ArithmeticOverflow)?;
        let ordered_header_identities = tuple.items
            [MAILBOX_MANIFEST_PREFIX_ITEM_COUNT..header_identity_end]
            .iter()
            .map(|item| read_hash(item, "header identity"))
            .collect::<Result<Vec<_>, _>>()?;
        let ordered_carrier_digests = tuple.items[header_identity_end..]
            .iter()
            .map(|item| read_hash(item, "carrier digest"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            layout_identity: layout.identity(),
            root_body_identity: expected_root.root_body_identity(),
            participant_count,
            author_roster_position: layout.author_roster_position(),
            ordered_header_identities: ordered_header_identities.into_boxed_slice(),
            ordered_carrier_digests: ordered_carrier_digests.into_boxed_slice(),
        })
    }

    pub(crate) fn identity(&self) -> Result<Hash512, MaskedBallotBivariateMailboxError320> {
        Ok(hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_MAILBOX_MANIFEST_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

/// Detached author signature over the exact aggregate carrier manifest.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateMailboxSignatureEnvelope320 {
    manifest_identity: Hash512,
    signature: [u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl MaskedBallotBivariateMailboxSignatureEnvelope320 {
    pub(crate) const fn new(
        manifest_identity: Hash512,
        signature: [u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            manifest_identity,
            signature,
        }
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, MaskedBallotBivariateMailboxError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_ENVELOPE_DOMAIN,
                )?,
                CanonicalItem::hash512(self.manifest_identity.into_bytes()),
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_manifest_identity: Hash512,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateMailboxError320> {
        let tuple = CanonicalTuple::decode(bytes, &mailbox_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_ENVELOPE_DOMAIN,
            MAILBOX_SIGNATURE_ENVELOPE_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected_manifest_identity,
            "manifest identity",
        )?;
        let signature = read_fixed_bytes::<MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH>(
            &tuple.items[2],
            "signature",
        )?;
        Ok(Self {
            manifest_identity: expected_manifest_identity,
            signature,
        })
    }
}

impl fmt::Debug for MaskedBallotBivariateMailboxSignatureEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateMailboxSignatureEnvelope320")
            .field("manifest_identity", &self.manifest_identity)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Exact fixed-shape encrypted package before the manifest signature exists.
///
/// The caller must retain each fresh encapsulation seed with the immutable
/// source until replay is no longer required. This type grants no receipt,
/// selected-set, release, or continuation authority.
pub(crate) struct SealedMaskedBallotBivariateMailboxPackage320 {
    headers: Box<[MaskedBallotBivariateMailboxHeaderBody320]>,
    encrypted_row_carriers: Box<[Zeroizing<Vec<u8>>]>,
    manifest: MaskedBallotBivariateMailboxManifestBody320,
}

impl SealedMaskedBallotBivariateMailboxPackage320 {
    pub(crate) fn headers(&self) -> &[MaskedBallotBivariateMailboxHeaderBody320] {
        &self.headers
    }

    pub(crate) fn encrypted_row_carriers(&self) -> &[Zeroizing<Vec<u8>>] {
        &self.encrypted_row_carriers
    }

    pub(crate) const fn manifest(&self) -> &MaskedBallotBivariateMailboxManifestBody320 {
        &self.manifest
    }
}

impl fmt::Debug for SealedMaskedBallotBivariateMailboxPackage320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedMaskedBallotBivariateMailboxPackage320")
            .field("headers", &self.headers)
            .field("encrypted_row_carriers", &"[redacted]")
            .field("manifest", &self.manifest)
            .finish()
    }
}

pub(crate) fn seal_masked_ballot_bivariate_mailbox_package_320(
    inventory: &MaskedBallotBivariateCommitmentInventory320,
    roster: &Roster,
    encapsulation_randomness: &[[u8; 32]],
) -> Result<SealedMaskedBallotBivariateMailboxPackage320, MaskedBallotBivariateMailboxError320> {
    let root_body = inventory.root_body();
    let layout = root_body.layout();
    validate_roster_for_layout(layout, roster)?;
    let expected_count = usize::from(layout.participant_count());
    if encapsulation_randomness.len() != expected_count {
        return Err(
            MaskedBallotBivariateMailboxError320::EncapsulationRandomnessCount {
                expected: expected_count,
                actual: encapsulation_randomness.len(),
            },
        );
    }
    let mut headers = Vec::with_capacity(expected_count);
    let mut encrypted_row_carriers = Vec::with_capacity(expected_count);
    let mut carrier_digests = Vec::with_capacity(expected_count);
    for (holder_index, holder_encapsulation_randomness) in
        encapsulation_randomness.iter().enumerate()
    {
        let holder_roster_position = u16::try_from(holder_index)
            .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?;
        let recipient_entry = require_roster_holder(roster, layout, holder_roster_position)?;
        let encapsulation_key =
            ml_kem_768::EncapsKey::try_from_bytes(recipient_entry.mailbox_encapsulation_key)
                .map_err(|_| MaskedBallotBivariateMailboxError320::MalformedEncapsulationKey)?;
        let (shared_secret, encapsulation_ciphertext) =
            encapsulation_key.encaps_from_seed(holder_encapsulation_randomness);
        let shared_secret_bytes = Zeroizing::new(shared_secret.into_bytes());
        let header = MaskedBallotBivariateMailboxHeaderBody320::new(
            root_body,
            roster,
            holder_roster_position,
            encapsulation_ciphertext.into_bytes(),
        )?;
        let header_bytes = header.canonical_bytes()?;
        let authenticated_encryption_key = derive_private_mailbox_key_256(
            &shared_secret_bytes,
            MASKED_BALLOT_BIVARIATE_MAILBOX_KEY_DERIVATION_LABEL,
            &header_bytes,
        );
        let associated_data = derive_mailbox_associated_data(&header)?;
        let nonce = derive_private_mailbox_nonce_96(
            &authenticated_encryption_key,
            MASKED_BALLOT_BIVARIATE_MAILBOX_NONCE_DERIVATION_LABEL,
            &associated_data,
        );
        let cipher = Aes256GcmSiv::new_from_slice(authenticated_encryption_key.as_ref())
            .map_err(|_| MaskedBallotBivariateMailboxError320::AuthenticatedEncryptionFailed)?;
        let private_row = inventory.private_row_body(holder_roster_position)?;
        let mut encrypted_row_carrier = Zeroizing::new(private_row.canonical_bytes()?);
        if encrypted_row_carrier.len()
            != usize::try_from(header.plaintext_byte_length)
                .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?
        {
            return Err(mailbox_object_mismatch("private-row byte length"));
        }
        let authentication_tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(nonce.as_ref()),
                &associated_data,
                &mut encrypted_row_carrier,
            )
            .map_err(|_| MaskedBallotBivariateMailboxError320::AuthenticatedEncryptionFailed)?;
        encrypted_row_carrier.extend_from_slice(authentication_tag.as_slice());
        let expected_carrier_byte_length = usize::try_from(header.carrier_byte_length)
            .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?;
        if encrypted_row_carrier.len() != expected_carrier_byte_length {
            return Err(MaskedBallotBivariateMailboxError320::CarrierByteLength {
                expected: expected_carrier_byte_length,
                actual: encrypted_row_carrier.len(),
            });
        }
        carrier_digests.push(hash_mailbox_carrier(&header, &encrypted_row_carrier)?);
        headers.push(header);
        encrypted_row_carriers.push(encrypted_row_carrier);
    }
    let manifest =
        MaskedBallotBivariateMailboxManifestBody320::new(root_body, &headers, carrier_digests)?;
    Ok(SealedMaskedBallotBivariateMailboxPackage320 {
        headers: headers.into_boxed_slice(),
        encrypted_row_carriers: encrypted_row_carriers.into_boxed_slice(),
        manifest,
    })
}

/// Positive author signature over one aggregate carrier manifest.
///
/// The type authenticates every public header identity and encrypted carrier
/// digest under one already authenticated commitment root. It does not prove
/// that any carrier decrypts, that a holder received it, or that a receipt or
/// continuation exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320 {
    manifest: MaskedBallotBivariateMailboxManifestBody320,
    manifest_identity: Hash512,
}

impl AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320 {
    pub(crate) const fn layout_identity(&self) -> Hash512 {
        self.manifest.layout_identity
    }

    pub(crate) const fn root_body_identity(&self) -> Hash512 {
        self.manifest.root_body_identity
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.manifest.participant_count
    }

    pub(crate) const fn author_roster_position(&self) -> u16 {
        self.manifest.author_roster_position
    }

    pub(crate) const fn manifest_identity(&self) -> Hash512 {
        self.manifest_identity
    }
}

pub(crate) fn verify_masked_ballot_bivariate_mailbox_manifest_signature_320(
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    roster: &Roster,
    manifest_bytes: &[u8],
    signature_envelope_bytes: &[u8],
) -> Result<
    AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    MaskedBallotBivariateMailboxError320,
> {
    let layout = authenticated_root.root_body().layout();
    validate_roster_for_layout(layout, roster)?;
    let manifest = MaskedBallotBivariateMailboxManifestBody320::from_canonical_bytes(
        authenticated_root,
        manifest_bytes,
    )?;
    let manifest_identity = manifest.identity()?;
    let signature_envelope =
        MaskedBallotBivariateMailboxSignatureEnvelope320::from_canonical_bytes(
            manifest_identity,
            signature_envelope_bytes,
        )?;
    let author_entry = require_roster_holder(roster, layout, layout.author_roster_position())?;
    let verification_key =
        ml_dsa_65::PublicKey::try_from_bytes(author_entry.signing_verification_key)
            .map_err(|_| MaskedBallotBivariateMailboxError320::MalformedSigningVerificationKey)?;
    if !verification_key.verify(
        manifest_bytes,
        &signature_envelope.signature,
        MASKED_BALLOT_BIVARIATE_MAILBOX_SIGNATURE_CONTEXT,
    ) {
        return Err(MaskedBallotBivariateMailboxError320::InvalidAuthorSignature);
    }
    Ok(AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320 {
        manifest,
        manifest_identity,
    })
}

/// Author-authenticated public carrier before recipient decapsulation.
///
/// This is the boundary at which altered or unsigned relay bytes have already
/// been refused. Any later authenticated-decryption or row-correspondence
/// failure is attributable to the author-signed carrier package, except for a
/// locally mismatched decapsulation key.
pub(crate) struct AuthorAuthenticatedMaskedBallotBivariateMailboxCarrier320 {
    header: MaskedBallotBivariateMailboxHeaderBody320,
    manifest_identity: Hash512,
    carrier_digest: Hash512,
    encrypted_row_carrier: Vec<u8>,
}

impl fmt::Debug for AuthorAuthenticatedMaskedBallotBivariateMailboxCarrier320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorAuthenticatedMaskedBallotBivariateMailboxCarrier320")
            .field("header", &self.header)
            .field("manifest_identity", &self.manifest_identity)
            .field("carrier_digest", &self.carrier_digest)
            .field("encrypted_row_carrier", &"[redacted]")
            .finish()
    }
}

pub(crate) fn verify_masked_ballot_bivariate_mailbox_public_carrier_320(
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    roster: &Roster,
    expected_holder_roster_position: u16,
    header_bytes: &[u8],
    encrypted_row_carrier: &[u8],
) -> Result<
    AuthorAuthenticatedMaskedBallotBivariateMailboxCarrier320,
    MaskedBallotBivariateMailboxError320,
> {
    require_manifest_matches_root(authenticated_root, authenticated_manifest)?;
    let layout = authenticated_root.root_body().layout();
    validate_roster_for_layout(layout, roster)?;
    let header = MaskedBallotBivariateMailboxHeaderBody320::from_canonical_bytes(
        authenticated_root,
        roster,
        expected_holder_roster_position,
        header_bytes,
    )?;
    let holder_index = usize::from(expected_holder_roster_position);
    let expected_header_identity = authenticated_manifest
        .manifest
        .ordered_header_identities
        .get(holder_index)
        .ok_or(
            MaskedBallotBivariateMailboxError320::HolderRosterPositionOutOfRange {
                holder_roster_position: expected_holder_roster_position,
                participant_count: layout.participant_count(),
            },
        )?;
    let header_identity = header.identity()?;
    if header_identity != *expected_header_identity {
        return Err(mailbox_object_mismatch("manifest header identity"));
    }
    let expected_carrier_byte_length = usize::try_from(header.carrier_byte_length)
        .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?;
    if encrypted_row_carrier.len() != expected_carrier_byte_length {
        return Err(MaskedBallotBivariateMailboxError320::CarrierByteLength {
            expected: expected_carrier_byte_length,
            actual: encrypted_row_carrier.len(),
        });
    }
    let carrier_digest = hash_mailbox_carrier(&header, encrypted_row_carrier)?;
    let expected_carrier_digest = authenticated_manifest
        .manifest
        .ordered_carrier_digests
        .get(holder_index)
        .ok_or(
            MaskedBallotBivariateMailboxError320::HolderRosterPositionOutOfRange {
                holder_roster_position: expected_holder_roster_position,
                participant_count: layout.participant_count(),
            },
        )?;
    if !bool::from(
        carrier_digest
            .as_bytes()
            .ct_eq(expected_carrier_digest.as_bytes()),
    ) {
        return Err(
            MaskedBallotBivariateMailboxError320::CarrierDigestMismatch {
                holder_roster_position: expected_holder_roster_position,
            },
        );
    }
    Ok(AuthorAuthenticatedMaskedBallotBivariateMailboxCarrier320 {
        header,
        manifest_identity: authenticated_manifest.manifest_identity,
        carrier_digest,
        encrypted_row_carrier: encrypted_row_carrier.to_vec(),
    })
}

/// Positive author-authenticated, confidential, root-matched local custody.
///
/// The exact private row bytes are retained because later included release
/// must reopen every root-bound value and salt. This type has no durable
/// receipt, all-roster terminal, selected-set, release, or continuation
/// authority.
pub(crate) struct AuthenticatedMaskedBallotBivariateMailboxDelivery320 {
    layout_identity: Hash512,
    root_body_identity: Hash512,
    manifest_identity: Hash512,
    carrier_header_identity: Hash512,
    carrier_digest: Hash512,
    author_roster_position: u16,
    holder_roster_position: u16,
    authenticated_private_row: AuthenticatedMaskedBallotBivariatePrivateRow320,
    retained_private_row_body_bytes: Zeroizing<Vec<u8>>,
}

impl AuthenticatedMaskedBallotBivariateMailboxDelivery320 {
    pub(crate) const fn layout_identity(&self) -> Hash512 {
        self.layout_identity
    }

    pub(crate) const fn root_body_identity(&self) -> Hash512 {
        self.root_body_identity
    }

    pub(crate) const fn manifest_identity(&self) -> Hash512 {
        self.manifest_identity
    }

    pub(crate) const fn carrier_header_identity(&self) -> Hash512 {
        self.carrier_header_identity
    }

    pub(crate) const fn carrier_digest(&self) -> Hash512 {
        self.carrier_digest
    }

    pub(crate) const fn author_roster_position(&self) -> u16 {
        self.author_roster_position
    }

    pub(crate) const fn holder_roster_position(&self) -> u16 {
        self.holder_roster_position
    }

    pub(crate) const fn authenticated_private_row(
        &self,
    ) -> &AuthenticatedMaskedBallotBivariatePrivateRow320 {
        &self.authenticated_private_row
    }

    pub(crate) fn retained_private_row_body_bytes(&self) -> &[u8] {
        &self.retained_private_row_body_bytes
    }
}

impl fmt::Debug for AuthenticatedMaskedBallotBivariateMailboxDelivery320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedMaskedBallotBivariateMailboxDelivery320")
            .field("layout_identity", &self.layout_identity)
            .field("root_body_identity", &self.root_body_identity)
            .field("manifest_identity", &self.manifest_identity)
            .field("carrier_header_identity", &self.carrier_header_identity)
            .field("carrier_digest", &self.carrier_digest)
            .field("author_roster_position", &self.author_roster_position)
            .field("holder_roster_position", &self.holder_roster_position)
            .field("authenticated_private_row", &"[redacted]")
            .field("retained_private_row_body_bytes", &"[redacted]")
            .finish()
    }
}

pub(crate) fn complete_masked_ballot_bivariate_mailbox_delivery_320(
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    roster: &Roster,
    public_carrier: AuthorAuthenticatedMaskedBallotBivariateMailboxCarrier320,
    recipient_decapsulation_key: &ml_kem_768::DecapsKey,
) -> Result<
    AuthenticatedMaskedBallotBivariateMailboxDelivery320,
    MaskedBallotBivariateMailboxError320,
> {
    let layout = authenticated_root.root_body().layout();
    validate_roster_for_layout(layout, roster)?;
    if public_carrier.header.layout_identity != layout.identity()
        || public_carrier.header.root_body_identity != authenticated_root.root_body_identity()
        || public_carrier.header.participant_count != layout.participant_count()
        || public_carrier.header.author_roster_position != layout.author_roster_position()
    {
        return Err(mailbox_object_mismatch("public carrier root scope"));
    }
    let holder_roster_position = public_carrier.header.holder_roster_position;
    require_recipient_decapsulation_key(
        roster,
        layout,
        holder_roster_position,
        recipient_decapsulation_key,
    )?;
    let encapsulation_ciphertext =
        ml_kem_768::CipherText::try_from_bytes(public_carrier.header.encapsulation_ciphertext)
            .map_err(|_| MaskedBallotBivariateMailboxError320::MalformedEncapsulationCiphertext)?;
    let shared_secret = recipient_decapsulation_key
        .try_decaps(&encapsulation_ciphertext)
        .map_err(|_| MaskedBallotBivariateMailboxError320::DecapsulationFailed)?;
    let shared_secret_bytes = Zeroizing::new(shared_secret.into_bytes());
    let header_bytes = public_carrier.header.canonical_bytes()?;
    let authenticated_encryption_key = derive_private_mailbox_key_256(
        &shared_secret_bytes,
        MASKED_BALLOT_BIVARIATE_MAILBOX_KEY_DERIVATION_LABEL,
        &header_bytes,
    );
    let associated_data = derive_mailbox_associated_data(&public_carrier.header)?;
    let nonce = derive_private_mailbox_nonce_96(
        &authenticated_encryption_key,
        MASKED_BALLOT_BIVARIATE_MAILBOX_NONCE_DERIVATION_LABEL,
        &associated_data,
    );
    let plaintext_byte_length = usize::try_from(public_carrier.header.plaintext_byte_length)
        .map_err(|_| MaskedBallotBivariateMailboxError320::IntegerConversion)?;
    let (ciphertext, authentication_tag_bytes) = public_carrier
        .encrypted_row_carrier
        .split_at(plaintext_byte_length);
    let mut private_row_body_bytes = Zeroizing::new(ciphertext.to_vec());
    let cipher = Aes256GcmSiv::new_from_slice(authenticated_encryption_key.as_ref())
        .map_err(|_| MaskedBallotBivariateMailboxError320::AuthenticatedDecryptionFailed)?;
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce.as_ref()),
            &associated_data,
            &mut private_row_body_bytes,
            Tag::from_slice(authentication_tag_bytes),
        )
        .map_err(|_| MaskedBallotBivariateMailboxError320::AuthenticatedDecryptionFailed)?;
    let authenticated_private_row = verify_masked_ballot_bivariate_private_row_320(
        authenticated_root,
        &private_row_body_bytes,
    )?;
    if authenticated_private_row.holder_roster_position() != holder_roster_position
        || authenticated_private_row.author_roster_position() != layout.author_roster_position()
        || authenticated_private_row.root_body_identity() != authenticated_root.root_body_identity()
    {
        return Err(mailbox_object_mismatch("authenticated private-row scope"));
    }
    Ok(AuthenticatedMaskedBallotBivariateMailboxDelivery320 {
        layout_identity: layout.identity(),
        root_body_identity: authenticated_root.root_body_identity(),
        manifest_identity: public_carrier.manifest_identity,
        carrier_header_identity: public_carrier.header.identity()?,
        carrier_digest: public_carrier.carrier_digest,
        author_roster_position: layout.author_roster_position(),
        holder_roster_position,
        authenticated_private_row,
        retained_private_row_body_bytes: private_row_body_bytes,
    })
}

fn require_manifest_matches_root(
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
) -> Result<(), MaskedBallotBivariateMailboxError320> {
    let layout = authenticated_root.root_body().layout();
    if authenticated_manifest.manifest.layout_identity != layout.identity()
        || authenticated_manifest.manifest.root_body_identity
            != authenticated_root.root_body_identity()
        || authenticated_manifest.manifest.participant_count != layout.participant_count()
        || authenticated_manifest.manifest.author_roster_position != layout.author_roster_position()
    {
        return Err(mailbox_object_mismatch("manifest root scope"));
    }
    Ok(())
}

fn derive_recipient_encapsulation_key_identity(
    layout: MaskedBallotBivariateCommitmentLayout320,
    holder_roster_position: u16,
    encapsulation_key: &[u8],
) -> Result<Hash512, MaskedBallotBivariateMailboxError320> {
    Ok(hash_foundation_tuple_512(
        MASKED_BALLOT_BIVARIATE_MAILBOX_RECIPIENT_KEY_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(layout.identity().into_bytes()),
            CanonicalItem::unsigned16(holder_roster_position),
            CanonicalItem::fixed_bytes(encapsulation_key)?,
        ],
    )?)
}

fn derive_mailbox_associated_data(
    header: &MaskedBallotBivariateMailboxHeaderBody320,
) -> Result<Vec<u8>, MaskedBallotBivariateMailboxError320> {
    Ok(CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        vec![
            CanonicalItem::nonempty_ascii(MASKED_BALLOT_BIVARIATE_MAILBOX_ASSOCIATED_DATA_DOMAIN)?,
            CanonicalItem::hash512(header.layout_identity.into_bytes()),
            CanonicalItem::hash512(header.root_body_identity.into_bytes()),
            CanonicalItem::hash512(header.identity()?.into_bytes()),
            CanonicalItem::unsigned64(header.plaintext_byte_length),
            CanonicalItem::unsigned64(header.carrier_byte_length),
        ],
    )
    .encode()?)
}

fn hash_mailbox_carrier(
    header: &MaskedBallotBivariateMailboxHeaderBody320,
    encrypted_row_carrier: &[u8],
) -> Result<Hash512, MaskedBallotBivariateMailboxError320> {
    let mut hasher = StreamingFoundationTupleHash512::new_variable_bytes(
        MASKED_BALLOT_BIVARIATE_MAILBOX_CARRIER_DIGEST_DOMAIN,
        &[
            CanonicalItem::hash512(header.layout_identity.into_bytes()),
            CanonicalItem::hash512(header.root_body_identity.into_bytes()),
            CanonicalItem::unsigned16(header.holder_roster_position),
            CanonicalItem::hash512(header.identity()?.into_bytes()),
        ],
        encrypted_row_carrier.len(),
    )
    .map_err(|_| MaskedBallotBivariateMailboxError320::StreamingHash)?;
    hasher
        .absorb(encrypted_row_carrier)
        .map_err(|_| MaskedBallotBivariateMailboxError320::StreamingHash)?;
    hasher
        .finalize()
        .map_err(|_| MaskedBallotBivariateMailboxError320::StreamingHash)
}

#[cfg(test)]
pub(super) fn hash_masked_ballot_bivariate_mailbox_carrier_for_test(
    header: &MaskedBallotBivariateMailboxHeaderBody320,
    encrypted_row_carrier: &[u8],
) -> Result<Hash512, MaskedBallotBivariateMailboxError320> {
    hash_mailbox_carrier(header, encrypted_row_carrier)
}

fn validate_roster_for_layout(
    layout: MaskedBallotBivariateCommitmentLayout320,
    roster: &Roster,
) -> Result<(), MaskedBallotBivariateMailboxError320> {
    roster
        .validate()
        .map_err(|_| MaskedBallotBivariateMailboxError320::RosterMismatch)?;
    if roster.entries.len() != usize::from(layout.participant_count())
        || roster
            .roster_hash()
            .map_err(|_| MaskedBallotBivariateMailboxError320::RosterMismatch)?
            != layout.preparation_context().roster_hash()
    {
        return Err(MaskedBallotBivariateMailboxError320::RosterMismatch);
    }
    Ok(())
}

fn require_roster_holder(
    roster: &Roster,
    layout: MaskedBallotBivariateCommitmentLayout320,
    holder_roster_position: u16,
) -> Result<&crate::foundation::RosterEntry, MaskedBallotBivariateMailboxError320> {
    roster
        .entries
        .get(usize::from(holder_roster_position))
        .filter(|entry| entry.roster_position == holder_roster_position)
        .ok_or(
            MaskedBallotBivariateMailboxError320::HolderRosterPositionOutOfRange {
                holder_roster_position,
                participant_count: layout.participant_count(),
            },
        )
}

fn require_recipient_decapsulation_key(
    roster: &Roster,
    layout: MaskedBallotBivariateCommitmentLayout320,
    holder_roster_position: u16,
    recipient_decapsulation_key: &ml_kem_768::DecapsKey,
) -> Result<(), MaskedBallotBivariateMailboxError320> {
    let recipient_entry = require_roster_holder(roster, layout, holder_roster_position)?;
    let decapsulation_key_bytes = Zeroizing::new(recipient_decapsulation_key.clone().into_bytes());
    let public_key_start = ML_KEM_768_DECAPSULATION_KEY_PUBLIC_KEY_OFFSET;
    let public_key_end = public_key_start
        .checked_add(recipient_entry.mailbox_encapsulation_key.len())
        .ok_or(MaskedBallotBivariateMailboxError320::ArithmeticOverflow)?;
    if !bool::from(
        decapsulation_key_bytes[public_key_start..public_key_end]
            .ct_eq(&recipient_entry.mailbox_encapsulation_key),
    ) {
        return Err(MaskedBallotBivariateMailboxError320::DecapsulationKeyMismatch);
    }
    Ok(())
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), MaskedBallotBivariateMailboxError320> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(mailbox_object_mismatch("schema identifier"));
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(mailbox_object_mismatch("schema version"));
    }
    if tuple.items.len() != expected_item_count {
        return Err(mailbox_object_mismatch("item count"));
    }
    require_ascii(&tuple.items[0], expected_domain, "object domain")
}

fn require_ascii(
    item: &CanonicalItem,
    expected: &str,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateMailboxError320> {
    if item.item_type() != CanonicalItemType::Ascii
        || item.variable_value_bytes()? != expected.as_bytes()
    {
        return Err(mailbox_object_mismatch(field));
    }
    Ok(())
}

fn read_hash(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<Hash512, MaskedBallotBivariateMailboxError320> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(mailbox_object_mismatch(field));
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| mailbox_object_mismatch(field))?;
    Ok(Hash512::from_bytes(bytes))
}

fn require_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateMailboxError320> {
    if read_hash(item, field)? != expected {
        return Err(mailbox_object_mismatch(field));
    }
    Ok(())
}

fn read_fixed_bytes<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<[u8; BYTE_LENGTH], MaskedBallotBivariateMailboxError320> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(mailbox_object_mismatch(field));
    }
    item.canonical_bytes().try_into().map_err(|_| {
        if field == "signature" {
            MaskedBallotBivariateMailboxError320::SignatureByteLength {
                expected: BYTE_LENGTH,
                actual: item.canonical_bytes().len(),
            }
        } else {
            mailbox_object_mismatch(field)
        }
    })
}

fn read_u16(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u16, MaskedBallotBivariateMailboxError320> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(mailbox_object_mismatch(field));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| mailbox_object_mismatch(field))?;
    Ok(u16::from_le_bytes(bytes))
}

fn require_u16(
    item: &CanonicalItem,
    expected: u16,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateMailboxError320> {
    if read_u16(item, field)? != expected {
        return Err(mailbox_object_mismatch(field));
    }
    Ok(())
}

fn read_u64(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u64, MaskedBallotBivariateMailboxError320> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(mailbox_object_mismatch(field));
    }
    let bytes: [u8; 8] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| mailbox_object_mismatch(field))?;
    Ok(u64::from_le_bytes(bytes))
}

fn require_u64(
    item: &CanonicalItem,
    expected: u64,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateMailboxError320> {
    if read_u64(item, field)? != expected {
        return Err(mailbox_object_mismatch(field));
    }
    Ok(())
}

const fn mailbox_object_mismatch(field: &'static str) -> MaskedBallotBivariateMailboxError320 {
    MaskedBallotBivariateMailboxError320::ObjectMismatch { field }
}

fn mailbox_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_MAILBOX_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_MAILBOX_CONTROL_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_MAILBOX_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_MAILBOX_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_MAILBOX_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}

const _: () = assert!(ML_KEM_768_DECAPSULATION_KEY_PUBLIC_KEY_OFFSET == 1_152);
const _: () = assert!(MASKED_BALLOT_BIVARIATE_MAILBOX_ML_KEM_CIPHERTEXT_BYTE_LENGTH == 1_088);
const _: () = assert!(CANONICAL_TUPLE_HEADER_BYTE_LENGTH == 8);
const _: () = assert!(CANONICAL_ITEM_HEADER_BYTE_LENGTH == 6);
const _: () = assert!(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH == 4);
