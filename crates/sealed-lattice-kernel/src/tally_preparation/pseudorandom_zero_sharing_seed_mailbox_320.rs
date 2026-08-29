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
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    Hash512, Roster, StreamingFoundationTupleHash512, hash_foundation_tuple_512,
};

use super::{
    private_mailbox_kmac_256::{derive_private_mailbox_key_256, derive_private_mailbox_nonce_96},
    pseudorandom_zero_sharing_seed_catalog_root_terminal_320::{
        PseudorandomZeroSharingSeedCatalogRootTerminalError320,
        RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    },
    pseudorandom_zero_sharing_seed_catalog_signature_320::ML_DSA_65_SIGNATURE_BYTE_LENGTH,
    pseudorandom_zero_sharing_seed_delivery_320::{
        PseudorandomZeroSharingSeedDeliveryDescriptorBody320,
        PseudorandomZeroSharingSeedDeliveryError320,
        PseudorandomZeroSharingSeedDeliveryVerifier320,
        RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320,
        derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320,
    },
};

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const MAILBOX_HEADER_ITEM_COUNT: usize = 9;
const MAILBOX_KEY_DERIVATION_CONTEXT_ITEM_COUNT: usize = 8;
const MAILBOX_MANIFEST_ITEM_COUNT: usize = 3;
const MAILBOX_SIGNATURE_BODY_ITEM_COUNT: usize = 7;
const MAILBOX_SIGNATURE_ENVELOPE_ITEM_COUNT: usize = 3;
const MAILBOX_CHUNK_ASSOCIATED_DATA_ITEM_COUNT: usize = 6;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;
const CANONICAL_HOMOGENEOUS_LIST_HEADER_BYTE_LENGTH: usize = 6;
const MAXIMUM_MAILBOX_CONTROL_OBJECT_BYTE_LENGTH: usize = 512 * 1024;
const MAXIMUM_MAILBOX_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 384 * 1024;
const MAXIMUM_MAILBOX_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 2 * 1024 * 1024;
const MAXIMUM_MAILBOX_CHUNK_COUNT: usize = 4_096;
const ML_KEM_768_DECAPSULATION_KEY_PUBLIC_KEY_OFFSET: usize = 384 * 3;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_ALGORITHM_IDENTIFIER: &str =
    "ml-kem-768+kmac256+aes-256-gcm-siv";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-header";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-header-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_CONTEXT_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-key-derivation-context";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_COMMITMENT_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-key-commitment";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATED_INCONSISTENCY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-authenticated-inconsistency-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_RECIPIENT_KEY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-recipient-key-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_ASSOCIATED_DATA_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-chunk-associated-data";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_DIGEST_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-chunk-digest";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MANIFEST_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-manifest";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MANIFEST_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-manifest-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-signature-body";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-mailbox-signature-envelope";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/preparation/seed-mailbox-manifest";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_LABEL: &[u8] =
    b"sealed-lattice/v1/preparation/seed-mailbox-aead-key";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_NONCE_DERIVATION_LABEL: &[u8] =
    b"sealed-lattice/v1/preparation/seed-mailbox-aead-nonce";

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH: usize = 16;
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH: usize =
    FOUNDATION_PROFILE.stream_chunk_byte_length
        - PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH;
pub(crate) const ML_KEM_768_CIPHERTEXT_BYTE_LENGTH: usize = ml_kem_768::CT_LEN;
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + MAILBOX_HEADER_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_DOMAIN.len()
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_ALGORITHM_IDENTIFIER.len()
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + super::pseudorandom_zero_sharing_seed_delivery_320::PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_BODY_BYTE_LENGTH
        + 2 * Hash512::BYTE_LENGTH
        + ML_KEM_768_CIPHERTEXT_BYTE_LENGTH
        + 3 * size_of::<u64>();
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_CONTEXT_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + MAILBOX_KEY_DERIVATION_CONTEXT_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_CONTEXT_DOMAIN.len()
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_ALGORITHM_IDENTIFIER.len()
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + super::pseudorandom_zero_sharing_seed_delivery_320::PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_BODY_BYTE_LENGTH
        + Hash512::BYTE_LENGTH
        + ML_KEM_768_CIPHERTEXT_BYTE_LENGTH
        + 3 * size_of::<u64>();
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_ASSOCIATED_DATA_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + MAILBOX_CHUNK_ASSOCIATED_DATA_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_ASSOCIATED_DATA_DOMAIN.len()
        + Hash512::BYTE_LENGTH
        + 4 * size_of::<u64>();
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + MAILBOX_SIGNATURE_BODY_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_DOMAIN.len()
        + 3 * Hash512::BYTE_LENGTH
        + 3 * size_of::<u16>();
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + MAILBOX_SIGNATURE_ENVELOPE_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_DOMAIN.len()
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_BYTE_LENGTH
        + ML_DSA_65_SIGNATURE_BYTE_LENGTH;

pub(crate) fn pseudorandom_zero_sharing_seed_mailbox_manifest_body_byte_length(
    chunk_count: u64,
) -> Result<usize, PseudorandomZeroSharingSeedMailboxError320> {
    let chunk_count = usize::try_from(chunk_count)
        .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
    if chunk_count == 0 || chunk_count > MAXIMUM_MAILBOX_CHUNK_COUNT {
        return Err(mailbox_object_mismatch("chunk count"));
    }
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        .checked_add(MAILBOX_MANIFEST_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH)
        .and_then(|length| length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH))
        .and_then(|length| {
            length.checked_add(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MANIFEST_DOMAIN.len())
        })
        .and_then(|length| length.checked_add(Hash512::BYTE_LENGTH))
        .and_then(|length| length.checked_add(CANONICAL_HOMOGENEOUS_LIST_HEADER_BYTE_LENGTH))
        .and_then(|length| {
            chunk_count
                .checked_mul(Hash512::BYTE_LENGTH)
                .and_then(|digest_bytes| length.checked_add(digest_bytes))
        })
        .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)
}

pub(crate) fn pseudorandom_zero_sharing_seed_mailbox_control_and_tag_byte_length(
    chunk_count: u64,
) -> Result<u64, PseudorandomZeroSharingSeedMailboxError320> {
    let manifest_byte_length =
        pseudorandom_zero_sharing_seed_mailbox_manifest_body_byte_length(chunk_count)?;
    let authentication_tag_byte_length = chunk_count
        .checked_mul(
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH)
                .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?,
        )
        .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
    u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_BODY_BYTE_LENGTH)
        .ok()
        .and_then(|length| {
            u64::try_from(manifest_byte_length)
                .ok()
                .and_then(|manifest_length| length.checked_add(manifest_length))
        })
        .and_then(|length| {
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH)
                .ok()
                .and_then(|signature_length| length.checked_add(signature_length))
        })
        .and_then(|length| length.checked_add(authentication_tag_byte_length))
        .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedMailboxError320 {
    Canonical(CanonicalCodecError),
    Delivery(PseudorandomZeroSharingSeedDeliveryError320),
    RootTerminal(PseudorandomZeroSharingSeedCatalogRootTerminalError320),
    ObjectMismatch {
        field: &'static str,
    },
    RosterMismatch,
    EndpointMismatch,
    IntegerConversion,
    ArithmeticOverflow,
    ChunkCount {
        expected: usize,
        actual: usize,
    },
    ChunkOrder {
        expected: usize,
        actual: usize,
    },
    ChunkByteLength {
        expected: usize,
        actual: usize,
    },
    ChunkDigestMismatch {
        chunk_index: usize,
    },
    PlaintextEntryTruncated,
    MalformedEncapsulationKey,
    MalformedEncapsulationCiphertext,
    DecapsulationKeyMismatch,
    DecapsulationFailed,
    AuthenticatedEncryptionFailed,
    AuthenticatedDecryptionFailed,
    AuthenticatedEncryptionKeyCommitmentMismatch,
    NoAuthenticatedInconsistency,
    MalformedSigningVerificationKey,
    FixedByteLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidSenderSignature,
    StreamingHash,
}

impl From<CanonicalCodecError> for PseudorandomZeroSharingSeedMailboxError320 {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<PseudorandomZeroSharingSeedDeliveryError320>
    for PseudorandomZeroSharingSeedMailboxError320
{
    fn from(error: PseudorandomZeroSharingSeedDeliveryError320) -> Self {
        Self::Delivery(error)
    }
}

impl From<PseudorandomZeroSharingSeedCatalogRootTerminalError320>
    for PseudorandomZeroSharingSeedMailboxError320
{
    fn from(error: PseudorandomZeroSharingSeedCatalogRootTerminalError320) -> Self {
        Self::RootTerminal(error)
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedMailboxError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => write!(formatter, "canonical seed-mailbox error: {error}"),
            Self::Delivery(error) => write!(formatter, "seed-mailbox delivery error: {error}"),
            Self::RootTerminal(error) => {
                write!(formatter, "seed-mailbox root-terminal error: {error}")
            }
            Self::ObjectMismatch { field } => {
                write!(formatter, "seed-mailbox object has a wrong {field}")
            }
            Self::RosterMismatch => formatter
                .write_str("seed-mailbox roster does not match the terminal preparation context"),
            Self::EndpointMismatch => {
                formatter.write_str("seed-mailbox sender or recipient does not match")
            }
            Self::IntegerConversion => {
                formatter.write_str("seed-mailbox integer does not fit its canonical width")
            }
            Self::ArithmeticOverflow => formatter.write_str("seed-mailbox arithmetic overflowed"),
            Self::ChunkCount { expected, actual } => write!(
                formatter,
                "seed-mailbox stream has {actual} chunks; expected {expected}"
            ),
            Self::ChunkOrder { expected, actual } => write!(
                formatter,
                "seed-mailbox chunk {actual} is out of order; expected {expected}"
            ),
            Self::ChunkByteLength { expected, actual } => write!(
                formatter,
                "seed-mailbox chunk has {actual} bytes; expected {expected}"
            ),
            Self::ChunkDigestMismatch { chunk_index } => write!(
                formatter,
                "seed-mailbox chunk {chunk_index} does not match the signed manifest"
            ),
            Self::PlaintextEntryTruncated => {
                formatter.write_str("seed-mailbox plaintext ends within a seed-delivery entry")
            }
            Self::MalformedEncapsulationKey => {
                formatter.write_str("seed-mailbox roster contains a malformed ML-KEM-768 key")
            }
            Self::MalformedEncapsulationCiphertext => {
                formatter.write_str("seed-mailbox contains a malformed ML-KEM-768 ciphertext")
            }
            Self::DecapsulationKeyMismatch => formatter.write_str(
                "seed-mailbox decapsulation key does not match the roster recipient key",
            ),
            Self::DecapsulationFailed => {
                formatter.write_str("seed-mailbox ML-KEM-768 decapsulation failed")
            }
            Self::AuthenticatedEncryptionFailed => {
                formatter.write_str("seed-mailbox AES-256-GCM-SIV encryption failed")
            }
            Self::AuthenticatedDecryptionFailed => {
                formatter.write_str("seed-mailbox AES-256-GCM-SIV authentication failed")
            }
            Self::AuthenticatedEncryptionKeyCommitmentMismatch => formatter
                .write_str("seed-mailbox disclosed AEAD key does not match the signed commitment"),
            Self::NoAuthenticatedInconsistency => formatter.write_str(
                "seed-mailbox disclosed AEAD key authenticates a valid committed delivery",
            ),
            Self::MalformedSigningVerificationKey => {
                formatter.write_str("seed-mailbox roster contains a malformed ML-DSA-65 key")
            }
            Self::FixedByteLength {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "seed-mailbox {field} has {actual} bytes; expected {expected}"
            ),
            Self::InvalidSenderSignature => {
                formatter.write_str("seed-mailbox manifest has an invalid sender signature")
            }
            Self::StreamingHash => formatter.write_str("seed-mailbox streamed hash framing failed"),
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedMailboxError320 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PseudorandomZeroSharingSeedMailboxChunkGeometry320 {
    plaintext_byte_offset: u64,
    plaintext_byte_length: usize,
    carrier_byte_length: usize,
}

/// Public, secret-free predecessor for one encrypted ordered delivery stream.
///
/// The exact seed-delivery descriptor carries the parameter, preparation,
/// terminal, sender, recipient, and plaintext-length bindings. The header adds
/// the selected recipient key, fresh ML-KEM ciphertext, fixed algorithm
/// identity, and complete chunk/carrier accounting without hashing plaintext.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedMailboxHeaderBody320 {
    delivery_descriptor: PseudorandomZeroSharingSeedDeliveryDescriptorBody320,
    recipient_encapsulation_key_identity: Hash512,
    encapsulation_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH],
    authenticated_encryption_key_commitment: Hash512,
    maximum_plaintext_chunk_byte_length: u64,
    chunk_count: u64,
    total_carrier_byte_length: u64,
}

impl PseudorandomZeroSharingSeedMailboxHeaderBody320 {
    pub(crate) fn new(
        root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
        roster: &Roster,
        sender_position: u16,
        recipient_position: u16,
        descriptor_bytes: &[u8],
        encapsulation_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH],
        authenticated_encryption_key_commitment: Hash512,
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        validate_roster_for_terminal(root_terminal, roster)?;
        let delivery_descriptor = require_expected_delivery_descriptor(
            root_terminal,
            sender_position,
            recipient_position,
            descriptor_bytes,
        )?;
        let recipient_entry = roster
            .entries
            .get(usize::from(recipient_position))
            .filter(|entry| entry.roster_position == recipient_position)
            .ok_or(PseudorandomZeroSharingSeedMailboxError320::EndpointMismatch)?;
        let recipient_encapsulation_key_identity = derive_recipient_encapsulation_key_identity(
            recipient_position,
            &recipient_entry.mailbox_encapsulation_key,
        )?;
        let (chunk_count, total_carrier_byte_length) =
            derive_mailbox_stream_geometry(delivery_descriptor.payload_byte_length())?;
        Ok(Self {
            delivery_descriptor,
            recipient_encapsulation_key_identity,
            encapsulation_ciphertext,
            authenticated_encryption_key_commitment,
            maximum_plaintext_chunk_byte_length: u64::try_from(
                PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH,
            )
            .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?,
            chunk_count,
            total_carrier_byte_length,
        })
    }

    pub(crate) const fn delivery_descriptor(
        &self,
    ) -> PseudorandomZeroSharingSeedDeliveryDescriptorBody320 {
        self.delivery_descriptor
    }

    pub(crate) const fn recipient_encapsulation_key_identity(&self) -> Hash512 {
        self.recipient_encapsulation_key_identity
    }

    pub(crate) const fn encapsulation_ciphertext(
        &self,
    ) -> &[u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH] {
        &self.encapsulation_ciphertext
    }

    pub(crate) const fn authenticated_encryption_key_commitment(&self) -> Hash512 {
        self.authenticated_encryption_key_commitment
    }

    pub(crate) const fn maximum_plaintext_chunk_byte_length(&self) -> u64 {
        self.maximum_plaintext_chunk_byte_length
    }

    pub(crate) const fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    pub(crate) const fn total_carrier_byte_length(&self) -> u64 {
        self.total_carrier_byte_length
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedMailboxError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_DOMAIN,
                )?,
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_ALGORITHM_IDENTIFIER,
                )?,
                CanonicalItem::variable_bytes(self.delivery_descriptor.canonical_bytes()?)?,
                CanonicalItem::hash512(self.recipient_encapsulation_key_identity.into_bytes()),
                CanonicalItem::fixed_bytes(self.encapsulation_ciphertext)?,
                CanonicalItem::hash512(self.authenticated_encryption_key_commitment.into_bytes()),
                CanonicalItem::unsigned64(self.maximum_plaintext_chunk_byte_length),
                CanonicalItem::unsigned64(self.chunk_count),
                CanonicalItem::unsigned64(self.total_carrier_byte_length),
            ],
        )
        .encode()?)
    }

    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        let tuple = CanonicalTuple::decode(bytes, &mailbox_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_DOMAIN,
            MAILBOX_HEADER_ITEM_COUNT,
        )?;
        require_ascii(
            &tuple.items[1],
            PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_ALGORITHM_IDENTIFIER,
            "algorithm identifier",
        )?;
        let descriptor_bytes = read_variable_bytes(&tuple.items[2], "delivery descriptor")?;
        let delivery_descriptor =
            PseudorandomZeroSharingSeedDeliveryDescriptorBody320::from_canonical_bytes(
                descriptor_bytes,
            )?;
        let recipient_encapsulation_key_identity =
            read_hash512(&tuple.items[3], "recipient encapsulation-key identity")?;
        let encapsulation_ciphertext = read_fixed_bytes::<ML_KEM_768_CIPHERTEXT_BYTE_LENGTH>(
            &tuple.items[4],
            "encapsulation ciphertext",
        )?;
        let header = Self {
            delivery_descriptor,
            recipient_encapsulation_key_identity,
            encapsulation_ciphertext,
            authenticated_encryption_key_commitment: read_hash512(
                &tuple.items[5],
                "authenticated-encryption key commitment",
            )?,
            maximum_plaintext_chunk_byte_length: read_u64(
                &tuple.items[6],
                "maximum plaintext chunk byte length",
            )?,
            chunk_count: read_u64(&tuple.items[7], "chunk count")?,
            total_carrier_byte_length: read_u64(&tuple.items[8], "total carrier byte length")?,
        };
        header.validate_internal_geometry()?;
        Ok(header)
    }

    pub(crate) fn identity(&self) -> Result<Hash512, PseudorandomZeroSharingSeedMailboxError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn key_derivation_context_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedMailboxError320> {
        let bytes = CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_CONTEXT_DOMAIN,
                )?,
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_ALGORITHM_IDENTIFIER,
                )?,
                CanonicalItem::variable_bytes(self.delivery_descriptor.canonical_bytes()?)?,
                CanonicalItem::hash512(self.recipient_encapsulation_key_identity.into_bytes()),
                CanonicalItem::fixed_bytes(self.encapsulation_ciphertext)?,
                CanonicalItem::unsigned64(self.maximum_plaintext_chunk_byte_length),
                CanonicalItem::unsigned64(self.chunk_count),
                CanonicalItem::unsigned64(self.total_carrier_byte_length),
            ],
        )
        .encode()?;
        if bytes.len() != PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_CONTEXT_BYTE_LENGTH
        {
            return Err(mailbox_object_mismatch(
                "key-derivation context byte length",
            ));
        }
        Ok(bytes)
    }

    pub(crate) fn encrypted_chunk_byte_lengths(
        &self,
    ) -> Result<Vec<usize>, PseudorandomZeroSharingSeedMailboxError320> {
        let chunk_count = usize::try_from(self.chunk_count)
            .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
        (0..chunk_count)
            .map(|chunk_index| {
                self.chunk_geometry(chunk_index)
                    .map(|geometry| geometry.carrier_byte_length)
            })
            .collect()
    }

    fn validate_internal_geometry(&self) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
        let expected_maximum = u64::try_from(
            PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH,
        )
        .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
        if self.maximum_plaintext_chunk_byte_length != expected_maximum {
            return Err(mailbox_object_mismatch(
                "maximum plaintext chunk byte length",
            ));
        }
        let (expected_chunk_count, expected_total_carrier_byte_length) =
            derive_mailbox_stream_geometry(self.delivery_descriptor.payload_byte_length())?;
        if self.chunk_count != expected_chunk_count {
            return Err(mailbox_object_mismatch("chunk count"));
        }
        if self.total_carrier_byte_length != expected_total_carrier_byte_length {
            return Err(mailbox_object_mismatch("total carrier byte length"));
        }
        Ok(())
    }

    fn chunk_geometry(
        &self,
        chunk_index: usize,
    ) -> Result<
        PseudorandomZeroSharingSeedMailboxChunkGeometry320,
        PseudorandomZeroSharingSeedMailboxError320,
    > {
        let chunk_count = usize::try_from(self.chunk_count)
            .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
        if chunk_index >= chunk_count {
            return Err(PseudorandomZeroSharingSeedMailboxError320::ChunkOrder {
                expected: chunk_count,
                actual: chunk_index,
            });
        }
        let maximum_plaintext_chunk_byte_length =
            usize::try_from(self.maximum_plaintext_chunk_byte_length)
                .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
        let plaintext_byte_offset = chunk_index
            .checked_mul(maximum_plaintext_chunk_byte_length)
            .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
        let total_plaintext_byte_length =
            usize::try_from(self.delivery_descriptor.payload_byte_length())
                .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
        let remaining_plaintext_byte_length = total_plaintext_byte_length
            .checked_sub(plaintext_byte_offset)
            .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
        let plaintext_byte_length =
            remaining_plaintext_byte_length.min(maximum_plaintext_chunk_byte_length);
        let carrier_byte_length = plaintext_byte_length
            .checked_add(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH)
            .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
        Ok(PseudorandomZeroSharingSeedMailboxChunkGeometry320 {
            plaintext_byte_offset: u64::try_from(plaintext_byte_offset)
                .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?,
            plaintext_byte_length,
            carrier_byte_length,
        })
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedMailboxHeaderBody320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedMailboxHeaderBody320")
            .field("delivery_descriptor", &self.delivery_descriptor)
            .field(
                "recipient_encapsulation_key_identity",
                &self.recipient_encapsulation_key_identity,
            )
            .field("encapsulation_ciphertext", &"[redacted]")
            .field(
                "maximum_plaintext_chunk_byte_length",
                &self.maximum_plaintext_chunk_byte_length,
            )
            .field("chunk_count", &self.chunk_count)
            .field("total_carrier_byte_length", &self.total_carrier_byte_length)
            .finish()
    }
}

/// Ordered digest inventory for the exact encrypted chunks.
///
/// The signed ordered list already commits to every byte, boundary, and
/// position, so no redundant second full-stream digest is carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedMailboxManifestBody320 {
    header_identity: Hash512,
    ordered_chunk_digests: Box<[Hash512]>,
}

impl PseudorandomZeroSharingSeedMailboxManifestBody320 {
    pub(crate) fn new(
        header: &PseudorandomZeroSharingSeedMailboxHeaderBody320,
        ordered_chunk_digests: Vec<Hash512>,
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        let expected_chunk_count = usize::try_from(header.chunk_count)
            .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
        if ordered_chunk_digests.len() != expected_chunk_count {
            return Err(PseudorandomZeroSharingSeedMailboxError320::ChunkCount {
                expected: expected_chunk_count,
                actual: ordered_chunk_digests.len(),
            });
        }
        Ok(Self {
            header_identity: header.identity()?,
            ordered_chunk_digests: ordered_chunk_digests.into_boxed_slice(),
        })
    }

    pub(crate) const fn header_identity(&self) -> Hash512 {
        self.header_identity
    }

    pub(crate) fn ordered_chunk_digests(&self) -> &[Hash512] {
        &self.ordered_chunk_digests
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedMailboxError320> {
        let digest_items = self
            .ordered_chunk_digests
            .iter()
            .map(|digest| CanonicalItem::hash512(digest.into_bytes()))
            .collect::<Vec<_>>();
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MANIFEST_DOMAIN,
                )?,
                CanonicalItem::hash512(self.header_identity.into_bytes()),
                CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &digest_items)?,
            ],
        )
        .encode()?)
    }

    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        let tuple = CanonicalTuple::decode(bytes, &mailbox_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MANIFEST_DOMAIN,
            MAILBOX_MANIFEST_ITEM_COUNT,
        )?;
        let header_identity = read_hash512(&tuple.items[1], "header identity")?;
        let ordered_chunk_digests = read_hash512_list(&tuple.items[2])?;
        if ordered_chunk_digests.is_empty()
            || ordered_chunk_digests.len() > MAXIMUM_MAILBOX_CHUNK_COUNT
        {
            return Err(mailbox_object_mismatch("chunk-digest count"));
        }
        Ok(Self {
            header_identity,
            ordered_chunk_digests: ordered_chunk_digests.into_boxed_slice(),
        })
    }

    pub(crate) fn identity(&self) -> Result<Hash512, PseudorandomZeroSharingSeedMailboxError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MANIFEST_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    pub(crate) fn require_header(
        &self,
        header: &PseudorandomZeroSharingSeedMailboxHeaderBody320,
    ) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
        if self.header_identity != header.identity()? {
            return Err(mailbox_object_mismatch("manifest header identity"));
        }
        let expected_chunk_count = usize::try_from(header.chunk_count)
            .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
        if self.ordered_chunk_digests.len() != expected_chunk_count {
            return Err(PseudorandomZeroSharingSeedMailboxError320::ChunkCount {
                expected: expected_chunk_count,
                actual: self.ordered_chunk_digests.len(),
            });
        }
        Ok(())
    }
}

/// Canonical ML-DSA message authenticating the encrypted-stream manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedMailboxSignatureBody320 {
    preparation_context_identity: Hash512,
    participant_count: u16,
    sender_position: u16,
    header_identity: Hash512,
    manifest_identity: Hash512,
}

impl PseudorandomZeroSharingSeedMailboxSignatureBody320 {
    pub(crate) fn new(
        header: &PseudorandomZeroSharingSeedMailboxHeaderBody320,
        manifest: &PseudorandomZeroSharingSeedMailboxManifestBody320,
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        Ok(Self {
            preparation_context_identity: header.delivery_descriptor.preparation_context_identity(),
            participant_count: header.delivery_descriptor.participant_count(),
            sender_position: header.delivery_descriptor.sender_position(),
            header_identity: header.identity()?,
            manifest_identity: manifest.identity()?,
        })
    }

    pub(crate) const fn sender_position(self) -> u16 {
        self.sender_position
    }

    pub(crate) const fn header_identity(self) -> Hash512 {
        self.header_identity
    }

    pub(crate) const fn manifest_identity(self) -> Hash512 {
        self.manifest_identity
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedMailboxError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.preparation_context_identity.into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::unsigned16(self.participant_count),
                CanonicalItem::unsigned16(self.sender_position),
                CanonicalItem::hash512(self.header_identity.into_bytes()),
                CanonicalItem::hash512(self.manifest_identity.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub(crate) fn from_canonical_bytes(
        expected: Self,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        let tuple = CanonicalTuple::decode(bytes, &mailbox_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_DOMAIN,
            MAILBOX_SIGNATURE_BODY_ITEM_COUNT,
        )?;
        require_hash512(
            &tuple.items[1],
            expected.preparation_context_identity,
            "signature preparation context identity",
        )?;
        require_u16(
            &tuple.items[2],
            PREPARATION_ATTEMPT_ORDINAL,
            "signature preparation attempt ordinal",
        )?;
        require_u16(
            &tuple.items[3],
            expected.participant_count,
            "signature participant count",
        )?;
        require_u16(
            &tuple.items[4],
            expected.sender_position,
            "signature sender position",
        )?;
        require_hash512(
            &tuple.items[5],
            expected.header_identity,
            "signature header identity",
        )?;
        require_hash512(
            &tuple.items[6],
            expected.manifest_identity,
            "signature manifest identity",
        )?;
        Ok(expected)
    }
}

/// Detached sender signature over one exact mailbox manifest.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSignedSeedMailboxManifestEnvelope320 {
    signature_body: PseudorandomZeroSharingSeedMailboxSignatureBody320,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl PseudorandomZeroSharingSignedSeedMailboxManifestEnvelope320 {
    pub(crate) const fn new(
        signature_body: PseudorandomZeroSharingSeedMailboxSignatureBody320,
        signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            signature_body,
            signature,
        }
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedMailboxError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_DOMAIN,
                )?,
                CanonicalItem::variable_bytes(self.signature_body.canonical_bytes()?)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    pub(crate) fn from_canonical_bytes(
        expected_signature_body: PseudorandomZeroSharingSeedMailboxSignatureBody320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        let tuple = CanonicalTuple::decode(bytes, &mailbox_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_DOMAIN,
            MAILBOX_SIGNATURE_ENVELOPE_ITEM_COUNT,
        )?;
        let signature_body =
            PseudorandomZeroSharingSeedMailboxSignatureBody320::from_canonical_bytes(
                expected_signature_body,
                read_variable_bytes(&tuple.items[1], "signature body")?,
            )?;
        let signature =
            read_fixed_bytes::<ML_DSA_65_SIGNATURE_BYTE_LENGTH>(&tuple.items[2], "signature")?;
        Ok(Self {
            signature_body,
            signature,
        })
    }
}

impl fmt::Debug for PseudorandomZeroSharingSignedSeedMailboxManifestEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSignedSeedMailboxManifestEnvelope320")
            .field("signature_body", &self.signature_body)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Stateful unactivated producer for one bounded encrypted stream.
///
/// The caller must supply fresh uniform ML-KEM encapsulation randomness and
/// persist it with the source payload if byte-identical replay is required.
/// The resulting manifest still needs the sender's roster signature before a
/// recipient can classify any decrypted inconsistency as authenticated.
pub(crate) struct PseudorandomZeroSharingSeedMailboxSealer320 {
    header: PseudorandomZeroSharingSeedMailboxHeaderBody320,
    authenticated_encryption_key: Zeroizing<[u8; 32]>,
    next_chunk_index: usize,
    ordered_chunk_digests: Vec<Hash512>,
}

impl PseudorandomZeroSharingSeedMailboxSealer320 {
    pub(crate) fn new(
        root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
        roster: &Roster,
        sender_position: u16,
        recipient_position: u16,
        descriptor_bytes: &[u8],
        encapsulation_randomness: &[u8; 32],
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        validate_roster_for_terminal(root_terminal, roster)?;
        let recipient_entry = roster
            .entries
            .get(usize::from(recipient_position))
            .filter(|entry| entry.roster_position == recipient_position)
            .ok_or(PseudorandomZeroSharingSeedMailboxError320::EndpointMismatch)?;
        let encapsulation_key =
            ml_kem_768::EncapsKey::try_from_bytes(recipient_entry.mailbox_encapsulation_key)
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMailboxError320::MalformedEncapsulationKey
                })?;
        let (shared_secret, encapsulation_ciphertext) =
            encapsulation_key.encaps_from_seed(encapsulation_randomness);
        let shared_secret_bytes = Zeroizing::new(shared_secret.into_bytes());
        let mut header = PseudorandomZeroSharingSeedMailboxHeaderBody320::new(
            root_terminal,
            roster,
            sender_position,
            recipient_position,
            descriptor_bytes,
            encapsulation_ciphertext.into_bytes(),
            Hash512::from_bytes([0; Hash512::BYTE_LENGTH]),
        )?;
        let authenticated_encryption_key = derive_authenticated_encryption_key(
            &shared_secret_bytes,
            &header.key_derivation_context_bytes()?,
        );
        header.authenticated_encryption_key_commitment =
            derive_authenticated_encryption_key_commitment(&authenticated_encryption_key)?;
        let expected_chunk_count = usize::try_from(header.chunk_count)
            .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
        Ok(Self {
            header,
            authenticated_encryption_key,
            next_chunk_index: 0,
            ordered_chunk_digests: Vec::with_capacity(expected_chunk_count),
        })
    }

    pub(crate) const fn header(&self) -> &PseudorandomZeroSharingSeedMailboxHeaderBody320 {
        &self.header
    }

    #[cfg(test)]
    pub(crate) fn authenticated_encryption_key_for_test(&self) -> [u8; 32] {
        *self.authenticated_encryption_key
    }

    pub(crate) fn seal_next_plaintext_chunk(
        &mut self,
        plaintext_chunk: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedMailboxError320> {
        let chunk_geometry = self.header.chunk_geometry(self.next_chunk_index)?;
        if plaintext_chunk.len() != chunk_geometry.plaintext_byte_length {
            return Err(
                PseudorandomZeroSharingSeedMailboxError320::ChunkByteLength {
                    expected: chunk_geometry.plaintext_byte_length,
                    actual: plaintext_chunk.len(),
                },
            );
        }
        let associated_data =
            derive_chunk_associated_data(&self.header, self.next_chunk_index, chunk_geometry)?;
        let nonce = derive_authenticated_encryption_nonce(
            &self.authenticated_encryption_key,
            &associated_data,
        );
        let cipher = Aes256GcmSiv::new_from_slice(self.authenticated_encryption_key.as_ref())
            .map_err(|_| {
                PseudorandomZeroSharingSeedMailboxError320::AuthenticatedEncryptionFailed
            })?;
        let mut carrier = Zeroizing::new(plaintext_chunk.to_vec());
        let authentication_tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(nonce.as_ref()),
                &associated_data,
                &mut carrier,
            )
            .map_err(|_| {
                PseudorandomZeroSharingSeedMailboxError320::AuthenticatedEncryptionFailed
            })?;
        carrier.extend_from_slice(authentication_tag.as_slice());
        if carrier.len() != chunk_geometry.carrier_byte_length {
            return Err(
                PseudorandomZeroSharingSeedMailboxError320::ChunkByteLength {
                    expected: chunk_geometry.carrier_byte_length,
                    actual: carrier.len(),
                },
            );
        }
        self.ordered_chunk_digests.push(hash_mailbox_chunk(
            self.header.identity()?,
            self.next_chunk_index,
            &carrier,
        )?);
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
        Ok(carrier)
    }

    pub(crate) fn finish(
        self,
    ) -> Result<
        PseudorandomZeroSharingSeedMailboxManifestBody320,
        PseudorandomZeroSharingSeedMailboxError320,
    > {
        let expected_chunk_count = usize::try_from(self.header.chunk_count)
            .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
        if self.next_chunk_index != expected_chunk_count {
            return Err(PseudorandomZeroSharingSeedMailboxError320::ChunkCount {
                expected: expected_chunk_count,
                actual: self.next_chunk_index,
            });
        }
        PseudorandomZeroSharingSeedMailboxManifestBody320::new(
            &self.header,
            self.ordered_chunk_digests,
        )
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedMailboxSealer320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedMailboxSealer320")
            .field("header", &self.header)
            .field("authenticated_encryption_key", &"[redacted]")
            .field("next_chunk_index", &self.next_chunk_index)
            .field("chunk_digest_count", &self.ordered_chunk_digests.len())
            .finish()
    }
}

/// Positive source-authenticated and root-matched private delivery.
///
/// This result has no durable receipt, all-recipient terminal, key-use
/// authority, or preparation-continuation authority.
pub(crate) struct AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320 {
    header_identity: Hash512,
    manifest_identity: Hash512,
    delivery: RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320,
    retained_payload_bytes: Zeroizing<Vec<u8>>,
}

impl AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320 {
    pub(crate) const fn header_identity(&self) -> Hash512 {
        self.header_identity
    }

    pub(crate) const fn manifest_identity(&self) -> Hash512 {
        self.manifest_identity
    }

    pub(crate) const fn delivery(
        &self,
    ) -> &RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320 {
        &self.delivery
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320,
        Zeroizing<Vec<u8>>,
    ) {
        (self.delivery, self.retained_payload_bytes)
    }
}

impl fmt::Debug for AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320")
            .field("header_identity", &self.header_identity)
            .field("manifest_identity", &self.manifest_identity)
            .field("delivery", &"[redacted]")
            .finish()
    }
}

/// Sequential recipient verifier for one signed encrypted stream.
///
/// The sender signature is checked before ML-KEM decapsulation. Each supplied
/// carrier chunk must then match its signed digest before authenticated
/// decryption, and decrypted entries are checked immediately against the
/// terminal-selected sender root.
pub(crate) struct PseudorandomZeroSharingSeedMailboxVerifier320 {
    header: PseudorandomZeroSharingSeedMailboxHeaderBody320,
    manifest: PseudorandomZeroSharingSeedMailboxManifestBody320,
    authenticated_encryption_key: Zeroizing<[u8; 32]>,
    next_chunk_index: usize,
    plaintext_parser: PseudorandomZeroSharingSeedMailboxPlaintextParser320,
    retained_payload_bytes: Zeroizing<Vec<u8>>,
}

impl PseudorandomZeroSharingSeedMailboxVerifier320 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
        roster: &Roster,
        expected_sender_position: u16,
        expected_recipient_position: u16,
        header_bytes: &[u8],
        manifest_bytes: &[u8],
        signature_envelope_bytes: &[u8],
        recipient_decapsulation_key: &ml_kem_768::DecapsKey,
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        validate_roster_for_terminal(root_terminal, roster)?;
        let header =
            PseudorandomZeroSharingSeedMailboxHeaderBody320::from_canonical_bytes(header_bytes)?;
        let manifest = PseudorandomZeroSharingSeedMailboxManifestBody320::from_canonical_bytes(
            manifest_bytes,
        )?;
        verify_sender_manifest_signature(
            roster,
            expected_sender_position,
            &header,
            &manifest,
            signature_envelope_bytes,
        )?;
        require_header_matches_expected(
            root_terminal,
            roster,
            expected_sender_position,
            expected_recipient_position,
            &header,
        )?;
        manifest.require_header(&header)?;
        require_recipient_decapsulation_key(
            roster,
            expected_recipient_position,
            recipient_decapsulation_key,
        )?;
        let encapsulation_ciphertext =
            ml_kem_768::CipherText::try_from_bytes(header.encapsulation_ciphertext).map_err(
                |_| PseudorandomZeroSharingSeedMailboxError320::MalformedEncapsulationCiphertext,
            )?;
        let shared_secret = recipient_decapsulation_key
            .try_decaps(&encapsulation_ciphertext)
            .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::DecapsulationFailed)?;
        let shared_secret_bytes = Zeroizing::new(shared_secret.into_bytes());
        Self::from_verified_control(
            root_terminal,
            expected_sender_position,
            expected_recipient_position,
            header,
            manifest,
            &shared_secret_bytes,
        )
    }

    /// Completes one already authenticated public carrier with the shared
    /// secret returned by the browser-local recipient key owner.
    ///
    /// This crate-private route still repeats every public signature, roster,
    /// endpoint, manifest, and root-terminal check before it accepts the
    /// shared secret. The production adapter invokes it only after its earlier
    /// public-carrier pass has completed for the entire ordered inventory.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_shared_secret(
        root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
        roster: &Roster,
        expected_sender_position: u16,
        expected_recipient_position: u16,
        header_bytes: &[u8],
        manifest_bytes: &[u8],
        signature_envelope_bytes: &[u8],
        shared_secret_bytes: &[u8; 32],
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        validate_roster_for_terminal(root_terminal, roster)?;
        let header =
            PseudorandomZeroSharingSeedMailboxHeaderBody320::from_canonical_bytes(header_bytes)?;
        let manifest = PseudorandomZeroSharingSeedMailboxManifestBody320::from_canonical_bytes(
            manifest_bytes,
        )?;
        verify_sender_manifest_signature(
            roster,
            expected_sender_position,
            &header,
            &manifest,
            signature_envelope_bytes,
        )?;
        require_header_matches_expected(
            root_terminal,
            roster,
            expected_sender_position,
            expected_recipient_position,
            &header,
        )?;
        manifest.require_header(&header)?;
        Self::from_verified_control(
            root_terminal,
            expected_sender_position,
            expected_recipient_position,
            header,
            manifest,
            shared_secret_bytes,
        )
    }

    fn from_verified_control(
        root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
        expected_sender_position: u16,
        expected_recipient_position: u16,
        header: PseudorandomZeroSharingSeedMailboxHeaderBody320,
        manifest: PseudorandomZeroSharingSeedMailboxManifestBody320,
        shared_secret_bytes: &[u8; 32],
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        let authenticated_encryption_key = derive_authenticated_encryption_key(
            shared_secret_bytes,
            &header.key_derivation_context_bytes()?,
        );
        Self::from_verified_control_with_authenticated_encryption_key(
            root_terminal,
            expected_sender_position,
            expected_recipient_position,
            header,
            manifest,
            authenticated_encryption_key,
        )
    }

    fn from_verified_control_with_authenticated_encryption_key(
        root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
        expected_sender_position: u16,
        expected_recipient_position: u16,
        header: PseudorandomZeroSharingSeedMailboxHeaderBody320,
        manifest: PseudorandomZeroSharingSeedMailboxManifestBody320,
        authenticated_encryption_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxError320> {
        if derive_authenticated_encryption_key_commitment(&authenticated_encryption_key)?
            != header.authenticated_encryption_key_commitment
        {
            return Err(
                PseudorandomZeroSharingSeedMailboxError320::AuthenticatedEncryptionKeyCommitmentMismatch,
            );
        }
        let delivery_verifier = PseudorandomZeroSharingSeedDeliveryVerifier320::new(
            root_terminal,
            expected_sender_position,
            expected_recipient_position,
            &header.delivery_descriptor.canonical_bytes()?,
        )?;
        let payload_byte_length = usize::try_from(header.delivery_descriptor.payload_byte_length())
            .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
        Ok(Self {
            header,
            manifest,
            authenticated_encryption_key,
            next_chunk_index: 0,
            plaintext_parser: PseudorandomZeroSharingSeedMailboxPlaintextParser320::new(
                delivery_verifier,
            ),
            retained_payload_bytes: Zeroizing::new(Vec::with_capacity(payload_byte_length)),
        })
    }

    pub(crate) fn absorb_next_encrypted_chunk(
        &mut self,
        encrypted_chunk: &[u8],
    ) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
        let chunk_geometry = self.header.chunk_geometry(self.next_chunk_index)?;
        if encrypted_chunk.len() != chunk_geometry.carrier_byte_length {
            return Err(
                PseudorandomZeroSharingSeedMailboxError320::ChunkByteLength {
                    expected: chunk_geometry.carrier_byte_length,
                    actual: encrypted_chunk.len(),
                },
            );
        }
        let actual_digest = hash_mailbox_chunk(
            self.header.identity()?,
            self.next_chunk_index,
            encrypted_chunk,
        )?;
        let expected_digest = self
            .manifest
            .ordered_chunk_digests
            .get(self.next_chunk_index)
            .ok_or(PseudorandomZeroSharingSeedMailboxError320::ChunkOrder {
                expected: self.manifest.ordered_chunk_digests.len(),
                actual: self.next_chunk_index,
            })?;
        if !bool::from(actual_digest.as_bytes().ct_eq(expected_digest.as_bytes())) {
            return Err(
                PseudorandomZeroSharingSeedMailboxError320::ChunkDigestMismatch {
                    chunk_index: self.next_chunk_index,
                },
            );
        }
        let associated_data =
            derive_chunk_associated_data(&self.header, self.next_chunk_index, chunk_geometry)?;
        let nonce = derive_authenticated_encryption_nonce(
            &self.authenticated_encryption_key,
            &associated_data,
        );
        let cipher = Aes256GcmSiv::new_from_slice(self.authenticated_encryption_key.as_ref())
            .map_err(|_| {
                PseudorandomZeroSharingSeedMailboxError320::AuthenticatedDecryptionFailed
            })?;
        let (ciphertext, authentication_tag_bytes) =
            encrypted_chunk.split_at(chunk_geometry.plaintext_byte_length);
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce.as_ref()),
                &associated_data,
                &mut plaintext,
                Tag::from_slice(authentication_tag_bytes),
            )
            .map_err(|_| {
                PseudorandomZeroSharingSeedMailboxError320::AuthenticatedDecryptionFailed
            })?;
        self.plaintext_parser.absorb(&plaintext)?;
        self.retained_payload_bytes.extend_from_slice(&plaintext);
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
        Ok(())
    }

    /// Copies the one-time stream key only so the recipient adapter can build
    /// independently verifiable burn evidence after authenticated plaintext
    /// correspondence has failed. Normal success paths must not publish it.
    pub(crate) fn authenticated_encryption_key_for_inconsistency(&self) -> [u8; 32] {
        *self.authenticated_encryption_key
    }

    pub(crate) fn finish(
        self,
    ) -> Result<
        AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320,
        PseudorandomZeroSharingSeedMailboxError320,
    > {
        let expected_chunk_count = self.manifest.ordered_chunk_digests.len();
        if self.next_chunk_index != expected_chunk_count {
            return Err(PseudorandomZeroSharingSeedMailboxError320::ChunkCount {
                expected: expected_chunk_count,
                actual: self.next_chunk_index,
            });
        }
        Ok(AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320 {
            header_identity: self.header.identity()?,
            manifest_identity: self.manifest.identity()?,
            delivery: self.plaintext_parser.finish()?,
            retained_payload_bytes: self.retained_payload_bytes,
        })
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedMailboxVerifier320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedMailboxVerifier320")
            .field("header", &self.header)
            .field("manifest", &self.manifest)
            .field("authenticated_encryption_key", &"[redacted]")
            .field("next_chunk_index", &self.next_chunk_index)
            .field("plaintext_parser", &"[redacted]")
            .finish()
    }
}

struct PseudorandomZeroSharingSeedMailboxPlaintextParser320 {
    delivery_verifier: PseudorandomZeroSharingSeedDeliveryVerifier320,
    pending_entry_bytes: Zeroizing<Vec<u8>>,
}

impl PseudorandomZeroSharingSeedMailboxPlaintextParser320 {
    fn new(delivery_verifier: PseudorandomZeroSharingSeedDeliveryVerifier320) -> Self {
        Self {
            delivery_verifier,
            pending_entry_bytes: Zeroizing::new(Vec::new()),
        }
    }

    fn absorb(
        &mut self,
        mut plaintext_fragment: &[u8],
    ) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
        while !plaintext_fragment.is_empty() {
            let (opening_byte_length, inclusion_proof_byte_length) = self
                .delivery_verifier
                .next_entry_byte_lengths()
                .ok_or(mailbox_object_mismatch("plaintext entry count"))?;
            let entry_byte_length = opening_byte_length
                .checked_add(inclusion_proof_byte_length)
                .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
            let remaining_entry_byte_length = entry_byte_length
                .checked_sub(self.pending_entry_bytes.len())
                .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
            let consumed_byte_length = remaining_entry_byte_length.min(plaintext_fragment.len());
            self.pending_entry_bytes
                .extend_from_slice(&plaintext_fragment[..consumed_byte_length]);
            plaintext_fragment = &plaintext_fragment[consumed_byte_length..];
            if self.pending_entry_bytes.len() == entry_byte_length {
                let complete_entry = core::mem::take(&mut self.pending_entry_bytes);
                let (opening_bytes, inclusion_proof_bytes) =
                    complete_entry.split_at(opening_byte_length);
                self.delivery_verifier
                    .absorb_next_entry(opening_bytes, inclusion_proof_bytes)?;
            }
        }
        Ok(())
    }

    fn finish(
        self,
    ) -> Result<
        RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320,
        PseudorandomZeroSharingSeedMailboxError320,
    > {
        if !self.pending_entry_bytes.is_empty() {
            return Err(PseudorandomZeroSharingSeedMailboxError320::PlaintextEntryTruncated);
        }
        Ok(self.delivery_verifier.finish()?)
    }
}

fn verify_sender_manifest_signature(
    roster: &Roster,
    expected_sender_position: u16,
    header: &PseudorandomZeroSharingSeedMailboxHeaderBody320,
    manifest: &PseudorandomZeroSharingSeedMailboxManifestBody320,
    signature_envelope_bytes: &[u8],
) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
    let expected_signature_body =
        PseudorandomZeroSharingSeedMailboxSignatureBody320::new(header, manifest)?;
    let envelope =
        PseudorandomZeroSharingSignedSeedMailboxManifestEnvelope320::from_canonical_bytes(
            expected_signature_body,
            signature_envelope_bytes,
        )?;
    let sender_entry = roster
        .entries
        .get(usize::from(expected_sender_position))
        .filter(|entry| entry.roster_position == expected_sender_position)
        .ok_or(PseudorandomZeroSharingSeedMailboxError320::RosterMismatch)?;
    let verification_key = ml_dsa_65::PublicKey::try_from_bytes(
        sender_entry.signing_verification_key,
    )
    .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::MalformedSigningVerificationKey)?;
    if !verification_key.verify(
        &envelope.signature_body.canonical_bytes()?,
        &envelope.signature,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_CONTEXT,
    ) {
        return Err(PseudorandomZeroSharingSeedMailboxError320::InvalidSenderSignature);
    }
    Ok(())
}

/// Positively verifies the public portion of one sender-produced carrier.
///
/// This check authenticates the sender, exact descriptor, manifest, chunk
/// order, chunk lengths, and every encrypted byte. It deliberately does not
/// decapsulate or claim that the ciphertext opens to a root-matched delivery;
/// only the recipient verifier can establish that private result.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_pseudorandom_zero_sharing_seed_mailbox_sender_carrier_320(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
    expected_sender_position: u16,
    expected_recipient_position: u16,
    expected_descriptor_bytes: &[u8],
    header_bytes: &[u8],
    manifest_bytes: &[u8],
    signature_envelope_bytes: &[u8],
    encrypted_chunks: &[&[u8]],
) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
    validate_roster_for_terminal(root_terminal, roster)?;
    require_expected_delivery_descriptor(
        root_terminal,
        expected_sender_position,
        expected_recipient_position,
        expected_descriptor_bytes,
    )?;
    let header =
        PseudorandomZeroSharingSeedMailboxHeaderBody320::from_canonical_bytes(header_bytes)?;
    let manifest =
        PseudorandomZeroSharingSeedMailboxManifestBody320::from_canonical_bytes(manifest_bytes)?;
    verify_sender_manifest_signature(
        roster,
        expected_sender_position,
        &header,
        &manifest,
        signature_envelope_bytes,
    )?;
    require_header_matches_expected(
        root_terminal,
        roster,
        expected_sender_position,
        expected_recipient_position,
        &header,
    )?;
    manifest.require_header(&header)?;
    let expected_chunk_byte_lengths = header.encrypted_chunk_byte_lengths()?;
    if encrypted_chunks.len() != expected_chunk_byte_lengths.len() {
        return Err(PseudorandomZeroSharingSeedMailboxError320::ChunkCount {
            expected: expected_chunk_byte_lengths.len(),
            actual: encrypted_chunks.len(),
        });
    }
    let header_identity = header.identity()?;
    for (chunk_index, (encrypted_chunk, expected_byte_length)) in encrypted_chunks
        .iter()
        .zip(expected_chunk_byte_lengths)
        .enumerate()
    {
        if encrypted_chunk.len() != expected_byte_length {
            return Err(
                PseudorandomZeroSharingSeedMailboxError320::ChunkByteLength {
                    expected: expected_byte_length,
                    actual: encrypted_chunk.len(),
                },
            );
        }
        let expected_digest = manifest.ordered_chunk_digests().get(chunk_index).ok_or(
            PseudorandomZeroSharingSeedMailboxError320::ChunkOrder {
                expected: manifest.ordered_chunk_digests().len(),
                actual: chunk_index,
            },
        )?;
        let actual_digest = hash_mailbox_chunk(header_identity, chunk_index, encrypted_chunk)?;
        if !bool::from(actual_digest.as_bytes().ct_eq(expected_digest.as_bytes())) {
            return Err(
                PseudorandomZeroSharingSeedMailboxError320::ChunkDigestMismatch { chunk_index },
            );
        }
    }
    Ok(())
}

/// Publicly reproducible proof that one sender-authenticated mailbox opens
/// under its committed one-time AEAD key but not to the committed seed
/// delivery.
///
/// The disclosed key is scoped to this fresh KEM stream. Verification first
/// rechecks the sender signature and every encrypted byte, then requires the
/// key's signed 512-bit commitment, and accepts only if a signed ciphertext
/// fails authentication under that key or if its authenticated plaintext fails
/// the root-matched delivery verifier. A wrong key commitment, unsigned
/// mutation, or valid delivery never mints this result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320 {
    sender_position: u16,
    recipient_position: u16,
    header_identity: Hash512,
    manifest_identity: Hash512,
    evidence_identity: Hash512,
}

impl VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320 {
    pub(crate) const fn sender_position(self) -> u16 {
        self.sender_position
    }

    pub(crate) const fn recipient_position(self) -> u16 {
        self.recipient_position
    }

    pub(crate) const fn header_identity(self) -> Hash512 {
        self.header_identity
    }

    pub(crate) const fn manifest_identity(self) -> Hash512 {
        self.manifest_identity
    }

    pub(crate) const fn identity(self) -> Hash512 {
        self.evidence_identity
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_pseudorandom_zero_sharing_seed_mailbox_authenticated_inconsistency_320(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
    expected_sender_position: u16,
    expected_recipient_position: u16,
    expected_descriptor_bytes: &[u8],
    header_bytes: &[u8],
    manifest_bytes: &[u8],
    signature_envelope_bytes: &[u8],
    encrypted_chunks: &[&[u8]],
    disclosed_authenticated_encryption_key: &[u8; 32],
) -> Result<
    VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320,
    PseudorandomZeroSharingSeedMailboxError320,
> {
    verify_pseudorandom_zero_sharing_seed_mailbox_sender_carrier_320(
        root_terminal,
        roster,
        expected_sender_position,
        expected_recipient_position,
        expected_descriptor_bytes,
        header_bytes,
        manifest_bytes,
        signature_envelope_bytes,
        encrypted_chunks,
    )?;
    let header =
        PseudorandomZeroSharingSeedMailboxHeaderBody320::from_canonical_bytes(header_bytes)?;
    let manifest =
        PseudorandomZeroSharingSeedMailboxManifestBody320::from_canonical_bytes(manifest_bytes)?;
    let authenticated_encryption_key = Zeroizing::new(*disclosed_authenticated_encryption_key);
    let mut verifier =
        PseudorandomZeroSharingSeedMailboxVerifier320::from_verified_control_with_authenticated_encryption_key(
            root_terminal,
            expected_sender_position,
            expected_recipient_position,
            header.clone(),
            manifest.clone(),
            authenticated_encryption_key,
        )?;
    for encrypted_chunk in encrypted_chunks {
        if let Err(error) = verifier.absorb_next_encrypted_chunk(encrypted_chunk) {
            if is_authenticated_delivery_inconsistency(&error) {
                return verified_authenticated_inconsistency(
                    root_terminal,
                    expected_sender_position,
                    expected_recipient_position,
                    &header,
                    &manifest,
                    disclosed_authenticated_encryption_key,
                );
            }
            return Err(error);
        }
    }
    match verifier.finish() {
        Ok(_) => Err(PseudorandomZeroSharingSeedMailboxError320::NoAuthenticatedInconsistency),
        Err(error) if is_authenticated_delivery_inconsistency(&error) => {
            verified_authenticated_inconsistency(
                root_terminal,
                expected_sender_position,
                expected_recipient_position,
                &header,
                &manifest,
                disclosed_authenticated_encryption_key,
            )
        }
        Err(error) => Err(error),
    }
}

fn is_authenticated_delivery_inconsistency(
    error: &PseudorandomZeroSharingSeedMailboxError320,
) -> bool {
    matches!(
        error,
        PseudorandomZeroSharingSeedMailboxError320::AuthenticatedDecryptionFailed
            | PseudorandomZeroSharingSeedMailboxError320::Delivery(_)
            | PseudorandomZeroSharingSeedMailboxError320::PlaintextEntryTruncated
            | PseudorandomZeroSharingSeedMailboxError320::ObjectMismatch {
                field: "plaintext entry count"
            }
    )
}

fn verified_authenticated_inconsistency(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    sender_position: u16,
    recipient_position: u16,
    header: &PseudorandomZeroSharingSeedMailboxHeaderBody320,
    manifest: &PseudorandomZeroSharingSeedMailboxManifestBody320,
    disclosed_authenticated_encryption_key: &[u8; 32],
) -> Result<
    VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320,
    PseudorandomZeroSharingSeedMailboxError320,
> {
    let header_identity = header.identity()?;
    let manifest_identity = manifest.identity()?;
    let evidence_identity = hash_foundation_tuple_512(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATED_INCONSISTENCY_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(root_terminal.identity()?.into_bytes()),
            CanonicalItem::unsigned16(sender_position),
            CanonicalItem::unsigned16(recipient_position),
            CanonicalItem::hash512(header_identity.into_bytes()),
            CanonicalItem::hash512(manifest_identity.into_bytes()),
            CanonicalItem::fixed_bytes(disclosed_authenticated_encryption_key)?,
        ],
    )?;
    Ok(
        VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320 {
            sender_position,
            recipient_position,
            header_identity,
            manifest_identity,
            evidence_identity,
        },
    )
}

fn require_header_matches_expected(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
    expected_sender_position: u16,
    expected_recipient_position: u16,
    header: &PseudorandomZeroSharingSeedMailboxHeaderBody320,
) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
    let expected_descriptor = derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
        root_terminal,
        expected_sender_position,
        expected_recipient_position,
    )?;
    if header.delivery_descriptor.canonical_bytes()? != expected_descriptor.canonical_bytes()? {
        return Err(mailbox_object_mismatch("delivery descriptor"));
    }
    let recipient_entry = roster
        .entries
        .get(usize::from(expected_recipient_position))
        .filter(|entry| entry.roster_position == expected_recipient_position)
        .ok_or(PseudorandomZeroSharingSeedMailboxError320::EndpointMismatch)?;
    let expected_key_identity = derive_recipient_encapsulation_key_identity(
        expected_recipient_position,
        &recipient_entry.mailbox_encapsulation_key,
    )?;
    if header.recipient_encapsulation_key_identity != expected_key_identity {
        return Err(mailbox_object_mismatch(
            "recipient encapsulation-key identity",
        ));
    }
    header.validate_internal_geometry()
}

fn require_expected_delivery_descriptor(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    sender_position: u16,
    recipient_position: u16,
    descriptor_bytes: &[u8],
) -> Result<
    PseudorandomZeroSharingSeedDeliveryDescriptorBody320,
    PseudorandomZeroSharingSeedMailboxError320,
> {
    let descriptor = PseudorandomZeroSharingSeedDeliveryDescriptorBody320::from_canonical_bytes(
        descriptor_bytes,
    )?;
    let expected = derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
        root_terminal,
        sender_position,
        recipient_position,
    )?;
    if descriptor.canonical_bytes()? != expected.canonical_bytes()? {
        return Err(mailbox_object_mismatch("delivery descriptor"));
    }
    Ok(descriptor)
}

fn validate_roster_for_terminal(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
    roster
        .validate()
        .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::RosterMismatch)?;
    let participant_count = root_terminal.root_inventory().body().participant_count();
    if roster.entries.len() != usize::from(participant_count) {
        return Err(PseudorandomZeroSharingSeedMailboxError320::RosterMismatch);
    }
    let first_root = root_terminal
        .root_inventory()
        .root_body(0)
        .ok_or(PseudorandomZeroSharingSeedMailboxError320::RosterMismatch)?;
    if roster
        .roster_hash()
        .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::RosterMismatch)?
        != first_root.layout().preparation_context().roster_hash()
    {
        return Err(PseudorandomZeroSharingSeedMailboxError320::RosterMismatch);
    }
    Ok(())
}

fn require_recipient_decapsulation_key(
    roster: &Roster,
    recipient_position: u16,
    recipient_decapsulation_key: &ml_kem_768::DecapsKey,
) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
    let recipient_entry = roster
        .entries
        .get(usize::from(recipient_position))
        .filter(|entry| entry.roster_position == recipient_position)
        .ok_or(PseudorandomZeroSharingSeedMailboxError320::RosterMismatch)?;
    let decapsulation_key_bytes = Zeroizing::new(recipient_decapsulation_key.clone().into_bytes());
    let public_key_start = ML_KEM_768_DECAPSULATION_KEY_PUBLIC_KEY_OFFSET;
    let public_key_end = public_key_start
        .checked_add(recipient_entry.mailbox_encapsulation_key.len())
        .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
    if !bool::from(
        decapsulation_key_bytes[public_key_start..public_key_end]
            .ct_eq(&recipient_entry.mailbox_encapsulation_key),
    ) {
        return Err(PseudorandomZeroSharingSeedMailboxError320::DecapsulationKeyMismatch);
    }
    Ok(())
}

fn derive_recipient_encapsulation_key_identity(
    recipient_position: u16,
    encapsulation_key: &[u8],
) -> Result<Hash512, PseudorandomZeroSharingSeedMailboxError320> {
    Ok(hash_foundation_tuple_512(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_RECIPIENT_KEY_IDENTITY_DOMAIN,
        &[
            CanonicalItem::unsigned16(recipient_position),
            CanonicalItem::fixed_bytes(encapsulation_key)?,
        ],
    )?)
}

pub(crate) fn derive_mailbox_stream_geometry(
    plaintext_byte_length: u64,
) -> Result<(u64, u64), PseudorandomZeroSharingSeedMailboxError320> {
    if plaintext_byte_length == 0 {
        return Err(mailbox_object_mismatch("plaintext byte length"));
    }
    let maximum_plaintext_chunk_byte_length =
        u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH)
            .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
    let chunk_count = plaintext_byte_length
        .checked_add(maximum_plaintext_chunk_byte_length - 1)
        .and_then(|rounded| rounded.checked_div(maximum_plaintext_chunk_byte_length))
        .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
    if chunk_count == 0
        || chunk_count
            > u64::try_from(MAXIMUM_MAILBOX_CHUNK_COUNT)
                .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?
    {
        return Err(mailbox_object_mismatch("chunk count"));
    }
    let total_carrier_byte_length = chunk_count
        .checked_mul(
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH)
                .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?,
        )
        .and_then(|tag_bytes| plaintext_byte_length.checked_add(tag_bytes))
        .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
    Ok((chunk_count, total_carrier_byte_length))
}

fn derive_chunk_associated_data(
    header: &PseudorandomZeroSharingSeedMailboxHeaderBody320,
    chunk_index: usize,
    chunk_geometry: PseudorandomZeroSharingSeedMailboxChunkGeometry320,
) -> Result<Vec<u8>, PseudorandomZeroSharingSeedMailboxError320> {
    let associated_data = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        vec![
            CanonicalItem::nonempty_ascii(
                PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_ASSOCIATED_DATA_DOMAIN,
            )?,
            CanonicalItem::hash512(header.identity()?.into_bytes()),
            CanonicalItem::unsigned64(
                u64::try_from(chunk_index)
                    .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?,
            ),
            CanonicalItem::unsigned64(chunk_geometry.plaintext_byte_offset),
            CanonicalItem::unsigned64(
                u64::try_from(chunk_geometry.plaintext_byte_length)
                    .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?,
            ),
            CanonicalItem::unsigned64(
                u64::try_from(chunk_geometry.carrier_byte_length)
                    .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?,
            ),
        ],
    )
    .encode()?;
    if associated_data.len()
        != PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_ASSOCIATED_DATA_BYTE_LENGTH
    {
        return Err(mailbox_object_mismatch("chunk associated-data byte length"));
    }
    Ok(associated_data)
}

fn derive_authenticated_encryption_key(
    shared_secret: &[u8; 32],
    key_derivation_context_bytes: &[u8],
) -> Zeroizing<[u8; 32]> {
    derive_private_mailbox_key_256(
        shared_secret,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_LABEL,
        key_derivation_context_bytes,
    )
}

fn derive_authenticated_encryption_key_commitment(
    authenticated_encryption_key: &[u8; 32],
) -> Result<Hash512, PseudorandomZeroSharingSeedMailboxError320> {
    Ok(hash_foundation_tuple_512(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_COMMITMENT_DOMAIN,
        &[CanonicalItem::fixed_bytes(authenticated_encryption_key)?],
    )?)
}

fn derive_authenticated_encryption_nonce(
    authenticated_encryption_key: &[u8; 32],
    associated_data: &[u8],
) -> Zeroizing<[u8; 12]> {
    derive_private_mailbox_nonce_96(
        authenticated_encryption_key,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_NONCE_DERIVATION_LABEL,
        associated_data,
    )
}

#[cfg(test)]
pub(super) fn derive_authenticated_encryption_key_for_test(
    shared_secret: &[u8; 32],
    key_derivation_context_bytes: &[u8],
) -> Zeroizing<[u8; 32]> {
    derive_authenticated_encryption_key(shared_secret, key_derivation_context_bytes)
}

#[cfg(test)]
pub(super) fn derive_authenticated_encryption_nonce_for_test(
    authenticated_encryption_key: &[u8; 32],
    associated_data: &[u8],
) -> Zeroizing<[u8; 12]> {
    derive_authenticated_encryption_nonce(authenticated_encryption_key, associated_data)
}

pub(crate) fn hash_mailbox_chunk(
    header_identity: Hash512,
    chunk_index: usize,
    encrypted_chunk: &[u8],
) -> Result<Hash512, PseudorandomZeroSharingSeedMailboxError320> {
    let mut hasher = StreamingFoundationTupleHash512::new_variable_bytes(
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_DIGEST_DOMAIN,
        &[
            CanonicalItem::hash512(header_identity.into_bytes()),
            CanonicalItem::unsigned64(
                u64::try_from(chunk_index)
                    .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?,
            ),
        ],
        encrypted_chunk.len(),
    )
    .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::StreamingHash)?;
    hasher
        .absorb(encrypted_chunk)
        .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::StreamingHash)?;
    hasher
        .finalize()
        .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::StreamingHash)
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
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
) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
    if item.item_type() != CanonicalItemType::Ascii
        || item.variable_value_bytes()? != expected.as_bytes()
    {
        return Err(mailbox_object_mismatch(field));
    }
    Ok(())
}

fn read_variable_bytes<'a>(
    item: &'a CanonicalItem,
    field: &'static str,
) -> Result<&'a [u8], PseudorandomZeroSharingSeedMailboxError320> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(mailbox_object_mismatch(field));
    }
    item.variable_value_bytes()
        .map_err(PseudorandomZeroSharingSeedMailboxError320::Canonical)
}

fn read_fixed_bytes<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<[u8; BYTE_LENGTH], PseudorandomZeroSharingSeedMailboxError320> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(mailbox_object_mismatch(field));
    }
    item.canonical_bytes().try_into().map_err(|_| {
        PseudorandomZeroSharingSeedMailboxError320::FixedByteLength {
            field,
            expected: BYTE_LENGTH,
            actual: item.canonical_bytes().len(),
        }
    })
}

fn read_hash512(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<Hash512, PseudorandomZeroSharingSeedMailboxError320> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(mailbox_object_mismatch(field));
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| mailbox_object_mismatch(field))?;
    Ok(Hash512::from_bytes(bytes))
}

fn require_hash512(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
    if read_hash512(item, field)? != expected {
        return Err(mailbox_object_mismatch(field));
    }
    Ok(())
}

fn read_hash512_list(
    item: &CanonicalItem,
) -> Result<Vec<Hash512>, PseudorandomZeroSharingSeedMailboxError320> {
    if item.item_type() != CanonicalItemType::HomogeneousList {
        return Err(mailbox_object_mismatch("chunk-digest list"));
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 6 {
        return Err(mailbox_object_mismatch("chunk-digest list"));
    }
    let element_type = u16::from_le_bytes(
        bytes[..2]
            .try_into()
            .map_err(|_| mailbox_object_mismatch("chunk-digest list"))?,
    );
    if element_type != CanonicalItemType::Hash512.canonical_code() {
        return Err(mailbox_object_mismatch("chunk-digest element type"));
    }
    let count = usize::try_from(u32::from_le_bytes(
        bytes[2..6]
            .try_into()
            .map_err(|_| mailbox_object_mismatch("chunk-digest count"))?,
    ))
    .map_err(|_| PseudorandomZeroSharingSeedMailboxError320::IntegerConversion)?;
    let expected_byte_length = count
        .checked_mul(Hash512::BYTE_LENGTH)
        .and_then(|payload_byte_length| payload_byte_length.checked_add(6))
        .ok_or(PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow)?;
    if bytes.len() != expected_byte_length {
        return Err(mailbox_object_mismatch("chunk-digest list byte length"));
    }
    bytes[6..]
        .chunks_exact(Hash512::BYTE_LENGTH)
        .map(|chunk| {
            let digest_bytes: [u8; Hash512::BYTE_LENGTH] = chunk
                .try_into()
                .map_err(|_| mailbox_object_mismatch("chunk digest"))?;
            Ok(Hash512::from_bytes(digest_bytes))
        })
        .collect()
}

fn read_u16(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u16, PseudorandomZeroSharingSeedMailboxError320> {
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
) -> Result<(), PseudorandomZeroSharingSeedMailboxError320> {
    if read_u16(item, field)? != expected {
        return Err(mailbox_object_mismatch(field));
    }
    Ok(())
}

fn read_u64(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u64, PseudorandomZeroSharingSeedMailboxError320> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(mailbox_object_mismatch(field));
    }
    let bytes: [u8; 8] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| mailbox_object_mismatch(field))?;
    Ok(u64::from_le_bytes(bytes))
}

const fn mailbox_object_mismatch(
    field: &'static str,
) -> PseudorandomZeroSharingSeedMailboxError320 {
    PseudorandomZeroSharingSeedMailboxError320::ObjectMismatch { field }
}

fn mailbox_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_MAILBOX_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_MAILBOX_CHUNK_COUNT.max(
            MAILBOX_HEADER_ITEM_COUNT
                .max(MAILBOX_SIGNATURE_BODY_ITEM_COUNT)
                .max(MAILBOX_CHUNK_ASSOCIATED_DATA_ITEM_COUNT),
        ),
        maximum_item_byte_length: MAXIMUM_MAILBOX_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_MAILBOX_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_MAILBOX_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}

const _: () = assert!(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH == 16);
const _: () = assert!(ML_KEM_768_CIPHERTEXT_BYTE_LENGTH == 1_088);
const _: () = assert!(ml_kem_768::DK_LEN == 2_400);
const _: () = assert!(ML_KEM_768_DECAPSULATION_KEY_PUBLIC_KEY_OFFSET == 1_152);
const _: () = assert!(core::mem::size_of::<Tag>() == 16);
