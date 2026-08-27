use core::fmt;

use fips204::{
    ml_dsa_65,
    traits::{SerDes, Signer, Verifier},
};
use zeroize::Zeroizing;

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, Roster,
    hash_foundation_tuple_512,
};

use super::{
    masked_ballot_bivariate_commitment_320::{
        AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
        MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH, MaskedBallotBivariateCommitmentLayout320,
    },
    masked_ballot_bivariate_mailbox_320::{
        AuthenticatedMaskedBallotBivariateMailboxDelivery320,
        AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
        MaskedBallotBivariateMailboxError320,
    },
    masked_ballot_bivariate_receipt_state_320::VerifiedMaskedBallotBivariateReceiptStateOutput320,
};

const RECEIPT_BODY_ITEM_COUNT: usize = 7;
const RECEIPT_AUTHORIZATION_BODY_ITEM_COUNT: usize = 3;
const RECEIPT_ENVELOPE_ITEM_COUNT: usize = 3;
const TERMINAL_BODY_ITEM_COUNT: usize = 6;
const TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT: usize = 2;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;
const MAXIMUM_RECEIPT_CONTROL_OBJECT_BYTE_LENGTH: usize = 8 * 1024;
const MAXIMUM_RECEIPT_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 4 * 1024;
const MAXIMUM_TERMINAL_CERTIFICATE_BYTE_LENGTH: usize = 128 * 1024;
const MAXIMUM_TERMINAL_CERTIFICATE_ITEM_COUNT: usize = 32;
const MAXIMUM_TERMINAL_CERTIFICATE_CUMULATIVE_BYTE_LENGTH: usize = 256 * 1024;

pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-receipt-body";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-receipt-body-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_AUTHORIZATION_BODY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-receipt-authorization-body";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-receipt-envelope";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-receipt-envelope-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/ballot/bivariate-private-row-receipt";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-receipt-terminal-body";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-receipt-terminal-body-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_CERTIFICATE_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-receipt-terminal-certificate";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_CERTIFICATE_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-receipt-terminal-certificate-identity";

pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + RECEIPT_BODY_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_DOMAIN.len()
        + 3 * Hash512::BYTE_LENGTH
        + 3 * size_of::<u16>();
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_AUTHORIZATION_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + RECEIPT_AUTHORIZATION_BODY_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + MASKED_BALLOT_BIVARIATE_RECEIPT_AUTHORIZATION_BODY_DOMAIN.len()
        + 2 * Hash512::BYTE_LENGTH;
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + RECEIPT_ENVELOPE_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_DOMAIN.len()
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + MASKED_BALLOT_BIVARIATE_RECEIPT_AUTHORIZATION_BODY_BYTE_LENGTH
        + MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH;
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + TERMINAL_BODY_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_DOMAIN.len()
        + 3 * Hash512::BYTE_LENGTH
        + 2 * size_of::<u16>();

pub(crate) fn masked_ballot_bivariate_receipt_terminal_certificate_byte_length(
    participant_count: u16,
) -> Result<usize, MaskedBallotBivariateReceiptError320> {
    if crate::foundation::derive_foundation_roster_parameters(participant_count).is_none() {
        return Err(receipt_object_mismatch("participant count"));
    }
    let participant_count = usize::from(participant_count);
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        .checked_add(
            TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT
                .checked_add(participant_count)
                .and_then(|item_count| item_count.checked_mul(CANONICAL_ITEM_HEADER_BYTE_LENGTH))
                .ok_or(MaskedBallotBivariateReceiptError320::ArithmeticOverflow)?,
        )
        .and_then(|length| length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH))
        .and_then(|length| {
            length.checked_add(MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_CERTIFICATE_DOMAIN.len())
        })
        .and_then(|length| length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH))
        .and_then(|length| {
            length.checked_add(MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_BYTE_LENGTH)
        })
        .and_then(|length| {
            CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
                .checked_add(MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_BYTE_LENGTH)
                .and_then(|envelope_length| participant_count.checked_mul(envelope_length))
                .and_then(|all_envelopes_length| length.checked_add(all_envelopes_length))
        })
        .ok_or(MaskedBallotBivariateReceiptError320::ArithmeticOverflow)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MaskedBallotBivariateReceiptError320 {
    Canonical(CanonicalCodecError),
    Mailbox(MaskedBallotBivariateMailboxError320),
    ObjectMismatch {
        field: &'static str,
    },
    RosterMismatch,
    HolderRosterPositionOutOfRange {
        holder_roster_position: u16,
        participant_count: u16,
    },
    ReceiptCount {
        expected: usize,
        actual: usize,
    },
    MalformedSigningVerificationKey {
        holder_roster_position: u16,
    },
    InvalidReceiptSignature {
        holder_roster_position: u16,
    },
    HolderSigningKeyMismatch {
        holder_roster_position: u16,
    },
    InvalidSignatureRandomness,
    SignatureGenerationFailed {
        holder_roster_position: u16,
    },
    SignatureByteLength {
        expected: usize,
        actual: usize,
    },
    LocalReceiptTerminalMismatch {
        field: &'static str,
    },
    ArithmeticOverflow,
}

impl From<CanonicalCodecError> for MaskedBallotBivariateReceiptError320 {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<MaskedBallotBivariateMailboxError320> for MaskedBallotBivariateReceiptError320 {
    fn from(error: MaskedBallotBivariateMailboxError320) -> Self {
        Self::Mailbox(error)
    }
}

impl fmt::Display for MaskedBallotBivariateReceiptError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => {
                write!(formatter, "canonical masked-ballot receipt error: {error}")
            }
            Self::Mailbox(error) => {
                write!(formatter, "masked-ballot receipt source error: {error}")
            }
            Self::ObjectMismatch { field } => {
                write!(
                    formatter,
                    "masked-ballot receipt object has a wrong {field}"
                )
            }
            Self::RosterMismatch => formatter
                .write_str("masked-ballot receipt roster does not match the commitment layout"),
            Self::HolderRosterPositionOutOfRange {
                holder_roster_position,
                participant_count,
            } => write!(
                formatter,
                "masked-ballot receipt holder {holder_roster_position} is outside participant count {participant_count}"
            ),
            Self::ReceiptCount { expected, actual } => write!(
                formatter,
                "masked-ballot receipt terminal has {actual} receipts; expected {expected}"
            ),
            Self::MalformedSigningVerificationKey {
                holder_roster_position,
            } => write!(
                formatter,
                "masked-ballot receipt holder {holder_roster_position} has a malformed ML-DSA-65 verification key"
            ),
            Self::InvalidReceiptSignature {
                holder_roster_position,
            } => write!(
                formatter,
                "masked-ballot receipt holder {holder_roster_position} has an invalid ML-DSA-65 signature"
            ),
            Self::HolderSigningKeyMismatch {
                holder_roster_position,
            } => write!(
                formatter,
                "masked-ballot receipt signing key does not match roster holder {holder_roster_position}"
            ),
            Self::InvalidSignatureRandomness => formatter.write_str(
                "masked-ballot receipt signature randomness must be a nonzero 32-byte value",
            ),
            Self::SignatureGenerationFailed {
                holder_roster_position,
            } => write!(
                formatter,
                "masked-ballot receipt signature generation failed for holder {holder_roster_position}"
            ),
            Self::SignatureByteLength { expected, actual } => write!(
                formatter,
                "masked-ballot receipt signature has {actual} bytes; expected {expected}"
            ),
            Self::LocalReceiptTerminalMismatch { field } => write!(
                formatter,
                "masked-ballot local receipt does not match the all-roster terminal {field}"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("masked-ballot receipt arithmetic overflowed")
            }
        }
    }
}

impl std::error::Error for MaskedBallotBivariateReceiptError320 {}

/// Canonical holder attestation over one exact signed aggregate manifest.
///
/// Manifest identity plus holder position transitively binds the holder's
/// header and carrier digest. Repeating those pointers here would add no
/// acceptance property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptBody320 {
    layout_identity: Hash512,
    root_body_identity: Hash512,
    manifest_identity: Hash512,
    participant_count: u16,
    author_roster_position: u16,
    holder_roster_position: u16,
}

impl MaskedBallotBivariateReceiptBody320 {
    pub(crate) fn new(
        authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
        authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
        holder_roster_position: u16,
    ) -> Result<Self, MaskedBallotBivariateReceiptError320> {
        require_manifest_scope(authenticated_root, authenticated_manifest)?;
        let layout = authenticated_root.root_body().layout();
        if holder_roster_position >= layout.participant_count() {
            return Err(
                MaskedBallotBivariateReceiptError320::HolderRosterPositionOutOfRange {
                    holder_roster_position,
                    participant_count: layout.participant_count(),
                },
            );
        }
        Ok(Self {
            layout_identity: layout.identity(),
            root_body_identity: authenticated_root.root_body_identity(),
            manifest_identity: authenticated_manifest.manifest_identity(),
            participant_count: layout.participant_count(),
            author_roster_position: layout.author_roster_position(),
            holder_roster_position,
        })
    }

    pub(crate) const fn holder_roster_position(self) -> u16 {
        self.holder_roster_position
    }

    pub(crate) fn canonical_bytes(self) -> Result<Vec<u8>, MaskedBallotBivariateReceiptError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_DOMAIN)?,
                CanonicalItem::hash512(self.layout_identity.into_bytes()),
                CanonicalItem::hash512(self.root_body_identity.into_bytes()),
                CanonicalItem::hash512(self.manifest_identity.into_bytes()),
                CanonicalItem::unsigned16(self.participant_count),
                CanonicalItem::unsigned16(self.author_roster_position),
                CanonicalItem::unsigned16(self.holder_roster_position),
            ],
        )
        .encode()?)
    }

    pub(crate) fn identity(self) -> Result<Hash512, MaskedBallotBivariateReceiptError320> {
        Ok(hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

/// Canonical holder-signature message after both state slots have passed.
///
/// The deterministic receipt body remains the semantic operation output. The
/// detached exact-output certificate identity authorizes those bytes without
/// becoming part of their identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptAuthorizationBody320 {
    receipt_body_identity: Hash512,
    exact_output_certificate_identity: Hash512,
}

impl MaskedBallotBivariateReceiptAuthorizationBody320 {
    pub(crate) fn new(
        verified_state_output: VerifiedMaskedBallotBivariateReceiptStateOutput320,
    ) -> Result<Self, MaskedBallotBivariateReceiptError320> {
        Ok(Self {
            receipt_body_identity: verified_state_output.receipt_body().identity()?,
            exact_output_certificate_identity: verified_state_output
                .exact_output_certificate_identity(),
        })
    }

    pub(crate) const fn exact_output_certificate_identity(self) -> Hash512 {
        self.exact_output_certificate_identity
    }

    pub(crate) fn canonical_bytes(self) -> Result<Vec<u8>, MaskedBallotBivariateReceiptError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_RECEIPT_AUTHORIZATION_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.receipt_body_identity.into_bytes()),
                CanonicalItem::hash512(self.exact_output_certificate_identity.into_bytes()),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected: Self,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptError320> {
        let tuple = CanonicalTuple::decode(bytes, &receipt_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_RECEIPT_AUTHORIZATION_BODY_DOMAIN,
            RECEIPT_AUTHORIZATION_BODY_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected.receipt_body_identity,
            "receipt-body identity",
        )?;
        require_hash(
            &tuple.items[2],
            expected.exact_output_certificate_identity,
            "exact-output-certificate identity",
        )?;
        Ok(expected)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptEnvelope320 {
    authorization_body: MaskedBallotBivariateReceiptAuthorizationBody320,
    signature: [u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl MaskedBallotBivariateReceiptEnvelope320 {
    pub(crate) const fn new(
        authorization_body: MaskedBallotBivariateReceiptAuthorizationBody320,
        signature: [u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            authorization_body,
            signature,
        }
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, MaskedBallotBivariateReceiptError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_DOMAIN)?,
                CanonicalItem::variable_bytes(self.authorization_body.canonical_bytes()?)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_authorization_body: MaskedBallotBivariateReceiptAuthorizationBody320,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptError320> {
        let tuple = CanonicalTuple::decode(bytes, &receipt_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_DOMAIN,
            RECEIPT_ENVELOPE_ITEM_COUNT,
        )?;
        if tuple.items[1].item_type() != CanonicalItemType::RawBytes {
            return Err(receipt_object_mismatch("receipt authorization body"));
        }
        let authorization_body =
            MaskedBallotBivariateReceiptAuthorizationBody320::from_canonical_bytes(
                expected_authorization_body,
                tuple.items[1].variable_value_bytes()?,
            )?;
        let signature = read_signature(&tuple.items[2])?;
        Ok(Self {
            authorization_body,
            signature,
        })
    }

    pub(crate) fn identity(&self) -> Result<Hash512, MaskedBallotBivariateReceiptError320> {
        Ok(hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_RECEIPT_ENVELOPE_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

impl fmt::Debug for MaskedBallotBivariateReceiptEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateReceiptEnvelope320")
            .field("authorization_body", &self.authorization_body)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Public roster signature over the expected package and holder position.
///
/// A corrupt holder can sign without possessing a valid row. Only the local
/// result below proves one holder's source correspondence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RosterSignedMaskedBallotBivariateReceipt320 {
    receipt_body: MaskedBallotBivariateReceiptBody320,
    state_key_identity: Hash512,
    reservation_certificate_identity: Hash512,
    exact_output_certificate_identity: Hash512,
    receipt_envelope_identity: Hash512,
}

impl RosterSignedMaskedBallotBivariateReceipt320 {
    pub(crate) const fn receipt_body(self) -> MaskedBallotBivariateReceiptBody320 {
        self.receipt_body
    }

    pub(crate) const fn state_key_identity(self) -> Hash512 {
        self.state_key_identity
    }

    pub(crate) const fn reservation_certificate_identity(self) -> Hash512 {
        self.reservation_certificate_identity
    }

    pub(crate) const fn exact_output_certificate_identity(self) -> Hash512 {
        self.exact_output_certificate_identity
    }

    pub(crate) const fn receipt_envelope_identity(self) -> Hash512 {
        self.receipt_envelope_identity
    }
}

pub(crate) fn verify_masked_ballot_bivariate_receipt_announcement_320(
    verified_state_output: VerifiedMaskedBallotBivariateReceiptStateOutput320,
    roster: &Roster,
    receipt_envelope_bytes: &[u8],
) -> Result<RosterSignedMaskedBallotBivariateReceipt320, MaskedBallotBivariateReceiptError320> {
    let layout = verified_state_output.layout();
    validate_roster_for_layout(layout, roster)?;
    let expected_receipt_body = verified_state_output.receipt_body();
    let expected_holder_roster_position = expected_receipt_body.holder_roster_position();
    let expected_authorization_body =
        MaskedBallotBivariateReceiptAuthorizationBody320::new(verified_state_output)?;
    let receipt_envelope = MaskedBallotBivariateReceiptEnvelope320::from_canonical_bytes(
        expected_authorization_body,
        receipt_envelope_bytes,
    )?;
    let holder_entry = require_roster_holder(roster, layout, expected_holder_roster_position)?;
    let verification_key =
        ml_dsa_65::PublicKey::try_from_bytes(holder_entry.signing_verification_key).map_err(
            |_| MaskedBallotBivariateReceiptError320::MalformedSigningVerificationKey {
                holder_roster_position: expected_holder_roster_position,
            },
        )?;
    if !verification_key.verify(
        &expected_authorization_body.canonical_bytes()?,
        &receipt_envelope.signature,
        MASKED_BALLOT_BIVARIATE_RECEIPT_SIGNATURE_CONTEXT,
    ) {
        return Err(
            MaskedBallotBivariateReceiptError320::InvalidReceiptSignature {
                holder_roster_position: expected_holder_roster_position,
            },
        );
    }
    Ok(RosterSignedMaskedBallotBivariateReceipt320 {
        receipt_body: expected_receipt_body,
        state_key_identity: verified_state_output.state_key_identity(),
        reservation_certificate_identity: verified_state_output.reservation_certificate_identity(),
        exact_output_certificate_identity: verified_state_output
            .exact_output_certificate_identity(),
        receipt_envelope_identity: receipt_envelope.identity()?,
    })
}

/// Positive local custody plus the holder's exact roster signature.
///
/// This type has no all-roster terminal, durable one-shot state, selected-set,
/// release, or continuation authority.
pub(crate) struct AuthenticatedMaskedBallotBivariateReceipt320 {
    delivery: AuthenticatedMaskedBallotBivariateMailboxDelivery320,
    receipt_body: MaskedBallotBivariateReceiptBody320,
    state_key_identity: Hash512,
    reservation_certificate_identity: Hash512,
    exact_output_certificate_identity: Hash512,
    receipt_envelope_identity: Hash512,
}

impl AuthenticatedMaskedBallotBivariateReceipt320 {
    pub(crate) const fn delivery(&self) -> &AuthenticatedMaskedBallotBivariateMailboxDelivery320 {
        &self.delivery
    }

    pub(crate) const fn receipt_body(&self) -> MaskedBallotBivariateReceiptBody320 {
        self.receipt_body
    }

    pub(crate) const fn state_key_identity(&self) -> Hash512 {
        self.state_key_identity
    }

    pub(crate) const fn reservation_certificate_identity(&self) -> Hash512 {
        self.reservation_certificate_identity
    }

    pub(crate) const fn exact_output_certificate_identity(&self) -> Hash512 {
        self.exact_output_certificate_identity
    }

    pub(crate) const fn receipt_envelope_identity(&self) -> Hash512 {
        self.receipt_envelope_identity
    }
}

impl fmt::Debug for AuthenticatedMaskedBallotBivariateReceipt320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedMaskedBallotBivariateReceipt320")
            .field("delivery", &"[redacted]")
            .field("receipt_body", &self.receipt_body)
            .field("state_key_identity", &self.state_key_identity)
            .field(
                "reservation_certificate_identity",
                &self.reservation_certificate_identity,
            )
            .field(
                "exact_output_certificate_identity",
                &self.exact_output_certificate_identity,
            )
            .field("receipt_envelope_identity", &self.receipt_envelope_identity)
            .finish()
    }
}

pub(crate) struct ProducedMaskedBallotBivariateReceipt320 {
    authenticated_receipt: AuthenticatedMaskedBallotBivariateReceipt320,
    receipt_envelope_bytes: Vec<u8>,
}

impl ProducedMaskedBallotBivariateReceipt320 {
    pub(crate) const fn authenticated_receipt(
        &self,
    ) -> &AuthenticatedMaskedBallotBivariateReceipt320 {
        &self.authenticated_receipt
    }

    pub(crate) fn receipt_envelope_bytes(&self) -> &[u8] {
        &self.receipt_envelope_bytes
    }

    pub(crate) fn into_authenticated_receipt(self) -> AuthenticatedMaskedBallotBivariateReceipt320 {
        self.authenticated_receipt
    }
}

impl fmt::Debug for ProducedMaskedBallotBivariateReceipt320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducedMaskedBallotBivariateReceipt320")
            .field("authenticated_receipt", &self.authenticated_receipt)
            .field(
                "receipt_envelope_byte_length",
                &self.receipt_envelope_bytes.len(),
            )
            .finish()
    }
}

pub(crate) fn verify_masked_ballot_bivariate_receipt_320(
    verified_state_output: VerifiedMaskedBallotBivariateReceiptStateOutput320,
    roster: &Roster,
    delivery: AuthenticatedMaskedBallotBivariateMailboxDelivery320,
    receipt_envelope_bytes: &[u8],
) -> Result<AuthenticatedMaskedBallotBivariateReceipt320, MaskedBallotBivariateReceiptError320> {
    require_state_output_matches_delivery(verified_state_output, &delivery)?;
    let roster_signed_receipt = verify_masked_ballot_bivariate_receipt_announcement_320(
        verified_state_output,
        roster,
        receipt_envelope_bytes,
    )?;
    Ok(AuthenticatedMaskedBallotBivariateReceipt320 {
        delivery,
        receipt_body: roster_signed_receipt.receipt_body,
        state_key_identity: roster_signed_receipt.state_key_identity,
        reservation_certificate_identity: roster_signed_receipt.reservation_certificate_identity,
        exact_output_certificate_identity: roster_signed_receipt.exact_output_certificate_identity,
        receipt_envelope_identity: roster_signed_receipt.receipt_envelope_identity,
    })
}

pub(crate) fn produce_masked_ballot_bivariate_receipt_320(
    verified_state_output: VerifiedMaskedBallotBivariateReceiptStateOutput320,
    roster: &Roster,
    delivery: AuthenticatedMaskedBallotBivariateMailboxDelivery320,
    holder_signing_key: &ml_dsa_65::PrivateKey,
    signature_randomness: [u8; 32],
) -> Result<ProducedMaskedBallotBivariateReceipt320, MaskedBallotBivariateReceiptError320> {
    require_state_output_matches_delivery(verified_state_output, &delivery)?;
    let layout = verified_state_output.layout();
    validate_roster_for_layout(layout, roster)?;
    let holder_roster_position = delivery.holder_roster_position();
    let holder_entry = require_roster_holder(roster, layout, holder_roster_position)?;
    if holder_signing_key.get_public_key().into_bytes() != holder_entry.signing_verification_key {
        return Err(
            MaskedBallotBivariateReceiptError320::HolderSigningKeyMismatch {
                holder_roster_position,
            },
        );
    }
    let signature_randomness = Zeroizing::new(signature_randomness);
    if signature_randomness.iter().all(|byte| *byte == 0) {
        return Err(MaskedBallotBivariateReceiptError320::InvalidSignatureRandomness);
    }
    let authorization_body =
        MaskedBallotBivariateReceiptAuthorizationBody320::new(verified_state_output)?;
    let signature = holder_signing_key
        .try_sign_with_seed(
            &signature_randomness,
            &authorization_body.canonical_bytes()?,
            MASKED_BALLOT_BIVARIATE_RECEIPT_SIGNATURE_CONTEXT,
        )
        .map_err(
            |_| MaskedBallotBivariateReceiptError320::SignatureGenerationFailed {
                holder_roster_position,
            },
        )?;
    let receipt_envelope_bytes =
        MaskedBallotBivariateReceiptEnvelope320::new(authorization_body, signature)
            .canonical_bytes()?;
    let authenticated_receipt = verify_masked_ballot_bivariate_receipt_320(
        verified_state_output,
        roster,
        delivery,
        &receipt_envelope_bytes,
    )?;
    Ok(ProducedMaskedBallotBivariateReceipt320 {
        authenticated_receipt,
        receipt_envelope_bytes,
    })
}

/// Semantic target for exactly one receipt from every roster holder.
///
/// Receipt-signature randomness and certificate framing are deliberately
/// excluded so alternate valid carriers cannot create another semantic
/// custody package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptTerminalBody320 {
    layout_identity: Hash512,
    root_body_identity: Hash512,
    manifest_identity: Hash512,
    participant_count: u16,
    author_roster_position: u16,
}

impl MaskedBallotBivariateReceiptTerminalBody320 {
    fn new(
        authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
        authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    ) -> Result<Self, MaskedBallotBivariateReceiptError320> {
        require_manifest_scope(authenticated_root, authenticated_manifest)?;
        let layout = authenticated_root.root_body().layout();
        Ok(Self {
            layout_identity: layout.identity(),
            root_body_identity: authenticated_root.root_body_identity(),
            manifest_identity: authenticated_manifest.manifest_identity(),
            participant_count: layout.participant_count(),
            author_roster_position: layout.author_roster_position(),
        })
    }

    pub(crate) fn canonical_bytes(self) -> Result<Vec<u8>, MaskedBallotBivariateReceiptError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.layout_identity.into_bytes()),
                CanonicalItem::hash512(self.root_body_identity.into_bytes()),
                CanonicalItem::hash512(self.manifest_identity.into_bytes()),
                CanonicalItem::unsigned16(self.participant_count),
                CanonicalItem::unsigned16(self.author_roster_position),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected: Self,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptError320> {
        let tuple = CanonicalTuple::decode(bytes, &receipt_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_DOMAIN,
            TERMINAL_BODY_ITEM_COUNT,
        )?;
        require_hash(&tuple.items[1], expected.layout_identity, "layout identity")?;
        require_hash(
            &tuple.items[2],
            expected.root_body_identity,
            "root-body identity",
        )?;
        require_hash(
            &tuple.items[3],
            expected.manifest_identity,
            "manifest identity",
        )?;
        require_u16(
            &tuple.items[4],
            expected.participant_count,
            "participant count",
        )?;
        require_u16(
            &tuple.items[5],
            expected.author_roster_position,
            "author roster position",
        )?;
        Ok(expected)
    }

    pub(crate) fn identity(self) -> Result<Hash512, MaskedBallotBivariateReceiptError320> {
        Ok(hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_BODY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct MaskedBallotBivariateReceiptTerminalCertificate320 {
    terminal_body: MaskedBallotBivariateReceiptTerminalBody320,
    receipt_envelope_bytes: Box<[Vec<u8>]>,
}

impl MaskedBallotBivariateReceiptTerminalCertificate320 {
    fn new(
        terminal_body: MaskedBallotBivariateReceiptTerminalBody320,
        receipt_envelope_bytes: Vec<Vec<u8>>,
    ) -> Result<Self, MaskedBallotBivariateReceiptError320> {
        let expected = usize::from(terminal_body.participant_count);
        if receipt_envelope_bytes.len() != expected {
            return Err(MaskedBallotBivariateReceiptError320::ReceiptCount {
                expected,
                actual: receipt_envelope_bytes.len(),
            });
        }
        Ok(Self {
            terminal_body,
            receipt_envelope_bytes: receipt_envelope_bytes.into_boxed_slice(),
        })
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, MaskedBallotBivariateReceiptError320> {
        let mut items = Vec::with_capacity(
            TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT + self.receipt_envelope_bytes.len(),
        );
        items.push(CanonicalItem::nonempty_ascii(
            MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_CERTIFICATE_DOMAIN,
        )?);
        items.push(CanonicalItem::variable_bytes(
            self.terminal_body.canonical_bytes()?,
        )?);
        for receipt_envelope_bytes in &self.receipt_envelope_bytes {
            items.push(CanonicalItem::variable_bytes(receipt_envelope_bytes)?);
        }
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            items,
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_terminal_body: MaskedBallotBivariateReceiptTerminalBody320,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptError320> {
        let tuple = CanonicalTuple::decode(bytes, &terminal_certificate_decode_limits())?;
        let expected_receipt_count = usize::from(expected_terminal_body.participant_count);
        let expected_item_count = TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT
            .checked_add(expected_receipt_count)
            .ok_or(MaskedBallotBivariateReceiptError320::ArithmeticOverflow)?;
        if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
            || tuple.schema_version != CANONICAL_TUPLE_VERSION
        {
            return Err(receipt_object_mismatch("terminal certificate header"));
        }
        if tuple.items.len() != expected_item_count {
            return Err(MaskedBallotBivariateReceiptError320::ReceiptCount {
                expected: expected_receipt_count,
                actual: tuple
                    .items
                    .len()
                    .saturating_sub(TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT),
            });
        }
        require_ascii(
            &tuple.items[0],
            MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_CERTIFICATE_DOMAIN,
            "object domain",
        )?;
        if tuple.items[1].item_type() != CanonicalItemType::RawBytes {
            return Err(receipt_object_mismatch("terminal body"));
        }
        let terminal_body = MaskedBallotBivariateReceiptTerminalBody320::from_canonical_bytes(
            expected_terminal_body,
            tuple.items[1].variable_value_bytes()?,
        )?;
        let receipt_envelope_bytes = tuple.items[TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT..]
            .iter()
            .map(|item| {
                if item.item_type() != CanonicalItemType::RawBytes {
                    return Err(receipt_object_mismatch("receipt envelope"));
                }
                Ok(item.variable_value_bytes()?.to_vec())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(terminal_body, receipt_envelope_bytes)
    }

    fn identity(&self) -> Result<Hash512, MaskedBallotBivariateReceiptError320> {
        Ok(hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_RECEIPT_TERMINAL_CERTIFICATE_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

impl fmt::Debug for MaskedBallotBivariateReceiptTerminalCertificate320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateReceiptTerminalCertificate320")
            .field("terminal_body", &self.terminal_body)
            .field("receipt_count", &self.receipt_envelope_bytes.len())
            .field("receipt_signatures", &"[redacted]")
            .finish()
    }
}

/// Exact all-roster receipt terminal for one signed aggregate manifest.
///
/// Every roster signature and both subject-excluding state certificates have
/// passed. Corrupt holders can still attest to rows they did not verify, while
/// honest local producers require positive delivery before signing. Durable
/// witness locking and replay remain separate runtime obligations. This result
/// grants no selected-set, release, or continuation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AllRosterMaskedBallotBivariateReceiptTerminal320 {
    terminal_body: MaskedBallotBivariateReceiptTerminalBody320,
    terminal_body_identity: Hash512,
    receipt_body_identities: Box<[Hash512]>,
    state_key_identities: Box<[Hash512]>,
    reservation_certificate_identities: Box<[Hash512]>,
    exact_output_certificate_identities: Box<[Hash512]>,
    receipt_envelope_identities: Box<[Hash512]>,
    certificate_identity: Hash512,
}

impl AllRosterMaskedBallotBivariateReceiptTerminal320 {
    pub(crate) const fn terminal_body(&self) -> MaskedBallotBivariateReceiptTerminalBody320 {
        self.terminal_body
    }

    pub(crate) const fn terminal_body_identity(&self) -> Hash512 {
        self.terminal_body_identity
    }

    pub(crate) fn receipt_body_identities(&self) -> &[Hash512] {
        &self.receipt_body_identities
    }

    pub(crate) fn state_key_identities(&self) -> &[Hash512] {
        &self.state_key_identities
    }

    pub(crate) fn reservation_certificate_identities(&self) -> &[Hash512] {
        &self.reservation_certificate_identities
    }

    pub(crate) fn exact_output_certificate_identities(&self) -> &[Hash512] {
        &self.exact_output_certificate_identities
    }

    pub(crate) fn receipt_envelope_identities(&self) -> &[Hash512] {
        &self.receipt_envelope_identities
    }

    pub(crate) const fn certificate_identity(&self) -> Hash512 {
        self.certificate_identity
    }
}

/// Local root-matched row custody joined to one all-roster receipt terminal.
///
/// This is the last positive custody result before durable state. It proves
/// that the holder's exact signed receipt occurs at its roster position in the
/// terminal and retains the root-bound private row bytes needed for a future
/// selected included release. It grants no selected-set, omitted-input,
/// release, or preparation-continuation authority.
pub(crate) struct JoinedMaskedBallotBivariateCustody320 {
    delivery: AuthenticatedMaskedBallotBivariateMailboxDelivery320,
    receipt_body_identity: Hash512,
    state_key_identity: Hash512,
    reservation_certificate_identity: Hash512,
    exact_output_certificate_identity: Hash512,
    receipt_envelope_identity: Hash512,
    terminal_body_identity: Hash512,
    terminal_certificate_identity: Hash512,
}

impl JoinedMaskedBallotBivariateCustody320 {
    pub(crate) const fn delivery(&self) -> &AuthenticatedMaskedBallotBivariateMailboxDelivery320 {
        &self.delivery
    }

    pub(crate) const fn receipt_body_identity(&self) -> Hash512 {
        self.receipt_body_identity
    }

    pub(crate) const fn receipt_envelope_identity(&self) -> Hash512 {
        self.receipt_envelope_identity
    }

    pub(crate) const fn state_key_identity(&self) -> Hash512 {
        self.state_key_identity
    }

    pub(crate) const fn reservation_certificate_identity(&self) -> Hash512 {
        self.reservation_certificate_identity
    }

    pub(crate) const fn exact_output_certificate_identity(&self) -> Hash512 {
        self.exact_output_certificate_identity
    }

    pub(crate) const fn terminal_body_identity(&self) -> Hash512 {
        self.terminal_body_identity
    }

    pub(crate) const fn terminal_certificate_identity(&self) -> Hash512 {
        self.terminal_certificate_identity
    }
}

impl fmt::Debug for JoinedMaskedBallotBivariateCustody320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinedMaskedBallotBivariateCustody320")
            .field("delivery", &"[redacted]")
            .field("receipt_body_identity", &self.receipt_body_identity)
            .field("state_key_identity", &self.state_key_identity)
            .field(
                "reservation_certificate_identity",
                &self.reservation_certificate_identity,
            )
            .field(
                "exact_output_certificate_identity",
                &self.exact_output_certificate_identity,
            )
            .field("receipt_envelope_identity", &self.receipt_envelope_identity)
            .field("terminal_body_identity", &self.terminal_body_identity)
            .field(
                "terminal_certificate_identity",
                &self.terminal_certificate_identity,
            )
            .finish()
    }
}

pub(crate) fn join_masked_ballot_bivariate_custody_320(
    authenticated_receipt: AuthenticatedMaskedBallotBivariateReceipt320,
    receipt_terminal: &AllRosterMaskedBallotBivariateReceiptTerminal320,
) -> Result<JoinedMaskedBallotBivariateCustody320, MaskedBallotBivariateReceiptError320> {
    let receipt_body = authenticated_receipt.receipt_body;
    let terminal_body = receipt_terminal.terminal_body;
    if receipt_body.layout_identity != terminal_body.layout_identity {
        return Err(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "layout identity",
            },
        );
    }
    if receipt_body.root_body_identity != terminal_body.root_body_identity {
        return Err(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "root-body identity",
            },
        );
    }
    if receipt_body.manifest_identity != terminal_body.manifest_identity {
        return Err(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "manifest identity",
            },
        );
    }
    if receipt_body.participant_count != terminal_body.participant_count
        || receipt_body.author_roster_position != terminal_body.author_roster_position
    {
        return Err(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "roster scope",
            },
        );
    }
    let holder_index = usize::from(receipt_body.holder_roster_position);
    let expected_receipt_body_identity = receipt_terminal
        .receipt_body_identities
        .get(holder_index)
        .ok_or(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "holder position",
            },
        )?;
    let receipt_body_identity = receipt_body.identity()?;
    if receipt_body_identity != *expected_receipt_body_identity {
        return Err(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "receipt-body identity",
            },
        );
    }
    let expected_state_key_identity = receipt_terminal
        .state_key_identities
        .get(holder_index)
        .ok_or(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "state-key position",
            },
        )?;
    if authenticated_receipt.state_key_identity != *expected_state_key_identity {
        return Err(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "state-key identity",
            },
        );
    }
    let expected_reservation_certificate_identity = receipt_terminal
        .reservation_certificate_identities
        .get(holder_index)
        .ok_or(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "reservation-certificate position",
            },
        )?;
    if authenticated_receipt.reservation_certificate_identity
        != *expected_reservation_certificate_identity
    {
        return Err(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "reservation-certificate identity",
            },
        );
    }
    let expected_exact_output_certificate_identity = receipt_terminal
        .exact_output_certificate_identities
        .get(holder_index)
        .ok_or(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "exact-output-certificate position",
            },
        )?;
    if authenticated_receipt.exact_output_certificate_identity
        != *expected_exact_output_certificate_identity
    {
        return Err(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "exact-output-certificate identity",
            },
        );
    }
    let expected_receipt_envelope_identity = receipt_terminal
        .receipt_envelope_identities
        .get(holder_index)
        .ok_or(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "holder envelope position",
            },
        )?;
    if authenticated_receipt.receipt_envelope_identity != *expected_receipt_envelope_identity {
        return Err(
            MaskedBallotBivariateReceiptError320::LocalReceiptTerminalMismatch {
                field: "receipt-envelope identity",
            },
        );
    }
    Ok(JoinedMaskedBallotBivariateCustody320 {
        delivery: authenticated_receipt.delivery,
        receipt_body_identity,
        state_key_identity: authenticated_receipt.state_key_identity,
        reservation_certificate_identity: authenticated_receipt.reservation_certificate_identity,
        exact_output_certificate_identity: authenticated_receipt.exact_output_certificate_identity,
        receipt_envelope_identity: authenticated_receipt.receipt_envelope_identity,
        terminal_body_identity: receipt_terminal.terminal_body_identity,
        terminal_certificate_identity: receipt_terminal.certificate_identity,
    })
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MaskedBallotBivariateReceiptAuthorizationPackage320<'a> {
    verified_state_output: VerifiedMaskedBallotBivariateReceiptStateOutput320,
    receipt_envelope_bytes: &'a [u8],
}

impl<'a> MaskedBallotBivariateReceiptAuthorizationPackage320<'a> {
    pub(crate) const fn new(
        verified_state_output: VerifiedMaskedBallotBivariateReceiptStateOutput320,
        receipt_envelope_bytes: &'a [u8],
    ) -> Self {
        Self {
            verified_state_output,
            receipt_envelope_bytes,
        }
    }
}

pub(crate) fn compile_masked_ballot_bivariate_receipt_terminal_certificate_320(
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    roster: &Roster,
    receipt_packages: &[MaskedBallotBivariateReceiptAuthorizationPackage320<'_>],
) -> Result<Vec<u8>, MaskedBallotBivariateReceiptError320> {
    let terminal_body = MaskedBallotBivariateReceiptTerminalBody320::new(
        authenticated_root,
        authenticated_manifest,
    )?;
    validate_roster_for_layout(authenticated_root.root_body().layout(), roster)?;
    let expected_receipt_count = usize::from(terminal_body.participant_count);
    if receipt_packages.len() != expected_receipt_count {
        return Err(MaskedBallotBivariateReceiptError320::ReceiptCount {
            expected: expected_receipt_count,
            actual: receipt_packages.len(),
        });
    }
    for (holder_index, receipt_package) in receipt_packages.iter().enumerate() {
        let holder_roster_position = u16::try_from(holder_index)
            .map_err(|_| MaskedBallotBivariateReceiptError320::ArithmeticOverflow)?;
        require_state_output_scope(
            receipt_package.verified_state_output,
            authenticated_root,
            authenticated_manifest,
            holder_roster_position,
        )?;
        verify_masked_ballot_bivariate_receipt_announcement_320(
            receipt_package.verified_state_output,
            roster,
            receipt_package.receipt_envelope_bytes,
        )?;
    }
    MaskedBallotBivariateReceiptTerminalCertificate320::new(
        terminal_body,
        receipt_packages
            .iter()
            .map(|package| package.receipt_envelope_bytes.to_vec())
            .collect(),
    )?
    .canonical_bytes()
}

pub(crate) fn verify_masked_ballot_bivariate_receipt_terminal_320(
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    roster: &Roster,
    verified_state_outputs: &[VerifiedMaskedBallotBivariateReceiptStateOutput320],
    terminal_certificate_bytes: &[u8],
) -> Result<AllRosterMaskedBallotBivariateReceiptTerminal320, MaskedBallotBivariateReceiptError320>
{
    let terminal_body = MaskedBallotBivariateReceiptTerminalBody320::new(
        authenticated_root,
        authenticated_manifest,
    )?;
    validate_roster_for_layout(authenticated_root.root_body().layout(), roster)?;
    let expected_receipt_count = usize::from(terminal_body.participant_count);
    if verified_state_outputs.len() != expected_receipt_count {
        return Err(MaskedBallotBivariateReceiptError320::ReceiptCount {
            expected: expected_receipt_count,
            actual: verified_state_outputs.len(),
        });
    }
    let terminal_certificate =
        MaskedBallotBivariateReceiptTerminalCertificate320::from_canonical_bytes(
            terminal_body,
            terminal_certificate_bytes,
        )?;
    let mut receipt_body_identities =
        Vec::with_capacity(usize::from(terminal_body.participant_count));
    let mut state_key_identities = Vec::with_capacity(usize::from(terminal_body.participant_count));
    let mut reservation_certificate_identities =
        Vec::with_capacity(usize::from(terminal_body.participant_count));
    let mut exact_output_certificate_identities =
        Vec::with_capacity(usize::from(terminal_body.participant_count));
    let mut receipt_envelope_identities =
        Vec::with_capacity(usize::from(terminal_body.participant_count));
    for (holder_index, envelope_bytes) in terminal_certificate
        .receipt_envelope_bytes
        .iter()
        .enumerate()
    {
        let holder_roster_position = u16::try_from(holder_index)
            .map_err(|_| MaskedBallotBivariateReceiptError320::ArithmeticOverflow)?;
        let verified_state_output = verified_state_outputs[holder_index];
        require_state_output_scope(
            verified_state_output,
            authenticated_root,
            authenticated_manifest,
            holder_roster_position,
        )?;
        let receipt = verify_masked_ballot_bivariate_receipt_announcement_320(
            verified_state_output,
            roster,
            envelope_bytes,
        )?;
        receipt_body_identities.push(receipt.receipt_body.identity()?);
        state_key_identities.push(receipt.state_key_identity);
        reservation_certificate_identities.push(receipt.reservation_certificate_identity);
        exact_output_certificate_identities.push(receipt.exact_output_certificate_identity);
        receipt_envelope_identities.push(receipt.receipt_envelope_identity);
    }
    if terminal_certificate_bytes.len()
        != masked_ballot_bivariate_receipt_terminal_certificate_byte_length(
            terminal_body.participant_count,
        )?
    {
        return Err(receipt_object_mismatch("terminal certificate byte length"));
    }
    Ok(AllRosterMaskedBallotBivariateReceiptTerminal320 {
        terminal_body,
        terminal_body_identity: terminal_body.identity()?,
        receipt_body_identities: receipt_body_identities.into_boxed_slice(),
        state_key_identities: state_key_identities.into_boxed_slice(),
        reservation_certificate_identities: reservation_certificate_identities.into_boxed_slice(),
        exact_output_certificate_identities: exact_output_certificate_identities.into_boxed_slice(),
        receipt_envelope_identities: receipt_envelope_identities.into_boxed_slice(),
        certificate_identity: terminal_certificate.identity()?,
    })
}

fn require_manifest_scope(
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
) -> Result<(), MaskedBallotBivariateReceiptError320> {
    let layout = authenticated_root.root_body().layout();
    if authenticated_manifest.layout_identity() != layout.identity()
        || authenticated_manifest.root_body_identity() != authenticated_root.root_body_identity()
        || authenticated_manifest.participant_count() != layout.participant_count()
        || authenticated_manifest.author_roster_position() != layout.author_roster_position()
    {
        return Err(receipt_object_mismatch("manifest root scope"));
    }
    Ok(())
}

fn require_state_output_scope(
    verified_state_output: VerifiedMaskedBallotBivariateReceiptStateOutput320,
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    holder_roster_position: u16,
) -> Result<(), MaskedBallotBivariateReceiptError320> {
    let expected_receipt_body = MaskedBallotBivariateReceiptBody320::new(
        authenticated_root,
        authenticated_manifest,
        holder_roster_position,
    )?;
    if verified_state_output.layout() != authenticated_root.root_body().layout()
        || verified_state_output.receipt_body() != expected_receipt_body
    {
        return Err(receipt_object_mismatch("verified state-output scope"));
    }
    Ok(())
}

fn require_state_output_matches_delivery(
    verified_state_output: VerifiedMaskedBallotBivariateReceiptStateOutput320,
    delivery: &AuthenticatedMaskedBallotBivariateMailboxDelivery320,
) -> Result<(), MaskedBallotBivariateReceiptError320> {
    let layout = verified_state_output.layout();
    let receipt_body = verified_state_output.receipt_body();
    if delivery.layout_identity() != layout.identity()
        || receipt_body.layout_identity != layout.identity()
        || delivery.root_body_identity() != receipt_body.root_body_identity
        || delivery.manifest_identity() != receipt_body.manifest_identity
        || delivery.author_roster_position() != receipt_body.author_roster_position
        || delivery.holder_roster_position() != receipt_body.holder_roster_position
        || receipt_body.participant_count != layout.participant_count()
    {
        return Err(receipt_object_mismatch("state-authorized delivery scope"));
    }
    Ok(())
}

fn validate_roster_for_layout(
    layout: MaskedBallotBivariateCommitmentLayout320,
    roster: &Roster,
) -> Result<(), MaskedBallotBivariateReceiptError320> {
    roster
        .validate()
        .map_err(|_| MaskedBallotBivariateReceiptError320::RosterMismatch)?;
    if roster.entries.len() != usize::from(layout.participant_count())
        || roster
            .roster_hash()
            .map_err(|_| MaskedBallotBivariateReceiptError320::RosterMismatch)?
            != layout.preparation_context().roster_hash()
    {
        return Err(MaskedBallotBivariateReceiptError320::RosterMismatch);
    }
    Ok(())
}

fn require_roster_holder(
    roster: &Roster,
    layout: MaskedBallotBivariateCommitmentLayout320,
    holder_roster_position: u16,
) -> Result<&crate::foundation::RosterEntry, MaskedBallotBivariateReceiptError320> {
    roster
        .entries
        .get(usize::from(holder_roster_position))
        .filter(|entry| entry.roster_position == holder_roster_position)
        .ok_or(
            MaskedBallotBivariateReceiptError320::HolderRosterPositionOutOfRange {
                holder_roster_position,
                participant_count: layout.participant_count(),
            },
        )
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), MaskedBallotBivariateReceiptError320> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
        || tuple.schema_version != CANONICAL_TUPLE_VERSION
        || tuple.items.len() != expected_item_count
    {
        return Err(receipt_object_mismatch("header"));
    }
    require_ascii(&tuple.items[0], expected_domain, "object domain")
}

fn require_ascii(
    item: &CanonicalItem,
    expected: &str,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateReceiptError320> {
    if item.item_type() != CanonicalItemType::Ascii
        || item.variable_value_bytes()? != expected.as_bytes()
    {
        return Err(receipt_object_mismatch(field));
    }
    Ok(())
}

fn read_hash(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<Hash512, MaskedBallotBivariateReceiptError320> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(receipt_object_mismatch(field));
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| receipt_object_mismatch(field))?;
    Ok(Hash512::from_bytes(bytes))
}

fn require_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateReceiptError320> {
    if read_hash(item, field)? != expected {
        return Err(receipt_object_mismatch(field));
    }
    Ok(())
}

fn read_u16(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u16, MaskedBallotBivariateReceiptError320> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(receipt_object_mismatch(field));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| receipt_object_mismatch(field))?;
    Ok(u16::from_le_bytes(bytes))
}

fn require_u16(
    item: &CanonicalItem,
    expected: u16,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateReceiptError320> {
    if read_u16(item, field)? != expected {
        return Err(receipt_object_mismatch(field));
    }
    Ok(())
}

fn read_signature(
    item: &CanonicalItem,
) -> Result<[u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH], MaskedBallotBivariateReceiptError320>
{
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(receipt_object_mismatch("signature"));
    }
    item.canonical_bytes().try_into().map_err(|_| {
        MaskedBallotBivariateReceiptError320::SignatureByteLength {
            expected: MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH,
            actual: item.canonical_bytes().len(),
        }
    })
}

const fn receipt_object_mismatch(field: &'static str) -> MaskedBallotBivariateReceiptError320 {
    MaskedBallotBivariateReceiptError320::ObjectMismatch { field }
}

fn receipt_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_RECEIPT_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: RECEIPT_BODY_ITEM_COUNT.max(RECEIPT_ENVELOPE_ITEM_COUNT),
        maximum_item_byte_length: MAXIMUM_RECEIPT_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_RECEIPT_CONTROL_OBJECT_BYTE_LENGTH * 2,
        maximum_cumulative_allocation_byte_length: MAXIMUM_RECEIPT_CONTROL_OBJECT_BYTE_LENGTH * 2,
    }
}

fn terminal_certificate_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_TERMINAL_CERTIFICATE_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_TERMINAL_CERTIFICATE_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_RECEIPT_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_TERMINAL_CERTIFICATE_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_TERMINAL_CERTIFICATE_CUMULATIVE_BYTE_LENGTH,
    }
}
