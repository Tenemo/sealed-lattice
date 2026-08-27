use core::fmt;

use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, Roster,
    derive_foundation_roster_parameters, hash_foundation_tuple_512,
};

use super::{
    masked_ballot_bivariate_commitment_320::{
        AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
        MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH, MaskedBallotBivariateCommitmentLayout320,
    },
    masked_ballot_bivariate_mailbox_320::AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    masked_ballot_bivariate_receipt_320::{
        MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_BYTE_LENGTH, MaskedBallotBivariateReceiptBody320,
        MaskedBallotBivariateReceiptError320,
    },
};

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const RESERVATION_INTENT_ITEM_COUNT: usize = 5;
const WITNESS_AUTHORIZATION_BODY_ITEM_COUNT: usize = 3;
const WITNESS_ENVELOPE_ITEM_COUNT: usize = 3;
const RESERVATION_CERTIFICATE_PREFIX_ITEM_COUNT: usize = 2;
const EXACT_OUTPUT_INTENT_ITEM_COUNT: usize = 6;
const EXACT_OUTPUT_WITNESS_AUTHORIZATION_BODY_ITEM_COUNT: usize = 3;
const EXACT_OUTPUT_WITNESS_ENVELOPE_ITEM_COUNT: usize = 3;
const EXACT_OUTPUT_CERTIFICATE_PREFIX_ITEM_COUNT: usize = 2;
const MAXIMUM_STATE_CONTROL_OBJECT_BYTE_LENGTH: usize = 8 * 1024;
const MAXIMUM_STATE_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 4 * 1024;
const MAXIMUM_STATE_CERTIFICATE_BYTE_LENGTH: usize = 128 * 1024;
const MAXIMUM_STATE_CERTIFICATE_ITEM_COUNT: usize = 32;
const MAXIMUM_STATE_CERTIFICATE_CUMULATIVE_BYTE_LENGTH: usize = 256 * 1024;

pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_OPERATION_KIND: &str =
    "ballot-bivariate-private-row-receipt";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_KEY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-key";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_INTENT_DOMAIN: &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-reservation-intent";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_INTENT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-reservation-intent-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_WITNESS_BODY_DOMAIN: &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-reservation-witness-body";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_WITNESS_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-reservation-witness-envelope";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_CERTIFICATE_DOMAIN: &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-reservation-certificate";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_CERTIFICATE_IDENTITY_DOMAIN:
    &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-reservation-certificate-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_WITNESS_SIGNATURE_CONTEXT:
    &[u8] = b"sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-reservation-witness";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_INTENT_DOMAIN: &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-exact-output-intent";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_INTENT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-exact-output-intent-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_WITNESS_BODY_DOMAIN: &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-exact-output-witness-body";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_WITNESS_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-exact-output-witness-envelope";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_CERTIFICATE_DOMAIN: &str =
    "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-exact-output-certificate";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_CERTIFICATE_IDENTITY_DOMAIN:
    &str = "sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-exact-output-certificate-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT:
    &[u8] = b"sealed-lattice/v1/state/ballot-bivariate-private-row-receipt-exact-output-witness";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MaskedBallotBivariateReceiptStateError320 {
    Canonical(CanonicalCodecError),
    Receipt(MaskedBallotBivariateReceiptError320),
    ObjectMismatch {
        field: &'static str,
    },
    RosterMismatch,
    WitnessCount {
        expected: usize,
        actual: usize,
    },
    WitnessPositionOutOfRange {
        witness_roster_position: u16,
        participant_count: u16,
    },
    SubjectCannotWitness,
    WitnessOrder,
    MalformedSigningVerificationKey {
        witness_roster_position: u16,
    },
    InvalidWitnessSignature {
        witness_roster_position: u16,
    },
    IntegerConversion,
}

impl From<CanonicalCodecError> for MaskedBallotBivariateReceiptStateError320 {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<MaskedBallotBivariateReceiptError320> for MaskedBallotBivariateReceiptStateError320 {
    fn from(error: MaskedBallotBivariateReceiptError320) -> Self {
        Self::Receipt(error)
    }
}

impl fmt::Display for MaskedBallotBivariateReceiptStateError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => {
                write!(formatter, "canonical ballot-receipt state error: {error}")
            }
            Self::Receipt(error) => write!(formatter, "ballot-receipt state source error: {error}"),
            Self::ObjectMismatch { field } => {
                write!(formatter, "ballot-receipt state object has a wrong {field}")
            }
            Self::RosterMismatch => formatter
                .write_str("ballot-receipt state roster does not match the commitment layout"),
            Self::WitnessCount { expected, actual } => write!(
                formatter,
                "ballot-receipt state certificate has {actual} witnesses; expected {expected}"
            ),
            Self::WitnessPositionOutOfRange {
                witness_roster_position,
                participant_count,
            } => write!(
                formatter,
                "ballot-receipt state witness {witness_roster_position} is outside participant count {participant_count}"
            ),
            Self::SubjectCannotWitness => {
                formatter.write_str("a ballot-row holder cannot witness its own receipt state")
            }
            Self::WitnessOrder => formatter.write_str(
                "ballot-receipt state witnesses must be distinct and in ascending roster order",
            ),
            Self::MalformedSigningVerificationKey {
                witness_roster_position,
            } => write!(
                formatter,
                "ballot-receipt state witness {witness_roster_position} has a malformed ML-DSA-65 verification key"
            ),
            Self::InvalidWitnessSignature {
                witness_roster_position,
            } => write!(
                formatter,
                "ballot-receipt state witness {witness_roster_position} has an invalid ML-DSA-65 signature"
            ),
            Self::IntegerConversion => formatter
                .write_str("ballot-receipt state length does not fit its canonical integer"),
        }
    }
}

impl std::error::Error for MaskedBallotBivariateReceiptStateError320 {}

/// Alternative-independent conflict key for one holder's ballot-row receipt.
///
/// The preparation-record identity, root, manifest, and receipt body are
/// deliberately excluded. With one preparation attempt per action, all of
/// those competing values must contend for the same holder slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptStateKey320 {
    identity: Hash512,
}

impl MaskedBallotBivariateReceiptStateKey320 {
    pub(crate) fn derive(
        layout: MaskedBallotBivariateCommitmentLayout320,
        holder_roster_position: u16,
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        if holder_roster_position >= layout.participant_count() {
            return Err(state_object_mismatch("holder roster position"));
        }
        let identity = hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_KEY_IDENTITY_DOMAIN,
            &[
                CanonicalItem::hash512(layout.parameter_identity().into_bytes()),
                CanonicalItem::hash512(layout.preparation_context().identity().into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_OPERATION_KIND,
                )?,
                CanonicalItem::unsigned16(layout.author_roster_position()),
                CanonicalItem::unsigned16(holder_roster_position),
            ],
        )?;
        Ok(Self { identity })
    }

    pub(crate) const fn identity(self) -> Hash512 {
        self.identity
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptStateReservationIntent320 {
    participant_count: u16,
    subject_roster_position: u16,
    state_key_identity: Hash512,
    predecessor_identity: Hash512,
    receipt_body_identity: Hash512,
}

impl MaskedBallotBivariateReceiptStateReservationIntent320 {
    pub(crate) fn new(
        layout: MaskedBallotBivariateCommitmentLayout320,
        receipt_body: MaskedBallotBivariateReceiptBody320,
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        let subject_roster_position = receipt_body.holder_roster_position();
        Ok(Self {
            participant_count: layout.participant_count(),
            subject_roster_position,
            state_key_identity: MaskedBallotBivariateReceiptStateKey320::derive(
                layout,
                subject_roster_position,
            )?
            .identity(),
            predecessor_identity: layout.preparation_record_identity(),
            receipt_body_identity: receipt_body.identity()?,
        })
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn subject_roster_position(self) -> u16 {
        self.subject_roster_position
    }

    pub(crate) const fn state_key_identity(self) -> Hash512 {
        self.state_key_identity
    }

    pub(crate) const fn predecessor_identity(self) -> Hash512 {
        self.predecessor_identity
    }

    pub(crate) const fn receipt_body_identity(self) -> Hash512 {
        self.receipt_body_identity
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, MaskedBallotBivariateReceiptStateError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_INTENT_DOMAIN,
                )?,
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_OPERATION_KIND,
                )?,
                CanonicalItem::hash512(self.state_key_identity.into_bytes()),
                CanonicalItem::hash512(self.predecessor_identity.into_bytes()),
                CanonicalItem::hash512(self.receipt_body_identity.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub(crate) fn identity(self) -> Result<Hash512, MaskedBallotBivariateReceiptStateError320> {
        Ok(hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_INTENT_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn from_canonical_bytes(
        expected: Self,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        let tuple = CanonicalTuple::decode(bytes, &state_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_INTENT_DOMAIN,
            RESERVATION_INTENT_ITEM_COUNT,
        )?;
        require_ascii(
            &tuple.items[1],
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_OPERATION_KIND,
            "operation kind",
        )?;
        require_hash(
            &tuple.items[2],
            expected.state_key_identity,
            "state-key identity",
        )?;
        require_hash(
            &tuple.items[3],
            expected.predecessor_identity,
            "predecessor identity",
        )?;
        require_hash(
            &tuple.items[4],
            expected.receipt_body_identity,
            "receipt-body identity",
        )?;
        Ok(expected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptStateReservationWitnessAuthorizationBody320 {
    reservation_intent_identity: Hash512,
    witness_roster_position: u16,
}

impl MaskedBallotBivariateReceiptStateReservationWitnessAuthorizationBody320 {
    pub(crate) fn new(
        reservation_intent: MaskedBallotBivariateReceiptStateReservationIntent320,
        witness_roster_position: u16,
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        validate_reservation_witness_position(reservation_intent, witness_roster_position)?;
        Ok(Self {
            reservation_intent_identity: reservation_intent.identity()?,
            witness_roster_position,
        })
    }

    pub(crate) const fn witness_roster_position(self) -> u16 {
        self.witness_roster_position
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, MaskedBallotBivariateReceiptStateError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_WITNESS_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.reservation_intent_identity.into_bytes()),
                CanonicalItem::unsigned16(self.witness_roster_position),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_reservation_intent: MaskedBallotBivariateReceiptStateReservationIntent320,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        let tuple = CanonicalTuple::decode(bytes, &state_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_WITNESS_BODY_DOMAIN,
            WITNESS_AUTHORIZATION_BODY_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected_reservation_intent.identity()?,
            "reservation-intent identity",
        )?;
        Self::new(
            expected_reservation_intent,
            read_u16(&tuple.items[2], "witness roster position")?,
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320 {
    authorization_body: MaskedBallotBivariateReceiptStateReservationWitnessAuthorizationBody320,
    signature: [u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320 {
    pub(crate) const fn new(
        authorization_body: MaskedBallotBivariateReceiptStateReservationWitnessAuthorizationBody320,
        signature: [u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            authorization_body,
            signature,
        }
    }

    pub(crate) const fn authorization_body(
        &self,
    ) -> MaskedBallotBivariateReceiptStateReservationWitnessAuthorizationBody320 {
        self.authorization_body
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, MaskedBallotBivariateReceiptStateError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_WITNESS_ENVELOPE_DOMAIN,
                )?,
                CanonicalItem::variable_bytes(self.authorization_body.canonical_bytes()?)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_reservation_intent: MaskedBallotBivariateReceiptStateReservationIntent320,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        let tuple = CanonicalTuple::decode(bytes, &state_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_WITNESS_ENVELOPE_DOMAIN,
            WITNESS_ENVELOPE_ITEM_COUNT,
        )?;
        let authorization_body = MaskedBallotBivariateReceiptStateReservationWitnessAuthorizationBody320::from_canonical_bytes(
            expected_reservation_intent,
            read_variable_bytes(&tuple.items[1], "witness authorization body")?,
        )?;
        let signature = read_signature(&tuple.items[2], "witness signature")?;
        Ok(Self {
            authorization_body,
            signature,
        })
    }
}

impl fmt::Debug for MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320")
            .field("authorization_body", &self.authorization_body)
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptStateReservationCertificate320 {
    reservation_intent: MaskedBallotBivariateReceiptStateReservationIntent320,
    witness_envelopes: Box<[MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320]>,
}

impl MaskedBallotBivariateReceiptStateReservationCertificate320 {
    pub(crate) fn new(
        reservation_intent: MaskedBallotBivariateReceiptStateReservationIntent320,
        witness_envelopes: Vec<MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320>,
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        validate_reservation_witness_inventory(reservation_intent, &witness_envelopes)?;
        Ok(Self {
            reservation_intent,
            witness_envelopes: witness_envelopes.into_boxed_slice(),
        })
    }

    pub(crate) fn witness_envelopes(
        &self,
    ) -> &[MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320] {
        &self.witness_envelopes
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, MaskedBallotBivariateReceiptStateError320> {
        let mut items = Vec::with_capacity(
            RESERVATION_CERTIFICATE_PREFIX_ITEM_COUNT + self.witness_envelopes.len(),
        );
        items.push(CanonicalItem::nonempty_ascii(
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_CERTIFICATE_DOMAIN,
        )?);
        items.push(CanonicalItem::variable_bytes(
            self.reservation_intent.canonical_bytes()?,
        )?);
        for witness_envelope in &self.witness_envelopes {
            items.push(CanonicalItem::variable_bytes(
                witness_envelope.canonical_bytes()?,
            )?);
        }
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            items,
        )
        .encode()?)
    }

    pub(crate) fn identity(&self) -> Result<Hash512, MaskedBallotBivariateReceiptStateError320> {
        Ok(hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_CERTIFICATE_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn from_canonical_bytes(
        expected_reservation_intent: MaskedBallotBivariateReceiptStateReservationIntent320,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        let tuple = CanonicalTuple::decode(bytes, &state_certificate_decode_limits())?;
        let expected_witness_count =
            state_witness_count(expected_reservation_intent.participant_count())?;
        let expected_item_count = RESERVATION_CERTIFICATE_PREFIX_ITEM_COUNT
            .checked_add(expected_witness_count)
            .ok_or(MaskedBallotBivariateReceiptStateError320::IntegerConversion)?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_CERTIFICATE_DOMAIN,
            expected_item_count,
        )?;
        let reservation_intent =
            MaskedBallotBivariateReceiptStateReservationIntent320::from_canonical_bytes(
                expected_reservation_intent,
                read_variable_bytes(&tuple.items[1], "reservation intent")?,
            )?;
        let witness_envelopes = tuple.items[RESERVATION_CERTIFICATE_PREFIX_ITEM_COUNT..]
            .iter()
            .map(|item| {
                MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320::from_canonical_bytes(
                    reservation_intent,
                    read_variable_bytes(item, "witness envelope")?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(reservation_intent, witness_envelopes)
    }
}

impl fmt::Debug for MaskedBallotBivariateReceiptStateReservationCertificate320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateReceiptStateReservationCertificate320")
            .field("reservation_intent", &self.reservation_intent)
            .field("witness_count", &self.witness_envelopes.len())
            .field("witness_signatures", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedMaskedBallotBivariateReceiptStateReservation320 {
    layout: MaskedBallotBivariateCommitmentLayout320,
    receipt_body: MaskedBallotBivariateReceiptBody320,
    state_key_identity: Hash512,
    reservation_intent_identity: Hash512,
    reservation_certificate_identity: Hash512,
}

impl VerifiedMaskedBallotBivariateReceiptStateReservation320 {
    pub(crate) const fn layout(self) -> MaskedBallotBivariateCommitmentLayout320 {
        self.layout
    }

    pub(crate) const fn receipt_body(self) -> MaskedBallotBivariateReceiptBody320 {
        self.receipt_body
    }

    pub(crate) const fn state_key_identity(self) -> Hash512 {
        self.state_key_identity
    }

    pub(crate) const fn reservation_intent_identity(self) -> Hash512 {
        self.reservation_intent_identity
    }

    pub(crate) const fn reservation_certificate_identity(self) -> Hash512 {
        self.reservation_certificate_identity
    }
}

pub(crate) fn verify_masked_ballot_bivariate_receipt_state_reservation_320(
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    authenticated_manifest: &AuthorAuthenticatedMaskedBallotBivariateMailboxManifest320,
    roster: &Roster,
    holder_roster_position: u16,
    reservation_certificate_bytes: &[u8],
) -> Result<
    VerifiedMaskedBallotBivariateReceiptStateReservation320,
    MaskedBallotBivariateReceiptStateError320,
> {
    let layout = authenticated_root.root_body().layout();
    validate_roster(layout, roster)?;
    let receipt_body = MaskedBallotBivariateReceiptBody320::new(
        authenticated_root,
        authenticated_manifest,
        holder_roster_position,
    )?;
    let reservation_intent =
        MaskedBallotBivariateReceiptStateReservationIntent320::new(layout, receipt_body)?;
    let certificate =
        MaskedBallotBivariateReceiptStateReservationCertificate320::from_canonical_bytes(
            reservation_intent,
            reservation_certificate_bytes,
        )?;
    verify_reservation_witness_signatures(roster, certificate.witness_envelopes())?;
    Ok(VerifiedMaskedBallotBivariateReceiptStateReservation320 {
        layout,
        receipt_body,
        state_key_identity: reservation_intent.state_key_identity(),
        reservation_intent_identity: reservation_intent.identity()?,
        reservation_certificate_identity: certificate.identity()?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptStateOutputIntent320 {
    participant_count: u16,
    subject_roster_position: u16,
    state_key_identity: Hash512,
    reservation_certificate_identity: Hash512,
    operation_body_byte_length: u64,
    operation_body_identity: Hash512,
}

impl MaskedBallotBivariateReceiptStateOutputIntent320 {
    pub(crate) fn new(
        verified_reservation: VerifiedMaskedBallotBivariateReceiptStateReservation320,
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        let receipt_body = verified_reservation.receipt_body();
        let operation_body_byte_length = u64::try_from(receipt_body.canonical_bytes()?.len())
            .map_err(|_| MaskedBallotBivariateReceiptStateError320::IntegerConversion)?;
        Ok(Self {
            participant_count: verified_reservation.layout().participant_count(),
            subject_roster_position: receipt_body.holder_roster_position(),
            state_key_identity: verified_reservation.state_key_identity(),
            reservation_certificate_identity: verified_reservation
                .reservation_certificate_identity(),
            operation_body_byte_length,
            operation_body_identity: receipt_body.identity()?,
        })
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn subject_roster_position(self) -> u16 {
        self.subject_roster_position
    }

    pub(crate) const fn state_key_identity(self) -> Hash512 {
        self.state_key_identity
    }

    pub(crate) const fn reservation_certificate_identity(self) -> Hash512 {
        self.reservation_certificate_identity
    }

    pub(crate) const fn operation_body_byte_length(self) -> u64 {
        self.operation_body_byte_length
    }

    pub(crate) const fn operation_body_identity(self) -> Hash512 {
        self.operation_body_identity
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, MaskedBallotBivariateReceiptStateError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_INTENT_DOMAIN,
                )?,
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_OPERATION_KIND,
                )?,
                CanonicalItem::hash512(self.state_key_identity.into_bytes()),
                CanonicalItem::hash512(self.reservation_certificate_identity.into_bytes()),
                CanonicalItem::unsigned64(self.operation_body_byte_length),
                CanonicalItem::hash512(self.operation_body_identity.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub(crate) fn identity(self) -> Result<Hash512, MaskedBallotBivariateReceiptStateError320> {
        Ok(hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_INTENT_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn from_canonical_bytes(
        expected: Self,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        let tuple = CanonicalTuple::decode(bytes, &state_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_INTENT_DOMAIN,
            EXACT_OUTPUT_INTENT_ITEM_COUNT,
        )?;
        require_ascii(
            &tuple.items[1],
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_OPERATION_KIND,
            "operation kind",
        )?;
        require_hash(
            &tuple.items[2],
            expected.state_key_identity,
            "state-key identity",
        )?;
        require_hash(
            &tuple.items[3],
            expected.reservation_certificate_identity,
            "reservation-certificate identity",
        )?;
        require_u64(
            &tuple.items[4],
            expected.operation_body_byte_length,
            "operation-body byte length",
        )?;
        require_hash(
            &tuple.items[5],
            expected.operation_body_identity,
            "operation-body identity",
        )?;
        Ok(expected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptStateOutputWitnessAuthorizationBody320 {
    exact_output_intent_identity: Hash512,
    witness_roster_position: u16,
}

impl MaskedBallotBivariateReceiptStateOutputWitnessAuthorizationBody320 {
    pub(crate) fn new(
        exact_output_intent: MaskedBallotBivariateReceiptStateOutputIntent320,
        witness_roster_position: u16,
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        validate_output_witness_position(exact_output_intent, witness_roster_position)?;
        Ok(Self {
            exact_output_intent_identity: exact_output_intent.identity()?,
            witness_roster_position,
        })
    }

    pub(crate) const fn witness_roster_position(self) -> u16 {
        self.witness_roster_position
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, MaskedBallotBivariateReceiptStateError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_WITNESS_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.exact_output_intent_identity.into_bytes()),
                CanonicalItem::unsigned16(self.witness_roster_position),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_exact_output_intent: MaskedBallotBivariateReceiptStateOutputIntent320,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        let tuple = CanonicalTuple::decode(bytes, &state_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_WITNESS_BODY_DOMAIN,
            EXACT_OUTPUT_WITNESS_AUTHORIZATION_BODY_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected_exact_output_intent.identity()?,
            "exact-output-intent identity",
        )?;
        Self::new(
            expected_exact_output_intent,
            read_u16(&tuple.items[2], "witness roster position")?,
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320 {
    authorization_body: MaskedBallotBivariateReceiptStateOutputWitnessAuthorizationBody320,
    signature: [u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320 {
    pub(crate) const fn new(
        authorization_body: MaskedBallotBivariateReceiptStateOutputWitnessAuthorizationBody320,
        signature: [u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            authorization_body,
            signature,
        }
    }

    pub(crate) const fn authorization_body(
        &self,
    ) -> MaskedBallotBivariateReceiptStateOutputWitnessAuthorizationBody320 {
        self.authorization_body
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, MaskedBallotBivariateReceiptStateError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_WITNESS_ENVELOPE_DOMAIN,
                )?,
                CanonicalItem::variable_bytes(self.authorization_body.canonical_bytes()?)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_exact_output_intent: MaskedBallotBivariateReceiptStateOutputIntent320,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        let tuple = CanonicalTuple::decode(bytes, &state_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_WITNESS_ENVELOPE_DOMAIN,
            EXACT_OUTPUT_WITNESS_ENVELOPE_ITEM_COUNT,
        )?;
        let authorization_body = MaskedBallotBivariateReceiptStateOutputWitnessAuthorizationBody320::from_canonical_bytes(
            expected_exact_output_intent,
            read_variable_bytes(&tuple.items[1], "witness authorization body")?,
        )?;
        let signature = read_signature(&tuple.items[2], "witness signature")?;
        Ok(Self {
            authorization_body,
            signature,
        })
    }
}

impl fmt::Debug for MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320")
            .field("authorization_body", &self.authorization_body)
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateReceiptStateOutputCertificate320 {
    exact_output_intent: MaskedBallotBivariateReceiptStateOutputIntent320,
    witness_envelopes: Box<[MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320]>,
}

impl MaskedBallotBivariateReceiptStateOutputCertificate320 {
    pub(crate) fn new(
        exact_output_intent: MaskedBallotBivariateReceiptStateOutputIntent320,
        witness_envelopes: Vec<MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320>,
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        validate_output_witness_inventory(exact_output_intent, &witness_envelopes)?;
        Ok(Self {
            exact_output_intent,
            witness_envelopes: witness_envelopes.into_boxed_slice(),
        })
    }

    pub(crate) fn witness_envelopes(
        &self,
    ) -> &[MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320] {
        &self.witness_envelopes
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, MaskedBallotBivariateReceiptStateError320> {
        let mut items = Vec::with_capacity(
            EXACT_OUTPUT_CERTIFICATE_PREFIX_ITEM_COUNT + self.witness_envelopes.len(),
        );
        items.push(CanonicalItem::nonempty_ascii(
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_CERTIFICATE_DOMAIN,
        )?);
        items.push(CanonicalItem::variable_bytes(
            self.exact_output_intent.canonical_bytes()?,
        )?);
        for witness_envelope in &self.witness_envelopes {
            items.push(CanonicalItem::variable_bytes(
                witness_envelope.canonical_bytes()?,
            )?);
        }
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            items,
        )
        .encode()?)
    }

    pub(crate) fn identity(&self) -> Result<Hash512, MaskedBallotBivariateReceiptStateError320> {
        Ok(hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_CERTIFICATE_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn from_canonical_bytes(
        expected_exact_output_intent: MaskedBallotBivariateReceiptStateOutputIntent320,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateReceiptStateError320> {
        let tuple = CanonicalTuple::decode(bytes, &state_certificate_decode_limits())?;
        let expected_witness_count =
            state_witness_count(expected_exact_output_intent.participant_count())?;
        let expected_item_count = EXACT_OUTPUT_CERTIFICATE_PREFIX_ITEM_COUNT
            .checked_add(expected_witness_count)
            .ok_or(MaskedBallotBivariateReceiptStateError320::IntegerConversion)?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_CERTIFICATE_DOMAIN,
            expected_item_count,
        )?;
        let exact_output_intent =
            MaskedBallotBivariateReceiptStateOutputIntent320::from_canonical_bytes(
                expected_exact_output_intent,
                read_variable_bytes(&tuple.items[1], "exact-output intent")?,
            )?;
        let witness_envelopes = tuple.items[EXACT_OUTPUT_CERTIFICATE_PREFIX_ITEM_COUNT..]
            .iter()
            .map(|item| {
                MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320::from_canonical_bytes(
                    exact_output_intent,
                    read_variable_bytes(item, "witness envelope")?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(exact_output_intent, witness_envelopes)
    }
}

impl fmt::Debug for MaskedBallotBivariateReceiptStateOutputCertificate320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateReceiptStateOutputCertificate320")
            .field("exact_output_intent", &self.exact_output_intent)
            .field("witness_count", &self.witness_envelopes.len())
            .field("witness_signatures", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedMaskedBallotBivariateReceiptStateOutput320 {
    layout: MaskedBallotBivariateCommitmentLayout320,
    receipt_body: MaskedBallotBivariateReceiptBody320,
    state_key_identity: Hash512,
    reservation_certificate_identity: Hash512,
    exact_output_intent_identity: Hash512,
    exact_output_certificate_identity: Hash512,
}

impl VerifiedMaskedBallotBivariateReceiptStateOutput320 {
    pub(crate) const fn layout(self) -> MaskedBallotBivariateCommitmentLayout320 {
        self.layout
    }

    pub(crate) const fn receipt_body(self) -> MaskedBallotBivariateReceiptBody320 {
        self.receipt_body
    }

    pub(crate) const fn state_key_identity(self) -> Hash512 {
        self.state_key_identity
    }

    pub(crate) const fn reservation_certificate_identity(self) -> Hash512 {
        self.reservation_certificate_identity
    }

    pub(crate) const fn exact_output_intent_identity(self) -> Hash512 {
        self.exact_output_intent_identity
    }

    pub(crate) const fn exact_output_certificate_identity(self) -> Hash512 {
        self.exact_output_certificate_identity
    }
}

pub(crate) fn verify_masked_ballot_bivariate_receipt_state_output_320(
    verified_reservation: VerifiedMaskedBallotBivariateReceiptStateReservation320,
    roster: &Roster,
    exact_output_certificate_bytes: &[u8],
) -> Result<
    VerifiedMaskedBallotBivariateReceiptStateOutput320,
    MaskedBallotBivariateReceiptStateError320,
> {
    validate_roster(verified_reservation.layout(), roster)?;
    let exact_output_intent =
        MaskedBallotBivariateReceiptStateOutputIntent320::new(verified_reservation)?;
    let certificate = MaskedBallotBivariateReceiptStateOutputCertificate320::from_canonical_bytes(
        exact_output_intent,
        exact_output_certificate_bytes,
    )?;
    verify_output_witness_signatures(roster, certificate.witness_envelopes())?;
    Ok(VerifiedMaskedBallotBivariateReceiptStateOutput320 {
        layout: verified_reservation.layout(),
        receipt_body: verified_reservation.receipt_body(),
        state_key_identity: exact_output_intent.state_key_identity(),
        reservation_certificate_identity: exact_output_intent.reservation_certificate_identity(),
        exact_output_intent_identity: exact_output_intent.identity()?,
        exact_output_certificate_identity: certificate.identity()?,
    })
}

fn verify_reservation_witness_signatures(
    roster: &Roster,
    witness_envelopes: &[MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320],
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    for witness_envelope in witness_envelopes {
        verify_witness_signature(
            roster,
            witness_envelope
                .authorization_body()
                .witness_roster_position(),
            &witness_envelope.authorization_body().canonical_bytes()?,
            &witness_envelope.signature,
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_RESERVATION_WITNESS_SIGNATURE_CONTEXT,
        )?;
    }
    Ok(())
}

fn verify_output_witness_signatures(
    roster: &Roster,
    witness_envelopes: &[MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320],
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    for witness_envelope in witness_envelopes {
        verify_witness_signature(
            roster,
            witness_envelope
                .authorization_body()
                .witness_roster_position(),
            &witness_envelope.authorization_body().canonical_bytes()?,
            &witness_envelope.signature,
            MASKED_BALLOT_BIVARIATE_RECEIPT_STATE_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
        )?;
    }
    Ok(())
}

fn verify_witness_signature(
    roster: &Roster,
    witness_roster_position: u16,
    message: &[u8],
    signature: &[u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    signature_context: &[u8],
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    let roster_entry = roster
        .entries
        .get(usize::from(witness_roster_position))
        .filter(|entry| entry.roster_position == witness_roster_position)
        .ok_or(MaskedBallotBivariateReceiptStateError320::RosterMismatch)?;
    let verification_key =
        ml_dsa_65::PublicKey::try_from_bytes(roster_entry.signing_verification_key).map_err(
            |_| MaskedBallotBivariateReceiptStateError320::MalformedSigningVerificationKey {
                witness_roster_position,
            },
        )?;
    if !verification_key.verify(message, signature, signature_context) {
        return Err(
            MaskedBallotBivariateReceiptStateError320::InvalidWitnessSignature {
                witness_roster_position,
            },
        );
    }
    Ok(())
}

fn validate_reservation_witness_inventory(
    reservation_intent: MaskedBallotBivariateReceiptStateReservationIntent320,
    witness_envelopes: &[MaskedBallotBivariateReceiptStateReservationWitnessEnvelope320],
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    let expected_witness_count = state_witness_count(reservation_intent.participant_count())?;
    if witness_envelopes.len() != expected_witness_count {
        return Err(MaskedBallotBivariateReceiptStateError320::WitnessCount {
            expected: expected_witness_count,
            actual: witness_envelopes.len(),
        });
    }
    let expected_intent_identity = reservation_intent.identity()?;
    let mut preceding_witness_position = None;
    for witness_envelope in witness_envelopes {
        let authorization_body = witness_envelope.authorization_body();
        if authorization_body.reservation_intent_identity != expected_intent_identity {
            return Err(state_object_mismatch("reservation-intent identity"));
        }
        let witness_roster_position = authorization_body.witness_roster_position();
        validate_reservation_witness_position(reservation_intent, witness_roster_position)?;
        if preceding_witness_position.is_some_and(|preceding| preceding >= witness_roster_position)
        {
            return Err(MaskedBallotBivariateReceiptStateError320::WitnessOrder);
        }
        preceding_witness_position = Some(witness_roster_position);
    }
    Ok(())
}

fn validate_output_witness_inventory(
    exact_output_intent: MaskedBallotBivariateReceiptStateOutputIntent320,
    witness_envelopes: &[MaskedBallotBivariateReceiptStateOutputWitnessEnvelope320],
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    let expected_witness_count = state_witness_count(exact_output_intent.participant_count())?;
    if witness_envelopes.len() != expected_witness_count {
        return Err(MaskedBallotBivariateReceiptStateError320::WitnessCount {
            expected: expected_witness_count,
            actual: witness_envelopes.len(),
        });
    }
    let expected_intent_identity = exact_output_intent.identity()?;
    let mut preceding_witness_position = None;
    for witness_envelope in witness_envelopes {
        let authorization_body = witness_envelope.authorization_body();
        if authorization_body.exact_output_intent_identity != expected_intent_identity {
            return Err(state_object_mismatch("exact-output-intent identity"));
        }
        let witness_roster_position = authorization_body.witness_roster_position();
        validate_output_witness_position(exact_output_intent, witness_roster_position)?;
        if preceding_witness_position.is_some_and(|preceding| preceding >= witness_roster_position)
        {
            return Err(MaskedBallotBivariateReceiptStateError320::WitnessOrder);
        }
        preceding_witness_position = Some(witness_roster_position);
    }
    Ok(())
}

fn validate_reservation_witness_position(
    reservation_intent: MaskedBallotBivariateReceiptStateReservationIntent320,
    witness_roster_position: u16,
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    validate_witness_position(
        reservation_intent.participant_count(),
        reservation_intent.subject_roster_position(),
        witness_roster_position,
    )
}

fn validate_output_witness_position(
    exact_output_intent: MaskedBallotBivariateReceiptStateOutputIntent320,
    witness_roster_position: u16,
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    validate_witness_position(
        exact_output_intent.participant_count(),
        exact_output_intent.subject_roster_position(),
        witness_roster_position,
    )
}

fn validate_witness_position(
    participant_count: u16,
    subject_roster_position: u16,
    witness_roster_position: u16,
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    if witness_roster_position >= participant_count {
        return Err(
            MaskedBallotBivariateReceiptStateError320::WitnessPositionOutOfRange {
                witness_roster_position,
                participant_count,
            },
        );
    }
    if witness_roster_position == subject_roster_position {
        return Err(MaskedBallotBivariateReceiptStateError320::SubjectCannotWitness);
    }
    Ok(())
}

fn state_witness_count(
    participant_count: u16,
) -> Result<usize, MaskedBallotBivariateReceiptStateError320> {
    derive_foundation_roster_parameters(participant_count)
        .map(|parameters| usize::from(parameters.state_witness_quorum))
        .ok_or(MaskedBallotBivariateReceiptStateError320::RosterMismatch)
}

fn validate_roster(
    layout: MaskedBallotBivariateCommitmentLayout320,
    roster: &Roster,
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    roster
        .validate()
        .map_err(|_| MaskedBallotBivariateReceiptStateError320::RosterMismatch)?;
    if roster.entries.len() != usize::from(layout.participant_count())
        || roster
            .roster_hash()
            .map_err(|_| MaskedBallotBivariateReceiptStateError320::RosterMismatch)?
            != layout.preparation_context().roster_hash()
    {
        return Err(MaskedBallotBivariateReceiptStateError320::RosterMismatch);
    }
    Ok(())
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(state_object_mismatch("schema identifier"));
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(state_object_mismatch("schema version"));
    }
    if tuple.items.len() != expected_item_count {
        return Err(state_object_mismatch("item count"));
    }
    require_ascii(&tuple.items[0], expected_domain, "object domain")
}

fn require_ascii(
    item: &CanonicalItem,
    expected: &str,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    if item.item_type() != CanonicalItemType::Ascii
        || item.variable_value_bytes()? != expected.as_bytes()
    {
        return Err(state_object_mismatch(field));
    }
    Ok(())
}

fn read_variable_bytes<'a>(
    item: &'a CanonicalItem,
    field: &'static str,
) -> Result<&'a [u8], MaskedBallotBivariateReceiptStateError320> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(state_object_mismatch(field));
    }
    Ok(item.variable_value_bytes()?)
}

fn read_signature(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<
    [u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    MaskedBallotBivariateReceiptStateError320,
> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(state_object_mismatch(field));
    }
    item.canonical_bytes()
        .try_into()
        .map_err(|_| state_object_mismatch(field))
}

fn require_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    if item.item_type() != CanonicalItemType::Hash512
        || item.canonical_bytes() != expected.as_bytes()
    {
        return Err(state_object_mismatch(field));
    }
    Ok(())
}

fn read_u16(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u16, MaskedBallotBivariateReceiptStateError320> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(state_object_mismatch(field));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| state_object_mismatch(field))?;
    Ok(u16::from_le_bytes(bytes))
}

fn require_u64(
    item: &CanonicalItem,
    expected: u64,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateReceiptStateError320> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(state_object_mismatch(field));
    }
    let bytes: [u8; 8] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| state_object_mismatch(field))?;
    if u64::from_le_bytes(bytes) != expected {
        return Err(state_object_mismatch(field));
    }
    Ok(())
}

const fn state_object_mismatch(field: &'static str) -> MaskedBallotBivariateReceiptStateError320 {
    MaskedBallotBivariateReceiptStateError320::ObjectMismatch { field }
}

fn state_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_STATE_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: 16,
        maximum_item_byte_length: MAXIMUM_STATE_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: 32 * 1024,
        maximum_cumulative_allocation_byte_length: 32 * 1024,
    }
}

fn state_certificate_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_STATE_CERTIFICATE_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_STATE_CERTIFICATE_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_STATE_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_STATE_CERTIFICATE_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length: MAXIMUM_STATE_CERTIFICATE_CUMULATIVE_BYTE_LENGTH,
    }
}

const _: () = assert!(MASKED_BALLOT_BIVARIATE_RECEIPT_BODY_BYTE_LENGTH == 311);
const _: () = assert!(MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH == ml_dsa_65::SIG_LEN);
