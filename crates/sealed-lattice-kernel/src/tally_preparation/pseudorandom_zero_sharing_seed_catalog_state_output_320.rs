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
    TallyPreparationError,
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogLayout320, PseudorandomZeroSharingSeedCatalogRootBody320,
    },
    pseudorandom_zero_sharing_seed_catalog_signature_320::{
        ML_DSA_65_SIGNATURE_BYTE_LENGTH, PseudorandomZeroSharingSeedCatalogSignatureError,
        verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320,
    },
    pseudorandom_zero_sharing_seed_catalog_state_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_OPERATION_KIND,
        PseudorandomZeroSharingSeedCatalogStateError,
        VerifiedPseudorandomZeroSharingSeedCatalogRootStateReservation320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320,
    },
};

const EXACT_OUTPUT_INTENT_ITEM_COUNT: usize = 6;
const EXACT_OUTPUT_WITNESS_AUTHORIZATION_BODY_ITEM_COUNT: usize = 3;
const EXACT_OUTPUT_WITNESS_ENVELOPE_ITEM_COUNT: usize = 3;
const EXACT_OUTPUT_CERTIFICATE_PREFIX_ITEM_COUNT: usize = 2;
const MAXIMUM_EXACT_OUTPUT_CONTROL_OBJECT_BYTE_LENGTH: usize = 131_072;
const MAXIMUM_EXACT_OUTPUT_CONTROL_OBJECT_ITEM_COUNT: usize = 32;
const MAXIMUM_EXACT_OUTPUT_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 8_192;
const MAXIMUM_EXACT_OUTPUT_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 262_144;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_INTENT_DOMAIN: &str =
    "sealed-lattice/v1/state/seed-catalog-root-exact-output-intent";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_INTENT_IDENTITY_DOMAIN:
    &str = "sealed-lattice/v1/state/seed-catalog-root-exact-output-intent-identity";
pub(crate) const
    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_AUTHORIZATION_BODY_DOMAIN:
    &str = "sealed-lattice/v1/state/seed-catalog-root-exact-output-witness-body";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_ENVELOPE_DOMAIN:
    &str = "sealed-lattice/v1/state/seed-catalog-root-exact-output-witness-envelope";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_CERTIFICATE_DOMAIN: &str =
    "sealed-lattice/v1/state/seed-catalog-root-exact-output-certificate";
pub(crate) const
    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_CERTIFICATE_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/state/seed-catalog-root-exact-output-certificate-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT:
    &[u8] = b"sealed-lattice/v1/state/seed-catalog-root-exact-output-witness";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedCatalogStateOutputError {
    Canonical(CanonicalCodecError),
    Preparation(TallyPreparationError),
    Reservation(PseudorandomZeroSharingSeedCatalogStateError),
    RootSignature(PseudorandomZeroSharingSeedCatalogSignatureError),
    ObjectMismatch {
        field: &'static str,
    },
    RosterMismatch,
    WitnessCount {
        expected: usize,
        actual: usize,
    },
    WitnessPositionOutOfRange {
        witness_position: u16,
        participant_count: u16,
    },
    SubjectCannotWitness,
    WitnessOrder,
    MalformedSigningVerificationKey {
        witness_position: u16,
    },
    InvalidWitnessSignature {
        witness_position: u16,
    },
    IntegerConversion,
}

impl From<CanonicalCodecError> for PseudorandomZeroSharingSeedCatalogStateOutputError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<TallyPreparationError> for PseudorandomZeroSharingSeedCatalogStateOutputError {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<PseudorandomZeroSharingSeedCatalogStateError>
    for PseudorandomZeroSharingSeedCatalogStateOutputError
{
    fn from(error: PseudorandomZeroSharingSeedCatalogStateError) -> Self {
        Self::Reservation(error)
    }
}

impl From<PseudorandomZeroSharingSeedCatalogSignatureError>
    for PseudorandomZeroSharingSeedCatalogStateOutputError
{
    fn from(error: PseudorandomZeroSharingSeedCatalogSignatureError) -> Self {
        Self::RootSignature(error)
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedCatalogStateOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => {
                write!(formatter, "canonical seed-catalog state-output error: {error}")
            }
            Self::Preparation(error) => {
                write!(formatter, "seed-catalog state-output preparation error: {error}")
            }
            Self::Reservation(error) => {
                write!(formatter, "seed-catalog state-reservation error: {error}")
            }
            Self::RootSignature(error) => {
                write!(formatter, "seed-catalog root signature error: {error}")
            }
            Self::ObjectMismatch { field } => {
                write!(formatter, "seed-catalog state-output object has a wrong {field}")
            }
            Self::RosterMismatch => formatter.write_str(
                "seed-catalog state-output roster does not match the expected preparation context",
            ),
            Self::WitnessCount { expected, actual } => write!(
                formatter,
                "seed-catalog state-output certificate has {actual} witnesses; expected {expected}"
            ),
            Self::WitnessPositionOutOfRange {
                witness_position,
                participant_count,
            } => write!(
                formatter,
                "seed-catalog state-output witness {witness_position} is outside participant count {participant_count}"
            ),
            Self::SubjectCannotWitness => formatter.write_str(
                "a seed-catalog root contributor cannot witness its own exact output",
            ),
            Self::WitnessOrder => formatter.write_str(
                "seed-catalog state-output witnesses must be distinct and in ascending roster order",
            ),
            Self::MalformedSigningVerificationKey { witness_position } => write!(
                formatter,
                "seed-catalog state-output witness {witness_position} has a malformed ML-DSA-65 verification key"
            ),
            Self::InvalidWitnessSignature { witness_position } => write!(
                formatter,
                "seed-catalog state-output witness {witness_position} has an invalid ML-DSA-65 signature"
            ),
            Self::IntegerConversion => formatter
                .write_str("seed-catalog exact-output length does not fit its canonical integer"),
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedCatalogStateOutputError {}

/// Exact root bytes bound after the first state reservation has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320 {
    participant_count: u16,
    subject_position: u16,
    state_key_identity: Hash512,
    reservation_certificate_identity: Hash512,
    operation_body_byte_length: u64,
    operation_body_identity: Hash512,
}

impl PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320 {
    pub(crate) fn new(
        verified_reservation: VerifiedPseudorandomZeroSharingSeedCatalogRootStateReservation320,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        let root_body = verified_reservation.root_body();
        let layout = root_body.layout();
        let operation_body_byte_length = u64::try_from(root_body.canonical_bytes()?.len())
            .map_err(|_| PseudorandomZeroSharingSeedCatalogStateOutputError::IntegerConversion)?;
        Ok(Self {
            participant_count: layout.participant_count(),
            subject_position: layout.contributor_position(),
            state_key_identity: verified_reservation.state_key_identity(),
            reservation_certificate_identity: verified_reservation.state_certificate_identity(),
            operation_body_byte_length,
            operation_body_identity: root_body.identity()?,
        })
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn subject_position(self) -> u16 {
        self.subject_position
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
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_INTENT_DOMAIN,
                )?,
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_OPERATION_KIND,
                )?,
                CanonicalItem::hash512(self.state_key_identity.into_bytes()),
                CanonicalItem::hash512(self.reservation_certificate_identity.into_bytes()),
                CanonicalItem::unsigned64(self.operation_body_byte_length),
                CanonicalItem::hash512(self.operation_body_identity.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub(crate) fn identity(
        self,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_INTENT_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn from_canonical_bytes(
        verified_reservation: VerifiedPseudorandomZeroSharingSeedCatalogRootStateReservation320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        let expected = Self::new(verified_reservation)?;
        let tuple = CanonicalTuple::decode(bytes, &exact_output_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_INTENT_DOMAIN,
            EXACT_OUTPUT_INTENT_ITEM_COUNT,
        )?;
        require_ascii(
            &tuple.items[1],
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_OPERATION_KIND,
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
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320 {
    exact_output_intent_identity: Hash512,
    witness_position: u16,
}

impl PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320 {
    pub(crate) fn new(
        exact_output_intent: PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
        witness_position: u16,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        validate_witness_position(exact_output_intent, witness_position)?;
        Ok(Self {
            exact_output_intent_identity: exact_output_intent.identity()?,
            witness_position,
        })
    }

    pub(crate) const fn witness_position(self) -> u16 {
        self.witness_position
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_AUTHORIZATION_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.exact_output_intent_identity.into_bytes()),
                CanonicalItem::unsigned16(self.witness_position),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_exact_output_intent: PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        let tuple = CanonicalTuple::decode(bytes, &exact_output_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_AUTHORIZATION_BODY_DOMAIN,
            EXACT_OUTPUT_WITNESS_AUTHORIZATION_BODY_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected_exact_output_intent.identity()?,
            "exact-output-intent identity",
        )?;
        Self::new(
            expected_exact_output_intent,
            read_u16(&tuple.items[2], "witness position")?,
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320 {
    authorization_body:
        PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320 {
    pub(crate) const fn new(
        authorization_body: PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320,
        signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            authorization_body,
            signature,
        }
    }

    pub(crate) const fn authorization_body(
        &self,
    ) -> PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320 {
        self.authorization_body
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_ENVELOPE_DOMAIN,
                )?,
                CanonicalItem::variable_bytes(self.authorization_body.canonical_bytes()?)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_exact_output_intent: PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        let tuple = CanonicalTuple::decode(bytes, &exact_output_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_ENVELOPE_DOMAIN,
            EXACT_OUTPUT_WITNESS_ENVELOPE_ITEM_COUNT,
        )?;
        let authorization_body =
            PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320::from_canonical_bytes(
                expected_exact_output_intent,
                read_variable_bytes(&tuple.items[1], "exact-output witness authorization body")?,
            )?;
        if tuple.items[2].item_type() != CanonicalItemType::RawBytes {
            return Err(state_output_object_mismatch("witness signature"));
        }
        let signature =
            <[u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH]>::try_from(tuple.items[2].canonical_bytes())
                .map_err(|_| state_output_object_mismatch("witness signature byte length"))?;
        Ok(Self {
            authorization_body,
            signature,
        })
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320")
            .field("authorization_body", &self.authorization_body)
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320 {
    exact_output_intent: PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
    witness_envelopes: Box<[PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320]>,
}

impl PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320 {
    pub(crate) fn new(
        exact_output_intent: PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
        witness_envelopes: Vec<PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320>,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        validate_witness_inventory(exact_output_intent, &witness_envelopes)?;
        Ok(Self {
            exact_output_intent,
            witness_envelopes: witness_envelopes.into_boxed_slice(),
        })
    }

    pub(crate) fn witness_envelopes(
        &self,
    ) -> &[PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320] {
        &self.witness_envelopes
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        let mut items = Vec::with_capacity(
            EXACT_OUTPUT_CERTIFICATE_PREFIX_ITEM_COUNT + self.witness_envelopes.len(),
        );
        items.push(CanonicalItem::nonempty_ascii(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_CERTIFICATE_DOMAIN,
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

    pub(crate) fn identity(
        &self,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_CERTIFICATE_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn from_canonical_bytes(
        verified_reservation: VerifiedPseudorandomZeroSharingSeedCatalogRootStateReservation320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateOutputError> {
        let expected_exact_output_intent =
            PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320::new(verified_reservation)?;
        let tuple = CanonicalTuple::decode(bytes, &exact_output_certificate_decode_limits())?;
        let roster_parameters =
            derive_foundation_roster_parameters(expected_exact_output_intent.participant_count())
                .ok_or(PseudorandomZeroSharingSeedCatalogStateOutputError::RosterMismatch)?;
        let expected_witness_count = usize::from(roster_parameters.state_witness_quorum);
        let expected_item_count = EXACT_OUTPUT_CERTIFICATE_PREFIX_ITEM_COUNT
            .checked_add(expected_witness_count)
            .ok_or(
                PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessCount {
                    expected: expected_witness_count,
                    actual: tuple.items.len(),
                },
            )?;
        if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
            return Err(state_output_object_mismatch("schema identifier"));
        }
        if tuple.schema_version != CANONICAL_TUPLE_VERSION {
            return Err(state_output_object_mismatch("schema version"));
        }
        if tuple.items.len() != expected_item_count {
            return Err(
                PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessCount {
                    expected: expected_witness_count,
                    actual: tuple
                        .items
                        .len()
                        .saturating_sub(EXACT_OUTPUT_CERTIFICATE_PREFIX_ITEM_COUNT),
                },
            );
        }
        require_ascii(
            &tuple.items[0],
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_CERTIFICATE_DOMAIN,
            "object domain",
        )?;
        let exact_output_intent =
            PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320::from_canonical_bytes(
                verified_reservation,
                read_variable_bytes(&tuple.items[1], "exact-output intent")?,
            )?;
        let witness_envelopes = tuple.items[EXACT_OUTPUT_CERTIFICATE_PREFIX_ITEM_COUNT..]
            .iter()
            .map(|item| {
                PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320::from_canonical_bytes(
                    exact_output_intent,
                    read_variable_bytes(item, "exact-output witness envelope")?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(exact_output_intent, witness_envelopes)
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320")
            .field("exact_output_intent", &self.exact_output_intent)
            .field("witness_count", &self.witness_envelopes.len())
            .field("witness_signatures", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedPseudorandomZeroSharingSeedCatalogRootStateOutput320 {
    root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
    state_key_identity: Hash512,
    reservation_certificate_identity: Hash512,
    exact_output_intent_identity: Hash512,
    exact_output_certificate_identity: Hash512,
}

impl VerifiedPseudorandomZeroSharingSeedCatalogRootStateOutput320 {
    pub(crate) const fn root_body(self) -> PseudorandomZeroSharingSeedCatalogRootBody320 {
        self.root_body
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

/// One root with both state slots and the contributor's final signature
/// positively verified. A later owner must still verify the all-roster root
/// inventory before this can become a private-delivery predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StateAndRosterAuthorizedPseudorandomZeroSharingSeedCatalogRoot320 {
    root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
    state_key_identity: Hash512,
    reservation_certificate_identity: Hash512,
    exact_output_certificate_identity: Hash512,
}

impl StateAndRosterAuthorizedPseudorandomZeroSharingSeedCatalogRoot320 {
    pub(crate) const fn root_body(self) -> PseudorandomZeroSharingSeedCatalogRootBody320 {
        self.root_body
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
}

pub(crate) fn verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
    verified_reservation: VerifiedPseudorandomZeroSharingSeedCatalogRootStateReservation320,
    roster: &Roster,
    exact_output_certificate_bytes: &[u8],
) -> Result<
    VerifiedPseudorandomZeroSharingSeedCatalogRootStateOutput320,
    PseudorandomZeroSharingSeedCatalogStateOutputError,
> {
    let root_body = verified_reservation.root_body();
    let layout = root_body.layout();
    validate_roster(layout, roster)?;
    let exact_output_intent =
        PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320::new(verified_reservation)?;
    let certificate =
        PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320::from_canonical_bytes(
            verified_reservation,
            exact_output_certificate_bytes,
        )?;
    for witness_envelope in certificate.witness_envelopes() {
        let witness_position = witness_envelope.authorization_body().witness_position();
        let roster_entry = roster.entries.get(usize::from(witness_position)).ok_or(
            PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessPositionOutOfRange {
                witness_position,
                participant_count: layout.participant_count(),
            },
        )?;
        if roster_entry.roster_position != witness_position {
            return Err(PseudorandomZeroSharingSeedCatalogStateOutputError::RosterMismatch);
        }
        let public_key = ml_dsa_65::PublicKey::try_from_bytes(
            roster_entry.signing_verification_key,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedCatalogStateOutputError::MalformedSigningVerificationKey {
                witness_position,
            }
        })?;
        if !public_key.verify(
            &witness_envelope.authorization_body().canonical_bytes()?,
            &witness_envelope.signature,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
        ) {
            return Err(
                PseudorandomZeroSharingSeedCatalogStateOutputError::InvalidWitnessSignature {
                    witness_position,
                },
            );
        }
    }
    Ok(
        VerifiedPseudorandomZeroSharingSeedCatalogRootStateOutput320 {
            root_body,
            state_key_identity: exact_output_intent.state_key_identity(),
            reservation_certificate_identity: exact_output_intent
                .reservation_certificate_identity(),
            exact_output_intent_identity: exact_output_intent.identity()?,
            exact_output_certificate_identity: certificate.identity()?,
        },
    )
}

pub(crate) fn verify_state_and_roster_authorized_pseudorandom_zero_sharing_seed_catalog_root_320(
    expected_layout: PseudorandomZeroSharingSeedCatalogLayout320,
    root_body_bytes: &[u8],
    roster: &Roster,
    reservation_certificate_bytes: &[u8],
    exact_output_certificate_bytes: &[u8],
    contributor_signature_envelope_bytes: &[u8],
) -> Result<
    StateAndRosterAuthorizedPseudorandomZeroSharingSeedCatalogRoot320,
    PseudorandomZeroSharingSeedCatalogStateOutputError,
> {
    let verified_reservation =
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            expected_layout,
            root_body_bytes,
            roster,
            reservation_certificate_bytes,
        )?;
    let verified_state_output =
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_output_320(
            verified_reservation,
            roster,
            exact_output_certificate_bytes,
        )?;
    verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
        expected_layout,
        root_body_bytes,
        verified_state_output.exact_output_certificate_identity(),
        roster,
        contributor_signature_envelope_bytes,
    )?;
    Ok(
        StateAndRosterAuthorizedPseudorandomZeroSharingSeedCatalogRoot320 {
            root_body: verified_state_output.root_body(),
            state_key_identity: verified_state_output.state_key_identity(),
            reservation_certificate_identity: verified_state_output
                .reservation_certificate_identity(),
            exact_output_certificate_identity: verified_state_output
                .exact_output_certificate_identity(),
        },
    )
}

fn validate_roster(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    roster: &Roster,
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateOutputError> {
    roster
        .validate()
        .map_err(|_| PseudorandomZeroSharingSeedCatalogStateOutputError::RosterMismatch)?;
    if roster.entries.len() != usize::from(layout.participant_count())
        || roster
            .roster_hash()
            .map_err(|_| PseudorandomZeroSharingSeedCatalogStateOutputError::RosterMismatch)?
            != layout.preparation_context().roster_hash()
    {
        return Err(PseudorandomZeroSharingSeedCatalogStateOutputError::RosterMismatch);
    }
    Ok(())
}

fn validate_witness_inventory(
    exact_output_intent: PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
    witness_envelopes: &[PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320],
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateOutputError> {
    let roster_parameters =
        derive_foundation_roster_parameters(exact_output_intent.participant_count())
            .ok_or(PseudorandomZeroSharingSeedCatalogStateOutputError::RosterMismatch)?;
    let expected_witness_count = usize::from(roster_parameters.state_witness_quorum);
    if witness_envelopes.len() != expected_witness_count {
        return Err(
            PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessCount {
                expected: expected_witness_count,
                actual: witness_envelopes.len(),
            },
        );
    }
    let expected_intent_identity = exact_output_intent.identity()?;
    let mut preceding_witness_position = None;
    for witness_envelope in witness_envelopes {
        let authorization_body = witness_envelope.authorization_body();
        if authorization_body.exact_output_intent_identity != expected_intent_identity {
            return Err(state_output_object_mismatch("exact-output-intent identity"));
        }
        let witness_position = authorization_body.witness_position();
        validate_witness_position(exact_output_intent, witness_position)?;
        if preceding_witness_position.is_some_and(|preceding| preceding >= witness_position) {
            return Err(PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessOrder);
        }
        preceding_witness_position = Some(witness_position);
    }
    Ok(())
}

fn validate_witness_position(
    exact_output_intent: PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
    witness_position: u16,
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateOutputError> {
    if witness_position >= exact_output_intent.participant_count() {
        return Err(
            PseudorandomZeroSharingSeedCatalogStateOutputError::WitnessPositionOutOfRange {
                witness_position,
                participant_count: exact_output_intent.participant_count(),
            },
        );
    }
    if witness_position == exact_output_intent.subject_position() {
        return Err(PseudorandomZeroSharingSeedCatalogStateOutputError::SubjectCannotWitness);
    }
    Ok(())
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateOutputError> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(state_output_object_mismatch("schema identifier"));
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(state_output_object_mismatch("schema version"));
    }
    if tuple.items.len() != expected_item_count {
        return Err(state_output_object_mismatch("item count"));
    }
    require_ascii(&tuple.items[0], expected_domain, "object domain")
}

fn require_ascii(
    item: &CanonicalItem,
    expected: &str,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateOutputError> {
    if item.item_type() != CanonicalItemType::Ascii
        || item.variable_value_bytes()? != expected.as_bytes()
    {
        return Err(state_output_object_mismatch(field));
    }
    Ok(())
}

fn read_variable_bytes<'a>(
    item: &'a CanonicalItem,
    field: &'static str,
) -> Result<&'a [u8], PseudorandomZeroSharingSeedCatalogStateOutputError> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(state_output_object_mismatch(field));
    }
    Ok(item.variable_value_bytes()?)
}

fn require_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateOutputError> {
    if item.item_type() != CanonicalItemType::Hash512
        || item.canonical_bytes() != expected.as_bytes()
    {
        return Err(state_output_object_mismatch(field));
    }
    Ok(())
}

fn read_u16(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u16, PseudorandomZeroSharingSeedCatalogStateOutputError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(state_output_object_mismatch(field));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| state_output_object_mismatch(field))?;
    Ok(u16::from_le_bytes(bytes))
}

fn require_u64(
    item: &CanonicalItem,
    expected: u64,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateOutputError> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(state_output_object_mismatch(field));
    }
    let bytes: [u8; 8] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| state_output_object_mismatch(field))?;
    if u64::from_le_bytes(bytes) != expected {
        return Err(state_output_object_mismatch(field));
    }
    Ok(())
}

const fn state_output_object_mismatch(
    field: &'static str,
) -> PseudorandomZeroSharingSeedCatalogStateOutputError {
    PseudorandomZeroSharingSeedCatalogStateOutputError::ObjectMismatch { field }
}

fn exact_output_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_EXACT_OUTPUT_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_item_count: 16,
        maximum_item_byte_length: MAXIMUM_EXACT_OUTPUT_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: 32_768,
        maximum_cumulative_allocation_byte_length: 32_768,
    }
}

fn exact_output_certificate_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_EXACT_OUTPUT_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_EXACT_OUTPUT_CONTROL_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_EXACT_OUTPUT_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length:
            MAXIMUM_EXACT_OUTPUT_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_EXACT_OUTPUT_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}
