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
    pseudorandom_zero_sharing_seed_catalog_signature_320::ML_DSA_65_SIGNATURE_BYTE_LENGTH,
};

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const RESERVATION_INTENT_ITEM_COUNT: usize = 5;
const WITNESS_AUTHORIZATION_BODY_ITEM_COUNT: usize = 3;
const WITNESS_ENVELOPE_ITEM_COUNT: usize = 3;
const STATE_CERTIFICATE_PREFIX_ITEM_COUNT: usize = 2;
const MAXIMUM_STATE_CONTROL_OBJECT_BYTE_LENGTH: usize = 131_072;
const MAXIMUM_STATE_CONTROL_OBJECT_ITEM_COUNT: usize = 32;
const MAXIMUM_STATE_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 8_192;
const MAXIMUM_STATE_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 262_144;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_OPERATION_KIND: &str =
    "preparation-seed-catalog-root";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_KEY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/state/seed-catalog-root-key";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_RESERVATION_INTENT_DOMAIN: &str =
    "sealed-lattice/v1/state/seed-catalog-root-reservation-intent";
pub(crate) const
    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_RESERVATION_INTENT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/state/seed-catalog-root-reservation-intent-identity";
pub(crate) const
    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_AUTHORIZATION_BODY_DOMAIN: &str =
    "sealed-lattice/v1/state/seed-catalog-root-reservation-witness-body";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/state/seed-catalog-root-reservation-witness-envelope";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_CERTIFICATE_DOMAIN: &str =
    "sealed-lattice/v1/state/seed-catalog-root-reservation-certificate";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_CERTIFICATE_IDENTITY_DOMAIN:
    &str = "sealed-lattice/v1/state/seed-catalog-root-reservation-certificate-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT:
    &[u8] = b"sealed-lattice/v1/state/seed-catalog-root-reservation-witness";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedCatalogStateError {
    Canonical(CanonicalCodecError),
    Preparation(TallyPreparationError),
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
}

impl From<CanonicalCodecError> for PseudorandomZeroSharingSeedCatalogStateError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<TallyPreparationError> for PseudorandomZeroSharingSeedCatalogStateError {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedCatalogStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => {
                write!(formatter, "canonical seed-catalog state error: {error}")
            }
            Self::Preparation(error) => {
                write!(formatter, "seed-catalog state preparation error: {error}")
            }
            Self::ObjectMismatch { field } => {
                write!(formatter, "seed-catalog state object has a wrong {field}")
            }
            Self::RosterMismatch => formatter.write_str(
                "seed-catalog state roster does not match the expected preparation context",
            ),
            Self::WitnessCount { expected, actual } => write!(
                formatter,
                "seed-catalog state certificate has {actual} witnesses; expected {expected}"
            ),
            Self::WitnessPositionOutOfRange {
                witness_position,
                participant_count,
            } => write!(
                formatter,
                "seed-catalog state witness {witness_position} is outside participant count {participant_count}"
            ),
            Self::SubjectCannotWitness => formatter
                .write_str("a seed-catalog root contributor cannot witness its own reservation"),
            Self::WitnessOrder => formatter.write_str(
                "seed-catalog state witnesses must be distinct and in ascending roster order",
            ),
            Self::MalformedSigningVerificationKey { witness_position } => write!(
                formatter,
                "seed-catalog state witness {witness_position} has a malformed ML-DSA-65 verification key"
            ),
            Self::InvalidWitnessSignature { witness_position } => write!(
                formatter,
                "seed-catalog state witness {witness_position} has an invalid ML-DSA-65 signature"
            ),
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedCatalogStateError {}

/// Verifier-derived stable conflict key for one contributor's seed catalog.
///
/// The key excludes the root digest and every other alternative value. Two
/// conflicting roots for the same catalog therefore compete for one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootStateKey320 {
    identity: Hash512,
}

impl PseudorandomZeroSharingSeedCatalogRootStateKey320 {
    pub(crate) fn derive(
        layout: PseudorandomZeroSharingSeedCatalogLayout320,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateError> {
        let identity = hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_KEY_IDENTITY_DOMAIN,
            &[
                CanonicalItem::hash512(layout.preparation_context().identity().into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_OPERATION_KIND,
                )?,
                CanonicalItem::hash512(layout.identity().into_bytes()),
                CanonicalItem::unsigned16(layout.contributor_position()),
            ],
        )?;
        Ok(Self { identity })
    }

    pub(crate) const fn identity(self) -> Hash512 {
        self.identity
    }
}

/// Exact alternative reserved under one verifier-derived state key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320 {
    participant_count: u16,
    subject_position: u16,
    state_key_identity: Hash512,
    predecessor_identity: Hash512,
    root_body_identity: Hash512,
}

impl PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320 {
    pub(crate) fn new(
        root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateError> {
        let layout = root_body.layout();
        Ok(Self {
            participant_count: layout.participant_count(),
            subject_position: layout.contributor_position(),
            state_key_identity: PseudorandomZeroSharingSeedCatalogRootStateKey320::derive(layout)?
                .identity(),
            predecessor_identity: layout.preparation_context().identity(),
            root_body_identity: root_body.identity()?,
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

    pub(crate) const fn predecessor_identity(self) -> Hash512 {
        self.predecessor_identity
    }

    pub(crate) const fn root_body_identity(self) -> Hash512 {
        self.root_body_identity
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogStateError> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_RESERVATION_INTENT_DOMAIN,
                )?,
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_OPERATION_KIND,
                )?,
                CanonicalItem::hash512(self.state_key_identity.into_bytes()),
                CanonicalItem::hash512(self.predecessor_identity.into_bytes()),
                CanonicalItem::hash512(self.root_body_identity.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub(crate) fn identity(self) -> Result<Hash512, PseudorandomZeroSharingSeedCatalogStateError> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_RESERVATION_INTENT_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn from_canonical_bytes(
        expected_root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateError> {
        let expected = Self::new(expected_root_body)?;
        let tuple = CanonicalTuple::decode(bytes, &state_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_RESERVATION_INTENT_DOMAIN,
            RESERVATION_INTENT_ITEM_COUNT,
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
            expected.predecessor_identity,
            "predecessor identity",
        )?;
        require_hash(
            &tuple.items[4],
            expected.root_body_identity,
            "root-body identity",
        )?;
        Ok(expected)
    }
}

/// Deterministic message signed by one non-subject state witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320 {
    reservation_intent_identity: Hash512,
    witness_position: u16,
}

impl PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320 {
    pub(crate) fn new(
        reservation_intent: PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
        witness_position: u16,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateError> {
        validate_witness_position(reservation_intent, witness_position)?;
        Ok(Self {
            reservation_intent_identity: reservation_intent.identity()?,
            witness_position,
        })
    }

    pub(crate) const fn witness_position(self) -> u16 {
        self.witness_position
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogStateError> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_AUTHORIZATION_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.reservation_intent_identity.into_bytes()),
                CanonicalItem::unsigned16(self.witness_position),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_reservation_intent: PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateError> {
        let tuple = CanonicalTuple::decode(bytes, &state_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_AUTHORIZATION_BODY_DOMAIN,
            WITNESS_AUTHORIZATION_BODY_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected_reservation_intent.identity()?,
            "reservation-intent identity",
        )?;
        Self::new(
            expected_reservation_intent,
            read_u16(&tuple.items[2], "witness position")?,
        )
    }
}

/// One detached witness signature over a reservation authorization body.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320 {
    authorization_body: PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320 {
    pub(crate) const fn new(
        authorization_body: PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320,
        signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            authorization_body,
            signature,
        }
    }

    pub(crate) const fn authorization_body(
        &self,
    ) -> PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320 {
        self.authorization_body
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogStateError> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_ENVELOPE_DOMAIN,
                )?,
                CanonicalItem::variable_bytes(self.authorization_body.canonical_bytes()?)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_reservation_intent: PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateError> {
        let tuple = CanonicalTuple::decode(bytes, &state_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_ENVELOPE_DOMAIN,
            WITNESS_ENVELOPE_ITEM_COUNT,
        )?;
        let authorization_body =
            PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320::from_canonical_bytes(
                expected_reservation_intent,
                read_variable_bytes(&tuple.items[1], "witness authorization body")?,
            )?;
        if tuple.items[2].item_type() != CanonicalItemType::RawBytes {
            return Err(state_object_mismatch("witness signature"));
        }
        let signature =
            <[u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH]>::try_from(tuple.items[2].canonical_bytes())
                .map_err(|_| state_object_mismatch("witness signature byte length"))?;
        Ok(Self {
            authorization_body,
            signature,
        })
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320")
            .field("authorization_body", &self.authorization_body)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Canonical roster-ordered quorum of non-subject witness carriers.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320 {
    reservation_intent: PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
    witness_envelopes: Box<[PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320]>,
}

impl PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320 {
    pub(crate) fn new(
        reservation_intent: PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
        witness_envelopes: Vec<PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320>,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateError> {
        validate_witness_inventory(reservation_intent, &witness_envelopes)?;
        Ok(Self {
            reservation_intent,
            witness_envelopes: witness_envelopes.into_boxed_slice(),
        })
    }

    pub(crate) fn witness_envelopes(
        &self,
    ) -> &[PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320] {
        &self.witness_envelopes
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogStateError> {
        let mut items =
            Vec::with_capacity(STATE_CERTIFICATE_PREFIX_ITEM_COUNT + self.witness_envelopes.len());
        items.push(CanonicalItem::nonempty_ascii(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_CERTIFICATE_DOMAIN,
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

    pub(crate) fn identity(&self) -> Result<Hash512, PseudorandomZeroSharingSeedCatalogStateError> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_CERTIFICATE_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn from_canonical_bytes(
        expected_root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogStateError> {
        let expected_reservation_intent =
            PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(
                expected_root_body,
            )?;
        let tuple = CanonicalTuple::decode(bytes, &state_certificate_decode_limits())?;
        let roster_parameters =
            derive_foundation_roster_parameters(expected_reservation_intent.participant_count())
                .ok_or(PseudorandomZeroSharingSeedCatalogStateError::RosterMismatch)?;
        let expected_witness_count = usize::from(roster_parameters.state_witness_quorum);
        let expected_item_count = STATE_CERTIFICATE_PREFIX_ITEM_COUNT
            .checked_add(expected_witness_count)
            .ok_or(PseudorandomZeroSharingSeedCatalogStateError::WitnessCount {
                expected: expected_witness_count,
                actual: tuple.items.len(),
            })?;
        if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
            return Err(state_object_mismatch("schema identifier"));
        }
        if tuple.schema_version != CANONICAL_TUPLE_VERSION {
            return Err(state_object_mismatch("schema version"));
        }
        if tuple.items.len() != expected_item_count {
            return Err(PseudorandomZeroSharingSeedCatalogStateError::WitnessCount {
                expected: expected_witness_count,
                actual: tuple
                    .items
                    .len()
                    .saturating_sub(STATE_CERTIFICATE_PREFIX_ITEM_COUNT),
            });
        }
        require_ascii(
            &tuple.items[0],
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_CERTIFICATE_DOMAIN,
            "object domain",
        )?;
        let reservation_intent =
            PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::from_canonical_bytes(
                expected_root_body,
                read_variable_bytes(&tuple.items[1], "reservation intent")?,
            )?;
        let witness_envelopes = tuple.items[STATE_CERTIFICATE_PREFIX_ITEM_COUNT..]
            .iter()
            .map(|item| {
                PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320::from_canonical_bytes(
                    reservation_intent,
                    read_variable_bytes(item, "witness envelope")?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(reservation_intent, witness_envelopes)
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320")
            .field("reservation_intent", &self.reservation_intent)
            .field("witness_count", &self.witness_envelopes.len())
            .field("witness_signatures", &"[redacted]")
            .finish()
    }
}

/// Positive witness-quorum verification for one exact catalog-root intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedPseudorandomZeroSharingSeedCatalogRootStateReservation320 {
    root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
    state_key_identity: Hash512,
    reservation_intent_identity: Hash512,
    state_certificate_identity: Hash512,
}

impl VerifiedPseudorandomZeroSharingSeedCatalogRootStateReservation320 {
    pub(crate) const fn root_body(self) -> PseudorandomZeroSharingSeedCatalogRootBody320 {
        self.root_body
    }

    pub(crate) const fn state_key_identity(self) -> Hash512 {
        self.state_key_identity
    }

    pub(crate) const fn reservation_intent_identity(self) -> Hash512 {
        self.reservation_intent_identity
    }

    pub(crate) const fn state_certificate_identity(self) -> Hash512 {
        self.state_certificate_identity
    }
}

pub(crate) fn verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
    expected_layout: PseudorandomZeroSharingSeedCatalogLayout320,
    root_body_bytes: &[u8],
    roster: &Roster,
    state_certificate_bytes: &[u8],
) -> Result<
    VerifiedPseudorandomZeroSharingSeedCatalogRootStateReservation320,
    PseudorandomZeroSharingSeedCatalogStateError,
> {
    let root_body = PseudorandomZeroSharingSeedCatalogRootBody320::from_canonical_bytes(
        expected_layout,
        root_body_bytes,
    )?;
    validate_roster(expected_layout, roster)?;
    let reservation_intent =
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(root_body)?;
    let certificate =
        PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320::from_canonical_bytes(
            root_body,
            state_certificate_bytes,
        )?;
    for witness_envelope in certificate.witness_envelopes() {
        let witness_position = witness_envelope.authorization_body().witness_position();
        let roster_entry = roster.entries.get(usize::from(witness_position)).ok_or(
            PseudorandomZeroSharingSeedCatalogStateError::WitnessPositionOutOfRange {
                witness_position,
                participant_count: expected_layout.participant_count(),
            },
        )?;
        if roster_entry.roster_position != witness_position {
            return Err(PseudorandomZeroSharingSeedCatalogStateError::RosterMismatch);
        }
        let public_key =
            ml_dsa_65::PublicKey::try_from_bytes(roster_entry.signing_verification_key).map_err(
                |_| PseudorandomZeroSharingSeedCatalogStateError::MalformedSigningVerificationKey {
                    witness_position,
                },
            )?;
        if !public_key.verify(
            &witness_envelope.authorization_body().canonical_bytes()?,
            &witness_envelope.signature,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
        ) {
            return Err(
                PseudorandomZeroSharingSeedCatalogStateError::InvalidWitnessSignature {
                    witness_position,
                },
            );
        }
    }
    Ok(
        VerifiedPseudorandomZeroSharingSeedCatalogRootStateReservation320 {
            root_body,
            state_key_identity: reservation_intent.state_key_identity(),
            reservation_intent_identity: reservation_intent.identity()?,
            state_certificate_identity: certificate.identity()?,
        },
    )
}

fn validate_roster(
    expected_layout: PseudorandomZeroSharingSeedCatalogLayout320,
    roster: &Roster,
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateError> {
    roster
        .validate()
        .map_err(|_| PseudorandomZeroSharingSeedCatalogStateError::RosterMismatch)?;
    if roster.entries.len() != usize::from(expected_layout.participant_count())
        || roster
            .roster_hash()
            .map_err(|_| PseudorandomZeroSharingSeedCatalogStateError::RosterMismatch)?
            != expected_layout.preparation_context().roster_hash()
    {
        return Err(PseudorandomZeroSharingSeedCatalogStateError::RosterMismatch);
    }
    Ok(())
}

fn validate_witness_inventory(
    reservation_intent: PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
    witness_envelopes: &[PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320],
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateError> {
    let roster_parameters =
        derive_foundation_roster_parameters(reservation_intent.participant_count())
            .ok_or(PseudorandomZeroSharingSeedCatalogStateError::RosterMismatch)?;
    let expected_witness_count = usize::from(roster_parameters.state_witness_quorum);
    if witness_envelopes.len() != expected_witness_count {
        return Err(PseudorandomZeroSharingSeedCatalogStateError::WitnessCount {
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
        let witness_position = authorization_body.witness_position();
        validate_witness_position(reservation_intent, witness_position)?;
        if preceding_witness_position.is_some_and(|preceding| preceding >= witness_position) {
            return Err(PseudorandomZeroSharingSeedCatalogStateError::WitnessOrder);
        }
        preceding_witness_position = Some(witness_position);
    }
    Ok(())
}

fn validate_witness_position(
    reservation_intent: PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
    witness_position: u16,
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateError> {
    if witness_position >= reservation_intent.participant_count() {
        return Err(
            PseudorandomZeroSharingSeedCatalogStateError::WitnessPositionOutOfRange {
                witness_position,
                participant_count: reservation_intent.participant_count(),
            },
        );
    }
    if witness_position == reservation_intent.subject_position() {
        return Err(PseudorandomZeroSharingSeedCatalogStateError::SubjectCannotWitness);
    }
    Ok(())
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateError> {
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
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateError> {
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
) -> Result<&'a [u8], PseudorandomZeroSharingSeedCatalogStateError> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(state_object_mismatch(field));
    }
    Ok(item.variable_value_bytes()?)
}

fn require_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedCatalogStateError> {
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
) -> Result<u16, PseudorandomZeroSharingSeedCatalogStateError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(state_object_mismatch(field));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| state_object_mismatch(field))?;
    Ok(u16::from_le_bytes(bytes))
}

const fn state_object_mismatch(
    field: &'static str,
) -> PseudorandomZeroSharingSeedCatalogStateError {
    PseudorandomZeroSharingSeedCatalogStateError::ObjectMismatch { field }
}

fn state_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_STATE_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_item_count: 16,
        maximum_item_byte_length: MAXIMUM_STATE_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: 32_768,
        maximum_cumulative_allocation_byte_length: 32_768,
    }
}

fn state_certificate_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_STATE_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_STATE_CONTROL_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_STATE_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_STATE_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_STATE_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}
