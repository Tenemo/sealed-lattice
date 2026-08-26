use core::fmt;

use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, Roster,
    hash_foundation_tuple_512,
};

use super::{
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320::{
        PseudorandomZeroSharingSeedCatalogRootInventoryError,
        VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
    },
    pseudorandom_zero_sharing_seed_catalog_signature_320::ML_DSA_65_SIGNATURE_BYTE_LENGTH,
};

const TERMINAL_BODY_ITEM_COUNT: usize = 2;
const ENDORSEMENT_AUTHORIZATION_BODY_ITEM_COUNT: usize = 3;
const ENDORSEMENT_ENVELOPE_ITEM_COUNT: usize = 3;
const TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT: usize = 2;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;
const MAXIMUM_TERMINAL_CONTROL_OBJECT_BYTE_LENGTH: usize = 131_072;
const MAXIMUM_TERMINAL_CONTROL_OBJECT_ITEM_COUNT: usize = 32;
const MAXIMUM_TERMINAL_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 8_192;
const MAXIMUM_TERMINAL_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 262_144;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-terminal";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-terminal-identity";
pub(crate) const
    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-terminal-endorsement-body";
pub(crate) const
    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-terminal-endorsement-envelope";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_CERTIFICATE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-terminal-certificate";
pub(crate) const
    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_CERTIFICATE_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-terminal-certificate-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/preparation/seed-catalog-root-terminal";

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + TERMINAL_BODY_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_DOMAIN.len()
        + Hash512::BYTE_LENGTH;
pub(crate) const
    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + ENDORSEMENT_AUTHORIZATION_BODY_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_DOMAIN
            .len()
        + Hash512::BYTE_LENGTH
        + size_of::<u16>();
pub(crate) const
    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + ENDORSEMENT_ENVELOPE_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_ENVELOPE_DOMAIN.len()
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_BYTE_LENGTH
        + ML_DSA_65_SIGNATURE_BYTE_LENGTH;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedCatalogRootTerminalError320 {
    Canonical(CanonicalCodecError),
    RootInventory(PseudorandomZeroSharingSeedCatalogRootInventoryError),
    ObjectMismatch {
        field: &'static str,
    },
    RosterMismatch,
    MissingRoot,
    EndorsementCount {
        expected: usize,
        actual: usize,
    },
    EndorserPositionOutOfRange {
        endorser_position: u16,
        participant_count: u16,
    },
    EndorsementOrder,
    MalformedSigningVerificationKey {
        endorser_position: u16,
    },
    InvalidEndorsementSignature {
        endorser_position: u16,
    },
    ArithmeticOverflow,
}

impl From<CanonicalCodecError> for PseudorandomZeroSharingSeedCatalogRootTerminalError320 {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<PseudorandomZeroSharingSeedCatalogRootInventoryError>
    for PseudorandomZeroSharingSeedCatalogRootTerminalError320
{
    fn from(error: PseudorandomZeroSharingSeedCatalogRootInventoryError) -> Self {
        Self::RootInventory(error)
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedCatalogRootTerminalError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => {
                write!(formatter, "canonical seed-catalog root-terminal error: {error}")
            }
            Self::RootInventory(error) => {
                write!(formatter, "seed-catalog root-terminal inventory error: {error}")
            }
            Self::ObjectMismatch { field } => {
                write!(formatter, "seed-catalog root-terminal object has a wrong {field}")
            }
            Self::RosterMismatch => formatter.write_str(
                "seed-catalog root-terminal roster does not match the root inventory",
            ),
            Self::MissingRoot => formatter.write_str(
                "seed-catalog root-terminal inventory has no root from which to verify the roster",
            ),
            Self::EndorsementCount { expected, actual } => write!(
                formatter,
                "seed-catalog root-terminal certificate has {actual} endorsements; expected {expected}"
            ),
            Self::EndorserPositionOutOfRange {
                endorser_position,
                participant_count,
            } => write!(
                formatter,
                "seed-catalog root-terminal endorser {endorser_position} is outside participant count {participant_count}"
            ),
            Self::EndorsementOrder => formatter.write_str(
                "seed-catalog root-terminal endorsements must cover every participant in canonical roster order",
            ),
            Self::MalformedSigningVerificationKey { endorser_position } => write!(
                formatter,
                "seed-catalog root-terminal endorser {endorser_position} has a malformed ML-DSA-65 verification key"
            ),
            Self::InvalidEndorsementSignature { endorser_position } => write!(
                formatter,
                "seed-catalog root-terminal endorser {endorser_position} has an invalid ML-DSA-65 signature"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("seed-catalog root-terminal arithmetic overflowed")
            }
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedCatalogRootTerminalError320 {}

/// Certificate-free semantic terminal over one complete inventory of
/// individually state-and-roster-authorized roots.
///
/// The inventory identity already binds the parameter, preparation context,
/// participant count, and every ordered root. Repeating those fields here would
/// create denormalized copies without adding a verifier predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootTerminalBody320 {
    root_inventory_identity: Hash512,
    participant_count: u16,
}

impl PseudorandomZeroSharingSeedCatalogRootTerminalBody320 {
    pub(crate) fn new(
        root_inventory: &VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        Ok(Self {
            root_inventory_identity: root_inventory.identity()?,
            participant_count: root_inventory.body().participant_count(),
        })
    }

    pub(crate) const fn root_inventory_identity(self) -> Hash512 {
        self.root_inventory_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.root_inventory_identity.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub(crate) fn identity(
        self,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn from_canonical_bytes(
        root_inventory: &VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        let expected = Self::new(root_inventory)?;
        let tuple = CanonicalTuple::decode(bytes, &terminal_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_DOMAIN,
            TERMINAL_BODY_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected.root_inventory_identity,
            "root-inventory identity",
        )?;
        Ok(expected)
    }
}

/// Deterministic message signed by one roster endorser only after locally
/// verifying the complete root inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementAuthorizationBody320 {
    terminal_body_identity: Hash512,
    endorser_position: u16,
}

impl PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementAuthorizationBody320 {
    pub(crate) fn new(
        terminal_body: PseudorandomZeroSharingSeedCatalogRootTerminalBody320,
        endorser_position: u16,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        validate_endorser_position(terminal_body, endorser_position)?;
        Ok(Self {
            terminal_body_identity: terminal_body.identity()?,
            endorser_position,
        })
    }

    pub(crate) const fn endorser_position(self) -> u16 {
        self.endorser_position
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.terminal_body_identity.into_bytes()),
                CanonicalItem::unsigned16(self.endorser_position),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_terminal_body: PseudorandomZeroSharingSeedCatalogRootTerminalBody320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        let tuple = CanonicalTuple::decode(bytes, &terminal_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_DOMAIN,
            ENDORSEMENT_AUTHORIZATION_BODY_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected_terminal_body.identity()?,
            "terminal-body identity",
        )?;
        Self::new(
            expected_terminal_body,
            read_u16(&tuple.items[2], "endorser position")?,
        )
    }
}

/// Detached ML-DSA-65 endorsement of one verifier-derived terminal body.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320 {
    authorization_body:
        PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementAuthorizationBody320,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320 {
    pub(crate) const fn new(
        authorization_body: PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementAuthorizationBody320,
        signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            authorization_body,
            signature,
        }
    }

    pub(crate) const fn authorization_body(
        &self,
    ) -> PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementAuthorizationBody320 {
        self.authorization_body
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_ENVELOPE_DOMAIN,
                )?,
                CanonicalItem::variable_bytes(self.authorization_body.canonical_bytes()?)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_terminal_body: PseudorandomZeroSharingSeedCatalogRootTerminalBody320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        let tuple = CanonicalTuple::decode(bytes, &terminal_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_ENVELOPE_DOMAIN,
            ENDORSEMENT_ENVELOPE_ITEM_COUNT,
        )?;
        let authorization_body =
            Self::read_authorization_body(expected_terminal_body, &tuple.items[1])?;
        if tuple.items[2].item_type() != CanonicalItemType::RawBytes {
            return Err(terminal_object_mismatch("endorsement signature"));
        }
        let signature =
            <[u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH]>::try_from(tuple.items[2].canonical_bytes())
                .map_err(|_| terminal_object_mismatch("endorsement signature byte length"))?;
        Ok(Self {
            authorization_body,
            signature,
        })
    }

    fn read_authorization_body(
        expected_terminal_body: PseudorandomZeroSharingSeedCatalogRootTerminalBody320,
        item: &CanonicalItem,
    ) -> Result<
        PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementAuthorizationBody320,
        PseudorandomZeroSharingSeedCatalogRootTerminalError320,
    > {
        if item.item_type() != CanonicalItemType::RawBytes {
            return Err(terminal_object_mismatch("endorsement authorization body"));
        }
        PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementAuthorizationBody320::from_canonical_bytes(
            expected_terminal_body,
            item.variable_value_bytes()?,
        )
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320")
            .field("authorization_body", &self.authorization_body)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Exact all-roster endorsement carrier for one terminal body.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320 {
    terminal_body: PseudorandomZeroSharingSeedCatalogRootTerminalBody320,
    endorsement_envelopes:
        Box<[PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320]>,
}

impl PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320 {
    pub(crate) fn new(
        terminal_body: PseudorandomZeroSharingSeedCatalogRootTerminalBody320,
        endorsement_envelopes: Vec<
            PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320,
        >,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        validate_endorsement_inventory(terminal_body, &endorsement_envelopes)?;
        Ok(Self {
            terminal_body,
            endorsement_envelopes: endorsement_envelopes.into_boxed_slice(),
        })
    }

    pub(crate) fn endorsement_envelopes(
        &self,
    ) -> &[PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320] {
        &self.endorsement_envelopes
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        let mut items = Vec::with_capacity(
            TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT + self.endorsement_envelopes.len(),
        );
        items.push(CanonicalItem::nonempty_ascii(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_CERTIFICATE_DOMAIN,
        )?);
        items.push(CanonicalItem::variable_bytes(
            self.terminal_body.canonical_bytes()?,
        )?);
        for endorsement_envelope in &self.endorsement_envelopes {
            items.push(CanonicalItem::variable_bytes(
                endorsement_envelope.canonical_bytes()?,
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
    ) -> Result<Hash512, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_CERTIFICATE_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    pub(crate) fn canonical_byte_length_for_participant_count(
        participant_count: u16,
    ) -> Result<usize, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        let endorsement_count = usize::from(participant_count);
        CANONICAL_TUPLE_HEADER_BYTE_LENGTH
            .checked_add(
                TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT
                    .checked_add(endorsement_count)
                    .ok_or(
                        PseudorandomZeroSharingSeedCatalogRootTerminalError320::ArithmeticOverflow,
                    )?
                    .checked_mul(CANONICAL_ITEM_HEADER_BYTE_LENGTH)
                    .ok_or(
                        PseudorandomZeroSharingSeedCatalogRootTerminalError320::ArithmeticOverflow,
                    )?,
            )
            .and_then(|byte_length| {
                byte_length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH)
            })
            .and_then(|byte_length| {
                byte_length.checked_add(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_CERTIFICATE_DOMAIN.len(),
                )
            })
            .and_then(|byte_length| {
                byte_length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH)
            })
            .and_then(|byte_length| {
                byte_length.checked_add(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_BYTE_LENGTH,
                )
            })
            .and_then(|byte_length| {
                CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
                    .checked_add(
                        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH,
                    )
                    .and_then(|endorsement_byte_length| {
                        endorsement_count.checked_mul(endorsement_byte_length)
                    })
                    .and_then(|all_endorsement_byte_length| {
                        byte_length.checked_add(all_endorsement_byte_length)
                    })
            })
            .ok_or(PseudorandomZeroSharingSeedCatalogRootTerminalError320::ArithmeticOverflow)
    }

    fn from_canonical_bytes(
        root_inventory: &VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        let expected_terminal_body =
            PseudorandomZeroSharingSeedCatalogRootTerminalBody320::new(root_inventory)?;
        let tuple = CanonicalTuple::decode(bytes, &terminal_certificate_decode_limits())?;
        let expected_endorsement_count = usize::from(expected_terminal_body.participant_count());
        let expected_item_count = TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT
            .checked_add(expected_endorsement_count)
            .ok_or(PseudorandomZeroSharingSeedCatalogRootTerminalError320::ArithmeticOverflow)?;
        if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
            return Err(terminal_object_mismatch("schema identifier"));
        }
        if tuple.schema_version != CANONICAL_TUPLE_VERSION {
            return Err(terminal_object_mismatch("schema version"));
        }
        if tuple.items.len() != expected_item_count {
            return Err(
                PseudorandomZeroSharingSeedCatalogRootTerminalError320::EndorsementCount {
                    expected: expected_endorsement_count,
                    actual: tuple
                        .items
                        .len()
                        .saturating_sub(TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT),
                },
            );
        }
        require_ascii(
            &tuple.items[0],
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_CERTIFICATE_DOMAIN,
            "object domain",
        )?;
        let terminal_body_item = &tuple.items[1];
        if terminal_body_item.item_type() != CanonicalItemType::RawBytes {
            return Err(terminal_object_mismatch("terminal body"));
        }
        let terminal_body =
            PseudorandomZeroSharingSeedCatalogRootTerminalBody320::from_canonical_bytes(
                root_inventory,
                terminal_body_item.variable_value_bytes()?,
            )?;
        let endorsement_envelopes = tuple.items[TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT..]
            .iter()
            .map(|item| {
                if item.item_type() != CanonicalItemType::RawBytes {
                    return Err(terminal_object_mismatch("endorsement envelope"));
                }
                PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320::from_canonical_bytes(
                    terminal_body,
                    item.variable_value_bytes()?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(terminal_body, endorsement_envelopes)
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320")
            .field("terminal_body", &self.terminal_body)
            .field("endorsement_count", &self.endorsement_envelopes.len())
            .field("endorsement_signatures", &"[redacted]")
            .finish()
    }
}

/// Complete root inventory after every participant endorsed the same semantic
/// terminal body under its roster-pinned signing key.
///
/// The constituent roots are already positively state-and-roster authorized,
/// so their deterministic inventory has no second semantic alternative. This
/// result proves common roster endorsement and supplies the chronology
/// predecessor required by seed-delivery verification. It does not implement
/// durable endorsement locking, external recency reconciliation, authenticated
/// mailbox delivery, or a preparation-continuation capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320 {
    root_inventory: VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
    terminal_body: PseudorandomZeroSharingSeedCatalogRootTerminalBody320,
    certificate_identity: Hash512,
}

impl RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320 {
    pub(crate) const fn root_inventory(
        &self,
    ) -> &VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320 {
        &self.root_inventory
    }

    pub(crate) const fn terminal_body(
        &self,
    ) -> PseudorandomZeroSharingSeedCatalogRootTerminalBody320 {
        self.terminal_body
    }

    pub(crate) fn identity(
        &self,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
        self.terminal_body.identity()
    }

    pub(crate) const fn certificate_identity(&self) -> Hash512 {
        self.certificate_identity
    }
}

pub(crate) fn verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
    root_inventory: VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
    roster: &Roster,
    terminal_certificate_bytes: &[u8],
) -> Result<
    RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    PseudorandomZeroSharingSeedCatalogRootTerminalError320,
> {
    validate_roster(&root_inventory, roster)?;
    let terminal_body =
        PseudorandomZeroSharingSeedCatalogRootTerminalBody320::new(&root_inventory)?;
    let terminal_certificate =
        PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320::from_canonical_bytes(
            &root_inventory,
            terminal_certificate_bytes,
        )?;
    for endorsement_envelope in terminal_certificate.endorsement_envelopes() {
        let endorser_position = endorsement_envelope
            .authorization_body()
            .endorser_position();
        let roster_entry = roster.entries.get(usize::from(endorser_position)).ok_or(
            PseudorandomZeroSharingSeedCatalogRootTerminalError320::EndorserPositionOutOfRange {
                endorser_position,
                participant_count: terminal_body.participant_count(),
            },
        )?;
        if roster_entry.roster_position != endorser_position {
            return Err(PseudorandomZeroSharingSeedCatalogRootTerminalError320::RosterMismatch);
        }
        let public_key = ml_dsa_65::PublicKey::try_from_bytes(
            roster_entry.signing_verification_key,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedCatalogRootTerminalError320::MalformedSigningVerificationKey {
                endorser_position,
            }
        })?;
        if !public_key.verify(
            &endorsement_envelope
                .authorization_body()
                .canonical_bytes()?,
            &endorsement_envelope.signature,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_SIGNATURE_CONTEXT,
        ) {
            return Err(
                PseudorandomZeroSharingSeedCatalogRootTerminalError320::InvalidEndorsementSignature {
                    endorser_position,
                },
            );
        }
    }
    Ok(
        RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320 {
            root_inventory,
            terminal_body,
            certificate_identity: terminal_certificate.identity()?,
        },
    )
}

fn validate_roster(
    root_inventory: &VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
    roster: &Roster,
) -> Result<(), PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
    roster
        .validate()
        .map_err(|_| PseudorandomZeroSharingSeedCatalogRootTerminalError320::RosterMismatch)?;
    let participant_count = root_inventory.body().participant_count();
    let first_root = root_inventory
        .root_body(0)
        .ok_or(PseudorandomZeroSharingSeedCatalogRootTerminalError320::MissingRoot)?;
    if roster.entries.len() != usize::from(participant_count)
        || roster
            .roster_hash()
            .map_err(|_| PseudorandomZeroSharingSeedCatalogRootTerminalError320::RosterMismatch)?
            != first_root.layout().preparation_context().roster_hash()
    {
        return Err(PseudorandomZeroSharingSeedCatalogRootTerminalError320::RosterMismatch);
    }
    Ok(())
}

fn validate_endorsement_inventory(
    terminal_body: PseudorandomZeroSharingSeedCatalogRootTerminalBody320,
    endorsement_envelopes: &[PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320],
) -> Result<(), PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
    let expected_endorsement_count = usize::from(terminal_body.participant_count());
    if endorsement_envelopes.len() != expected_endorsement_count {
        return Err(
            PseudorandomZeroSharingSeedCatalogRootTerminalError320::EndorsementCount {
                expected: expected_endorsement_count,
                actual: endorsement_envelopes.len(),
            },
        );
    }
    let expected_terminal_body_identity = terminal_body.identity()?;
    for (endorser_index, endorsement_envelope) in endorsement_envelopes.iter().enumerate() {
        let authorization_body = endorsement_envelope.authorization_body();
        if authorization_body.terminal_body_identity != expected_terminal_body_identity {
            return Err(terminal_object_mismatch("terminal-body identity"));
        }
        let expected_endorser_position = u16::try_from(endorser_index).map_err(|_| {
            PseudorandomZeroSharingSeedCatalogRootTerminalError320::ArithmeticOverflow
        })?;
        if authorization_body.endorser_position() != expected_endorser_position {
            return Err(PseudorandomZeroSharingSeedCatalogRootTerminalError320::EndorsementOrder);
        }
    }
    Ok(())
}

fn validate_endorser_position(
    terminal_body: PseudorandomZeroSharingSeedCatalogRootTerminalBody320,
    endorser_position: u16,
) -> Result<(), PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
    if endorser_position >= terminal_body.participant_count() {
        return Err(
            PseudorandomZeroSharingSeedCatalogRootTerminalError320::EndorserPositionOutOfRange {
                endorser_position,
                participant_count: terminal_body.participant_count(),
            },
        );
    }
    Ok(())
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(terminal_object_mismatch("schema identifier"));
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(terminal_object_mismatch("schema version"));
    }
    if tuple.items.len() != expected_item_count {
        return Err(terminal_object_mismatch("item count"));
    }
    require_ascii(&tuple.items[0], expected_domain, "object domain")
}

fn require_ascii(
    item: &CanonicalItem,
    expected: &str,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
    if item.item_type() != CanonicalItemType::Ascii
        || item.variable_value_bytes()? != expected.as_bytes()
    {
        return Err(terminal_object_mismatch(field));
    }
    Ok(())
}

fn require_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(terminal_object_mismatch(field));
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| terminal_object_mismatch(field))?;
    if Hash512::from_bytes(bytes) != expected {
        return Err(terminal_object_mismatch(field));
    }
    Ok(())
}

fn read_u16(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u16, PseudorandomZeroSharingSeedCatalogRootTerminalError320> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(terminal_object_mismatch(field));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| terminal_object_mismatch(field))?;
    Ok(u16::from_le_bytes(bytes))
}

const fn terminal_object_mismatch(
    field: &'static str,
) -> PseudorandomZeroSharingSeedCatalogRootTerminalError320 {
    PseudorandomZeroSharingSeedCatalogRootTerminalError320::ObjectMismatch { field }
}

fn terminal_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_TERMINAL_CONTROL_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_TERMINAL_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}

fn terminal_certificate_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_TERMINAL_CONTROL_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_TERMINAL_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}

const _: () = assert!(PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_BYTE_LENGTH == 144);
const _: () = assert!(
    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_BYTE_LENGTH
        == 169
);
const _: () = assert!(
    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH == 3_589
);
const _: () = assert!(ML_DSA_65_SIGNATURE_BYTE_LENGTH == ml_dsa_65::SIG_LEN);
