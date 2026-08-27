use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    StreamingFoundationTupleHash512,
};

use super::{
    TallyPreparationError,
    binary_field_320::BinaryFieldElement320,
    pseudorandom_zero_sharing_field_stream_320::PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH,
    pseudorandom_zero_sharing_seed_catalog_320::{
        CatalogIncludedSeedCommitment320, PseudorandomZeroSharingSeedCatalogCoordinate320,
        PseudorandomZeroSharingSeedCatalogLayout320,
        verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320,
    },
};

pub(crate) const PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH: usize =
    PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH;
pub(crate) const COLLECTIVE_COIN_SOURCE_BYTE_LENGTH: usize =
    BinaryFieldElement320::CANONICAL_BYTE_LENGTH;
pub(crate) const SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH: usize = 64;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_SECRET_LEAF_DOMAIN: &str =
    "sealed-lattice/v1/preparation/pair-seed-secret-leaf";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_COMMITMENT_OBJECT_DOMAIN: &str =
    "sealed-lattice/v1/preparation/pair-seed-contribution-commitment";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_DOMAIN: &str =
    "sealed-lattice/v1/preparation/pair-seed-contribution-opening";
pub(crate) const COLLECTIVE_COIN_SOURCE_SECRET_LEAF_DOMAIN: &str =
    "sealed-lattice/v1/preparation/collective-coin-source-secret-leaf";
pub(crate) const COLLECTIVE_COIN_SOURCE_COMMITMENT_OBJECT_DOMAIN: &str =
    "sealed-lattice/v1/preparation/collective-coin-source-commitment";
pub(crate) const COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_DOMAIN: &str =
    "sealed-lattice/v1/preparation/collective-coin-source-opening";

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const PAIR_COORDINATE_ITEM_COUNT: usize = 8;
const COLLECTIVE_COIN_COORDINATE_ITEM_COUNT: usize = 6;
const PAIR_COMMITMENT_OBJECT_ITEM_COUNT: usize = 1 + PAIR_COORDINATE_ITEM_COUNT + 1;
const PAIR_OPENING_OBJECT_ITEM_COUNT: usize = 1 + PAIR_COORDINATE_ITEM_COUNT + 2;
const COLLECTIVE_COIN_COMMITMENT_OBJECT_ITEM_COUNT: usize =
    1 + COLLECTIVE_COIN_COORDINATE_ITEM_COUNT + 1;
const COLLECTIVE_COIN_OPENING_OBJECT_ITEM_COUNT: usize =
    1 + COLLECTIVE_COIN_COORDINATE_ITEM_COUNT + 2;
const MAXIMUM_SECRET_LEAF_OBJECT_BYTE_LENGTH: usize = 1_024;
const MAXIMUM_SECRET_LEAF_OBJECT_ITEM_BYTE_LENGTH: usize = 256;
const MAXIMUM_SECRET_LEAF_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 4_096;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;
const PAIR_COORDINATE_CANONICAL_VALUE_BYTE_LENGTH: usize =
    Hash512::BYTE_LENGTH + Hash512::BYTE_LENGTH + 2 + Hash512::BYTE_LENGTH + 2 + 2 + 2 + 2;
const COLLECTIVE_COIN_COORDINATE_CANONICAL_VALUE_BYTE_LENGTH: usize =
    Hash512::BYTE_LENGTH + Hash512::BYTE_LENGTH + 2 + Hash512::BYTE_LENGTH + 2 + 2;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_COMMITMENT_OBJECT_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + PAIR_COMMITMENT_OBJECT_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_COMMITMENT_OBJECT_DOMAIN.len()
        + PAIR_COORDINATE_CANONICAL_VALUE_BYTE_LENGTH
        + Hash512::BYTE_LENGTH;
pub(crate) const PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + PAIR_OPENING_OBJECT_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_DOMAIN.len()
        + PAIR_COORDINATE_CANONICAL_VALUE_BYTE_LENGTH
        + SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH;
pub(crate) const COLLECTIVE_COIN_SOURCE_COMMITMENT_OBJECT_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + COLLECTIVE_COIN_COMMITMENT_OBJECT_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + COLLECTIVE_COIN_SOURCE_COMMITMENT_OBJECT_DOMAIN.len()
        + COLLECTIVE_COIN_COORDINATE_CANONICAL_VALUE_BYTE_LENGTH
        + Hash512::BYTE_LENGTH;
pub(crate) const COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + COLLECTIVE_COIN_OPENING_OBJECT_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_DOMAIN.len()
        + COLLECTIVE_COIN_COORDINATE_CANONICAL_VALUE_BYTE_LENGTH
        + SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH
        + COLLECTIVE_COIN_SOURCE_BYTE_LENGTH;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SeedCatalogSecretLeafError320 {
    Canonical(CanonicalCodecError),
    Preparation(TallyPreparationError),
    ObjectMismatch {
        object_kind: &'static str,
        field: &'static str,
    },
    PairCoordinateMismatch,
    CollectiveCoinCoordinateMismatch,
    PairCommitmentMismatch,
    CollectiveCoinCommitmentMismatch,
    CommitmentHashFailure {
        leaf_domain: &'static str,
    },
    PairContributorOrderMismatch {
        contribution_index: usize,
        expected_contributor_position: u16,
        actual_contributor_position: u16,
    },
}

impl From<CanonicalCodecError> for SeedCatalogSecretLeafError320 {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<TallyPreparationError> for SeedCatalogSecretLeafError320 {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl fmt::Display for SeedCatalogSecretLeafError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => write!(formatter, "canonical secret-leaf error: {error}"),
            Self::Preparation(error) => write!(formatter, "secret-leaf preparation error: {error}"),
            Self::ObjectMismatch { object_kind, field } => {
                write!(formatter, "{object_kind} object has a wrong {field}")
            }
            Self::PairCoordinateMismatch => formatter.write_str(
                "pair-seed commitment and opening coordinates do not match the expected coordinate",
            ),
            Self::CollectiveCoinCoordinateMismatch => formatter.write_str(
                "collective-coin commitment and opening coordinates do not match the expected coordinate",
            ),
            Self::PairCommitmentMismatch => {
                formatter.write_str("pair-seed opening does not match its commitment")
            }
            Self::CollectiveCoinCommitmentMismatch => {
                formatter.write_str("collective-coin opening does not match its commitment")
            }
            Self::CommitmentHashFailure { leaf_domain } => {
                write!(formatter, "secret-leaf hash framing failed for {leaf_domain}")
            }
            Self::PairContributorOrderMismatch {
                contribution_index,
                expected_contributor_position,
                actual_contributor_position,
            } => write!(
                formatter,
                "pair-seed contribution {contribution_index} belongs to participant {actual_contributor_position}; expected participant {expected_contributor_position}"
            ),
        }
    }
}

impl std::error::Error for SeedCatalogSecretLeafError320 {}

/// Public scope shared by both contributions to one pair key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingPairSeedScope320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    participant_count: u16,
    lower_roster_position: u16,
    upper_roster_position: u16,
}

impl PseudorandomZeroSharingPairSeedScope320 {
    fn new(
        parameter_identity: Hash512,
        preparation_context_identity: Hash512,
        participant_count: u16,
        lower_roster_position: u16,
        upper_roster_position: u16,
    ) -> Result<Self, SeedCatalogSecretLeafError320> {
        validate_participant_count(participant_count, "pair-seed")?;
        if lower_roster_position >= upper_roster_position
            || upper_roster_position >= participant_count
        {
            return Err(SeedCatalogSecretLeafError320::ObjectMismatch {
                object_kind: "pair-seed",
                field: "pair endpoints",
            });
        }
        Ok(Self {
            parameter_identity,
            preparation_context_identity,
            participant_count,
            lower_roster_position,
            upper_roster_position,
        })
    }

    pub(crate) const fn parameter_identity(self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context_identity(self) -> Hash512 {
        self.preparation_context_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn lower_roster_position(self) -> u16 {
        self.lower_roster_position
    }

    pub(crate) const fn upper_roster_position(self) -> u16 {
        self.upper_roster_position
    }
}

/// Contributor-specific pair coordinate inside one participant catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingPairSeedContributionCoordinate320 {
    scope: PseudorandomZeroSharingPairSeedScope320,
    seed_catalog_identity: Hash512,
    contributor_position: u16,
}

impl PseudorandomZeroSharingPairSeedContributionCoordinate320 {
    pub(crate) fn from_catalog_layout(
        layout: PseudorandomZeroSharingSeedCatalogLayout320,
        counterpart_position: u16,
    ) -> Result<Self, SeedCatalogSecretLeafError320> {
        let pair_coordinate = layout.pair_coordinate(counterpart_position)?;
        let PseudorandomZeroSharingSeedCatalogCoordinate320::Pair {
            lower_roster_position,
            upper_roster_position,
        } = pair_coordinate
        else {
            return Err(SeedCatalogSecretLeafError320::PairCoordinateMismatch);
        };
        let scope = PseudorandomZeroSharingPairSeedScope320::new(
            layout.parameter_identity(),
            layout.preparation_context().identity(),
            layout.participant_count(),
            lower_roster_position,
            upper_roster_position,
        )?;
        Ok(Self {
            scope,
            seed_catalog_identity: layout.identity(),
            contributor_position: layout.contributor_position(),
        })
    }

    fn from_decoded_components(
        parameter_identity: Hash512,
        preparation_context_identity: Hash512,
        seed_catalog_identity: Hash512,
        participant_count: u16,
        lower_roster_position: u16,
        upper_roster_position: u16,
        contributor_position: u16,
    ) -> Result<Self, SeedCatalogSecretLeafError320> {
        let scope = PseudorandomZeroSharingPairSeedScope320::new(
            parameter_identity,
            preparation_context_identity,
            participant_count,
            lower_roster_position,
            upper_roster_position,
        )?;
        if contributor_position != lower_roster_position
            && contributor_position != upper_roster_position
        {
            return Err(SeedCatalogSecretLeafError320::ObjectMismatch {
                object_kind: "pair-seed",
                field: "contributor position",
            });
        }
        Ok(Self {
            scope,
            seed_catalog_identity,
            contributor_position,
        })
    }

    pub(crate) const fn scope(self) -> PseudorandomZeroSharingPairSeedScope320 {
        self.scope
    }

    pub(crate) const fn seed_catalog_identity(self) -> Hash512 {
        self.seed_catalog_identity
    }

    pub(crate) const fn contributor_position(self) -> u16 {
        self.contributor_position
    }

    fn canonical_items(self) -> Vec<CanonicalItem> {
        vec![
            CanonicalItem::hash512(self.scope.parameter_identity.into_bytes()),
            CanonicalItem::hash512(self.scope.preparation_context_identity.into_bytes()),
            CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
            CanonicalItem::hash512(self.seed_catalog_identity.into_bytes()),
            CanonicalItem::unsigned16(self.scope.participant_count),
            CanonicalItem::unsigned16(self.scope.lower_roster_position),
            CanonicalItem::unsigned16(self.scope.upper_roster_position),
            CanonicalItem::unsigned16(self.contributor_position),
        ]
    }
}

#[cfg(test)]
pub(super) const fn pair_seed_coordinate_with_catalog_identity_for_test(
    coordinate: PseudorandomZeroSharingPairSeedContributionCoordinate320,
    seed_catalog_identity: Hash512,
) -> PseudorandomZeroSharingPairSeedContributionCoordinate320 {
    PseudorandomZeroSharingPairSeedContributionCoordinate320 {
        seed_catalog_identity,
        ..coordinate
    }
}

/// Contributor-specific collective-coin source coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CollectiveCoinSourceCoordinate320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    seed_catalog_identity: Hash512,
    participant_count: u16,
    contributor_position: u16,
}

impl CollectiveCoinSourceCoordinate320 {
    pub(crate) fn from_catalog_layout(
        layout: PseudorandomZeroSharingSeedCatalogLayout320,
    ) -> Result<Self, SeedCatalogSecretLeafError320> {
        validate_participant_count(layout.participant_count(), "collective-coin source")?;
        Ok(Self {
            parameter_identity: layout.parameter_identity(),
            preparation_context_identity: layout.preparation_context().identity(),
            seed_catalog_identity: layout.identity(),
            participant_count: layout.participant_count(),
            contributor_position: layout.contributor_position(),
        })
    }

    fn from_decoded_components(
        parameter_identity: Hash512,
        preparation_context_identity: Hash512,
        seed_catalog_identity: Hash512,
        participant_count: u16,
        contributor_position: u16,
    ) -> Result<Self, SeedCatalogSecretLeafError320> {
        validate_participant_count(participant_count, "collective-coin source")?;
        if contributor_position >= participant_count {
            return Err(SeedCatalogSecretLeafError320::ObjectMismatch {
                object_kind: "collective-coin source",
                field: "contributor position",
            });
        }
        Ok(Self {
            parameter_identity,
            preparation_context_identity,
            seed_catalog_identity,
            participant_count,
            contributor_position,
        })
    }

    pub(crate) const fn parameter_identity(self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context_identity(self) -> Hash512 {
        self.preparation_context_identity
    }

    pub(crate) const fn seed_catalog_identity(self) -> Hash512 {
        self.seed_catalog_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn contributor_position(self) -> u16 {
        self.contributor_position
    }

    fn canonical_items(self) -> Vec<CanonicalItem> {
        vec![
            CanonicalItem::hash512(self.parameter_identity.into_bytes()),
            CanonicalItem::hash512(self.preparation_context_identity.into_bytes()),
            CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
            CanonicalItem::hash512(self.seed_catalog_identity.into_bytes()),
            CanonicalItem::unsigned16(self.participant_count),
            CanonicalItem::unsigned16(self.contributor_position),
        ]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingPairSeedCommitment320 {
    coordinate: PseudorandomZeroSharingPairSeedContributionCoordinate320,
    digest: Hash512,
}

impl PseudorandomZeroSharingPairSeedCommitment320 {
    pub(crate) const fn coordinate(
        self,
    ) -> PseudorandomZeroSharingPairSeedContributionCoordinate320 {
        self.coordinate
    }

    pub(crate) const fn digest(self) -> Hash512 {
        self.digest
    }

    pub(crate) fn canonical_bytes(self) -> Result<Vec<u8>, SeedCatalogSecretLeafError320> {
        encode_commitment(
            PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_COMMITMENT_OBJECT_DOMAIN,
            self.coordinate.canonical_items(),
            self.digest,
        )
    }

    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, SeedCatalogSecretLeafError320> {
        let tuple = CanonicalTuple::decode(bytes, &secret_leaf_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_COMMITMENT_OBJECT_DOMAIN,
            PAIR_COMMITMENT_OBJECT_ITEM_COUNT,
            "pair-seed commitment",
        )?;
        Ok(Self {
            coordinate: read_pair_coordinate(&tuple.items[1..1 + PAIR_COORDINATE_ITEM_COUNT])?,
            digest: read_hash512(
                &tuple.items[PAIR_COMMITMENT_OBJECT_ITEM_COUNT - 1],
                "pair-seed commitment",
                "commitment digest",
            )?,
        })
    }
}

impl fmt::Debug for PseudorandomZeroSharingPairSeedCommitment320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingPairSeedCommitment320")
            .field("coordinate", &self.coordinate)
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingPairSeedOpening320 {
    coordinate: PseudorandomZeroSharingPairSeedContributionCoordinate320,
    commitment_salt: [u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    contribution: [u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
}

impl PseudorandomZeroSharingPairSeedOpening320 {
    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, SeedCatalogSecretLeafError320> {
        encode_opening(
            PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_DOMAIN,
            self.coordinate.canonical_items(),
            &self.commitment_salt,
            &self.contribution,
        )
    }

    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, SeedCatalogSecretLeafError320> {
        let tuple = Zeroizing::new(CanonicalTuple::decode(
            bytes,
            &secret_leaf_object_decode_limits(),
        )?);
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_DOMAIN,
            PAIR_OPENING_OBJECT_ITEM_COUNT,
            "pair-seed opening",
        )?;
        Ok(Self {
            coordinate: read_pair_coordinate(&tuple.items[1..1 + PAIR_COORDINATE_ITEM_COUNT])?,
            commitment_salt: read_fixed_raw_bytes(
                &tuple.items[PAIR_OPENING_OBJECT_ITEM_COUNT - 2],
                "pair-seed opening",
                "commitment salt",
            )?,
            contribution: read_fixed_raw_bytes(
                &tuple.items[PAIR_OPENING_OBJECT_ITEM_COUNT - 1],
                "pair-seed opening",
                "seed contribution",
            )?,
        })
    }

    pub(crate) fn matches_retained_secret_material(
        &self,
        contribution: &[u8],
        commitment_salt: &[u8],
    ) -> bool {
        bool::from(self.contribution.as_slice().ct_eq(contribution))
            && bool::from(self.commitment_salt.as_slice().ct_eq(commitment_salt))
    }
}

impl fmt::Debug for PseudorandomZeroSharingPairSeedOpening320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingPairSeedOpening320")
            .field("coordinate", &self.coordinate)
            .field("commitment_salt", &"[redacted]")
            .field("contribution", &"[redacted]")
            .finish()
    }
}

impl Drop for PseudorandomZeroSharingPairSeedOpening320 {
    fn drop(&mut self) {
        self.commitment_salt.zeroize();
        self.contribution.zeroize();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CollectiveCoinSourceCommitment320 {
    coordinate: CollectiveCoinSourceCoordinate320,
    digest: Hash512,
}

impl CollectiveCoinSourceCommitment320 {
    pub(crate) const fn coordinate(self) -> CollectiveCoinSourceCoordinate320 {
        self.coordinate
    }

    pub(crate) const fn digest(self) -> Hash512 {
        self.digest
    }

    pub(crate) fn canonical_bytes(self) -> Result<Vec<u8>, SeedCatalogSecretLeafError320> {
        encode_commitment(
            COLLECTIVE_COIN_SOURCE_COMMITMENT_OBJECT_DOMAIN,
            self.coordinate.canonical_items(),
            self.digest,
        )
    }

    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, SeedCatalogSecretLeafError320> {
        let tuple = CanonicalTuple::decode(bytes, &secret_leaf_object_decode_limits())?;
        require_object_header(
            &tuple,
            COLLECTIVE_COIN_SOURCE_COMMITMENT_OBJECT_DOMAIN,
            COLLECTIVE_COIN_COMMITMENT_OBJECT_ITEM_COUNT,
            "collective-coin source commitment",
        )?;
        Ok(Self {
            coordinate: read_collective_coin_coordinate(
                &tuple.items[1..1 + COLLECTIVE_COIN_COORDINATE_ITEM_COUNT],
            )?,
            digest: read_hash512(
                &tuple.items[COLLECTIVE_COIN_COMMITMENT_OBJECT_ITEM_COUNT - 1],
                "collective-coin source commitment",
                "commitment digest",
            )?,
        })
    }
}

impl fmt::Debug for CollectiveCoinSourceCommitment320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectiveCoinSourceCommitment320")
            .field("coordinate", &self.coordinate)
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct CollectiveCoinSourceOpening320 {
    coordinate: CollectiveCoinSourceCoordinate320,
    commitment_salt: [u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    source: [u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
}

impl CollectiveCoinSourceOpening320 {
    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, SeedCatalogSecretLeafError320> {
        encode_opening(
            COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_DOMAIN,
            self.coordinate.canonical_items(),
            &self.commitment_salt,
            &self.source,
        )
    }

    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, SeedCatalogSecretLeafError320> {
        let tuple = Zeroizing::new(CanonicalTuple::decode(
            bytes,
            &secret_leaf_object_decode_limits(),
        )?);
        require_object_header(
            &tuple,
            COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_DOMAIN,
            COLLECTIVE_COIN_OPENING_OBJECT_ITEM_COUNT,
            "collective-coin source opening",
        )?;
        Ok(Self {
            coordinate: read_collective_coin_coordinate(
                &tuple.items[1..1 + COLLECTIVE_COIN_COORDINATE_ITEM_COUNT],
            )?,
            commitment_salt: read_fixed_raw_bytes(
                &tuple.items[COLLECTIVE_COIN_OPENING_OBJECT_ITEM_COUNT - 2],
                "collective-coin source opening",
                "commitment salt",
            )?,
            source: read_fixed_raw_bytes(
                &tuple.items[COLLECTIVE_COIN_OPENING_OBJECT_ITEM_COUNT - 1],
                "collective-coin source opening",
                "coin source",
            )?,
        })
    }

    pub(crate) fn matches_retained_secret_material(
        &self,
        source: &[u8],
        commitment_salt: &[u8],
    ) -> bool {
        bool::from(self.source.as_slice().ct_eq(source))
            && bool::from(self.commitment_salt.as_slice().ct_eq(commitment_salt))
    }
}

impl fmt::Debug for CollectiveCoinSourceOpening320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectiveCoinSourceOpening320")
            .field("coordinate", &self.coordinate)
            .field("commitment_salt", &"[redacted]")
            .field("source", &"[redacted]")
            .finish()
    }
}

impl Drop for CollectiveCoinSourceOpening320 {
    fn drop(&mut self) {
        self.commitment_salt.zeroize();
        self.source.zeroize();
    }
}

pub(crate) struct CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320 {
    coordinate: PseudorandomZeroSharingPairSeedContributionCoordinate320,
    contribution: [u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
}

impl CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320 {
    pub(crate) const fn coordinate(
        &self,
    ) -> PseudorandomZeroSharingPairSeedContributionCoordinate320 {
        self.coordinate
    }

    pub(super) fn into_parts(
        mut self,
    ) -> (
        PseudorandomZeroSharingPairSeedContributionCoordinate320,
        [u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
    ) {
        let contribution = core::mem::replace(
            &mut self.contribution,
            [0_u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
        );
        (self.coordinate, contribution)
    }
}

impl fmt::Debug for CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320")
            .field("coordinate", &self.coordinate)
            .field("contribution", &"[redacted]")
            .finish()
    }
}

impl Drop for CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320 {
    fn drop(&mut self) {
        self.contribution.zeroize();
    }
}

pub(crate) struct CommitmentMatchedCollectiveCoinSource320 {
    coordinate: CollectiveCoinSourceCoordinate320,
    source: [u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
}

impl CommitmentMatchedCollectiveCoinSource320 {
    pub(crate) const fn coordinate(&self) -> CollectiveCoinSourceCoordinate320 {
        self.coordinate
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH] {
        &self.source
    }

    pub(super) fn into_parts(
        mut self,
    ) -> (
        CollectiveCoinSourceCoordinate320,
        [u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
    ) {
        let source =
            core::mem::replace(&mut self.source, [0_u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH]);
        (self.coordinate, source)
    }
}

impl fmt::Debug for CommitmentMatchedCollectiveCoinSource320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommitmentMatchedCollectiveCoinSource320")
            .field("coordinate", &self.coordinate)
            .field("source", &"[redacted]")
            .finish()
    }
}

impl Drop for CommitmentMatchedCollectiveCoinSource320 {
    fn drop(&mut self) {
        self.source.zeroize();
    }
}

/// Creates one candidate pair contribution from caller-supplied secret bytes.
///
/// This does not establish randomness, source authentication, catalog
/// inclusion, delivery, or receipt authority.
pub(crate) fn create_pseudorandom_zero_sharing_pair_seed_contribution_320(
    coordinate: PseudorandomZeroSharingPairSeedContributionCoordinate320,
    contribution: [u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
    commitment_salt: [u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
) -> Result<
    (
        PseudorandomZeroSharingPairSeedCommitment320,
        PseudorandomZeroSharingPairSeedOpening320,
    ),
    SeedCatalogSecretLeafError320,
> {
    let opening = PseudorandomZeroSharingPairSeedOpening320 {
        coordinate,
        commitment_salt,
        contribution,
    };
    let digest = derive_secret_leaf_digest(
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_SECRET_LEAF_DOMAIN,
        coordinate.canonical_items(),
        &opening.commitment_salt,
        &opening.contribution,
    )?;
    Ok((
        PseudorandomZeroSharingPairSeedCommitment320 { coordinate, digest },
        opening,
    ))
}

/// Positively matches one canonical pair contribution to its commitment.
pub(crate) fn verify_pseudorandom_zero_sharing_pair_seed_contribution_320(
    expected_coordinate: PseudorandomZeroSharingPairSeedContributionCoordinate320,
    commitment_bytes: &[u8],
    opening_bytes: &[u8],
) -> Result<
    CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320,
    SeedCatalogSecretLeafError320,
> {
    let commitment =
        PseudorandomZeroSharingPairSeedCommitment320::from_canonical_bytes(commitment_bytes)?;
    let opening = PseudorandomZeroSharingPairSeedOpening320::from_canonical_bytes(opening_bytes)?;
    if commitment.coordinate != expected_coordinate || opening.coordinate != expected_coordinate {
        return Err(SeedCatalogSecretLeafError320::PairCoordinateMismatch);
    }
    let expected_digest = derive_secret_leaf_digest(
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_SECRET_LEAF_DOMAIN,
        opening.coordinate.canonical_items(),
        &opening.commitment_salt,
        &opening.contribution,
    )?;
    if !bool::from(
        commitment
            .digest
            .as_bytes()
            .ct_eq(expected_digest.as_bytes()),
    ) {
        return Err(SeedCatalogSecretLeafError320::PairCommitmentMismatch);
    }
    Ok(
        CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320 {
            coordinate: opening.coordinate,
            contribution: opening.contribution,
        },
    )
}

/// Creates one candidate collective-coin source from caller-supplied bytes.
pub(crate) fn create_collective_coin_source_320(
    coordinate: CollectiveCoinSourceCoordinate320,
    source: [u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
    commitment_salt: [u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
) -> Result<
    (
        CollectiveCoinSourceCommitment320,
        CollectiveCoinSourceOpening320,
    ),
    SeedCatalogSecretLeafError320,
> {
    let opening = CollectiveCoinSourceOpening320 {
        coordinate,
        commitment_salt,
        source,
    };
    let digest = derive_secret_leaf_digest(
        COLLECTIVE_COIN_SOURCE_SECRET_LEAF_DOMAIN,
        coordinate.canonical_items(),
        &opening.commitment_salt,
        &opening.source,
    )?;
    Ok((
        CollectiveCoinSourceCommitment320 { coordinate, digest },
        opening,
    ))
}

/// Positively matches one canonical collective-coin source to its commitment.
pub(crate) fn verify_collective_coin_source_320(
    expected_coordinate: CollectiveCoinSourceCoordinate320,
    commitment_bytes: &[u8],
    opening_bytes: &[u8],
) -> Result<CommitmentMatchedCollectiveCoinSource320, SeedCatalogSecretLeafError320> {
    let commitment = CollectiveCoinSourceCommitment320::from_canonical_bytes(commitment_bytes)?;
    let opening = CollectiveCoinSourceOpening320::from_canonical_bytes(opening_bytes)?;
    if commitment.coordinate != expected_coordinate || opening.coordinate != expected_coordinate {
        return Err(SeedCatalogSecretLeafError320::CollectiveCoinCoordinateMismatch);
    }
    let expected_digest = derive_secret_leaf_digest(
        COLLECTIVE_COIN_SOURCE_SECRET_LEAF_DOMAIN,
        opening.coordinate.canonical_items(),
        &opening.commitment_salt,
        &opening.source,
    )?;
    if !bool::from(
        commitment
            .digest
            .as_bytes()
            .ct_eq(expected_digest.as_bytes()),
    ) {
        return Err(SeedCatalogSecretLeafError320::CollectiveCoinCommitmentMismatch);
    }
    Ok(CommitmentMatchedCollectiveCoinSource320 {
        coordinate: opening.coordinate,
        source: opening.source,
    })
}

/// Recomputes one pair commitment from its opening and checks the exact
/// unsigned catalog path. No redundant commitment object is needed in the
/// private-delivery stream.
pub(crate) fn verify_pseudorandom_zero_sharing_pair_seed_opening_catalog_inclusion_320(
    expected_layout: PseudorandomZeroSharingSeedCatalogLayout320,
    counterpart_position: u16,
    root_body_bytes: &[u8],
    opening_bytes: &[u8],
    inclusion_proof_bytes: &[u8],
) -> Result<
    (
        CatalogIncludedSeedCommitment320,
        CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320,
    ),
    SeedCatalogSecretLeafError320,
> {
    let expected_coordinate =
        PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
            expected_layout,
            counterpart_position,
        )?;
    let opening = PseudorandomZeroSharingPairSeedOpening320::from_canonical_bytes(opening_bytes)?;
    if opening.coordinate != expected_coordinate {
        return Err(SeedCatalogSecretLeafError320::PairCoordinateMismatch);
    }
    let commitment_digest = derive_secret_leaf_digest(
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_SECRET_LEAF_DOMAIN,
        opening.coordinate.canonical_items(),
        &opening.commitment_salt,
        &opening.contribution,
    )?;
    let catalog_inclusion = verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320(
        expected_layout,
        root_body_bytes,
        expected_layout.pair_coordinate(counterpart_position)?,
        commitment_digest,
        inclusion_proof_bytes,
    )?;
    Ok((
        catalog_inclusion,
        CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320 {
            coordinate: opening.coordinate,
            contribution: opening.contribution,
        },
    ))
}

/// Recomputes one coin commitment from its opening and checks the exact
/// unsigned catalog path. No redundant commitment object is needed later.
pub(crate) fn verify_collective_coin_source_opening_catalog_inclusion_320(
    expected_layout: PseudorandomZeroSharingSeedCatalogLayout320,
    root_body_bytes: &[u8],
    opening_bytes: &[u8],
    inclusion_proof_bytes: &[u8],
) -> Result<
    (
        CatalogIncludedSeedCommitment320,
        CommitmentMatchedCollectiveCoinSource320,
    ),
    SeedCatalogSecretLeafError320,
> {
    let expected_coordinate =
        CollectiveCoinSourceCoordinate320::from_catalog_layout(expected_layout)?;
    let opening = CollectiveCoinSourceOpening320::from_canonical_bytes(opening_bytes)?;
    if opening.coordinate != expected_coordinate {
        return Err(SeedCatalogSecretLeafError320::CollectiveCoinCoordinateMismatch);
    }
    let commitment_digest = derive_secret_leaf_digest(
        COLLECTIVE_COIN_SOURCE_SECRET_LEAF_DOMAIN,
        opening.coordinate.canonical_items(),
        &opening.commitment_salt,
        &opening.source,
    )?;
    let catalog_inclusion = verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320(
        expected_layout,
        root_body_bytes,
        expected_layout.collective_coin_coordinate(),
        commitment_digest,
        inclusion_proof_bytes,
    )?;
    Ok((
        catalog_inclusion,
        CommitmentMatchedCollectiveCoinSource320 {
            coordinate: opening.coordinate,
            source: opening.source,
        },
    ))
}

fn encode_commitment(
    domain: &'static str,
    mut coordinate_items: Vec<CanonicalItem>,
    digest: Hash512,
) -> Result<Vec<u8>, SeedCatalogSecretLeafError320> {
    let mut items = Vec::with_capacity(coordinate_items.len() + 2);
    items.push(CanonicalItem::nonempty_ascii(domain)?);
    items.append(&mut coordinate_items);
    items.push(CanonicalItem::hash512(digest.into_bytes()));
    Ok(CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        items,
    )
    .encode()?)
}

fn encode_opening<const SECRET_BYTE_LENGTH: usize>(
    domain: &'static str,
    mut coordinate_items: Vec<CanonicalItem>,
    commitment_salt: &[u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    secret: &[u8; SECRET_BYTE_LENGTH],
) -> Result<Zeroizing<Vec<u8>>, SeedCatalogSecretLeafError320> {
    let mut items = Vec::with_capacity(coordinate_items.len() + 3);
    items.push(CanonicalItem::nonempty_ascii(domain)?);
    items.append(&mut coordinate_items);
    items.push(CanonicalItem::fixed_bytes(*commitment_salt)?);
    items.push(CanonicalItem::fixed_bytes(*secret)?);
    let tuple = Zeroizing::new(CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        items,
    ));
    Ok(Zeroizing::new(tuple.encode()?))
}

fn derive_secret_leaf_digest<const SECRET_BYTE_LENGTH: usize>(
    domain: &'static str,
    prefix_items: Vec<CanonicalItem>,
    commitment_salt: &[u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    secret: &[u8; SECRET_BYTE_LENGTH],
) -> Result<Hash512, SeedCatalogSecretLeafError320> {
    let payload_byte_length = commitment_salt.len().checked_add(secret.len()).ok_or(
        SeedCatalogSecretLeafError320::ObjectMismatch {
            object_kind: "secret leaf",
            field: "payload length",
        },
    )?;
    let hash_failure = |_| SeedCatalogSecretLeafError320::CommitmentHashFailure {
        leaf_domain: domain,
    };
    let mut hasher = StreamingFoundationTupleHash512::new_variable_bytes(
        domain,
        &prefix_items,
        payload_byte_length,
    )
    .map_err(hash_failure)?;
    hasher.absorb(commitment_salt).map_err(hash_failure)?;
    hasher.absorb(secret).map_err(hash_failure)?;
    hasher.finalize().map_err(hash_failure)
}

fn read_pair_coordinate(
    items: &[CanonicalItem],
) -> Result<PseudorandomZeroSharingPairSeedContributionCoordinate320, SeedCatalogSecretLeafError320>
{
    require_coordinate_item_count(items, PAIR_COORDINATE_ITEM_COUNT, "pair-seed")?;
    require_attempt_ordinal(&items[2], "pair-seed")?;
    PseudorandomZeroSharingPairSeedContributionCoordinate320::from_decoded_components(
        read_hash512(&items[0], "pair-seed", "parameter identity")?,
        read_hash512(&items[1], "pair-seed", "preparation context identity")?,
        read_hash512(&items[3], "pair-seed", "seed catalog identity")?,
        read_u16(&items[4], "pair-seed", "participant count")?,
        read_u16(&items[5], "pair-seed", "lower roster position")?,
        read_u16(&items[6], "pair-seed", "upper roster position")?,
        read_u16(&items[7], "pair-seed", "contributor position")?,
    )
}

fn read_collective_coin_coordinate(
    items: &[CanonicalItem],
) -> Result<CollectiveCoinSourceCoordinate320, SeedCatalogSecretLeafError320> {
    require_coordinate_item_count(
        items,
        COLLECTIVE_COIN_COORDINATE_ITEM_COUNT,
        "collective-coin source",
    )?;
    require_attempt_ordinal(&items[2], "collective-coin source")?;
    CollectiveCoinSourceCoordinate320::from_decoded_components(
        read_hash512(&items[0], "collective-coin source", "parameter identity")?,
        read_hash512(
            &items[1],
            "collective-coin source",
            "preparation context identity",
        )?,
        read_hash512(&items[3], "collective-coin source", "seed catalog identity")?,
        read_u16(&items[4], "collective-coin source", "participant count")?,
        read_u16(&items[5], "collective-coin source", "contributor position")?,
    )
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
    object_kind: &'static str,
) -> Result<(), SeedCatalogSecretLeafError320> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(object_mismatch(object_kind, "schema identifier"));
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(object_mismatch(object_kind, "schema version"));
    }
    if tuple.items.len() != expected_item_count {
        return Err(object_mismatch(object_kind, "item count"));
    }
    let domain_item = &tuple.items[0];
    if domain_item.item_type() != CanonicalItemType::Ascii
        || domain_item.variable_value_bytes()? != expected_domain.as_bytes()
    {
        return Err(object_mismatch(object_kind, "object domain"));
    }
    Ok(())
}

fn require_coordinate_item_count(
    items: &[CanonicalItem],
    expected_item_count: usize,
    object_kind: &'static str,
) -> Result<(), SeedCatalogSecretLeafError320> {
    if items.len() != expected_item_count {
        return Err(object_mismatch(object_kind, "coordinate item count"));
    }
    Ok(())
}

fn require_attempt_ordinal(
    item: &CanonicalItem,
    object_kind: &'static str,
) -> Result<(), SeedCatalogSecretLeafError320> {
    if read_u16(item, object_kind, "preparation attempt ordinal")? != PREPARATION_ATTEMPT_ORDINAL {
        return Err(object_mismatch(object_kind, "preparation attempt ordinal"));
    }
    Ok(())
}

fn read_hash512(
    item: &CanonicalItem,
    object_kind: &'static str,
    field: &'static str,
) -> Result<Hash512, SeedCatalogSecretLeafError320> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(object_mismatch(object_kind, field));
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| object_mismatch(object_kind, field))?;
    Ok(Hash512::from_bytes(bytes))
}

fn read_u16(
    item: &CanonicalItem,
    object_kind: &'static str,
    field: &'static str,
) -> Result<u16, SeedCatalogSecretLeafError320> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(object_mismatch(object_kind, field));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| object_mismatch(object_kind, field))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_fixed_raw_bytes<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    object_kind: &'static str,
    field: &'static str,
) -> Result<[u8; BYTE_LENGTH], SeedCatalogSecretLeafError320> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(object_mismatch(object_kind, field));
    }
    item.canonical_bytes()
        .try_into()
        .map_err(|_| object_mismatch(object_kind, field))
}

fn validate_participant_count(
    participant_count: u16,
    object_kind: &'static str,
) -> Result<(), SeedCatalogSecretLeafError320> {
    if !(MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT)
        .contains(&participant_count)
    {
        return Err(object_mismatch(object_kind, "participant count"));
    }
    Ok(())
}

const fn object_mismatch(
    object_kind: &'static str,
    field: &'static str,
) -> SeedCatalogSecretLeafError320 {
    SeedCatalogSecretLeafError320::ObjectMismatch { object_kind, field }
}

fn secret_leaf_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_SECRET_LEAF_OBJECT_BYTE_LENGTH,
        maximum_item_count: PAIR_OPENING_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_SECRET_LEAF_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_SECRET_LEAF_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_SECRET_LEAF_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}
