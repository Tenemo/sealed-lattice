use subtle::ConstantTimeEq;

use crate::{
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalDecodeLimits,
        CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, hash_foundation_tuple_512,
    },
    hashing::hash_framed_parts_512,
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    pseudorandom_zero_sharing_subset_seed_320::{
        CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320,
        PseudorandomZeroSharingSubsetMasterScope320,
        PseudorandomZeroSharingSubsetSeedCoordinate320,
        verify_pseudorandom_zero_sharing_subset_seed_opening_320,
    },
    replicated_random_sharing::{
        ReplicatedRandomSharingGeometry, ReplicatedRandomSharingSubset,
        ReplicatedRandomSharingSubsetIterator,
    },
};

const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_SOURCE: &[u8] =
    include_bytes!("pseudorandom_zero_sharing_seed_catalog_320.rs");
const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_VERSION: u16 = 1;
const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const SUBSET_COORDINATE_KIND_CODE: u8 = 1;
const PAIR_COORDINATE_KIND_CODE: u8 = 2;
const COLLECTIVE_COIN_COORDINATE_KIND_CODE: u8 = 3;
const COLLECTIVE_COIN_LEAF_COUNT: u64 = 1;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_COMPILER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-compiler-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_LEAF_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-leaf";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_PADDING_LEAF_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-padding-leaf";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INTERNAL_NODE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-internal-node";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-body";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_BODY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-body-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INCLUSION_PROOF_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-inclusion-proof";

const ROOT_BODY_ITEM_COUNT: usize = 15;
const INCLUSION_PROOF_PREFIX_ITEM_COUNT: usize = 4;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;
const MAXIMUM_SEED_CATALOG_CONTROL_OBJECT_BYTE_LENGTH: usize = 4_096;
const MAXIMUM_SEED_CATALOG_CONTROL_OBJECT_ITEM_COUNT: usize = 64;
const MAXIMUM_SEED_CATALOG_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 512;
const MAXIMUM_SEED_CATALOG_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 16_384;

/// One formula-derived leaf coordinate in a participant's seed catalog.
///
/// The catalog owner and preparation context live in the surrounding layout.
/// Pair endpoints are canonicalized into ascending roster order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedCatalogCoordinate320 {
    Subset(ReplicatedRandomSharingSubset),
    Pair {
        lower_roster_position: u16,
        upper_roster_position: u16,
    },
    CollectiveCoin,
}

impl PseudorandomZeroSharingSeedCatalogCoordinate320 {
    const fn kind_code(self) -> u8 {
        match self {
            Self::Subset(_) => SUBSET_COORDINATE_KIND_CODE,
            Self::Pair { .. } => PAIR_COORDINATE_KIND_CODE,
            Self::CollectiveCoin => COLLECTIVE_COIN_COORDINATE_KIND_CODE,
        }
    }

    fn append_hash_items(self, items: &mut Vec<CanonicalItem>) {
        items.push(CanonicalItem::unsigned8(self.kind_code()));
        match self {
            Self::Subset(subset) => {
                items.push(CanonicalItem::unsigned32(subset.excluded_position_mask()));
            }
            Self::Pair {
                lower_roster_position,
                upper_roster_position,
            } => {
                items.push(CanonicalItem::unsigned16(lower_roster_position));
                items.push(CanonicalItem::unsigned16(upper_roster_position));
            }
            Self::CollectiveCoin => {}
        }
    }
}

/// Context-independent tree geometry shared by the catalog and its resource
/// compiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PseudorandomZeroSharingSeedCatalogShape320 {
    subset_leaf_count: u64,
    pair_leaf_count: u64,
    leaf_count: u64,
    tree_capacity: u64,
    tree_height: u16,
}

impl PseudorandomZeroSharingSeedCatalogShape320 {
    fn derive(participant_count: u16) -> Result<Self, TallyPreparationError> {
        let geometry = ReplicatedRandomSharingGeometry::derive(participant_count)?;
        let subset_leaf_count = geometry.authorized_subset_count_per_participant;
        let pair_leaf_count = u64::from(
            participant_count
                .checked_sub(1)
                .ok_or(TallyPreparationError::GeometryMismatch)?,
        );
        let leaf_count = subset_leaf_count
            .checked_add(pair_leaf_count)
            .and_then(|count| count.checked_add(COLLECTIVE_COIN_LEAF_COUNT))
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        let tree_capacity = leaf_count
            .checked_next_power_of_two()
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        let tree_height = u16::try_from(tree_capacity.ilog2())
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        Ok(Self {
            subset_leaf_count,
            pair_leaf_count,
            leaf_count,
            tree_capacity,
            tree_height,
        })
    }
}

/// Deterministic, value-independent coordinate owner for one sender catalog.
///
/// The identity is computed before any commitment value. It binds the exact
/// formula-derived counts, tree geometry, context, sender, and compiler source,
/// so it can safely appear inside salted leaf commitments without referring to
/// the later Merkle root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogLayout320 {
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    contributor_position: u16,
    compiler_identity: Hash512,
    identity: Hash512,
    subset_leaf_count: u64,
    pair_leaf_count: u64,
    leaf_count: u64,
    tree_capacity: u64,
    tree_height: u16,
}

impl PseudorandomZeroSharingSeedCatalogLayout320 {
    pub(crate) fn derive(
        parameter_identity: Hash512,
        preparation_context: TallyPreparationContext,
        contributor_position: u16,
    ) -> Result<Self, TallyPreparationError> {
        let participant_count = preparation_context.participant_count();
        if contributor_position >= participant_count {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingSeedCatalogContributorPositionOutOfRange {
                    contributor_position,
                    participant_count,
                },
            );
        }
        let shape = PseudorandomZeroSharingSeedCatalogShape320::derive(participant_count)?;
        let compiler_identity = pseudorandom_zero_sharing_seed_catalog_compiler_identity()?;
        let identity = hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_IDENTITY_DOMAIN,
            &[
                CanonicalItem::hash512(parameter_identity.into_bytes()),
                CanonicalItem::hash512(preparation_context.identity().into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::hash512(compiler_identity.into_bytes()),
                CanonicalItem::unsigned16(participant_count),
                CanonicalItem::unsigned16(contributor_position),
                CanonicalItem::unsigned64(shape.subset_leaf_count),
                CanonicalItem::unsigned64(shape.pair_leaf_count),
                CanonicalItem::unsigned64(COLLECTIVE_COIN_LEAF_COUNT),
                CanonicalItem::unsigned64(shape.leaf_count),
                CanonicalItem::unsigned64(shape.tree_capacity),
                CanonicalItem::unsigned16(shape.tree_height),
            ],
        )?;
        Ok(Self {
            parameter_identity,
            preparation_context,
            contributor_position,
            compiler_identity,
            identity,
            subset_leaf_count: shape.subset_leaf_count,
            pair_leaf_count: shape.pair_leaf_count,
            leaf_count: shape.leaf_count,
            tree_capacity: shape.tree_capacity,
            tree_height: shape.tree_height,
        })
    }

    pub(crate) const fn parameter_identity(self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context(self) -> TallyPreparationContext {
        self.preparation_context
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.preparation_context.participant_count()
    }

    pub(crate) const fn contributor_position(self) -> u16 {
        self.contributor_position
    }

    pub(crate) const fn compiler_identity(self) -> Hash512 {
        self.compiler_identity
    }

    pub(crate) const fn identity(self) -> Hash512 {
        self.identity
    }

    pub(crate) const fn subset_leaf_count(self) -> u64 {
        self.subset_leaf_count
    }

    pub(crate) const fn pair_leaf_count(self) -> u64 {
        self.pair_leaf_count
    }

    pub(crate) const fn collective_coin_leaf_count(self) -> u64 {
        COLLECTIVE_COIN_LEAF_COUNT
    }

    pub(crate) const fn leaf_count(self) -> u64 {
        self.leaf_count
    }

    pub(crate) const fn tree_capacity(self) -> u64 {
        self.tree_capacity
    }

    pub(crate) const fn tree_height(self) -> u16 {
        self.tree_height
    }

    pub(crate) fn coordinates(
        self,
    ) -> Result<PseudorandomZeroSharingSeedCatalogCoordinateIterator320, TallyPreparationError>
    {
        Ok(PseudorandomZeroSharingSeedCatalogCoordinateIterator320 {
            subset_iterator: ReplicatedRandomSharingSubset::iter(self.participant_count())?,
            contributor_position: self.contributor_position,
            participant_count: self.participant_count(),
            next_pair_counterpart_position: 0,
            collective_coin_emitted: false,
            remaining: usize::try_from(self.leaf_count)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        })
    }

    pub(crate) fn coordinate(
        self,
        leaf_ordinal: u64,
    ) -> Result<PseudorandomZeroSharingSeedCatalogCoordinate320, TallyPreparationError> {
        if leaf_ordinal >= self.leaf_count {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingSeedCatalogLeafOrdinalOutOfRange {
                    leaf_ordinal,
                    leaf_count: self.leaf_count,
                },
            );
        }
        self.coordinates()?
            .nth(
                usize::try_from(leaf_ordinal)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            )
            .ok_or(TallyPreparationError::GeometryMismatch)
    }

    pub(crate) fn subset_coordinate(
        self,
        subset: ReplicatedRandomSharingSubset,
    ) -> Result<PseudorandomZeroSharingSeedCatalogCoordinate320, TallyPreparationError> {
        let coordinate = PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset);
        self.validate_coordinate(coordinate)?;
        Ok(coordinate)
    }

    pub(crate) fn pair_coordinate(
        self,
        counterpart_position: u16,
    ) -> Result<PseudorandomZeroSharingSeedCatalogCoordinate320, TallyPreparationError> {
        if counterpart_position >= self.participant_count()
            || counterpart_position == self.contributor_position
        {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingSeedCatalogCoordinateMismatch,
            );
        }
        let coordinate = PseudorandomZeroSharingSeedCatalogCoordinate320::Pair {
            lower_roster_position: self.contributor_position.min(counterpart_position),
            upper_roster_position: self.contributor_position.max(counterpart_position),
        };
        self.validate_coordinate(coordinate)?;
        Ok(coordinate)
    }

    pub(crate) fn collective_coin_coordinate(
        self,
    ) -> PseudorandomZeroSharingSeedCatalogCoordinate320 {
        PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin
    }

    pub(crate) fn subset_seed_coordinate(
        self,
        subset: ReplicatedRandomSharingSubset,
    ) -> Result<PseudorandomZeroSharingSubsetSeedCoordinate320, TallyPreparationError> {
        self.validate_coordinate(PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(
            subset,
        ))?;
        let master_scope = PseudorandomZeroSharingSubsetMasterScope320::new(
            self.parameter_identity,
            self.preparation_context,
            subset,
        )?;
        PseudorandomZeroSharingSubsetSeedCoordinate320::new(
            master_scope,
            self.identity,
            self.contributor_position,
        )
    }

    pub(crate) fn leaf_ordinal(
        self,
        coordinate: PseudorandomZeroSharingSeedCatalogCoordinate320,
    ) -> Result<u64, TallyPreparationError> {
        self.validate_coordinate(coordinate)?;
        match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) => {
                subset_rank_excluding_contributor(subset, self.contributor_position)
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::Pair {
                lower_roster_position,
                upper_roster_position,
            } => {
                let counterpart_position = if lower_roster_position == self.contributor_position {
                    upper_roster_position
                } else {
                    lower_roster_position
                };
                let relative_pair_ordinal = if counterpart_position < self.contributor_position {
                    u64::from(counterpart_position)
                } else {
                    u64::from(counterpart_position - 1)
                };
                self.subset_leaf_count
                    .checked_add(relative_pair_ordinal)
                    .ok_or(TallyPreparationError::ArithmeticOverflow)
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => self
                .subset_leaf_count
                .checked_add(self.pair_leaf_count)
                .ok_or(TallyPreparationError::ArithmeticOverflow),
        }
    }

    fn validate_coordinate(
        self,
        coordinate: PseudorandomZeroSharingSeedCatalogCoordinate320,
    ) -> Result<(), TallyPreparationError> {
        match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) => {
                if subset.participant_count() != self.participant_count()
                    || !subset.contains(self.contributor_position)?
                {
                    return Err(
                        TallyPreparationError::PseudorandomZeroSharingSeedCatalogCoordinateMismatch,
                    );
                }
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::Pair {
                lower_roster_position,
                upper_roster_position,
            } => {
                if lower_roster_position >= upper_roster_position
                    || upper_roster_position >= self.participant_count()
                    || (lower_roster_position != self.contributor_position
                        && upper_roster_position != self.contributor_position)
                {
                    return Err(
                        TallyPreparationError::PseudorandomZeroSharingSeedCatalogCoordinateMismatch,
                    );
                }
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => {}
        }
        Ok(())
    }
}

pub(crate) struct PseudorandomZeroSharingSeedCatalogCoordinateIterator320 {
    subset_iterator: ReplicatedRandomSharingSubsetIterator,
    contributor_position: u16,
    participant_count: u16,
    next_pair_counterpart_position: u16,
    collective_coin_emitted: bool,
    remaining: usize,
}

impl Iterator for PseudorandomZeroSharingSeedCatalogCoordinateIterator320 {
    type Item = PseudorandomZeroSharingSeedCatalogCoordinate320;

    fn next(&mut self) -> Option<Self::Item> {
        for subset in self.subset_iterator.by_ref() {
            let contributor_bit = 1_u32 << u32::from(self.contributor_position);
            if subset.excluded_position_mask() & contributor_bit == 0 {
                self.remaining = self.remaining.saturating_sub(1);
                return Some(PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(
                    subset,
                ));
            }
        }
        while self.next_pair_counterpart_position < self.participant_count {
            let counterpart_position = self.next_pair_counterpart_position;
            self.next_pair_counterpart_position += 1;
            if counterpart_position != self.contributor_position {
                self.remaining = self.remaining.saturating_sub(1);
                return Some(PseudorandomZeroSharingSeedCatalogCoordinate320::Pair {
                    lower_roster_position: self.contributor_position.min(counterpart_position),
                    upper_roster_position: self.contributor_position.max(counterpart_position),
                });
            }
        }
        if !self.collective_coin_emitted {
            self.collective_coin_emitted = true;
            self.remaining = self.remaining.saturating_sub(1);
            return Some(PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin);
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for PseudorandomZeroSharingSeedCatalogCoordinateIterator320 {}

/// Unsigned root body for one complete participant seed catalog.
///
/// This body has no roster signature or state reservation. Its identity is a
/// future detached-signature input, not preparation authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootBody320 {
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    root_digest: Hash512,
}

impl PseudorandomZeroSharingSeedCatalogRootBody320 {
    pub(crate) const fn layout(self) -> PseudorandomZeroSharingSeedCatalogLayout320 {
        self.layout
    }

    pub(crate) const fn root_digest(self) -> Hash512 {
        self.root_digest
    }

    pub(crate) fn canonical_bytes(self) -> Result<Vec<u8>, TallyPreparationError> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.layout.parameter_identity.into_bytes()),
                CanonicalItem::hash512(self.layout.preparation_context.identity().into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::hash512(self.layout.compiler_identity.into_bytes()),
                CanonicalItem::hash512(self.layout.identity.into_bytes()),
                CanonicalItem::unsigned16(self.layout.participant_count()),
                CanonicalItem::unsigned16(self.layout.contributor_position),
                CanonicalItem::unsigned64(self.layout.subset_leaf_count),
                CanonicalItem::unsigned64(self.layout.pair_leaf_count),
                CanonicalItem::unsigned64(COLLECTIVE_COIN_LEAF_COUNT),
                CanonicalItem::unsigned64(self.layout.leaf_count),
                CanonicalItem::unsigned64(self.layout.tree_capacity),
                CanonicalItem::unsigned16(self.layout.tree_height),
                CanonicalItem::hash512(self.root_digest.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub(crate) fn from_canonical_bytes(
        expected_layout: PseudorandomZeroSharingSeedCatalogLayout320,
        bytes: &[u8],
    ) -> Result<Self, TallyPreparationError> {
        let tuple = CanonicalTuple::decode(bytes, &seed_catalog_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_BODY_DOMAIN,
            ROOT_BODY_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected_layout.parameter_identity,
            "parameter identity",
        )?;
        require_hash(
            &tuple.items[2],
            expected_layout.preparation_context.identity(),
            "preparation context identity",
        )?;
        require_u16(
            &tuple.items[3],
            PREPARATION_ATTEMPT_ORDINAL,
            "preparation attempt ordinal",
        )?;
        require_hash(
            &tuple.items[4],
            expected_layout.compiler_identity,
            "catalog compiler identity",
        )?;
        require_hash(
            &tuple.items[5],
            expected_layout.identity,
            "catalog identity",
        )?;
        require_u16(
            &tuple.items[6],
            expected_layout.participant_count(),
            "participant count",
        )?;
        require_u16(
            &tuple.items[7],
            expected_layout.contributor_position,
            "contributor position",
        )?;
        require_u64(
            &tuple.items[8],
            expected_layout.subset_leaf_count,
            "subset leaf count",
        )?;
        require_u64(
            &tuple.items[9],
            expected_layout.pair_leaf_count,
            "pair leaf count",
        )?;
        require_u64(
            &tuple.items[10],
            COLLECTIVE_COIN_LEAF_COUNT,
            "collective-coin leaf count",
        )?;
        require_u64(&tuple.items[11], expected_layout.leaf_count, "leaf count")?;
        require_u64(
            &tuple.items[12],
            expected_layout.tree_capacity,
            "tree capacity",
        )?;
        require_u16(&tuple.items[13], expected_layout.tree_height, "tree height")?;
        Ok(Self {
            layout: expected_layout,
            root_digest: read_hash(&tuple.items[14], "root digest")?,
        })
    }

    pub(crate) fn identity(self) -> Result<Hash512, TallyPreparationError> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_BODY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogInclusionProof320 {
    catalog_identity: Hash512,
    leaf_ordinal: u64,
    sibling_digests: Box<[Hash512]>,
}

impl PseudorandomZeroSharingSeedCatalogInclusionProof320 {
    pub(crate) fn canonical_byte_length_for_participant_count(
        participant_count: u16,
    ) -> Result<usize, TallyPreparationError> {
        let shape = PseudorandomZeroSharingSeedCatalogShape320::derive(participant_count)?;
        Self::canonical_byte_length_for_tree_height(shape.tree_height)
    }

    pub(crate) fn canonical_byte_length_for_layout(
        layout: PseudorandomZeroSharingSeedCatalogLayout320,
    ) -> Result<usize, TallyPreparationError> {
        Self::canonical_byte_length_for_tree_height(layout.tree_height())
    }

    fn canonical_byte_length_for_tree_height(
        tree_height: u16,
    ) -> Result<usize, TallyPreparationError> {
        let sibling_count = usize::from(tree_height);
        let item_count = INCLUSION_PROOF_PREFIX_ITEM_COUNT
            .checked_add(sibling_count)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        CANONICAL_TUPLE_HEADER_BYTE_LENGTH
            .checked_add(
                item_count
                    .checked_mul(CANONICAL_ITEM_HEADER_BYTE_LENGTH)
                    .ok_or(TallyPreparationError::ArithmeticOverflow)?,
            )
            .and_then(|length| {
                length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH)
            })
            .and_then(|length| {
                length.checked_add(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INCLUSION_PROOF_DOMAIN.len(),
                )
            })
            .and_then(|length| length.checked_add(Hash512::BYTE_LENGTH))
            .and_then(|length| length.checked_add(size_of::<u64>()))
            .and_then(|length| length.checked_add(size_of::<u16>()))
            .and_then(|length| {
                sibling_count
                    .checked_mul(Hash512::BYTE_LENGTH)
                    .and_then(|sibling_byte_length| length.checked_add(sibling_byte_length))
            })
            .ok_or(TallyPreparationError::ArithmeticOverflow)
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, TallyPreparationError> {
        let mut items =
            Vec::with_capacity(INCLUSION_PROOF_PREFIX_ITEM_COUNT + self.sibling_digests.len());
        items.push(CanonicalItem::nonempty_ascii(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INCLUSION_PROOF_DOMAIN,
        )?);
        items.push(CanonicalItem::hash512(self.catalog_identity.into_bytes()));
        items.push(CanonicalItem::unsigned64(self.leaf_ordinal));
        items.push(CanonicalItem::unsigned16(
            u16::try_from(self.sibling_digests.len())
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        ));
        items.extend(
            self.sibling_digests
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
        expected_layout: PseudorandomZeroSharingSeedCatalogLayout320,
        expected_leaf_ordinal: u64,
        bytes: &[u8],
    ) -> Result<Self, TallyPreparationError> {
        let tuple = CanonicalTuple::decode(bytes, &seed_catalog_control_object_decode_limits())?;
        let expected_sibling_count = usize::from(expected_layout.tree_height);
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INCLUSION_PROOF_DOMAIN,
            INCLUSION_PROOF_PREFIX_ITEM_COUNT + expected_sibling_count,
        )?;
        require_hash(
            &tuple.items[1],
            expected_layout.identity,
            "catalog identity",
        )?;
        require_u64(&tuple.items[2], expected_leaf_ordinal, "leaf ordinal")?;
        require_u16(&tuple.items[3], expected_layout.tree_height, "proof height")?;
        let sibling_digests = tuple.items[INCLUSION_PROOF_PREFIX_ITEM_COUNT..]
            .iter()
            .map(|item| read_hash(item, "sibling digest"))
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        Ok(Self {
            catalog_identity: expected_layout.identity,
            leaf_ordinal: expected_leaf_ordinal,
            sibling_digests,
        })
    }
}

/// Producer-side tree retained only long enough to emit exact inclusion paths.
///
/// The tree proves catalog membership but provides no signature, state,
/// delivery, receipt, or preparation-continuation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogTree320 {
    root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
    layers: Vec<Box<[Hash512]>>,
}

impl PseudorandomZeroSharingSeedCatalogTree320 {
    pub(crate) fn create(
        layout: PseudorandomZeroSharingSeedCatalogLayout320,
        commitment_digests: Vec<Hash512>,
    ) -> Result<Self, TallyPreparationError> {
        let expected_leaf_count = usize::try_from(layout.leaf_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if commitment_digests.len() != expected_leaf_count {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingSeedCatalogLeafCountMismatch {
                    expected: expected_leaf_count,
                    actual: commitment_digests.len(),
                },
            );
        }
        let tree_capacity = usize::try_from(layout.tree_capacity)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let mut leaf_nodes = Vec::with_capacity(tree_capacity);
        for (leaf_ordinal, (coordinate, commitment_digest)) in
            layout.coordinates()?.zip(commitment_digests).enumerate()
        {
            leaf_nodes.push(seed_catalog_leaf_digest(
                layout,
                u64::try_from(leaf_ordinal)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
                coordinate,
                commitment_digest,
            )?);
        }
        for padding_ordinal in layout.leaf_count..layout.tree_capacity {
            leaf_nodes.push(seed_catalog_padding_leaf_digest(layout, padding_ordinal)?);
        }
        if leaf_nodes.len() != tree_capacity {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let mut layers = Vec::with_capacity(usize::from(layout.tree_height) + 1);
        layers.push(leaf_nodes.into_boxed_slice());
        for level in 0..layout.tree_height {
            let child_layer = layers
                .last()
                .ok_or(TallyPreparationError::GeometryMismatch)?;
            if child_layer.len() < 2 || child_layer.len() % 2 != 0 {
                return Err(TallyPreparationError::GeometryMismatch);
            }
            let mut parent_layer = Vec::with_capacity(child_layer.len() / 2);
            for (node_index, children) in child_layer.chunks_exact(2).enumerate() {
                parent_layer.push(seed_catalog_internal_node_digest(
                    layout,
                    level,
                    u64::try_from(node_index)
                        .map_err(|_| TallyPreparationError::IntegerConversion)?,
                    children[0],
                    children[1],
                )?);
            }
            layers.push(parent_layer.into_boxed_slice());
        }
        let root_layer = layers
            .last()
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        if root_layer.len() != 1 {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        Ok(Self {
            root_body: PseudorandomZeroSharingSeedCatalogRootBody320 {
                layout,
                root_digest: root_layer[0],
            },
            layers,
        })
    }

    pub(crate) const fn root_body(&self) -> PseudorandomZeroSharingSeedCatalogRootBody320 {
        self.root_body
    }

    pub(crate) fn inclusion_proof(
        &self,
        leaf_ordinal: u64,
    ) -> Result<PseudorandomZeroSharingSeedCatalogInclusionProof320, TallyPreparationError> {
        let layout = self.root_body.layout;
        if leaf_ordinal >= layout.leaf_count {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingSeedCatalogLeafOrdinalOutOfRange {
                    leaf_ordinal,
                    leaf_count: layout.leaf_count,
                },
            );
        }
        let mut node_index =
            usize::try_from(leaf_ordinal).map_err(|_| TallyPreparationError::IntegerConversion)?;
        let mut sibling_digests = Vec::with_capacity(usize::from(layout.tree_height));
        for layer in self.layers.iter().take(usize::from(layout.tree_height)) {
            sibling_digests.push(
                *layer
                    .get(node_index ^ 1)
                    .ok_or(TallyPreparationError::GeometryMismatch)?,
            );
            node_index /= 2;
        }
        Ok(PseudorandomZeroSharingSeedCatalogInclusionProof320 {
            catalog_identity: layout.identity,
            leaf_ordinal,
            sibling_digests: sibling_digests.into_boxed_slice(),
        })
    }
}

/// Result of positively checking one digest against one unsigned root body.
///
/// This is deliberately not source-authenticated and cannot authorize seed
/// use or any later preparation transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CatalogIncludedSeedCommitment320 {
    root_body_identity: Hash512,
    coordinate: PseudorandomZeroSharingSeedCatalogCoordinate320,
    commitment_digest: Hash512,
}

impl CatalogIncludedSeedCommitment320 {
    pub(crate) const fn root_body_identity(self) -> Hash512 {
        self.root_body_identity
    }

    pub(crate) const fn coordinate(self) -> PseudorandomZeroSharingSeedCatalogCoordinate320 {
        self.coordinate
    }

    pub(crate) const fn commitment_digest(self) -> Hash512 {
        self.commitment_digest
    }
}

/// Positively verifies a canonical inclusion path against an expected layout
/// and unsigned root body.
pub(crate) fn verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320(
    expected_layout: PseudorandomZeroSharingSeedCatalogLayout320,
    root_body_bytes: &[u8],
    coordinate: PseudorandomZeroSharingSeedCatalogCoordinate320,
    commitment_digest: Hash512,
    inclusion_proof_bytes: &[u8],
) -> Result<CatalogIncludedSeedCommitment320, TallyPreparationError> {
    let leaf_ordinal = expected_layout.leaf_ordinal(coordinate)?;
    let root_body = PseudorandomZeroSharingSeedCatalogRootBody320::from_canonical_bytes(
        expected_layout,
        root_body_bytes,
    )?;
    let proof = PseudorandomZeroSharingSeedCatalogInclusionProof320::from_canonical_bytes(
        expected_layout,
        leaf_ordinal,
        inclusion_proof_bytes,
    )?;
    if proof.sibling_digests.len() != usize::from(expected_layout.tree_height) {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSeedCatalogProofLengthMismatch {
                expected: usize::from(expected_layout.tree_height),
                actual: proof.sibling_digests.len(),
            },
        );
    }

    let mut node_digest =
        seed_catalog_leaf_digest(expected_layout, leaf_ordinal, coordinate, commitment_digest)?;
    let mut node_index = leaf_ordinal;
    for (level, sibling_digest) in proof.sibling_digests.iter().copied().enumerate() {
        let parent_index = node_index / 2;
        let level = u16::try_from(level).map_err(|_| TallyPreparationError::IntegerConversion)?;
        node_digest = if node_index % 2 == 0 {
            seed_catalog_internal_node_digest(
                expected_layout,
                level,
                parent_index,
                node_digest,
                sibling_digest,
            )?
        } else {
            seed_catalog_internal_node_digest(
                expected_layout,
                level,
                parent_index,
                sibling_digest,
                node_digest,
            )?
        };
        node_index = parent_index;
    }
    if !bool::from(
        node_digest
            .as_bytes()
            .ct_eq(root_body.root_digest.as_bytes()),
    ) {
        return Err(TallyPreparationError::PseudorandomZeroSharingSeedCatalogRootMismatch);
    }
    Ok(CatalogIncludedSeedCommitment320 {
        root_body_identity: root_body.identity()?,
        coordinate,
        commitment_digest,
    })
}

/// Recomputes one subset commitment from its opening and checks its exact
/// unsigned catalog path. No redundant commitment object is needed in the
/// private-delivery stream.
pub(crate) fn verify_pseudorandom_zero_sharing_subset_seed_opening_catalog_inclusion_320(
    expected_layout: PseudorandomZeroSharingSeedCatalogLayout320,
    subset: ReplicatedRandomSharingSubset,
    root_body_bytes: &[u8],
    opening_bytes: &[u8],
    inclusion_proof_bytes: &[u8],
) -> Result<
    (
        CatalogIncludedSeedCommitment320,
        CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320,
    ),
    TallyPreparationError,
> {
    let expected_subset_coordinate = expected_layout.subset_seed_coordinate(subset)?;
    let (commitment_digest, matched_contribution) =
        verify_pseudorandom_zero_sharing_subset_seed_opening_320(
            expected_subset_coordinate,
            opening_bytes,
        )?;
    let catalog_inclusion = verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320(
        expected_layout,
        root_body_bytes,
        expected_layout.subset_coordinate(subset)?,
        commitment_digest,
        inclusion_proof_bytes,
    )?;
    Ok((catalog_inclusion, matched_contribution))
}

fn seed_catalog_leaf_digest(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    leaf_ordinal: u64,
    coordinate: PseudorandomZeroSharingSeedCatalogCoordinate320,
    commitment_digest: Hash512,
) -> Result<Hash512, TallyPreparationError> {
    layout.validate_coordinate(coordinate)?;
    if layout.leaf_ordinal(coordinate)? != leaf_ordinal {
        return Err(TallyPreparationError::PseudorandomZeroSharingSeedCatalogCoordinateMismatch);
    }
    let mut items = vec![
        CanonicalItem::hash512(layout.identity.into_bytes()),
        CanonicalItem::unsigned64(leaf_ordinal),
        CanonicalItem::unsigned16(layout.participant_count()),
        CanonicalItem::unsigned16(layout.contributor_position),
    ];
    coordinate.append_hash_items(&mut items);
    items.push(CanonicalItem::hash512(commitment_digest.into_bytes()));
    Ok(hash_foundation_tuple_512(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_LEAF_DOMAIN,
        &items,
    )?)
}

fn seed_catalog_padding_leaf_digest(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    padding_ordinal: u64,
) -> Result<Hash512, TallyPreparationError> {
    if padding_ordinal < layout.leaf_count || padding_ordinal >= layout.tree_capacity {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    Ok(hash_foundation_tuple_512(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_PADDING_LEAF_DOMAIN,
        &[
            CanonicalItem::hash512(layout.identity.into_bytes()),
            CanonicalItem::unsigned64(padding_ordinal),
        ],
    )?)
}

fn seed_catalog_internal_node_digest(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    level: u16,
    node_index: u64,
    left_digest: Hash512,
    right_digest: Hash512,
) -> Result<Hash512, TallyPreparationError> {
    Ok(hash_foundation_tuple_512(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INTERNAL_NODE_DOMAIN,
        &[
            CanonicalItem::hash512(layout.identity.into_bytes()),
            CanonicalItem::unsigned16(level),
            CanonicalItem::unsigned64(node_index),
            CanonicalItem::hash512(left_digest.into_bytes()),
            CanonicalItem::hash512(right_digest.into_bytes()),
        ],
    )?)
}

fn subset_rank_excluding_contributor(
    subset: ReplicatedRandomSharingSubset,
    contributor_position: u16,
) -> Result<u64, TallyPreparationError> {
    if contributor_position >= subset.participant_count()
        || !subset.contains(contributor_position)?
    {
        return Err(TallyPreparationError::PseudorandomZeroSharingSeedCatalogCoordinateMismatch);
    }
    let mut rank = 0_u64;
    let mut selected_position_count = 0_u64;
    for roster_position in 0..subset.participant_count() {
        if roster_position == contributor_position {
            continue;
        }
        let roster_bit = 1_u32 << u32::from(roster_position);
        if subset.excluded_position_mask() & roster_bit == 0 {
            continue;
        }
        selected_position_count = selected_position_count
            .checked_add(1)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        let compressed_position = if roster_position < contributor_position {
            u64::from(roster_position)
        } else {
            u64::from(roster_position - 1)
        };
        rank = rank
            .checked_add(checked_binomial_coefficient(
                compressed_position,
                selected_position_count,
            )?)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
    }
    if selected_position_count != u64::from(subset.active_fault_bound()) {
        return Err(TallyPreparationError::PseudorandomZeroSharingSeedCatalogCoordinateMismatch);
    }
    Ok(rank)
}

fn checked_binomial_coefficient(
    population_size: u64,
    selected_size: u64,
) -> Result<u64, TallyPreparationError> {
    if selected_size > population_size {
        return Ok(0);
    }
    let selected_size = selected_size.min(population_size - selected_size);
    let mut result = 1_u64;
    for selected_position in 1..=selected_size {
        result = result
            .checked_mul(population_size - selected_size + selected_position)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?
            / selected_position;
    }
    Ok(result)
}

fn pseudorandom_zero_sharing_seed_catalog_compiler_identity()
-> Result<Hash512, TallyPreparationError> {
    pseudorandom_zero_sharing_seed_catalog_compiler_identity_from_source(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_SOURCE,
    )
}

fn pseudorandom_zero_sharing_seed_catalog_compiler_identity_from_source(
    source: &[u8],
) -> Result<Hash512, TallyPreparationError> {
    if core::str::from_utf8(source).is_err()
        || source.starts_with(&[0xef, 0xbb, 0xbf])
        || source.contains(&b'\r')
        || !source.ends_with(b"\n")
    {
        return Err(TallyPreparationError::NonCanonicalPreparationSourceEncoding);
    }
    Ok(Hash512::from_bytes(hash_framed_parts_512(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_COMPILER_IDENTITY_DOMAIN,
        &[
            source,
            &PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_VERSION.to_le_bytes(),
        ],
    )))
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), TallyPreparationError> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(seed_catalog_object_mismatch("schema identifier"));
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(seed_catalog_object_mismatch("schema version"));
    }
    if tuple.items.len() != expected_item_count {
        return Err(seed_catalog_object_mismatch("item count"));
    }
    if tuple.items[0].item_type() != CanonicalItemType::Ascii
        || tuple.items[0].variable_value_bytes()? != expected_domain.as_bytes()
    {
        return Err(seed_catalog_object_mismatch("object domain"));
    }
    Ok(())
}

fn read_hash(item: &CanonicalItem, field: &'static str) -> Result<Hash512, TallyPreparationError> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(seed_catalog_object_mismatch(field));
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| seed_catalog_object_mismatch(field))?;
    Ok(Hash512::from_bytes(bytes))
}

fn require_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), TallyPreparationError> {
    if read_hash(item, field)? != expected {
        return Err(seed_catalog_object_mismatch(field));
    }
    Ok(())
}

fn read_u16(item: &CanonicalItem, field: &'static str) -> Result<u16, TallyPreparationError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(seed_catalog_object_mismatch(field));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| seed_catalog_object_mismatch(field))?;
    Ok(u16::from_le_bytes(bytes))
}

fn require_u16(
    item: &CanonicalItem,
    expected: u16,
    field: &'static str,
) -> Result<(), TallyPreparationError> {
    if read_u16(item, field)? != expected {
        return Err(seed_catalog_object_mismatch(field));
    }
    Ok(())
}

fn read_u64(item: &CanonicalItem, field: &'static str) -> Result<u64, TallyPreparationError> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(seed_catalog_object_mismatch(field));
    }
    let bytes: [u8; 8] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| seed_catalog_object_mismatch(field))?;
    Ok(u64::from_le_bytes(bytes))
}

fn require_u64(
    item: &CanonicalItem,
    expected: u64,
    field: &'static str,
) -> Result<(), TallyPreparationError> {
    if read_u64(item, field)? != expected {
        return Err(seed_catalog_object_mismatch(field));
    }
    Ok(())
}

const fn seed_catalog_object_mismatch(field: &'static str) -> TallyPreparationError {
    TallyPreparationError::PseudorandomZeroSharingSeedCatalogObjectMismatch { field }
}

fn seed_catalog_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_SEED_CATALOG_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_SEED_CATALOG_CONTROL_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_SEED_CATALOG_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length:
            MAXIMUM_SEED_CATALOG_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_SEED_CATALOG_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}

#[cfg(test)]
pub(crate) fn compiler_identity_from_source_for_test(
    source: &[u8],
) -> Result<Hash512, TallyPreparationError> {
    pseudorandom_zero_sharing_seed_catalog_compiler_identity_from_source(source)
}
