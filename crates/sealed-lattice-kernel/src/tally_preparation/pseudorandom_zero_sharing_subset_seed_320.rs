use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalDecodeLimits,
    CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, StreamingFoundationTupleHash512,
};

use super::{
    TallyPreparationContext, TallyPreparationError, binary_field_320::BinaryFieldElement320,
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH: usize =
    BinaryFieldElement320::CANONICAL_BYTE_LENGTH;
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH: usize = 64;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_SECRET_LEAF_DOMAIN: &str =
    "sealed-lattice/v1/preparation/subset-seed-secret-leaf";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_OBJECT_DOMAIN: &str =
    "sealed-lattice/v1/preparation/subset-seed-contribution-commitment";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_DOMAIN: &str =
    "sealed-lattice/v1/preparation/subset-seed-contribution-opening";

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const COORDINATE_ITEM_COUNT: usize = 7;
const COMMITMENT_OBJECT_ITEM_COUNT: usize = 1 + COORDINATE_ITEM_COUNT + 1;
const OPENING_OBJECT_ITEM_COUNT: usize = 1 + COORDINATE_ITEM_COUNT + 2;
const MAXIMUM_SUBSET_SEED_OBJECT_BYTE_LENGTH: usize = 1_024;
const MAXIMUM_SUBSET_SEED_OBJECT_ITEM_BYTE_LENGTH: usize = 256;
const MAXIMUM_SUBSET_SEED_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 4_096;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;
const COORDINATE_CANONICAL_VALUE_BYTE_LENGTH: usize =
    Hash512::BYTE_LENGTH + Hash512::BYTE_LENGTH + 2 + Hash512::BYTE_LENGTH + 2 + 4 + 2;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_OBJECT_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + COMMITMENT_OBJECT_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_OBJECT_DOMAIN.len()
        + COORDINATE_CANONICAL_VALUE_BYTE_LENGTH
        + Hash512::BYTE_LENGTH;
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + OPENING_OBJECT_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_DOMAIN.len()
        + COORDINATE_CANONICAL_VALUE_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH;

/// Public scope shared by every contribution to one subset master.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSubsetMasterScope320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    subset: ReplicatedRandomSharingSubset,
}

impl PseudorandomZeroSharingSubsetMasterScope320 {
    pub(crate) fn new(
        parameter_identity: Hash512,
        preparation_context: TallyPreparationContext,
        subset: ReplicatedRandomSharingSubset,
    ) -> Result<Self, TallyPreparationError> {
        if subset.participant_count() != preparation_context.participant_count() {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingSubsetSeedSubsetParticipantCountMismatch {
                    subset_participant_count: subset.participant_count(),
                    context_participant_count: preparation_context.participant_count(),
                },
            );
        }
        Ok(Self {
            parameter_identity,
            preparation_context_identity: preparation_context.identity(),
            subset,
        })
    }

    pub(crate) const fn parameter_identity(self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context_identity(self) -> Hash512 {
        self.preparation_context_identity
    }

    pub(crate) const fn subset(self) -> ReplicatedRandomSharingSubset {
        self.subset
    }

    fn from_decoded_components(
        parameter_identity: Hash512,
        preparation_context_identity: Hash512,
        participant_count: u16,
        excluded_position_mask: u32,
    ) -> Result<Self, TallyPreparationError> {
        let mask_limit = 1_u32.checked_shl(u32::from(participant_count)).ok_or(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch {
                field: "subset participant count",
            },
        )?;
        if excluded_position_mask >= mask_limit {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch {
                    field: "excluded-position mask",
                },
            );
        }
        let excluded_positions = (0..participant_count)
            .filter(|roster_position| {
                let position_bit = 1_u32 << u32::from(*roster_position);
                excluded_position_mask & position_bit != 0
            })
            .collect::<Vec<_>>();
        let subset = ReplicatedRandomSharingSubset::from_excluded_positions(
            participant_count,
            &excluded_positions,
        )
        .map_err(|_| {
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch {
                field: "subset geometry",
            }
        })?;
        Ok(Self {
            parameter_identity,
            preparation_context_identity,
            subset,
        })
    }
}

/// Contributor-specific coordinate of one salted subset contribution leaf.
///
/// The catalog identity belongs to this leaf, not to the shared master scope.
/// Keeping those identities separate permits contributions from distinct
/// participant catalogs to join only when their parameter, preparation, and
/// subset scope agrees. This coordinate carries no source authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSubsetSeedCoordinate320 {
    master_scope: PseudorandomZeroSharingSubsetMasterScope320,
    seed_catalog_identity: Hash512,
    contributor_position: u16,
}

impl PseudorandomZeroSharingSubsetSeedCoordinate320 {
    pub(crate) fn new(
        master_scope: PseudorandomZeroSharingSubsetMasterScope320,
        seed_catalog_identity: Hash512,
        contributor_position: u16,
    ) -> Result<Self, TallyPreparationError> {
        if contributor_position >= master_scope.subset.participant_count()
            || !master_scope.subset.contains(contributor_position)?
        {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingSubsetSeedContributorNotMember {
                    contributor_position,
                },
            );
        }
        Ok(Self {
            master_scope,
            seed_catalog_identity,
            contributor_position,
        })
    }

    pub(crate) const fn master_scope(self) -> PseudorandomZeroSharingSubsetMasterScope320 {
        self.master_scope
    }

    pub(crate) const fn seed_catalog_identity(self) -> Hash512 {
        self.seed_catalog_identity
    }

    pub(crate) const fn contributor_position(self) -> u16 {
        self.contributor_position
    }

    fn canonical_items(self) -> Vec<CanonicalItem> {
        vec![
            CanonicalItem::hash512(self.master_scope.parameter_identity.into_bytes()),
            CanonicalItem::hash512(self.master_scope.preparation_context_identity.into_bytes()),
            CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
            CanonicalItem::hash512(self.seed_catalog_identity.into_bytes()),
            CanonicalItem::unsigned16(self.master_scope.subset.participant_count()),
            CanonicalItem::unsigned32(self.master_scope.subset.excluded_position_mask()),
            CanonicalItem::unsigned16(self.contributor_position),
        ]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSubsetSeedCommitment320 {
    coordinate: PseudorandomZeroSharingSubsetSeedCoordinate320,
    digest: Hash512,
}

impl PseudorandomZeroSharingSubsetSeedCommitment320 {
    pub(crate) const fn digest(self) -> Hash512 {
        self.digest
    }

    pub(crate) fn canonical_bytes(self) -> Result<Vec<u8>, TallyPreparationError> {
        let mut items = Vec::with_capacity(COMMITMENT_OBJECT_ITEM_COUNT);
        items.push(CanonicalItem::nonempty_ascii(
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_OBJECT_DOMAIN,
        )?);
        items.extend(self.coordinate.canonical_items());
        items.push(CanonicalItem::hash512(self.digest.into_bytes()));
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            items,
        )
        .encode()?)
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let tuple = CanonicalTuple::decode(bytes, &subset_seed_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_OBJECT_DOMAIN,
            COMMITMENT_OBJECT_ITEM_COUNT,
        )?;
        let coordinate = read_coordinate(&tuple.items[1..1 + COORDINATE_ITEM_COUNT])?;
        let digest = read_hash512(
            &tuple.items[COMMITMENT_OBJECT_ITEM_COUNT - 1],
            "commitment digest",
        )?;
        Ok(Self { coordinate, digest })
    }
}

impl fmt::Debug for PseudorandomZeroSharingSubsetSeedCommitment320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSubsetSeedCommitment320")
            .field("coordinate", &self.coordinate)
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSubsetSeedOpening320 {
    coordinate: PseudorandomZeroSharingSubsetSeedCoordinate320,
    commitment_salt: [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
    contribution: [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
}

impl PseudorandomZeroSharingSubsetSeedOpening320 {
    pub(crate) fn canonical_bytes(&self) -> Result<Zeroizing<Vec<u8>>, TallyPreparationError> {
        let mut items = Vec::with_capacity(OPENING_OBJECT_ITEM_COUNT);
        items.push(CanonicalItem::nonempty_ascii(
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_DOMAIN,
        )?);
        items.extend(self.coordinate.canonical_items());
        items.push(CanonicalItem::fixed_bytes(self.commitment_salt)?);
        items.push(CanonicalItem::fixed_bytes(self.contribution)?);
        let tuple = Zeroizing::new(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            items,
        ));
        Ok(Zeroizing::new(tuple.encode()?))
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let tuple = Zeroizing::new(CanonicalTuple::decode(
            bytes,
            &subset_seed_object_decode_limits(),
        )?);
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_DOMAIN,
            OPENING_OBJECT_ITEM_COUNT,
        )?;
        let coordinate = read_coordinate(&tuple.items[1..1 + COORDINATE_ITEM_COUNT])?;
        let commitment_salt = read_fixed_raw_bytes::<
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
        >(
            &tuple.items[OPENING_OBJECT_ITEM_COUNT - 2],
            "commitment salt",
        )?;
        let contribution =
            read_fixed_raw_bytes::<PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH>(
                &tuple.items[OPENING_OBJECT_ITEM_COUNT - 1],
                "seed contribution",
            )?;
        Ok(Self {
            coordinate,
            commitment_salt,
            contribution,
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

impl fmt::Debug for PseudorandomZeroSharingSubsetSeedOpening320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSubsetSeedOpening320")
            .field("coordinate", &self.coordinate)
            .field("commitment_salt", &"[redacted]")
            .field("contribution", &"[redacted]")
            .finish()
    }
}

impl Drop for PseudorandomZeroSharingSubsetSeedOpening320 {
    fn drop(&mut self) {
        self.commitment_salt.zeroize();
        self.contribution.zeroize();
    }
}

pub(crate) struct CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320 {
    coordinate: PseudorandomZeroSharingSubsetSeedCoordinate320,
    contribution: [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
}

impl fmt::Debug for CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320")
            .field("coordinate", &self.coordinate)
            .field("contribution", &"[redacted]")
            .finish()
    }
}

impl CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320 {
    pub(super) const fn coordinate(&self) -> PseudorandomZeroSharingSubsetSeedCoordinate320 {
        self.coordinate
    }

    pub(super) fn into_parts(
        mut self,
    ) -> (
        PseudorandomZeroSharingSubsetSeedCoordinate320,
        [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
    ) {
        let contribution = core::mem::replace(
            &mut self.contribution,
            [0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
        );
        (self.coordinate, contribution)
    }
}

impl Drop for CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320 {
    fn drop(&mut self) {
        self.contribution.zeroize();
    }
}

/// Creates a candidate salted leaf from caller-supplied secret material.
///
/// This function does not establish randomness, source authentication,
/// catalog inclusion, delivery, or receipt authority.
pub(crate) fn create_pseudorandom_zero_sharing_subset_seed_contribution_320(
    coordinate: PseudorandomZeroSharingSubsetSeedCoordinate320,
    contribution: [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
    commitment_salt: [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
) -> Result<
    (
        PseudorandomZeroSharingSubsetSeedCommitment320,
        PseudorandomZeroSharingSubsetSeedOpening320,
    ),
    TallyPreparationError,
> {
    let opening = PseudorandomZeroSharingSubsetSeedOpening320 {
        coordinate,
        commitment_salt,
        contribution,
    };
    let digest = derive_subset_seed_commitment_digest(
        coordinate,
        &opening.commitment_salt,
        &opening.contribution,
    )?;
    Ok((
        PseudorandomZeroSharingSubsetSeedCommitment320 { coordinate, digest },
        opening,
    ))
}

/// Positively matches canonical commitment and opening bytes to one expected
/// coordinate. It does not verify a sender signature or catalog path.
pub(crate) fn verify_pseudorandom_zero_sharing_subset_seed_contribution_320(
    expected_coordinate: PseudorandomZeroSharingSubsetSeedCoordinate320,
    commitment_bytes: &[u8],
    opening_bytes: &[u8],
) -> Result<CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320, TallyPreparationError>
{
    let commitment =
        PseudorandomZeroSharingSubsetSeedCommitment320::from_canonical_bytes(commitment_bytes)?;
    if commitment.coordinate != expected_coordinate {
        return Err(TallyPreparationError::PseudorandomZeroSharingSubsetSeedCoordinateMismatch);
    }
    let (expected_digest, matched_contribution) =
        verify_pseudorandom_zero_sharing_subset_seed_opening_320(
            expected_coordinate,
            opening_bytes,
        )?;
    if !bool::from(
        commitment
            .digest
            .as_bytes()
            .ct_eq(expected_digest.as_bytes()),
    ) {
        return Err(TallyPreparationError::PseudorandomZeroSharingSubsetSeedCommitmentMismatch);
    }
    Ok(matched_contribution)
}

/// Recomputes the salted commitment digest directly from one canonical
/// opening. A later catalog verifier can therefore avoid carrying a redundant
/// commitment object in the private-delivery stream.
pub(crate) fn verify_pseudorandom_zero_sharing_subset_seed_opening_320(
    expected_coordinate: PseudorandomZeroSharingSubsetSeedCoordinate320,
    opening_bytes: &[u8],
) -> Result<
    (
        Hash512,
        CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320,
    ),
    TallyPreparationError,
> {
    let opening = PseudorandomZeroSharingSubsetSeedOpening320::from_canonical_bytes(opening_bytes)?;
    if opening.coordinate != expected_coordinate {
        return Err(TallyPreparationError::PseudorandomZeroSharingSubsetSeedCoordinateMismatch);
    }
    let commitment_digest = derive_subset_seed_commitment_digest(
        opening.coordinate,
        &opening.commitment_salt,
        &opening.contribution,
    )?;
    Ok((
        commitment_digest,
        CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320 {
            coordinate: opening.coordinate,
            contribution: opening.contribution,
        },
    ))
}

fn derive_subset_seed_commitment_digest(
    coordinate: PseudorandomZeroSharingSubsetSeedCoordinate320,
    commitment_salt: &[u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
    contribution: &[u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
) -> Result<Hash512, TallyPreparationError> {
    let prefix_items = coordinate.canonical_items();
    let payload_byte_length = commitment_salt
        .len()
        .checked_add(contribution.len())
        .ok_or(TallyPreparationError::ArithmeticOverflow)?;
    let mut hasher = StreamingFoundationTupleHash512::new_variable_bytes(
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_SECRET_LEAF_DOMAIN,
        &prefix_items,
        payload_byte_length,
    )
    .map_err(|_| TallyPreparationError::PseudorandomZeroSharingSubsetSeedCommitmentHashFailure)?;
    hasher.absorb(commitment_salt).map_err(|_| {
        TallyPreparationError::PseudorandomZeroSharingSubsetSeedCommitmentHashFailure
    })?;
    hasher.absorb(contribution).map_err(|_| {
        TallyPreparationError::PseudorandomZeroSharingSubsetSeedCommitmentHashFailure
    })?;
    hasher
        .finalize()
        .map_err(|_| TallyPreparationError::PseudorandomZeroSharingSubsetSeedCommitmentHashFailure)
}

fn read_coordinate(
    items: &[CanonicalItem],
) -> Result<PseudorandomZeroSharingSubsetSeedCoordinate320, TallyPreparationError> {
    if items.len() != COORDINATE_ITEM_COUNT {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch {
                field: "coordinate item count",
            },
        );
    }
    let parameter_identity = read_hash512(&items[0], "parameter identity")?;
    let preparation_context_identity = read_hash512(&items[1], "preparation context identity")?;
    if read_u16(&items[2], "preparation attempt ordinal")? != PREPARATION_ATTEMPT_ORDINAL {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch {
                field: "preparation attempt ordinal",
            },
        );
    }
    let seed_catalog_identity = read_hash512(&items[3], "seed catalog identity")?;
    let participant_count = read_u16(&items[4], "participant count")?;
    let excluded_position_mask = read_u32(&items[5], "excluded-position mask")?;
    let contributor_position = read_u16(&items[6], "contributor position")?;
    let master_scope = PseudorandomZeroSharingSubsetMasterScope320::from_decoded_components(
        parameter_identity,
        preparation_context_identity,
        participant_count,
        excluded_position_mask,
    )?;
    PseudorandomZeroSharingSubsetSeedCoordinate320::new(
        master_scope,
        seed_catalog_identity,
        contributor_position,
    )
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), TallyPreparationError> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch {
                field: "schema identifier",
            },
        );
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch {
                field: "schema version",
            },
        );
    }
    if tuple.items.len() != expected_item_count {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch {
                field: "item count",
            },
        );
    }
    let domain_item = &tuple.items[0];
    if domain_item.item_type() != CanonicalItemType::Ascii
        || domain_item.variable_value_bytes()? != expected_domain.as_bytes()
    {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch {
                field: "object domain",
            },
        );
    }
    Ok(())
}

fn read_hash512(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<Hash512, TallyPreparationError> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch { field },
        );
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item.canonical_bytes().try_into().map_err(|_| {
        TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch { field }
    })?;
    Ok(Hash512::from_bytes(bytes))
}

fn read_u16(item: &CanonicalItem, field: &'static str) -> Result<u16, TallyPreparationError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch { field },
        );
    }
    let bytes: [u8; 2] = item.canonical_bytes().try_into().map_err(|_| {
        TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch { field }
    })?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(item: &CanonicalItem, field: &'static str) -> Result<u32, TallyPreparationError> {
    if item.item_type() != CanonicalItemType::Unsigned32 {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch { field },
        );
    }
    let bytes: [u8; 4] = item.canonical_bytes().try_into().map_err(|_| {
        TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch { field }
    })?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_fixed_raw_bytes<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<[u8; BYTE_LENGTH], TallyPreparationError> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch { field },
        );
    }
    item.canonical_bytes().try_into().map_err(|_| {
        TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch { field }
    })
}

fn subset_seed_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_SUBSET_SEED_OBJECT_BYTE_LENGTH,
        maximum_item_count: OPENING_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_SUBSET_SEED_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_SUBSET_SEED_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_SUBSET_SEED_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}
