use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalDecodeLimits,
    CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, StreamingFoundationTupleHash512,
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    pseudorandom_zero_sharing_field_stream_320::PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH,
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH: usize =
    PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH;
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
///
/// The catalog identity is a caller-supplied candidate identity until the
/// emitted catalog compiler exists. This scope carries no source authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSubsetSeedScope320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    seed_catalog_identity: Hash512,
    subset: ReplicatedRandomSharingSubset,
}

impl PseudorandomZeroSharingSubsetSeedScope320 {
    pub(crate) fn new(
        parameter_identity: Hash512,
        preparation_context: TallyPreparationContext,
        seed_catalog_identity: Hash512,
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
            seed_catalog_identity,
            subset,
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

    pub(crate) const fn subset(self) -> ReplicatedRandomSharingSubset {
        self.subset
    }

    fn from_decoded_components(
        parameter_identity: Hash512,
        preparation_context_identity: Hash512,
        seed_catalog_identity: Hash512,
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
            seed_catalog_identity,
            subset,
        })
    }

    fn canonical_items(self) -> Vec<CanonicalItem> {
        vec![
            CanonicalItem::hash512(self.parameter_identity.into_bytes()),
            CanonicalItem::hash512(self.preparation_context_identity.into_bytes()),
            CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
            CanonicalItem::hash512(self.seed_catalog_identity.into_bytes()),
            CanonicalItem::unsigned16(self.subset.participant_count()),
            CanonicalItem::unsigned32(self.subset.excluded_position_mask()),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSubsetSeedCoordinate320 {
    scope: PseudorandomZeroSharingSubsetSeedScope320,
    contributor_position: u16,
}

impl PseudorandomZeroSharingSubsetSeedCoordinate320 {
    pub(crate) fn new(
        scope: PseudorandomZeroSharingSubsetSeedScope320,
        contributor_position: u16,
    ) -> Result<Self, TallyPreparationError> {
        if contributor_position >= scope.subset.participant_count()
            || !scope.subset.contains(contributor_position)?
        {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingSubsetSeedContributorNotMember {
                    contributor_position,
                },
            );
        }
        Ok(Self {
            scope,
            contributor_position,
        })
    }

    fn canonical_items(self) -> Vec<CanonicalItem> {
        let mut items = self.scope.canonical_items();
        items.push(CanonicalItem::unsigned16(self.contributor_position));
        items
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSubsetSeedCommitment320 {
    coordinate: PseudorandomZeroSharingSubsetSeedCoordinate320,
    digest: Hash512,
}

impl PseudorandomZeroSharingSubsetSeedCommitment320 {
    pub(crate) const fn coordinate(self) -> PseudorandomZeroSharingSubsetSeedCoordinate320 {
        self.coordinate
    }

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

impl Drop for CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320 {
    fn drop(&mut self) {
        self.contribution.zeroize();
    }
}

pub(crate) struct CommitmentMatchedPseudorandomZeroSharingSubsetMaster320 {
    scope: PseudorandomZeroSharingSubsetSeedScope320,
    bytes: [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH],
}

impl CommitmentMatchedPseudorandomZeroSharingSubsetMaster320 {
    pub(crate) const fn scope(&self) -> PseudorandomZeroSharingSubsetSeedScope320 {
        self.scope
    }

    pub(crate) const fn as_bytes(
        &self,
    ) -> &[u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for CommitmentMatchedPseudorandomZeroSharingSubsetMaster320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommitmentMatchedPseudorandomZeroSharingSubsetMaster320([redacted])")
    }
}

impl Drop for CommitmentMatchedPseudorandomZeroSharingSubsetMaster320 {
    fn drop(&mut self) {
        self.bytes.zeroize();
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
    let opening = PseudorandomZeroSharingSubsetSeedOpening320::from_canonical_bytes(opening_bytes)?;
    if commitment.coordinate != expected_coordinate || opening.coordinate != expected_coordinate {
        return Err(TallyPreparationError::PseudorandomZeroSharingSubsetSeedCoordinateMismatch);
    }
    let expected_digest = derive_subset_seed_commitment_digest(
        opening.coordinate,
        &opening.commitment_salt,
        &opening.contribution,
    )?;
    if !bool::from(
        commitment
            .digest
            .as_bytes()
            .ct_eq(expected_digest.as_bytes()),
    ) {
        return Err(TallyPreparationError::PseudorandomZeroSharingSubsetSeedCommitmentMismatch);
    }
    Ok(
        CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320 {
            coordinate: opening.coordinate,
            contribution: opening.contribution,
        },
    )
}

/// Combines one commitment-matched contribution from every subset member.
///
/// Commitment matching alone is not source authentication. The returned
/// master must not be used as a protocol continuation capability until every
/// contribution also has catalog, signature, delivery, receipt, and state
/// provenance.
pub(crate) fn combine_commitment_matched_pseudorandom_zero_sharing_subset_master_320(
    expected_scope: PseudorandomZeroSharingSubsetSeedScope320,
    contributions: Vec<CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320>,
) -> Result<CommitmentMatchedPseudorandomZeroSharingSubsetMaster320, TallyPreparationError> {
    let expected_contributors = expected_scope.subset.member_positions();
    if contributions.len() != expected_contributors.len() {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedInventoryCountMismatch {
                expected: expected_contributors.len(),
                actual: contributions.len(),
            },
        );
    }

    let mut seen_contributor_mask = 0_u32;
    let mut master = Zeroizing::new([0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH]);
    for matched_contribution in contributions {
        let coordinate = matched_contribution.coordinate;
        if coordinate.scope != expected_scope {
            return Err(TallyPreparationError::PseudorandomZeroSharingSubsetSeedCoordinateMismatch);
        }
        let contributor_bit = 1_u32
            .checked_shl(u32::from(coordinate.contributor_position))
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        if seen_contributor_mask & contributor_bit != 0 {
            return Err(
                TallyPreparationError::PseudorandomZeroSharingSubsetSeedDuplicateContributor {
                    contributor_position: coordinate.contributor_position,
                },
            );
        }
        seen_contributor_mask |= contributor_bit;
        for (master_byte, contribution_byte) in master
            .iter_mut()
            .zip(matched_contribution.contribution.iter())
        {
            *master_byte ^= contribution_byte;
        }
    }

    let expected_contributor_mask =
        expected_contributors
            .into_iter()
            .try_fold(0_u32, |mask, contributor_position| {
                let contributor_bit = 1_u32
                    .checked_shl(u32::from(contributor_position))
                    .ok_or(TallyPreparationError::ArithmeticOverflow)?;
                Ok::<_, TallyPreparationError>(mask | contributor_bit)
            })?;
    if seen_contributor_mask != expected_contributor_mask {
        return Err(TallyPreparationError::PseudorandomZeroSharingSubsetSeedCoordinateMismatch);
    }

    Ok(CommitmentMatchedPseudorandomZeroSharingSubsetMaster320 {
        scope: expected_scope,
        bytes: *master,
    })
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
    let scope = PseudorandomZeroSharingSubsetSeedScope320::from_decoded_components(
        parameter_identity,
        preparation_context_identity,
        seed_catalog_identity,
        participant_count,
        excluded_position_mask,
    )?;
    PseudorandomZeroSharingSubsetSeedCoordinate320::new(scope, contributor_position)
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
