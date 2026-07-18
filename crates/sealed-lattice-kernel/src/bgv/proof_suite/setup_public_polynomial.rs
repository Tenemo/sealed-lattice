//! Canonical statement-owned public-polynomial LDE trees.
//!
//! Setup statements bind these Merkle roots directly. The canonical source
//! coefficients are evaluated by this module, so an object hash or a claimed
//! root can never stand in for the tree opened by the common proof verifier.

use crate::{
    bgv::setup::{
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES, parse_lattice_anchor_commitment_canonical_bytes,
    },
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
    },
};

use super::{
    PROOF_EVALUATION_COSET_OFFSET, ProofBaseFieldElement, ProofEvaluationDomain, ProofFieldError,
    ProofPolynomialError,
};

const SETUP_PUBLIC_POLYNOMIAL_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x121b;
pub(super) const SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER: u16 = 0x121c;
const SCHEMA_VERSION: u16 = 1;

const CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/setup/public-polynomial/context/v1";
const PHASE_PAIR_LEAF_HASH_DOMAIN: &str =
    "sealed-lattice/setup/public-polynomial/phase-pair-leaf/v1";
const MERKLE_NODE_HASH_DOMAIN: &str = "sealed-lattice/setup/public-polynomial/merkle-node/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupPublicPolynomialError {
    InvalidContext,
    InvalidInput,
    InvalidLatticeAnchor,
    CountOverflow,
    CanonicalEncoding,
    Field(ProofFieldError),
    Polynomial(ProofPolynomialError),
}

impl From<ProofFieldError> for SetupPublicPolynomialError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

impl From<ProofPolynomialError> for SetupPublicPolynomialError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

fn canonical_encoding_error<T>(_: T) -> SetupPublicPolynomialError {
    SetupPublicPolynomialError::CanonicalEncoding
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum SetupPublicPolynomialRootRole {
    LatticeAnchor = 1,
    PublicKeyShare = 2,
    CollectivePublicKey = 3,
    RelinearizationRoundOneLeft = 4,
    RelinearizationRoundOneRight = 5,
    RelinearizationAggregateRoundOneLeft = 6,
    RelinearizationAggregateRoundOneRight = 7,
    RelinearizationRoundTwo = 8,
    GaloisKeyShare = 9,
    RelinearizationRuntime = 10,
    GaloisCommon = 11,
    GaloisRuntime = 12,
}

impl SetupPublicPolynomialRootRole {
    const fn requires_owner(self) -> bool {
        matches!(
            self,
            Self::LatticeAnchor
                | Self::PublicKeyShare
                | Self::RelinearizationRoundOneLeft
                | Self::RelinearizationRoundOneRight
                | Self::RelinearizationRoundTwo
                | Self::GaloisKeyShare
        )
    }

    const fn requires_schedule_position(self) -> bool {
        matches!(
            self,
            Self::RelinearizationRoundOneLeft
                | Self::RelinearizationRoundOneRight
                | Self::RelinearizationAggregateRoundOneLeft
                | Self::RelinearizationAggregateRoundOneRight
                | Self::RelinearizationRoundTwo
                | Self::GaloisKeyShare
                | Self::RelinearizationRuntime
                | Self::GaloisCommon
                | Self::GaloisRuntime
        )
    }

    const fn requires_commitment_data_prime(self) -> bool {
        matches!(self, Self::LatticeAnchor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SetupPublicPolynomialContext {
    setup_proof_context_hash: [u8; 64],
    root_role: SetupPublicPolynomialRootRole,
    owner_participant_identity: Option<[u8; 64]>,
    owner_roster_position: Option<u16>,
    schedule_position: Option<u32>,
    commitment_data_prime_index: Option<u16>,
}

impl SetupPublicPolynomialContext {
    pub(crate) fn new(
        setup_proof_context_hash: [u8; 64],
        root_role: SetupPublicPolynomialRootRole,
        owner_participant_identity: Option<[u8; 64]>,
        owner_roster_position: Option<u16>,
        schedule_position: Option<u32>,
        commitment_data_prime_index: Option<u16>,
    ) -> Result<Self, SetupPublicPolynomialError> {
        let context = Self {
            setup_proof_context_hash,
            root_role,
            owner_participant_identity,
            owner_roster_position,
            schedule_position,
            commitment_data_prime_index,
        };
        context.validate()?;
        Ok(context)
    }

    pub(crate) fn lattice_anchor(
        setup_proof_context_hash: [u8; 64],
        owner_participant_identity: [u8; 64],
        owner_roster_position: u16,
        commitment_data_prime_index: u16,
    ) -> Result<Self, SetupPublicPolynomialError> {
        Self::new(
            setup_proof_context_hash,
            SetupPublicPolynomialRootRole::LatticeAnchor,
            Some(owner_participant_identity),
            Some(owner_roster_position),
            None,
            Some(commitment_data_prime_index),
        )
    }

    pub(crate) fn public_key_share(
        setup_proof_context_hash: [u8; 64],
        owner_participant_identity: [u8; 64],
        owner_roster_position: u16,
    ) -> Result<Self, SetupPublicPolynomialError> {
        Self::new(
            setup_proof_context_hash,
            SetupPublicPolynomialRootRole::PublicKeyShare,
            Some(owner_participant_identity),
            Some(owner_roster_position),
            None,
            None,
        )
    }

    pub(crate) fn collective_public_key(
        setup_proof_context_hash: [u8; 64],
    ) -> Result<Self, SetupPublicPolynomialError> {
        Self::new(
            setup_proof_context_hash,
            SetupPublicPolynomialRootRole::CollectivePublicKey,
            None,
            None,
            None,
            None,
        )
    }

    pub(crate) fn galois_common(
        setup_proof_context_hash: [u8; 64],
        schedule_position: u32,
    ) -> Result<Self, SetupPublicPolynomialError> {
        Self::new(
            setup_proof_context_hash,
            SetupPublicPolynomialRootRole::GaloisCommon,
            None,
            None,
            Some(schedule_position),
            None,
        )
    }

    fn validate(&self) -> Result<(), SetupPublicPolynomialError> {
        let owns_root =
            self.owner_participant_identity.is_some() && self.owner_roster_position.is_some();
        if owns_root != self.root_role.requires_owner()
            || self.owner_participant_identity.is_some() != self.owner_roster_position.is_some()
            || self.schedule_position.is_some() != self.root_role.requires_schedule_position()
            || self.commitment_data_prime_index.is_some()
                != self.root_role.requires_commitment_data_prime()
            || self.commitment_data_prime_index.is_some_and(|index| {
                !SETUP_COMMITMENT_MODULUS_LIMB_INDICES
                    .iter()
                    .any(|selected| u16::try_from(*selected).ok() == Some(index))
            })
        {
            return Err(SetupPublicPolynomialError::InvalidContext);
        }
        Ok(())
    }

    pub(crate) const fn root_role(&self) -> SetupPublicPolynomialRootRole {
        self.root_role
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; 64] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn owner_participant_identity(&self) -> Option<[u8; 64]> {
        self.owner_participant_identity
    }

    pub(crate) const fn owner_roster_position(&self) -> Option<u16> {
        self.owner_roster_position
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, SetupPublicPolynomialError> {
        let owner_participant_identity = self
            .owner_participant_identity
            .map(CanonicalItem::participant_identity);
        let owner_roster_position = self.owner_roster_position.map(CanonicalItem::unsigned16);
        let schedule_position = self.schedule_position.map(CanonicalItem::unsigned32);
        let commitment_data_prime_index = self
            .commitment_data_prime_index
            .map(CanonicalItem::unsigned16);
        CanonicalTuple::new(
            SETUP_PUBLIC_POLYNOMIAL_CONTEXT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.setup_proof_context_hash),
                CanonicalItem::unsigned16(self.root_role as u16),
                CanonicalItem::optional(
                    CanonicalItemType::ParticipantIdentity,
                    owner_participant_identity.as_ref(),
                )
                .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(
                    CanonicalItemType::Unsigned16,
                    owner_roster_position.as_ref(),
                )
                .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(CanonicalItemType::Unsigned32, schedule_position.as_ref())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(
                    CanonicalItemType::Unsigned16,
                    commitment_data_prime_index.as_ref(),
                )
                .map_err(canonical_encoding_error)?,
            ],
        )
        .encode()
        .map_err(canonical_encoding_error)
    }

    pub(crate) fn context_hash(&self) -> Result<[u8; 64], SetupPublicPolynomialError> {
        Ok(hash_foundation_tuple_512(
            CONTEXT_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)
                .map_err(canonical_encoding_error)?],
        )
        .map_err(canonical_encoding_error)?
        .into_bytes())
    }
}

pub(crate) struct SetupPublicPolynomialTreeInput<'input> {
    pub(crate) context: &'input SetupPublicPolynomialContext,
    pub(crate) evaluation_domain_size: usize,
    pub(crate) source_polynomial_degree_bound_exclusive: usize,
    pub(crate) ordered_coefficient_columns: &'input [Vec<ProofBaseFieldElement>],
}

pub(crate) struct SetupPublicPolynomialTree {
    public_polynomial_context_hash: [u8; 64],
    root_role: SetupPublicPolynomialRootRole,
    schedule_position: Option<u32>,
    source_polynomial_degree_bound_exclusive: usize,
    ordered_coefficient_columns: Vec<Vec<ProofBaseFieldElement>>,
    extension_columns: Vec<Vec<ProofBaseFieldElement>>,
    merkle_levels: Vec<Vec<[u8; 64]>>,
}

impl SetupPublicPolynomialTree {
    /// Decodes the sole canonical lattice-anchor representation and derives
    /// the role-one tree from the low and high coefficient halves of each
    /// logical row, in row-major order. The selected prime is checked against
    /// the typed context; neither an object hash nor a claimed Merkle root is
    /// accepted.
    pub(crate) fn from_lattice_anchor_canonical_bytes(
        context: &SetupPublicPolynomialContext,
        evaluation_domain_size: usize,
        canonical_commitment_bytes: &[u8],
    ) -> Result<Self, SetupPublicPolynomialError> {
        let commitment =
            parse_lattice_anchor_commitment_canonical_bytes(canonical_commitment_bytes)
                .map_err(|_| SetupPublicPolynomialError::InvalidLatticeAnchor)?;
        let commitment_data_prime_index = u16::try_from(commitment.commitment_data_prime_index)
            .map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        if context.root_role != SetupPublicPolynomialRootRole::LatticeAnchor
            || context.commitment_data_prime_index != Some(commitment_data_prime_index)
        {
            return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
        }
        let physical_column_coefficient_count = commitment.ring_degree / 2;
        if physical_column_coefficient_count == 0
            || physical_column_coefficient_count.checked_mul(2) != Some(commitment.ring_degree)
        {
            return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
        }
        let physical_column_count = commitment
            .rows
            .len()
            .checked_mul(2)
            .ok_or(SetupPublicPolynomialError::CountOverflow)?;
        let mut ordered_coefficient_columns = Vec::with_capacity(physical_column_count);
        for logical_row in &commitment.rows {
            if logical_row.len() != commitment.ring_degree {
                return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
            }
            let (low_coefficients, high_coefficients) =
                logical_row.split_at(physical_column_coefficient_count);
            for physical_column in [low_coefficients, high_coefficients] {
                ordered_coefficient_columns.push(
                    physical_column
                        .iter()
                        .map(|coefficient| ProofBaseFieldElement::from_canonical(*coefficient))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
        }
        Self::construct_from_canonical_coefficients(SetupPublicPolynomialTreeInput {
            context,
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive: commitment.ring_degree,
            ordered_coefficient_columns: &ordered_coefficient_columns,
        })
    }

    pub(crate) fn construct(
        input: SetupPublicPolynomialTreeInput<'_>,
    ) -> Result<Self, SetupPublicPolynomialError> {
        if input.context.root_role == SetupPublicPolynomialRootRole::LatticeAnchor {
            return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
        }
        Self::construct_from_canonical_coefficients(input)
    }

    fn construct_from_canonical_coefficients(
        input: SetupPublicPolynomialTreeInput<'_>,
    ) -> Result<Self, SetupPublicPolynomialError> {
        if input.evaluation_domain_size < 2
            || !input.evaluation_domain_size.is_power_of_two()
            || input.source_polynomial_degree_bound_exclusive == 0
            || input.source_polynomial_degree_bound_exclusive > input.evaluation_domain_size
            || input.ordered_coefficient_columns.is_empty()
            || u32::try_from(input.ordered_coefficient_columns.len()).is_err()
            || input.ordered_coefficient_columns.iter().any(|column| {
                column.is_empty() || column.len() > input.source_polynomial_degree_bound_exclusive
            })
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let evaluation_domain = ProofEvaluationDomain::new(
            input.evaluation_domain_size,
            PROOF_EVALUATION_COSET_OFFSET,
        )?;
        let public_polynomial_context_hash = input.context.context_hash()?;
        let ordered_coefficient_columns = input.ordered_coefficient_columns.to_vec();
        let extension_columns = ordered_coefficient_columns
            .iter()
            .map(|coefficients| evaluation_domain.evaluate_base_polynomial(coefficients))
            .collect::<Result<Vec<_>, _>>()?;
        let leaf_count = input.evaluation_domain_size / 2;
        let leaf_digests = (0..leaf_count)
            .map(|leaf_index| {
                canonical_phase_pair_leaf_bytes(
                    public_polynomial_context_hash,
                    &extension_columns,
                    leaf_index,
                )
                .and_then(|bytes| canonical_leaf_digest(&bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let merkle_levels = build_merkle_levels(public_polynomial_context_hash, leaf_digests)?;
        Ok(Self {
            public_polynomial_context_hash,
            root_role: input.context.root_role(),
            schedule_position: input.context.schedule_position(),
            source_polynomial_degree_bound_exclusive: input
                .source_polynomial_degree_bound_exclusive,
            ordered_coefficient_columns,
            extension_columns,
            merkle_levels,
        })
    }

    pub(crate) const fn public_polynomial_context_hash(&self) -> [u8; 64] {
        self.public_polynomial_context_hash
    }

    pub(crate) const fn root_role(&self) -> SetupPublicPolynomialRootRole {
        self.root_role
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn source_polynomial_degree_bound_exclusive(&self) -> usize {
        self.source_polynomial_degree_bound_exclusive
    }

    pub(crate) fn ordered_coefficient_columns(&self) -> &[Vec<ProofBaseFieldElement>] {
        &self.ordered_coefficient_columns
    }

    /// Consumes a verifier-built tree and releases its large evaluation and
    /// Merkle layers while preserving the exact coefficient columns whose
    /// committed root was opened by the common proof verifier.
    pub(crate) fn into_ordered_coefficient_columns(self) -> Vec<Vec<ProofBaseFieldElement>> {
        self.ordered_coefficient_columns
    }

    pub(crate) fn extension_columns(&self) -> &[Vec<ProofBaseFieldElement>] {
        &self.extension_columns
    }

    pub(crate) fn row_width(&self) -> u32 {
        u32::try_from(self.extension_columns.len())
            .expect("a constructed public-polynomial tree has a canonical row width")
    }

    pub(crate) fn leaf_count(&self) -> usize {
        self.extension_columns[0].len() / 2
    }

    pub(crate) fn root(&self) -> [u8; 64] {
        self.merkle_levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("a constructed public-polynomial tree has one terminal root")
    }

    pub(crate) fn canonical_leaf_bytes(
        &self,
        leaf_index: usize,
    ) -> Result<Vec<u8>, SetupPublicPolynomialError> {
        canonical_phase_pair_leaf_bytes(
            self.public_polynomial_context_hash,
            &self.extension_columns,
            leaf_index,
        )
    }
}

fn canonical_phase_pair_leaf_bytes(
    public_polynomial_context_hash: [u8; 64],
    extension_columns: &[Vec<ProofBaseFieldElement>],
    leaf_index: usize,
) -> Result<Vec<u8>, SetupPublicPolynomialError> {
    if extension_columns.is_empty()
        || extension_columns.iter().any(|column| {
            column.len() != extension_columns[0].len() || !column.len().is_power_of_two()
        })
        || extension_columns[0].len() < 2
        || leaf_index >= extension_columns[0].len() / 2
    {
        return Err(SetupPublicPolynomialError::InvalidInput);
    }
    let opposite_index = leaf_index
        .checked_add(extension_columns[0].len() / 2)
        .ok_or(SetupPublicPolynomialError::CountOverflow)?;
    let first_values = extension_columns
        .iter()
        .map(|column| canonical_field_item(column[leaf_index]))
        .collect::<Result<Vec<_>, _>>()?;
    let opposite_values = extension_columns
        .iter()
        .map(|column| canonical_field_item(column[opposite_index]))
        .collect::<Result<Vec<_>, _>>()?;
    CanonicalTuple::new(
        SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(public_polynomial_context_hash),
            CanonicalItem::unsigned64(
                u64::try_from(leaf_index).map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
            ),
            CanonicalItem::homogeneous_list(CanonicalItemType::FieldElement, &first_values)
                .map_err(canonical_encoding_error)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::FieldElement, &opposite_values)
                .map_err(canonical_encoding_error)?,
        ],
    )
    .encode()
    .map_err(canonical_encoding_error)
}

fn canonical_field_item(
    value: ProofBaseFieldElement,
) -> Result<CanonicalItem, SetupPublicPolynomialError> {
    CanonicalItem::from_canonical_bytes(
        CanonicalItemType::FieldElement,
        value.canonical().to_le_bytes().to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .map_err(canonical_encoding_error)
}

fn canonical_leaf_digest(canonical_bytes: &[u8]) -> Result<[u8; 64], SetupPublicPolynomialError> {
    Ok(hash_foundation_tuple_512(
        PHASE_PAIR_LEAF_HASH_DOMAIN,
        &[CanonicalItem::variable_bytes(canonical_bytes).map_err(canonical_encoding_error)?],
    )
    .map_err(canonical_encoding_error)?
    .into_bytes())
}

fn build_merkle_levels(
    public_polynomial_context_hash: [u8; 64],
    leaf_digests: Vec<[u8; 64]>,
) -> Result<Vec<Vec<[u8; 64]>>, SetupPublicPolynomialError> {
    if leaf_digests.is_empty() || !leaf_digests.len().is_power_of_two() {
        return Err(SetupPublicPolynomialError::InvalidInput);
    }
    let mut levels = vec![leaf_digests];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let child_level = levels
            .last()
            .ok_or(SetupPublicPolynomialError::InvalidInput)?;
        let level =
            u32::try_from(levels.len()).map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        let parents = child_level
            .chunks_exact(2)
            .enumerate()
            .map(|(parent_index, children)| {
                let left_child_index = parent_index
                    .checked_mul(2)
                    .ok_or(SetupPublicPolynomialError::CountOverflow)?;
                Ok::<[u8; 64], SetupPublicPolynomialError>(
                    hash_foundation_tuple_512(
                        MERKLE_NODE_HASH_DOMAIN,
                        &[
                            CanonicalItem::hash512(public_polynomial_context_hash),
                            CanonicalItem::unsigned32(level),
                            CanonicalItem::unsigned64(
                                u64::try_from(left_child_index)
                                    .map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
                            ),
                            CanonicalItem::hash512(children[0]),
                            CanonicalItem::hash512(children[1]),
                        ],
                    )
                    .map_err(canonical_encoding_error)?
                    .into_bytes(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        levels.push(parents);
    }
    Ok(levels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::{
        parameters::POLYNOMIAL_DEGREE,
        setup::{
            LatticeAnchorCommitment, SETUP_COMMITMENT_MODULE_RANK,
            lattice_anchor_commitment_canonical_bytes,
        },
    };

    fn lattice_anchor_context() -> SetupPublicPolynomialContext {
        SetupPublicPolynomialContext::lattice_anchor([0x31; 64], [0x71; 64], 2, 1)
            .expect("the selected role-one context is canonical")
    }

    fn public_key_share_context() -> SetupPublicPolynomialContext {
        SetupPublicPolynomialContext::public_key_share([0x31; 64], [0x71; 64], 2)
            .expect("the public-key-share context is canonical")
    }

    fn construct_test_tree(
        second_row_constant: u64,
    ) -> Result<SetupPublicPolynomialTree, SetupPublicPolynomialError> {
        let context = public_key_share_context();
        let ordered_coefficient_columns = vec![
            vec![
                ProofBaseFieldElement::from_canonical(3)?,
                ProofBaseFieldElement::from_canonical(5)?,
            ],
            vec![ProofBaseFieldElement::from_canonical(second_row_constant)?],
        ];
        SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
            context: &context,
            evaluation_domain_size: 8,
            source_polynomial_degree_bound_exclusive: 4,
            ordered_coefficient_columns: &ordered_coefficient_columns,
        })
    }

    #[test]
    fn lattice_anchor_context_requires_one_selected_commitment_prime() {
        assert_eq!(
            SetupPublicPolynomialContext::lattice_anchor([0x31; 64], [0x71; 64], 2, 3),
            Err(SetupPublicPolynomialError::InvalidContext),
        );
        assert_eq!(
            SetupPublicPolynomialContext::new(
                [0x31; 64],
                SetupPublicPolynomialRootRole::LatticeAnchor,
                Some([0x71; 64]),
                None,
                None,
                Some(1),
            ),
            Err(SetupPublicPolynomialError::InvalidContext),
        );
    }

    #[test]
    fn coefficient_mutation_changes_the_recomputed_public_polynomial_root() {
        let original = construct_test_tree(7).expect("the original tree is canonical");
        let changed = construct_test_tree(8).expect("the changed tree is canonical");

        assert_eq!(original.row_width(), 2);
        assert_eq!(original.leaf_count(), 4);
        assert_ne!(original.root(), changed.root());
        assert_ne!(
            original.canonical_leaf_bytes(0).expect("the leaf encodes"),
            changed.canonical_leaf_bytes(0).expect("the leaf encodes"),
        );
    }

    #[test]
    fn canonical_lattice_anchor_provider_uses_relation_column_order_and_rejects_detached_columns() {
        let context = lattice_anchor_context();
        let physical_column_coefficient_count = POLYNOMIAL_DEGREE / 2;
        let mut commitment = LatticeAnchorCommitment {
            commitment_data_prime_index: 1,
            ring_degree: POLYNOMIAL_DEGREE,
            rows: vec![
                vec![0; POLYNOMIAL_DEGREE];
                SETUP_COMMITMENT_MODULE_RANK
                    .checked_add(1)
                    .expect("the anchor row count fits usize")
            ],
        };
        commitment.rows[0][0] = 3;
        commitment.rows[0][physical_column_coefficient_count - 1] = 5;
        commitment.rows[0][physical_column_coefficient_count] = 7;
        commitment.rows[0][POLYNOMIAL_DEGREE - 1] = 11;
        commitment.rows[1][0] = 13;
        commitment.rows[1][physical_column_coefficient_count - 1] = 17;
        commitment.rows[1][physical_column_coefficient_count] = 19;
        commitment.rows[1][POLYNOMIAL_DEGREE - 1] = 23;
        let canonical_bytes = lattice_anchor_commitment_canonical_bytes(&commitment)
            .expect("the anchor bytes are canonical");
        let original = SetupPublicPolynomialTree::from_lattice_anchor_canonical_bytes(
            &context,
            2 * POLYNOMIAL_DEGREE,
            &canonical_bytes,
        )
        .expect("the canonical anchor builds its role-one tree");
        let original_root = original.root();
        assert_eq!(original.row_width(), 4);
        assert_eq!(
            original.source_polynomial_degree_bound_exclusive(),
            POLYNOMIAL_DEGREE,
        );
        let expected_physical_columns = [
            &commitment.rows[0][..physical_column_coefficient_count],
            &commitment.rows[0][physical_column_coefficient_count..],
            &commitment.rows[1][..physical_column_coefficient_count],
            &commitment.rows[1][physical_column_coefficient_count..],
        ];
        for (physical_column, expected_coefficients) in original
            .ordered_coefficient_columns()
            .iter()
            .zip(expected_physical_columns)
        {
            assert_eq!(
                physical_column
                    .iter()
                    .map(|coefficient| coefficient.canonical())
                    .collect::<Vec<_>>(),
                expected_coefficients,
            );
        }

        let mut wrong_order_columns = original.ordered_coefficient_columns().to_vec();
        wrong_order_columns.swap(1, 2);
        drop(original);
        assert_eq!(
            SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
                context: &context,
                evaluation_domain_size: 2 * POLYNOMIAL_DEGREE,
                source_polynomial_degree_bound_exclusive: POLYNOMIAL_DEGREE,
                ordered_coefficient_columns: &wrong_order_columns,
            })
            .map(|tree| tree.root()),
            Err(SetupPublicPolynomialError::InvalidLatticeAnchor),
        );
        let wrong_order_tree = SetupPublicPolynomialTree::construct_from_canonical_coefficients(
            SetupPublicPolynomialTreeInput {
                context: &context,
                evaluation_domain_size: 2 * POLYNOMIAL_DEGREE,
                source_polynomial_degree_bound_exclusive: POLYNOMIAL_DEGREE,
                ordered_coefficient_columns: &wrong_order_columns,
            },
        )
        .expect("the detached columns remain individually well formed");
        assert_ne!(original_root, wrong_order_tree.root());
        drop(wrong_order_tree);

        commitment.rows[1][3] = 1;
        let changed_bytes = lattice_anchor_commitment_canonical_bytes(&commitment)
            .expect("the changed anchor bytes are canonical");
        let changed = SetupPublicPolynomialTree::from_lattice_anchor_canonical_bytes(
            &context,
            2 * POLYNOMIAL_DEGREE,
            &changed_bytes,
        )
        .expect("the changed anchor builds its role-one tree");
        assert_ne!(original_root, changed.root());

        let wrong_prime_context =
            SetupPublicPolynomialContext::lattice_anchor([0x31; 64], [0x71; 64], 2, 2)
                .expect("the other selected prime context is canonical");
        assert_eq!(
            SetupPublicPolynomialTree::from_lattice_anchor_canonical_bytes(
                &wrong_prime_context,
                2 * POLYNOMIAL_DEGREE,
                &changed_bytes,
            )
            .map(|tree| tree.root()),
            Err(SetupPublicPolynomialError::InvalidLatticeAnchor),
        );
    }
}
