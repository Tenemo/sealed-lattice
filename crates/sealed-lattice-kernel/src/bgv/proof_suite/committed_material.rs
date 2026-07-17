//! Persistent committed-material trees over the common proof field.
//!
//! A logical lattice message has one reusable root. Its two canonical
//! radix-three digit columns are split into two coefficient halves, masked as
//! polynomials over the trace subgroup, and committed in the fixed physical
//! order `[low half 0, low half 1, high half 0, high half 1]`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    mem::size_of,
};

use tiny_keccak::{Hasher, Kmac};
use zeroize::Zeroizing;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    hash_foundation_tuple_512,
};

use super::{
    BoundedCommonProofByteSinkError, CommonProofBoundOpeningProvider, CommonProofEncodingError,
    CommonProofOpeningArtifact, CommonProofOpeningGeometry, CommonProofProverError,
    CommonProofSourcePolynomial, CompleteProofTreeCatalog, PROOF_BASE_FIELD_MODULUS,
    PROOF_EVALUATION_BLOWUP_FACTOR, PROOF_EVALUATION_COSET_OFFSET,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, ProofBaseFieldElement,
    ProofEvaluationDomain, ProofFieldError, ProofPolynomialError, ProofTreeCatalogEntry,
    ProofTreeCatalogSource, apply_trace_mask, encode_common_proof_query_tree_fragment,
};

const MATERIAL_DERIVATION_INPUT_SCHEMA_IDENTIFIER: u16 = 0x2105;
pub(super) const COMMITTED_MATERIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER: u16 = 0x2102;
const SCHEMA_VERSION: u16 = 1;
const MATERIAL_COLUMN_COUNT: usize = 4;
const MATERIAL_DIGIT_COLUMN_COUNT: usize = 2;
const SECRET_LEAF_SALT_BYTE_LENGTH: usize = 48;
const DERIVED_BLOCK_BYTE_LENGTH: usize = 64;
const MAXIMUM_MASKING_POLYNOMIAL_DEGREE: usize = 2_047;

const PRIVATE_DERIVATION_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/setup/vss-committed-material/private-derivation/v1";
const PHASE_PAIR_LEAF_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-committed-material/phase-pair-leaf/v1";
const MERKLE_NODE_HASH_DOMAIN: &str = "sealed-lattice/setup/vss-committed-material/merkle-node/v1";
const COLUMN_MASK_PURPOSE: &str = "column-mask";
const LEAF_SALT_PURPOSE: &str = "leaf-salt";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommittedMaterialError {
    InvalidProfile,
    InvalidInput,
    CandidateDrawCeilingExceeded,
    CountOverflow,
    CanonicalEncoding,
    Field(ProofFieldError),
    Polynomial(ProofPolynomialError),
    Prover(CommonProofProverError),
}

impl From<ProofFieldError> for CommittedMaterialError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

impl From<ProofPolynomialError> for CommittedMaterialError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

impl From<CommonProofProverError> for CommittedMaterialError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

fn canonical_encoding_error<T>(_: T) -> CommittedMaterialError {
    CommittedMaterialError::CanonicalEncoding
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommittedMaterialProfile {
    trace_domain_size: usize,
    evaluation_domain_size: usize,
    evaluation_coset_offset: u64,
    masking_polynomial_maximum_degree: usize,
    committed_polynomial_degree_bound_exclusive: usize,
    material_column_degree_bound_exclusive: usize,
}

impl CommittedMaterialProfile {
    pub(crate) fn selected(ring_degree: usize) -> Result<Self, CommittedMaterialError> {
        let (
            trace_domain_size,
            masking_polynomial_maximum_degree,
            material_column_degree_bound_exclusive,
            minimum_committed_polynomial_degree_bound_exclusive,
        ) = Self::degree_bounds(ring_degree)?;
        let evaluation_domain_size = minimum_committed_polynomial_degree_bound_exclusive
            .checked_mul(
                usize::try_from(PROOF_EVALUATION_BLOWUP_FACTOR)
                    .map_err(|_| CommittedMaterialError::CountOverflow)?,
            )
            .ok_or(CommittedMaterialError::CountOverflow)?;
        Self::new(
            trace_domain_size,
            evaluation_domain_size,
            masking_polynomial_maximum_degree,
            minimum_committed_polynomial_degree_bound_exclusive,
            material_column_degree_bound_exclusive,
        )
    }

    /// Selects the same masked material polynomials on the evaluation domain
    /// of the consuming common proof. A persistent root is therefore opened
    /// directly by that proof rather than being reinterpreted through a
    /// second, incompatible tree domain.
    pub(crate) fn for_common_proof_evaluation_domain(
        ring_degree: usize,
        evaluation_domain_size: usize,
    ) -> Result<Self, CommittedMaterialError> {
        let (
            trace_domain_size,
            masking_polynomial_maximum_degree,
            material_column_degree_bound_exclusive,
            minimum_committed_polynomial_degree_bound_exclusive,
        ) = Self::degree_bounds(ring_degree)?;
        let blowup_factor = usize::try_from(PROOF_EVALUATION_BLOWUP_FACTOR)
            .map_err(|_| CommittedMaterialError::CountOverflow)?;
        let committed_polynomial_degree_bound_exclusive = evaluation_domain_size
            .checked_div(blowup_factor)
            .filter(|degree_bound| {
                *degree_bound >= minimum_committed_polynomial_degree_bound_exclusive
                    && *degree_bound * blowup_factor == evaluation_domain_size
            })
            .ok_or(CommittedMaterialError::InvalidProfile)?;
        Self::new(
            trace_domain_size,
            evaluation_domain_size,
            masking_polynomial_maximum_degree,
            committed_polynomial_degree_bound_exclusive,
            material_column_degree_bound_exclusive,
        )
    }

    fn degree_bounds(
        ring_degree: usize,
    ) -> Result<(usize, usize, usize, usize), CommittedMaterialError> {
        let trace_domain_size = ring_degree
            .checked_div(2)
            .filter(|trace_size| {
                ring_degree.is_power_of_two() && ring_degree >= 8 && *trace_size * 2 == ring_degree
            })
            .ok_or(CommittedMaterialError::InvalidProfile)?;
        let masking_polynomial_maximum_degree =
            MAXIMUM_MASKING_POLYNOMIAL_DEGREE.min(trace_domain_size - 1);
        let mask_coefficient_count = masking_polynomial_maximum_degree
            .checked_add(1)
            .ok_or(CommittedMaterialError::CountOverflow)?;
        let material_column_degree_bound_exclusive = trace_domain_size
            .checked_add(mask_coefficient_count)
            .ok_or(CommittedMaterialError::CountOverflow)?;

        // The persistent root must use the largest consuming domain. Cubic
        // trit constraints dominate the selector-times-material linkage rows.
        let maximum_consuming_numerator_degree = material_column_degree_bound_exclusive
            .checked_sub(1)
            .and_then(|degree| degree.checked_mul(3))
            .ok_or(CommittedMaterialError::CountOverflow)?;
        let minimum_committed_polynomial_degree_bound_exclusive =
            maximum_consuming_numerator_degree
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or(CommittedMaterialError::CountOverflow)?;
        Ok((
            trace_domain_size,
            masking_polynomial_maximum_degree,
            material_column_degree_bound_exclusive,
            minimum_committed_polynomial_degree_bound_exclusive,
        ))
    }

    fn new(
        trace_domain_size: usize,
        evaluation_domain_size: usize,
        masking_polynomial_maximum_degree: usize,
        committed_polynomial_degree_bound_exclusive: usize,
        material_column_degree_bound_exclusive: usize,
    ) -> Result<Self, CommittedMaterialError> {
        let profile = Self {
            trace_domain_size,
            evaluation_domain_size,
            evaluation_coset_offset: PROOF_EVALUATION_COSET_OFFSET,
            masking_polynomial_maximum_degree,
            committed_polynomial_degree_bound_exclusive,
            material_column_degree_bound_exclusive,
        };
        profile.validate()?;
        Ok(profile)
    }

    fn validate(self) -> Result<(), CommittedMaterialError> {
        if self.trace_domain_size < 4
            || !self.trace_domain_size.is_power_of_two()
            || self.evaluation_domain_size == 0
            || !self.evaluation_domain_size.is_power_of_two()
            || self.evaluation_domain_size
                != self
                    .committed_polynomial_degree_bound_exclusive
                    .checked_mul(
                        usize::try_from(PROOF_EVALUATION_BLOWUP_FACTOR)
                            .map_err(|_| CommittedMaterialError::CountOverflow)?,
                    )
                    .ok_or(CommittedMaterialError::CountOverflow)?
            || self.evaluation_coset_offset != PROOF_EVALUATION_COSET_OFFSET
            || self.masking_polynomial_maximum_degree >= self.trace_domain_size
            || self.material_column_degree_bound_exclusive
                != self
                    .trace_domain_size
                    .checked_add(self.masking_polynomial_maximum_degree + 1)
                    .ok_or(CommittedMaterialError::CountOverflow)?
            || self.material_column_degree_bound_exclusive
                >= self.committed_polynomial_degree_bound_exclusive
            || !self
                .evaluation_domain_size
                .is_multiple_of(self.trace_domain_size)
            || u64::try_from(self.evaluation_domain_size)
                .ok()
                .is_none_or(|size| !(PROOF_BASE_FIELD_MODULUS - 1).is_multiple_of(size))
        {
            return Err(CommittedMaterialError::InvalidProfile);
        }
        ProofEvaluationDomain::new(self.evaluation_domain_size, self.evaluation_coset_offset)?;
        Ok(())
    }

    pub(crate) const fn trace_domain_size(self) -> usize {
        self.trace_domain_size
    }

    pub(crate) const fn evaluation_domain_size(self) -> usize {
        self.evaluation_domain_size
    }

    pub(crate) const fn evaluation_coset_offset(self) -> u64 {
        self.evaluation_coset_offset
    }

    pub(crate) const fn masking_polynomial_maximum_degree(self) -> usize {
        self.masking_polynomial_maximum_degree
    }

    pub(crate) const fn committed_polynomial_degree_bound_exclusive(self) -> usize {
        self.committed_polynomial_degree_bound_exclusive
    }

    pub(crate) const fn material_column_degree_bound_exclusive(self) -> usize {
        self.material_column_degree_bound_exclusive
    }
}

pub(crate) struct CommittedMaterialTreeInput<'input> {
    pub(crate) profile: CommittedMaterialProfile,
    pub(crate) material_context_hash: [u8; 64],
    pub(crate) material_seed: [u8; 64],
    pub(crate) message_digit_columns: &'input [Vec<u64>],
}

pub(crate) struct CommittedMaterialTree {
    profile: CommittedMaterialProfile,
    material_context_hash: [u8; 64],
    material_seed: Zeroizing<[u8; 64]>,
    masked_coefficients_by_physical_column: Vec<Vec<ProofBaseFieldElement>>,
    extension_columns: Vec<Vec<ProofBaseFieldElement>>,
    merkle_levels: Vec<Vec<[u8; 64]>>,
}

impl fmt::Debug for CommittedMaterialTree {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedMaterialTree")
            .field("profile", &self.profile)
            .field("material_context_hash", &self.material_context_hash)
            .field("material_seed", &"[REDACTED]")
            .field(
                "masked_physical_column_count",
                &self.masked_coefficients_by_physical_column.len(),
            )
            .field("extension_column_count", &self.extension_columns.len())
            .field("merkle_level_count", &self.merkle_levels.len())
            .finish()
    }
}

impl CommittedMaterialTree {
    pub(crate) fn construct(
        input: CommittedMaterialTreeInput<'_>,
    ) -> Result<Self, CommittedMaterialError> {
        input.profile.validate()?;
        if input.message_digit_columns.len() != MATERIAL_DIGIT_COLUMN_COUNT
            || input.message_digit_columns.iter().any(|column| {
                column.len() != input.profile.trace_domain_size.checked_mul(2).unwrap_or(0)
                    || column
                        .iter()
                        .any(|value| *value >= PROOF_BASE_FIELD_MODULUS)
            })
        {
            return Err(CommittedMaterialError::InvalidInput);
        }
        let trace_domain = ProofEvaluationDomain::new_subgroup(input.profile.trace_domain_size)?;
        let evaluation_domain = ProofEvaluationDomain::new(
            input.profile.evaluation_domain_size,
            input.profile.evaluation_coset_offset,
        )?;
        let material_seed = Zeroizing::new(input.material_seed);
        let mask_coefficient_count = input
            .profile
            .masking_polynomial_maximum_degree
            .checked_add(1)
            .ok_or(CommittedMaterialError::CountOverflow)?;
        let mut masked_coefficients_by_physical_column = Vec::with_capacity(MATERIAL_COLUMN_COUNT);
        let mut extension_columns = Vec::with_capacity(MATERIAL_COLUMN_COUNT);
        for (digit_column_ordinal, digit_column) in input.message_digit_columns.iter().enumerate() {
            for half_ordinal in 0..2 {
                let physical_column_ordinal = digit_column_ordinal * 2 + half_ordinal;
                let half_start = half_ordinal * input.profile.trace_domain_size;
                let half_end = half_start
                    .checked_add(input.profile.trace_domain_size)
                    .ok_or(CommittedMaterialError::CountOverflow)?;
                let trace_values = digit_column[half_start..half_end]
                    .iter()
                    .copied()
                    .map(ProofBaseFieldElement::from_canonical)
                    .collect::<Result<Vec<_>, _>>()?;
                let witness_coefficients =
                    trace_domain.interpolate_base_polynomial(&trace_values)?;
                let mut derivation = MaterialPrivateDerivation::new(
                    &material_seed,
                    input.material_context_hash,
                    COLUMN_MASK_PURPOSE,
                    u64::try_from(physical_column_ordinal)
                        .map_err(|_| CommittedMaterialError::CountOverflow)?,
                );
                let mut mask_coefficients = Vec::with_capacity(mask_coefficient_count);
                for _ in 0..mask_coefficient_count {
                    mask_coefficients.push(ProofBaseFieldElement::from_canonical(
                        derivation.sample_uniform_base_field()?,
                    )?);
                }
                let masked_coefficients = match apply_trace_mask(
                    CommonProofSourcePolynomial::Base(witness_coefficients),
                    u64::try_from(input.profile.trace_domain_size)
                        .map_err(|_| CommittedMaterialError::CountOverflow)?,
                    CommonProofSourcePolynomial::Base(mask_coefficients),
                )? {
                    CommonProofSourcePolynomial::Base(coefficients) => coefficients,
                    CommonProofSourcePolynomial::Extension(_) => {
                        return Err(CommittedMaterialError::InvalidInput);
                    }
                };
                if masked_coefficients.len() > input.profile.material_column_degree_bound_exclusive
                {
                    return Err(CommittedMaterialError::InvalidProfile);
                }
                extension_columns
                    .push(evaluation_domain.evaluate_base_polynomial(&masked_coefficients)?);
                masked_coefficients_by_physical_column.push(masked_coefficients);
            }
        }

        let leaf_count = input.profile.evaluation_domain_size / 2;
        let mut leaf_digests = Vec::with_capacity(leaf_count);
        for leaf_index in 0..leaf_count {
            let canonical_leaf_bytes = canonical_phase_pair_leaf_bytes(
                input.material_context_hash,
                &material_seed,
                &extension_columns,
                leaf_index,
            )?;
            leaf_digests.push(
                hash_foundation_tuple_512(
                    PHASE_PAIR_LEAF_HASH_DOMAIN,
                    &[CanonicalItem::variable_bytes(canonical_leaf_bytes)
                        .map_err(canonical_encoding_error)?],
                )
                .map_err(canonical_encoding_error)?
                .into_bytes(),
            );
        }
        let merkle_levels = build_merkle_levels(leaf_digests)?;
        Ok(Self {
            profile: input.profile,
            material_context_hash: input.material_context_hash,
            material_seed,
            masked_coefficients_by_physical_column,
            extension_columns,
            merkle_levels,
        })
    }

    pub(crate) const fn profile(&self) -> CommittedMaterialProfile {
        self.profile
    }

    pub(crate) const fn material_context_hash(&self) -> [u8; 64] {
        self.material_context_hash
    }

    pub(crate) fn masked_coefficients_by_physical_column(&self) -> &[Vec<ProofBaseFieldElement>] {
        &self.masked_coefficients_by_physical_column
    }

    pub(crate) fn extension_columns(&self) -> &[Vec<ProofBaseFieldElement>] {
        &self.extension_columns
    }

    pub(crate) fn root(&self) -> [u8; 64] {
        self.merkle_levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("a constructed committed-material tree has one terminal root")
    }

    pub(crate) fn canonical_leaf_bytes(
        &self,
        leaf_index: usize,
    ) -> Result<Vec<u8>, CommittedMaterialError> {
        canonical_phase_pair_leaf_bytes(
            self.material_context_hash,
            &self.material_seed,
            &self.extension_columns,
            leaf_index,
        )
    }

    pub(crate) fn authentication_frontier(
        &self,
        sorted_unique_leaf_indices: &[usize],
    ) -> Result<Vec<(u32, u64, [u8; 64])>, CommittedMaterialError> {
        if sorted_unique_leaf_indices.is_empty()
            || sorted_unique_leaf_indices
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || sorted_unique_leaf_indices
                .last()
                .is_none_or(|index| *index >= self.merkle_levels[0].len())
        {
            return Err(CommittedMaterialError::InvalidInput);
        }
        let mut current = sorted_unique_leaf_indices
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut frontier = Vec::new();
        for (level_ordinal, level) in self
            .merkle_levels
            .iter()
            .take(self.merkle_levels.len() - 1)
            .enumerate()
        {
            let mut next = BTreeSet::new();
            for index in current.iter().copied() {
                let sibling_index = index ^ 1;
                if !current.contains(&sibling_index) {
                    frontier.push((
                        u32::try_from(level_ordinal)
                            .map_err(|_| CommittedMaterialError::CountOverflow)?,
                        u64::try_from(sibling_index)
                            .map_err(|_| CommittedMaterialError::CountOverflow)?,
                        *level
                            .get(sibling_index)
                            .ok_or(CommittedMaterialError::InvalidInput)?,
                    ));
                }
                next.insert(index / 2);
            }
            current = next;
        }
        frontier.sort_by_key(|(level, index, _)| (*level, *index));
        Ok(frontier)
    }
}

struct CommittedMaterialOpeningArtifact<'tree> {
    tree_catalog_index: u16,
    canonical_leaf_byte_length: usize,
    tree: &'tree CommittedMaterialTree,
}

impl CommonProofOpeningArtifact for CommittedMaterialOpeningArtifact<'_> {
    type Error = CommittedMaterialError;

    fn tree_catalog_index(&self) -> u16 {
        self.tree_catalog_index
    }

    fn leaf_count(&self) -> usize {
        self.tree.profile.evaluation_domain_size / 2
    }

    fn canonical_leaf_byte_length(&self) -> usize {
        self.canonical_leaf_byte_length
    }

    fn read_canonical_leaf(
        &mut self,
        leaf_index: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let canonical_bytes = self.tree.canonical_leaf_bytes(
            usize::try_from(leaf_index).map_err(|_| CommittedMaterialError::CountOverflow)?,
        )?;
        if canonical_bytes.len() != self.canonical_leaf_byte_length
            || destination.len() != self.canonical_leaf_byte_length
        {
            return Err(CommittedMaterialError::InvalidInput);
        }
        destination.copy_from_slice(&canonical_bytes);
        Ok(())
    }

    fn read_digest(&mut self, level: u32, node_index: u64) -> Result<[u8; 64], Self::Error> {
        self.tree
            .merkle_levels
            .get(usize::try_from(level).map_err(|_| CommittedMaterialError::CountOverflow)?)
            .and_then(|nodes| {
                usize::try_from(node_index)
                    .ok()
                    .and_then(|index| nodes.get(index))
            })
            .copied()
            .ok_or(CommittedMaterialError::InvalidInput)
    }
}

/// Catalog-indexed adapter for persistent committed-material roots. It feeds
/// the same generated prover used by every application family and never
/// reconstructs a second proof-specific representation of the tree.
pub(crate) struct CommittedMaterialBoundOpeningProvider<'tree> {
    artifacts: BTreeMap<u16, CommittedMaterialOpeningArtifact<'tree>>,
}

impl<'tree> CommittedMaterialBoundOpeningProvider<'tree> {
    pub(crate) fn new(
        trees: impl IntoIterator<Item = (u16, &'tree CommittedMaterialTree)>,
    ) -> Result<Self, CommittedMaterialError> {
        let mut artifacts = BTreeMap::new();
        for (tree_catalog_index, tree) in trees {
            let canonical_leaf_byte_length = tree.canonical_leaf_bytes(0)?.len();
            let artifact = CommittedMaterialOpeningArtifact {
                tree_catalog_index,
                canonical_leaf_byte_length,
                tree,
            };
            if artifacts.insert(tree_catalog_index, artifact).is_some() {
                return Err(CommittedMaterialError::InvalidInput);
            }
        }
        if artifacts.is_empty() {
            return Err(CommittedMaterialError::InvalidInput);
        }
        Ok(Self { artifacts })
    }
}

impl CommonProofBoundOpeningProvider for CommittedMaterialBoundOpeningProvider<'_> {
    type Error = CommittedMaterialError;

    fn opening_geometry(
        &self,
        catalog_entry: &ProofTreeCatalogEntry,
    ) -> Result<CommonProofOpeningGeometry, Self::Error> {
        if catalog_entry.source() != ProofTreeCatalogSource::RelationBoundPublic {
            return Err(CommittedMaterialError::InvalidInput);
        }
        let artifact = self
            .artifacts
            .get(&catalog_entry.tree_catalog_index())
            .ok_or(CommittedMaterialError::InvalidInput)?;
        Ok(CommonProofOpeningGeometry {
            tree_catalog_index: artifact.tree_catalog_index(),
            leaf_count: artifact.leaf_count(),
            canonical_leaf_byte_length: artifact.canonical_leaf_byte_length(),
        })
    }

    fn encode_bound_opening_fragment(
        &mut self,
        catalog: &CompleteProofTreeCatalog,
        catalog_index: usize,
        geometry: CommonProofOpeningGeometry,
        sorted_query_representatives: &[u64],
        maximum_fragment_byte_length: usize,
    ) -> Result<Vec<u8>, CommonProofEncodingError<BoundedCommonProofByteSinkError, Self::Error>>
    {
        let entry =
            catalog
                .entries()
                .get(catalog_index)
                .ok_or(CommonProofEncodingError::Artifact(
                    CommittedMaterialError::InvalidInput,
                ))?;
        let artifact = self.artifacts.get_mut(&entry.tree_catalog_index()).ok_or(
            CommonProofEncodingError::Artifact(CommittedMaterialError::InvalidInput),
        )?;
        encode_common_proof_query_tree_fragment(
            catalog,
            catalog_index,
            geometry,
            sorted_query_representatives,
            artifact,
            maximum_fragment_byte_length,
        )
    }
}

struct MaterialPrivateDerivation<'seed> {
    material_seed: &'seed [u8; 64],
    material_context_hash: [u8; 64],
    purpose: &'static str,
    physical_index: u64,
    next_counter: u64,
}

impl<'seed> MaterialPrivateDerivation<'seed> {
    fn new(
        material_seed: &'seed [u8; 64],
        material_context_hash: [u8; 64],
        purpose: &'static str,
        physical_index: u64,
    ) -> Self {
        Self {
            material_seed,
            material_context_hash,
            purpose,
            physical_index,
            next_counter: 0,
        }
    }

    fn next_block(
        &mut self,
    ) -> Result<Zeroizing<[u8; DERIVED_BLOCK_BYTE_LENGTH]>, CommittedMaterialError> {
        let counter = self.next_counter;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(CommittedMaterialError::CountOverflow)?;
        let input = CanonicalTuple::new(
            MATERIAL_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.material_context_hash),
                CanonicalItem::ascii(self.purpose).map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned64(self.physical_index),
                CanonicalItem::unsigned64(counter),
            ],
        )
        .encode()
        .map_err(canonical_encoding_error)?;
        let mut output = Zeroizing::new([0_u8; DERIVED_BLOCK_BYTE_LENGTH]);
        let mut kmac = Kmac::v256(self.material_seed, PRIVATE_DERIVATION_CUSTOMIZATION);
        kmac.update(&input);
        kmac.finalize(output.as_mut());
        Ok(output)
    }

    fn sample_uniform_base_field(&mut self) -> Result<u64, CommittedMaterialError> {
        let significant_bit_length = u64::BITS - PROOF_BASE_FIELD_MODULUS.leading_zeros();
        let sample_byte_length = usize::try_from(significant_bit_length.div_ceil(8))
            .map_err(|_| CommittedMaterialError::CountOverflow)?;
        let sample_space = 1_u128 << (sample_byte_length * 8);
        let modulus = u128::from(PROOF_BASE_FIELD_MODULUS);
        let acceptance_limit = sample_space - sample_space % modulus;
        for _ in 0..PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT {
            let block = self.next_block()?;
            let mut candidate_bytes = [0_u8; size_of::<u64>()];
            candidate_bytes[..sample_byte_length].copy_from_slice(&block[..sample_byte_length]);
            let candidate = u64::from_le_bytes(candidate_bytes);
            if u128::from(candidate) < acceptance_limit {
                return Ok(candidate % PROOF_BASE_FIELD_MODULUS);
            }
        }
        Err(CommittedMaterialError::CandidateDrawCeilingExceeded)
    }
}

fn canonical_phase_pair_leaf_bytes(
    material_context_hash: [u8; 64],
    material_seed: &[u8; 64],
    extension_columns: &[Vec<ProofBaseFieldElement>],
    leaf_index: usize,
) -> Result<Vec<u8>, CommittedMaterialError> {
    if extension_columns.len() != MATERIAL_COLUMN_COUNT
        || extension_columns.iter().any(|column| {
            column.len() != extension_columns[0].len() || !column.len().is_power_of_two()
        })
        || extension_columns[0].len() < 2
        || leaf_index >= extension_columns[0].len() / 2
    {
        return Err(CommittedMaterialError::InvalidInput);
    }
    let opposite_index = leaf_index
        .checked_add(extension_columns[0].len() / 2)
        .ok_or(CommittedMaterialError::CountOverflow)?;
    let first_values = extension_columns
        .iter()
        .map(|column| canonical_field_item(column[leaf_index]))
        .collect::<Result<Vec<_>, _>>()?;
    let opposite_values = extension_columns
        .iter()
        .map(|column| canonical_field_item(column[opposite_index]))
        .collect::<Result<Vec<_>, _>>()?;
    let mut salt_derivation = MaterialPrivateDerivation::new(
        material_seed,
        material_context_hash,
        LEAF_SALT_PURPOSE,
        u64::try_from(leaf_index).map_err(|_| CommittedMaterialError::CountOverflow)?,
    );
    let salt_block = salt_derivation.next_block()?;
    CanonicalTuple::new(
        COMMITTED_MATERIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(material_context_hash),
            CanonicalItem::unsigned64(
                u64::try_from(leaf_index).map_err(|_| CommittedMaterialError::CountOverflow)?,
            ),
            CanonicalItem::fixed_bytes(&salt_block[..SECRET_LEAF_SALT_BYTE_LENGTH])
                .map_err(canonical_encoding_error)?,
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
) -> Result<CanonicalItem, CommittedMaterialError> {
    CanonicalItem::from_canonical_bytes(
        CanonicalItemType::FieldElement,
        value.canonical().to_le_bytes().to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .map_err(canonical_encoding_error)
}

fn build_merkle_levels(
    leaf_digests: Vec<[u8; 64]>,
) -> Result<Vec<Vec<[u8; 64]>>, CommittedMaterialError> {
    if leaf_digests.is_empty() || !leaf_digests.len().is_power_of_two() {
        return Err(CommittedMaterialError::InvalidInput);
    }
    let mut levels = vec![leaf_digests];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let child_level = levels.last().ok_or(CommittedMaterialError::InvalidInput)?;
        let level =
            u32::try_from(levels.len()).map_err(|_| CommittedMaterialError::CountOverflow)?;
        let mut parents = Vec::with_capacity(child_level.len() / 2);
        for (parent_index, children) in child_level.chunks_exact(2).enumerate() {
            let left_child_index = parent_index
                .checked_mul(2)
                .ok_or(CommittedMaterialError::CountOverflow)?;
            parents.push(
                hash_foundation_tuple_512(
                    MERKLE_NODE_HASH_DOMAIN,
                    &[
                        CanonicalItem::unsigned32(level),
                        CanonicalItem::unsigned64(
                            u64::try_from(left_child_index)
                                .map_err(|_| CommittedMaterialError::CountOverflow)?,
                        ),
                        CanonicalItem::hash512(children[0]),
                        CanonicalItem::hash512(children[1]),
                    ],
                )
                .map_err(canonical_encoding_error)?
                .into_bytes(),
            );
        }
        levels.push(parents);
    }
    Ok(levels)
}
