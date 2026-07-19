//! Persistent committed-material trees over the common proof field.
//!
//! A logical lattice message has one reusable root. Its two canonical
//! radix-three digit columns are split into two coefficient halves, masked as
//! polynomials over the trace subgroup, and committed in the fixed physical
//! order `[low half 0, low half 1, high half 0, high half 1]`.

use std::{fmt, mem::size_of, sync::Arc};

use tiny_keccak::{Hasher, Kmac};
use zeroize::Zeroizing;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    PrivateRandomnessKmacInputClassAccounting, hash_foundation_tuple_512,
};

use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, CommonProofProverError, CommonProofSourcePolynomial,
    PROOF_BASE_FIELD_MODULUS, PROOF_EVALUATION_BLOWUP_FACTOR, PROOF_EVALUATION_COSET_OFFSET,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, ProofBaseFieldElement,
    ProofEvaluationDomain, ProofFieldError, ProofPolynomialError, apply_trace_mask,
};

const MATERIAL_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x2101;
const MATERIAL_DERIVATION_INPUT_SCHEMA_IDENTIFIER: u16 = 0x2105;
pub(super) const COMMITTED_MATERIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER: u16 = 0x2102;
const SCHEMA_VERSION: u16 = 1;
const MATERIAL_COLUMN_COUNT: usize = 4;
const MATERIAL_DIGIT_COLUMN_COUNT: usize = 2;
const MATERIAL_DIGIT_RADIX: u64 = 129_140_163;
const DERIVED_BLOCK_BYTE_LENGTH: usize = 64;
const MAXIMUM_MASKING_POLYNOMIAL_DEGREE: usize = 2_047;

const PRIVATE_DERIVATION_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/setup/vss-committed-material/private-derivation/v1";
const MATERIAL_CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/setup/vss-committed-material/context/v1";
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
#[repr(u16)]
pub(crate) enum CommittedMaterialRole {
    Coefficient = 1,
    RecipientShare = 2,
    AggregateThresholdShare = 3,
}

/// Canonical owner and index coordinates for one persistent material tree.
/// The suite fixes every omitted field and tree dimension, so a caller cannot
/// supply proof geometry through this context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommittedMaterialContext {
    suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    owner_participant_identity: [u8; 64],
    material_role: CommittedMaterialRole,
    sharing_limb_index: u16,
    object_index: u16,
}

impl CommittedMaterialContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        suite_identifier: [u8; 64],
        ceremony_context_hash: [u8; 64],
        action_context_hash: [u8; 64],
        owner_participant_identity: [u8; 64],
        material_role: CommittedMaterialRole,
        sharing_limb_index: u16,
        object_index: u16,
    ) -> Self {
        Self {
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            owner_participant_identity,
            material_role,
            sharing_limb_index,
            object_index,
        }
    }

    pub(crate) fn canonical_bytes(self) -> Result<Vec<u8>, CommittedMaterialError> {
        CanonicalTuple::new(
            MATERIAL_CONTEXT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.suite_identifier),
                CanonicalItem::hash512(self.ceremony_context_hash),
                CanonicalItem::hash512(self.action_context_hash),
                CanonicalItem::participant_identity(self.owner_participant_identity),
                CanonicalItem::unsigned16(self.material_role as u16),
                CanonicalItem::unsigned16(self.sharing_limb_index),
                CanonicalItem::unsigned16(self.object_index),
            ],
        )
        .encode()
        .map_err(canonical_encoding_error)
    }

    pub(crate) fn context_hash(self) -> Result<[u8; 64], CommittedMaterialError> {
        let canonical_bytes = self.canonical_bytes()?;
        hash_foundation_tuple_512(
            MATERIAL_CONTEXT_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(canonical_bytes).map_err(canonical_encoding_error)?],
        )
        .map(|hash| hash.into_bytes())
        .map_err(canonical_encoding_error)
    }
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

/// Maximum number of distinct canonical inner-derivation KMAC inputs needed
/// to construct the supplied action-level population of persistent material
/// roots. Every mask candidate advances its physical-column counter, while
/// every leaf salt consumes consecutive 64-byte counter blocks.
pub(crate) fn maximum_committed_material_inner_derivation_count(
    profile: CommittedMaterialProfile,
    physical_root_count: u64,
    full_salted_leaf_count: u64,
) -> Result<u64, CommittedMaterialError> {
    profile.validate()?;
    let mask_coefficient_count = u64::try_from(
        profile
            .masking_polynomial_maximum_degree()
            .checked_add(1)
            .ok_or(CommittedMaterialError::CountOverflow)?,
    )
    .map_err(|_| CommittedMaterialError::CountOverflow)?;
    let maximum_mask_candidate_count = physical_root_count
        .checked_mul(
            u64::try_from(MATERIAL_COLUMN_COUNT)
                .map_err(|_| CommittedMaterialError::CountOverflow)?,
        )
        .and_then(|count| count.checked_mul(mask_coefficient_count))
        .and_then(|count| {
            count.checked_mul(u64::from(
                PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            ))
        })
        .ok_or(CommittedMaterialError::CountOverflow)?;
    let leaf_salt_block_count = u64::try_from(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)
        .map_err(|_| CommittedMaterialError::CountOverflow)?
        .div_ceil(
            u64::try_from(DERIVED_BLOCK_BYTE_LENGTH)
                .map_err(|_| CommittedMaterialError::CountOverflow)?,
        );
    maximum_mask_candidate_count
        .checked_add(
            full_salted_leaf_count
                .checked_mul(leaf_salt_block_count)
                .ok_or(CommittedMaterialError::CountOverflow)?,
        )
        .ok_or(CommittedMaterialError::CountOverflow)
}

/// Source-owned private-randomness accounting for a persistent committed
/// material population. Every physical root has one 64-byte material-seed
/// stream block, while mask candidates and full-leaf salts use the inner
/// derivation keyed by that seed.
pub(crate) fn maximum_committed_material_kmac_input_accounting(
    profile: CommittedMaterialProfile,
    physical_root_count: u64,
    full_salted_leaf_count: u64,
) -> Result<PrivateRandomnessKmacInputClassAccounting, CommittedMaterialError> {
    let inner_derivation_count = maximum_committed_material_inner_derivation_count(
        profile,
        physical_root_count,
        full_salted_leaf_count,
    )?;
    PrivateRandomnessKmacInputClassAccounting::checked_new(
        0,
        0,
        physical_root_count,
        inner_derivation_count,
    )
    .ok_or(CommittedMaterialError::CountOverflow)
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
    masked_coefficients_by_physical_column: Vec<Zeroizing<Vec<ProofBaseFieldElement>>>,
    extension_columns: Vec<Vec<ProofBaseFieldElement>>,
    merkle_levels: Vec<Vec<[u8; 64]>>,
}

/// Compact regeneration authority retained after a committed-material root is
/// constructed. The evaluation columns and Merkle layers are deliberately
/// absent: together with an authenticated canonical message, the common prover
/// rebuilds one source polynomial at a time from its recipe-derived trace row
/// and obtains only the leaf salt it is currently materializing. The seed never
/// crosses the Rust/Wasm boundary.
pub(crate) struct CompactCommittedMaterialSource {
    profile: CommittedMaterialProfile,
    material_context_hash: [u8; 64],
    material_seed: Zeroizing<[u8; 64]>,
    root: [u8; 64],
}

/// One process-local Arc allocation retained by an authenticated committed
/// source. The identifier is used only to de-duplicate live process memory;
/// it is never serialized, hashed, or admitted into a proof binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommittedMaterialSharedAllocationMemoryAccounting {
    owner_identifier: usize,
    retained_byte_length: u64,
}

impl CommittedMaterialSharedAllocationMemoryAccounting {
    pub(crate) const fn new(owner_identifier: usize, retained_byte_length: u64) -> Self {
        Self {
            owner_identifier,
            retained_byte_length,
        }
    }

    pub(crate) const fn owner_identifier(self) -> usize {
        self.owner_identifier
    }

    pub(crate) const fn retained_byte_length(self) -> u64 {
        self.retained_byte_length
    }
}

/// Allocation-complete memory facts for the two Arc owners carried by one
/// authenticated compact source. Wrapper references live in their enclosing
/// catalogs and are deliberately not counted here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedCommittedMaterialSharedMemoryAccounting {
    compact_source: CommittedMaterialSharedAllocationMemoryAccounting,
    canonical_message: CommittedMaterialSharedAllocationMemoryAccounting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedCommittedMaterialSharedAllocationByteLengths {
    compact_source: u64,
    canonical_message: u64,
}

impl AuthenticatedCommittedMaterialSharedAllocationByteLengths {
    pub(crate) const fn compact_source(self) -> u64 {
        self.compact_source
    }

    pub(crate) const fn canonical_message(self) -> u64 {
        self.canonical_message
    }

    pub(crate) fn total(self) -> Result<u64, CommittedMaterialError> {
        self.compact_source
            .checked_add(self.canonical_message)
            .ok_or(CommittedMaterialError::CountOverflow)
    }
}

pub(crate) fn authenticated_committed_material_shared_allocation_byte_lengths(
    canonical_coefficient_count: usize,
) -> Result<AuthenticatedCommittedMaterialSharedAllocationByteLengths, CommittedMaterialError> {
    let arc_header_byte_length = size_of::<usize>()
        .checked_mul(2)
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(CommittedMaterialError::CountOverflow)?;
    let compact_source = u64::try_from(size_of::<CompactCommittedMaterialSource>())
        .ok()
        .and_then(|length| length.checked_add(arc_header_byte_length))
        .ok_or(CommittedMaterialError::CountOverflow)?;
    let canonical_message = u64::try_from(canonical_coefficient_count)
        .ok()
        .and_then(|count| count.checked_mul(size_of::<u64>() as u64))
        .and_then(|length| {
            length.checked_add(u64::try_from(size_of::<Zeroizing<Box<[u64]>>>()).ok()?)
        })
        .and_then(|length| length.checked_add(arc_header_byte_length))
        .ok_or(CommittedMaterialError::CountOverflow)?;
    Ok(AuthenticatedCommittedMaterialSharedAllocationByteLengths {
        compact_source,
        canonical_message,
    })
}

impl AuthenticatedCommittedMaterialSharedMemoryAccounting {
    pub(crate) const fn compact_source(self) -> CommittedMaterialSharedAllocationMemoryAccounting {
        self.compact_source
    }

    pub(crate) const fn canonical_message(
        self,
    ) -> CommittedMaterialSharedAllocationMemoryAccounting {
        self.canonical_message
    }
}

/// One positively authenticated committed-material root and its compact
/// canonical lattice coefficients. The expensive evaluation columns, Merkle
/// layers, and digit trace rows are absent. A proof source derives only the
/// requested physical column from these coefficients and drops that working
/// set before advancing.
#[derive(Clone)]
pub(crate) struct AuthenticatedCompactCommittedMaterialSource {
    compact_source: Arc<CompactCommittedMaterialSource>,
    canonical_message: Arc<Zeroizing<Box<[u64]>>>,
    canonical_modulus: u64,
}

impl AuthenticatedCompactCommittedMaterialSource {
    /// Consumes a tree that was recomputed from these exact coefficients. The
    /// positive opening check keeps the compact source, root, and canonical
    /// coefficients inseparable after the full tree is released.
    pub(crate) fn from_recomputed_tree_and_canonical_message(
        tree: CommittedMaterialTree,
        canonical_message: Zeroizing<Box<[u64]>>,
        canonical_modulus: u64,
    ) -> Result<Self, CommittedMaterialError> {
        if !tree.authenticates_canonical_message(&canonical_message, canonical_modulus)? {
            return Err(CommittedMaterialError::InvalidInput);
        }
        Ok(Self {
            compact_source: Arc::new(tree.into_compact_source()),
            canonical_message: Arc::new(canonical_message),
            canonical_modulus,
        })
    }

    pub(crate) fn compact_source(&self) -> &CompactCommittedMaterialSource {
        &self.compact_source
    }

    pub(crate) fn canonical_message(&self) -> &[u64] {
        &self.canonical_message
    }

    pub(crate) const fn canonical_modulus(&self) -> u64 {
        self.canonical_modulus
    }

    pub(crate) fn authenticates_canonical_message(
        &self,
        canonical_message: &[u64],
        canonical_modulus: u64,
    ) -> bool {
        canonical_modulus == self.canonical_modulus && canonical_message == self.canonical_message()
    }

    pub(crate) fn material_digit(
        &self,
        physical_half_ordinal: usize,
        material_digit_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<u64, CommittedMaterialError> {
        if physical_half_ordinal >= 2 || material_digit_ordinal >= 2 {
            return Err(CommittedMaterialError::InvalidInput);
        }
        let trace_domain_size = self.compact_source.profile.trace_domain_size;
        let coefficient_ordinal = physical_half_ordinal
            .checked_mul(trace_domain_size)
            .and_then(|offset| offset.checked_add(row_ordinal))
            .ok_or(CommittedMaterialError::CountOverflow)?;
        let coefficient = *self
            .canonical_message
            .get(coefficient_ordinal)
            .ok_or(CommittedMaterialError::InvalidInput)?;
        Ok(if material_digit_ordinal == 0 {
            coefficient % MATERIAL_DIGIT_RADIX
        } else {
            coefficient / MATERIAL_DIGIT_RADIX
        })
    }

    pub(crate) fn regenerate_masked_coefficients(
        &self,
        physical_column_ordinal: usize,
    ) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommittedMaterialError> {
        self.compact_source
            .regenerate_masked_coefficients_from_canonical_message(
                physical_column_ordinal,
                self.canonical_message(),
                self.canonical_modulus,
            )
    }

    pub(crate) fn retained_canonical_coefficient_byte_length(&self) -> usize {
        self.canonical_message
            .len()
            .saturating_mul(size_of::<u64>())
    }

    /// Process-local identities for the two Arc-backed allocations shared by
    /// generation custody and a prepared committed-material proof provider.
    /// They are never serialized or bound into a transcript; memory
    /// accounting uses them only to count each live allocation once.
    pub(crate) fn shared_allocation_owner_identifiers(&self) -> (usize, usize) {
        (
            Arc::as_ptr(&self.compact_source) as usize,
            Arc::as_ptr(&self.canonical_message) as usize,
        )
    }

    pub(crate) fn shared_memory_accounting(
        &self,
    ) -> Result<AuthenticatedCommittedMaterialSharedMemoryAccounting, CommittedMaterialError> {
        let (compact_source_owner_identifier, canonical_message_owner_identifier) =
            self.shared_allocation_owner_identifiers();
        let byte_lengths = authenticated_committed_material_shared_allocation_byte_lengths(
            self.canonical_message.len(),
        )?;
        Ok(AuthenticatedCommittedMaterialSharedMemoryAccounting {
            compact_source: CommittedMaterialSharedAllocationMemoryAccounting {
                owner_identifier: compact_source_owner_identifier,
                retained_byte_length: byte_lengths.compact_source(),
            },
            canonical_message: CommittedMaterialSharedAllocationMemoryAccounting {
                owner_identifier: canonical_message_owner_identifier,
                retained_byte_length: byte_lengths.canonical_message(),
            },
        })
    }

    pub(crate) fn maximum_regeneration_trace_byte_length(&self) -> usize {
        self.compact_source
            .profile
            .trace_domain_size
            .saturating_mul(size_of::<ProofBaseFieldElement>())
    }
}

impl fmt::Debug for AuthenticatedCompactCommittedMaterialSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedCompactCommittedMaterialSource")
            .field("compact_source", &self.compact_source)
            .field("canonical_message", &"[REDACTED]")
            .field("canonical_modulus", &self.canonical_modulus)
            .finish()
    }
}

impl CompactCommittedMaterialSource {
    pub(crate) const fn profile(&self) -> CommittedMaterialProfile {
        self.profile
    }

    pub(crate) const fn material_context_hash(&self) -> [u8; 64] {
        self.material_context_hash
    }

    pub(crate) const fn root(&self) -> [u8; 64] {
        self.root
    }

    /// Rebuilds exactly one masked physical column from one caller-supplied
    /// unmasked trace row. The authenticated wrapper derives that row from its
    /// canonical message. This is the only large scratch allocation retained by
    /// the caller for source-polynomial delivery.
    pub(crate) fn regenerate_masked_coefficients(
        &self,
        physical_column_ordinal: usize,
        trace_values: &[u64],
    ) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommittedMaterialError> {
        if physical_column_ordinal >= MATERIAL_COLUMN_COUNT
            || trace_values.len() != self.profile.trace_domain_size
            || trace_values
                .iter()
                .any(|value| *value >= PROOF_BASE_FIELD_MODULUS)
        {
            return Err(CommittedMaterialError::InvalidInput);
        }
        let trace_domain = ProofEvaluationDomain::new_subgroup(self.profile.trace_domain_size)?;
        let mut canonical_trace_values = trace_values
            .iter()
            .copied()
            .map(ProofBaseFieldElement::from_canonical)
            .collect::<Result<Vec<_>, _>>()?;
        trace_domain.interpolate_base_polynomial_in_place(&mut canonical_trace_values)?;
        self.apply_mask_to_witness_coefficients(physical_column_ordinal, canonical_trace_values)
    }

    pub(crate) fn regenerate_masked_coefficients_from_canonical_message(
        &self,
        physical_column_ordinal: usize,
        canonical_message: &[u64],
        canonical_modulus: u64,
    ) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommittedMaterialError> {
        let trace_domain_size = self.profile.trace_domain_size;
        if physical_column_ordinal >= MATERIAL_COLUMN_COUNT
            || canonical_modulus <= 1
            || canonical_message.len() != trace_domain_size.checked_mul(2).unwrap_or(0)
            || canonical_message
                .iter()
                .any(|coefficient| *coefficient >= canonical_modulus)
            || u128::from(canonical_modulus - 1)
                >= u128::from(MATERIAL_DIGIT_RADIX) * u128::from(MATERIAL_DIGIT_RADIX)
        {
            return Err(CommittedMaterialError::InvalidInput);
        }
        let material_digit_ordinal = physical_column_ordinal / 2;
        let physical_half_ordinal = physical_column_ordinal % 2;
        let coefficient_start = physical_half_ordinal
            .checked_mul(trace_domain_size)
            .ok_or(CommittedMaterialError::CountOverflow)?;
        let coefficient_end = coefficient_start
            .checked_add(trace_domain_size)
            .ok_or(CommittedMaterialError::CountOverflow)?;
        let mut witness_coefficients = canonical_message[coefficient_start..coefficient_end]
            .iter()
            .copied()
            .map(|coefficient| {
                let digit = if material_digit_ordinal == 0 {
                    coefficient % MATERIAL_DIGIT_RADIX
                } else {
                    coefficient / MATERIAL_DIGIT_RADIX
                };
                ProofBaseFieldElement::from_canonical(digit)
            })
            .collect::<Result<Vec<_>, _>>()?;
        ProofEvaluationDomain::new_subgroup(trace_domain_size)?
            .interpolate_base_polynomial_in_place(&mut witness_coefficients)?;
        self.apply_mask_to_witness_coefficients(physical_column_ordinal, witness_coefficients)
    }

    fn apply_mask_to_witness_coefficients(
        &self,
        physical_column_ordinal: usize,
        witness_coefficients: Vec<ProofBaseFieldElement>,
    ) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommittedMaterialError> {
        let mask_coefficient_count = self
            .profile
            .masking_polynomial_maximum_degree
            .checked_add(1)
            .ok_or(CommittedMaterialError::CountOverflow)?;
        let mut derivation = MaterialPrivateDerivation::new(
            &self.material_seed,
            self.material_context_hash,
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
            CommonProofSourcePolynomial::from_base_coefficients(witness_coefficients),
            u64::try_from(self.profile.trace_domain_size)
                .map_err(|_| CommittedMaterialError::CountOverflow)?,
            CommonProofSourcePolynomial::from_base_coefficients(mask_coefficients),
        )? {
            CommonProofSourcePolynomial::Base(coefficients) => coefficients,
            CommonProofSourcePolynomial::Extension(_) => {
                return Err(CommittedMaterialError::InvalidInput);
            }
        };
        if masked_coefficients.len() > self.profile.material_column_degree_bound_exclusive {
            return Err(CommittedMaterialError::InvalidProfile);
        }
        Ok(masked_coefficients)
    }

    pub(crate) fn persistent_leaf_salt(
        &self,
        leaf_index: usize,
    ) -> Result<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH], CommittedMaterialError> {
        if leaf_index >= self.profile.evaluation_domain_size / 2 {
            return Err(CommittedMaterialError::InvalidInput);
        }
        derive_material_leaf_salt(self.material_context_hash, &self.material_seed, leaf_index)
    }

    pub(crate) const fn retained_byte_length(&self) -> usize {
        size_of::<Self>()
    }

    pub(crate) fn maximum_regenerated_column_byte_length(&self) -> usize {
        self.profile
            .material_column_degree_bound_exclusive
            .saturating_mul(size_of::<ProofBaseFieldElement>())
    }
}

impl fmt::Debug for CompactCommittedMaterialSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactCommittedMaterialSource")
            .field("profile", &self.profile)
            .field("material_context_hash", &self.material_context_hash)
            .field("material_seed", &"[REDACTED]")
            .field("root", &self.root)
            .finish()
    }
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
    /// Constructs the persistent tree from one canonical lattice message.
    /// Digit decomposition and physical-column ordering remain inside Rust so
    /// a caller cannot detach rows from the message whose root is retained.
    pub(crate) fn from_canonical_message(
        profile: CommittedMaterialProfile,
        material_context_hash: [u8; 64],
        material_seed: [u8; 64],
        canonical_message: &[u64],
        canonical_modulus: u64,
    ) -> Result<Self, CommittedMaterialError> {
        let expected_message_length = profile
            .trace_domain_size
            .checked_mul(2)
            .ok_or(CommittedMaterialError::CountOverflow)?;
        if canonical_modulus <= 1
            || canonical_message.len() != expected_message_length
            || canonical_message
                .iter()
                .any(|coefficient| *coefficient >= canonical_modulus)
            || u128::from(canonical_modulus - 1)
                >= u128::from(MATERIAL_DIGIT_RADIX) * u128::from(MATERIAL_DIGIT_RADIX)
        {
            return Err(CommittedMaterialError::InvalidInput);
        }

        let message_digit_columns = vec![
            canonical_message
                .iter()
                .map(|coefficient| coefficient % MATERIAL_DIGIT_RADIX)
                .collect::<Vec<_>>(),
            canonical_message
                .iter()
                .map(|coefficient| coefficient / MATERIAL_DIGIT_RADIX)
                .collect::<Vec<_>>(),
        ];
        let tree = Self::construct(CommittedMaterialTreeInput {
            profile,
            material_context_hash,
            material_seed,
            message_digit_columns: &message_digit_columns,
        })?;

        if !tree.authenticates_canonical_message(canonical_message, canonical_modulus)? {
            return Err(CommittedMaterialError::InvalidInput);
        }
        Ok(tree)
    }

    pub(crate) fn construct(
        input: CommittedMaterialTreeInput<'_>,
    ) -> Result<Self, CommittedMaterialError> {
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
                    CommonProofSourcePolynomial::from_base_coefficients(witness_coefficients),
                    u64::try_from(input.profile.trace_domain_size)
                        .map_err(|_| CommittedMaterialError::CountOverflow)?,
                    CommonProofSourcePolynomial::from_base_coefficients(mask_coefficients),
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

    pub(crate) fn masked_coefficients_by_physical_column(
        &self,
    ) -> &[Zeroizing<Vec<ProofBaseFieldElement>>] {
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

    /// Releases the full evaluation and Merkle representation after its root
    /// has been fixed, retaining only the private data required to regenerate
    /// source columns and persistent leaf salts exactly.
    pub(crate) fn into_compact_source(self) -> CompactCommittedMaterialSource {
        let root = self.root();
        CompactCommittedMaterialSource {
            profile: self.profile,
            material_context_hash: self.material_context_hash,
            material_seed: self.material_seed,
            root,
        }
    }

    /// Positively checks that this exact masked tree opens to the supplied
    /// canonical lattice message on the committed trace subgroup. This is used
    /// when a browser-owned private share is joined to a separately verified
    /// public root; a detached share or a tree for another message cannot pass.
    pub(crate) fn authenticates_canonical_message(
        &self,
        canonical_message: &[u64],
        canonical_modulus: u64,
    ) -> Result<bool, CommittedMaterialError> {
        let trace_domain_size = self.profile.trace_domain_size();
        if canonical_modulus <= 1
            || canonical_message.len() != trace_domain_size.checked_mul(2).unwrap_or(0)
            || canonical_message
                .iter()
                .any(|coefficient| *coefficient >= canonical_modulus)
            || self.masked_coefficients_by_physical_column.len() != MATERIAL_COLUMN_COUNT
            || u128::from(canonical_modulus - 1)
                >= u128::from(MATERIAL_DIGIT_RADIX) * u128::from(MATERIAL_DIGIT_RADIX)
        {
            return Ok(false);
        }
        let trace_domain = ProofEvaluationDomain::new_subgroup(trace_domain_size)?;
        for (physical_column_ordinal, masked_coefficients) in self
            .masked_coefficients_by_physical_column
            .iter()
            .enumerate()
        {
            let digit_ordinal = physical_column_ordinal / 2;
            let half_ordinal = physical_column_ordinal % 2;
            let start = half_ordinal * trace_domain_size;
            let mut trace_restriction_coefficients =
                Zeroizing::new(vec![ProofBaseFieldElement::ZERO; trace_domain_size]);
            for (coefficient_ordinal, coefficient) in
                masked_coefficients.iter().copied().enumerate()
            {
                let trace_coefficient_ordinal = coefficient_ordinal % trace_domain_size;
                trace_restriction_coefficients[trace_coefficient_ordinal] =
                    trace_restriction_coefficients[trace_coefficient_ordinal].add(coefficient);
            }
            let trace_values =
                trace_domain.evaluate_base_polynomial(&trace_restriction_coefficients)?;
            if trace_values
                .iter()
                .zip(&canonical_message[start..start + trace_domain_size])
                .any(|(actual, message_coefficient)| {
                    let expected = if digit_ordinal == 0 {
                        *message_coefficient % MATERIAL_DIGIT_RADIX
                    } else {
                        *message_coefficient / MATERIAL_DIGIT_RADIX
                    };
                    actual.canonical() != expected
                })
            {
                return Ok(false);
            }
        }
        Ok(true)
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
    let leaf_salt = derive_material_leaf_salt(material_context_hash, material_seed, leaf_index)?;
    CanonicalTuple::new(
        COMMITTED_MATERIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(material_context_hash),
            CanonicalItem::unsigned64(
                u64::try_from(leaf_index).map_err(|_| CommittedMaterialError::CountOverflow)?,
            ),
            CanonicalItem::fixed_bytes(leaf_salt).map_err(canonical_encoding_error)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::FieldElement, &first_values)
                .map_err(canonical_encoding_error)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::FieldElement, &opposite_values)
                .map_err(canonical_encoding_error)?,
        ],
    )
    .encode()
    .map_err(canonical_encoding_error)
}

fn derive_material_leaf_salt(
    material_context_hash: [u8; 64],
    material_seed: &[u8; 64],
    leaf_index: usize,
) -> Result<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH], CommittedMaterialError> {
    let mut salt_derivation = MaterialPrivateDerivation::new(
        material_seed,
        material_context_hash,
        LEAF_SALT_PURPOSE,
        u64::try_from(leaf_index).map_err(|_| CommittedMaterialError::CountOverflow)?,
    );
    let mut leaf_salt = [0_u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH];
    for salt_chunk in leaf_salt.chunks_mut(DERIVED_BLOCK_BYTE_LENGTH) {
        let salt_block = salt_derivation.next_block()?;
        salt_chunk.copy_from_slice(&salt_block[..salt_chunk.len()]);
    }
    Ok(leaf_salt)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn committed_message_fixture() -> (CommittedMaterialTree, Vec<u64>, u64) {
        let canonical_modulus = 1_000_000_007_u64;
        let canonical_message = vec![
            0,
            1,
            MATERIAL_DIGIT_RADIX - 1,
            MATERIAL_DIGIT_RADIX,
            MATERIAL_DIGIT_RADIX + 19,
            canonical_modulus - 2,
            77_777_777,
            canonical_modulus - 1,
        ];
        let profile = CommittedMaterialProfile::selected(canonical_message.len())
            .expect("small committed-material profile");
        let tree = CommittedMaterialTree::from_canonical_message(
            profile,
            [0x31; 64],
            [0x52; 64],
            &canonical_message,
            canonical_modulus,
        )
        .expect("committed material tree");
        (tree, canonical_message, canonical_modulus)
    }

    #[test]
    fn canonical_message_constructor_derives_the_exact_physical_trace_order() {
        let canonical_modulus = 1_000_000_007_u64;
        let canonical_message = [
            0,
            MATERIAL_DIGIT_RADIX,
            MATERIAL_DIGIT_RADIX + 7,
            canonical_modulus - 1,
            19,
            MATERIAL_DIGIT_RADIX * 2 + 23,
            41,
            canonical_modulus - 2,
        ];
        let profile = CommittedMaterialProfile::selected(canonical_message.len())
            .expect("small committed-material profile");
        let tree = CommittedMaterialTree::from_canonical_message(
            profile,
            [0x17; 64],
            [0x81; 64],
            &canonical_message,
            canonical_modulus,
        )
        .expect("canonical message constructs");
        let source = AuthenticatedCompactCommittedMaterialSource::
            from_recomputed_tree_and_canonical_message(
                tree,
                Zeroizing::new(canonical_message.to_vec().into_boxed_slice()),
                canonical_modulus,
            )
            .expect("canonical message authenticates");
        let trace_size = profile.trace_domain_size();
        let material_digits = |physical_half_ordinal, material_digit_ordinal| {
            (0..trace_size)
                .map(|row_ordinal| {
                    source
                        .material_digit(physical_half_ordinal, material_digit_ordinal, row_ordinal)
                        .expect("authenticated material digit derives")
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            material_digits(0, 0),
            canonical_message[..trace_size]
                .iter()
                .map(|coefficient| coefficient % MATERIAL_DIGIT_RADIX)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            material_digits(1, 0),
            canonical_message[trace_size..]
                .iter()
                .map(|coefficient| coefficient % MATERIAL_DIGIT_RADIX)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            material_digits(0, 1),
            canonical_message[..trace_size]
                .iter()
                .map(|coefficient| coefficient / MATERIAL_DIGIT_RADIX)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            material_digits(1, 1),
            canonical_message[trace_size..]
                .iter()
                .map(|coefficient| coefficient / MATERIAL_DIGIT_RADIX)
                .collect::<Vec<_>>()
        );
        assert!(source.authenticates_canonical_message(&canonical_message, canonical_modulus));
    }

    #[test]
    fn canonical_message_constructor_rejects_detached_shapes_and_values() {
        let profile = CommittedMaterialProfile::selected(8).expect("small material profile");
        let construct = |message: &[u64], modulus: u64| {
            CommittedMaterialTree::from_canonical_message(
                profile, [0x21; 64], [0x43; 64], message, modulus,
            )
        };
        assert!(construct(&[0; 7], 257).is_err());
        assert!(construct(&[0, 1, 2, 3, 4, 5, 6, 257], 257).is_err());
        assert!(construct(&[0; 8], 1).is_err());
        assert!(construct(&[0; 8], MATERIAL_DIGIT_RADIX * MATERIAL_DIGIT_RADIX + 1,).is_err());
    }

    #[test]
    fn committed_tree_positively_authenticates_the_exact_canonical_message() {
        let (tree, canonical_message, canonical_modulus) = committed_message_fixture();
        assert!(
            tree.authenticates_canonical_message(&canonical_message, canonical_modulus)
                .expect("exact opening check")
        );

        let mut changed_low_digit = canonical_message.clone();
        changed_low_digit[1] += 1;
        assert!(
            !tree
                .authenticates_canonical_message(&changed_low_digit, canonical_modulus)
                .expect("changed low digit check")
        );

        let mut changed_high_digit = canonical_message.clone();
        changed_high_digit[4] += MATERIAL_DIGIT_RADIX;
        assert!(
            !tree
                .authenticates_canonical_message(&changed_high_digit, canonical_modulus)
                .expect("changed high digit check")
        );
    }

    #[test]
    fn committed_tree_rejects_wrong_length_noncanonical_values_and_oversized_modulus() {
        let (tree, mut canonical_message, canonical_modulus) = committed_message_fixture();
        assert!(
            !tree
                .authenticates_canonical_message(&canonical_message[..7], canonical_modulus)
                .expect("short message check")
        );
        canonical_message[0] = canonical_modulus;
        assert!(
            !tree
                .authenticates_canonical_message(&canonical_message, canonical_modulus)
                .expect("noncanonical message check")
        );
        assert!(
            !tree
                .authenticates_canonical_message(
                    &[0; 8],
                    MATERIAL_DIGIT_RADIX * MATERIAL_DIGIT_RADIX + 1,
                )
                .expect("oversized modulus check")
        );
    }

    #[test]
    fn compact_source_regenerates_every_masked_column_and_leaf_salt_without_tree_storage() {
        let (tree, canonical_message, canonical_modulus) = committed_message_fixture();
        let profile = tree.profile();
        let expected_root = tree.root();
        let expected_columns = tree.masked_coefficients_by_physical_column().to_vec();
        let source = AuthenticatedCompactCommittedMaterialSource::
            from_recomputed_tree_and_canonical_message(
                tree,
                Zeroizing::new(canonical_message.into_boxed_slice()),
                canonical_modulus,
            )
            .expect("canonical source authenticates");
        assert_eq!(source.compact_source().root(), expected_root);
        assert_eq!(source.compact_source().profile(), profile);
        for (physical_column_ordinal, expected_coefficients) in expected_columns.iter().enumerate()
        {
            assert_eq!(
                source
                    .regenerate_masked_coefficients(physical_column_ordinal)
                    .expect("the compact source regenerates the canonical column"),
                *expected_coefficients
            );
        }
        assert_ne!(
            source
                .compact_source()
                .persistent_leaf_salt(0)
                .expect("first leaf salt"),
            source
                .compact_source()
                .persistent_leaf_salt(1)
                .expect("second leaf salt")
        );
        assert!(
            source
                .compact_source()
                .persistent_leaf_salt(profile.evaluation_domain_size() / 2)
                .is_err()
        );
        assert_eq!(
            source.compact_source().retained_byte_length(),
            size_of_val(source.compact_source())
        );
        assert_eq!(
            source
                .compact_source()
                .maximum_regenerated_column_byte_length(),
            profile.material_column_degree_bound_exclusive() * size_of::<ProofBaseFieldElement>()
        );
    }

    #[test]
    fn persistent_leaf_salt_uses_two_sequential_domain_separated_kmac_blocks() {
        let material_seed = [0x37_u8; 64];
        let material_context_hash = [0xa9_u8; 64];
        let leaf_index = 19_usize;
        let leaf_salt =
            derive_material_leaf_salt(material_context_hash, &material_seed, leaf_index)
                .expect("the persistent leaf salt derives");

        let mut expected_derivation = MaterialPrivateDerivation::new(
            &material_seed,
            material_context_hash,
            LEAF_SALT_PURPOSE,
            u64::try_from(leaf_index).expect("the fixture leaf index fits u64"),
        );
        let first_block = expected_derivation
            .next_block()
            .expect("the first salt block derives");
        let second_block = expected_derivation
            .next_block()
            .expect("the second salt block derives");
        assert_eq!(&leaf_salt[..DERIVED_BLOCK_BYTE_LENGTH], &first_block[..]);
        assert_eq!(&leaf_salt[DERIVED_BLOCK_BYTE_LENGTH..], &second_block[..]);
        assert_ne!(first_block[..], second_block[..]);

        let neighboring_leaf_salt =
            derive_material_leaf_salt(material_context_hash, &material_seed, leaf_index + 1)
                .expect("the neighboring persistent leaf salt derives");
        assert_ne!(leaf_salt, neighboring_leaf_salt);

        let mut mask_derivation = MaterialPrivateDerivation::new(
            &material_seed,
            material_context_hash,
            COLUMN_MASK_PURPOSE,
            u64::try_from(leaf_index).expect("the fixture physical index fits u64"),
        );
        let mask_block = mask_derivation
            .next_block()
            .expect("the column-mask block derives");
        assert_ne!(&leaf_salt[..DERIVED_BLOCK_BYTE_LENGTH], &mask_block[..]);
    }
}
