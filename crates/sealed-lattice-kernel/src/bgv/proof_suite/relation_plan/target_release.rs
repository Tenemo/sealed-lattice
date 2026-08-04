use super::super::prover::requested_pre_challenge_source_column_ordinals;
use super::key_relation::{
    KeyRelationGeometry, KeyRelationPlanBuilder, KeyVerifierSourceKey, MATERIAL_DIGIT_RADIX,
    ReversibleShiftedSmallVector, ShiftedSmallVector, SplitIntegerVector,
    TargetBoundedUnsignedVector, TargetCenteredVector, TargetCommittedMaterialVector,
    constant_linear_term, integer_lift_half, scaled_constant_linear_term, statement_root_source,
    target_converted_radix_digit_source, target_partial_decryption_radix_digit_source,
};
use super::*;
use crate::bgv::proof_suite::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, CommittedMaterialSharedAllocationMemoryAccounting,
    CommonProofBoundTreeLeafSaltRequest, CommonProofPrivateCoinCoordinateCapacity,
    CommonProofProverError, CommonProofRelationPlanCapability, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
    CommonProofSourcePolynomialRequestContext, CommonProofSourceProviderMemoryAccounting,
    CommonProofVerifierError, CompactCommittedMaterialSource, PROOF_BASE_FIELD_MODULUS,
    ProofBaseFieldElement, ProofChallengeExtensionElement, ProofEvaluationDomain, ProofFieldError,
    ProofLeafVisibility, ProofPolynomialError, ProofTreeRole, ProvidedCommonProofSourcePolynomial,
    RelationProofTreeInput, StatementOwnedProofTreeInput, VerifiedCommonProof,
    VerifiedRelationColumnEvaluator, VerifiedRelationColumnEvaluatorMemoryAccounting,
};
use crate::foundation::PersistentProofWitnessCoinBinding;
use crate::hashing::hash_framed_parts_512;
use num_bigint::Sign;
use num_traits::ToPrimitive;
use zeroize::{Zeroize, Zeroizing};
const TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER: u16 =
    crate::foundation::ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER;
const MATERIAL_ROOTS_FIELD_ORDINAL: u64 = 10;
const TARGET_ROLE_COUNT: u16 = 2;
const RADIX_TRITS_PER_LIMB: usize = 11;
const RADIX: u64 = 177_147;
const QUOTIENT_DIGIT_TRIT_COUNT: usize = 12;
const CARRY_TRIT_COUNT: usize = 23;
const TARGET_RELEASE_SOURCE_RESTART_BINDING_DOMAIN: &str =
    "sealed-lattice/proof/target-release-source-restart-binding/v1";
const TARGET_RELEASE_SOURCE_POLYNOMIAL_REPLAY_DOMAIN: &str =
    "sealed-lattice/proof/target-release-source-polynomial-replay/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetReleaseCapabilityError {
    WrongApplication,
    WrongRelation,
}

/// Family capability derived by consuming the common verifier's opaque
/// result. Raw proof bytes, roots, and caller-supplied status fields cannot
/// construct this value.
pub(crate) struct VerifiedTargetReleaseProof {
    application_statement_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
}

impl VerifiedTargetReleaseProof {
    pub(crate) fn from_borrowed_common_proof(
        common_proof: &VerifiedCommonProof,
    ) -> Result<Self, TargetReleaseCapabilityError> {
        if common_proof.application_statement_schema_identifier()
            != TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
            || common_proof.schedule_position().is_some()
            || common_proof.top_count().is_some()
        {
            return Err(TargetReleaseCapabilityError::WrongApplication);
        }
        Ok(Self {
            application_statement_hash: common_proof.application_statement_hash(),
            relation_plan_variant_hash: common_proof.relation_plan_variant_hash(),
        })
    }

    pub(crate) const fn application_statement_hash(&self) -> [u8; 64] {
        self.application_statement_hash
    }

    pub(crate) fn require_selected_relation(&self) -> Result<(), TargetReleaseCapabilityError> {
        let (_, selected_relation_plan, _) = selected_target_release_generation_relation()
            .map_err(|_| TargetReleaseCapabilityError::WrongRelation)?;
        if self.relation_plan_variant_hash != selected_relation_plan.relation_plan_variant_hash() {
            return Err(TargetReleaseCapabilityError::WrongRelation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct TargetReleaseFloodingWitnessLayout {
    bounded_shift: TargetBoundedUnsignedVector,
    grouped_limbs: Vec<SplitIntegerVector>,
}

#[derive(Clone, Debug)]
struct TargetReleaseRoleEquationWitnessLayout {
    scaled_a_digits: Vec<SplitIntegerVector>,
    partial_decryption_digits: Vec<SplitIntegerVector>,
    quotient_digits: Vec<TargetCenteredVector>,
    carry_values: Vec<TargetCenteredVector>,
    exact_integer_lift_carry_columns: Vec<u32>,
}

#[derive(Clone, Debug)]
struct TargetReleaseModulusWitnessLayout {
    modulus_reference: SuiteModulusReference,
    modulus: u64,
    material: TargetCommittedMaterialVector,
    share_limbs: Vec<ReversibleShiftedSmallVector>,
    role_equations: Vec<TargetReleaseRoleEquationWitnessLayout>,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledTargetReleaseRelation {
    relation_plan: CompiledRelationPlan,
    ring_degree: usize,
    decryption_scale: u64,
    simulation_scale: u64,
    flooding_bound: BigUint,
    constant_one_column: u32,
    zero_column: u32,
    flooding_by_role: Vec<TargetReleaseFloodingWitnessLayout>,
    moduli: Vec<TargetReleaseModulusWitnessLayout>,
}

impl CompiledTargetReleaseRelation {
    pub(crate) const fn relation_plan(&self) -> &CompiledRelationPlan {
        &self.relation_plan
    }

    fn retained_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        target_release_compilation_retained_payload_byte_length(self)
    }
}

fn retained_target_release_vector_allocation<Value>(
    values: &Vec<Value>,
) -> Result<u64, RelationPlanError> {
    u64::try_from(values.capacity())
        .ok()
        .and_then(|count| count.checked_mul(core::mem::size_of::<Value>() as u64))
        .ok_or(RelationPlanError::CountOverflow)
}

fn checked_target_release_payload_sum(
    byte_lengths: impl IntoIterator<Item = Result<u64, RelationPlanError>>,
) -> Result<u64, RelationPlanError> {
    byte_lengths
        .into_iter()
        .try_fold(0_u64, |total, byte_length| {
            total
                .checked_add(byte_length?)
                .ok_or(RelationPlanError::CountOverflow)
        })
}

fn target_release_role_equation_retained_payload_byte_length(
    role: &TargetReleaseRoleEquationWitnessLayout,
) -> Result<u64, RelationPlanError> {
    checked_target_release_payload_sum(
        [
            retained_target_release_vector_allocation(&role.scaled_a_digits),
            retained_target_release_vector_allocation(&role.partial_decryption_digits),
            retained_target_release_vector_allocation(&role.quotient_digits),
            retained_target_release_vector_allocation(&role.carry_values),
            retained_target_release_vector_allocation(&role.exact_integer_lift_carry_columns),
        ]
        .into_iter()
        .chain(
            role.quotient_digits
                .iter()
                .chain(&role.carry_values)
                .map(TargetCenteredVector::retained_heap_byte_length),
        ),
    )
}

fn target_release_modulus_retained_payload_byte_length(
    modulus: &TargetReleaseModulusWitnessLayout,
) -> Result<u64, RelationPlanError> {
    checked_target_release_payload_sum(
        [
            modulus.material.retained_heap_byte_length(),
            retained_target_release_vector_allocation(&modulus.share_limbs),
            retained_target_release_vector_allocation(&modulus.role_equations),
        ]
        .into_iter()
        .chain(
            modulus
                .role_equations
                .iter()
                .map(target_release_role_equation_retained_payload_byte_length),
        ),
    )
}

fn target_release_compilation_retained_payload_byte_length(
    compilation: &CompiledTargetReleaseRelation,
) -> Result<u64, RelationPlanError> {
    let flooding_bound_digit_byte_length = compilation
        .flooding_bound
        .bits()
        .div_ceil(usize::BITS as u64)
        .checked_mul(core::mem::size_of::<usize>() as u64)
        .ok_or(RelationPlanError::CountOverflow)?;
    checked_target_release_payload_sum(
        [
            compilation
                .relation_plan
                .resident_owned_payload_byte_length(),
            Ok(flooding_bound_digit_byte_length),
            retained_target_release_vector_allocation(&compilation.flooding_by_role),
            retained_target_release_vector_allocation(&compilation.moduli),
        ]
        .into_iter()
        .chain(compilation.flooding_by_role.iter().flat_map(|flooding| {
            [
                flooding.bounded_shift.retained_heap_byte_length(),
                retained_target_release_vector_allocation(&flooding.grouped_limbs),
            ]
        }))
        .chain(
            compilation
                .moduli
                .iter()
                .map(target_release_modulus_retained_payload_byte_length),
        ),
    )
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TargetReleaseRoleWitness<'input> {
    /// The converted ciphertext `a` component in least-nonnegative target-prime
    /// residues. The relation applies `decryption_scale` before decomposition.
    pub(crate) converted_a: &'input [u64],
    /// The published, flooded partial decryption in least-nonnegative
    /// target-prime residues.
    pub(crate) partial_decryption: &'input [u64],
}

#[derive(Clone, Copy)]
pub(crate) struct TargetReleaseModulusWitness<'input> {
    pub(crate) committed_share_source: &'input CompactCommittedMaterialSource,
    pub(crate) threshold_share: &'input [u64],
    pub(crate) roles: [TargetReleaseRoleWitness<'input>; 2],
}

/// Public target inputs rebuilt by the verifier for one target prime. This
/// deliberately excludes the material opening, threshold share, and flooding
/// witness, so a verifier-column evaluator cannot accidentally retain or
/// consult prover-owned secrets.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VerifiedTargetReleaseModulusInput<'input> {
    pub(crate) roles: [TargetReleaseRoleWitness<'input>; 2],
}

/// Polynomial view of only the plan-owned verifier-sequence columns. It is
/// derived from verified target streams and is the sole target-family adapter
/// consumed by the common verifier.
pub(crate) struct TargetReleaseVerifiedColumnEvaluator {
    columns: Box<[(u32, CommonProofSourcePolynomial)]>,
}

impl VerifiedRelationColumnEvaluator for TargetReleaseVerifiedColumnEvaluator {
    fn memory_accounting(
        &self,
    ) -> Result<VerifiedRelationColumnEvaluatorMemoryAccounting, CommonProofVerifierError> {
        let fixed_and_catalog_byte_length = u64::try_from(core::mem::size_of::<Self>())
            .ok()
            .and_then(|fixed| {
                u64::try_from(self.columns.len()).ok().and_then(|count| {
                    u64::try_from(core::mem::size_of::<(u32, CommonProofSourcePolynomial)>())
                        .ok()
                        .and_then(|width| count.checked_mul(width))
                        .and_then(|payload| fixed.checked_add(payload))
                })
            })
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let fixed_and_input_resident_byte_length = self.columns.iter().try_fold(
            fixed_and_catalog_byte_length,
            |total, (_, polynomial)| {
                polynomial
                    .resident_payload_byte_length()
                    .ok()
                    .and_then(|payload| total.checked_add(payload))
                    .ok_or(CommonProofVerifierError::InvalidTreeLayout)
            },
        )?;
        VerifiedRelationColumnEvaluatorMemoryAccounting::new(
            fixed_and_input_resident_byte_length,
            0,
            0,
        )
    }

    fn evaluate_at_extension_point(
        &mut self,
        column_ordinal: u32,
        point: ProofChallengeExtensionElement,
    ) -> Option<ProofChallengeExtensionElement> {
        self.columns
            .binary_search_by_key(&column_ordinal, |(ordinal, _)| *ordinal)
            .ok()
            .and_then(|index| self.columns.get(index))
            .map(|(_, column)| column.evaluate_at(point))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetReleaseWitnessError {
    InvalidWitness,
    CountOverflow,
    IntegerOverflow,
    Relation(RelationPlanError),
    Field(ProofFieldError),
    Polynomial(ProofPolynomialError),
}

impl From<RelationPlanError> for TargetReleaseWitnessError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<ProofFieldError> for TargetReleaseWitnessError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

impl From<ProofPolynomialError> for TargetReleaseWitnessError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

/// Exact retained and callback-scoped payload owned by a target-release
/// witness source. Arc allocations keep their process-local owner identities
/// so a wider action-memory calculation can de-duplicate custody and lease
/// references without trusting a caller-supplied byte total.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TargetReleaseWitnessSourceMemoryAccounting {
    unique_owned_heap_byte_length: u64,
    shared_allocations: Box<[CommittedMaterialSharedAllocationMemoryAccounting]>,
    shared_allocation_byte_length: u64,
    flooding_callback_ready_resident_byte_length: u64,
    flooding_callback_construction_transient_byte_length: u64,
    modulus_callback_transient_byte_length: u64,
}

impl TargetReleaseWitnessSourceMemoryAccounting {
    pub(crate) fn new(
        unique_owned_heap_byte_length: u64,
        shared_allocations: Vec<CommittedMaterialSharedAllocationMemoryAccounting>,
        flooding_callback_ready_resident_byte_length: u64,
        flooding_callback_construction_transient_byte_length: u64,
        modulus_callback_transient_byte_length: u64,
    ) -> Result<Self, TargetReleaseWitnessError> {
        let mut allocation_byte_lengths = BTreeMap::<usize, u64>::new();
        for allocation in shared_allocations {
            if allocation.retained_byte_length() == 0 {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            match allocation_byte_lengths.get(&allocation.owner_identifier()) {
                Some(byte_length) if *byte_length != allocation.retained_byte_length() => {
                    return Err(TargetReleaseWitnessError::InvalidWitness);
                }
                Some(_) => {}
                None => {
                    allocation_byte_lengths.insert(
                        allocation.owner_identifier(),
                        allocation.retained_byte_length(),
                    );
                }
            }
        }
        let shared_allocation_byte_length =
            allocation_byte_lengths
                .values()
                .try_fold(0_u64, |total, byte_length| {
                    total
                        .checked_add(*byte_length)
                        .ok_or(TargetReleaseWitnessError::CountOverflow)
                })?;
        let shared_allocations = allocation_byte_lengths
            .into_iter()
            .map(|(owner_identifier, retained_byte_length)| {
                CommittedMaterialSharedAllocationMemoryAccounting::new(
                    owner_identifier,
                    retained_byte_length,
                )
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            unique_owned_heap_byte_length,
            shared_allocations,
            shared_allocation_byte_length,
            flooding_callback_ready_resident_byte_length,
            flooding_callback_construction_transient_byte_length,
            modulus_callback_transient_byte_length,
        })
    }

    pub(crate) const fn flooding_callback_ready_resident_byte_length(&self) -> u64 {
        self.flooding_callback_ready_resident_byte_length
    }

    pub(crate) const fn unique_owned_heap_byte_length(&self) -> u64 {
        self.unique_owned_heap_byte_length
    }

    pub(crate) const fn shared_allocation_byte_length(&self) -> u64 {
        self.shared_allocation_byte_length
    }

    pub(crate) const fn flooding_callback_construction_transient_byte_length(&self) -> u64 {
        self.flooding_callback_construction_transient_byte_length
    }

    pub(crate) const fn modulus_callback_transient_byte_length(&self) -> u64 {
        self.modulus_callback_transient_byte_length
    }

    pub(crate) fn additional_persistent_resident_byte_length(
        &self,
    ) -> Result<u64, TargetReleaseWitnessError> {
        self.unique_owned_heap_byte_length
            .checked_add(self.shared_allocation_byte_length)
            .ok_or(TargetReleaseWitnessError::CountOverflow)
    }
}

/// Opaque family-owned access to the selected target witness. Implementations
/// retain the accepted-setup authority and borrow one committed share only for
/// the duration of a block derivation; raw share vectors never become a host
/// input or a serialized proof-runtime field.
pub(crate) trait TargetReleaseWitnessSource {
    /// Reports every retained allocation and every allocation that can remain
    /// live while either callback body executes. Flooding scratch construction
    /// is separate because its final conversion buffer is gone before the
    /// callback body; modulus callback scratch is reported independently.
    fn memory_accounting(
        &self,
    ) -> Result<TargetReleaseWitnessSourceMemoryAccounting, TargetReleaseWitnessError>;

    fn with_flooding_errors<Output, Operation>(
        &self,
        role_ordinal: usize,
        operation: Operation,
    ) -> Result<Output, TargetReleaseWitnessError>
    where
        Operation: FnOnce(&[BigInt]) -> Result<Output, TargetReleaseWitnessError>;

    fn with_modulus_witness<Output, Operation>(
        &self,
        modulus_ordinal: usize,
        operation: Operation,
    ) -> Result<Output, TargetReleaseWitnessError>
    where
        Operation: for<'input> FnOnce(
            TargetReleaseModulusWitness<'input>,
        ) -> Result<Output, TargetReleaseWitnessError>;

    fn source_restart_binding_hash(&self) -> [u8; 64];

    fn absorb_canonical_semantic_witness(
        &self,
        binding: &mut PersistentProofWitnessCoinBinding,
    ) -> Result<(), TargetReleaseWitnessError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetReleaseSourceBlock {
    ConstantOne,
    ConstantZero,
    FloodingBounded {
        role_ordinal: usize,
    },
    FloodingGrouped {
        role_ordinal: usize,
    },
    CommittedShare {
        modulus_ordinal: usize,
    },
    ShareGrouped {
        modulus_ordinal: usize,
    },
    RoleVerifier {
        modulus_ordinal: usize,
        role_ordinal: usize,
    },
    RoleQuotient {
        modulus_ordinal: usize,
        role_ordinal: usize,
        digit_ordinal: usize,
    },
    RoleCarry {
        modulus_ordinal: usize,
        role_ordinal: usize,
        digit_ordinal: usize,
    },
    ExactIntegerLiftCarry {
        modulus_ordinal: usize,
        role_ordinal: usize,
        carry_column_ordinal: u32,
    },
}

struct TargetReleaseRoleDerivedLayers {
    flooding_shift_layers: Zeroizing<Vec<Vec<u64>>>,
    quotient_layers: Zeroizing<Vec<Vec<i128>>>,
    carry_layers: Zeroizing<Vec<Vec<i128>>>,
}

fn zeroize_consumed_derived_layer(values: &mut Vec<i128>) -> Result<(), TargetReleaseWitnessError> {
    if values.is_empty() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    values.zeroize();
    Ok(())
}

fn clear_target_release_role_layer_cache(
    cached_role_key: &mut Option<(usize, usize)>,
    cached_role_layers: &mut Option<TargetReleaseRoleDerivedLayers>,
) {
    if let Some(layers) = cached_role_layers.as_mut() {
        layers.flooding_shift_layers.zeroize();
        for values in layers
            .quotient_layers
            .iter_mut()
            .chain(layers.carry_layers.iter_mut())
        {
            values.zeroize();
        }
    }
    *cached_role_layers = None;
    *cached_role_key = None;
}

fn prepare_target_release_role_layer_cache(
    cached_role_key: &mut Option<(usize, usize)>,
    cached_role_layers: &mut Option<TargetReleaseRoleDerivedLayers>,
    requested_role_key: (usize, usize),
) -> Result<bool, TargetReleaseWitnessError> {
    if cached_role_key.is_some() != cached_role_layers.is_some() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let Some(layers) = cached_role_layers.as_ref() else {
        return Ok(true);
    };
    let has_unconsumed_values = layers
        .quotient_layers
        .iter()
        .chain(layers.carry_layers.iter())
        .any(|values| !values.is_empty());
    if has_unconsumed_values {
        if *cached_role_key == Some(requested_role_key) {
            return Ok(false);
        }
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    clear_target_release_role_layer_cache(cached_role_key, cached_role_layers);
    Ok(true)
}

/// Restartable one-polynomial-at-a-time source provider for schema `0x1621`.
///
/// Family arithmetic may derive bounded radix scratch for the requested
/// column, but only that polynomial is interpolated and returned. The common
/// prover therefore never coexists with a provider-owned polynomial catalog.
/// Replay identities bind the exact action-owned source, checked plan variant,
/// descriptor, and ordinal so checkpoint recovery cannot substitute another
/// witness.
pub(crate) struct TargetReleaseSourcePolynomialAdapter<Source> {
    compilation: CompiledTargetReleaseRelation,
    source: Source,
    protocol_version: u16,
    suite_identifier: [u8; 64],
    application_statement_hash: [u8; 64],
    relation_plan_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    restart_binding_hash: [u8; 64],
    ordered_source_column_ordinals: Box<[u32]>,
    ordered_source_blocks: Box<[TargetReleaseSourceBlock]>,
    bound_sources_by_catalog_index: Box<[(u16, usize)]>,
    next_source_column_position: usize,
    cached_role_key: Option<(usize, usize)>,
    cached_role_layers: Option<TargetReleaseRoleDerivedLayers>,
    cached_exact_carry_column_ordinal: Option<u32>,
    cached_exact_carry_rows: Option<Zeroizing<Vec<i128>>>,
    source_polynomials_finished: bool,
    next_leaf_salt_source_ordinal: usize,
    next_leaf_salt_index: usize,
    leaf_salts_finished: bool,
}

impl<Source> TargetReleaseSourcePolynomialAdapter<Source>
where
    Source: TargetReleaseWitnessSource,
{
    /// Atomically derives the sole production compilation, its checked common
    /// proof capability, and the source adapter. Bounds, scales, and target
    /// moduli never enter this constructor as caller-selected values.
    pub(crate) fn new_selected(
        protocol_version: u16,
        suite_identifier: [u8; 64],
        application_statement_hash: [u8; 64],
        source: Source,
    ) -> Result<
        (
            CommonProofRelationPlanCapability,
            CommonProofPrivateCoinCoordinateCapacity,
            Self,
        ),
        TargetReleaseWitnessError,
    > {
        let (compilation, relation_plan, coordinate_capacity) =
            selected_target_release_generation_relation()?;
        let relation_plan_hash = relation_plan.relation_plan_hash();
        let source_adapter = Self::new(
            compilation,
            protocol_version,
            suite_identifier,
            application_statement_hash,
            relation_plan_hash,
            source,
        )?;
        Ok((relation_plan, coordinate_capacity, source_adapter))
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        compilation: CompiledTargetReleaseRelation,
        protocol_version: u16,
        suite_identifier: [u8; 64],
        application_statement_hash: [u8; 64],
        relation_plan_hash: [u8; 64],
        source: Source,
    ) -> Result<Self, TargetReleaseWitnessError> {
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)?
            .clone();
        let trace_domain_size = compilation
            .ring_degree
            .checked_div(2)
            .filter(|trace_domain_size| {
                *trace_domain_size > 1
                    && trace_domain_size.checked_mul(2) == Some(compilation.ring_degree)
            })
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let relation_plan_variant_hash = variant.canonical_hash()?;
        let source_restart_binding_hash = source.source_restart_binding_hash();
        if protocol_version == 0
            || suite_identifier == [0_u8; 64]
            || application_statement_hash == [0_u8; 64]
            || relation_plan_hash == [0_u8; 64]
            || relation_plan_variant_hash == [0_u8; 64]
            || source_restart_binding_hash == [0_u8; 64]
            || compilation
                .relation_plan()
                .application_statement_schema_identifier()
                != TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
            || variant.schedule_position().is_some()
            || variant.top_count().is_some()
            || usize::try_from(variant.trace_domain_size()).ok() != Some(trace_domain_size)
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let (ordered_source_column_ordinals, ordered_source_blocks) =
            target_release_source_blocks(&compilation)?
                .into_iter()
                .unzip::<_, _, Vec<_>, Vec<_>>();
        if ordered_source_column_ordinals.is_empty() {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let mut bound_sources_by_catalog_index = Vec::with_capacity(compilation.moduli.len());
        for (tree_catalog_index, descriptor) in variant.ordered_trees().iter().enumerate() {
            let RelationTreeDescriptor::BoundPublic {
                construction_kind,
                ordered_column_ordinals,
                ..
            } = descriptor
            else {
                continue;
            };
            let modulus_ordinal = bound_sources_by_catalog_index.len();
            let modulus_layout = compilation
                .moduli
                .get(modulus_ordinal)
                .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
            if *construction_kind != BoundTreeConstructionKind::CommittedMaterial
                || ordered_column_ordinals.as_slice() != modulus_layout.material.bound_columns
            {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            source.with_modulus_witness(modulus_ordinal, |witness| {
                if witness.committed_share_source.profile().trace_domain_size() != trace_domain_size
                    || witness.threshold_share.len() != compilation.ring_degree
                    || witness
                        .threshold_share
                        .iter()
                        .any(|value| *value >= modulus_layout.modulus)
                {
                    return Err(TargetReleaseWitnessError::InvalidWitness);
                }
                Ok(())
            })?;
            bound_sources_by_catalog_index.push((
                u16::try_from(tree_catalog_index)
                    .map_err(|_| TargetReleaseWitnessError::CountOverflow)?,
                modulus_ordinal,
            ));
        }
        if bound_sources_by_catalog_index.len() != compilation.moduli.len() {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let restart_binding_hash = hash_framed_parts_512(
            TARGET_RELEASE_SOURCE_RESTART_BINDING_DOMAIN,
            &[
                &source_restart_binding_hash,
                &application_statement_hash,
                &relation_plan_hash,
                &relation_plan_variant_hash,
            ],
        );
        Ok(Self {
            compilation,
            source,
            protocol_version,
            suite_identifier,
            application_statement_hash,
            relation_plan_hash,
            relation_plan_variant_hash,
            restart_binding_hash,
            ordered_source_column_ordinals: ordered_source_column_ordinals.into_boxed_slice(),
            ordered_source_blocks: ordered_source_blocks.into_boxed_slice(),
            bound_sources_by_catalog_index: bound_sources_by_catalog_index.into_boxed_slice(),
            next_source_column_position: 0,
            cached_role_key: None,
            cached_role_layers: None,
            cached_exact_carry_column_ordinal: None,
            cached_exact_carry_rows: None,
            source_polynomials_finished: false,
            next_leaf_salt_source_ordinal: 0,
            next_leaf_salt_index: 0,
            leaf_salts_finished: false,
        })
    }

    pub(crate) fn absorb_canonical_semantic_witness(
        &self,
        binding: &mut PersistentProofWitnessCoinBinding,
    ) -> Result<(), TargetReleaseWitnessError> {
        self.source.absorb_canonical_semantic_witness(binding)
    }

    pub(crate) fn relation_tree_inputs(
        &self,
    ) -> Result<Vec<RelationProofTreeInput>, CommonProofProverError> {
        let variant = self
            .compilation
            .relation_plan()
            .select_variant(None, None)
            .map_err(|_| CommonProofProverError::InvalidTree)?;
        variant
            .ordered_trees()
            .iter()
            .enumerate()
            .map(|(tree_catalog_index, descriptor)| match descriptor {
                RelationTreeDescriptor::BoundPublic { .. } => {
                    let expected_catalog_index = u16::try_from(tree_catalog_index)
                        .map_err(|_| CommonProofProverError::CountOverflow)?;
                    let modulus_ordinal = self
                        .bound_sources_by_catalog_index
                        .iter()
                        .find_map(|(catalog_index, modulus_ordinal)| {
                            (*catalog_index == expected_catalog_index).then_some(*modulus_ordinal)
                        })
                        .ok_or(CommonProofProverError::InvalidTree)?;
                    self.source
                        .with_modulus_witness(modulus_ordinal, |witness| {
                            Ok(RelationProofTreeInput::BoundPublic(
                                StatementOwnedProofTreeInput::CommittedMaterial {
                                    material_context_hash: witness
                                        .committed_share_source
                                        .material_context_hash(),
                                    expected_root: witness.committed_share_source.root(),
                                },
                            ))
                        })
                        .map_err(|_| CommonProofProverError::InvalidTree)
                }
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                } => {
                    let tree_role = match *proof_tree_role {
                        value if value == ProofTreeRole::BaseOracle as u16 => {
                            ProofTreeRole::BaseOracle
                        }
                        value if value == ProofTreeRole::AuxiliaryOracle as u16 => {
                            ProofTreeRole::AuxiliaryOracle
                        }
                        _ => return Err(CommonProofProverError::InvalidTree),
                    };
                    let leaf_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                        usize::try_from(*column_ordinal)
                            .ok()
                            .and_then(|column_index| variant.ordered_columns().get(column_index))
                            .is_some_and(|column| {
                                matches!(column.origin(), RelationColumnOrigin::Prover)
                            })
                    }) {
                        ProofLeafVisibility::SecretBearing
                    } else {
                        ProofLeafVisibility::Public
                    };
                    Ok(RelationProofTreeInput::ProofCreated {
                        tree_role,
                        row_width: u32::try_from(ordered_column_ordinals.len())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                        leaf_visibility,
                    })
                }
            })
            .collect()
    }

    const fn expected_request_context(&self) -> CommonProofSourcePolynomialRequestContext {
        CommonProofSourcePolynomialRequestContext::new(
            self.protocol_version,
            self.suite_identifier,
            TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
            self.application_statement_hash,
            self.relation_plan_hash,
            self.relation_plan_variant_hash,
            None,
            None,
        )
    }

    fn source_polynomial_replay_identity(
        &self,
        column_ordinal: u32,
    ) -> Result<[u8; 64], TargetReleaseWitnessError> {
        let descriptor = self
            .compilation
            .relation_plan()
            .select_variant(None, None)?
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| TargetReleaseWitnessError::CountOverflow)?,
            )
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let descriptor_bytes = descriptor
            .canonical_tuple()?
            .encode()
            .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
        Ok(hash_framed_parts_512(
            TARGET_RELEASE_SOURCE_POLYNOMIAL_REPLAY_DOMAIN,
            &[
                &self.restart_binding_hash,
                &column_ordinal.to_le_bytes(),
                &descriptor_bytes,
            ],
        ))
    }

    fn materialize_requested_column(
        &mut self,
        block: TargetReleaseSourceBlock,
        requested_column_ordinal: u32,
    ) -> Result<CommonProofSourcePolynomial, TargetReleaseWitnessError> {
        let mut columns = RequestedTargetReleaseSourcePolynomial::new(requested_column_ordinal);
        let trace_domain = ProofEvaluationDomain::new_subgroup(self.compilation.ring_degree / 2)?;
        match block {
            TargetReleaseSourceBlock::ConstantOne => insert_source_polynomial(
                &mut columns,
                self.compilation.constant_one_column,
                CommonProofSourcePolynomial::from_base_coefficients(vec![
                    ProofBaseFieldElement::ONE,
                ]),
            )?,
            TargetReleaseSourceBlock::ConstantZero => insert_source_polynomial(
                &mut columns,
                self.compilation.zero_column,
                CommonProofSourcePolynomial::from_base_coefficients(vec![
                    ProofBaseFieldElement::ZERO,
                ]),
            )?,
            TargetReleaseSourceBlock::FloodingBounded { role_ordinal } => {
                let shifted = self
                    .source
                    .with_flooding_errors(role_ordinal, |flooding_error| {
                        shifted_flooding_values(
                            flooding_error,
                            self.compilation.ring_degree,
                            &self.compilation.flooding_bound,
                        )
                    })?;
                insert_bounded_unsigned_vector(
                    &mut columns,
                    trace_domain,
                    &self.compilation.flooding_by_role[role_ordinal].bounded_shift,
                    &shifted,
                    &(&self.compilation.flooding_bound * 2_u8),
                )?;
            }
            TargetReleaseSourceBlock::FloodingGrouped { role_ordinal } => {
                let shifted = self
                    .source
                    .with_flooding_errors(role_ordinal, |flooding_error| {
                        shifted_flooding_values(
                            flooding_error,
                            self.compilation.ring_degree,
                            &self.compilation.flooding_bound,
                        )
                    })?;
                let layouts = &self.compilation.flooding_by_role[role_ordinal].grouped_limbs;
                let layers = big_unsigned_radix_layers(&shifted, RADIX, layouts.len())?;
                insert_split_radix_layers(&mut columns, trace_domain, layouts, &layers)?;
            }
            TargetReleaseSourceBlock::CommittedShare { modulus_ordinal } => {
                let layout = &self.compilation.moduli[modulus_ordinal];
                self.source
                    .with_modulus_witness(modulus_ordinal, |witness| {
                        insert_committed_share_columns(
                            &mut columns,
                            trace_domain,
                            &layout.material,
                            witness.committed_share_source,
                            witness.threshold_share,
                            layout.modulus,
                        )?;
                        Ok(())
                    })?;
            }
            TargetReleaseSourceBlock::ShareGrouped { modulus_ordinal } => {
                let layout = &self.compilation.moduli[modulus_ordinal];
                self.source
                    .with_modulus_witness(modulus_ordinal, |witness| {
                        let layers = unsigned_radix_layers(
                            witness.threshold_share,
                            RADIX,
                            layout.share_limbs.len(),
                        )?;
                        let split_layouts = layout
                            .share_limbs
                            .iter()
                            .map(|limb| limb.source.coefficients)
                            .collect::<Vec<_>>();
                        insert_split_radix_layers(
                            &mut columns,
                            trace_domain,
                            &split_layouts,
                            &layers,
                        )
                    })?;
            }
            TargetReleaseSourceBlock::RoleVerifier {
                modulus_ordinal,
                role_ordinal,
            } => {
                let modulus_layout = &self.compilation.moduli[modulus_ordinal];
                let role_layout = &modulus_layout.role_equations[role_ordinal];
                self.source
                    .with_modulus_witness(modulus_ordinal, |witness| {
                        insert_role_verifier_columns(
                            &mut columns,
                            trace_domain,
                            role_layout,
                            witness.roles[role_ordinal],
                            modulus_layout.modulus,
                            self.compilation.decryption_scale,
                        )?;
                        Ok(())
                    })?;
            }
            TargetReleaseSourceBlock::RoleQuotient {
                modulus_ordinal,
                role_ordinal,
                digit_ordinal,
            } => {
                self.ensure_role_layers(modulus_ordinal, role_ordinal)?;
                let role_layout =
                    &self.compilation.moduli[modulus_ordinal].role_equations[role_ordinal];
                let values = self
                    .cached_role_layers
                    .as_ref()
                    .and_then(|layers| layers.quotient_layers.get(digit_ordinal))
                    .filter(|values| !values.is_empty())
                    .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
                insert_centered_vector(
                    &mut columns,
                    trace_domain,
                    role_layout
                        .quotient_digits
                        .get(digit_ordinal)
                        .ok_or(TargetReleaseWitnessError::InvalidWitness)?,
                    values,
                )?;
            }
            TargetReleaseSourceBlock::RoleCarry {
                modulus_ordinal,
                role_ordinal,
                digit_ordinal,
            } => {
                self.ensure_role_layers(modulus_ordinal, role_ordinal)?;
                let role_layout =
                    &self.compilation.moduli[modulus_ordinal].role_equations[role_ordinal];
                let values = self
                    .cached_role_layers
                    .as_ref()
                    .and_then(|layers| layers.carry_layers.get(digit_ordinal))
                    .filter(|values| !values.is_empty())
                    .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
                insert_centered_vector(
                    &mut columns,
                    trace_domain,
                    role_layout
                        .carry_values
                        .get(digit_ordinal)
                        .ok_or(TargetReleaseWitnessError::InvalidWitness)?,
                    values,
                )?;
            }
            TargetReleaseSourceBlock::ExactIntegerLiftCarry {
                modulus_ordinal,
                role_ordinal,
                carry_column_ordinal,
            } => {
                self.ensure_exact_carry_rows(modulus_ordinal, role_ordinal, carry_column_ordinal)?;
                let carry_rows = self
                    .cached_exact_carry_rows
                    .as_ref()
                    .filter(|rows| !rows.is_empty())
                    .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
                if requested_column_ordinal == carry_column_ordinal {
                    insert_signed_half_column(
                        &mut columns,
                        trace_domain,
                        carry_column_ordinal,
                        carry_rows,
                    )?;
                } else {
                    let variant = self
                        .compilation
                        .relation_plan()
                        .select_variant(None, None)?;
                    let semantic_cell = variant
                        .ordered_semantic_cells
                        .iter()
                        .find(|semantic_cell| semantic_cell.column_ordinal == carry_column_ordinal)
                        .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
                    let RelationBoundCertificate::ShiftedRadixRecomposition {
                        radix,
                        offset,
                        ordered_digit_column_ordinals,
                        ..
                    } = &semantic_cell.bound_certificate
                    else {
                        return Err(TargetReleaseWitnessError::InvalidWitness);
                    };
                    let digit_ordinal = ordered_digit_column_ordinals
                        .iter()
                        .position(|candidate| *candidate == requested_column_ordinal)
                        .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
                    let offset = offset
                        .to_i128()
                        .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
                    let digit_count = u32::try_from(ordered_digit_column_ordinals.len())
                        .map_err(|_| TargetReleaseWitnessError::CountOverflow)?;
                    let capacity = i128::from(*radix)
                        .checked_pow(digit_count)
                        .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
                    let divisor = i128::from(*radix)
                        .checked_pow(
                            u32::try_from(digit_ordinal)
                                .map_err(|_| TargetReleaseWitnessError::CountOverflow)?,
                        )
                        .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
                    let digit_rows = carry_rows
                        .iter()
                        .map(|value| {
                            value
                                .checked_add(offset)
                                .filter(|shifted| *shifted >= 0 && *shifted < capacity)
                                .and_then(|shifted| {
                                    u64::try_from((shifted / divisor) % i128::from(*radix)).ok()
                                })
                                .ok_or(TargetReleaseWitnessError::InvalidWitness)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    insert_unsigned_half_column(
                        &mut columns,
                        trace_domain,
                        requested_column_ordinal,
                        &digit_rows,
                    )?;
                }
            }
        }
        let polynomial = columns.finish()?;
        let block_finishes_after_this_column = self
            .next_source_column_position
            .checked_add(1)
            .and_then(|next_position| self.ordered_source_blocks.get(next_position))
            .is_none_or(|next_block| *next_block != block);
        if block_finishes_after_this_column {
            match block {
                TargetReleaseSourceBlock::RoleQuotient { digit_ordinal, .. } => {
                    let values = self
                        .cached_role_layers
                        .as_mut()
                        .and_then(|layers| layers.quotient_layers.get_mut(digit_ordinal))
                        .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
                    zeroize_consumed_derived_layer(values)?;
                }
                TargetReleaseSourceBlock::RoleCarry { digit_ordinal, .. } => {
                    let values = self
                        .cached_role_layers
                        .as_mut()
                        .and_then(|layers| layers.carry_layers.get_mut(digit_ordinal))
                        .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
                    zeroize_consumed_derived_layer(values)?;
                }
                TargetReleaseSourceBlock::ExactIntegerLiftCarry {
                    modulus_ordinal,
                    role_ordinal,
                    carry_column_ordinal,
                } => {
                    if self.cached_exact_carry_column_ordinal != Some(carry_column_ordinal) {
                        return Err(TargetReleaseWitnessError::InvalidWitness);
                    }
                    let rows = self
                        .cached_exact_carry_rows
                        .as_mut()
                        .filter(|rows| !rows.is_empty())
                        .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
                    rows.zeroize();
                    self.cached_exact_carry_rows = None;
                    self.cached_exact_carry_column_ordinal = None;
                    let next_exact_carry_has_same_role = self
                        .next_source_column_position
                        .checked_add(1)
                        .and_then(|next_position| self.ordered_source_blocks.get(next_position))
                        .is_some_and(|next_block| {
                            matches!(
                                next_block,
                                TargetReleaseSourceBlock::ExactIntegerLiftCarry {
                                    modulus_ordinal: next_modulus_ordinal,
                                    role_ordinal: next_role_ordinal,
                                    ..
                                } if *next_modulus_ordinal == modulus_ordinal
                                    && *next_role_ordinal == role_ordinal
                            )
                        });
                    if !next_exact_carry_has_same_role {
                        self.clear_cached_role_layers();
                    }
                }
                _ => {}
            }
        }
        Ok(polynomial)
    }

    fn ensure_role_layers(
        &mut self,
        modulus_ordinal: usize,
        role_ordinal: usize,
    ) -> Result<(), TargetReleaseWitnessError> {
        let key = (modulus_ordinal, role_ordinal);
        if !prepare_target_release_role_layer_cache(
            &mut self.cached_role_key,
            &mut self.cached_role_layers,
            key,
        )? {
            return Ok(());
        }
        let modulus_layout = &self.compilation.moduli[modulus_ordinal];
        let role_layout = &modulus_layout.role_equations[role_ordinal];
        let derived = self
            .source
            .with_flooding_errors(role_ordinal, |flooding_error| {
                let flooding_shift_layers = Zeroizing::new(shifted_flooding_radix_layers(
                    flooding_error,
                    self.compilation.ring_degree,
                    &self.compilation.flooding_bound,
                    RADIX,
                    self.compilation.flooding_by_role[role_ordinal]
                        .grouped_limbs
                        .len(),
                )?);
                self.source
                    .with_modulus_witness(modulus_ordinal, |witness| {
                        let share_layers = unsigned_radix_layers(
                            witness.threshold_share,
                            RADIX,
                            modulus_layout.share_limbs.len(),
                        )?;
                        let share_transform = RadixLayerTransform::new(&share_layers)?;
                        drop(share_layers);
                        derive_role_equation_layers(
                            role_layout,
                            witness.roles[role_ordinal],
                            share_transform,
                            flooding_error,
                            flooding_shift_layers,
                            modulus_layout.modulus,
                            self.compilation.decryption_scale,
                            self.compilation.simulation_scale,
                            &self.compilation.flooding_bound,
                            self.compilation.ring_degree,
                        )
                    })
            })?;
        self.cached_role_key = Some(key);
        self.cached_role_layers = Some(derived);
        Ok(())
    }

    fn clear_cached_role_layers(&mut self) {
        clear_target_release_role_layer_cache(
            &mut self.cached_role_key,
            &mut self.cached_role_layers,
        );
    }

    fn ensure_exact_carry_rows(
        &mut self,
        modulus_ordinal: usize,
        role_ordinal: usize,
        carry_column_ordinal: u32,
    ) -> Result<(), TargetReleaseWitnessError> {
        if self.cached_exact_carry_column_ordinal == Some(carry_column_ordinal)
            && self
                .cached_exact_carry_rows
                .as_ref()
                .is_some_and(|rows| !rows.is_empty())
        {
            return Ok(());
        }
        if self.cached_exact_carry_column_ordinal.is_some()
            || self.cached_exact_carry_rows.is_some()
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let requested_role_key = (modulus_ordinal, role_ordinal);
        if let Some(existing_layers) = self.cached_role_layers.as_ref() {
            let all_layers_empty = existing_layers
                .quotient_layers
                .iter()
                .chain(existing_layers.carry_layers.iter())
                .all(Vec::is_empty);
            if self.cached_role_key != Some(requested_role_key) || all_layers_empty {
                if !all_layers_empty {
                    return Err(TargetReleaseWitnessError::InvalidWitness);
                }
                self.clear_cached_role_layers();
            }
        }
        self.ensure_role_layers(modulus_ordinal, role_ordinal)?;
        let role_layers = self
            .cached_role_layers
            .as_ref()
            .filter(|layers| {
                layers
                    .quotient_layers
                    .iter()
                    .chain(layers.carry_layers.iter())
                    .all(|values| !values.is_empty())
            })
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let active_column_capacity = self
            .compilation
            .moduli
            .get(modulus_ordinal)
            .and_then(|modulus| modulus.role_equations.get(role_ordinal))
            .and_then(|role| role.exact_integer_lift_carry_columns.len().checked_add(1))
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        let variant = self
            .compilation
            .relation_plan()
            .select_variant(None, None)?;
        let mut derivation = TargetReleaseExactCarryDerivation {
            compilation: &self.compilation,
            source: &self.source,
            variant,
            modulus_ordinal,
            role_ordinal,
            role_layers,
            active_columns: vec![0_u32; active_column_capacity].into_boxed_slice(),
            active_column_count: 0,
        };
        let rows = derivation.derive_rows(carry_column_ordinal)?;
        self.cached_exact_carry_column_ordinal = Some(carry_column_ordinal);
        self.cached_exact_carry_rows = Some(rows);
        Ok(())
    }
}

fn selected_target_release_generation_relation() -> Result<
    (
        CompiledTargetReleaseRelation,
        CommonProofRelationPlanCapability,
        CommonProofPrivateCoinCoordinateCapacity,
    ),
    TargetReleaseWitnessError,
> {
    let compilation = crate::bgv::proof_suite::selected_profile::selected_target_release_relation()
        .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
    let relation_context =
        crate::bgv::proof_suite::selected_profile::selected_relation_plan_check_context(
            TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        compilation.relation_plan(),
        &relation_context,
        None,
        None,
    )
    .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
    let coordinate_capacity = CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(
        compilation.relation_plan().select_variant(None, None)?,
    )
    .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
    Ok((compilation, relation_plan, coordinate_capacity))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TargetReleaseMemoryScalarByteLengths {
    vector_header_byte_length: u64,
    unsigned_coefficient_byte_length: u64,
    signed_coefficient_byte_length: u64,
    proof_field_element_byte_length: u64,
    column_ordinal_byte_length: u64,
}

impl TargetReleaseMemoryScalarByteLengths {
    const fn current_target() -> Self {
        Self {
            vector_header_byte_length: core::mem::size_of::<Vec<u8>>() as u64,
            unsigned_coefficient_byte_length: core::mem::size_of::<u64>() as u64,
            signed_coefficient_byte_length: core::mem::size_of::<i128>() as u64,
            proof_field_element_byte_length: core::mem::size_of::<ProofBaseFieldElement>() as u64,
            column_ordinal_byte_length: core::mem::size_of::<u32>() as u64,
        }
    }

    #[cfg(test)]
    const fn wasm32() -> Self {
        Self {
            vector_header_byte_length: 12,
            unsigned_coefficient_byte_length: 8,
            signed_coefficient_byte_length: 16,
            proof_field_element_byte_length: 8,
            column_ordinal_byte_length: 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TargetReleaseRoleLayerConstructionMemoryAccounting {
    callback_construction_byte_length: u64,
    flooding_layer_construction_byte_length: u64,
    share_radix_construction_byte_length: u64,
    share_transform_construction_byte_length: u64,
    product_evaluation_byte_length: u64,
    product_folding_byte_length: u64,
    quotient_construction_byte_length: u64,
    carry_construction_byte_length: u64,
    role_cache_byte_length: u64,
    steady_role_envelope_byte_length: u64,
    exact_carry_derivation_byte_length: u64,
    exact_carry_materialization_byte_length: u64,
    ordinary_materialization_byte_length: u64,
}

impl TargetReleaseRoleLayerConstructionMemoryAccounting {
    fn maximum_dynamic_byte_length(self) -> u64 {
        [
            self.callback_construction_byte_length,
            self.flooding_layer_construction_byte_length,
            self.share_radix_construction_byte_length,
            self.share_transform_construction_byte_length,
            self.product_evaluation_byte_length,
            self.product_folding_byte_length,
            self.quotient_construction_byte_length,
            self.carry_construction_byte_length,
            self.exact_carry_derivation_byte_length,
            self.exact_carry_materialization_byte_length,
            self.ordinary_materialization_byte_length,
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
    }
}

fn target_release_checked_memory_add(left: u64, right: u64) -> Result<u64, CommonProofProverError> {
    left.checked_add(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn target_release_checked_memory_multiply(
    left: u64,
    right: u64,
) -> Result<u64, CommonProofProverError> {
    left.checked_mul(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn target_release_memory_count(value: usize) -> Result<u64, CommonProofProverError> {
    u64::try_from(value).map_err(|_| CommonProofProverError::CountOverflow)
}

fn target_release_nested_layer_byte_length(
    layer_count: usize,
    coefficient_count: u64,
    coefficient_byte_length: u64,
    widths: TargetReleaseMemoryScalarByteLengths,
) -> Result<u64, CommonProofProverError> {
    let one_layer_byte_length = target_release_checked_memory_add(
        widths.vector_header_byte_length,
        target_release_checked_memory_multiply(coefficient_count, coefficient_byte_length)?,
    )?;
    target_release_checked_memory_multiply(
        target_release_memory_count(layer_count)?,
        one_layer_byte_length,
    )
}

fn target_release_modulus_digit_count(mut modulus: u64) -> Result<usize, CommonProofProverError> {
    if modulus == 0 || RADIX < 2 {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let mut count = 1_usize;
    while modulus >= RADIX {
        modulus /= RADIX;
        count = count
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
    }
    Ok(count)
}

#[allow(clippy::too_many_arguments)]
fn target_release_role_layer_construction_memory_accounting(
    compilation: &CompiledTargetReleaseRelation,
    modulus_layout: &TargetReleaseModulusWitnessLayout,
    role_layout: &TargetReleaseRoleEquationWitnessLayout,
    role_ordinal: usize,
    flooding_callback_ready_resident_byte_length: u64,
    flooding_callback_construction_transient_byte_length: u64,
    modulus_callback_transient_byte_length: u64,
    widths: TargetReleaseMemoryScalarByteLengths,
) -> Result<TargetReleaseRoleLayerConstructionMemoryAccounting, CommonProofProverError> {
    let ring_degree = target_release_memory_count(compilation.ring_degree)?;
    let trace_domain_size = ring_degree
        .checked_div(2)
        .filter(|trace_domain_size| {
            *trace_domain_size > 1 && trace_domain_size.checked_mul(2) == Some(ring_degree)
        })
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let doubled_ring_degree = ring_degree
        .checked_mul(2)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let flooding_layer_count = compilation
        .flooding_by_role
        .get(role_ordinal)
        .map(|layout| layout.grouped_limbs.len())
        .filter(|count| *count > 0)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let share_layer_count = modulus_layout.share_limbs.len();
    let scaled_a_layer_count = role_layout.scaled_a_digits.len();
    let partial_decryption_layer_count = role_layout.partial_decryption_digits.len();
    let product_layer_count = scaled_a_layer_count
        .checked_add(share_layer_count)
        .and_then(|count| count.checked_sub(1))
        .filter(|count| *count > 0)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let quotient_layer_count = role_layout.quotient_digits.len();
    let carry_layer_count = role_layout.carry_values.len();
    if share_layer_count == 0
        || scaled_a_layer_count == 0
        || partial_decryption_layer_count == 0
        || quotient_layer_count == 0
        || carry_layer_count == 0
    {
        return Err(CommonProofProverError::InvalidColumn);
    }

    let flooding_layers = target_release_nested_layer_byte_length(
        flooding_layer_count,
        ring_degree,
        widths.unsigned_coefficient_byte_length,
        widths,
    )?;
    let share_layers = target_release_nested_layer_byte_length(
        share_layer_count,
        ring_degree,
        widths.unsigned_coefficient_byte_length,
        widths,
    )?;
    let share_transform = target_release_nested_layer_byte_length(
        share_layer_count,
        doubled_ring_degree,
        widths.proof_field_element_byte_length,
        widths,
    )?;
    let scaled_a_layers = target_release_nested_layer_byte_length(
        scaled_a_layer_count,
        ring_degree,
        widths.unsigned_coefficient_byte_length,
        widths,
    )?;
    let partial_decryption_layers = target_release_nested_layer_byte_length(
        partial_decryption_layer_count,
        ring_degree,
        widths.unsigned_coefficient_byte_length,
        widths,
    )?;
    let product_layers = target_release_nested_layer_byte_length(
        product_layer_count,
        ring_degree,
        widths.signed_coefficient_byte_length,
        widths,
    )?;
    let quotient_layers = target_release_nested_layer_byte_length(
        quotient_layer_count,
        ring_degree,
        widths.signed_coefficient_byte_length,
        widths,
    )?;
    let carry_layers = target_release_nested_layer_byte_length(
        carry_layer_count,
        ring_degree,
        widths.signed_coefficient_byte_length,
        widths,
    )?;
    let nested_callback_byte_length = target_release_checked_memory_add(
        flooding_callback_ready_resident_byte_length,
        modulus_callback_transient_byte_length,
    )?;
    let role_base_with_flooding =
        target_release_checked_memory_add(nested_callback_byte_length, flooding_layers)?;
    let callback_construction_byte_length = target_release_checked_memory_add(
        flooding_callback_ready_resident_byte_length,
        flooding_callback_construction_transient_byte_length,
    )?;
    let flooding_layer_construction_byte_length = target_release_checked_memory_add(
        flooding_callback_ready_resident_byte_length,
        flooding_layers,
    )?;
    let share_radix_construction_byte_length =
        target_release_checked_memory_add(role_base_with_flooding, share_layers)?;
    let share_transform_construction_byte_length = [
        role_base_with_flooding,
        share_layers,
        share_transform,
        target_release_checked_memory_multiply(
            ring_degree,
            widths.proof_field_element_byte_length,
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, target_release_checked_memory_add)?;
    let product_base_byte_length = [
        role_base_with_flooding,
        share_transform,
        scaled_a_layers,
        partial_decryption_layers,
    ]
    .into_iter()
    .try_fold(0_u64, target_release_checked_memory_add)?;
    let product_evaluations = target_release_nested_layer_byte_length(
        product_layer_count,
        doubled_ring_degree,
        widths.proof_field_element_byte_length,
        widths,
    )?;
    let one_product_evaluation_scratch = [
        target_release_checked_memory_multiply(
            ring_degree,
            widths.proof_field_element_byte_length,
        )?,
        target_release_checked_memory_multiply(
            doubled_ring_degree,
            widths.proof_field_element_byte_length,
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, target_release_checked_memory_add)?;
    let product_evaluation_byte_length = [
        product_base_byte_length,
        product_evaluations,
        one_product_evaluation_scratch,
    ]
    .into_iter()
    .try_fold(0_u64, target_release_checked_memory_add)?;
    let product_outer_header_byte_length = target_release_checked_memory_multiply(
        target_release_checked_memory_multiply(
            target_release_memory_count(product_layer_count)?,
            2,
        )?,
        widths.vector_header_byte_length,
    )?;
    let mut maximum_product_fold_payload_byte_length = 0_u64;
    for completed_product_count in 0..product_layer_count {
        let remaining_evaluation_count = product_layer_count - completed_product_count;
        let remaining_evaluations = target_release_checked_memory_multiply(
            target_release_memory_count(remaining_evaluation_count)?,
            target_release_checked_memory_multiply(
                doubled_ring_degree,
                widths.proof_field_element_byte_length,
            )?,
        )?;
        let completed_and_current_products = target_release_checked_memory_multiply(
            target_release_memory_count(completed_product_count + 1)?,
            target_release_checked_memory_multiply(
                ring_degree,
                widths.signed_coefficient_byte_length,
            )?,
        )?;
        maximum_product_fold_payload_byte_length =
            maximum_product_fold_payload_byte_length.max(target_release_checked_memory_add(
                remaining_evaluations,
                completed_and_current_products,
            )?);
    }
    let product_folding_byte_length = [
        product_base_byte_length,
        product_outer_header_byte_length,
        maximum_product_fold_payload_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, target_release_checked_memory_add)?;
    let quotient_construction_byte_length = [
        role_base_with_flooding,
        partial_decryption_layers,
        product_layers,
        quotient_layers,
    ]
    .into_iter()
    .try_fold(0_u64, target_release_checked_memory_add)?;
    let equation_layer_count = carry_layer_count
        .checked_add(1)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let small_carry_digit_byte_length = target_release_checked_memory_multiply(
        target_release_memory_count(
            target_release_modulus_digit_count(modulus_layout.modulus)?
                .checked_add(equation_layer_count)
                .ok_or(CommonProofProverError::CountOverflow)?,
        )?,
        widths.unsigned_coefficient_byte_length,
    )?;
    let two_carry_rows = target_release_checked_memory_multiply(
        target_release_checked_memory_multiply(ring_degree, widths.signed_coefficient_byte_length)?,
        2,
    )?;
    let carry_construction_byte_length = [
        role_base_with_flooding,
        partial_decryption_layers,
        product_layers,
        quotient_layers,
        carry_layers,
        two_carry_rows,
        small_carry_digit_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, target_release_checked_memory_add)?;
    let role_cache_byte_length = [flooding_layers, quotient_layers, carry_layers]
        .into_iter()
        .try_fold(0_u64, target_release_checked_memory_add)?;
    let trace_row_byte_length = target_release_checked_memory_multiply(
        trace_domain_size,
        widths.signed_coefficient_byte_length,
    )?;
    let exact_carry_count = role_layout.exact_integer_lift_carry_columns.len();
    let cached_exact_carry_row_byte_length = if exact_carry_count == 0 {
        0
    } else {
        trace_row_byte_length
    };
    let steady_role_envelope_byte_length = target_release_checked_memory_add(
        role_cache_byte_length,
        cached_exact_carry_row_byte_length,
    )?;
    let exact_carry_derivation_byte_length = if exact_carry_count == 0 {
        0
    } else {
        let active_column_byte_length = target_release_checked_memory_multiply(
            target_release_memory_count(
                exact_carry_count
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )?,
            widths.column_ordinal_byte_length,
        )?;
        let outer_recursive_accumulator_byte_length = target_release_checked_memory_multiply(
            target_release_memory_count(exact_carry_count.saturating_sub(1))?,
            trace_row_byte_length,
        )?;
        let direct_derivation_workspace_byte_length =
            target_release_checked_memory_multiply(trace_row_byte_length, 3)?;
        let full_ring_derivation_workspace_byte_length = target_release_checked_memory_add(
            target_release_checked_memory_multiply(
                trace_domain_size,
                target_release_checked_memory_multiply(11, widths.signed_coefficient_byte_length)?,
            )?,
            target_release_checked_memory_multiply(
                trace_domain_size,
                target_release_checked_memory_multiply(8, widths.proof_field_element_byte_length)?,
            )?,
        )?;
        [
            role_cache_byte_length,
            modulus_callback_transient_byte_length,
            active_column_byte_length,
            outer_recursive_accumulator_byte_length,
            direct_derivation_workspace_byte_length.max(full_ring_derivation_workspace_byte_length),
        ]
        .into_iter()
        .try_fold(0_u64, target_release_checked_memory_add)?
    };
    let exact_carry_materialization_byte_length = if exact_carry_count == 0 {
        0
    } else {
        target_release_checked_memory_add(
            steady_role_envelope_byte_length,
            target_release_checked_memory_multiply(
                trace_domain_size,
                target_release_checked_memory_add(
                    widths.unsigned_coefficient_byte_length,
                    widths.proof_field_element_byte_length,
                )?,
            )?,
        )?
    };
    let ordinary_materialization_byte_length = target_release_checked_memory_add(
        role_cache_byte_length,
        target_release_checked_memory_multiply(
            trace_domain_size,
            target_release_checked_memory_add(
                target_release_checked_memory_multiply(3, widths.unsigned_coefficient_byte_length)?,
                widths.proof_field_element_byte_length,
            )?,
        )?,
    )?;

    Ok(TargetReleaseRoleLayerConstructionMemoryAccounting {
        callback_construction_byte_length,
        flooding_layer_construction_byte_length,
        share_radix_construction_byte_length,
        share_transform_construction_byte_length,
        product_evaluation_byte_length,
        product_folding_byte_length,
        quotient_construction_byte_length,
        carry_construction_byte_length,
        role_cache_byte_length,
        steady_role_envelope_byte_length,
        exact_carry_derivation_byte_length,
        exact_carry_materialization_byte_length,
        ordinary_materialization_byte_length,
    })
}

#[allow(clippy::too_many_arguments)]
fn target_release_source_provider_memory_accounting_from_dimensions(
    compilation: &CompiledTargetReleaseRelation,
    provider_fixed_owner_byte_length: u64,
    source_additional_persistent_resident_byte_length: u64,
    flooding_callback_ready_resident_byte_length: u64,
    flooding_callback_construction_transient_byte_length: u64,
    modulus_callback_transient_byte_length: u64,
    source_column_count: usize,
    source_block_count: usize,
    bound_source_count: usize,
) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
    let widths = TargetReleaseMemoryScalarByteLengths::current_target();
    let ring_degree = target_release_memory_count(compilation.ring_degree)?;
    let trace_domain_size = ring_degree
        .checked_div(2)
        .filter(|trace_domain_size| {
            *trace_domain_size > 1 && trace_domain_size.checked_mul(2) == Some(ring_degree)
        })
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let fixed_and_catalog_byte_length = [
        provider_fixed_owner_byte_length,
        source_additional_persistent_resident_byte_length,
        target_release_checked_memory_multiply(
            target_release_memory_count(source_column_count)?,
            core::mem::size_of::<u32>() as u64,
        )?,
        target_release_checked_memory_multiply(
            target_release_memory_count(source_block_count)?,
            core::mem::size_of::<TargetReleaseSourceBlock>() as u64,
        )?,
        target_release_checked_memory_multiply(
            target_release_memory_count(bound_source_count)?,
            core::mem::size_of::<(u16, usize)>() as u64,
        )?,
        compilation
            .retained_owned_payload_byte_length()
            .map_err(CommonProofProverError::Relation)?,
    ]
    .into_iter()
    .try_fold(0_u64, target_release_checked_memory_add)?;
    let mut maximum_steady_role_envelope_byte_length = 0_u64;
    let mut maximum_dynamic_byte_length = 0_u64;
    let mut role_count = 0_usize;
    for modulus_layout in &compilation.moduli {
        for (role_ordinal, role_layout) in modulus_layout.role_equations.iter().enumerate() {
            let accounting = target_release_role_layer_construction_memory_accounting(
                compilation,
                modulus_layout,
                role_layout,
                role_ordinal,
                flooding_callback_ready_resident_byte_length,
                flooding_callback_construction_transient_byte_length,
                modulus_callback_transient_byte_length,
                widths,
            )?;
            maximum_steady_role_envelope_byte_length = maximum_steady_role_envelope_byte_length
                .max(accounting.steady_role_envelope_byte_length);
            maximum_dynamic_byte_length =
                maximum_dynamic_byte_length.max(accounting.maximum_dynamic_byte_length());
            role_count = role_count
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
        }
    }
    if role_count == 0 {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let maximum_loading_dynamic_byte_length =
        maximum_dynamic_byte_length.max(maximum_steady_role_envelope_byte_length);
    let additional_loading_transient_byte_length = maximum_loading_dynamic_byte_length
        .checked_sub(maximum_steady_role_envelope_byte_length)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let loading_persistent_resident_byte_length = target_release_checked_memory_add(
        fixed_and_catalog_byte_length,
        maximum_steady_role_envelope_byte_length,
    )?;
    let maximum_returned_source_polynomial_byte_length = target_release_checked_memory_multiply(
        trace_domain_size,
        widths.proof_field_element_byte_length,
    )?;
    Ok(CommonProofSourceProviderMemoryAccounting::new(
        loading_persistent_resident_byte_length,
        // Replay can reconstruct any source column and may rebuild the full
        // steady role envelope after the initial pass. Charge that live set
        // throughout exact same-secret opening generation.
        loading_persistent_resident_byte_length,
        additional_loading_transient_byte_length,
        maximum_returned_source_polynomial_byte_length,
    ))
}

pub(crate) fn target_release_source_provider_memory_accounting_for_source<Source>(
    compilation: &CompiledTargetReleaseRelation,
    source_additional_persistent_resident_byte_length: u64,
    flooding_callback_ready_resident_byte_length: u64,
    flooding_callback_construction_transient_byte_length: u64,
    modulus_callback_transient_byte_length: u64,
) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError>
where
    Source: TargetReleaseWitnessSource,
{
    let source_blocks = target_release_source_blocks(compilation)
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
    let source_count = source_blocks.len();
    let adapter_fixed_byte_length = u64::try_from(core::mem::size_of::<
        TargetReleaseSourcePolynomialAdapter<Source>,
    >())
    .map_err(|_| CommonProofProverError::CountOverflow)?;
    target_release_source_provider_memory_accounting_from_dimensions(
        compilation,
        adapter_fixed_byte_length,
        source_additional_persistent_resident_byte_length,
        flooding_callback_ready_resident_byte_length,
        flooding_callback_construction_transient_byte_length,
        modulus_callback_transient_byte_length,
        source_count,
        source_count,
        compilation.moduli.len(),
    )
}

impl<Source> CommonProofSourcePolynomialProvider for TargetReleaseSourcePolynomialAdapter<Source>
where
    Source: TargetReleaseWitnessSource,
{
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        let source_memory_accounting = self
            .source
            .memory_accounting()
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        let source_additional_persistent_resident_byte_length = source_memory_accounting
            .additional_persistent_resident_byte_length()
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        target_release_source_provider_memory_accounting_for_source::<Source>(
            &self.compilation,
            source_additional_persistent_resident_byte_length,
            source_memory_accounting.flooding_callback_ready_resident_byte_length(),
            source_memory_accounting.flooding_callback_construction_transient_byte_length(),
            source_memory_accounting.modulus_callback_transient_byte_length(),
        )
    }

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        if self.source_polynomials_finished {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let expected_column_ordinal = self
            .ordered_source_column_ordinals
            .get(self.next_source_column_position)
            .copied()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let expected_descriptor = self
            .compilation
            .relation_plan()
            .select_variant(None, None)
            .map_err(|_| CommonProofProverError::InvalidColumn)?
            .ordered_columns()
            .get(
                usize::try_from(expected_column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if request.protocol_version() != self.protocol_version
            || request.suite_identifier() != self.suite_identifier
            || request.application_statement_schema_identifier()
                != TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
            || request.application_statement_hash() != self.application_statement_hash
            || request.relation_plan_hash() != self.relation_plan_hash
            || request.relation_plan_variant_hash() != self.relation_plan_variant_hash
            || request.schedule_position().is_some()
            || request.top_count().is_some()
            || request.column_ordinal() != expected_column_ordinal
            || request.descriptor() != expected_descriptor
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let block = self
            .ordered_source_blocks
            .get(self.next_source_column_position)
            .copied()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let polynomial = self
            .materialize_requested_column(block, expected_column_ordinal)
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let replay_identity = CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(
            self.source_polynomial_replay_identity(expected_column_ordinal)
                .map_err(|_| CommonProofProverError::InvalidColumn)?,
        )?;
        self.next_source_column_position += 1;
        Ok(CommonProofSourcePolynomialProviderPoll::Ready(
            ProvidedCommonProofSourcePolynomial::new(polynomial, replay_identity),
        ))
    }

    fn poll_replayed_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        if !self.source_polynomials_finished
            || request.request_context() != self.expected_request_context()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let source_position = self
            .ordered_source_column_ordinals
            .binary_search(&request.column_ordinal())
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        if self
            .compilation
            .relation_plan()
            .select_variant(None, None)
            .map_err(|_| CommonProofProverError::InvalidColumn)?
            .ordered_columns()
            .get(
                usize::try_from(request.column_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            != Some(request.descriptor())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let block = self
            .ordered_source_blocks
            .get(source_position)
            .copied()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        self.cached_role_key = None;
        self.cached_role_layers = None;
        self.cached_exact_carry_column_ordinal = None;
        self.cached_exact_carry_rows = None;
        let materialized = self.materialize_requested_column(block, request.column_ordinal());
        self.cached_role_key = None;
        self.cached_role_layers = None;
        self.cached_exact_carry_column_ordinal = None;
        self.cached_exact_carry_rows = None;
        let polynomial = materialized.map_err(|_| CommonProofProverError::InvalidColumn)?;
        let replay_identity = CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(
            self.source_polynomial_replay_identity(request.column_ordinal())
                .map_err(|_| CommonProofProverError::InvalidColumn)?,
        )?;
        Ok(CommonProofSourcePolynomialProviderPoll::Ready(
            ProvidedCommonProofSourcePolynomial::new(polynomial, replay_identity),
        ))
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        if self.source_polynomials_finished
            || self.next_source_column_position != self.ordered_source_column_ordinals.len()
            || self.cached_exact_carry_column_ordinal.is_some()
            || self.cached_exact_carry_rows.is_some()
            || self.cached_role_layers.as_ref().is_some_and(|layers| {
                layers
                    .quotient_layers
                    .iter()
                    .chain(layers.carry_layers.iter())
                    .any(|values| !values.is_empty())
            })
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.cached_role_key = None;
        self.cached_role_layers = None;
        self.source_polynomials_finished = true;
        Ok(())
    }

    fn provide_bound_tree_leaf_salt(
        &mut self,
        request: CommonProofBoundTreeLeafSaltRequest,
    ) -> Result<Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>, CommonProofProverError>
    {
        if !self.source_polynomials_finished || self.leaf_salts_finished {
            return Err(CommonProofProverError::InvalidTree);
        }
        let (expected_catalog_index, modulus_ordinal) = self
            .bound_sources_by_catalog_index
            .get(self.next_leaf_salt_source_ordinal)
            .copied()
            .ok_or(CommonProofProverError::InvalidTree)?;
        let next_leaf_salt_index = self.next_leaf_salt_index;
        let (expected_leaf_count, salt) = self
            .source
            .with_modulus_witness(modulus_ordinal, |witness| {
                let committed_share_source = witness.committed_share_source;
                let expected_leaf_count =
                    committed_share_source.profile().evaluation_domain_size() / 2;
                if request.request_context() != self.expected_request_context()
                    || request.tree_catalog_index() != expected_catalog_index
                    || request.expected_root() != committed_share_source.root()
                    || usize::try_from(request.leaf_index()).ok() != Some(next_leaf_salt_index)
                    || next_leaf_salt_index >= expected_leaf_count
                {
                    return Err(TargetReleaseWitnessError::InvalidWitness);
                }
                let salt = committed_share_source
                    .persistent_leaf_salt(next_leaf_salt_index)
                    .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
                Ok((expected_leaf_count, salt))
            })
            .map_err(|_| CommonProofProverError::InvalidTree)?;
        self.next_leaf_salt_index = self
            .next_leaf_salt_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if self.next_leaf_salt_index == expected_leaf_count {
            self.next_leaf_salt_source_ordinal = self
                .next_leaf_salt_source_ordinal
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
            self.next_leaf_salt_index = 0;
        }
        Ok(Some(salt))
    }

    fn finish_bound_tree_leaf_salts(&mut self) -> Result<(), CommonProofProverError> {
        if self.source_polynomials_finished
            && !self.leaf_salts_finished
            && self.next_leaf_salt_source_ordinal == self.bound_sources_by_catalog_index.len()
            && self.next_leaf_salt_index == 0
        {
            self.leaf_salts_finished = true;
            Ok(())
        } else {
            Err(CommonProofProverError::InvalidTree)
        }
    }

    fn finish_source_replay(&mut self) -> Result<(), CommonProofProverError> {
        if !self.source_polynomials_finished
            || self.cached_role_key.is_some()
            || self.cached_role_layers.is_some()
            || self.cached_exact_carry_column_ordinal.is_some()
            || self.cached_exact_carry_rows.is_some()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(())
    }
}

fn register_source_columns(
    source_blocks_by_column: &mut BTreeMap<u32, TargetReleaseSourceBlock>,
    block: TargetReleaseSourceBlock,
    column_ordinals: impl IntoIterator<Item = u32>,
) -> Result<(), TargetReleaseWitnessError> {
    for column_ordinal in column_ordinals {
        if source_blocks_by_column
            .insert(column_ordinal, block)
            .is_some()
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
    }
    Ok(())
}

fn comparator_source_column_ordinals(
    comparator: &super::key_relation::UpperBoundComparatorWitnessLayout,
) -> Vec<u32> {
    comparator
        .difference_digits
        .iter()
        .flat_map(|difference| {
            std::iter::once(difference.target_column_ordinal)
                .chain(difference.trit_column_ordinals.iter().copied())
        })
        .chain(comparator.borrow_column_ordinals.iter().copied())
        .collect()
}

fn bounded_source_column_ordinals(layout: &TargetBoundedUnsignedVector) -> Vec<u32> {
    layout
        .digit_columns_by_half
        .iter()
        .flatten()
        .copied()
        .chain(layout.trits_by_half.iter().flatten().copied())
        .chain(
            layout
                .upper_bound_comparators
                .iter()
                .flat_map(comparator_source_column_ordinals),
        )
        .collect()
}

fn committed_source_column_ordinals(layout: &TargetCommittedMaterialVector) -> Vec<u32> {
    layout
        .bound_columns
        .iter()
        .copied()
        .chain(layout.trits_by_half.iter().flatten().copied())
        .chain(
            layout
                .upper_bound_comparators
                .iter()
                .flat_map(comparator_source_column_ordinals),
        )
        .collect()
}

fn centered_source_column_ordinals(layout: &TargetCenteredVector) -> Vec<u32> {
    layout
        .value
        .coefficients
        .halves
        .iter()
        .copied()
        .chain(layout.trits_by_half.iter().flatten().copied())
        .collect()
}

fn exact_integer_lift_carry_source_column_ordinals(
    variant: &RelationPlanVariant,
    carry_column_ordinal: u32,
) -> Result<Vec<u32>, TargetReleaseWitnessError> {
    let semantic_cell = variant
        .ordered_semantic_cells
        .iter()
        .find(|semantic_cell| semantic_cell.column_ordinal == carry_column_ordinal)
        .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
    let RelationBoundCertificate::ShiftedRadixRecomposition {
        radix,
        ordered_digit_column_ordinals,
        ..
    } = &semantic_cell.bound_certificate
    else {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    };
    if *radix != 3 || ordered_digit_column_ordinals.is_empty() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    Ok(std::iter::once(carry_column_ordinal)
        .chain(ordered_digit_column_ordinals.iter().copied())
        .collect())
}

fn split_source_column_ordinals(layouts: &[SplitIntegerVector]) -> Vec<u32> {
    layouts
        .iter()
        .flat_map(|layout| layout.halves.iter().copied())
        .collect()
}

fn target_release_source_blocks(
    compilation: &CompiledTargetReleaseRelation,
) -> Result<BTreeMap<u32, TargetReleaseSourceBlock>, TargetReleaseWitnessError> {
    let variant = compilation.relation_plan().select_variant(None, None)?;
    let mut blocks = BTreeMap::new();
    register_source_columns(
        &mut blocks,
        TargetReleaseSourceBlock::ConstantOne,
        std::iter::once(compilation.constant_one_column),
    )?;
    register_source_columns(
        &mut blocks,
        TargetReleaseSourceBlock::ConstantZero,
        std::iter::once(compilation.zero_column),
    )?;
    for (role_ordinal, flooding_layout) in compilation.flooding_by_role.iter().enumerate() {
        register_source_columns(
            &mut blocks,
            TargetReleaseSourceBlock::FloodingBounded { role_ordinal },
            bounded_source_column_ordinals(&flooding_layout.bounded_shift),
        )?;
        register_source_columns(
            &mut blocks,
            TargetReleaseSourceBlock::FloodingGrouped { role_ordinal },
            split_source_column_ordinals(&flooding_layout.grouped_limbs),
        )?;
    }
    for (modulus_ordinal, modulus_layout) in compilation.moduli.iter().enumerate() {
        register_source_columns(
            &mut blocks,
            TargetReleaseSourceBlock::CommittedShare { modulus_ordinal },
            committed_source_column_ordinals(&modulus_layout.material),
        )?;
        let share_layouts = modulus_layout
            .share_limbs
            .iter()
            .map(|limb| limb.source.coefficients)
            .collect::<Vec<_>>();
        register_source_columns(
            &mut blocks,
            TargetReleaseSourceBlock::ShareGrouped { modulus_ordinal },
            split_source_column_ordinals(&share_layouts),
        )?;
        for (role_ordinal, role_layout) in modulus_layout.role_equations.iter().enumerate() {
            register_source_columns(
                &mut blocks,
                TargetReleaseSourceBlock::RoleVerifier {
                    modulus_ordinal,
                    role_ordinal,
                },
                split_source_column_ordinals(&role_layout.scaled_a_digits)
                    .into_iter()
                    .chain(split_source_column_ordinals(
                        &role_layout.partial_decryption_digits,
                    )),
            )?;
            for (digit_ordinal, digit_layout) in role_layout.quotient_digits.iter().enumerate() {
                register_source_columns(
                    &mut blocks,
                    TargetReleaseSourceBlock::RoleQuotient {
                        modulus_ordinal,
                        role_ordinal,
                        digit_ordinal,
                    },
                    centered_source_column_ordinals(digit_layout),
                )?;
            }
            for (digit_ordinal, digit_layout) in role_layout.carry_values.iter().enumerate() {
                register_source_columns(
                    &mut blocks,
                    TargetReleaseSourceBlock::RoleCarry {
                        modulus_ordinal,
                        role_ordinal,
                        digit_ordinal,
                    },
                    centered_source_column_ordinals(digit_layout),
                )?;
            }
            for carry_column_ordinal in role_layout.exact_integer_lift_carry_columns.iter().copied()
            {
                register_source_columns(
                    &mut blocks,
                    TargetReleaseSourceBlock::ExactIntegerLiftCarry {
                        modulus_ordinal,
                        role_ordinal,
                        carry_column_ordinal,
                    },
                    exact_integer_lift_carry_source_column_ordinals(variant, carry_column_ordinal)?,
                )?;
            }
        }
    }
    let requested_source_columns = requested_pre_challenge_source_column_ordinals(variant)
        .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
    if !blocks.keys().copied().eq(requested_source_columns) {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    Ok(blocks)
}

const TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT: usize = 4;

/// Allocation-free signed-magnitude arithmetic for the selected target
/// release role equations. Four little-endian `u64` limbs cover every
/// selected flooding, residual, and quotient intermediate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TargetReleaseFixedSignedInteger {
    negative: bool,
    magnitude_limbs: [u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT],
}

impl TargetReleaseFixedSignedInteger {
    const ZERO: Self = Self {
        negative: false,
        magnitude_limbs: [0_u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT],
    };

    const fn from_u64(value: u64) -> Self {
        let mut magnitude_limbs = [0_u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT];
        magnitude_limbs[0] = value;
        Self {
            negative: false,
            magnitude_limbs,
        }
    }

    const fn from_i128(value: i128) -> Self {
        let magnitude = value.unsigned_abs();
        let mut magnitude_limbs = [0_u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT];
        magnitude_limbs[0] = magnitude as u64;
        magnitude_limbs[1] = (magnitude >> u64::BITS) as u64;
        Self {
            negative: value < 0,
            magnitude_limbs,
        }
    }

    fn from_biguint(value: &BigUint) -> Result<Self, TargetReleaseWitnessError> {
        let mut magnitude_limbs = [0_u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT];
        for (limb_ordinal, limb) in value.iter_u64_digits().enumerate() {
            *magnitude_limbs
                .get_mut(limb_ordinal)
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)? = limb;
        }
        Ok(Self {
            negative: false,
            magnitude_limbs,
        })
    }

    fn from_bigint(value: &BigInt) -> Result<Self, TargetReleaseWitnessError> {
        let mut fixed = Self::from_biguint(value.magnitude())?;
        fixed.negative = value.sign() == Sign::Minus && !fixed.is_zero();
        Ok(fixed)
    }

    fn is_zero(&self) -> bool {
        self.magnitude_limbs.iter().all(|limb| *limb == 0)
    }

    fn magnitude_ordering(&self, other: &Self) -> core::cmp::Ordering {
        self.magnitude_limbs
            .iter()
            .rev()
            .cmp(other.magnitude_limbs.iter().rev())
    }

    fn checked_add_magnitudes(
        left: &[u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT],
        right: &[u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT],
    ) -> Result<[u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT], TargetReleaseWitnessError> {
        let mut result = [0_u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT];
        let mut carry = false;
        for ((destination, left_limb), right_limb) in result.iter_mut().zip(left).zip(right) {
            let (partial, first_carry) = left_limb.overflowing_add(*right_limb);
            let (sum, second_carry) = partial.overflowing_add(u64::from(carry));
            *destination = sum;
            carry = first_carry || second_carry;
        }
        if carry {
            return Err(TargetReleaseWitnessError::IntegerOverflow);
        }
        Ok(result)
    }

    fn checked_subtract_magnitudes(
        larger: &[u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT],
        smaller: &[u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT],
    ) -> Result<[u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT], TargetReleaseWitnessError> {
        let mut result = [0_u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT];
        let mut borrow = false;
        for ((destination, larger_limb), smaller_limb) in result.iter_mut().zip(larger).zip(smaller)
        {
            let (partial, first_borrow) = larger_limb.overflowing_sub(*smaller_limb);
            let (difference, second_borrow) = partial.overflowing_sub(u64::from(borrow));
            *destination = difference;
            borrow = first_borrow || second_borrow;
        }
        if borrow {
            return Err(TargetReleaseWitnessError::IntegerOverflow);
        }
        Ok(result)
    }

    fn checked_add(self, other: Self) -> Result<Self, TargetReleaseWitnessError> {
        if self.negative == other.negative {
            let mut result = Self {
                negative: self.negative,
                magnitude_limbs: Self::checked_add_magnitudes(
                    &self.magnitude_limbs,
                    &other.magnitude_limbs,
                )?,
            };
            if result.is_zero() {
                result.negative = false;
            }
            return Ok(result);
        }
        let (negative, magnitude_limbs) = match self.magnitude_ordering(&other) {
            core::cmp::Ordering::Greater => (
                self.negative,
                Self::checked_subtract_magnitudes(&self.magnitude_limbs, &other.magnitude_limbs)?,
            ),
            core::cmp::Ordering::Less => (
                other.negative,
                Self::checked_subtract_magnitudes(&other.magnitude_limbs, &self.magnitude_limbs)?,
            ),
            core::cmp::Ordering::Equal => return Ok(Self::ZERO),
        };
        Ok(Self {
            negative,
            magnitude_limbs,
        })
    }

    fn negated(mut self) -> Self {
        if !self.is_zero() {
            self.negative = !self.negative;
        }
        self
    }

    fn checked_subtract(self, other: Self) -> Result<Self, TargetReleaseWitnessError> {
        self.checked_add(other.negated())
    }

    fn checked_multiply_unsigned(self, scalar: u64) -> Result<Self, TargetReleaseWitnessError> {
        if scalar == 0 || self.is_zero() {
            return Ok(Self::ZERO);
        }
        let mut magnitude_limbs = [0_u64; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT];
        let mut carry = 0_u128;
        for (destination, limb) in magnitude_limbs.iter_mut().zip(self.magnitude_limbs) {
            let product = u128::from(limb)
                .checked_mul(u128::from(scalar))
                .and_then(|value| value.checked_add(carry))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            *destination = product as u64;
            carry = product >> u64::BITS;
        }
        if carry != 0 {
            return Err(TargetReleaseWitnessError::IntegerOverflow);
        }
        Ok(Self {
            negative: self.negative,
            magnitude_limbs,
        })
    }

    fn checked_increment_magnitude(&mut self) -> Result<(), TargetReleaseWitnessError> {
        for limb in &mut self.magnitude_limbs {
            let (incremented, carry) = limb.overflowing_add(1);
            *limb = incremented;
            if !carry {
                return Ok(());
            }
        }
        Err(TargetReleaseWitnessError::IntegerOverflow)
    }

    fn divide_magnitude_by_unsigned(
        &mut self,
        divisor: u64,
    ) -> Result<u64, TargetReleaseWitnessError> {
        if divisor == 0 {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let divisor = u128::from(divisor);
        let mut remainder = 0_u128;
        for limb in self.magnitude_limbs.iter_mut().rev() {
            let numerator = (remainder << u64::BITS) | u128::from(*limb);
            *limb = u64::try_from(numerator / divisor)
                .map_err(|_| TargetReleaseWitnessError::IntegerOverflow)?;
            remainder = numerator % divisor;
        }
        if self.is_zero() {
            self.negative = false;
        }
        u64::try_from(remainder).map_err(|_| TargetReleaseWitnessError::IntegerOverflow)
    }

    fn checked_divide_unsigned(
        mut self,
        divisor: u64,
    ) -> Result<(Self, u64), TargetReleaseWitnessError> {
        let remainder = self.divide_magnitude_by_unsigned(divisor)?;
        Ok((self, remainder))
    }

    fn take_balanced_radix_digit(&mut self, radix: u64) -> Result<i128, TargetReleaseWitnessError> {
        if radix < 3 || radix.is_multiple_of(2) {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let was_negative = self.negative;
        let remainder = self.divide_magnitude_by_unsigned(radix)?;
        let half_radix = radix / 2;
        if !was_negative {
            if remainder > half_radix {
                self.checked_increment_magnitude()?;
                return Ok(i128::from(remainder) - i128::from(radix));
            }
            return Ok(i128::from(remainder));
        }
        if remainder == 0 {
            self.negative = !self.is_zero();
            return Ok(0);
        }
        if remainder <= half_radix {
            self.negative = !self.is_zero();
            return Ok(-i128::from(remainder));
        }
        self.checked_increment_magnitude()?;
        self.negative = true;
        Ok(i128::from(radix - remainder))
    }
}

fn fixed_width_unsigned_radix_digits(
    mut value: TargetReleaseFixedSignedInteger,
    count: usize,
    radix: u64,
) -> Result<Vec<u64>, TargetReleaseWitnessError> {
    if value.negative || count == 0 || radix < 2 {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let mut digits = Vec::with_capacity(count);
    for _ in 0..count {
        digits.push(value.divide_magnitude_by_unsigned(radix)?);
    }
    if !value.is_zero() {
        return Err(TargetReleaseWitnessError::IntegerOverflow);
    }
    Ok(digits)
}

fn minimum_u64_radix_digit_count(
    mut maximum: u64,
    radix: u64,
) -> Result<usize, TargetReleaseWitnessError> {
    if radix < 2 {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let mut count = 1_usize;
    while maximum >= radix {
        maximum /= radix;
        count = count
            .checked_add(1)
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    }
    Ok(count)
}

fn shifted_flooding_radix_layers(
    flooding_errors: &[BigInt],
    ring_degree: usize,
    flooding_bound: &BigUint,
    radix: u64,
    layer_count: usize,
) -> Result<Vec<Vec<u64>>, TargetReleaseWitnessError> {
    if flooding_errors.len() != ring_degree
        || flooding_bound.is_zero()
        || radix < 2
        || layer_count == 0
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let fixed_flooding_bound = TargetReleaseFixedSignedInteger::from_biguint(flooding_bound)?;
    let mut layers = vec![vec![0_u64; ring_degree]; layer_count];
    for (coefficient_ordinal, flooding_error) in flooding_errors.iter().enumerate() {
        if flooding_error.magnitude() > flooding_bound {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let mut shifted = fixed_flooding_bound.checked_add(
            TargetReleaseFixedSignedInteger::from_bigint(flooding_error)?,
        )?;
        if shifted.negative {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        for layer in &mut layers {
            layer[coefficient_ordinal] = shifted.divide_magnitude_by_unsigned(radix)?;
        }
        if !shifted.is_zero() {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
    }
    Ok(layers)
}

fn shifted_flooding_values(
    flooding_errors: &[BigInt],
    ring_degree: usize,
    flooding_bound: &BigUint,
) -> Result<Vec<BigUint>, TargetReleaseWitnessError> {
    if flooding_errors.len() != ring_degree
        || flooding_errors
            .iter()
            .any(|error| error.magnitude() > flooding_bound)
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    flooding_errors
        .iter()
        .map(|error| {
            (error + BigInt::from(flooding_bound.clone()))
                .to_biguint()
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TargetReleaseRelationPlanInput {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) material_column_degree_bound_exclusive: u64,
    pub(crate) public_polynomial_column_degree_bound_exclusive: u64,
    pub(crate) target_modulus_indices: Vec<u16>,
    pub(crate) decryption_scale: u64,
    pub(crate) simulation_scale: u64,
    pub(crate) flooding_bound: BigUint,
}

fn minimum_radix_digit_count(maximum: &BigUint) -> Result<usize, RelationPlanError> {
    let mut remaining = maximum.clone();
    let radix = BigUint::from(RADIX);
    let mut count = 1_usize;
    while remaining >= radix {
        remaining /= &radix;
        count = count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    Ok(count)
}

fn minimum_balanced_radix_digit_count(
    maximum_magnitude: &BigUint,
) -> Result<usize, RelationPlanError> {
    let required_capacity = maximum_magnitude * 2_u8 + BigUint::one();
    let radix = BigUint::from(RADIX);
    let mut radix_power = radix.clone();
    let mut count = 1_usize;
    while radix_power < required_capacity {
        radix_power *= &radix;
        count = count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    Ok(count)
}

fn fixed_radix_digits(
    value: &BigUint,
    count: usize,
    radix: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    if count == 0 || radix < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut value = value.clone();
    let radix = BigUint::from(radix);
    let mut digits = Vec::with_capacity(count);
    for _ in 0..count {
        digits.push(
            u64::try_from(&value % &radix).map_err(|_| RelationPlanError::IntegerBoundOverflow)?,
        );
        value /= &radix;
    }
    if !value.is_zero() {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    Ok(digits)
}

fn centered_linear_term(
    value: &ShiftedSmallVector,
    half_ordinal: usize,
    coefficient: u64,
    negative: bool,
) -> RelationIntegerLiftLinearTermDescriptor {
    RelationIntegerLiftLinearTermDescriptor {
        negative,
        column_ordinal: value.coefficients.halves[half_ordinal],
        column_offset: value.offset,
        coefficient: RelationIntegerLiftCoefficient::Constant(coefficient),
    }
}

fn validate_input(
    input: &TargetReleaseRelationPlanInput,
    context: &RelationPlanCheckContext,
) -> Result<Vec<(SuiteModulusReference, u64)>, RelationPlanError> {
    let expected_indices = (0..input.target_modulus_indices.len())
        .map(|index| u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow))
        .collect::<Result<Vec<_>, _>>()?;
    if input.target_modulus_indices != expected_indices
        || input.decryption_scale == 0
        || input.simulation_scale == 0
        || input.flooding_bound.is_zero()
    {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let resolved_moduli = input
        .target_modulus_indices
        .iter()
        .copied()
        .map(|index| {
            let modulus_reference = SuiteModulusReference::target(index);
            let modulus = context.resolved_modulus(modulus_reference)?;
            if modulus <= input.ring_degree
                || u128::from(modulus - 1)
                    .checked_mul(u128::from(input.decryption_scale))
                    .is_none()
            {
                return Err(RelationPlanError::InvalidModulus);
            }
            Ok((modulus_reference, modulus))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let target_modulus = resolved_moduli
        .iter()
        .map(|(_, modulus)| BigUint::from(*modulus))
        .product::<BigUint>();
    if input.flooding_bound >= target_modulus {
        return Err(RelationPlanError::InvalidModulus);
    }
    Ok(resolved_moduli)
}

fn target_sources(
    input: &TargetReleaseRelationPlanInput,
    moduli: &[(SuiteModulusReference, u64)],
) -> Result<Vec<(KeyVerifierSourceKey, RelationVerifierSource)>, RelationPlanError> {
    let mut sources = Vec::new();
    for (logical_root_ordinal, (modulus_reference, modulus)) in moduli.iter().copied().enumerate() {
        sources.push(statement_root_source(
            MATERIAL_ROOTS_FIELD_ORDINAL,
            Some(
                u64::try_from(logical_root_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            ),
        ));
        let target_modulus_index = modulus_reference.modulus_index;
        let scaled_a_maximum = BigUint::from(modulus - 1) * input.decryption_scale;
        let scaled_a_digit_count = u16::try_from(minimum_radix_digit_count(&scaled_a_maximum)?)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let partial_decryption_digit_count =
            u16::try_from(minimum_radix_digit_count(&BigUint::from(modulus - 1))?)
                .map_err(|_| RelationPlanError::CountOverflow)?;
        for target_role in 0..TARGET_ROLE_COUNT {
            for digit_ordinal in 0..scaled_a_digit_count {
                sources.push(target_converted_radix_digit_source(
                    input.ring_degree,
                    target_role,
                    1,
                    target_modulus_index,
                    input.decryption_scale,
                    RADIX,
                    digit_ordinal,
                    scaled_a_digit_count,
                ));
            }
            for digit_ordinal in 0..partial_decryption_digit_count {
                sources.push(target_partial_decryption_radix_digit_source(
                    input.ring_degree,
                    target_role,
                    target_modulus_index,
                    RADIX,
                    digit_ordinal,
                    partial_decryption_digit_count,
                ));
            }
        }
    }
    Ok(sources)
}

fn verifier_digit_vectors(
    builder: &mut KeyRelationPlanBuilder<'_>,
    input: &TargetReleaseRelationPlanInput,
    modulus_reference: SuiteModulusReference,
    modulus: u64,
    target_role: u16,
) -> Result<(Vec<SplitIntegerVector>, Vec<SplitIntegerVector>), RelationPlanError> {
    let scaled_a_maximum = BigUint::from(modulus - 1) * input.decryption_scale;
    let scaled_a_digit_count = u16::try_from(minimum_radix_digit_count(&scaled_a_maximum)?)
        .map_err(|_| RelationPlanError::CountOverflow)?;
    let partial_decryption_digit_count =
        u16::try_from(minimum_radix_digit_count(&BigUint::from(modulus - 1))?)
            .map_err(|_| RelationPlanError::CountOverflow)?;
    let mut scaled_a_digits = Vec::with_capacity(usize::from(scaled_a_digit_count));
    for digit_ordinal in 0..scaled_a_digit_count {
        scaled_a_digits.push(builder.add_split_verifier_base_vector(
            &KeyVerifierSourceKey::TargetConvertedRadixDigit {
                target_role,
                component_ordinal: 1,
                target_modulus_index: modulus_reference.modulus_index,
                scale: input.decryption_scale,
                radix: RADIX,
                digit_ordinal,
                digit_count: scaled_a_digit_count,
            },
        )?);
    }
    let mut partial_decryption_digits =
        Vec::with_capacity(usize::from(partial_decryption_digit_count));
    for digit_ordinal in 0..partial_decryption_digit_count {
        partial_decryption_digits.push(builder.add_split_verifier_base_vector(
            &KeyVerifierSourceKey::TargetPartialDecryptionRadixDigit {
                target_role,
                target_modulus_index: modulus_reference.modulus_index,
                radix: RADIX,
                digit_ordinal,
                digit_count: partial_decryption_digit_count,
            },
        )?);
    }
    Ok((scaled_a_digits, partial_decryption_digits))
}

#[allow(clippy::too_many_arguments)]
fn add_role_equations(
    builder: &mut KeyRelationPlanBuilder<'_>,
    context: &RelationPlanCheckContext,
    input: &TargetReleaseRelationPlanInput,
    modulus_reference: SuiteModulusReference,
    modulus: u64,
    share_limbs: &[super::key_relation::ReversibleShiftedSmallVector],
    flooding_shift_limbs: &[SplitIntegerVector],
    scaled_a_digits: &[SplitIntegerVector],
    partial_decryption_digits: &[SplitIntegerVector],
    constant_one_column: u32,
    zero_column: u32,
) -> Result<TargetReleaseRoleEquationWitnessLayout, RelationPlanError> {
    let product_layer_count = scaled_a_digits
        .len()
        .checked_add(share_limbs.len())
        .and_then(|count| count.checked_sub(1))
        .ok_or(RelationPlanError::CountOverflow)?;
    let modulus = BigUint::from(modulus);
    let modulus_digits = fixed_radix_digits(&modulus, minimum_radix_digit_count(&modulus)?, RADIX)?;
    let maximum_quotient =
        BigUint::from(input.decryption_scale) * input.ring_degree * (&modulus - BigUint::one())
            + BigUint::from(input.simulation_scale) * &input.flooding_bound
            + BigUint::from(2_u8);
    let quotient_digit_count = minimum_balanced_radix_digit_count(&maximum_quotient)?;
    let quotient_product_layer_count = modulus_digits
        .len()
        .checked_add(quotient_digit_count)
        .and_then(|count| count.checked_sub(1))
        .ok_or(RelationPlanError::CountOverflow)?;
    let equation_layer_count = product_layer_count
        .max(flooding_shift_limbs.len())
        .max(partial_decryption_digits.len())
        .max(quotient_product_layer_count);
    let quotient_digit_offset = (3_u64.pow(
        u32::try_from(QUOTIENT_DIGIT_TRIT_COUNT).map_err(|_| RelationPlanError::CountOverflow)?,
    ) - 1)
        / 2;
    let quotient_capacity =
        (0..quotient_digit_count).try_fold(BigUint::zero(), |capacity, digit_ordinal| {
            let exponent =
                u32::try_from(digit_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            Ok::<_, RelationPlanError>(
                capacity
                    + BigUint::from(quotient_digit_offset) * BigUint::from(RADIX).pow(exponent),
            )
        })?;
    if quotient_capacity < maximum_quotient {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }

    let quotient_digits = (0..quotient_digit_count)
        .map(|_| builder.add_centered_split_vector(QUOTIENT_DIGIT_TRIT_COUNT))
        .collect::<Result<Vec<_>, _>>()?;
    let carry_values = (0..equation_layer_count.saturating_sub(1))
        .map(|_| builder.add_centered_split_vector(CARRY_TRIT_COUNT))
        .collect::<Result<Vec<_>, _>>()?;
    let flooding_constant = &input.flooding_bound * input.simulation_scale;
    let flooding_constant_digits =
        fixed_radix_digits(&flooding_constant, equation_layer_count, RADIX)?;
    let mut exact_integer_lift_carry_columns = Vec::new();

    for challenge_ordinal in 0..context.non_native_theta_repetition_count {
        let batch_key = (modulus_reference, challenge_ordinal);
        for layer_ordinal in 0..equation_layer_count {
            let product_pairs = (0..scaled_a_digits.len())
                .filter_map(|left_digit| {
                    layer_ordinal
                        .checked_sub(left_digit)
                        .filter(|right_digit| *right_digit < share_limbs.len())
                        .map(|right_digit| (left_digit, right_digit))
                })
                .collect::<Vec<_>>();
            for half_ordinal in 0..2 {
                let mut linear_terms = Vec::new();
                if let Some(partial_decryption_digit) = partial_decryption_digits.get(layer_ordinal)
                {
                    linear_terms.push(constant_linear_term(
                        partial_decryption_digit.halves[half_ordinal],
                        0,
                        false,
                    ));
                }
                if let Some(flooding_shift_digit) = flooding_shift_limbs.get(layer_ordinal) {
                    linear_terms.push(scaled_constant_linear_term(
                        flooding_shift_digit.halves[half_ordinal],
                        true,
                        input.simulation_scale,
                    ));
                }
                if flooding_constant_digits[layer_ordinal] != 0 {
                    linear_terms.push(scaled_constant_linear_term(
                        constant_one_column,
                        false,
                        flooding_constant_digits[layer_ordinal],
                    ));
                }
                for (modulus_digit_ordinal, modulus_digit) in
                    modulus_digits.iter().copied().enumerate()
                {
                    let Some(quotient_digit_ordinal) =
                        layer_ordinal.checked_sub(modulus_digit_ordinal)
                    else {
                        continue;
                    };
                    if let Some(quotient_digit) = quotient_digits.get(quotient_digit_ordinal) {
                        linear_terms.push(centered_linear_term(
                            &quotient_digit.value,
                            half_ordinal,
                            modulus_digit,
                            true,
                        ));
                    }
                }
                if layer_ordinal > 0 {
                    linear_terms.push(centered_linear_term(
                        &carry_values[layer_ordinal - 1].value,
                        half_ordinal,
                        1,
                        false,
                    ));
                }
                if let Some(next_carry) = carry_values.get(layer_ordinal) {
                    linear_terms.push(centered_linear_term(
                        &next_carry.value,
                        half_ordinal,
                        RADIX,
                        true,
                    ));
                }

                let products = product_pairs
                    .iter()
                    .copied()
                    .map(|(left_digit, right_digit)| {
                        builder.full_ring_product(
                            batch_key,
                            integer_lift_half(half_ordinal)?,
                            true,
                            scaled_a_digits[left_digit],
                            &share_limbs[right_digit],
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                for carry_column in builder.add_integer_lift_component(
                    batch_key,
                    zero_column,
                    linear_terms,
                    products,
                )? {
                    if !exact_integer_lift_carry_columns.contains(&carry_column) {
                        exact_integer_lift_carry_columns.push(carry_column);
                    }
                }
            }
        }
    }
    Ok(TargetReleaseRoleEquationWitnessLayout {
        scaled_a_digits: scaled_a_digits.to_vec(),
        partial_decryption_digits: partial_decryption_digits.to_vec(),
        quotient_digits,
        carry_values,
        exact_integer_lift_carry_columns,
    })
}

pub(crate) fn compile_target_release_relation(
    input: &TargetReleaseRelationPlanInput,
    context: &RelationPlanCheckContext,
) -> Result<CompiledTargetReleaseRelation, RelationPlanError> {
    let moduli = validate_input(input, context)?;
    let sources = target_sources(input, &moduli)?;
    let geometry = KeyRelationGeometry::for_target_release(
        input.ring_degree,
        input.evaluation_domain_size,
        input.opening_degree_bound_exclusive,
        input.material_column_degree_bound_exclusive,
        input.public_polynomial_column_degree_bound_exclusive,
        input.target_modulus_indices.clone(),
    );
    let mut builder = KeyRelationPlanBuilder::new(
        TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        &geometry,
        context,
        sources,
    )?;
    let constant_one_column = builder.add_one_column()?;
    let zero_column = builder.add_zero_column()?;

    let flooding_shift_maximum = &input.flooding_bound * 2_u8;
    let mut flooding_by_role = Vec::with_capacity(usize::from(TARGET_ROLE_COUNT));
    for _ in 0..TARGET_ROLE_COUNT {
        let bounded_shift = builder.add_bounded_unsigned_vector_trits(&flooding_shift_maximum)?;
        let grouped_limbs = builder
            .add_grouped_trit_split_limbs(&bounded_shift.trits_by_half, RADIX_TRITS_PER_LIMB)?;
        flooding_by_role.push(TargetReleaseFloodingWitnessLayout {
            bounded_shift,
            grouped_limbs,
        });
    }

    let mut modulus_layouts = Vec::with_capacity(moduli.len());
    for (logical_root_ordinal, (modulus_reference, modulus)) in moduli.iter().copied().enumerate() {
        let material = builder.add_target_committed_material_root(
            &KeyVerifierSourceKey::StatementRoot {
                field_ordinal: MATERIAL_ROOTS_FIELD_ORDINAL,
                list_ordinal: Some(
                    u64::try_from(logical_root_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                ),
            },
            modulus_reference,
        )?;
        let share_limbs =
            builder.add_grouped_trit_limbs(&material.trits_by_half, RADIX_TRITS_PER_LIMB)?;
        let mut role_equations = Vec::with_capacity(usize::from(TARGET_ROLE_COUNT));
        for target_role in 0..TARGET_ROLE_COUNT {
            let (scaled_a_digits, partial_decryption_digits) = verifier_digit_vectors(
                &mut builder,
                input,
                modulus_reference,
                modulus,
                target_role,
            )?;
            role_equations.push(add_role_equations(
                &mut builder,
                context,
                input,
                modulus_reference,
                modulus,
                &share_limbs,
                &flooding_by_role[usize::from(target_role)].grouped_limbs,
                &scaled_a_digits,
                &partial_decryption_digits,
                constant_one_column,
                zero_column,
            )?);
        }
        modulus_layouts.push(TargetReleaseModulusWitnessLayout {
            modulus_reference,
            modulus,
            material,
            share_limbs,
            role_equations,
        });
    }
    Ok(CompiledTargetReleaseRelation {
        relation_plan: builder.finish()?,
        ring_degree: usize::try_from(input.ring_degree)
            .map_err(|_| RelationPlanError::CountOverflow)?,
        decryption_scale: input.decryption_scale,
        simulation_scale: input.simulation_scale,
        flooding_bound: input.flooding_bound.clone(),
        constant_one_column,
        zero_column,
        flooding_by_role,
        moduli: modulus_layouts,
    })
}

trait TargetReleaseSourcePolynomialSink {
    fn wants_column(&self, column_ordinal: u32) -> bool;

    fn insert_polynomial(
        &mut self,
        column_ordinal: u32,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), TargetReleaseWitnessError>;
}

impl TargetReleaseSourcePolynomialSink for BTreeMap<u32, CommonProofSourcePolynomial> {
    fn wants_column(&self, _column_ordinal: u32) -> bool {
        true
    }

    fn insert_polynomial(
        &mut self,
        column_ordinal: u32,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), TargetReleaseWitnessError> {
        if self.insert(column_ordinal, polynomial).is_some() {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        Ok(())
    }
}

struct RequestedTargetReleaseSourcePolynomial {
    requested_column_ordinal: u32,
    polynomial: Option<CommonProofSourcePolynomial>,
}

impl RequestedTargetReleaseSourcePolynomial {
    const fn new(requested_column_ordinal: u32) -> Self {
        Self {
            requested_column_ordinal,
            polynomial: None,
        }
    }

    fn finish(self) -> Result<CommonProofSourcePolynomial, TargetReleaseWitnessError> {
        self.polynomial
            .ok_or(TargetReleaseWitnessError::InvalidWitness)
    }
}

impl TargetReleaseSourcePolynomialSink for RequestedTargetReleaseSourcePolynomial {
    fn wants_column(&self, column_ordinal: u32) -> bool {
        column_ordinal == self.requested_column_ordinal
    }

    fn insert_polynomial(
        &mut self,
        column_ordinal: u32,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), TargetReleaseWitnessError> {
        if column_ordinal != self.requested_column_ordinal || self.polynomial.is_some() {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        self.polynomial = Some(polynomial);
        Ok(())
    }
}

fn insert_source_polynomial(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    column_ordinal: u32,
    polynomial: CommonProofSourcePolynomial,
) -> Result<(), TargetReleaseWitnessError> {
    columns.insert_polynomial(column_ordinal, polynomial)
}

fn signed_base_field_element(
    value: i128,
) -> Result<ProofBaseFieldElement, TargetReleaseWitnessError> {
    let canonical = if value >= 0 {
        u64::try_from(value).map_err(|_| TargetReleaseWitnessError::IntegerOverflow)?
    } else {
        let magnitude = u64::try_from(
            value
                .checked_abs()
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?,
        )
        .map_err(|_| TargetReleaseWitnessError::IntegerOverflow)?;
        if magnitude >= PROOF_BASE_FIELD_MODULUS {
            return Err(TargetReleaseWitnessError::IntegerOverflow);
        }
        PROOF_BASE_FIELD_MODULUS - magnitude
    };
    Ok(ProofBaseFieldElement::from_canonical(canonical)?)
}

fn interpolate_unsigned_rows(
    trace_domain: ProofEvaluationDomain,
    rows: &[u64],
) -> Result<CommonProofSourcePolynomial, TargetReleaseWitnessError> {
    let rows = rows
        .iter()
        .copied()
        .map(ProofBaseFieldElement::from_canonical)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CommonProofSourcePolynomial::from_base_coefficients(
        trace_domain.interpolate_base_polynomial(&rows)?,
    ))
}

fn interpolate_signed_rows(
    trace_domain: ProofEvaluationDomain,
    rows: &[i128],
) -> Result<CommonProofSourcePolynomial, TargetReleaseWitnessError> {
    let rows = rows
        .iter()
        .copied()
        .map(signed_base_field_element)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CommonProofSourcePolynomial::from_base_coefficients(
        trace_domain.interpolate_base_polynomial(&rows)?,
    ))
}

fn insert_unsigned_half_column(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    column_ordinal: u32,
    rows: &[u64],
) -> Result<(), TargetReleaseWitnessError> {
    if rows.len() != trace_domain.size() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    if !columns.wants_column(column_ordinal) {
        return Ok(());
    }
    insert_source_polynomial(
        columns,
        column_ordinal,
        interpolate_unsigned_rows(trace_domain, rows)?,
    )
}

fn insert_signed_half_column(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    column_ordinal: u32,
    rows: &[i128],
) -> Result<(), TargetReleaseWitnessError> {
    if rows.len() != trace_domain.size() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    if !columns.wants_column(column_ordinal) {
        return Ok(());
    }
    insert_source_polynomial(
        columns,
        column_ordinal,
        interpolate_signed_rows(trace_domain, rows)?,
    )
}

fn insert_unsigned_ring_vector(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    layout: SplitIntegerVector,
    values: &[u64],
) -> Result<(), TargetReleaseWitnessError> {
    if values.len()
        != trace_domain
            .size()
            .checked_mul(2)
            .ok_or(TargetReleaseWitnessError::CountOverflow)?
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    for (half_ordinal, column_ordinal) in layout.halves.iter().copied().enumerate() {
        let start = half_ordinal
            .checked_mul(trace_domain.size())
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        insert_unsigned_half_column(
            columns,
            trace_domain,
            column_ordinal,
            &values[start..start + trace_domain.size()],
        )?;
    }
    Ok(())
}

fn insert_signed_ring_vector(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    layout: SplitIntegerVector,
    values: &[i128],
) -> Result<(), TargetReleaseWitnessError> {
    if values.len()
        != trace_domain
            .size()
            .checked_mul(2)
            .ok_or(TargetReleaseWitnessError::CountOverflow)?
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    for (half_ordinal, column_ordinal) in layout.halves.iter().copied().enumerate() {
        let start = half_ordinal
            .checked_mul(trace_domain.size())
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        insert_signed_half_column(
            columns,
            trace_domain,
            column_ordinal,
            &values[start..start + trace_domain.size()],
        )?;
    }
    Ok(())
}

fn unsigned_radix_layers(
    values: &[u64],
    radix: u64,
    layer_count: usize,
) -> Result<Vec<Vec<u64>>, TargetReleaseWitnessError> {
    if radix < 2 || layer_count == 0 {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let mut layers = vec![vec![0_u64; values.len()]; layer_count];
    for (coefficient_ordinal, value) in values.iter().copied().enumerate() {
        let mut remaining = value;
        for layer in &mut layers {
            layer[coefficient_ordinal] = remaining % radix;
            remaining /= radix;
        }
        if remaining != 0 {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
    }
    Ok(layers)
}

fn big_unsigned_radix_layers(
    values: &[BigUint],
    radix: u64,
    layer_count: usize,
) -> Result<Vec<Vec<u64>>, TargetReleaseWitnessError> {
    if radix < 2 || layer_count == 0 {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let radix = BigUint::from(radix);
    let mut remaining = values.to_vec();
    let mut layers = vec![vec![0_u64; values.len()]; layer_count];
    for layer in &mut layers {
        for (digit, value) in layer.iter_mut().zip(&mut remaining) {
            *digit = u64::try_from(&*value % &radix)
                .map_err(|_| TargetReleaseWitnessError::IntegerOverflow)?;
            *value /= &radix;
        }
    }
    if remaining.iter().any(|value| !value.is_zero()) {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    Ok(layers)
}

fn scaled_residue_radix_layers(
    values: &[u64],
    modulus: u64,
    scale: u64,
    radix: u64,
    layer_count: usize,
) -> Result<Vec<Vec<u64>>, TargetReleaseWitnessError> {
    let digit_count =
        u16::try_from(layer_count).map_err(|_| TargetReleaseWitnessError::CountOverflow)?;
    (0..digit_count)
        .map(|digit_ordinal| {
            radix_decompose_scaled_residues(
                values,
                modulus,
                scale,
                radix,
                digit_ordinal,
                digit_count,
            )
            .map_err(TargetReleaseWitnessError::from)
        })
        .collect()
}

fn insert_split_radix_layers(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    layouts: &[SplitIntegerVector],
    layers: &[Vec<u64>],
) -> Result<(), TargetReleaseWitnessError> {
    if layouts.len() != layers.len() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    for (layout, values) in layouts.iter().copied().zip(layers) {
        insert_unsigned_ring_vector(columns, trace_domain, layout, values)?;
    }
    Ok(())
}

fn insert_half_trit_columns(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    column_ordinals: &[u32],
    values: &[u64],
) -> Result<(), TargetReleaseWitnessError> {
    if values.len() != trace_domain.size() || column_ordinals.is_empty() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let mut remaining = values.to_vec();
    for column_ordinal in column_ordinals {
        let mut rows = Vec::with_capacity(values.len());
        for value in &mut remaining {
            rows.push(*value % 3);
            *value /= 3;
        }
        insert_unsigned_half_column(columns, trace_domain, *column_ordinal, &rows)?;
    }
    if remaining.iter().any(|value| *value != 0) {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    Ok(())
}

fn insert_big_unsigned_half_trit_columns(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    column_ordinals: &[u32],
    values: &[BigUint],
) -> Result<(), TargetReleaseWitnessError> {
    if values.len() != trace_domain.size() || column_ordinals.is_empty() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let trit_radix = BigUint::from(3_u8);
    let mut remaining = values.to_vec();
    for column_ordinal in column_ordinals {
        let wants_column = columns.wants_column(*column_ordinal);
        let mut rows = wants_column.then(|| Vec::with_capacity(values.len()));
        for value in &mut remaining {
            if let Some(rows) = rows.as_mut() {
                rows.push(
                    u64::try_from(&*value % &trit_radix)
                        .map_err(|_| TargetReleaseWitnessError::IntegerOverflow)?,
                );
            }
            *value /= &trit_radix;
        }
        if let Some(rows) = rows {
            insert_unsigned_half_column(columns, trace_domain, *column_ordinal, &rows)?;
        }
    }
    if remaining.iter().any(|value| !value.is_zero()) {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    Ok(())
}

fn insert_upper_bound_comparator(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    layout: &super::key_relation::UpperBoundComparatorWitnessLayout,
    value_digit_layers: &[Vec<u64>],
    maximum_digits: &[u64],
    half_ordinal: usize,
) -> Result<(), TargetReleaseWitnessError> {
    if layout.difference_digits.len() != value_digit_layers.len()
        || value_digit_layers.len() != maximum_digits.len()
        || layout.borrow_column_ordinals.len() + 1 != value_digit_layers.len()
        || half_ordinal >= 2
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let half_start = half_ordinal
        .checked_mul(trace_domain.size())
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    let half_end = half_start
        .checked_add(trace_domain.size())
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    if value_digit_layers
        .iter()
        .any(|layer| layer.len() != trace_domain.size() * 2)
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let mut previous_borrow = vec![0_u64; trace_domain.size()];
    for digit_ordinal in 0..value_digit_layers.len() {
        let value_rows = &value_digit_layers[digit_ordinal][half_start..half_end];
        let mut difference_rows = Vec::with_capacity(trace_domain.size());
        let mut next_borrow = vec![0_u64; trace_domain.size()];
        for row_ordinal in 0..trace_domain.size() {
            let raw_difference = i128::from(maximum_digits[digit_ordinal])
                - i128::from(value_rows[row_ordinal])
                - i128::from(previous_borrow[row_ordinal]);
            let borrow = u64::from(raw_difference < 0);
            if digit_ordinal + 1 == value_digit_layers.len() && borrow != 0 {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            let difference = raw_difference
                .checked_add(i128::from(MATERIAL_DIGIT_RADIX) * i128::from(borrow))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            difference_rows.push(
                u64::try_from(difference).map_err(|_| TargetReleaseWitnessError::InvalidWitness)?,
            );
            next_borrow[row_ordinal] = borrow;
        }
        let difference_layout = &layout.difference_digits[digit_ordinal];
        insert_unsigned_half_column(
            columns,
            trace_domain,
            difference_layout.target_column_ordinal,
            &difference_rows,
        )?;
        insert_half_trit_columns(
            columns,
            trace_domain,
            &difference_layout.trit_column_ordinals,
            &difference_rows,
        )?;
        if let Some(borrow_column_ordinal) = layout.borrow_column_ordinals.get(digit_ordinal) {
            insert_unsigned_half_column(
                columns,
                trace_domain,
                *borrow_column_ordinal,
                &next_borrow,
            )?;
        }
        previous_borrow = next_borrow;
    }
    Ok(())
}

fn insert_bounded_unsigned_vector(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    layout: &TargetBoundedUnsignedVector,
    values: &[BigUint],
    maximum: &BigUint,
) -> Result<Vec<Vec<u64>>, TargetReleaseWitnessError> {
    if values.len() != trace_domain.size() * 2
        || values.iter().any(|value| value > maximum)
        || layout.upper_bound_comparators.len() != 2
        || layout.digit_columns_by_half[0].is_empty()
        || layout.digit_columns_by_half[0].len() != layout.digit_columns_by_half[1].len()
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let digit_count = layout.digit_columns_by_half[0].len();
    let digit_layers = big_unsigned_radix_layers(values, MATERIAL_DIGIT_RADIX, digit_count)?;
    let maximum_digits = fixed_radix_digits(maximum, digit_count, MATERIAL_DIGIT_RADIX)
        .map_err(TargetReleaseWitnessError::from)?;
    for half_ordinal in 0..2 {
        for (digit_ordinal, digit_layer) in digit_layers.iter().enumerate() {
            let half_start = half_ordinal * trace_domain.size();
            insert_unsigned_half_column(
                columns,
                trace_domain,
                layout.digit_columns_by_half[half_ordinal][digit_ordinal],
                &digit_layer[half_start..half_start + trace_domain.size()],
            )?;
        }
        let half_start = half_ordinal * trace_domain.size();
        let half_values = &values[half_start..half_start + trace_domain.size()];
        insert_big_unsigned_half_trit_columns(
            columns,
            trace_domain,
            &layout.trits_by_half[half_ordinal],
            half_values,
        )?;
        insert_upper_bound_comparator(
            columns,
            trace_domain,
            &layout.upper_bound_comparators[half_ordinal],
            &digit_layers,
            &maximum_digits,
            half_ordinal,
        )?;
    }
    Ok(digit_layers)
}

fn insert_centered_vector(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    layout: &TargetCenteredVector,
    values: &[i128],
) -> Result<(), TargetReleaseWitnessError> {
    if values.len() != trace_domain.size() * 2 || layout.trits_by_half.len() != 2 {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let offset = i128::from(layout.trit_encoding_offset);
    if values
        .iter()
        .any(|value| *value < -offset || *value > offset)
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    insert_signed_ring_vector(columns, trace_domain, layout.value.coefficients, values)?;
    for half_ordinal in 0..2 {
        let start = half_ordinal * trace_domain.size();
        let encoded = values[start..start + trace_domain.size()]
            .iter()
            .map(|value| {
                u64::try_from(*value + offset)
                    .map_err(|_| TargetReleaseWitnessError::IntegerOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        insert_half_trit_columns(
            columns,
            trace_domain,
            &layout.trits_by_half[half_ordinal],
            &encoded,
        )?;
    }
    Ok(())
}

fn insert_committed_share_columns(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    layout: &TargetCommittedMaterialVector,
    committed_share_source: &CompactCommittedMaterialSource,
    share: &[u64],
    modulus: u64,
) -> Result<Vec<Vec<u64>>, TargetReleaseWitnessError> {
    if share.len() != trace_domain.size() * 2
        || share.iter().any(|value| *value >= modulus)
        || committed_share_source.profile().trace_domain_size() != trace_domain.size()
        || layout.upper_bound_comparators.len() != 2
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let digit_layers = unsigned_radix_layers(share, MATERIAL_DIGIT_RADIX, 2)?;
    let maximum_digits = fixed_radix_digits(&BigUint::from(modulus - 1), 2, MATERIAL_DIGIT_RADIX)?;
    for (physical_ordinal, column_ordinal) in layout.bound_columns.iter().copied().enumerate() {
        let digit_ordinal = physical_ordinal / 2;
        let half_ordinal = physical_ordinal % 2;
        if columns.wants_column(column_ordinal) {
            let start = half_ordinal * trace_domain.size();
            let trace_values = &digit_layers[digit_ordinal][start..start + trace_domain.size()];
            let masked_coefficients = committed_share_source
                .regenerate_masked_coefficients(physical_ordinal, trace_values)
                .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
            insert_source_polynomial(
                columns,
                column_ordinal,
                CommonProofSourcePolynomial::from_protected_base_coefficients(masked_coefficients),
            )?;
        }
    }
    for half_ordinal in 0..2 {
        let start = half_ordinal * trace_domain.size();
        insert_half_trit_columns(
            columns,
            trace_domain,
            &layout.trits_by_half[half_ordinal],
            &share[start..start + trace_domain.size()],
        )?;
        insert_upper_bound_comparator(
            columns,
            trace_domain,
            &layout.upper_bound_comparators[half_ordinal],
            &digit_layers,
            &maximum_digits,
            half_ordinal,
        )?;
    }
    Ok(digit_layers)
}

struct RadixLayerTransform {
    coefficient_count: usize,
    evaluation_domain: ProofEvaluationDomain,
    evaluations: Vec<Vec<ProofBaseFieldElement>>,
}

impl RadixLayerTransform {
    fn new(layers: &[Vec<u64>]) -> Result<Self, TargetReleaseWitnessError> {
        let coefficient_count = layers
            .first()
            .map(Vec::len)
            .filter(|count| *count >= 2 && count.is_power_of_two())
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        if layers.is_empty()
            || layers.iter().any(|layer| {
                layer.len() != coefficient_count || layer.iter().any(|value| *value >= RADIX)
            })
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let evaluation_domain = ProofEvaluationDomain::new_subgroup(
            coefficient_count
                .checked_mul(2)
                .ok_or(TargetReleaseWitnessError::CountOverflow)?,
        )?;
        let evaluations = layers
            .iter()
            .map(|layer| {
                let coefficients = layer
                    .iter()
                    .copied()
                    .map(ProofBaseFieldElement::from_canonical)
                    .collect::<Result<Vec<_>, _>>()?;
                evaluation_domain
                    .evaluate_base_polynomial(&coefficients)
                    .map_err(TargetReleaseWitnessError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            coefficient_count,
            evaluation_domain,
            evaluations,
        })
    }

    fn multiply_left_layers(
        &self,
        left_layers: &[Vec<u64>],
    ) -> Result<Vec<Vec<i128>>, TargetReleaseWitnessError> {
        if left_layers.is_empty()
            || left_layers.iter().any(|layer| {
                layer.len() != self.coefficient_count || layer.iter().any(|value| *value >= RADIX)
            })
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let layer_count = left_layers
            .len()
            .checked_add(self.evaluations.len())
            .and_then(|count| count.checked_sub(1))
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        let maximum_ordinary_coefficient = u128::try_from(self.coefficient_count)
            .map_err(|_| TargetReleaseWitnessError::CountOverflow)?
            .checked_mul(u128::from(RADIX - 1).pow(2))
            .and_then(|value| {
                value.checked_mul(
                    u128::try_from(left_layers.len().min(self.evaluations.len())).ok()?,
                )
            })
            .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
        if maximum_ordinary_coefficient >= u128::from(PROOF_BASE_FIELD_MODULUS / 2) {
            return Err(TargetReleaseWitnessError::IntegerOverflow);
        }
        let mut product_evaluations =
            vec![vec![ProofBaseFieldElement::ZERO; self.evaluation_domain.size()]; layer_count];
        for (left_ordinal, left_layer) in left_layers.iter().enumerate() {
            let left_coefficients = left_layer
                .iter()
                .copied()
                .map(ProofBaseFieldElement::from_canonical)
                .collect::<Result<Vec<_>, _>>()?;
            let left_evaluations = self
                .evaluation_domain
                .evaluate_base_polynomial(&left_coefficients)?;
            for (right_ordinal, right_evaluations) in self.evaluations.iter().enumerate() {
                let output = &mut product_evaluations[left_ordinal + right_ordinal];
                for ((destination, left), right) in output
                    .iter_mut()
                    .zip(&left_evaluations)
                    .zip(right_evaluations)
                {
                    *destination = destination.add(left.multiply(*right));
                }
            }
        }
        let mut product_layers = Vec::with_capacity(layer_count);
        for mut coefficients in product_evaluations {
            self.evaluation_domain
                .interpolate_base_polynomial_in_place(&mut coefficients)?;
            let mut folded = Vec::with_capacity(self.coefficient_count);
            for coefficient_ordinal in 0..self.coefficient_count {
                let low = coefficients
                    .get(coefficient_ordinal)
                    .copied()
                    .unwrap_or(ProofBaseFieldElement::ZERO)
                    .canonical();
                let high = coefficients
                    .get(coefficient_ordinal + self.coefficient_count)
                    .copied()
                    .unwrap_or(ProofBaseFieldElement::ZERO)
                    .canonical();
                if u128::from(low) > maximum_ordinary_coefficient
                    || u128::from(high) > maximum_ordinary_coefficient
                {
                    return Err(TargetReleaseWitnessError::IntegerOverflow);
                }
                folded.push(i128::from(low) - i128::from(high));
            }
            product_layers.push(folded);
        }
        Ok(product_layers)
    }
}

fn insert_balanced_radix_value(
    mut remaining: TargetReleaseFixedSignedInteger,
    radix: u64,
    layers: &mut [Vec<i128>],
    coefficient_ordinal: usize,
) -> Result<(), TargetReleaseWitnessError> {
    if radix < 3
        || radix.is_multiple_of(2)
        || layers.is_empty()
        || layers
            .iter()
            .any(|layer| coefficient_ordinal >= layer.len())
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    for layer in layers {
        layer[coefficient_ordinal] = remaining.take_balanced_radix_digit(radix)?;
    }
    if !remaining.is_zero() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    Ok(())
}

fn checked_product_value(
    product_layers: &[Vec<i128>],
    coefficient_ordinal: usize,
) -> Result<i128, TargetReleaseWitnessError> {
    product_layers
        .iter()
        .rev()
        .try_fold(0_i128, |value, layer| {
            value
                .checked_mul(i128::from(RADIX))
                .and_then(|value| value.checked_add(layer[coefficient_ordinal]))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)
        })
}

#[allow(clippy::too_many_arguments)]
fn derive_role_equation_layers(
    layout: &TargetReleaseRoleEquationWitnessLayout,
    role: TargetReleaseRoleWitness<'_>,
    share_transform: RadixLayerTransform,
    flooding_error: &[BigInt],
    flooding_shift_layers: Zeroizing<Vec<Vec<u64>>>,
    modulus: u64,
    decryption_scale: u64,
    simulation_scale: u64,
    flooding_bound: &BigUint,
    ring_degree: usize,
) -> Result<TargetReleaseRoleDerivedLayers, TargetReleaseWitnessError> {
    if role.converted_a.len() != ring_degree
        || role.partial_decryption.len() != ring_degree
        || flooding_error.len() != ring_degree
        || role.converted_a.iter().any(|value| *value >= modulus)
        || role
            .partial_decryption
            .iter()
            .any(|value| *value >= modulus)
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let scaled_a_layers = scaled_residue_radix_layers(
        role.converted_a,
        modulus,
        decryption_scale,
        RADIX,
        layout.scaled_a_digits.len(),
    )?;
    let partial_decryption_layers = scaled_residue_radix_layers(
        role.partial_decryption,
        modulus,
        1,
        RADIX,
        layout.partial_decryption_digits.len(),
    )?;
    let product_layers = Zeroizing::new(share_transform.multiply_left_layers(&scaled_a_layers)?);
    drop(share_transform);
    drop(scaled_a_layers);
    let fixed_flooding_bound = TargetReleaseFixedSignedInteger::from_biguint(flooding_bound)?;
    let mut quotient_layers = Zeroizing::new(vec![
        vec![0_i128; ring_degree];
        layout.quotient_digits.len()
    ]);
    for (coefficient_ordinal, (partial_decryption_coefficient, flooding_error_coefficient)) in role
        .partial_decryption
        .iter()
        .copied()
        .zip(flooding_error)
        .enumerate()
    {
        let product = checked_product_value(&product_layers, coefficient_ordinal)?;
        if flooding_error_coefficient.magnitude() > flooding_bound {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let flooding_term =
            TargetReleaseFixedSignedInteger::from_bigint(flooding_error_coefficient)?
                .checked_multiply_unsigned(simulation_scale)?;
        let residual_without_flooding = i128::from(partial_decryption_coefficient)
            .checked_sub(product)
            .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
        let residual = TargetReleaseFixedSignedInteger::from_i128(residual_without_flooding)
            .checked_subtract(flooding_term)?;
        let (quotient, remainder) = residual.checked_divide_unsigned(modulus)?;
        if remainder != 0 {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        insert_balanced_radix_value(quotient, RADIX, &mut quotient_layers, coefficient_ordinal)?;
    }

    let modulus_digits = fixed_width_unsigned_radix_digits(
        TargetReleaseFixedSignedInteger::from_u64(modulus),
        minimum_u64_radix_digit_count(modulus, RADIX)?,
        RADIX,
    )?;
    let flooding_constant = fixed_flooding_bound.checked_multiply_unsigned(simulation_scale)?;
    let equation_layer_count = layout
        .carry_values
        .len()
        .checked_add(1)
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    let flooding_constant_digits =
        fixed_width_unsigned_radix_digits(flooding_constant, equation_layer_count, RADIX)?;
    let mut carry_layers =
        Zeroizing::new(vec![vec![0_i128; ring_degree]; layout.carry_values.len()]);
    let mut previous_carry = Zeroizing::new(vec![0_i128; ring_degree]);
    for (layer_ordinal, flooding_constant_digit) in flooding_constant_digits
        .iter()
        .copied()
        .enumerate()
        .take(equation_layer_count)
    {
        let mut next_carry = Zeroizing::new(vec![0_i128; ring_degree]);
        for coefficient_ordinal in 0..ring_degree {
            let mut numerator = i128::from(
                partial_decryption_layers
                    .get(layer_ordinal)
                    .map_or(0, |layer| layer[coefficient_ordinal]),
            )
            .checked_sub(
                product_layers
                    .get(layer_ordinal)
                    .map_or(0, |layer| layer[coefficient_ordinal]),
            )
            .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            let shifted_flooding = flooding_shift_layers
                .get(layer_ordinal)
                .map_or(0, |layer| layer[coefficient_ordinal]);
            numerator = numerator
                .checked_sub(
                    i128::from(simulation_scale)
                        .checked_mul(i128::from(shifted_flooding))
                        .ok_or(TargetReleaseWitnessError::IntegerOverflow)?,
                )
                .and_then(|value| value.checked_add(i128::from(flooding_constant_digit)))
                .and_then(|value| value.checked_add(previous_carry[coefficient_ordinal]))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            for (modulus_digit_ordinal, modulus_digit) in modulus_digits.iter().enumerate() {
                let Some(quotient_digit_ordinal) = layer_ordinal.checked_sub(modulus_digit_ordinal)
                else {
                    continue;
                };
                if let Some(quotient_layer) = quotient_layers.get(quotient_digit_ordinal) {
                    numerator = numerator
                        .checked_sub(
                            i128::from(*modulus_digit)
                                .checked_mul(quotient_layer[coefficient_ordinal])
                                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?,
                        )
                        .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
                }
            }
            if layer_ordinal + 1 == equation_layer_count {
                if numerator != 0 {
                    return Err(TargetReleaseWitnessError::InvalidWitness);
                }
            } else {
                if numerator.rem_euclid(i128::from(RADIX)) != 0 {
                    return Err(TargetReleaseWitnessError::InvalidWitness);
                }
                next_carry[coefficient_ordinal] = numerator / i128::from(RADIX);
            }
        }
        if let Some(destination) = carry_layers.get_mut(layer_ordinal) {
            destination.copy_from_slice(&next_carry);
        }
        previous_carry = next_carry;
    }
    Ok(TargetReleaseRoleDerivedLayers {
        flooding_shift_layers,
        quotient_layers,
        carry_layers,
    })
}

fn unsigned_radix_half_rows(
    values: &[u64],
    radix: u64,
    digit_ordinal: usize,
    digit_count: usize,
    half_ordinal: usize,
    trace_domain_size: usize,
) -> Result<Zeroizing<Vec<i128>>, TargetReleaseWitnessError> {
    if radix < 2
        || digit_ordinal >= digit_count
        || half_ordinal >= 2
        || trace_domain_size == 0
        || values.len()
            != trace_domain_size
                .checked_mul(2)
                .ok_or(TargetReleaseWitnessError::CountOverflow)?
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let radix = u128::from(radix);
    let capacity = (0..digit_count).try_fold(1_u128, |capacity, _| {
        capacity
            .checked_mul(radix)
            .ok_or(TargetReleaseWitnessError::IntegerOverflow)
    })?;
    if values.iter().any(|value| u128::from(*value) >= capacity) {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let divisor = (0..digit_ordinal).try_fold(1_u128, |divisor, _| {
        divisor
            .checked_mul(radix)
            .ok_or(TargetReleaseWitnessError::IntegerOverflow)
    })?;
    let start = half_ordinal
        .checked_mul(trace_domain_size)
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    Ok(Zeroizing::new(
        values[start..start + trace_domain_size]
            .iter()
            .copied()
            .map(|value| i128::try_from((u128::from(value) / divisor) % radix))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TargetReleaseWitnessError::IntegerOverflow)?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn scaled_residue_radix_half_rows(
    values: &[u64],
    modulus: u64,
    scale: u64,
    radix: u64,
    digit_ordinal: usize,
    digit_count: usize,
    half_ordinal: usize,
    trace_domain_size: usize,
) -> Result<Zeroizing<Vec<i128>>, TargetReleaseWitnessError> {
    if modulus < 3
        || scale == 0
        || radix < 2
        || digit_ordinal >= digit_count
        || half_ordinal >= 2
        || trace_domain_size == 0
        || values.len()
            != trace_domain_size
                .checked_mul(2)
                .ok_or(TargetReleaseWitnessError::CountOverflow)?
        || values.iter().any(|value| *value >= modulus)
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let radix = u128::from(radix);
    let capacity = (0..digit_count).try_fold(1_u128, |capacity, _| {
        capacity
            .checked_mul(radix)
            .ok_or(TargetReleaseWitnessError::IntegerOverflow)
    })?;
    let maximum_scaled = u128::from(modulus - 1)
        .checked_mul(u128::from(scale))
        .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
    if maximum_scaled >= capacity {
        return Err(TargetReleaseWitnessError::IntegerOverflow);
    }
    let divisor = (0..digit_ordinal).try_fold(1_u128, |divisor, _| {
        divisor
            .checked_mul(radix)
            .ok_or(TargetReleaseWitnessError::IntegerOverflow)
    })?;
    let start = half_ordinal
        .checked_mul(trace_domain_size)
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    Ok(Zeroizing::new(
        values[start..start + trace_domain_size]
            .iter()
            .copied()
            .map(|value| i128::try_from((u128::from(value) * u128::from(scale) / divisor) % radix))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TargetReleaseWitnessError::IntegerOverflow)?,
    ))
}

fn split_centered_layer_rows(
    layouts: &[TargetCenteredVector],
    layers: &[Vec<i128>],
    column_ordinal: u32,
    trace_domain_size: usize,
) -> Result<Option<Zeroizing<Vec<i128>>>, TargetReleaseWitnessError> {
    if layouts.len() != layers.len() || trace_domain_size == 0 {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    for (layout, layer) in layouts.iter().zip(layers) {
        let Some(half_ordinal) = layout
            .value
            .coefficients
            .halves
            .iter()
            .position(|candidate| *candidate == column_ordinal)
        else {
            continue;
        };
        if layer.len()
            != trace_domain_size
                .checked_mul(2)
                .ok_or(TargetReleaseWitnessError::CountOverflow)?
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let start = half_ordinal
            .checked_mul(trace_domain_size)
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        return Ok(Some(Zeroizing::new(
            layer[start..start + trace_domain_size].to_vec(),
        )));
    }
    Ok(None)
}

fn resolve_target_release_integer_lift_coefficient(
    coefficient: RelationIntegerLiftCoefficient,
    modulus_layout: &TargetReleaseModulusWitnessLayout,
) -> Result<i128, TargetReleaseWitnessError> {
    let value = match coefficient {
        RelationIntegerLiftCoefficient::Constant(value) => u128::from(value),
        RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier,
        } => {
            if modulus_reference != modulus_layout.modulus_reference {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            u128::from(modulus_layout.modulus)
                .checked_mul(u128::from(multiplier))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?
        }
        RelationIntegerLiftCoefficient::ModulusRadixDigit {
            modulus_reference,
            multiplier,
            radix,
            digit_ordinal,
        } => {
            if modulus_reference != modulus_layout.modulus_reference || radix < 2 {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            let scaled_modulus = u128::from(modulus_layout.modulus)
                .checked_mul(u128::from(multiplier))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            let divisor = u128::from(radix)
                .checked_pow(u32::from(digit_ordinal))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            (scaled_modulus / divisor) % u128::from(radix)
        }
    };
    i128::try_from(value).map_err(|_| TargetReleaseWitnessError::IntegerOverflow)
}

fn same_target_release_exact_carry_equation(
    left: &RelationIntegerLiftComponentDescriptor,
    right: &RelationIntegerLiftComponentDescriptor,
) -> bool {
    left.ordered_linear_terms == right.ordered_linear_terms
        && left.ordered_convolution_products.is_empty()
        && right.ordered_convolution_products.is_empty()
        && left.ordered_full_ring_negacyclic_products.len()
            == right.ordered_full_ring_negacyclic_products.len()
        && left
            .ordered_full_ring_negacyclic_products
            .iter()
            .zip(&right.ordered_full_ring_negacyclic_products)
            .all(|(left_product, right_product)| {
                left_product.negative == right_product.negative
                    && left_product.selected_half == right_product.selected_half
                    && left_product.multiplicand_low_column_ordinal
                        == right_product.multiplicand_low_column_ordinal
                    && left_product.multiplicand_high_column_ordinal
                        == right_product.multiplicand_high_column_ordinal
                    && left_product.multiplier_low_column_ordinal
                        == right_product.multiplier_low_column_ordinal
                    && left_product.multiplier_high_column_ordinal
                        == right_product.multiplier_high_column_ordinal
                    && left_product.multiplier_low_offset == right_product.multiplier_low_offset
                    && left_product.multiplier_high_offset == right_product.multiplier_high_offset
            })
}

struct TargetReleaseExactCarryDerivation<'input, Source> {
    compilation: &'input CompiledTargetReleaseRelation,
    source: &'input Source,
    variant: &'input RelationPlanVariant,
    modulus_ordinal: usize,
    role_ordinal: usize,
    role_layers: &'input TargetReleaseRoleDerivedLayers,
    active_columns: Box<[u32]>,
    active_column_count: usize,
}

impl<Source> TargetReleaseExactCarryDerivation<'_, Source>
where
    Source: TargetReleaseWitnessSource,
{
    fn trace_domain_size(&self) -> Result<usize, TargetReleaseWitnessError> {
        self.compilation
            .ring_degree
            .checked_div(2)
            .filter(|trace_domain_size| {
                *trace_domain_size > 1
                    && trace_domain_size.checked_mul(2) == Some(self.compilation.ring_degree)
            })
            .ok_or(TargetReleaseWitnessError::InvalidWitness)
    }

    fn derive_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Zeroizing<Vec<i128>>, TargetReleaseWitnessError> {
        if self
            .active_columns
            .get(..self.active_column_count)
            .is_none_or(|active_columns| active_columns.contains(&column_ordinal))
            || self.active_column_count == self.active_columns.len()
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        *self
            .active_columns
            .get_mut(self.active_column_count)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)? = column_ordinal;
        self.active_column_count += 1;
        let rows = match self.direct_rows(column_ordinal)? {
            Some(rows) => Ok(rows),
            None => self.exact_carry_rows(column_ordinal),
        };
        self.active_column_count = self
            .active_column_count
            .checked_sub(1)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let active_column = self
            .active_columns
            .get_mut(self.active_column_count)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        if *active_column != column_ordinal {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        *active_column = 0;
        let rows = rows?;
        if rows.len() != self.trace_domain_size()? {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        Ok(rows)
    }

    fn direct_rows(
        &self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, TargetReleaseWitnessError> {
        let trace_domain_size = self.trace_domain_size()?;
        if column_ordinal == self.compilation.constant_one_column {
            return Ok(Some(Zeroizing::new(vec![1_i128; trace_domain_size])));
        }
        if column_ordinal == self.compilation.zero_column {
            return Ok(Some(Zeroizing::new(vec![0_i128; trace_domain_size])));
        }
        let flooding_layout = self
            .compilation
            .flooding_by_role
            .get(self.role_ordinal)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        if let Some((digit_ordinal, half_ordinal)) = flooding_layout
            .grouped_limbs
            .iter()
            .enumerate()
            .find_map(|(digit_ordinal, layout)| {
                layout
                    .halves
                    .iter()
                    .position(|candidate| *candidate == column_ordinal)
                    .map(|half_ordinal| (digit_ordinal, half_ordinal))
            })
        {
            let ring_degree = trace_domain_size
                .checked_mul(2)
                .ok_or(TargetReleaseWitnessError::CountOverflow)?;
            let layer = self
                .role_layers
                .flooding_shift_layers
                .get(digit_ordinal)
                .filter(|layer| layer.len() == ring_degree)
                .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
            let start = half_ordinal
                .checked_mul(trace_domain_size)
                .ok_or(TargetReleaseWitnessError::CountOverflow)?;
            return Ok(Some(Zeroizing::new(
                layer[start..start + trace_domain_size]
                    .iter()
                    .copied()
                    .map(i128::from)
                    .collect(),
            )));
        }
        let modulus_layout = self
            .compilation
            .moduli
            .get(self.modulus_ordinal)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let role_layout = modulus_layout
            .role_equations
            .get(self.role_ordinal)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        if let Some((digit_ordinal, half_ordinal)) = modulus_layout
            .share_limbs
            .iter()
            .enumerate()
            .find_map(|(digit_ordinal, layout)| {
                layout
                    .source
                    .coefficients
                    .halves
                    .iter()
                    .position(|candidate| *candidate == column_ordinal)
                    .map(|half_ordinal| (digit_ordinal, half_ordinal))
            })
        {
            return self
                .source
                .with_modulus_witness(self.modulus_ordinal, |witness| {
                    unsigned_radix_half_rows(
                        witness.threshold_share,
                        RADIX,
                        digit_ordinal,
                        modulus_layout.share_limbs.len(),
                        half_ordinal,
                        trace_domain_size,
                    )
                    .map(Some)
                });
        }
        if let Some((digit_ordinal, half_ordinal)) = role_layout
            .scaled_a_digits
            .iter()
            .enumerate()
            .find_map(|(digit_ordinal, layout)| {
                layout
                    .halves
                    .iter()
                    .position(|candidate| *candidate == column_ordinal)
                    .map(|half_ordinal| (digit_ordinal, half_ordinal))
            })
        {
            return self
                .source
                .with_modulus_witness(self.modulus_ordinal, |witness| {
                    scaled_residue_radix_half_rows(
                        witness.roles[self.role_ordinal].converted_a,
                        modulus_layout.modulus,
                        self.compilation.decryption_scale,
                        RADIX,
                        digit_ordinal,
                        role_layout.scaled_a_digits.len(),
                        half_ordinal,
                        trace_domain_size,
                    )
                    .map(Some)
                });
        }
        if let Some((digit_ordinal, half_ordinal)) = role_layout
            .partial_decryption_digits
            .iter()
            .enumerate()
            .find_map(|(digit_ordinal, layout)| {
                layout
                    .halves
                    .iter()
                    .position(|candidate| *candidate == column_ordinal)
                    .map(|half_ordinal| (digit_ordinal, half_ordinal))
            })
        {
            return self
                .source
                .with_modulus_witness(self.modulus_ordinal, |witness| {
                    scaled_residue_radix_half_rows(
                        witness.roles[self.role_ordinal].partial_decryption,
                        modulus_layout.modulus,
                        1,
                        RADIX,
                        digit_ordinal,
                        role_layout.partial_decryption_digits.len(),
                        half_ordinal,
                        trace_domain_size,
                    )
                    .map(Some)
                });
        }
        if let Some(rows) = split_centered_layer_rows(
            &role_layout.quotient_digits,
            &self.role_layers.quotient_layers,
            column_ordinal,
            trace_domain_size,
        )? {
            return Ok(Some(rows));
        }
        split_centered_layer_rows(
            &role_layout.carry_values,
            &self.role_layers.carry_layers,
            column_ordinal,
            trace_domain_size,
        )
    }

    fn exact_carry_component_position(
        &self,
        column_ordinal: u32,
    ) -> Result<(usize, usize), TargetReleaseWitnessError> {
        let modulus_reference = self
            .compilation
            .moduli
            .get(self.modulus_ordinal)
            .map(|layout| layout.modulus_reference)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let mut matched_component: Option<(usize, usize)> = None;
        for (batch_ordinal, batch) in self
            .variant
            .ordered_integer_lift_batches()
            .iter()
            .enumerate()
        {
            if batch.modulus_reference() != modulus_reference {
                continue;
            }
            for (component_ordinal, component) in batch.ordered_components.iter().enumerate() {
                let is_outgoing_carry = component.ordered_linear_terms.iter().any(|term| {
                    term.negative
                        && term.column_ordinal == column_ordinal
                        && term.column_offset == 0
                        && term.coefficient
                            == RelationIntegerLiftCoefficient::Constant(
                                super::key_relation::EXACT_INTEGER_LIFT_RADIX,
                            )
                });
                if !is_outgoing_carry {
                    continue;
                }
                if let Some((matched_batch_ordinal, matched_component_ordinal)) = matched_component
                {
                    let matched = self
                        .variant
                        .ordered_integer_lift_batches()
                        .get(matched_batch_ordinal)
                        .and_then(|batch| batch.ordered_components.get(matched_component_ordinal))
                        .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
                    if !same_target_release_exact_carry_equation(matched, component) {
                        return Err(TargetReleaseWitnessError::InvalidWitness);
                    }
                } else {
                    matched_component = Some((batch_ordinal, component_ordinal));
                }
            }
        }
        matched_component.ok_or(TargetReleaseWitnessError::InvalidWitness)
    }

    fn exact_carry_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Zeroizing<Vec<i128>>, TargetReleaseWitnessError> {
        let (batch_ordinal, component_ordinal) =
            self.exact_carry_component_position(column_ordinal)?;
        let modulus_layout = self
            .compilation
            .moduli
            .get(self.modulus_ordinal)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let mut accumulated = Zeroizing::new(vec![0_i128; self.trace_domain_size()?]);
        let linear_term_count = self
            .variant
            .ordered_integer_lift_batches()
            .get(batch_ordinal)
            .and_then(|batch| batch.ordered_components.get(component_ordinal))
            .map(|component| component.ordered_linear_terms.len())
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        for term_ordinal in 0..linear_term_count {
            let term = self
                .variant
                .ordered_integer_lift_batches()
                .get(batch_ordinal)
                .and_then(|batch| batch.ordered_components.get(component_ordinal))
                .and_then(|component| component.ordered_linear_terms.get(term_ordinal))
                .cloned()
                .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
            if term.negative
                && term.column_ordinal == column_ordinal
                && term.column_offset == 0
                && term.coefficient
                    == RelationIntegerLiftCoefficient::Constant(
                        super::key_relation::EXACT_INTEGER_LIFT_RADIX,
                    )
            {
                continue;
            }
            let rows = self.derive_rows(term.column_ordinal)?;
            let coefficient =
                resolve_target_release_integer_lift_coefficient(term.coefficient, modulus_layout)?;
            for (accumulated_value, row_value) in accumulated.iter_mut().zip(rows.iter()) {
                let shifted = row_value
                    .checked_sub(i128::from(term.column_offset))
                    .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
                let contribution = shifted
                    .checked_mul(coefficient)
                    .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
                *accumulated_value = if term.negative {
                    accumulated_value.checked_sub(contribution)
                } else {
                    accumulated_value.checked_add(contribution)
                }
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            }
        }
        let full_ring_product_count = self
            .variant
            .ordered_integer_lift_batches()
            .get(batch_ordinal)
            .and_then(|batch| batch.ordered_components.get(component_ordinal))
            .map(|component| component.ordered_full_ring_negacyclic_products.len())
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        for product_ordinal in 0..full_ring_product_count {
            let product = self
                .variant
                .ordered_integer_lift_batches()
                .get(batch_ordinal)
                .and_then(|batch| batch.ordered_components.get(component_ordinal))
                .and_then(|component| {
                    component
                        .ordered_full_ring_negacyclic_products
                        .get(product_ordinal)
                })
                .cloned()
                .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
            let product_rows = self.full_ring_product_rows(&product)?;
            for (accumulated_value, product_value) in
                accumulated.iter_mut().zip(product_rows.iter())
            {
                *accumulated_value = accumulated_value
                    .checked_add(*product_value)
                    .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            }
        }
        let radix = i128::from(super::key_relation::EXACT_INTEGER_LIFT_RADIX);
        if accumulated.iter().any(|value| value % radix != 0) {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        Ok(Zeroizing::new(
            accumulated
                .iter()
                .copied()
                .map(|value| value / radix)
                .collect(),
        ))
    }

    fn full_ring_product_rows(
        &mut self,
        product: &RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    ) -> Result<Zeroizing<Vec<i128>>, TargetReleaseWitnessError> {
        let multiplicand_low = self.derive_rows(product.multiplicand_low_column_ordinal)?;
        let multiplicand_high = self.derive_rows(product.multiplicand_high_column_ordinal)?;
        let multiplier_low = self.derive_rows(product.multiplier_low_column_ordinal)?;
        let multiplier_high = self.derive_rows(product.multiplier_high_column_ordinal)?;
        let multiplicand = multiplicand_low
            .iter()
            .chain(multiplicand_high.iter())
            .copied()
            .collect::<Vec<_>>();
        let multiplier = multiplier_low
            .iter()
            .map(|value| value.checked_sub(i128::from(product.multiplier_low_offset)))
            .chain(
                multiplier_high
                    .iter()
                    .map(|value| value.checked_sub(i128::from(product.multiplier_high_offset))),
            )
            .collect::<Option<Vec<_>>>()
            .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
        let product_coefficients = super::galois_key_share_adapter::exact_negacyclic_product_small(
            &multiplicand,
            &multiplier,
        )
        .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
        let half_size = multiplicand_low.len();
        let selected = match product.selected_half {
            RelationIntegerLiftFullRingHalf::Low => product_coefficients
                .get(..half_size)
                .ok_or(TargetReleaseWitnessError::InvalidWitness)?,
            RelationIntegerLiftFullRingHalf::High => product_coefficients
                .get(half_size..)
                .ok_or(TargetReleaseWitnessError::InvalidWitness)?,
        };
        selected
            .iter()
            .copied()
            .map(|value| {
                if product.negative {
                    value
                        .checked_neg()
                        .ok_or(TargetReleaseWitnessError::IntegerOverflow)
                } else {
                    Ok(value)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Zeroizing::new)
    }
}

type RoleVerifierRadixLayers = (Vec<Vec<u64>>, Vec<Vec<u64>>);

fn insert_role_verifier_columns(
    columns: &mut impl TargetReleaseSourcePolynomialSink,
    trace_domain: ProofEvaluationDomain,
    layout: &TargetReleaseRoleEquationWitnessLayout,
    role: TargetReleaseRoleWitness<'_>,
    modulus: u64,
    decryption_scale: u64,
) -> Result<RoleVerifierRadixLayers, TargetReleaseWitnessError> {
    let ring_degree = trace_domain
        .size()
        .checked_mul(2)
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    if role.converted_a.len() != ring_degree
        || role.partial_decryption.len() != ring_degree
        || role.converted_a.iter().any(|value| *value >= modulus)
        || role
            .partial_decryption
            .iter()
            .any(|value| *value >= modulus)
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let scaled_a_layers = scaled_residue_radix_layers(
        role.converted_a,
        modulus,
        decryption_scale,
        RADIX,
        layout.scaled_a_digits.len(),
    )?;
    let partial_decryption_layers = scaled_residue_radix_layers(
        role.partial_decryption,
        modulus,
        1,
        RADIX,
        layout.partial_decryption_digits.len(),
    )?;
    insert_split_radix_layers(
        columns,
        trace_domain,
        &layout.scaled_a_digits,
        &scaled_a_layers,
    )?;
    insert_split_radix_layers(
        columns,
        trace_domain,
        &layout.partial_decryption_digits,
        &partial_decryption_layers,
    )?;
    Ok((scaled_a_layers, partial_decryption_layers))
}

impl CompiledTargetReleaseRelation {
    /// Builds the verifier-sequence adapter from public streams that have
    /// already been authenticated and reconstructed by the target verifier.
    /// The shape check is exact: every verifier-sequence column in the selected
    /// relation must be present and no prover or bound-tree column may enter
    /// this adapter.
    pub(crate) fn verified_column_evaluator(
        &self,
        public_moduli: &[VerifiedTargetReleaseModulusInput<'_>],
    ) -> Result<TargetReleaseVerifiedColumnEvaluator, TargetReleaseWitnessError> {
        if public_moduli.len() != self.moduli.len()
            || self.ring_degree < 2
            || !self.ring_degree.is_power_of_two()
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let trace_domain = ProofEvaluationDomain::new_subgroup(self.ring_degree / 2)?;
        let mut columns = BTreeMap::new();
        for (modulus_layout, public_modulus) in self.moduli.iter().zip(public_moduli) {
            if modulus_layout.role_equations.len() != usize::from(TARGET_ROLE_COUNT) {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            for role_ordinal in 0..usize::from(TARGET_ROLE_COUNT) {
                insert_role_verifier_columns(
                    &mut columns,
                    trace_domain,
                    &modulus_layout.role_equations[role_ordinal],
                    public_modulus.roles[role_ordinal],
                    modulus_layout.modulus,
                    self.decryption_scale,
                )?;
            }
        }
        let variant = self.relation_plan.select_variant(None, None)?;
        for (column_index, descriptor) in variant.ordered_columns().iter().enumerate() {
            let column_ordinal = u32::try_from(column_index)
                .map_err(|_| TargetReleaseWitnessError::CountOverflow)?;
            let is_verifier_sequence = matches!(
                descriptor.origin(),
                RelationColumnOrigin::VerifierSequence { .. }
            );
            if columns.contains_key(&column_ordinal) != is_verifier_sequence {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
        }
        Ok(TargetReleaseVerifiedColumnEvaluator {
            columns: columns.into_iter().collect::<Vec<_>>().into_boxed_slice(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::ntt::negacyclic_convolution_for_tests;
    use crate::bgv::parameters::DATA_PRIMES;
    use crate::bgv::proof_suite::{
        CommittedMaterialProfile, CommittedMaterialTree, CommittedMaterialTreeInput,
        CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSource,
        CommonProofSourcePolynomialRequestContext, PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
        PROOF_BASE_FIELD_MODULUS, construct_pre_challenge_relation_columns,
    };

    const TEST_EVALUATION_DOMAIN_SIZE: u64 = 8_192;
    const TEST_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 1_024;

    struct DeterministicPrivateCoins {
        initial_sample: u64,
        next_sample_by_coordinate:
            std::collections::BTreeMap<CommonProofPrivateCoinCoordinate, u64>,
    }

    impl DeterministicPrivateCoins {
        fn new(initial_sample: u64) -> Self {
            Self {
                initial_sample,
                next_sample_by_coordinate: std::collections::BTreeMap::new(),
            }
        }
    }

    #[derive(Clone, Copy)]
    struct BorrowedTargetReleaseWitnessSource<'input> {
        flooding_errors_by_role: [&'input [BigInt]; 2],
        modulus_witness: TargetReleaseModulusWitness<'input>,
        restart_binding_hash: [u8; 64],
    }

    impl TargetReleaseWitnessSource for BorrowedTargetReleaseWitnessSource<'_> {
        fn memory_accounting(
            &self,
        ) -> Result<TargetReleaseWitnessSourceMemoryAccounting, TargetReleaseWitnessError> {
            TargetReleaseWitnessSourceMemoryAccounting::new(0, Vec::new(), 0, 0, 0)
        }

        fn with_flooding_errors<Output, Operation>(
            &self,
            role_ordinal: usize,
            operation: Operation,
        ) -> Result<Output, TargetReleaseWitnessError>
        where
            Operation: for<'scratch> FnOnce(
                &'scratch [BigInt],
            )
                -> Result<Output, TargetReleaseWitnessError>,
        {
            operation(
                self.flooding_errors_by_role
                    .get(role_ordinal)
                    .copied()
                    .ok_or(TargetReleaseWitnessError::InvalidWitness)?,
            )
        }

        fn with_modulus_witness<Output, Operation>(
            &self,
            modulus_ordinal: usize,
            operation: Operation,
        ) -> Result<Output, TargetReleaseWitnessError>
        where
            Operation: for<'input> FnOnce(
                TargetReleaseModulusWitness<'input>,
            ) -> Result<Output, TargetReleaseWitnessError>,
        {
            if modulus_ordinal != 0 {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            operation(self.modulus_witness)
        }

        fn source_restart_binding_hash(&self) -> [u8; 64] {
            self.restart_binding_hash
        }

        fn absorb_canonical_semantic_witness(
            &self,
            binding: &mut PersistentProofWitnessCoinBinding,
        ) -> Result<(), TargetReleaseWitnessError> {
            binding
                .absorb_canonical_bytes(
                    b"sealed-lattice/common-proof/test-target-canonical-semantic-witness/v1",
                )
                .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
            for errors in self.flooding_errors_by_role {
                for error in errors {
                    binding
                        .absorb_canonical_bytes(&error.to_signed_bytes_le())
                        .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
                }
            }
            binding
                .absorb_canonical_u64_values(self.modulus_witness.threshold_share)
                .map_err(|_| TargetReleaseWitnessError::InvalidWitness)
        }
    }

    impl CommonProofPrivateCoinSource for DeterministicPrivateCoins {
        type Error = ();

        fn sample_modulo(
            &mut self,
            coordinate: CommonProofPrivateCoinCoordinate,
            modulus: u64,
            _maximum_candidate_draws_per_output: u32,
        ) -> Result<u64, Self::Error> {
            let next_sample = self
                .next_sample_by_coordinate
                .entry(coordinate)
                .or_insert(self.initial_sample);
            let value = *next_sample % modulus;
            *next_sample = next_sample.wrapping_add(1);
            Ok(value)
        }

        fn fill_raw_bytes(
            &mut self,
            coordinate: CommonProofPrivateCoinCoordinate,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            let next_sample = self
                .next_sample_by_coordinate
                .entry(coordinate)
                .or_insert(self.initial_sample);
            for byte in destination {
                *byte = *next_sample as u8;
                *next_sample = next_sample.wrapping_add(1);
            }
            Ok(())
        }

        fn replay_modulo_samples(
            &mut self,
            coordinate: CommonProofPrivateCoinCoordinate,
            modulus: u64,
            _maximum_candidate_draws_per_output: u32,
            destination: &mut [u64],
        ) -> Result<(), Self::Error> {
            let expected_end = self
                .next_sample_by_coordinate
                .get(&coordinate)
                .copied()
                .ok_or(())?;
            for (sample_ordinal, sampled) in destination.iter_mut().enumerate() {
                *sampled = self.initial_sample.wrapping_add(sample_ordinal as u64) % modulus;
            }
            if self.initial_sample.wrapping_add(destination.len() as u64) != expected_end {
                return Err(());
            }
            Ok(())
        }
    }

    fn plan_context() -> RelationPlanCheckContext {
        let evaluation_domain_size = TEST_EVALUATION_DOMAIN_SIZE;
        RelationPlanCheckContext {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE
                as u16,
            evaluation_domain_generator: modular_power(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                (1_u64 << 32) / evaluation_domain_size,
                PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            out_of_domain_point_count: 1,
            quotient_component_count: 4,
            quotient_component_degree_bound_exclusive: 1_024,
            phase_column_query_coordinate_count: 8,
            non_native_theta_repetition_count: 1,
            non_native_alpha_repetition_count: 1,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli: DATA_PRIMES[..6]
                .iter()
                .copied()
                .enumerate()
                .map(|(modulus_index, modulus)| {
                    ResolvedSuiteModulus::new(
                        SuiteModulusReference::target(
                            u16::try_from(modulus_index).expect("target modulus index"),
                        ),
                        modulus,
                    )
                })
                .collect(),
        }
    }

    fn bigint_from_fixed_for_tests(value: TargetReleaseFixedSignedInteger) -> BigInt {
        let magnitude_bytes = value
            .magnitude_limbs
            .iter()
            .flat_map(|limb| limb.to_le_bytes())
            .collect::<Vec<_>>();
        let magnitude = BigUint::from_bytes_le(&magnitude_bytes);
        let sign = if magnitude.is_zero() {
            Sign::NoSign
        } else if value.negative {
            Sign::Minus
        } else {
            Sign::Plus
        };
        BigInt::from_biguint(sign, magnitude)
    }

    fn recompose_unsigned_radix_column_for_tests(
        layers: &[Vec<u64>],
        coefficient_ordinal: usize,
        radix: u64,
    ) -> BigUint {
        layers.iter().rev().fold(BigUint::zero(), |value, layer| {
            value * radix + layer[coefficient_ordinal]
        })
    }

    #[test]
    fn verifier_radix_view_is_canonical_and_rejects_non_residues() {
        assert_eq!(
            radix_decompose_scaled_residues(&[0, 96, 42], 97, 4, 9, 1, 3).expect("digits"),
            vec![0, 6, 0]
        );
        assert_eq!(
            radix_decompose_scaled_residues(&[97], 97, 4, 9, 0, 3),
            Err(RelationPlanError::InvalidSource)
        );
    }

    #[test]
    fn balanced_quotient_width_accounts_for_the_terminal_carry() {
        assert_eq!(
            minimum_balanced_radix_digit_count(&BigUint::from((RADIX - 1) / 2))
                .expect("one balanced digit"),
            1
        );
        assert_eq!(
            minimum_balanced_radix_digit_count(&BigUint::from(RADIX.div_ceil(2)))
                .expect("two balanced digits"),
            2
        );
        assert_eq!(
            minimum_balanced_radix_digit_count(&BigUint::from(RADIX - 1)).expect("terminal carry"),
            2
        );
    }

    #[test]
    fn fixed_width_shift_maps_both_flooding_boundaries_without_wrap() {
        let flooding_bound =
            crate::bgv::proof_suite::selected_profile::selected_target_decryption_flooding_bound()
                .expect("selected flooding bound");
        assert_eq!(flooding_bound.bits(), 146);
        assert_eq!(
            flooding_bound.to_str_radix(10),
            "48425557508880960588220213618157405536780288",
        );
        let flooding_errors = [
            BigInt::from_biguint(Sign::Minus, flooding_bound.clone()),
            BigInt::zero(),
            BigInt::from_biguint(Sign::Plus, flooding_bound.clone()),
        ];
        let layers = shifted_flooding_radix_layers(
            &flooding_errors,
            flooding_errors.len(),
            &flooding_bound,
            RADIX,
            13,
        )
        .expect("selected fixed-width flooding shift");
        assert_eq!(
            recompose_unsigned_radix_column_for_tests(&layers, 0, RADIX),
            BigUint::zero()
        );
        assert_eq!(
            recompose_unsigned_radix_column_for_tests(&layers, 1, RADIX),
            flooding_bound
        );
        assert_eq!(
            recompose_unsigned_radix_column_for_tests(&layers, 2, RADIX),
            &flooding_bound * 2_u8
        );

        let outside_bound = BigInt::from_biguint(Sign::Plus, &flooding_bound + 1_u8);
        assert_eq!(
            shifted_flooding_radix_layers(&[outside_bound], 1, &flooding_bound, RADIX, 13),
            Err(TargetReleaseWitnessError::InvalidWitness)
        );
    }

    #[test]
    fn fixed_width_integer_refuses_values_and_products_beyond_four_limbs() {
        assert_eq!(
            TargetReleaseFixedSignedInteger::from_biguint(&(BigUint::one() << 256_usize)),
            Err(TargetReleaseWitnessError::IntegerOverflow)
        );
        let maximum = TargetReleaseFixedSignedInteger {
            negative: false,
            magnitude_limbs: [u64::MAX; TARGET_RELEASE_FIXED_INTEGER_LIMB_COUNT],
        };
        assert_eq!(
            maximum.checked_multiply_unsigned(2),
            Err(TargetReleaseWitnessError::IntegerOverflow)
        );

        let overflowing_bound = BigUint::one() << 255_usize;
        let positive_boundary = BigInt::from_biguint(Sign::Plus, overflowing_bound.clone());
        assert_eq!(
            shifted_flooding_radix_layers(&[positive_boundary], 1, &overflowing_bound, RADIX, 16,),
            Err(TargetReleaseWitnessError::IntegerOverflow)
        );
    }

    #[test]
    fn fixed_width_division_distinguishes_exact_and_nonexact_residuals() {
        let modulus = DATA_PRIMES[0];
        let expected_quotient = (BigInt::one() << 188_usize) + BigInt::from(0x51_73_u64);
        let exact_residual = &expected_quotient * modulus;
        let (quotient, remainder) = TargetReleaseFixedSignedInteger::from_bigint(&exact_residual)
            .expect("four-limb exact residual")
            .checked_divide_unsigned(modulus)
            .expect("fixed-width exact division");
        assert_eq!(remainder, 0);
        assert_eq!(bigint_from_fixed_for_tests(quotient), expected_quotient);

        let negative_residual = -exact_residual;
        let (negative_quotient, negative_remainder) =
            TargetReleaseFixedSignedInteger::from_bigint(&negative_residual)
                .expect("four-limb negative residual")
                .checked_divide_unsigned(modulus)
                .expect("fixed-width negative division");
        assert_eq!(negative_remainder, 0);
        assert_eq!(
            bigint_from_fixed_for_tests(negative_quotient),
            -expected_quotient.clone()
        );

        let nonexact_residual = negative_residual - 1_u8;
        let (_, nonzero_remainder) =
            TargetReleaseFixedSignedInteger::from_bigint(&nonexact_residual)
                .expect("four-limb nonexact residual")
                .checked_divide_unsigned(modulus)
                .expect("fixed-width nonexact division");
        assert_ne!(nonzero_remainder, 0);
    }

    #[test]
    fn fixed_width_cancellation_canonicalizes_negative_zero() {
        let magnitude = TargetReleaseFixedSignedInteger::from_biguint(
            &((BigUint::one() << 219_usize) + BigUint::from(17_u8)),
        )
        .expect("four-limb cancellation magnitude");
        let cancelled = magnitude
            .checked_add(magnitude.negated())
            .expect("opposite magnitudes cancel");
        assert_eq!(cancelled, TargetReleaseFixedSignedInteger::ZERO);
        assert!(!cancelled.negative);
        assert_eq!(
            TargetReleaseFixedSignedInteger::ZERO.negated(),
            TargetReleaseFixedSignedInteger::ZERO
        );
        assert_eq!(
            TargetReleaseFixedSignedInteger::from_i128(-19)
                .checked_add(TargetReleaseFixedSignedInteger::from_u64(7))
                .expect("opposite-sign subtraction"),
            TargetReleaseFixedSignedInteger::from_i128(-12)
        );
    }

    #[test]
    fn fixed_width_negative_balanced_radix_uses_euclidean_digits() {
        let half_radix = i128::from(RADIX / 2);
        let cases = [
            (-1_i128, [-1_i128, 0, 0]),
            (-half_radix, [-half_radix, 0, 0]),
            (-(half_radix + 1), [half_radix, -1, 0]),
            (-(i128::from(RADIX) - 1), [1, -1, 0]),
            (-i128::from(RADIX), [0, -1, 0]),
            (-(i128::from(RADIX) + 1), [-1, -1, 0]),
        ];
        for (value, expected_digits) in cases {
            let mut layers = vec![vec![0_i128; 1]; expected_digits.len()];
            insert_balanced_radix_value(
                TargetReleaseFixedSignedInteger::from_i128(value),
                RADIX,
                &mut layers,
                0,
            )
            .expect("fixed-width balanced radix digits");
            assert_eq!(
                layers.iter().map(|layer| layer[0]).collect::<Vec<_>>(),
                expected_digits,
                "unexpected balanced radix digits for {value}",
            );
            let recomposed = layers.iter().rev().fold(0_i128, |accumulated, layer| {
                accumulated * i128::from(RADIX) + layer[0]
            });
            assert_eq!(recomposed, value);
        }
    }

    #[test]
    fn unsigned_radix_layers_cover_zero_boundaries_and_capacity_refusal() {
        let radix_squared = RADIX.checked_mul(RADIX).expect("selected radix square");
        let layers = unsigned_radix_layers(&[0, RADIX - 1, RADIX, radix_squared - 1], RADIX, 2)
            .expect("two unsigned radix layers");
        assert_eq!(layers[0], vec![0, RADIX - 1, 0, RADIX - 1]);
        assert_eq!(layers[1], vec![0, 0, 1, RADIX - 1]);
        assert_eq!(
            unsigned_radix_layers(&[radix_squared], RADIX, 2),
            Err(TargetReleaseWitnessError::InvalidWitness)
        );
    }

    #[test]
    fn consumed_derived_layer_is_zeroized_before_its_storage_is_released() {
        let mut derived_values = vec![i128::MIN + 1, -7, 0, 11, i128::MAX];
        zeroize_consumed_derived_layer(&mut derived_values)
            .expect("consume secret quotient or carry layer");
        assert!(derived_values.is_empty());
        assert_eq!(
            zeroize_consumed_derived_layer(&mut derived_values),
            Err(TargetReleaseWitnessError::InvalidWitness),
            "a consumed layer cannot be replayed",
        );
    }

    fn role_layer_cache_fixture() -> TargetReleaseRoleDerivedLayers {
        TargetReleaseRoleDerivedLayers {
            flooding_shift_layers: Zeroizing::new(vec![vec![3_u64, 2, 1]]),
            quotient_layers: Zeroizing::new(vec![vec![-7_i128, 0, 9]]),
            carry_layers: Zeroizing::new(vec![vec![11_i128, -13, 0]]),
        }
    }

    #[test]
    fn role_layer_cache_state_machine_reuses_rejects_and_releases_exactly() {
        let requested_role_key = (2_usize, 1_usize);

        let mut absent_key = None;
        let mut absent_layers = None;
        assert_eq!(
            prepare_target_release_role_layer_cache(
                &mut absent_key,
                &mut absent_layers,
                requested_role_key,
            ),
            Ok(true),
            "an absent cache requires derivation",
        );

        let mut matching_key = Some(requested_role_key);
        let mut matching_layers = Some(role_layer_cache_fixture());
        assert_eq!(
            prepare_target_release_role_layer_cache(
                &mut matching_key,
                &mut matching_layers,
                requested_role_key,
            ),
            Ok(false),
            "an unconsumed matching cache must be reused without a callback",
        );
        assert_eq!(
            matching_layers
                .as_ref()
                .expect("matching cache remains live")
                .quotient_layers[0],
            [-7_i128, 0, 9],
        );

        let mut different_key = Some((2_usize, 0_usize));
        let mut different_layers = Some(role_layer_cache_fixture());
        assert_eq!(
            prepare_target_release_role_layer_cache(
                &mut different_key,
                &mut different_layers,
                requested_role_key,
            ),
            Err(TargetReleaseWitnessError::InvalidWitness),
            "a role switch cannot discard unconsumed secret layers",
        );
        assert_eq!(different_key, Some((2, 0)));
        assert!(different_layers.is_some());

        for exhausted_key in [requested_role_key, (3_usize, 0_usize)] {
            let mut exhausted_layers = role_layer_cache_fixture();
            for values in exhausted_layers
                .quotient_layers
                .iter_mut()
                .chain(exhausted_layers.carry_layers.iter_mut())
            {
                let retained_capacity = values.capacity();
                values.zeroize();
                assert!(values.is_empty());
                assert_eq!(values.capacity(), retained_capacity);
                assert!(retained_capacity > 0);
            }
            let mut exhausted_key = Some(exhausted_key);
            let mut exhausted_layers = Some(exhausted_layers);
            assert_eq!(
                prepare_target_release_role_layer_cache(
                    &mut exhausted_key,
                    &mut exhausted_layers,
                    requested_role_key,
                ),
                Ok(true),
                "exhausted retained capacities must be released before derivation",
            );
            assert_eq!(exhausted_key, None);
            assert!(exhausted_layers.is_none());
        }

        let mut key_without_layers = Some(requested_role_key);
        let mut missing_layers = None;
        assert_eq!(
            prepare_target_release_role_layer_cache(
                &mut key_without_layers,
                &mut missing_layers,
                requested_role_key,
            ),
            Err(TargetReleaseWitnessError::InvalidWitness),
        );
        let mut missing_key = None;
        let mut layers_without_key = Some(role_layer_cache_fixture());
        assert_eq!(
            prepare_target_release_role_layer_cache(
                &mut missing_key,
                &mut layers_without_key,
                requested_role_key,
            ),
            Err(TargetReleaseWitnessError::InvalidWitness),
        );
    }

    #[test]
    fn target_release_plan_compiles_with_compact_safe_limb_products() {
        let context = plan_context();
        let plan = compile_target_release_relation(
            &TargetReleaseRelationPlanInput {
                ring_degree: 256,
                evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
                opening_degree_bound_exclusive: TEST_OPENING_DEGREE_BOUND_EXCLUSIVE,
                material_column_degree_bound_exclusive: 128,
                public_polynomial_column_degree_bound_exclusive: 256,
                target_modulus_indices: vec![0],
                decryption_scale: 4,
                simulation_scale: 4,
                flooding_bound: BigUint::from(1_000_000_u64),
            },
            &context,
        )
        .expect("target release relation plan")
        .relation_plan;
        let variant = plan.select_variant(None, None).expect("variant");
        assert_eq!(variant.ordered_integer_lift_batches().len(), 1);
        let components = variant
            .ordered_integer_lift_batches()
            .iter()
            .flat_map(|batch| &batch.ordered_components)
            .collect::<Vec<_>>();
        assert!(
            components
                .iter()
                .any(|component| !component.ordered_full_ring_negacyclic_products.is_empty())
        );
        assert!(
            components
                .iter()
                .any(|component| component.ordered_full_ring_negacyclic_products.is_empty())
        );
        super::super::same_secret_anchor::tests::assert_integer_lift_phase_ownership(variant);
    }

    #[test]
    fn selected_role_layer_memory_phases_match_independent_native_and_wasm_derivations() {
        let (compilation, _, _) = selected_target_release_generation_relation()
            .expect("selected target release relation");
        let modulus_layout = compilation.moduli.first().expect("selected target modulus");
        let role_layout = modulus_layout
            .role_equations
            .first()
            .expect("selected target role");
        assert_eq!(compilation.ring_degree, 32_768);
        assert_eq!(compilation.flooding_by_role[0].grouped_limbs.len(), 13,);
        assert_eq!(modulus_layout.share_limbs.len(), 4);
        assert_eq!(role_layout.scaled_a_digits.len(), 2);
        assert_eq!(role_layout.partial_decryption_digits.len(), 2);
        assert_eq!(role_layout.quotient_digits.len(), 13);
        assert_eq!(role_layout.carry_values.len(), 13);
        assert_eq!(role_layout.exact_integer_lift_carry_columns.len(), 28);
        assert_eq!(
            role_layout.scaled_a_digits.len() + modulus_layout.share_limbs.len() - 1,
            5,
        );
        assert_eq!(
            target_release_modulus_digit_count(modulus_layout.modulus)
                .expect("selected modulus radix width"),
            2,
        );

        let wasm_accounting = target_release_role_layer_construction_memory_accounting(
            &compilation,
            modulus_layout,
            role_layout,
            0,
            1_572_864,
            32,
            0,
            TargetReleaseMemoryScalarByteLengths::wasm32(),
        )
        .expect("modeled wasm target role accounting");
        assert_eq!(wasm_accounting.callback_construction_byte_length, 1_572_896);
        assert_eq!(
            wasm_accounting.flooding_layer_construction_byte_length,
            4_980_892,
        );
        assert_eq!(
            wasm_accounting.share_radix_construction_byte_length,
            6_029_516,
        );
        assert_eq!(
            wasm_accounting.share_transform_construction_byte_length,
            8_388_860,
        );
        assert_eq!(wasm_accounting.product_evaluation_byte_length, 11_534_648);
        assert_eq!(wasm_accounting.product_folding_byte_length, 11_272_564);
        assert_eq!(
            wasm_accounting.quotient_construction_byte_length,
            14_942_604,
        );
        assert_eq!(wasm_accounting.carry_construction_byte_length, 22_807_208);
        assert_eq!(wasm_accounting.role_cache_byte_length, 17_039_828);
        assert_eq!(wasm_accounting.steady_role_envelope_byte_length, 17_301_972,);
        assert_eq!(
            wasm_accounting.exact_carry_derivation_byte_length,
            28_049_992,
        );
        assert_eq!(
            wasm_accounting.exact_carry_materialization_byte_length,
            17_564_116,
        );
        assert_eq!(
            wasm_accounting.ordinary_materialization_byte_length,
            17_564_116,
        );
        assert_eq!(
            wasm_accounting.maximum_dynamic_byte_length(),
            wasm_accounting.exact_carry_derivation_byte_length,
            "the selected exact-carry recursion ceiling is the role peak",
        );
        assert_eq!(
            wasm_accounting
                .maximum_dynamic_byte_length()
                .checked_sub(wasm_accounting.steady_role_envelope_byte_length),
            Some(10_748_020),
        );

        let construction_dominant = target_release_role_layer_construction_memory_accounting(
            &compilation,
            modulus_layout,
            role_layout,
            0,
            1_572_864,
            30_000_000,
            0,
            TargetReleaseMemoryScalarByteLengths::wasm32(),
        )
        .expect("construction-dominant callback accounting");
        assert_eq!(
            construction_dominant.callback_construction_byte_length,
            31_572_864,
        );
        assert_eq!(
            construction_dominant.carry_construction_byte_length,
            wasm_accounting.carry_construction_byte_length,
            "construction-only bytes must not leak into the callback body",
        );
        assert_eq!(
            construction_dominant.exact_carry_derivation_byte_length,
            wasm_accounting.exact_carry_derivation_byte_length,
        );

        let larger_flooding_ready = target_release_role_layer_construction_memory_accounting(
            &compilation,
            modulus_layout,
            role_layout,
            0,
            1_576_960,
            32,
            0,
            TargetReleaseMemoryScalarByteLengths::wasm32(),
        )
        .expect("larger flooding callback accounting");
        assert_eq!(
            larger_flooding_ready.carry_construction_byte_length,
            wasm_accounting.carry_construction_byte_length + 4_096,
        );
        assert_eq!(
            larger_flooding_ready.exact_carry_derivation_byte_length,
            wasm_accounting.exact_carry_derivation_byte_length,
            "exact carries never reconstruct flooding callback scratch",
        );

        let modulus_callback_scratch = target_release_role_layer_construction_memory_accounting(
            &compilation,
            modulus_layout,
            role_layout,
            0,
            1_572_864,
            32,
            2_048,
            TargetReleaseMemoryScalarByteLengths::wasm32(),
        )
        .expect("modulus callback accounting");
        assert_eq!(
            modulus_callback_scratch.callback_construction_byte_length,
            wasm_accounting.callback_construction_byte_length,
        );
        assert_eq!(
            modulus_callback_scratch.flooding_layer_construction_byte_length,
            wasm_accounting.flooding_layer_construction_byte_length,
        );
        assert_eq!(
            modulus_callback_scratch.carry_construction_byte_length,
            wasm_accounting.carry_construction_byte_length + 2_048,
        );
        assert_eq!(
            modulus_callback_scratch.exact_carry_derivation_byte_length,
            wasm_accounting.exact_carry_derivation_byte_length + 2_048,
        );

        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(core::mem::size_of::<BigInt>(), 32);
            let native_accounting = target_release_role_layer_construction_memory_accounting(
                &compilation,
                modulus_layout,
                role_layout,
                0,
                2_097_152,
                32,
                0,
                TargetReleaseMemoryScalarByteLengths::current_target(),
            )
            .expect("native target role accounting");
            assert_eq!(
                native_accounting.callback_construction_byte_length,
                2_097_184,
            );
            assert_eq!(
                native_accounting.share_transform_construction_byte_length,
                8_913_400,
            );
            assert_eq!(native_accounting.product_evaluation_byte_length, 12_059_248,);
            assert_eq!(native_accounting.product_folding_byte_length, 11_797_224,);
            assert_eq!(
                native_accounting.quotient_construction_byte_length,
                15_467_288,
            );
            assert_eq!(native_accounting.carry_construction_byte_length, 23_332_048,);
            assert_eq!(native_accounting.role_cache_byte_length, 17_040_296);
            assert_eq!(
                native_accounting.steady_role_envelope_byte_length,
                17_302_440,
            );
            assert_eq!(
                native_accounting.exact_carry_derivation_byte_length,
                28_050_460,
            );
            assert_eq!(
                native_accounting.exact_carry_materialization_byte_length,
                17_564_584,
            );
            assert_eq!(
                native_accounting.ordinary_materialization_byte_length,
                17_564_584,
            );
            assert_eq!(
                native_accounting.maximum_dynamic_byte_length(),
                native_accounting.exact_carry_derivation_byte_length,
            );
            assert_eq!(
                native_accounting
                    .maximum_dynamic_byte_length()
                    .checked_sub(native_accounting.steady_role_envelope_byte_length),
                Some(10_748_020),
            );

            let provider_accounting =
                target_release_source_provider_memory_accounting_from_dimensions(
                    &compilation,
                    0,
                    0,
                    2_097_152,
                    32,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("selected native provider accounting");
            assert_eq!(
                provider_accounting
                    .loading_persistent_resident_byte_length()
                    .checked_sub(
                        provider_accounting
                            .post_source_polynomial_finish_persistent_resident_byte_length(),
                    ),
                Some(0),
                "source replay can rebuild one role-specific steady envelope",
            );
            assert_eq!(
                provider_accounting.additional_loading_transient_byte_length(),
                10_748_020,
            );
            assert_eq!(
                provider_accounting.maximum_returned_source_polynomial_byte_length(),
                131_072,
            );
        }
    }

    #[test]
    fn target_release_source_catalog_covers_exact_carries_and_keeps_centered_offsets_distinct() {
        let context = plan_context();
        let compilation = compile_target_release_relation(
            &TargetReleaseRelationPlanInput {
                ring_degree: 256,
                evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
                opening_degree_bound_exclusive: TEST_OPENING_DEGREE_BOUND_EXCLUSIVE,
                material_column_degree_bound_exclusive: 128,
                public_polynomial_column_degree_bound_exclusive: 256,
                target_modulus_indices: vec![0],
                decryption_scale: 4,
                simulation_scale: 4,
                flooding_bound: BigUint::from(1_000_000_u64),
            },
            &context,
        )
        .expect("target release relation compilation");
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .expect("target release relation variant");
        let source_blocks =
            target_release_source_blocks(&compilation).expect("complete target source catalog");
        let mut exact_carry_count = 0_usize;
        let mut centered_vector_count = 0_usize;

        for (modulus_ordinal, modulus_layout) in compilation.moduli.iter().enumerate() {
            for (role_ordinal, role_layout) in modulus_layout.role_equations.iter().enumerate() {
                for carry_column_ordinal in
                    role_layout.exact_integer_lift_carry_columns.iter().copied()
                {
                    exact_carry_count += 1;
                    let expected_block = TargetReleaseSourceBlock::ExactIntegerLiftCarry {
                        modulus_ordinal,
                        role_ordinal,
                        carry_column_ordinal,
                    };
                    let semantic_cell = variant
                        .ordered_semantic_cells
                        .iter()
                        .find(|cell| cell.column_ordinal == carry_column_ordinal)
                        .expect("exact carry semantic cell");
                    let RelationBoundCertificate::ShiftedRadixRecomposition {
                        radix,
                        ordered_digit_column_ordinals,
                        ..
                    } = &semantic_cell.bound_certificate
                    else {
                        panic!("an exact carry must retain its shifted-radix certificate");
                    };
                    assert_eq!(*radix, 3);
                    assert!(!ordered_digit_column_ordinals.is_empty());
                    for source_column_ordinal in std::iter::once(carry_column_ordinal)
                        .chain(ordered_digit_column_ordinals.iter().copied())
                    {
                        assert_eq!(
                            source_blocks.get(&source_column_ordinal),
                            Some(&expected_block),
                            "the exact carry and every support trit must have one source owner",
                        );
                    }
                }

                for centered_layout in role_layout
                    .quotient_digits
                    .iter()
                    .chain(&role_layout.carry_values)
                {
                    centered_vector_count += 1;
                    assert_eq!(centered_layout.value.offset, 0);
                    assert!(centered_layout.trit_encoding_offset > 0);
                    for half_ordinal in 0..2 {
                        let value_column_ordinal =
                            centered_layout.value.coefficients.halves[half_ordinal];
                        let semantic_cell = variant
                            .ordered_semantic_cells
                            .iter()
                            .find(|cell| cell.column_ordinal == value_column_ordinal)
                            .expect("centered value semantic cell");
                        let RelationBoundCertificate::ShiftedRadixRecomposition {
                            radix,
                            offset,
                            ordered_digit_column_ordinals,
                            ..
                        } = &semantic_cell.bound_certificate
                        else {
                            panic!("a centered value must retain its shifted-radix certificate");
                        };
                        assert_eq!(*radix, 3);
                        assert_eq!(offset, &BigUint::from(centered_layout.trit_encoding_offset));
                        assert_eq!(
                            ordered_digit_column_ordinals,
                            &centered_layout.trits_by_half[half_ordinal]
                        );
                    }
                }
            }
        }
        assert!(exact_carry_count > 0);
        assert!(centered_vector_count > 0);

        let mut incomplete_compilation = compilation.clone();
        let removed_carry = incomplete_compilation
            .moduli
            .iter_mut()
            .flat_map(|modulus| modulus.role_equations.iter_mut())
            .find_map(|role| role.exact_integer_lift_carry_columns.pop());
        assert!(removed_carry.is_some());
        assert_eq!(
            target_release_source_blocks(&incomplete_compilation),
            Err(TargetReleaseWitnessError::InvalidWitness),
            "a source catalog missing one compiler-requested carry must fail closed",
        );
    }

    #[test]
    fn target_release_plan_keeps_exact_equations_for_wide_flooding_bounds() {
        let context = plan_context();
        let target_modulus_product = (0_u16..6)
            .map(|target_modulus_index| {
                context
                    .resolved_modulus(SuiteModulusReference::target(target_modulus_index))
                    .expect("target modulus")
            })
            .map(BigUint::from)
            .product::<BigUint>();
        let flooding_bound = &target_modulus_product >> 1_usize;
        assert!(flooding_bound.bits() > 128);
        assert!(flooding_bound < target_modulus_product);
        let plan = compile_target_release_relation(
            &TargetReleaseRelationPlanInput {
                ring_degree: 256,
                evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
                opening_degree_bound_exclusive: TEST_OPENING_DEGREE_BOUND_EXCLUSIVE,
                material_column_degree_bound_exclusive: 128,
                public_polynomial_column_degree_bound_exclusive: 256,
                target_modulus_indices: vec![0, 1, 2, 3, 4, 5],
                decryption_scale: 4,
                simulation_scale: 4,
                flooding_bound,
            },
            &context,
        )
        .expect("wide target release relation plan")
        .relation_plan;
        let variant = plan.select_variant(None, None).expect("variant");
        let components = variant
            .ordered_integer_lift_batches()
            .iter()
            .flat_map(|batch| &batch.ordered_components)
            .collect::<Vec<_>>();
        assert_eq!(variant.ordered_integer_lift_batches().len(), 6);
        assert!(
            components
                .iter()
                .any(|component| { !component.ordered_full_ring_negacyclic_products.is_empty() })
        );
        assert!(
            components
                .iter()
                .any(|component| { component.ordered_full_ring_negacyclic_products.is_empty() })
        );
        super::super::same_secret_anchor::tests::assert_integer_lift_phase_ownership(variant);
    }

    #[test]
    fn selected_generation_atomically_mints_the_compilation_and_checked_plan() {
        let (compilation, checked_plan, coordinate_capacity) =
            selected_target_release_generation_relation()
                .expect("selected target release generation relation");
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .expect("selected target release variant");
        assert_eq!(
            checked_plan.relation_plan_variant_hash(),
            variant
                .canonical_hash()
                .expect("selected target release variant hash")
        );
        assert_ne!(checked_plan.relation_plan_hash(), [0_u8; 64]);
        assert_eq!(
            coordinate_capacity,
            CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(variant)
                .expect("selected target release coordinate capacity")
        );
        assert_eq!(
            compilation.flooding_bound,
            crate::bgv::proof_suite::selected_profile::selected_target_decryption_flooding_bound()
                .expect("selected target flooding bound")
        );
        assert_eq!(
            compilation.decryption_scale,
            crate::bgv::target_decryption::kllps_release::KLLPS_DENOMINATOR_CLEARING_FACTOR
        );
        assert_eq!(compilation.simulation_scale, compilation.decryption_scale);

        let selected_proof = VerifiedTargetReleaseProof {
            application_statement_hash: [0x51; 64],
            relation_plan_variant_hash: checked_plan.relation_plan_variant_hash(),
        };
        selected_proof
            .require_selected_relation()
            .expect("selected target-release proof relation");
        let mut changed_variant_hash = checked_plan.relation_plan_variant_hash();
        changed_variant_hash[0] ^= 1;
        assert_eq!(
            VerifiedTargetReleaseProof {
                application_statement_hash: [0x51; 64],
                relation_plan_variant_hash: changed_variant_hash,
            }
            .require_selected_relation(),
            Err(TargetReleaseCapabilityError::WrongRelation),
        );
    }

    #[test]
    fn streaming_target_witness_populates_requested_columns_and_verifier_rejects_non_residues() {
        let context = plan_context();
        let ring_degree = 256_usize;
        let material_profile = CommittedMaterialProfile::for_common_proof_evaluation_domain(
            ring_degree,
            usize::try_from(TEST_EVALUATION_DOMAIN_SIZE)
                .expect("test evaluation domain fits usize"),
            usize::try_from(TEST_OPENING_DEGREE_BOUND_EXCLUSIVE)
                .expect("test opening degree fits usize"),
        )
        .expect("material profile");
        let compilation = compile_target_release_relation(
            &TargetReleaseRelationPlanInput {
                ring_degree: ring_degree as u64,
                evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
                opening_degree_bound_exclusive: TEST_OPENING_DEGREE_BOUND_EXCLUSIVE,
                material_column_degree_bound_exclusive: material_profile
                    .material_column_degree_bound_exclusive()
                    as u64,
                public_polynomial_column_degree_bound_exclusive: ring_degree as u64,
                target_modulus_indices: vec![0],
                decryption_scale: 4,
                simulation_scale: 4,
                flooding_bound: BigUint::from(1_000_000_u64),
            },
            &context,
        )
        .expect("target relation compilation");
        let modulus = context
            .resolved_modulus(SuiteModulusReference::target(0))
            .expect("target modulus");
        let share = (0..ring_degree)
            .map(|index| ((index * 37 + 11) as u64) % modulus)
            .collect::<Vec<_>>();
        let material_digits =
            unsigned_radix_layers(&share, MATERIAL_DIGIT_RADIX, 2).expect("material digits");
        let committed_share = CommittedMaterialTree::construct(CommittedMaterialTreeInput {
            profile: material_profile,
            material_context_hash: [0x51; 64],
            material_seed: [0x73; 64],
            message_digit_columns: &material_digits,
        })
        .expect("committed share");
        let committed_share_source = committed_share.into_compact_source();
        let flooding_identifier = (0..ring_degree)
            .map(|index| BigInt::from(index % 11) - 5_u8)
            .collect::<Vec<_>>();
        let flooding_order = (0..ring_degree)
            .map(|index| BigInt::from(7_u8) - BigInt::from(index % 13))
            .collect::<Vec<_>>();
        let converted_identifier = (0..ring_degree)
            .map(|index| ((index * 19 + 3) as u64) % modulus)
            .collect::<Vec<_>>();
        let converted_order = (0..ring_degree)
            .map(|index| ((index * 23 + 9) as u64) % modulus)
            .collect::<Vec<_>>();
        let partial = |converted: &[u64], flooding: &[BigInt]| {
            negacyclic_convolution_for_tests(converted, &share, modulus)
                .expect("selected-modulus product")
                .iter()
                .zip(flooding)
                .map(|(product, error)| {
                    (4_i128 * i128::from(*product)
                        + 4_i128 * i128::try_from(error).expect("small flooding error"))
                    .rem_euclid(i128::from(modulus)) as u64
                })
                .collect::<Vec<_>>()
        };
        let partial_identifier = partial(&converted_identifier, &flooding_identifier);
        let partial_order = partial(&converted_order, &flooding_order);
        let modulus_witness = TargetReleaseModulusWitness {
            committed_share_source: &committed_share_source,
            threshold_share: &share,
            roles: [
                TargetReleaseRoleWitness {
                    converted_a: &converted_identifier,
                    partial_decryption: &partial_identifier,
                },
                TargetReleaseRoleWitness {
                    converted_a: &converted_order,
                    partial_decryption: &partial_order,
                },
            ],
        };
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .expect("target relation variant");
        let evaluation_point = ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(7).expect("canonical point"),
        );
        let request_context = CommonProofSourcePolynomialRequestContext::new(
            1,
            [0x31; 64],
            compilation
                .relation_plan()
                .application_statement_schema_identifier(),
            [0x32; 64],
            compilation
                .relation_plan()
                .canonical_hash()
                .expect("target relation plan hash"),
            variant
                .canonical_hash()
                .expect("target relation variant hash"),
            None,
            None,
        );
        let streaming_source = BorrowedTargetReleaseWitnessSource {
            flooding_errors_by_role: [&flooding_identifier, &flooding_order],
            modulus_witness,
            restart_binding_hash: [0x91; 64],
        };
        let relation_plan_hash = compilation
            .relation_plan()
            .canonical_hash()
            .expect("target relation plan hash");
        let mut streaming_provider = TargetReleaseSourcePolynomialAdapter::new(
            compilation.clone(),
            1,
            [0x31; 64],
            [0x32; 64],
            relation_plan_hash,
            streaming_source,
        )
        .expect("streaming target source");
        let streaming_pre_challenge_columns = construct_pre_challenge_relation_columns(
            variant,
            request_context,
            &mut streaming_provider,
            &mut DeterministicPrivateCoins::new(1),
            128,
        )
        .expect("the block-streaming source covers every requested column");
        let mut exact_carry_count = 0_usize;
        for role_layout in compilation
            .moduli
            .iter()
            .flat_map(|modulus| &modulus.role_equations)
        {
            for carry_column_ordinal in role_layout.exact_integer_lift_carry_columns.iter().copied()
            {
                exact_carry_count += 1;
                let semantic_cell = variant
                    .ordered_semantic_cells
                    .iter()
                    .find(|cell| cell.column_ordinal == carry_column_ordinal)
                    .expect("exact carry semantic cell");
                let RelationBoundCertificate::ShiftedRadixRecomposition {
                    ordered_digit_column_ordinals,
                    ..
                } = &semantic_cell.bound_certificate
                else {
                    panic!("an exact carry must retain its shifted-radix certificate");
                };
                for source_column_ordinal in std::iter::once(carry_column_ordinal)
                    .chain(ordered_digit_column_ordinals.iter().copied())
                {
                    assert!(
                        streaming_pre_challenge_columns
                            .column(source_column_ordinal)
                            .is_some(),
                        "the streaming provider must materialize exact carry source column {source_column_ordinal}",
                    );
                }
            }
        }
        assert!(exact_carry_count > 0);
        let mut verified_column_evaluator = compilation
            .verified_column_evaluator(&[VerifiedTargetReleaseModulusInput {
                roles: modulus_witness.roles,
            }])
            .expect("verified public target columns");
        for (column_index, descriptor) in variant.ordered_columns().iter().enumerate() {
            let column_ordinal = u32::try_from(column_index).expect("column ordinal");
            if matches!(
                descriptor.origin(),
                RelationColumnOrigin::VerifierSequence { .. }
            ) {
                assert_eq!(
                    verified_column_evaluator
                        .evaluate_at_extension_point(column_ordinal, evaluation_point),
                    streaming_pre_challenge_columns
                        .column(column_ordinal)
                        .map(|column| column.evaluate_at(evaluation_point)),
                    "the verifier must independently reconstruct column {column_ordinal}",
                );
            } else {
                assert_eq!(
                    verified_column_evaluator
                        .evaluate_at_extension_point(column_ordinal, evaluation_point),
                    None,
                    "a non-verifier column must never enter the public evaluator",
                );
            }
        }

        let mut noncanonical_partial = partial_identifier.clone();
        noncanonical_partial[0] = modulus;
        assert!(matches!(
            compilation.verified_column_evaluator(&[VerifiedTargetReleaseModulusInput {
                roles: [
                    TargetReleaseRoleWitness {
                        converted_a: &converted_identifier,
                        partial_decryption: &noncanonical_partial,
                    },
                    modulus_witness.roles[1],
                ],
            }]),
            Err(TargetReleaseWitnessError::InvalidWitness)
        ));
    }
}
