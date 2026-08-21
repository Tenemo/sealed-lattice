//! Canonical generated relation plans.
//!
//! The semantic relation owner lowers one typed definition into this module's
//! closed plan grammar. Proof bytes never choose a source, column, tree,
//! challenge, opening, or privacy mode. `CompiledRelationPlan::check` is a
//! second pass over the generated value and does not trust compiler-side
//! counters or ordering decisions.

use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use crate::foundation::ProofApplicationSlotCeilings;

mod bounds;
mod compiled_plan;
mod integer_lift;
mod layout;
mod model;
mod schema;

#[cfg(test)]
use bounds::{
    canonical_signed_integer_tuple, canonical_unsigned_magnitude_item,
    signed_integer_from_magnitude,
};
use compiled_plan::RelationPlan;
#[cfg(test)]
use schema::*;

pub(crate) use bounds::{
    RelationBoundCertificate, RelationConstraintDescriptor, SemanticCellDescriptor,
    SignedIntegerInterval,
};
pub(crate) use compiled_plan::{
    CompiledRelationPlan, RelationPlanCheckContext, ResolvedSuiteModulus,
};
pub(crate) use integer_lift::{
    RelationCoefficientLocalIdentityBatchDescriptor, RelationCoefficientLocalResidualDescriptor,
    RelationIntegerLiftBatchDescriptor, RelationIntegerLiftCoefficient,
    RelationIntegerLiftComponentDescriptor, RelationIntegerLiftConvolutionKind,
    RelationIntegerLiftConvolutionProductDescriptor, RelationIntegerLiftFullRingHalf,
    RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    RelationIntegerLiftLinearTermDescriptor,
    RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor,
    RelationIntegerLiftReversedColumnBindingDescriptor, resolved_modulus_radix_digit,
};
pub(crate) use layout::{
    RelationCompactTraceEncoding, RelationMaskCoordinate, RelationMaskDescriptor, RelationMaskKind,
    RelationMaskTargetClass, RelationOpeningClaimDescriptor, RelationOpeningPointDescriptor,
    RelationOpeningSourceClass, RelationPlanVariant,
};
pub(crate) use model::{
    BoundTreeConstructionKind, BoundTreeRootUse, ModulusCatalog, ProofPrivacyMode,
    RelationChallengeRole, RelationColumnDescriptor, RelationColumnOrigin, RelationColumnValueType,
    RelationElementKind, RelationEmbeddingKind, RelationPlanError, RelationSelectorPathStep,
    RelationTreeDescriptor, RelationValueLayout, RelationVerifierSource, SelectorPathStepKind,
    SuiteModulusReference, apply_negacyclic_automorphism, negacyclic_automorphism_mapping_values,
    radix_decompose_scaled_residues,
};
#[cfg(test)]
pub(crate) use model::{
    RelationChallengeModulusSelector, RelationChallengeSampling,
    RelationRadixConvolutionDescriptor, RelationRadixFactorDescriptor,
    RelationRadixProductTermDescriptor, negacyclic_automorphism_semantics_match,
};
mod checking;
mod compact_ring_vector;
mod expressions;

#[cfg(all(test, feature = "theorem-evidence"))]
pub(crate) const fn relation_plan_identity_hash_domains() -> (&'static str, &'static str) {
    (
        schema::RELATION_PLAN_HASH_DOMAIN,
        schema::RELATION_PLAN_VARIANT_HASH_DOMAIN,
    )
}

use checking::{RelationPlanChecker, full_trace_zeroifier_expression};
#[cfg(test)]
use checking::{
    derive_semantic_cell_interval, integer_lift_maximum_absolute_product,
    zeroifier_roots_are_confined_to_trace_domain,
};
use expressions::*;

#[cfg(test)]
pub(crate) use expressions::finite_integer_set_constraint_expressions;
pub(crate) use expressions::{
    RelationConstantColumnVerifierSequenceProductTerm, RelationConstraintColumnQuery,
    RelationExpressionInstruction, ordered_injective_integer_factor_product_expression,
    unsigned_radix_comparator_digit_expression,
};

mod aggregate_threshold_share;
mod ballot_validity;
mod ballot_validity_adapter;
mod collective_public_key_adapter;
mod committed_material;
mod committed_material_adapter;
mod galois_key_share_adapter;
mod interpreter;
mod key_relation;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod production_source_witness_oracle;
mod public_aggregate;
mod public_key_share;
mod relinearization_round_one_adapter;
mod relinearization_round_one_aggregate_adapter;
mod relinearization_round_two_adapter;
mod same_secret_anchor;
mod setup_key_relation_adapter;
mod target_release;
mod trustee_evaluation_key;
mod verified_key_relation_column_evaluator;
mod vss_share_linkage;

pub(crate) const COMMITTED_MATERIAL_TRACE_PACKING_FACTOR: u64 =
    committed_material::COMMITTED_MATERIAL_TRACE_PACKING_FACTOR;

pub(crate) use aggregate_threshold_share::compile_aggregate_threshold_share_relation_plan;
pub(crate) use ballot_validity::{
    BallotValidityColumnTransform, BallotValidityRelationPlanInput,
    BallotValiditySourceColumnRecipe, BallotValiditySourcePlan, BallotValidityVerifierColumnSource,
    BallotValidityWitnessValueSource, CompiledBallotValidityRelation,
    compile_ballot_validity_relation, compile_ballot_validity_relation_plan,
};
#[cfg(test)]
pub(crate) use ballot_validity_adapter::selected_ballot_validity_carrier_buffer_accounting;
pub(crate) use ballot_validity_adapter::{
    BallotValidityAcceptedSetupBinding, BallotValidityAdapterError,
    BallotValidityBoundPublicMaterial, BallotValidityCiphertextReadback,
    BallotValidityCiphertextStreamDecoder, BallotValidityGenerationPreparationError,
    BallotValidityPreparedProofAttempt, BallotValidityVerifiedColumnEvaluator,
};
pub(crate) use collective_public_key_adapter::{
    CollectivePublicKeySetupPolynomialSource, CollectivePublicKeySourcePolynomialProvider,
};
#[cfg(test)]
pub(crate) use collective_public_key_adapter::{
    CollectivePublicKeySourceProviderMemoryAccounting,
    collective_public_key_source_provider_memory_accounting,
};
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) use committed_material::SelectedVssSourceReplayMeasurement;
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) use committed_material::derive_vss_relation_packing_candidate_geometry;
#[cfg(test)]
pub(crate) use committed_material::vss_share_linkage_trace_witness_structure_memory_accounting;
pub(crate) use committed_material::{
    CommittedMaterialRelationPlanInput, CommittedMaterialTraceWitnessProvider,
    CommittedMaterialTraceWitnessStructureMemoryAccounting,
    derive_aggregate_threshold_share_trace_witness_provider,
    derive_vss_share_linkage_trace_witness_provider,
};
#[cfg(all(feature = "primitive-measurement-evidence", test))]
pub(crate) use committed_material::{
    derive_vss_relation_range_arity_candidate_geometry, vss_fused_bound_range_candidate_inventory,
    vss_fused_bound_range_trace_witness_structure_memory_accounting,
    vss_relation_range_digit_prover_column_ordinals, vss_relation_trinary_prover_column_ordinals,
};
pub(crate) use committed_material_adapter::CommittedMaterialSourcePolynomialAdapter;
#[cfg(all(feature = "primitive-measurement-evidence", test))]
pub(crate) use committed_material_adapter::fused_vss_radix_51_source_provider_memory_accounting;
#[cfg(test)]
pub(crate) use committed_material_adapter::selected_vss_source_provider_memory_accounting;
pub(crate) use compact_ring_vector::derive_compact_public_key_relation_catalog;
#[cfg(test)]
pub(crate) use compact_ring_vector::{
    CompactLookupRelationGeometry, compact_structured_r1cs_row_source_geometry,
    compact_structured_witness_covector_geometry,
};
pub(crate) use compact_ring_vector::{
    CompactPublicKeyRelationCatalog, selected_compact_public_key_relation_catalog,
};
pub(crate) use compact_ring_vector::{
    CompactStructuredWitnessCovectorAccumulator, CompactStructuredWitnessCovectorAccumulatorPoll,
    StructuredTransposeValueSource,
};
pub(crate) use galois_key_share_adapter::{
    GaloisKeyShareSourcePolynomialAdapter, galois_relation_tree_inputs,
};
#[cfg(test)]
pub(crate) use interpreter::OutOfDomainPointSamplerCardinalityBound;
pub(crate) use interpreter::{
    CheckedRelationApplicationChallenges, OutOfDomainCompositionVerificationInput,
    RelationApplicationChallengeAssignment,
};
#[cfg(all(test, feature = "theorem-evidence"))]
pub(crate) use interpreter::{
    RelationCompilerInterpreterSemanticCertificate, checked_relation_compiler_interpreter_semantics,
};
#[cfg(test)]
pub(crate) use key_relation::MODULAR_QUOTIENT_BIT_COUNT;
#[cfg(test)]
pub(crate) use key_relation::{MODULAR_QUOTIENT_MAXIMUM, MODULAR_QUOTIENT_MINIMUM};
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
pub(crate) use key_relation::{
    MODULAR_QUOTIENT_VALUE_COUNT, TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE,
};
pub(crate) use key_relation::{PublicKeyShareRelationPlanInput, SameSecretRelationPlanInput};
pub(crate) use public_aggregate::{
    CollectivePublicKeyAggregatePlanInput, EvaluatorKeyAggregateEntryPlanInput,
    EvaluatorKeyAggregatePlanInput, EvaluatorKeyAggregateVariantInput,
    PublicAggregateRelationGeometry, RkgRoundOneAggregatePlanInput,
    RkgRoundOneAggregateVariantInput, compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_rkg_round_one_aggregate_relation_plan,
};
pub(crate) use public_key_share::{
    PublicKeyShareSourceLayout, compile_public_key_share_relation_plan,
    compile_public_key_share_relation_with_source_layout,
};
pub(crate) use relinearization_round_one_adapter::{
    RelinearizationRoundOneSourcePolynomialAdapter, relinearization_round_one_relation_tree_inputs,
};
pub(crate) use relinearization_round_one_aggregate_adapter::prepare_relinearization_round_one_aggregate_source;
pub(crate) use relinearization_round_two_adapter::{
    RelinearizationRoundTwoAuthenticatedAggregateSourcePlan,
    RelinearizationRoundTwoSourcePolynomialAdapter, relinearization_round_two_relation_tree_inputs,
};
pub(crate) use same_secret_anchor::{
    SameSecretSourceLayout, compile_same_secret_relation_plan,
    compile_same_secret_relation_with_source_layout,
};
#[cfg(test)]
pub(crate) use setup_key_relation_adapter::same_secret_source_provider_memory_accounting;
pub(crate) use setup_key_relation_adapter::{
    SetupKeyRelationSourcePolynomialAdapter, public_key_share_relation_tree_inputs,
    same_secret_relation_tree_inputs,
};
#[cfg(test)]
pub(crate) use target_release::target_release_source_provider_memory_accounting_for_source;
pub(crate) use target_release::{
    CompiledTargetReleaseRelation, TargetReleaseModulusWitness, TargetReleaseRelationPlanInput,
    TargetReleaseRoleWitness, TargetReleaseSourcePolynomialAdapter,
    TargetReleaseVerifiedColumnEvaluator, TargetReleaseWitnessError, TargetReleaseWitnessSource,
    TargetReleaseWitnessSourceMemoryAccounting, VerifiedTargetReleaseModulusInput,
    VerifiedTargetReleaseProof, compile_target_release_relation,
};
pub(crate) use trustee_evaluation_key::{
    GaloisKeyShareRelationEntryInput, GaloisKeyShareRelationPlanInput,
    RelinearizationRoundOneRelationPlanInput, RelinearizationRoundTwoRelationPlanInput,
    TrusteeEvaluationKeyRelationGeometry, compile_galois_key_share_relation_plan,
    compile_galois_key_share_relation_with_source_layout,
    compile_relinearization_round_one_relation_plan,
    compile_relinearization_round_one_relation_with_source_layout,
    compile_relinearization_round_two_relation_plan,
    compile_relinearization_round_two_relation_with_source_layout,
    selected_galois_key_share_batch_schedule,
    trustee_evaluation_key_relation_basis_for_catalog_level,
};
pub(crate) use verified_key_relation_column_evaluator::VerifiedKeyRelationColumnEvaluator;
pub(crate) use vss_share_linkage::compile_vss_share_linkage_relation_plan;
#[cfg(test)]
mod tests;
