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
    RelationMaskCoordinate, RelationMaskDescriptor, RelationMaskKind, RelationMaskTargetClass,
    RelationOpeningClaimDescriptor, RelationOpeningPointDescriptor, RelationOpeningSourceClass,
    RelationPlanVariant,
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
mod expressions;

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

#[cfg(test)]
pub(crate) const COMMITTED_MATERIAL_TRACE_PACKING_FACTOR: u64 =
    committed_material::COMMITTED_MATERIAL_TRACE_PACKING_FACTOR;

pub(crate) use aggregate_threshold_share::compile_aggregate_threshold_share_relation_plan;
pub(crate) use ballot_validity::{
    BallotValidityColumnTransform, BallotValidityRelationPlanInput,
    BallotValiditySourceColumnRecipe, BallotValiditySourcePlan, BallotValidityVerifierColumnSource,
    BallotValidityWitnessValueSource, CompiledBallotValidityRelation,
    compile_ballot_validity_relation, compile_ballot_validity_relation_plan,
};
pub(crate) use ballot_validity_adapter::{
    BallotValidityAcceptedSetupBinding, BallotValidityAdapterError,
    BallotValidityBoundPublicMaterial, BallotValidityCiphertextReadback,
    BallotValidityCiphertextStreamDecoder, BallotValidityGenerationPreparationError,
    BallotValidityPreparedProofAttempt, BallotValidityVerifiedColumnEvaluator,
};
#[cfg(test)]
pub(crate) use ballot_validity_adapter::{
    SelectedBallotValidityCarrierBufferAccounting,
    selected_ballot_validity_carrier_buffer_accounting,
};
pub(crate) use collective_public_key_adapter::{
    CollectivePublicKeySetupPolynomialSource, CollectivePublicKeySourcePolynomialProvider,
};
#[cfg(test)]
pub(crate) use collective_public_key_adapter::{
    CollectivePublicKeySourceProviderMemoryAccounting,
    collective_public_key_source_provider_memory_accounting,
};
pub(crate) use committed_material::{
    CommittedMaterialRelationPlanInput, CommittedMaterialTraceWitnessProvider,
    CommittedMaterialTraceWitnessStructureMemoryAccounting,
    derive_aggregate_threshold_share_trace_witness_provider,
    derive_vss_share_linkage_trace_witness_provider,
};
#[cfg(test)]
pub(crate) use committed_material::{
    aggregate_threshold_share_trace_witness_structure_memory_accounting,
    vss_share_linkage_trace_witness_structure_memory_accounting,
};
pub(crate) use committed_material_adapter::CommittedMaterialSourcePolynomialAdapter;
#[cfg(test)]
pub(crate) use committed_material_adapter::{
    CommittedMaterialSourceProviderMemoryAccounting,
    aggregate_threshold_share_source_provider_memory_accounting,
    vss_share_linkage_source_provider_memory_accounting,
};
#[cfg(test)]
pub(crate) use galois_key_share_adapter::galois_key_share_source_provider_memory_accounting;
#[cfg(test)]
pub(crate) use galois_key_share_adapter::galois_key_share_topology_comparison_memory_accounting;
pub(crate) use galois_key_share_adapter::{
    GaloisKeyShareSourcePolynomialAdapter, galois_relation_tree_inputs,
};
#[cfg(test)]
pub(crate) use interpreter::DeepPointSamplerCardinalityBound;
pub(crate) use interpreter::{
    CheckedRelationApplicationChallenges, DeepCompositionVerificationInput,
    RelationApplicationChallengeAssignment,
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
#[cfg(test)]
pub(crate) use relinearization_round_one_adapter::relinearization_round_one_source_provider_memory_accounting;
pub(crate) use relinearization_round_one_adapter::{
    RelinearizationRoundOneSourcePolynomialAdapter, relinearization_round_one_relation_tree_inputs,
};
pub(crate) use relinearization_round_one_aggregate_adapter::prepare_relinearization_round_one_aggregate_source;
#[cfg(test)]
pub(crate) use relinearization_round_two_adapter::relinearization_round_two_source_provider_memory_accounting;
pub(crate) use relinearization_round_two_adapter::{
    RelinearizationRoundTwoAuthenticatedAggregateSourcePlan,
    RelinearizationRoundTwoSourcePolynomialAdapter, relinearization_round_two_relation_tree_inputs,
};
pub(crate) use same_secret_anchor::{
    SameSecretSourceLayout, compile_same_secret_relation_plan,
    compile_same_secret_relation_with_source_layout,
};
pub(crate) use setup_key_relation_adapter::{
    SetupKeyRelationSourcePolynomialAdapter, public_key_share_relation_tree_inputs,
    same_secret_relation_tree_inputs,
};
#[cfg(test)]
pub(crate) use setup_key_relation_adapter::{
    public_key_share_source_provider_memory_accounting,
    same_secret_source_provider_memory_accounting,
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
#[cfg(test)]
pub(crate) use trustee_evaluation_key::compile_galois_key_share_relation_topology_comparison;
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
