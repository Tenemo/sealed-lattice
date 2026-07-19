//! Canonical generated relation plans.
//!
//! The semantic relation owner lowers one typed definition into this module's
//! closed plan grammar. Proof bytes never choose a source, column, tree,
//! challenge, opening, or privacy mode. `CompiledRelationPlan::check` is a
//! second pass over the generated value and does not trust compiler-side
//! counters or ordering decisions.

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    ProofApplicationSlotCeilings, StreamingFoundationTupleHash512,
};

use super::transcript::{
    CommonProofApplicationChallengeGroup, CommonProofChallenge, CommonProofPrivacyMode,
    CommonProofTranscriptSchedule,
};

mod bounds;
mod compiled_plan;
mod integer_lift;
mod layout;
mod model;
mod schema;

#[cfg(test)]
use bounds::signed_integer_from_magnitude;
use bounds::{canonical_signed_integer_tuple, canonical_unsigned_magnitude_item};
use compiled_plan::RelationPlan;
use layout::challenge_descriptor;
use model::{canonical_encoding_error, validate_negacyclic_automorphism};
use schema::*;

pub(crate) use bounds::{
    RelationBoundCertificate, RelationConstraintDescriptor, SemanticCellDescriptor,
    SignedIntegerInterval,
};
pub(crate) use compiled_plan::{
    CompiledRelationPlan, ProofApplicationSlotTemplate, RelationPlanCheckContext,
    ResolvedSuiteModulus, merge_checked_relation_plan_variants,
};
pub(crate) use integer_lift::{
    RelationCoefficientLocalIdentityBatchDescriptor, RelationCoefficientLocalResidualDescriptor,
    RelationIntegerLiftBatchDescriptor, RelationIntegerLiftCoefficient,
    RelationIntegerLiftComponentDescriptor, RelationIntegerLiftConstraintProgram,
    RelationIntegerLiftConvolutionKind, RelationIntegerLiftConvolutionProductDescriptor,
    RelationIntegerLiftFullRingHalf, RelationIntegerLiftFullRingNegacyclicProductDescriptor,
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
    RelationChallengeDescriptor, RelationChallengeEpochCatalog,
    RelationChallengeEpochPrecedingMessage, RelationChallengeModulusSelector,
    RelationChallengeRole, RelationChallengeSampling, RelationColumnDescriptor,
    RelationColumnOrigin, RelationColumnValueType, RelationElementKind, RelationEmbeddingKind,
    RelationPlanError, RelationPublicSamplerDescriptor, RelationRadixConvolutionDescriptor,
    RelationRadixFactorDescriptor, RelationRadixProductTermDescriptor, RelationSelectorPathStep,
    RelationTreeDescriptor, RelationValueLayout, RelationVerifierSource,
    ResolvedRelationChallengeSampling, SelectorPathStepKind, SuiteModulusReference,
    apply_negacyclic_automorphism, negacyclic_automorphism_mapping_values,
    negacyclic_automorphism_semantics_match, radix_decompose_scaled_residues,
};
mod checking;
mod expressions;

use checking::{
    RelationPlanChecker, derive_semantic_cell_interval, full_trace_zeroifier_expression,
    integer_lift_maximum_absolute_product, zeroifier_roots_are_confined_to_trace_domain,
};
use expressions::*;

pub(crate) use expressions::{
    RelationConstraintColumnQuery, RelationExpressionInstruction,
    finite_integer_set_constraint_expressions, ordered_injective_integer_factor_product_expression,
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

pub(crate) use aggregate_threshold_share::compile_aggregate_threshold_share_relation_plan;
pub(crate) use ballot_validity::{
    BallotValidityColumnTransform, BallotValidityRelationPlanInput,
    BallotValiditySourceColumnRecipe, BallotValiditySourcePlan, BallotValidityVerifierColumnSource,
    BallotValidityWitnessValueSource, CompiledBallotValidityRelation,
    compile_ballot_validity_relation, compile_ballot_validity_relation_plan,
};
pub(crate) use ballot_validity_adapter::{
    BallotValidityAcceptedSetupBinding, BallotValidityAdapterError,
    BallotValidityAuthenticatedCiphertext, BallotValidityBoundPublicMaterial,
    BallotValidityCiphertextReadback, BallotValidityCiphertextStreamDecoder,
    BallotValidityEncryptionAttemptWitness, BallotValidityGeneratedCiphertext,
    BallotValidityGenerationPreparationError, BallotValidityPreparedProofAttempt,
    BallotValiditySourcePolynomialAdapter, BallotValidityVerifiedColumnEvaluator,
    SelectedBallotValidityCarrierBufferAccounting,
    ballot_encryption_private_randomness_kmac_input_accounting,
    proof_created_relation_tree_inputs_from_checked_variant,
    selected_ballot_validity_carrier_buffer_accounting,
};
pub(crate) use collective_public_key_adapter::{
    CollectivePublicKeySetupPolynomialSource, CollectivePublicKeySourcePolynomialProvider,
    CollectivePublicKeySourceProviderMemoryAccounting,
    collective_public_key_source_provider_memory_accounting,
};
pub(crate) use committed_material::{
    CommittedMaterialRelationPlanInput, CommittedMaterialRootTraceRows,
    CommittedMaterialTraceWitnessProvider, CommittedMaterialTraceWitnessStructureMemoryAccounting,
    aggregate_threshold_share_trace_witness_structure_memory_accounting,
    derive_aggregate_threshold_share_trace_witness_provider,
    derive_owned_aggregate_threshold_share_trace_witness_provider,
    derive_owned_vss_share_linkage_trace_witness_provider,
    derive_vss_share_linkage_trace_witness_provider,
    vss_share_linkage_trace_witness_structure_memory_accounting,
};
pub(crate) use committed_material_adapter::{
    CommittedMaterialSourcePolynomialAdapter, CommittedMaterialSourceProviderMemoryAccounting,
    aggregate_threshold_share_source_provider_memory_accounting,
    vss_share_linkage_source_provider_memory_accounting,
};
pub(crate) use galois_key_share_adapter::{
    GaloisKeyShareSourcePolynomialAdapter, GaloisKeyShareSourceProviderMemoryAccounting,
    galois_key_share_source_provider_memory_accounting, galois_relation_tree_inputs,
};
pub(crate) use interpreter::{
    CheckedRelationApplicationChallenges, RelationApplicationChallengeAssignment,
    RelationConstraintEvaluation,
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
    RelinearizationRoundTwoSourcePolynomialAdapter,
    RelinearizationRoundTwoSourceProviderMemoryAccounting,
    relinearization_round_two_relation_tree_inputs,
    relinearization_round_two_source_provider_memory_accounting,
};
pub(crate) use same_secret_anchor::{
    SameSecretSourceLayout, compile_same_secret_relation_plan,
    compile_same_secret_relation_with_source_layout,
};
pub(crate) use setup_key_relation_adapter::{
    SetupKeyRelationSourcePolynomialAdapter, public_key_share_relation_tree_inputs,
    same_secret_relation_tree_inputs,
};
pub(crate) use target_release::{
    CompiledTargetReleaseRelation, TargetReleaseCapabilityError, TargetReleaseModulusWitness,
    TargetReleaseRelationPlanInput, TargetReleaseRoleWitness, TargetReleaseSourcePolynomialAdapter,
    TargetReleaseVerifiedColumnEvaluator, TargetReleaseWitness, TargetReleaseWitnessError,
    TargetReleaseWitnessSource, VerifiedTargetReleaseModulusInput, VerifiedTargetReleaseProof,
    compile_target_release_relation, compile_target_release_relation_plan,
    target_release_radix_semantics_match,
};
pub(crate) use trustee_evaluation_key::{
    CompiledRelinearizationRoundOneRelation, CompiledRelinearizationRoundTwoRelation,
    GaloisKeyShareRelationEntryInput, GaloisKeyShareRelationPlanInput,
    RelinearizationRoundOneRelationPlanInput, RelinearizationRoundOneSourceLayout,
    RelinearizationRoundTwoRelationPlanInput, RelinearizationRoundTwoSourceLayout,
    TrusteeEvaluationKeyDecompositionBlock, TrusteeEvaluationKeyRelationBasis,
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
