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
    RelationIntegerLiftReversedColumnBindingDescriptor,
};
pub(crate) use layout::{
    RelationMaskDescriptor, RelationMaskKind, RelationMaskTargetClass,
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
    RelationExpressionInstruction, finite_integer_set_constraint_expressions,
    ordered_injective_integer_factor_product_expression,
    unsigned_radix_comparator_digit_expression,
};

mod aggregate_threshold_share;
mod ballot_validity;
mod committed_material;
mod interpreter;
mod key_relation;
mod public_aggregate;
mod public_key_share;
mod same_secret_anchor;
mod target_release;
mod trustee_evaluation_key;
mod vss_share_linkage;

pub(crate) use aggregate_threshold_share::compile_aggregate_threshold_share_relation_plan;
pub(crate) use ballot_validity::{
    BallotValidityRelationPlanInput, compile_ballot_validity_relation_plan,
};
pub(crate) use committed_material::CommittedMaterialRelationPlanInput;
pub(crate) use interpreter::{
    RelationApplicationChallengeAssignment, RelationConstraintEvaluation,
};
pub(crate) use key_relation::{PublicKeyShareRelationPlanInput, SameSecretRelationPlanInput};
pub(crate) use public_aggregate::{
    CollectivePublicKeyAggregatePlanInput, EvaluatorKeyAggregateEntryPlanInput,
    EvaluatorKeyAggregatePlanInput, EvaluatorKeyAggregateVariantInput,
    PublicAggregateRelationGeometry, RkgRoundOneAggregatePlanInput,
    RkgRoundOneAggregateVariantInput, compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_rkg_round_one_aggregate_relation_plan,
};
pub(crate) use public_key_share::compile_public_key_share_relation_plan;
pub(crate) use same_secret_anchor::compile_same_secret_relation_plan;
pub(crate) use target_release::{
    CompiledTargetReleaseRelation, TargetReleaseCapabilityError, TargetReleaseModulusWitness,
    TargetReleaseRelationPlanInput, TargetReleaseRoleWitness, TargetReleaseVerifiedColumnEvaluator,
    TargetReleaseWitness, TargetReleaseWitnessError, VerifiedTargetReleaseModulusInput,
    VerifiedTargetReleaseProof, compile_target_release_relation,
    compile_target_release_relation_plan, target_release_radix_semantics_match,
};
pub(crate) use trustee_evaluation_key::{
    GaloisKeyShareRelationPlanInput, RelinearizationRoundOneRelationPlanInput,
    RelinearizationRoundTwoRelationPlanInput, TrusteeEvaluationKeyDecompositionBlock,
    TrusteeEvaluationKeyRelationGeometry, compile_galois_key_share_relation_plan,
    compile_relinearization_round_one_relation_plan,
    compile_relinearization_round_two_relation_plan,
};
pub(crate) use vss_share_linkage::compile_vss_share_linkage_relation_plan;
#[cfg(test)]
mod tests;
