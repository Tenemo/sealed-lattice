use std::collections::BTreeMap;

use super::key_relation::{
    AnchorEquationInputs, AnchorOpeningWitness, AnchorQuotientWitness, BoundPolynomialRootUse,
    KeyRelationGeometry, KeyRelationPlanBuilder, KeyVerifierSourceKey, PublicKeyEquationInputs,
    PublicKeyShareRelationPlanInput, QuarterBackedSplitIntegerVector, ReversibleShiftedSmallVector,
    ShiftedSmallVector, SplitIntegerVector, public_key_common_reference_source,
    statement_root_source,
};
use super::same_secret_anchor::{add_matrix_columns, append_matrix_sources};
use super::*;

const PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 =
    crate::foundation::ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
const ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL: u64 = 3;
const PUBLIC_KEY_SHARE_ROOT_FIELD_ORDINAL: u64 = 4;

pub(crate) struct CompiledPublicKeyShareRelation {
    pub(crate) relation_plan: CompiledRelationPlan,
    pub(crate) source_layout: PublicKeyShareSourceLayout,
}

pub(crate) struct PublicKeyShareSourceLayout {
    pub(super) common_secret: ReversibleShiftedSmallVector,
    pub(super) public_key_error: ShiftedSmallVector,
    pub(super) public_key_share_limbs: Box<[QuarterBackedSplitIntegerVector]>,
    pub(super) ordered_limbs: Box<[PublicKeyShareLimbSourceLayout]>,
    pub(super) ordered_anchors: Box<[PublicKeyShareAnchorSourceLayout]>,
    pub(super) exact_radix_digits_by_column: BTreeMap<u32, Box<[u32]>>,
}

pub(super) struct PublicKeyShareLimbSourceLayout {
    pub(super) data_modulus_index: u16,
    pub(super) common_reference: SplitIntegerVector,
    pub(super) quotient_columns: [u32; 2],
}

pub(super) struct PublicKeyShareAnchorSourceLayout {
    pub(super) data_modulus_index: u16,
    pub(super) opening: AnchorOpeningWitness,
    pub(super) commitments: Box<[SplitIntegerVector]>,
    pub(super) first_matrix: Box<[Box<[SplitIntegerVector]>]>,
    pub(super) second_matrix: Box<[SplitIntegerVector]>,
    pub(super) quotients: AnchorQuotientWitness,
}

pub(crate) fn compile_public_key_share_relation_plan(
    input: &PublicKeyShareRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    compile_public_key_share_relation_with_source_layout(input, check_context)
        .map(|compiled| compiled.relation_plan)
}

pub(crate) fn compile_public_key_share_relation_with_source_layout(
    input: &PublicKeyShareRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledPublicKeyShareRelation, RelationPlanError> {
    let rank = usize::from(input.commitment_module_rank);
    let mut sources = vec![statement_root_source(
        PUBLIC_KEY_SHARE_ROOT_FIELD_ORDINAL,
        None,
    )];
    for (root_ordinal, data_modulus_index) in input
        .commitment_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        sources.push(statement_root_source(
            ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL,
            Some(u64::try_from(root_ordinal).map_err(|_| RelationPlanError::CountOverflow)?),
        ));
        append_matrix_sources(&mut sources, input.ring_degree, data_modulus_index, rank)?;
    }
    for data_modulus_index in input.data_modulus_indices.iter().copied() {
        sources.push(public_key_common_reference_source(
            input.ring_degree,
            data_modulus_index,
        ));
    }
    let geometry = KeyRelationGeometry::for_public_key_share(input);
    let mut builder = KeyRelationPlanBuilder::new(
        PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        &geometry,
        check_context,
        sources,
    )?;
    let secret = builder.add_reversible_shifted_ternary_vector()?;
    let public_key_error = builder.add_shifted_eta_two_vector()?;
    let data_modulus_references = input
        .data_modulus_indices
        .iter()
        .copied()
        .map(SuiteModulusReference::data)
        .collect::<Vec<_>>();
    let public_key_share_limbs = builder.add_setup_polynomial_limb_root(
        &KeyVerifierSourceKey::StatementRoot {
            field_ordinal: PUBLIC_KEY_SHARE_ROOT_FIELD_ORDINAL,
            list_ordinal: None,
        },
        &data_modulus_references,
        BoundPolynomialRootUse::Output,
    )?;
    let mut limb_source_layouts = Vec::with_capacity(input.data_modulus_indices.len());
    for (limb_ordinal, data_modulus_index) in input.data_modulus_indices.iter().copied().enumerate()
    {
        let modulus_reference = SuiteModulusReference::data(data_modulus_index);
        let common_reference = builder.add_split_verifier_vector(
            &KeyVerifierSourceKey::PublicKeyCommonReference { data_modulus_index },
            modulus_reference,
        )?;
        let quotient_columns = builder.add_public_key_quotient_witness()?;
        for challenge_ordinal in 0..check_context.non_native_modular_identity_challenge_count {
            builder.add_public_key_equation(
                modulus_reference,
                challenge_ordinal,
                PublicKeyEquationInputs::new(
                    &public_key_share_limbs[limb_ordinal].half_projections,
                    &common_reference,
                    &secret,
                    &public_key_error,
                    quotient_columns,
                ),
            )?;
        }
        limb_source_layouts.push(PublicKeyShareLimbSourceLayout {
            data_modulus_index,
            common_reference,
            quotient_columns,
        });
    }
    let mut anchor_source_layouts = Vec::with_capacity(input.commitment_data_modulus_indices.len());
    for (root_ordinal, data_modulus_index) in input
        .commitment_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        // Prime-limb commitments use independent openings while sharing only
        // the bounded semantic secret proved by the cross-limb relation.
        let opening = builder.add_anchor_opening_witness()?;
        let modulus_reference = SuiteModulusReference::data(data_modulus_index);
        let commitments = builder.add_setup_polynomial_root(
            &KeyVerifierSourceKey::StatementRoot {
                field_ordinal: ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL,
                list_ordinal: Some(
                    u64::try_from(root_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ),
            },
            modulus_reference,
            rank.checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?,
            BoundPolynomialRootUse::Input,
        )?;
        let (first_matrix, second_matrix) =
            add_matrix_columns(&mut builder, data_modulus_index, rank)?;
        let quotients = builder.add_anchor_quotient_witness()?;
        for challenge_ordinal in 0..check_context.non_native_modular_identity_challenge_count {
            builder.add_anchor_equations(
                modulus_reference,
                challenge_ordinal,
                AnchorEquationInputs::new(
                    &commitments,
                    &first_matrix,
                    &second_matrix,
                    &opening,
                    &secret.source,
                    &quotients,
                ),
            )?;
        }
        anchor_source_layouts.push(PublicKeyShareAnchorSourceLayout {
            data_modulus_index,
            opening,
            commitments: commitments.into_boxed_slice(),
            first_matrix: first_matrix
                .into_iter()
                .map(Vec::into_boxed_slice)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            second_matrix: second_matrix.into_boxed_slice(),
            quotients,
        });
    }
    let exact_radix_digits_by_column = builder
        .exact_radix_digits_by_column()
        .iter()
        .map(|(column_ordinal, digit_column_ordinals)| {
            (
                *column_ordinal,
                digit_column_ordinals.clone().into_boxed_slice(),
            )
        })
        .collect();
    let relation_plan = builder.finish()?;
    Ok(CompiledPublicKeyShareRelation {
        relation_plan,
        source_layout: PublicKeyShareSourceLayout {
            common_secret: secret,
            public_key_error,
            public_key_share_limbs: public_key_share_limbs.into_boxed_slice(),
            ordered_limbs: limb_source_layouts.into_boxed_slice(),
            ordered_anchors: anchor_source_layouts.into_boxed_slice(),
            exact_radix_digits_by_column,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::super::same_secret_anchor::tests::{
        TEST_EVALUATION_DOMAIN_SIZE, TEST_OPENING_DEGREE_BOUND_EXCLUSIVE, TEST_RING_DEGREE,
        application_challenges, check_context, production_context, proof_tree_width,
    };
    use super::*;
    use crate::bgv::proof_suite::field::{ProofBaseFieldElement, ProofChallengeExtensionElement};

    fn public_key_input() -> PublicKeyShareRelationPlanInput {
        PublicKeyShareRelationPlanInput {
            ring_degree: TEST_RING_DEGREE,
            evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: TEST_OPENING_DEGREE_BOUND_EXCLUSIVE,
            public_polynomial_column_degree_bound_exclusive: TEST_RING_DEGREE,
            data_modulus_indices: vec![0, 1, 2],
            commitment_data_modulus_indices: vec![0, 1, 2],
            commitment_module_rank: 1,
            plaintext_modulus: 257,
        }
    }

    #[test]
    fn public_key_share_plan_is_checked_and_interpretable() {
        let context = check_context(true);
        let plan = compile_public_key_share_relation_plan(&public_key_input(), &context)
            .expect("public-key-share relation plan");
        let variant = plan
            .select_variant(None, None)
            .expect("public-key-share plan variant");
        let challenges = application_challenges(variant, &context);
        let evaluation_point = ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(context.evaluation_coset_offset)
                .expect("evaluation point"),
        );
        let evaluations = variant
            .evaluate_constraints_at_point(&context, evaluation_point, &challenges, |_, _, _| {
                Ok(ProofChallengeExtensionElement::ZERO)
            })
            .expect("every generated constraint is interpretable");
        assert_eq!(evaluations.len(), variant.ordered_constraints.len());
        assert_eq!(
            variant.evaluate_constraints_at_point(
                &context,
                evaluation_point,
                &challenges[..challenges.len() - 1],
                |_, _, _| Ok(ProofChallengeExtensionElement::ZERO),
            ),
            Err(RelationPlanError::InvalidChallengeCatalog)
        );
        eprintln!(
            "public-key-share columns={} constraints={} trees={} base_width={} auxiliary_width={}",
            variant.ordered_columns.len(),
            variant.ordered_constraints.len(),
            variant.ordered_trees.len(),
            proof_tree_width(variant, 1),
            proof_tree_width(variant, 2),
        );
    }

    #[test]
    fn public_key_share_plan_rejects_plaintext_and_basis_mutations() {
        let context = check_context(true);
        let mut wrong_plaintext = public_key_input();
        wrong_plaintext.plaintext_modulus = 263;
        assert_eq!(
            compile_public_key_share_relation_plan(&wrong_plaintext, &context),
            Err(RelationPlanError::InvalidModulus)
        );
        let mut missing_data_limb = public_key_input();
        missing_data_limb.data_modulus_indices = vec![1];
        assert_eq!(
            compile_public_key_share_relation_plan(&missing_data_limb, &context),
            Err(RelationPlanError::NonCanonicalOrder)
        );
        let mut unsupported_commitment_rank = public_key_input();
        unsupported_commitment_rank.commitment_module_rank = 2;
        assert_eq!(
            compile_public_key_share_relation_plan(&unsupported_commitment_rank, &context),
            Err(RelationPlanError::InvalidDomain)
        );
    }

    #[test]
    fn public_key_share_production_profile_closes_the_degree_fixed_point() {
        let context = production_context(true);
        let plan = compile_public_key_share_relation_plan(
            &PublicKeyShareRelationPlanInput {
                ring_degree: crate::bgv::parameters::POLYNOMIAL_DEGREE as u64,
                evaluation_domain_size: crate::bgv::proof_suite::selected_profile::SELECTED_EVALUATION_DOMAIN_SIZE,
                opening_degree_bound_exclusive: crate::bgv::proof_suite::selected_profile::SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
                public_polynomial_column_degree_bound_exclusive: crate::bgv::proof_suite::selected_profile::SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
                data_modulus_indices: (0..crate::bgv::parameters::DATA_PRIMES.len() as u16).collect(),
                commitment_data_modulus_indices: vec![0, 1, 2],
                commitment_module_rank: 1,
                plaintext_modulus: crate::bgv::parameters::PLAINTEXT_MODULUS,
            },
            &context,
        )
        .expect("production public-key-share relation plan");
        plan.check(&context)
            .expect("checked production public-key-share relation plan");
    }
}
