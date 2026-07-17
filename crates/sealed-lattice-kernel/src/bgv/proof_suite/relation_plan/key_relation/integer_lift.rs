use super::super::{
    integer_lift::{
        RelationIntegerLiftBatchDescriptor, RelationIntegerLiftCoefficient,
        RelationIntegerLiftComponentDescriptor, RelationIntegerLiftFullRingHalf,
        RelationIntegerLiftFullRingNegacyclicProductDescriptor,
        RelationIntegerLiftLinearTermDescriptor,
        RelationIntegerLiftReversedColumnBindingDescriptor,
    },
    model::{RelationPlanError, SuiteModulusReference},
};
use super::{
    AnchorEquationInputs, KeyRelationPlanBuilder, ProofTreePhase, PublicKeyEquationInputs,
    ReversibleShiftedSmallVector, ShiftedSmallVector, SplitIntegerVector,
    TrusteeAnchorOpeningWitness, TrusteeRadixThreeQuotientWitness,
    column_builder::{
        constant_linear_term, integer_lift_half, plaintext_scaled_linear_term,
        scaled_constant_linear_term, sort_canonical_items, trustee_quotient_carry_linear_term,
    },
};

impl<'context> KeyRelationPlanBuilder<'context> {
    pub(in crate::bgv::proof_suite::relation_plan) fn ensure_reversed_vector_bindings(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        vector: &ReversibleShiftedSmallVector,
    ) -> Result<(), RelationPlanError> {
        for half_ordinal in 0..2 {
            let source_column_ordinal = vector.source.coefficients.halves[half_ordinal];
            let reversed_column_ordinal = vector.reversed.halves[half_ordinal];
            let binding_key = (source_column_ordinal, reversed_column_ordinal);
            let already_present = self
                .pending_integer_lift_batches
                .get(&batch_key)
                .is_some_and(|batch| batch.reversed_bindings.contains_key(&binding_key));
            if already_present {
                continue;
            }
            let binding = RelationIntegerLiftReversedColumnBindingDescriptor {
                source_column_ordinal,
                reversed_column_ordinal,
                source_prefix_evaluation_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                reversed_suffix_evaluation_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
            };
            if self
                .pending_integer_lift_batches
                .entry(batch_key)
                .or_default()
                .reversed_bindings
                .insert(binding_key, binding)
                .is_some()
            {
                return Err(RelationPlanError::DuplicateItem);
            }
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn full_ring_product(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        selected_half: RelationIntegerLiftFullRingHalf,
        negative: bool,
        multiplicand: SplitIntegerVector,
        multiplier: &ReversibleShiftedSmallVector,
    ) -> Result<RelationIntegerLiftFullRingNegacyclicProductDescriptor, RelationPlanError> {
        self.ensure_reversed_vector_bindings(batch_key, multiplier)?;
        Ok(RelationIntegerLiftFullRingNegacyclicProductDescriptor {
            negative,
            selected_half,
            multiplicand_low_column_ordinal: multiplicand.halves[0],
            multiplicand_high_column_ordinal: multiplicand.halves[1],
            multiplier_low_column_ordinal: multiplier.source.coefficients.halves[0],
            multiplier_high_column_ordinal: multiplier.source.coefficients.halves[1],
            reversed_multiplier_low_column_ordinal: multiplier.reversed.halves[0],
            reversed_multiplier_high_column_ordinal: multiplier.reversed.halves[1],
            multiplier_low_offset: multiplier.source.offset,
            multiplier_high_offset: multiplier.source.offset,
            multiplicand_low_suffix_evaluation_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
            multiplicand_high_suffix_evaluation_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
            reversed_multiplier_low_transpose_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
            reversed_multiplier_high_transpose_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_integer_lift_component(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        quotient_column_ordinal: u32,
        mut ordered_linear_terms: Vec<RelationIntegerLiftLinearTermDescriptor>,
        mut ordered_full_ring_negacyclic_products: Vec<
            RelationIntegerLiftFullRingNegacyclicProductDescriptor,
        >,
    ) -> Result<(), RelationPlanError> {
        sort_canonical_items(&mut ordered_linear_terms, |term| term.canonical_bytes())?;
        sort_canonical_items(&mut ordered_full_ring_negacyclic_products, |product| {
            product.canonical_bytes()
        })?;
        let component = RelationIntegerLiftComponentDescriptor {
            quotient_is_negative: true,
            quotient_column_ordinal,
            ordered_linear_terms,
            ordered_convolution_products: Vec::new(),
            ordered_full_ring_negacyclic_products,
            linear_evaluation_column_ordinal: self.push_prover_column(ProofTreePhase::Auxiliary)?,
            product_accumulator_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
        };
        self.pending_integer_lift_batches
            .entry(batch_key)
            .or_default()
            .components
            .push(component);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::bgv::proof_suite::relation_plan) fn add_relinearization_round_one_equations(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        round_one_left: &SplitIntegerVector,
        round_one_right: &SplitIntegerVector,
        common_reference: SplitIntegerVector,
        secret: &ReversibleShiftedSmallVector,
        ephemeral_secret: &ReversibleShiftedSmallVector,
        round_one_left_error: &ShiftedSmallVector,
        round_one_right_error: &ShiftedSmallVector,
        gadget_coefficient: u64,
        left_quotient: TrusteeRadixThreeQuotientWitness,
        right_quotient: TrusteeRadixThreeQuotientWitness,
    ) -> Result<(), RelationPlanError> {
        let modulus = self.modulus(modulus_reference)?;
        if secret.source.offset != 0
            || ephemeral_secret.source.offset != 0
            || round_one_left_error.offset != 0
            || round_one_right_error.offset != 0
            || gadget_coefficient >= modulus
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let mut left_linear_terms = vec![
                constant_linear_term(round_one_left.halves[half_ordinal], 0, false),
                plaintext_scaled_linear_term(
                    round_one_left_error.coefficients.halves[half_ordinal],
                    true,
                ),
                trustee_quotient_carry_linear_term(
                    left_quotient.high_carries[half_ordinal],
                    modulus_reference,
                ),
            ];
            if gadget_coefficient != 0 {
                left_linear_terms.push(scaled_constant_linear_term(
                    secret.source.coefficients.halves[half_ordinal],
                    true,
                    gadget_coefficient,
                ));
            }
            let common_reference_times_ephemeral = self.full_ring_product(
                batch_key,
                selected_half,
                false,
                common_reference,
                ephemeral_secret,
            )?;
            self.add_integer_lift_component(
                batch_key,
                left_quotient.low_quotients[half_ordinal],
                left_linear_terms,
                vec![common_reference_times_ephemeral],
            )?;

            let common_reference_times_secret =
                self.full_ring_product(batch_key, selected_half, true, common_reference, secret)?;
            self.add_integer_lift_component(
                batch_key,
                right_quotient.low_quotients[half_ordinal],
                vec![
                    constant_linear_term(round_one_right.halves[half_ordinal], 0, false),
                    plaintext_scaled_linear_term(
                        round_one_right_error.coefficients.halves[half_ordinal],
                        true,
                    ),
                    trustee_quotient_carry_linear_term(
                        right_quotient.high_carries[half_ordinal],
                        modulus_reference,
                    ),
                ],
                vec![common_reference_times_secret],
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::bgv::proof_suite::relation_plan) fn add_relinearization_round_two_equation(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        round_two: &SplitIntegerVector,
        aggregate_round_one_left: &ReversibleShiftedSmallVector,
        aggregate_round_one_right: &ReversibleShiftedSmallVector,
        secret: &ReversibleShiftedSmallVector,
        ephemeral_secret: &ReversibleShiftedSmallVector,
        round_two_error: &ShiftedSmallVector,
        quotient: TrusteeRadixThreeQuotientWitness,
    ) -> Result<(), RelationPlanError> {
        let modulus = self.modulus(modulus_reference)?;
        let centered_offset = (modulus - 1) / 2;
        if secret.source.offset != 0
            || ephemeral_secret.source.offset != 0
            || round_two_error.offset != 0
            || aggregate_round_one_left.source.offset != centered_offset
            || aggregate_round_one_right.source.offset != centered_offset
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let secret_times_aggregate_left = self.full_ring_product(
                batch_key,
                selected_half,
                true,
                secret.source.coefficients,
                aggregate_round_one_left,
            )?;
            let ephemeral_times_aggregate_right = self.full_ring_product(
                batch_key,
                selected_half,
                true,
                ephemeral_secret.source.coefficients,
                aggregate_round_one_right,
            )?;
            let secret_times_aggregate_right = self.full_ring_product(
                batch_key,
                selected_half,
                false,
                secret.source.coefficients,
                aggregate_round_one_right,
            )?;
            self.add_integer_lift_component(
                batch_key,
                quotient.low_quotients[half_ordinal],
                vec![
                    constant_linear_term(round_two.halves[half_ordinal], 0, false),
                    plaintext_scaled_linear_term(
                        round_two_error.coefficients.halves[half_ordinal],
                        true,
                    ),
                    trustee_quotient_carry_linear_term(
                        quotient.high_carries[half_ordinal],
                        modulus_reference,
                    ),
                ],
                vec![
                    secret_times_aggregate_left,
                    ephemeral_times_aggregate_right,
                    secret_times_aggregate_right,
                ],
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::bgv::proof_suite::relation_plan) fn add_trustee_anchor_equations(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        commitments: &[SplitIntegerVector],
        first_matrix: &[Vec<ReversibleShiftedSmallVector>],
        second_matrix: &[ReversibleShiftedSmallVector],
        opening: &TrusteeAnchorOpeningWitness,
        secret: &ShiftedSmallVector,
        quotients: &[TrusteeRadixThreeQuotientWitness],
    ) -> Result<(), RelationPlanError> {
        let rank = usize::from(self.geometry.commitment_module_rank);
        let centered_offset = (self.modulus(modulus_reference)? - 1) / 2;
        if commitments.len() != rank + 1
            || first_matrix.len() != rank
            || first_matrix.iter().any(|row| row.len() != rank + 1)
            || second_matrix.len() != rank
            || opening.hiding_secrets.len() != rank + 1
            || opening.hiding_errors.len() != rank
            || quotients.len() != rank + 1
            || secret.offset != 0
            || first_matrix
                .iter()
                .flatten()
                .chain(second_matrix)
                .any(|matrix| matrix.source.offset != centered_offset)
            || opening.hiding_errors.iter().any(|value| value.offset != 0)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for row_ordinal in 0..rank {
            for half_ordinal in 0..2 {
                let selected_half = integer_lift_half(half_ordinal)?;
                let mut products = Vec::with_capacity(rank + 1);
                for column_ordinal in 0..=rank {
                    products.push(self.full_ring_product(
                        batch_key,
                        selected_half,
                        true,
                        opening.hiding_secrets[column_ordinal],
                        &first_matrix[row_ordinal][column_ordinal],
                    )?);
                }
                self.add_integer_lift_component(
                    batch_key,
                    quotients[row_ordinal].low_quotients[half_ordinal],
                    vec![
                        constant_linear_term(
                            commitments[row_ordinal].halves[half_ordinal],
                            0,
                            false,
                        ),
                        constant_linear_term(
                            opening.hiding_errors[row_ordinal].coefficients.halves[half_ordinal],
                            0,
                            true,
                        ),
                        trustee_quotient_carry_linear_term(
                            quotients[row_ordinal].high_carries[half_ordinal],
                            modulus_reference,
                        ),
                    ],
                    products,
                )?;
            }
        }

        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let mut products = Vec::with_capacity(rank);
            for (hiding_secret, second_matrix_column) in
                opening.hiding_secrets.iter().copied().zip(second_matrix)
            {
                products.push(self.full_ring_product(
                    batch_key,
                    selected_half,
                    true,
                    hiding_secret,
                    second_matrix_column,
                )?);
            }
            self.add_integer_lift_component(
                batch_key,
                quotients[rank].low_quotients[half_ordinal],
                vec![
                    constant_linear_term(commitments[rank].halves[half_ordinal], 0, false),
                    constant_linear_term(
                        opening.hiding_secrets[rank].halves[half_ordinal],
                        0,
                        true,
                    ),
                    constant_linear_term(secret.coefficients.halves[half_ordinal], 0, true),
                    trustee_quotient_carry_linear_term(
                        quotients[rank].high_carries[half_ordinal],
                        modulus_reference,
                    ),
                ],
                products,
            )?;
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_anchor_equations(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        inputs: AnchorEquationInputs<'_>,
    ) -> Result<(), RelationPlanError> {
        let AnchorEquationInputs {
            commitments,
            first_matrix,
            second_matrix,
            opening,
            secret,
            quotients,
        } = inputs;
        let rank = usize::from(self.geometry.commitment_module_rank);
        if commitments.len() != rank + 1
            || first_matrix.len() != rank
            || first_matrix.iter().any(|row| row.len() != rank + 1)
            || second_matrix.len() != rank
            || opening.hiding_secrets.len() != rank + 1
            || opening.hiding_errors.len() != rank
            || quotients.rows.len() != rank + 1
            || secret.offset != 1
            || opening
                .hiding_secrets
                .iter()
                .any(|value| value.source.offset != 1)
            || opening.hiding_errors.iter().any(|value| value.offset != 1)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for row_ordinal in 0..rank {
            for half_ordinal in 0..2 {
                let selected_half = integer_lift_half(half_ordinal)?;
                let mut products = Vec::with_capacity(rank + 1);
                for column_ordinal in 0..=rank {
                    products.push(self.full_ring_product(
                        batch_key,
                        selected_half,
                        true,
                        first_matrix[row_ordinal][column_ordinal],
                        &opening.hiding_secrets[column_ordinal],
                    )?);
                }
                self.add_integer_lift_component(
                    batch_key,
                    quotients.rows[row_ordinal][half_ordinal],
                    vec![
                        constant_linear_term(
                            commitments[row_ordinal].halves[half_ordinal],
                            0,
                            false,
                        ),
                        constant_linear_term(
                            opening.hiding_errors[row_ordinal].coefficients.halves[half_ordinal],
                            opening.hiding_errors[row_ordinal].offset,
                            true,
                        ),
                    ],
                    products,
                )?;
            }
        }

        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let mut products = Vec::with_capacity(rank);
            for (second_matrix_column, hiding_secret) in
                second_matrix.iter().copied().zip(&opening.hiding_secrets)
            {
                products.push(self.full_ring_product(
                    batch_key,
                    selected_half,
                    true,
                    second_matrix_column,
                    hiding_secret,
                )?);
            }
            self.add_integer_lift_component(
                batch_key,
                quotients.rows[rank][half_ordinal],
                vec![
                    constant_linear_term(commitments[rank].halves[half_ordinal], 0, false),
                    constant_linear_term(
                        opening.hiding_secrets[rank].source.coefficients.halves[half_ordinal],
                        opening.hiding_secrets[rank].source.offset,
                        true,
                    ),
                    constant_linear_term(
                        secret.coefficients.halves[half_ordinal],
                        secret.offset,
                        true,
                    ),
                ],
                products,
            )?;
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_public_key_equation(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        inputs: PublicKeyEquationInputs<'_>,
    ) -> Result<(), RelationPlanError> {
        let PublicKeyEquationInputs {
            public_key_share,
            common_reference,
            secret,
            error,
            quotient_columns,
        } = inputs;
        if secret.source.offset != 1 || error.offset != 2 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for (half_ordinal, quotient_column) in quotient_columns.into_iter().enumerate() {
            let product = self.full_ring_product(
                batch_key,
                integer_lift_half(half_ordinal)?,
                false,
                *common_reference,
                secret,
            )?;
            self.add_integer_lift_component(
                batch_key,
                quotient_column,
                vec![
                    constant_linear_term(public_key_share.halves[half_ordinal], 0, false),
                    RelationIntegerLiftLinearTermDescriptor {
                        negative: true,
                        column_ordinal: error.coefficients.halves[half_ordinal],
                        column_offset: error.offset,
                        coefficient: RelationIntegerLiftCoefficient::Modulus {
                            modulus_reference: SuiteModulusReference::plaintext(),
                            multiplier: 1,
                        },
                    },
                ],
                vec![product],
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::bgv::proof_suite::relation_plan) fn add_galois_key_equation(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        galois_key_share: &SplitIntegerVector,
        common_reference: SplitIntegerVector,
        secret: &ReversibleShiftedSmallVector,
        automorphed_secret: &ShiftedSmallVector,
        error: &ShiftedSmallVector,
        gadget_coefficient: u64,
        quotient: TrusteeRadixThreeQuotientWitness,
    ) -> Result<(), RelationPlanError> {
        let modulus = self.modulus(modulus_reference)?;
        if secret.source.offset != 0
            || automorphed_secret.offset != 0
            || error.offset != 0
            || gadget_coefficient >= modulus
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for half_ordinal in 0..2 {
            let mut linear_terms = vec![
                constant_linear_term(galois_key_share.halves[half_ordinal], 0, false),
                plaintext_scaled_linear_term(error.coefficients.halves[half_ordinal], true),
                trustee_quotient_carry_linear_term(
                    quotient.high_carries[half_ordinal],
                    modulus_reference,
                ),
            ];
            if gadget_coefficient != 0 {
                linear_terms.push(scaled_constant_linear_term(
                    automorphed_secret.coefficients.halves[half_ordinal],
                    true,
                    gadget_coefficient,
                ));
            }
            let common_reference_times_secret = self.full_ring_product(
                batch_key,
                integer_lift_half(half_ordinal)?,
                false,
                common_reference,
                secret,
            )?;
            self.add_integer_lift_component(
                batch_key,
                quotient.low_quotients[half_ordinal],
                linear_terms,
                vec![common_reference_times_secret],
            )?;
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn finalize_integer_lift_batches(
        &mut self,
    ) -> Result<(), RelationPlanError> {
        let pending = std::mem::take(&mut self.pending_integer_lift_batches);
        let mut batches = Vec::with_capacity(pending.len());
        for ((modulus_reference, challenge_ordinal), pending_batch) in pending {
            let mut ordered_reversed_column_bindings = pending_batch
                .reversed_bindings
                .into_values()
                .collect::<Vec<_>>();
            sort_canonical_items(&mut ordered_reversed_column_bindings, |binding| {
                binding.canonical_bytes()
            })?;
            let mut ordered_negacyclic_automorphism_permutations =
                pending_batch.negacyclic_automorphism_permutations;
            sort_canonical_items(
                &mut ordered_negacyclic_automorphism_permutations,
                |permutation| permutation.canonical_bytes(),
            )?;
            let mut ordered_components = pending_batch.components;
            sort_canonical_items(&mut ordered_components, |component| {
                component.canonical_bytes()
            })?;
            let batch = RelationIntegerLiftBatchDescriptor {
                modulus_reference,
                challenge_ordinal,
                ordered_reversed_column_bindings,
                ordered_negacyclic_automorphism_permutations,
                ordered_components,
            };
            let modulus_ordinal = self.modulus_ordinal(modulus_reference)?;
            for program in batch.constraint_programs(
                modulus_ordinal,
                self.geometry.trace_domain_size()?,
                self.geometry.evaluation_domain_size,
                self.context,
            )? {
                self.add_constraint(
                    program.numerator_postfix_expression,
                    program.zeroifier_postfix_expression,
                    false,
                )?;
            }
            batches.push(batch);
        }
        sort_canonical_items(&mut batches, |batch| batch.canonical_bytes())?;
        self.ordered_integer_lift_batches = batches;
        Ok(())
    }
}
