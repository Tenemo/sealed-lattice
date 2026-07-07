use super::constraints::*;
use super::*;

#[cfg(test)]
pub(in super::super) fn verify_round_one_key_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    proof: &KeyFriProof<LIMB_COUNT>,
    proof_parameters: &KeyFriProofParameters,
) -> CanonicalResult<bool> {
    verify_key_fri(
        parameters,
        ring_degree,
        public,
        &KeySource::RoundOne,
        proof,
        None,
        &ZERO_STATEMENT_BINDING,
        0,
        proof_parameters,
    )
}

pub(in super::super) fn verify_key_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    proof: &KeyFriProof<LIMB_COUNT>,
    linkage_statement: Option<&linkage::LinkageStatement<'_>>,
    statement_binding: &[u8; 64],
    schedule_index: u64,
    proof_parameters: &KeyFriProofParameters,
) -> CanonicalResult<bool> {
    let layout = layout(ring_degree)?;
    let digit_count = public.digits.len();
    if digit_count == 0 {
        return Ok(false);
    }
    let trace_domain = CyclicDomain::new(parameters, layout.trace_size)?;
    let coset_domain = CyclicDomain::new(parameters, layout.coset_size)?;
    let offset = coset_offset(parameters);
    let negacyclic = NegacyclicDomain::new(parameters, ring_degree)?;
    let table_count = carry_range_lookup::table_count(ring_degree);
    let linkage_layout_data = match linkage_statement {
        Some(_) => Some(linkage::linkage_layout(ring_degree)?),
        None => None,
    };
    let base_count = base_column_count(ring_degree, digit_count, linkage_layout_data.as_ref());
    let material_count = material_column_count(digit_count);
    let aux_count = aux_column_count(ring_degree, digit_count, linkage_layout_data.as_ref());

    // The logUp terminals in the proof must be shaped for this key, and the
    // cross-check `lookup = sum_k table_k` must hold before any query work.
    if proof.table_terminals.len() != table_count {
        return Ok(false);
    }
    let table_terminal_sum = proof
        .table_terminals
        .iter()
        .fold(parameters.zero(), |sum, terminal| {
            parameters.add(&sum, terminal)
        });
    if table_terminal_sum != proof.lookup_terminal {
        return Ok(false);
    }

    let mut transcript = Transcript::new(PROTOCOL_LABEL);
    transcript.absorb("key-statement-binding", statement_binding);
    transcript.absorb_u64("key-schedule-index", schedule_index);
    absorb_public(&mut transcript, ring_degree, public, source);
    transcript.absorb_u64(
        "key-linkage-present",
        u64::from(linkage_statement.is_some()),
    );
    if let Some(statement) = linkage_statement {
        linkage::absorb_linkage_statement(&mut transcript, statement);
    }
    transcript.absorb_digest("key-base-root", &proof.base_root);
    transcript.absorb_digest("key-material-root", &proof.material_root);
    let gamma = transcript.challenge_field_elements(parameters, "key-gamma", ring_degree);
    let delta = transcript.challenge_field_elements(parameters, "key-delta", digit_count);
    let lookup_challenge = transcript.challenge_field_elements(parameters, "key-lookup-mu", 1);
    let mu = lookup_challenge[0];
    let linkage_weights = linkage_statement.map(|_| {
        transcript.challenge_field_elements(
            parameters,
            "key-linkage-omega",
            linkage::linkage_claim_count(),
        )
    });

    transcript.absorb_digest("key-aux-root", &proof.aux_root);
    transcript.absorb_field_elements("key-lookup-terminal", &[proof.lookup_terminal]);
    transcript.absorb_field_elements("key-table-terminals", &proof.table_terminals);
    let sum_batch =
        transcript.challenge_field_elements(parameters, "key-sum-batch", 1 + table_count);
    let alpha = transcript.challenge_field_elements(
        parameters,
        "key-support-alpha",
        support_constraint_count(ring_degree, digit_count, linkage_layout_data.as_ref()),
    );

    transcript.absorb_digest("key-quotient-root", &proof.quotient_root);
    let weights = transcript.challenge_field_elements(
        parameters,
        "key-combination",
        base_count + material_count + aux_count + QUOTIENT_COLUMN_COUNT + 1,
    );

    let fri_parameters = FriParameters {
        blowup: FRI_RATE_BLOWUP,
    };
    let Some(verification) = fri_verify_structure(
        parameters,
        &mut transcript,
        &proof.fri,
        layout.coset_size,
        &offset,
        &fri_parameters,
    )?
    else {
        return Ok(false);
    };
    let query_positions = transcript.challenge_positions(
        "key-query",
        layout.coset_size,
        proof_parameters.query_count,
    );
    if !fri_verify_queries(parameters, &verification, &proof.fri, &query_positions) {
        return Ok(false);
    }

    let Some(base_rows) = verify_column_opening(
        &proof.base_root,
        layout.coset_size,
        base_count,
        &proof.base_opening,
    ) else {
        return Ok(false);
    };
    let Some(material_rows) = verify_column_opening(
        &proof.material_root,
        layout.coset_size,
        material_count,
        &proof.material_opening,
    ) else {
        return Ok(false);
    };
    let Some(aux_rows) = verify_column_opening(
        &proof.aux_root,
        layout.coset_size,
        aux_count,
        &proof.aux_opening,
    ) else {
        return Ok(false);
    };
    let Some(quotient_rows) = verify_column_opening(
        &proof.quotient_root,
        layout.coset_size,
        QUOTIENT_COLUMN_COUNT,
        &proof.quotient_opening,
    ) else {
        return Ok(false);
    };

    // Evaluate every public polynomial once per opened position, streaming the
    // per-digit linear forms so no all-digit form set is ever resident (at the
    // full profile that set alone is hundreds of megabytes). Slot `s` holds the
    // evaluations at the `s`-th opened index.
    let opened_indices: Vec<usize> = base_rows.keys().copied().collect();
    let slot_of_index: std::collections::BTreeMap<usize, usize> = opened_indices
        .iter()
        .enumerate()
        .map(|(slot, &index)| (index, slot))
        .collect();
    let x_of_slot: Vec<[u64; LIMB_COUNT]> = opened_indices
        .iter()
        .map(|&index| parameters.multiply(&offset, &coset_domain.point(index)))
        .collect();
    let evaluate_at_slots = |coefficients: &[[u64; LIMB_COUNT]]| -> Vec<[u64; LIMB_COUNT]> {
        x_of_slot
            .iter()
            .map(|x| polynomial::evaluate(parameters, coefficients, x))
            .collect()
    };

    let mut error_form_at_slot: Vec<Vec<[u64; LIMB_COUNT]>> = Vec::with_capacity(digit_count);
    let mut carry_form_at_slot: Vec<Vec<[u64; LIMB_COUNT]>> = Vec::with_capacity(digit_count);
    // The material form `delta_j * gamma` per digit, interpolated and evaluated
    // at the opened points, so the sumcheck folds the opened committed material
    // column with it exactly as the prover folds the material column into `f`.
    let mut material_form_at_slot: Vec<Vec<[u64; LIMB_COUNT]>> = Vec::with_capacity(digit_count);
    let (secret_form, atom_target) = accumulate_forms(
        parameters,
        &negacyclic,
        ring_degree,
        public,
        source,
        &gamma,
        &delta,
        |_, forms| {
            let error_linear = trace_domain.interpolate(&forms.error_form);
            error_form_at_slot.push(evaluate_at_slots(&error_linear));
            let carry_linear = trace_domain.interpolate(&forms.carry_form);
            carry_form_at_slot.push(evaluate_at_slots(&carry_linear));
            let material_linear = trace_domain.interpolate(&forms.material_form);
            material_form_at_slot.push(evaluate_at_slots(&material_linear));
            Ok(())
        },
    )?;
    let ls = trace_domain.interpolate(&secret_form);
    let secret_form_at_slot = evaluate_at_slots(&ls);
    let table_polynomials = table_value_polynomials(parameters, &trace_domain, ring_degree);
    let table_value_at_slot: Vec<Vec<[u64; LIMB_COUNT]>> = table_polynomials
        .iter()
        .map(|table_polynomial| evaluate_at_slots(table_polynomial))
        .collect();
    // Linkage: the public opening forms evaluated at the opened points, plus
    // the constraint context for the support walk.
    let linkage_forms = match (linkage_statement, &linkage_weights) {
        (Some(statement), Some(weights)) => Some(linkage::build_linkage_forms(
            parameters,
            statement,
            ring_degree,
            weights,
        )?),
        _ => None,
    };
    let linkage_form_at_slot: Option<Vec<Vec<[u64; LIMB_COUNT]>>> =
        linkage_forms.as_ref().map(|forms| {
            forms
                .digit_forms
                .iter()
                .chain(forms.randomness_forms.iter())
                .chain(std::iter::once(&forms.carry_form))
                .map(|form| evaluate_at_slots(&trace_domain.interpolate(form)))
                .collect()
        });
    let linkage_context = match linkage_statement {
        Some(statement) => Some(linkage::linkage_constraint_context(
            parameters,
            ring_degree,
            statement.source_message_modulus,
        )?),
        None => None,
    };

    let size_inverse =
        parameters.inverse(&parameters.unsigned_word_to_element(layout.trace_size as u64));
    // Combined sumcheck target: the atom target plus the batched logUp terminals.
    let mut target = parameters.add(
        &atom_target,
        &parameters.multiply(&sum_batch[0], &proof.lookup_terminal),
    );
    for table_index in 0..table_count {
        target = parameters.add(
            &target,
            &parameters.multiply(
                &sum_batch[1 + table_index],
                &proof.table_terminals[table_index],
            ),
        );
    }
    if let Some(forms) = &linkage_forms {
        target = parameters.add(&target, &forms.target);
    }
    let target_over_size = parameters.multiply(&target, &size_inverse);

    let half = layout.coset_size / 2;
    for (query_index, &position) in query_positions.iter().enumerate() {
        let folded = position % half;
        let sibling = folded + half;
        let layers = &proof.fri.query_answers[query_index].layers;
        if layers.is_empty() {
            return Ok(false);
        }
        let layer_zero = &layers[0];
        for (index, expected) in [
            (folded, layer_zero.value),
            (sibling, layer_zero.sibling_value),
        ] {
            let Some(base_values) = base_rows.get(&index) else {
                return Ok(false);
            };
            let Some(material_values) = material_rows.get(&index) else {
                return Ok(false);
            };
            let Some(aux_values) = aux_rows.get(&index) else {
                return Ok(false);
            };
            let Some(quotient_values) = quotient_rows.get(&index) else {
                return Ok(false);
            };
            let Some(&slot) = slot_of_index.get(&index) else {
                return Ok(false);
            };
            let x = x_of_slot[slot];
            // combination_at zips the weights against base+material+aux+quotient
            // columns in that fixed order, so the extra trailing weight is
            // ignored here and used below for the g degree-adjustment term.
            let mut combined = combination_at(
                parameters,
                base_values,
                material_values,
                aux_values,
                quotient_values,
                &weights,
            );
            // g degree adjustment (sumcheck soundness): mirror the prover's
            // shifted g term (x^{trace_size + 1} g), reconstructed from the
            // opened g value, so the combined FRI enforces deg(g) <=
            // trace_size - 2. See `g_degree_adjustment_shift`.
            let g_shift = g_degree_adjustment_shift(layout.trace_size);
            let mut g_shift_exponent = [0_u64; LIMB_COUNT];
            g_shift_exponent[0] = g_shift as u64;
            let x_pow_g_shift = parameters.power(&x, &g_shift_exponent);
            let g_adjustment_weight =
                weights[base_count + material_count + aux_count + QUOTIENT_COLUMN_COUNT];
            combined = parameters.add(
                &combined,
                &parameters.multiply(
                    &g_adjustment_weight,
                    &parameters.multiply(&x_pow_g_shift, &quotient_values[QUOTIENT_G]),
                ),
            );
            if combined != expected {
                return Ok(false);
            }
            let vanishing_x = polynomial::vanishing_at(parameters, &x, layout.trace_size);

            // Sumcheck: f(x) = target/m + x g(x) + Z_H(x) q_sc(x), where f folds
            // in the batched logUp fraction columns.
            let mut f_x =
                parameters.multiply(&secret_form_at_slot[slot], &base_values[COLUMN_SECRET]);
            for digit in 0..digit_count {
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(
                        &error_form_at_slot[digit][slot],
                        &base_values[digit_column(digit, DIGIT_ERROR)],
                    ),
                );
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(
                        &carry_form_at_slot[digit][slot],
                        &base_values[digit_column(digit, DIGIT_CARRY)],
                    ),
                );
                // Material form: add `(delta_j gamma)(x) * B_col_j(x)`, the
                // committed component term the prover folds into `f`. This is the
                // sole binding of `B_col_j`, so a wrong committed material makes
                // `f_x` miss the sumcheck right-hand side and verification fails.
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(&material_form_at_slot[digit][slot], &material_values[digit]),
                );
            }
            for digit in 0..digit_count {
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(&sum_batch[0], &aux_values[aux_lookup_column(digit)]),
                );
            }
            for table_index in 0..table_count {
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(
                        &sum_batch[1 + table_index],
                        &aux_values[aux_table_fraction_column(digit_count, table_index)],
                    ),
                );
            }
            if let Some(layout_data) = linkage_layout_data.as_ref() {
                let linkage_aux = aux_linkage_start(ring_degree, digit_count);
                for offset in 0..linkage::linkage_aux_column_count(layout_data) {
                    f_x = parameters.add(
                        &f_x,
                        &parameters.multiply(&sum_batch[0], &aux_values[linkage_aux + offset]),
                    );
                }
                let forms_at_slot = linkage_form_at_slot
                    .as_ref()
                    .expect("linkage forms exist with a linkage statement");
                let linkage_base = base_linkage_start(ring_degree, digit_count);
                let form_columns = [
                    linkage::link_digit(0),
                    linkage::link_digit(1),
                    linkage::link_randomness(layout_data, 0),
                    linkage::link_randomness(layout_data, 1),
                    linkage::link_carry(layout_data),
                ];
                for (form_values, column_offset) in forms_at_slot.iter().zip(form_columns) {
                    f_x = parameters.add(
                        &f_x,
                        &parameters.multiply(
                            &form_values[slot],
                            &base_values[linkage_base + column_offset],
                        ),
                    );
                }
            }
            let sumcheck_rhs = parameters.add(
                &parameters.add(
                    &target_over_size,
                    &parameters.multiply(&x, &quotient_values[QUOTIENT_G]),
                ),
                &parameters.multiply(&vanishing_x, &quotient_values[QUOTIENT_SUMCHECK]),
            );
            if f_x != sumcheck_rhs {
                return Ok(false);
            }

            // Support: V(x) = Z_H(x) q_support(x), with the table value
            // polynomials evaluated at x for the fraction pins.
            let table_values_at_point: Vec<[u64; LIMB_COUNT]> = table_value_at_slot
                .iter()
                .map(|values| values[slot])
                .collect();
            let v_x = support_value_at(
                parameters,
                ring_degree,
                digit_count,
                base_values,
                aux_values,
                &table_values_at_point,
                &mu,
                &alpha,
                linkage_context.as_ref(),
            );
            if v_x != parameters.multiply(&vanishing_x, &quotient_values[QUOTIENT_SUPPORT]) {
                return Ok(false);
            }
        }
    }

    Ok(true)
}
