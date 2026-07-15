use super::columns::*;
use super::constraints::*;
use super::*;

#[cfg(all(test, not(target_arch = "wasm32")))]
use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
const KEY_PROVER_PHASE_COUNT: usize = 8;
#[cfg(all(test, not(target_arch = "wasm32")))]
static KEY_PROVER_TIMING_ENABLED: AtomicBool = AtomicBool::new(false);
#[cfg(all(test, not(target_arch = "wasm32")))]
static KEY_PROVER_PHASE_NANOSECONDS: [AtomicU64; KEY_PROVER_PHASE_COUNT] =
    [const { AtomicU64::new(0) }; KEY_PROVER_PHASE_COUNT];

#[cfg(all(test, not(target_arch = "wasm32")))]
#[derive(Clone, Copy)]
enum KeyProverPhase {
    DomainAndPlan,
    BaseAndMaterialCommitments,
    AuxiliaryRound,
    ConstraintComposition,
    QuotientCommitment,
    Combination,
    Fri,
    Openings,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
impl KeyProverPhase {
    const ALL: [Self; KEY_PROVER_PHASE_COUNT] = [
        Self::DomainAndPlan,
        Self::BaseAndMaterialCommitments,
        Self::AuxiliaryRound,
        Self::ConstraintComposition,
        Self::QuotientCommitment,
        Self::Combination,
        Self::Fri,
        Self::Openings,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::DomainAndPlan => "domain and plan",
            Self::BaseAndMaterialCommitments => "base and material commitments",
            Self::AuxiliaryRound => "auxiliary round",
            Self::ConstraintComposition => "constraint composition",
            Self::QuotientCommitment => "quotient commitment",
            Self::Combination => "combination",
            Self::Fri => "FRI",
            Self::Openings => "openings",
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
struct KeyProverPhaseTimer {
    phase: KeyProverPhase,
    started: Option<Instant>,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
impl KeyProverPhaseTimer {
    fn start(phase: KeyProverPhase) -> Self {
        Self {
            phase,
            started: KEY_PROVER_TIMING_ENABLED
                .load(Ordering::SeqCst)
                .then(Instant::now),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
impl Drop for KeyProverPhaseTimer {
    fn drop(&mut self) {
        let Some(started) = self.started else {
            return;
        };
        let elapsed = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        KEY_PROVER_PHASE_NANOSECONDS[self.phase as usize].fetch_add(elapsed, Ordering::SeqCst);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(in super::super) fn begin_key_prover_phase_timing() {
    KEY_PROVER_TIMING_ENABLED.store(false, Ordering::SeqCst);
    for elapsed in &KEY_PROVER_PHASE_NANOSECONDS {
        elapsed.store(0, Ordering::SeqCst);
    }
    KEY_PROVER_TIMING_ENABLED.store(true, Ordering::SeqCst);
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(in super::super) fn finish_key_prover_phase_timing() -> Vec<(&'static str, f64)> {
    KEY_PROVER_TIMING_ENABLED.store(false, Ordering::SeqCst);
    KeyProverPhase::ALL
        .into_iter()
        .map(|phase| {
            (
                phase.label(),
                KEY_PROVER_PHASE_NANOSECONDS[phase as usize].load(Ordering::SeqCst) as f64
                    / 1_000_000.0,
            )
        })
        .collect()
}

#[cfg(test)]
pub(in super::super) fn prove_round_one_key_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    secret: &[i64],
    digits: &[DigitWitness],
    proof_parameters: &KeyFriProofParameters,
    private_randomness: &mut PrivateProofRandomness,
) -> CanonicalResult<KeyFriProof<LIMB_COUNT>> {
    prove_key_fri(
        parameters,
        ring_degree,
        public,
        &KeySource::RoundOne,
        secret,
        digits,
        None,
        &ZERO_STATEMENT_BINDING,
        0,
        proof_parameters,
        private_randomness,
    )
}

// Commit the transported public component material as the `B_col_j` columns and
// prove. Production always commits the public
// material; the streamed body accepts the material explicitly so a test can
// substitute a mismatched column and confirm the relation (the sumcheck)
// rejects it.
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn prove_key_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    secret: &[i64],
    digits: &[DigitWitness],
    linkage_inputs: Option<(&linkage::LinkageStatement<'_>, &linkage::LinkageWitness<'_>)>,
    statement_binding: &[u8; 64],
    schedule_index: u64,
    proof_parameters: &KeyFriProofParameters,
    private_randomness: &mut PrivateProofRandomness,
) -> CanonicalResult<KeyFriProof<LIMB_COUNT>> {
    let negacyclic_domain = NegacyclicDomain::new(parameters, ring_degree)?;
    prove_key_fri_with_negacyclic_domain(
        parameters,
        ring_degree,
        &negacyclic_domain,
        public,
        source,
        secret,
        digits,
        linkage_inputs,
        statement_binding,
        schedule_index,
        proof_parameters,
        private_randomness,
    )
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn prove_key_fri_with_negacyclic_domain<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    negacyclic_domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    secret: &[i64],
    digits: &[DigitWitness],
    linkage_inputs: Option<(&linkage::LinkageStatement<'_>, &linkage::LinkageWitness<'_>)>,
    statement_binding: &[u8; 64],
    schedule_index: u64,
    proof_parameters: &KeyFriProofParameters,
    private_randomness: &mut PrivateProofRandomness,
) -> CanonicalResult<KeyFriProof<LIMB_COUNT>> {
    let component_b: Vec<&[[u64; LIMB_COUNT]]> = public
        .digits
        .iter()
        .map(|digit| digit.recombined_component_b.as_slice())
        .collect();
    prove_key_fri_streamed(
        parameters,
        ring_degree,
        negacyclic_domain,
        public,
        source,
        secret,
        digits,
        component_b,
        linkage_inputs,
        statement_binding,
        schedule_index,
        proof_parameters,
        private_randomness,
    )
}

// A test entry that commits caller-supplied component material instead of the
// public material, so the relation binding on the committed `B_col_j` columns
// can be exercised in isolation: a mismatched committed material makes the atom
// congruence `B + A(*)s - t e - G source - Q c = 0` miss, and the sumcheck
// rejects it.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn prove_key_fri_with_component_b<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    secret: &[i64],
    digits: &[DigitWitness],
    component_b: Vec<&[[u64; LIMB_COUNT]]>,
    linkage_inputs: Option<(&linkage::LinkageStatement<'_>, &linkage::LinkageWitness<'_>)>,
    statement_binding: &[u8; 64],
    schedule_index: u64,
    proof_parameters: &KeyFriProofParameters,
    private_randomness: &mut PrivateProofRandomness,
) -> CanonicalResult<KeyFriProof<LIMB_COUNT>> {
    let negacyclic_domain = NegacyclicDomain::new(parameters, ring_degree)?;
    prove_key_fri_streamed(
        parameters,
        ring_degree,
        &negacyclic_domain,
        public,
        source,
        secret,
        digits,
        component_b,
        linkage_inputs,
        statement_binding,
        schedule_index,
        proof_parameters,
        private_randomness,
    )
}

pub(super) fn accumulate_weighted_coefficients<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    combined_coefficients: &mut [[u64; LIMB_COUNT]],
    weight: &[u64; LIMB_COUNT],
    coefficients: &[[u64; LIMB_COUNT]],
    starting_degree: usize,
) {
    let ending_degree = starting_degree + coefficients.len();
    debug_assert!(ending_degree <= combined_coefficients.len());
    for (combined_coefficient, coefficient) in combined_coefficients[starting_degree..ending_degree]
        .iter_mut()
        .zip(coefficients)
    {
        *combined_coefficient = parameters.add(
            combined_coefficient,
            &parameters.multiply(weight, coefficient),
        );
    }
}

// The streamed prover commits and opens exactly the columns regenerated from
// the deterministic `KeyColumnPlan`, so peak memory is bounded by one coset
// codeword plus one incremental leaf-hash state per coset position - never the
// full column set (at the full profile the retained column set alone is
// gigabytes). The FRI combination is formed in coefficient space and extended
// once, avoiding a separate low-degree extension for every column. Transcript,
// challenge order, and deterministic salt/mask streams remain unchanged.
#[allow(clippy::too_many_arguments)]
fn prove_key_fri_streamed<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    negacyclic: &NegacyclicDomain<'_, LIMB_COUNT>,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    secret: &[i64],
    digits: &[DigitWitness],
    component_b: Vec<&[[u64; LIMB_COUNT]]>,
    linkage_inputs: Option<(&linkage::LinkageStatement<'_>, &linkage::LinkageWitness<'_>)>,
    statement_binding: &[u8; 64],
    schedule_index: u64,
    proof_parameters: &KeyFriProofParameters,
    private_randomness: &mut PrivateProofRandomness,
) -> CanonicalResult<KeyFriProof<LIMB_COUNT>> {
    if public.digits.len() != digits.len() || digits.is_empty() {
        return Err(invalid_key("digit public and witness counts must match"));
    }
    #[cfg(all(test, not(target_arch = "wasm32")))]
    let domain_and_plan_timer = KeyProverPhaseTimer::start(KeyProverPhase::DomainAndPlan);
    let layout = layout(ring_degree)?;
    let digit_count = digits.len();
    let trace_domain = CyclicDomain::for_interpolation(parameters, layout.trace_size)?;
    let coset_domain = CyclicDomain::for_evaluation(parameters, layout.coset_size)?;
    let offset = coset_offset(parameters);
    let table_count = carry_range_lookup::table_count(ring_degree);

    let mut plan = KeyColumnPlan::new(
        parameters,
        ring_degree,
        proof_parameters.mask_degree,
        secret,
        digits,
        component_b,
        linkage_inputs,
        private_randomness,
    )?;
    let base_count = plan.base_column_count();
    let material_count = material_column_count(digit_count);
    let mut codeword = vec![parameters.zero(); layout.coset_size];
    #[cfg(all(test, not(target_arch = "wasm32")))]
    drop(domain_and_plan_timer);
    #[cfg(all(test, not(target_arch = "wasm32")))]
    let base_and_material_timer =
        KeyProverPhaseTimer::start(KeyProverPhase::BaseAndMaterialCommitments);

    // Round 1 (streamed): witness columns plus the carry-range multiplicity
    // columns, committed one codeword at a time.
    let mut base_builder =
        StreamedColumnCommitmentBuilder::begin(layout.coset_size, base_count, private_randomness)?;
    for column in 0..base_count {
        let coefficients = plan.base_column_coefficients(parameters, &trace_domain, column);
        coset_evaluate_coefficients_into(&coset_domain, &offset, &coefficients, &mut codeword);
        base_builder.absorb_column(&codeword)?;
    }
    let base_commitment = base_builder.finalize()?;

    // Commit each masked material column once. The same deterministic plan
    // regenerates individual columns later when producing openings.
    let mut material_builder = StreamedColumnCommitmentBuilder::begin(
        layout.coset_size,
        material_count,
        private_randomness,
    )?;
    for digit in 0..material_count {
        let coefficients = plan.material_column_coefficients(parameters, &trace_domain, digit);
        coset_evaluate_coefficients_into(&coset_domain, &offset, &coefficients, &mut codeword);
        material_builder.absorb_column(&codeword)?;
    }
    let material_commitment = material_builder.finalize()?;
    #[cfg(all(test, not(target_arch = "wasm32")))]
    drop(base_and_material_timer);
    #[cfg(all(test, not(target_arch = "wasm32")))]
    let auxiliary_round_timer = KeyProverPhaseTimer::start(KeyProverPhase::AuxiliaryRound);

    let mut transcript = Transcript::new(PROTOCOL_LABEL);
    transcript.absorb("key-statement-binding", statement_binding);
    transcript.absorb_u64("key-schedule-index", schedule_index);
    absorb_public(&mut transcript, ring_degree, public, source);
    transcript.absorb_u64("key-linkage-present", u64::from(linkage_inputs.is_some()));
    if let Some((statement, _)) = linkage_inputs {
        linkage::absorb_linkage_statement(&mut transcript, statement)?;
    }
    transcript.absorb_digest("key-base-root", &base_commitment.root());
    transcript.absorb_digest("key-material-root", &material_commitment.root());
    let linkage_public_forms = match linkage_inputs {
        Some((statement, _)) => {
            let challenges =
                linkage::draw_linkage_challenges(&mut transcript, statement, ring_degree)?;
            let forms = linkage::build_linkage_public_forms(statement, &challenges, ring_degree)?;
            plan.populate_linkage_reduced_witness(&forms)?;
            Some(forms)
        }
        None => None,
    };
    let gamma = transcript.challenge_field_elements(parameters, "key-gamma", ring_degree);
    let delta = transcript.challenge_field_elements(parameters, "key-delta", digit_count);
    let lookup_challenge = transcript.challenge_field_elements(parameters, "key-lookup-mu", 1);
    let mu = lookup_challenge[0];

    // Round 2 (streamed): the logUp fraction columns, which depend on `mu`. The
    // lookup and table terminals are computed from the on-domain values and
    // bound into the transcript.
    plan.set_lookup_challenge(mu, private_randomness);
    let aux_count = plan.aux_column_count();
    let (lookup_terminal, table_terminals) = plan.lookup_terminals(parameters)?;
    let mut aux_builder =
        StreamedColumnCommitmentBuilder::begin(layout.coset_size, aux_count, private_randomness)?;
    for column in 0..aux_count {
        let coefficients = plan.aux_column_coefficients(parameters, &trace_domain, column)?;
        coset_evaluate_coefficients_into(&coset_domain, &offset, &coefficients, &mut codeword);
        aux_builder.absorb_column(&codeword)?;
    }
    let aux_commitment = aux_builder.finalize()?;
    drop(codeword);
    transcript.absorb_digest("key-aux-root", &aux_commitment.root());
    transcript.absorb_field_elements("key-lookup-terminal", &[lookup_terminal]);
    transcript.absorb_field_elements("key-table-terminals", &table_terminals);
    // The quotient chunks depend on the BDLOP lincheck challenges and are
    // fixed by the auxiliary commitment. Draw the final coordinate batching
    // weights only now, so a prover cannot choose those chunks to cancel
    // malformed claims across commitment fields or extension coordinates.
    let linkage_weights = linkage_public_forms.as_ref().map(|_| {
        transcript.challenge_field_elements(
            parameters,
            "key-linkage-omega",
            linkage::linkage_claim_count(),
        )
    });

    // Batching challenges: one for the lookup terminal, one per table terminal,
    // folded into the single sumcheck; and the support-constraint weights.
    let sum_batch =
        transcript.challenge_field_elements(parameters, "key-sum-batch", 1 + table_count);
    let alpha = transcript.challenge_field_elements(
        parameters,
        "key-support-alpha",
        support_constraint_count(ring_degree, digit_count, plan.linkage_layout()),
    );
    #[cfg(all(test, not(target_arch = "wasm32")))]
    drop(auxiliary_round_timer);
    #[cfg(all(test, not(target_arch = "wasm32")))]
    let constraint_composition_timer =
        KeyProverPhaseTimer::start(KeyProverPhase::ConstraintComposition);

    // Sumcheck: f = Ls*S + sum_j (Le_j*E_j + Lc_j*C_j) plus the batched logUp
    // fraction sums, whose target folds in the committed terminals. The
    // per-digit forms stream through `accumulate_forms` and are dropped after
    // their products; witness columns regenerate from the plan.
    let mut f = vec![parameters.zero()];
    let (secret_form, atom_target) = accumulate_forms(
        parameters,
        negacyclic,
        ring_degree,
        public,
        source,
        &gamma,
        &delta,
        |digit, forms| {
            let error_linear = trace_domain.interpolate(&forms.error_form);
            let error_column = plan.base_column_coefficients(
                parameters,
                &trace_domain,
                digit_column(digit, DIGIT_ERROR),
            );
            f = polynomial::add(
                parameters,
                &f,
                &polynomial::multiply_via_ntt(parameters, &error_linear, &error_column),
            );
            let carry_linear = trace_domain.interpolate(&forms.carry_form);
            let carry_column = plan.base_column_coefficients(
                parameters,
                &trace_domain,
                digit_column(digit, DIGIT_CARRY),
            );
            f = polynomial::add(
                parameters,
                &f,
                &polynomial::multiply_via_ntt(parameters, &carry_linear, &carry_column),
            );
            // Fold the committed `B_col_j` into the left-hand side with
            // `delta_j * gamma`, like the error and carry columns.
            let material_linear = trace_domain.interpolate(&forms.material_form);
            let material_column =
                plan.material_column_coefficients(parameters, &trace_domain, digit);
            f = polynomial::add(
                parameters,
                &f,
                &polynomial::multiply_via_ntt(parameters, &material_linear, &material_column),
            );
            Ok(())
        },
    )?;
    let ls = trace_domain.interpolate(&secret_form);
    let secret_column = plan.base_column_coefficients(parameters, &trace_domain, COLUMN_SECRET);
    f = polynomial::add(
        parameters,
        &f,
        &polynomial::multiply_via_ntt(parameters, &ls, &secret_column),
    );
    let lookup_weight = sum_batch[0];
    for digit in 0..digit_count {
        let column =
            plan.aux_column_coefficients(parameters, &trace_domain, aux_lookup_column(digit))?;
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::scale(parameters, &column, &lookup_weight),
        );
    }
    for table_index in 0..table_count {
        let column = plan.aux_column_coefficients(
            parameters,
            &trace_domain,
            aux_table_fraction_column(digit_count, table_index),
        )?;
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::scale(parameters, &column, &sum_batch[1 + table_index]),
        );
    }
    // Linkage: the aux linkage fraction columns join the lookup side of the
    // logUp balance, and the batched opening claims join the sumcheck with the
    // omega weights against the linkage witness columns.
    let linkage_start_base = base_linkage_start(ring_degree, digit_count);
    let linkage_start_aux = aux_linkage_start(ring_degree, digit_count);
    let linkage_forms = match (&linkage_public_forms, &linkage_weights) {
        (Some(public_forms), Some(weights)) => Some(linkage::build_linkage_forms(
            parameters,
            public_forms,
            ring_degree,
            weights,
        )?),
        _ => None,
    };
    if let Some(forms) = &linkage_forms {
        let mut fold_form = |form: &Vec<[u64; LIMB_COUNT]>, column: usize| -> CanonicalResult<()> {
            let form_polynomial = trace_domain.interpolate(form);
            let column_coefficients =
                plan.base_column_coefficients(parameters, &trace_domain, column);
            f = polynomial::add(
                parameters,
                &f,
                &polynomial::multiply_via_ntt(parameters, &form_polynomial, &column_coefficients),
            );
            Ok(())
        };
        fold_form(&forms.secret_form, COLUMN_SECRET)?;
        fold_form(&forms.negative_form, linkage_start_base + linkage::LINK_NEG)?;
        for (randomness_position, form) in forms.randomness_forms.iter().enumerate() {
            let commitment_limb_position = randomness_position
                / crate::bgv::setup::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH;
            let randomness_column = randomness_position
                % crate::bgv::setup::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH;
            fold_form(
                form,
                linkage_start_base
                    + linkage::link_randomness(commitment_limb_position, randomness_column),
            )?;
        }
        for (chunk, form) in forms.carry_chunk_forms.iter().enumerate() {
            let form_polynomial = trace_domain.interpolate(form);
            let column_coefficients = plan.aux_column_coefficients(
                parameters,
                &trace_domain,
                linkage_start_aux + linkage::aux_carry_chunk(chunk),
            )?;
            f = polynomial::add(
                parameters,
                &f,
                &polynomial::multiply_via_ntt(parameters, &form_polynomial, &column_coefficients),
            );
        }
    }
    let mut target = parameters.add(
        &atom_target,
        &parameters.multiply(&lookup_weight, &lookup_terminal),
    );
    for table_index in 0..table_count {
        target = parameters.add(
            &target,
            &parameters.multiply(&sum_batch[1 + table_index], &table_terminals[table_index]),
        );
    }
    if let Some(forms) = &linkage_forms {
        target = parameters.add(&target, &forms.target);
    }

    let vanishing = vanishing_polynomial(parameters, layout.trace_size);
    let q_sc = polynomial::divide_by_vanishing(parameters, &f, layout.trace_size);
    let mut remainder = polynomial::subtract(
        parameters,
        &f,
        &polynomial::multiply_via_ntt(parameters, &q_sc, &vanishing),
    );
    drop(f);
    polynomial::trim(&mut remainder);
    let size_inverse =
        parameters.inverse(&parameters.unsigned_word_to_element(layout.trace_size as u64));
    let target_over_size = parameters.multiply(&target, &size_inverse);
    let remainder_constant = remainder
        .first()
        .copied()
        .unwrap_or_else(|| parameters.zero());
    if remainder_constant != target_over_size {
        return Err(invalid_key("sumcheck remainder constant mismatch"));
    }
    let mut shifted = remainder;
    if shifted.is_empty() {
        shifted.push(parameters.zero());
    }
    shifted[0] = parameters.subtract(&shifted[0], &target_over_size);
    let g = if shifted.len() > 1 {
        shifted[1..].to_vec()
    } else {
        vec![parameters.zero()]
    };

    // Support: V = sum alpha_i constraint_i, vanishing on H, streamed in the
    // same fixed constraint order the verifier's `support_value_at` walks:
    // ternary, then per digit [eta-2 x3, lookup fraction pin], then the table
    // fraction pins. Each constraint polynomial is weighted into V and dropped.
    let table_polynomials = table_value_polynomials(parameters, &trace_domain, ring_degree);
    let one = vec![parameters.one()];
    let four = vec![parameters.unsigned_word_to_element(4)];
    let shift = parameters.unsigned_word_to_element((ring_degree + 1) as u64);
    let challenge_minus_shift = vec![parameters.subtract(&mu, &shift)];
    let challenge_constant = vec![mu];
    let mut v = vec![parameters.zero()];
    let mut alpha_index = 0;
    let fold_constraint = |v: &mut Vec<[u64; LIMB_COUNT]>,
                           alpha_index: &mut usize,
                           constraint: Vec<[u64; LIMB_COUNT]>| {
        *v = polynomial::add(
            parameters,
            v,
            &polynomial::scale(parameters, &constraint, &alpha[*alpha_index]),
        );
        *alpha_index += 1;
    };
    {
        let secret_column = plan.base_column_coefficients(parameters, &trace_domain, COLUMN_SECRET);
        let secret_square_column =
            plan.base_column_coefficients(parameters, &trace_domain, COLUMN_SECRET_SQUARE);
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::subtract(
                parameters,
                &secret_square_column,
                &polynomial::multiply_via_ntt(parameters, &secret_column, &secret_column),
            ),
        );
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::multiply_via_ntt(
                parameters,
                &secret_column,
                &polynomial::subtract(parameters, &secret_square_column, &one),
            ),
        );
    }
    for digit in 0..digit_count {
        let error_column = plan.base_column_coefficients(
            parameters,
            &trace_domain,
            digit_column(digit, DIGIT_ERROR),
        );
        let error_square_column = plan.base_column_coefficients(
            parameters,
            &trace_domain,
            digit_column(digit, DIGIT_ERROR_SQUARE),
        );
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::subtract(
                parameters,
                &error_square_column,
                &polynomial::multiply_via_ntt(parameters, &error_column, &error_column),
            ),
        );
        let error_support_column = plan.base_column_coefficients(
            parameters,
            &trace_domain,
            digit_column(digit, DIGIT_ERROR_SUPPORT),
        );
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::subtract(
                parameters,
                &error_support_column,
                &polynomial::multiply_via_ntt(
                    parameters,
                    &polynomial::subtract(parameters, &error_square_column, &one),
                    &polynomial::subtract(parameters, &error_square_column, &four),
                ),
            ),
        );
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::multiply_via_ntt(parameters, &error_column, &error_support_column),
        );
        // lookup fraction pin: (mu - shift - C) * f - 1 = 0.
        let carry_column = plan.base_column_coefficients(
            parameters,
            &trace_domain,
            digit_column(digit, DIGIT_CARRY),
        );
        let fraction_column =
            plan.aux_column_coefficients(parameters, &trace_domain, aux_lookup_column(digit))?;
        let denominator = polynomial::subtract(parameters, &challenge_minus_shift, &carry_column);
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::subtract(
                parameters,
                &polynomial::multiply_via_ntt(parameters, &denominator, &fraction_column),
                &one,
            ),
        );
    }
    // Table fraction pins: (mu - T_k) * f_T_k - m_k = 0.
    for (table_index, table_polynomial) in table_polynomials.iter().enumerate() {
        let fraction_column = plan.aux_column_coefficients(
            parameters,
            &trace_domain,
            aux_table_fraction_column(digit_count, table_index),
        )?;
        let multiplicity_column = plan.base_column_coefficients(
            parameters,
            &trace_domain,
            base_multiplicity_column(digit_count, table_index),
        );
        let denominator = polynomial::subtract(parameters, &challenge_constant, table_polynomial);
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::subtract(
                parameters,
                &polynomial::multiply_via_ntt(parameters, &denominator, &fraction_column),
                &multiplicity_column,
            ),
        );
    }
    if linkage_inputs.is_some() {
        let context = linkage::linkage_constraint_context(ring_degree)?;
        let layout_data = *context.layout();
        let base_poly = |offset: usize| {
            plan.base_column_coefficients(parameters, &trace_domain, linkage_start_base + offset)
        };
        let aux_poly = |offset: usize| {
            plan.aux_column_coefficients(parameters, &trace_domain, linkage_start_aux + offset)
        };
        let negative_indicator = base_poly(linkage::LINK_NEG);
        fold_constraint(
            &mut v,
            &mut alpha_index,
            polynomial::multiply_via_ntt(
                parameters,
                &negative_indicator,
                &polynomial::subtract(parameters, &negative_indicator, &one),
            ),
        );
        // Every commitment field has an independent all-ternary opening tape.
        // Both purposes bind a square column, then enforce the same exact
        // ternary support polynomial.
        for commitment_limb_position in
            0..crate::bgv::setup::commitment::SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
        {
            for randomness_column in
                0..crate::bgv::setup::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH
            {
                let randomness = base_poly(linkage::link_randomness(
                    commitment_limb_position,
                    randomness_column,
                ));
                let randomness_square = base_poly(linkage::link_randomness_square(
                    commitment_limb_position,
                    randomness_column,
                ));
                fold_constraint(
                    &mut v,
                    &mut alpha_index,
                    polynomial::subtract(
                        parameters,
                        &randomness_square,
                        &polynomial::multiply_via_ntt(parameters, &randomness, &randomness),
                    ),
                );
                let square_minus_one = polynomial::subtract(parameters, &randomness_square, &one);
                let support_polynomial =
                    polynomial::multiply_via_ntt(parameters, &randomness, &square_minus_one);
                fold_constraint(&mut v, &mut alpha_index, support_polynomial);
            }
        }
        // Each quotient chunk is reconstructed from committed binary columns.
        let two = parameters.unsigned_word_to_element(2);
        for chunk in 0..2 {
            let mut reconstruction = aux_poly(linkage::aux_carry_chunk(chunk))?;
            let mut power = parameters.one();
            for bit in 0..linkage::carry_chunk_bit_count(&layout_data, chunk) {
                reconstruction = polynomial::subtract(
                    parameters,
                    &reconstruction,
                    &polynomial::scale(
                        parameters,
                        &aux_poly(linkage::aux_carry_bit(&layout_data, chunk, bit))?,
                        &power,
                    ),
                );
                power = parameters.multiply(&power, &two);
            }
            fold_constraint(&mut v, &mut alpha_index, reconstruction);
        }
        for chunk in 0..2 {
            for bit in 0..linkage::carry_chunk_bit_count(&layout_data, chunk) {
                let bit_polynomial = aux_poly(linkage::aux_carry_bit(&layout_data, chunk, bit))?;
                fold_constraint(
                    &mut v,
                    &mut alpha_index,
                    polynomial::multiply_via_ntt(
                        parameters,
                        &bit_polynomial,
                        &polynomial::subtract(parameters, &bit_polynomial, &one),
                    ),
                );
            }
        }
    }
    let q_support = polynomial::divide_by_vanishing(parameters, &v, layout.trace_size);
    let mut support_remainder = polynomial::subtract(
        parameters,
        &v,
        &polynomial::multiply_via_ntt(parameters, &q_support, &vanishing),
    );
    drop(v);
    polynomial::trim(&mut support_remainder);
    if support_remainder
        .iter()
        .any(|c| c.iter().any(|limb| *limb != 0))
    {
        return Err(invalid_key("support constraints do not vanish on H"));
    }

    // Round 3 (streamed): quotients. Their coefficient vectors stay resident
    // (three short vectors) so the combination and opening passes can
    // regenerate their codewords.
    let quotient_coefficients = [q_sc, g, q_support];
    #[cfg(all(test, not(target_arch = "wasm32")))]
    drop(constraint_composition_timer);
    #[cfg(all(test, not(target_arch = "wasm32")))]
    let quotient_commitment_timer = KeyProverPhaseTimer::start(KeyProverPhase::QuotientCommitment);
    let mut quotient_builder = StreamedColumnCommitmentBuilder::begin(
        layout.coset_size,
        QUOTIENT_COLUMN_COUNT,
        private_randomness,
    )?;
    let mut codeword = vec![parameters.zero(); layout.coset_size];
    for coefficients in &quotient_coefficients {
        coset_evaluate_coefficients_into(&coset_domain, &offset, coefficients, &mut codeword);
        quotient_builder.absorb_column(&codeword)?;
    }
    let quotient_commitment = quotient_builder.finalize()?;
    transcript.absorb_digest("key-quotient-root", &quotient_commitment.root());
    #[cfg(all(test, not(target_arch = "wasm32")))]
    drop(quotient_commitment_timer);
    #[cfg(all(test, not(target_arch = "wasm32")))]
    let combination_timer = KeyProverPhaseTimer::start(KeyProverPhase::Combination);

    let weights = transcript.challenge_field_elements(
        parameters,
        "key-combination",
        base_count + material_count + aux_count + QUOTIENT_COLUMN_COUNT + 1,
    );

    // Combination pass: form the weighted coefficient sum in the fixed order
    // base + material + aux + quotient, then perform its coset extension once.
    // Linearity makes this byte-identical to weighting the separately extended
    // codewords while removing one full transform per input column.
    codeword.fill(parameters.zero());
    let mut weight_index = 0;
    for column in 0..base_count {
        let coefficients = plan.base_column_coefficients(parameters, &trace_domain, column);
        accumulate_weighted_coefficients(
            parameters,
            &mut codeword,
            &weights[weight_index],
            &coefficients,
            0,
        );
        weight_index += 1;
    }
    for digit in 0..material_count {
        let coefficients = plan.material_column_coefficients(parameters, &trace_domain, digit);
        accumulate_weighted_coefficients(
            parameters,
            &mut codeword,
            &weights[weight_index],
            &coefficients,
            0,
        );
        weight_index += 1;
    }
    for column in 0..aux_count {
        let coefficients = plan.aux_column_coefficients(parameters, &trace_domain, column)?;
        accumulate_weighted_coefficients(
            parameters,
            &mut codeword,
            &weights[weight_index],
            &coefficients,
            0,
        );
        weight_index += 1;
    }
    for coefficients in &quotient_coefficients {
        accumulate_weighted_coefficients(
            parameters,
            &mut codeword,
            &weights[weight_index],
            coefficients,
            0,
        );
        weight_index += 1;
    }
    // g degree adjustment (sumcheck soundness): re-enter g shifted by
    // x^{trace_size + 1} so the combined FRI bound forces deg(g) <=
    // trace_size - 2. See `g_degree_adjustment_shift`. The shifted codeword is
    // derived from g's coefficients and is not committed or opened; the
    // verifier reconstructs its value from the opened g column, so this adds no
    // proof bytes.
    let g_shift = g_degree_adjustment_shift(layout.trace_size);
    accumulate_weighted_coefficients(
        parameters,
        &mut codeword,
        &weights[weight_index],
        &quotient_coefficients[QUOTIENT_G],
        g_shift,
    );
    weight_index += 1;
    debug_assert_eq!(weight_index, weights.len());
    coset_evaluate_coefficients_in_place(&coset_domain, &offset, &mut codeword);
    #[cfg(all(test, not(target_arch = "wasm32")))]
    drop(combination_timer);
    #[cfg(all(test, not(target_arch = "wasm32")))]
    let fri_timer = KeyProverPhaseTimer::start(KeyProverPhase::Fri);

    let fri_commitment = fri_commit(
        parameters,
        &mut transcript,
        &codeword,
        &offset,
        private_randomness,
    )?;
    let query_positions = transcript.challenge_positions(
        "key-query",
        layout.coset_size,
        proof_parameters.query_count,
    );
    let fri = fri_answer(&fri_commitment, &query_positions);
    #[cfg(all(test, not(target_arch = "wasm32")))]
    drop(fri_timer);
    #[cfg(all(test, not(target_arch = "wasm32")))]
    let openings_timer = KeyProverPhaseTimer::start(KeyProverPhase::Openings);

    // Opening pass: regenerate each column's codeword once more and collect the
    // values at the sorted unique opened positions.
    let half = layout.coset_size / 2;
    let mut open_indices = Vec::with_capacity(query_positions.len() * 2);
    for &position in &query_positions {
        let folded = position % half;
        open_indices.push(folded);
        open_indices.push(folded + half);
    }
    let sorted = sorted_unique_indices(open_indices.iter().copied());
    let mut base_rows_values = vec![Vec::with_capacity(base_count); sorted.len()];
    for column in 0..base_count {
        let coefficients = plan.base_column_coefficients(parameters, &trace_domain, column);
        coset_evaluate_coefficients_into(&coset_domain, &offset, &coefficients, &mut codeword);
        for (row, &index) in base_rows_values.iter_mut().zip(sorted.iter()) {
            row.push(codeword[index]);
        }
    }
    let mut material_rows_values = vec![Vec::with_capacity(material_count); sorted.len()];
    for digit in 0..material_count {
        let coefficients = plan.material_column_coefficients(parameters, &trace_domain, digit);
        coset_evaluate_coefficients_into(&coset_domain, &offset, &coefficients, &mut codeword);
        for (row, &index) in material_rows_values.iter_mut().zip(sorted.iter()) {
            row.push(codeword[index]);
        }
    }
    let mut aux_rows_values = vec![Vec::with_capacity(aux_count); sorted.len()];
    for column in 0..aux_count {
        let coefficients = plan.aux_column_coefficients(parameters, &trace_domain, column)?;
        coset_evaluate_coefficients_into(&coset_domain, &offset, &coefficients, &mut codeword);
        for (row, &index) in aux_rows_values.iter_mut().zip(sorted.iter()) {
            row.push(codeword[index]);
        }
    }
    let mut quotient_rows_values = vec![Vec::with_capacity(QUOTIENT_COLUMN_COUNT); sorted.len()];
    for coefficients in &quotient_coefficients {
        coset_evaluate_coefficients_into(&coset_domain, &offset, coefficients, &mut codeword);
        for (row, &index) in quotient_rows_values.iter_mut().zip(sorted.iter()) {
            row.push(codeword[index]);
        }
    }
    let base_opening = base_commitment.open_rows(&sorted, base_rows_values)?;
    let material_opening = material_commitment.open_rows(&sorted, material_rows_values)?;
    let aux_opening = aux_commitment.open_rows(&sorted, aux_rows_values)?;
    let quotient_opening = quotient_commitment.open_rows(&sorted, quotient_rows_values)?;
    #[cfg(all(test, not(target_arch = "wasm32")))]
    drop(openings_timer);

    Ok(KeyFriProof {
        base_root: base_commitment.root(),
        material_root: material_commitment.root(),
        aux_root: aux_commitment.root(),
        quotient_root: quotient_commitment.root(),
        fri,
        base_opening,
        material_opening,
        aux_opening,
        quotient_opening,
        lookup_terminal,
        table_terminals,
    })
}
