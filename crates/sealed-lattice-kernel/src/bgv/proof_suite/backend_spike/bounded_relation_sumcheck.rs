//! Space-bounded sumcheck arithmetic for the affine recomposition relation.
//!
//! This module implements the outer degree-two sumcheck and its verifier. It
//! deliberately does not call the raw Merkle diagnostic a polynomial
//! commitment. Verification is complete only when the four terminal witness
//! evaluations supplied to `verify_with_authenticated_terminal_evaluations`
//! came from a separately verified multilinear PCS opening.

use crate::hashing::hash_framed_parts_512;

use super::arena::{
    ArenaGeometry, CIPHERTEXT_MODULUS, GOLDILOCKS_MODULUS, MATERIAL_RADIX, relation_residual_at,
    stacked_value_at,
};
use super::field::ExtensionFieldElement;

const TRANSCRIPT_DOMAIN: &str = "sealed-lattice/backend-research/affine-sumcheck-transcript/v1";
const EQUALITY_POINT_DOMAIN: &str =
    "sealed-lattice/backend-research/affine-sumcheck-equality-point/v1";
const ROUND_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/backend-research/affine-sumcheck-round-challenge/v1";
const CHALLENGE_COEFFICIENT_DOMAIN: &str =
    "sealed-lattice/backend-research/uniform-goldilocks-coefficient/v1";
const INVERSE_OF_TWO: u64 = 9_223_372_034_707_292_161;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RoundPolynomial {
    pub(crate) evaluations_at_zero_one_two: [ExtensionFieldElement; 3],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationSumcheckProof {
    pub(crate) round_polynomials: Vec<RoundPolynomial>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TerminalWitnessEvaluations {
    pub(crate) low_digit: ExtensionFieldElement,
    pub(crate) high_digit: ExtensionFieldElement,
    pub(crate) shifted_secret: ExtensionFieldElement,
    pub(crate) negative_indicator: ExtensionFieldElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedRelationSumcheck {
    pub(crate) terminal_point: Vec<ExtensionFieldElement>,
    pub(crate) terminal_claim: ExtensionFieldElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationSumcheckVerificationError {
    WrongRoundCount { expected: usize, actual: usize },
    RoundClaimMismatch { round_index: usize },
    TerminalRelationMismatch,
}

#[derive(Clone, Copy)]
pub(crate) struct RelationSumcheckContext<'a> {
    pub(crate) geometry: ArenaGeometry,
    pub(crate) canonical_statement: &'a [u8],
    /// The 512-bit witness commitment bound before any sumcheck challenge.
    /// The raw arithmetic diagnostic supplies its non-PCS root; the composed
    /// path supplies the verified streaming commitment root.
    pub(crate) witness_commitment_root: &'a [u8; 64],
}

fn initial_transcript(context: RelationSumcheckContext<'_>) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(context.canonical_statement.len() + 96);
    transcript.extend_from_slice(TRANSCRIPT_DOMAIN.as_bytes());
    transcript.extend_from_slice(
        &context
            .geometry
            .relation_instance_variable_count
            .to_le_bytes(),
    );
    transcript.extend_from_slice(&context.geometry.row_variable_count.to_le_bytes());
    transcript.extend_from_slice(
        &u64::try_from(context.canonical_statement.len())
            .expect("the research statement length fits u64")
            .to_le_bytes(),
    );
    transcript.extend_from_slice(context.canonical_statement);
    transcript.extend_from_slice(context.witness_commitment_root);
    transcript.extend_from_slice(&[0_u8; 40]);
    transcript
}

fn append_round(transcript: &mut Vec<u8>, round_index: usize, round: &RoundPolynomial) {
    transcript.extend_from_slice(
        &u32::try_from(round_index)
            .expect("the relation variable count fits u32")
            .to_le_bytes(),
    );
    for evaluation in round.evaluations_at_zero_one_two {
        transcript.extend_from_slice(&evaluation.to_canonical_bytes());
    }
}

#[cfg(test)]
fn first_canonical_base_field_candidate(candidates: &[u64]) -> Option<u64> {
    candidates
        .iter()
        .copied()
        .find(|candidate| *candidate < GOLDILOCKS_MODULUS)
}

fn sample_uniform_base_field(
    domain: &str,
    transcript: &[u8],
    challenge_index: usize,
    coefficient_index: usize,
) -> u64 {
    let challenge_index_bytes = (challenge_index as u64).to_le_bytes();
    let coefficient_index_bytes = (coefficient_index as u64).to_le_bytes();
    for attempt in 0_u64.. {
        let digest = hash_framed_parts_512(
            CHALLENGE_COEFFICIENT_DOMAIN,
            &[
                domain.as_bytes(),
                transcript,
                &challenge_index_bytes,
                &coefficient_index_bytes,
                &attempt.to_le_bytes(),
            ],
        );
        let candidate = u64::from_le_bytes(
            digest[..8]
                .try_into()
                .expect("a SHAKE-256 digest has at least eight bytes"),
        );
        if candidate < GOLDILOCKS_MODULUS {
            return candidate;
        }
    }
    unreachable!("uniform field sampling eventually accepts")
}

fn derive_extension_challenge(
    domain: &str,
    transcript: &[u8],
    challenge_index: usize,
) -> ExtensionFieldElement {
    ExtensionFieldElement {
        coefficients: core::array::from_fn(|coefficient_index| {
            sample_uniform_base_field(domain, transcript, challenge_index, coefficient_index)
        }),
    }
}

fn equality_random_point(context: RelationSumcheckContext<'_>) -> Vec<ExtensionFieldElement> {
    let transcript = initial_transcript(context);
    (0..context.geometry.relation_variable_count() as usize)
        .map(|variable_index| {
            derive_extension_challenge(EQUALITY_POINT_DOMAIN, &transcript, variable_index)
        })
        .collect()
}

#[inline]
fn multilinear_weight(
    point: &[ExtensionFieldElement],
    boolean_index: usize,
) -> ExtensionFieldElement {
    let mut weight = ExtensionFieldElement::ONE;
    for (variable_index, challenge) in point.iter().enumerate() {
        let bit = (boolean_index >> (point.len() - 1 - variable_index)) & 1;
        weight = weight.mul(if bit == 1 {
            *challenge
        } else {
            ExtensionFieldElement::ONE.sub(*challenge)
        });
    }
    weight
}

fn equality_at_partial_point(
    equality_point: &[ExtensionFieldElement],
    fixed_prefix: &[ExtensionFieldElement],
    current_value: ExtensionFieldElement,
    trailing_boolean_index: usize,
) -> ExtensionFieldElement {
    let mut value = ExtensionFieldElement::ONE;
    for (&left, &right) in equality_point.iter().zip(fixed_prefix) {
        value = value.mul(
            left.mul(right).add(
                ExtensionFieldElement::ONE
                    .sub(left)
                    .mul(ExtensionFieldElement::ONE.sub(right)),
            ),
        );
    }
    let current_equality_coordinate = equality_point[fixed_prefix.len()];
    value = value.mul(
        current_equality_coordinate.mul(current_value).add(
            ExtensionFieldElement::ONE
                .sub(current_equality_coordinate)
                .mul(ExtensionFieldElement::ONE.sub(current_value)),
        ),
    );
    let trailing_point = &equality_point[fixed_prefix.len() + 1..];
    value.mul(multilinear_weight(trailing_point, trailing_boolean_index))
}

fn folded_residual_pair(
    geometry: ArenaGeometry,
    fixed_prefix: &[ExtensionFieldElement],
    trailing_boolean_index: usize,
) -> (ExtensionFieldElement, ExtensionFieldElement) {
    let trailing_variable_count =
        geometry.relation_variable_count() as usize - fixed_prefix.len() - 1;
    let trailing_span = 1usize << trailing_variable_count;
    let fixed_span = 1usize << fixed_prefix.len();
    let mut at_zero = ExtensionFieldElement::ZERO;
    let mut at_one = ExtensionFieldElement::ZERO;
    for fixed_boolean_index in 0..fixed_span {
        let weight = multilinear_weight(fixed_prefix, fixed_boolean_index);
        let zero_index =
            (fixed_boolean_index << (trailing_variable_count + 1)) | trailing_boolean_index;
        let one_index = zero_index | trailing_span;
        at_zero = at_zero.add(weight.mul_base(relation_residual_at(geometry, zero_index)));
        at_one = at_one.add(weight.mul_base(relation_residual_at(geometry, one_index)));
    }
    (at_zero, at_one)
}

fn interpolate_line(
    at_zero: ExtensionFieldElement,
    at_one: ExtensionFieldElement,
    point: ExtensionFieldElement,
) -> ExtensionFieldElement {
    at_zero.add(at_one.sub(at_zero).mul(point))
}

fn streaming_round(
    geometry: ArenaGeometry,
    equality_point: &[ExtensionFieldElement],
    fixed_prefix: &[ExtensionFieldElement],
) -> RoundPolynomial {
    let trailing_variable_count =
        geometry.relation_variable_count() as usize - fixed_prefix.len() - 1;
    let trailing_span = 1usize << trailing_variable_count;
    let evaluation_points = [
        ExtensionFieldElement::ZERO,
        ExtensionFieldElement::ONE,
        ExtensionFieldElement::from_base(2),
    ];
    let mut evaluations = [ExtensionFieldElement::ZERO; 3];
    for trailing_boolean_index in 0..trailing_span {
        let (residual_at_zero, residual_at_one) =
            folded_residual_pair(geometry, fixed_prefix, trailing_boolean_index);
        for (evaluation, point) in evaluations.iter_mut().zip(evaluation_points) {
            let residual = interpolate_line(residual_at_zero, residual_at_one, point);
            let equality = equality_at_partial_point(
                equality_point,
                fixed_prefix,
                point,
                trailing_boolean_index,
            );
            *evaluation = evaluation.add(equality.mul(residual));
        }
    }
    RoundPolynomial {
        evaluations_at_zero_one_two: evaluations,
    }
}

fn folded_residual_table(
    geometry: ArenaGeometry,
    fixed_prefix: &[ExtensionFieldElement],
) -> Vec<ExtensionFieldElement> {
    let held_variable_count = geometry.relation_variable_count() as usize - fixed_prefix.len();
    let held_span = 1usize << held_variable_count;
    let fixed_span = 1usize << fixed_prefix.len();
    let mut table = Vec::with_capacity(held_span);
    for trailing_boolean_index in 0..held_span {
        let mut value = ExtensionFieldElement::ZERO;
        for fixed_boolean_index in 0..fixed_span {
            let weight = multilinear_weight(fixed_prefix, fixed_boolean_index);
            let relation_index =
                (fixed_boolean_index << held_variable_count) | trailing_boolean_index;
            value = value.add(weight.mul_base(relation_residual_at(geometry, relation_index)));
        }
        table.push(value);
    }
    table
}

fn resident_round(
    table: &[ExtensionFieldElement],
    equality_point: &[ExtensionFieldElement],
    fixed_prefix: &[ExtensionFieldElement],
) -> RoundPolynomial {
    let half = table.len() / 2;
    let evaluation_points = [
        ExtensionFieldElement::ZERO,
        ExtensionFieldElement::ONE,
        ExtensionFieldElement::from_base(2),
    ];
    let mut evaluations = [ExtensionFieldElement::ZERO; 3];
    for trailing_boolean_index in 0..half {
        for (evaluation, point) in evaluations.iter_mut().zip(evaluation_points) {
            let residual = interpolate_line(
                table[trailing_boolean_index],
                table[half + trailing_boolean_index],
                point,
            );
            let equality = equality_at_partial_point(
                equality_point,
                fixed_prefix,
                point,
                trailing_boolean_index,
            );
            *evaluation = evaluation.add(equality.mul(residual));
        }
    }
    RoundPolynomial {
        evaluations_at_zero_one_two: evaluations,
    }
}

fn evaluate_degree_two_round(
    round: RoundPolynomial,
    point: ExtensionFieldElement,
) -> ExtensionFieldElement {
    let [at_zero, at_one, at_two] = round.evaluations_at_zero_one_two;
    let point_minus_one = point.sub(ExtensionFieldElement::ONE);
    let point_minus_two = point.sub(ExtensionFieldElement::from_base(2));
    let first_basis = point_minus_one
        .mul(point_minus_two)
        .mul_base(INVERSE_OF_TWO);
    let second_basis = point.mul(ExtensionFieldElement::from_base(2).sub(point));
    let third_basis = point.mul(point_minus_one).mul_base(INVERSE_OF_TWO);
    at_zero
        .mul(first_basis)
        .add(at_one.mul(second_basis))
        .add(at_two.mul(third_basis))
}

pub(crate) fn prove_bounded(
    context: RelationSumcheckContext<'_>,
    held_trailing_variable_count: u32,
) -> RelationSumcheckProof {
    let variable_count = context.geometry.relation_variable_count() as usize;
    let held = usize::min(held_trailing_variable_count as usize, variable_count);
    let crossover_round = variable_count - held;
    let equality_point = equality_random_point(context);
    let mut transcript = initial_transcript(context);
    let mut challenges = Vec::with_capacity(variable_count);
    let mut rounds = Vec::with_capacity(variable_count);

    for round_index in 0..crossover_round {
        let round = streaming_round(context.geometry, &equality_point, &challenges);
        append_round(&mut transcript, round_index, &round);
        let challenge =
            derive_extension_challenge(ROUND_CHALLENGE_DOMAIN, &transcript, round_index);
        rounds.push(round);
        challenges.push(challenge);
    }

    let mut residual_table = folded_residual_table(context.geometry, &challenges);
    for round_index in crossover_round..variable_count {
        let round = resident_round(&residual_table, &equality_point, &challenges);
        append_round(&mut transcript, round_index, &round);
        let challenge =
            derive_extension_challenge(ROUND_CHALLENGE_DOMAIN, &transcript, round_index);
        let half = residual_table.len() / 2;
        for trailing_index in 0..half {
            residual_table[trailing_index] = interpolate_line(
                residual_table[trailing_index],
                residual_table[half + trailing_index],
                challenge,
            );
        }
        residual_table.truncate(half);
        rounds.push(round);
        challenges.push(challenge);
    }

    RelationSumcheckProof {
        round_polynomials: rounds,
    }
}

pub(crate) fn terminal_point(
    context: RelationSumcheckContext<'_>,
    proof: &RelationSumcheckProof,
) -> Result<Vec<ExtensionFieldElement>, RelationSumcheckVerificationError> {
    let expected_round_count = context.geometry.relation_variable_count() as usize;
    if proof.round_polynomials.len() != expected_round_count {
        return Err(RelationSumcheckVerificationError::WrongRoundCount {
            expected: expected_round_count,
            actual: proof.round_polynomials.len(),
        });
    }
    let mut transcript = initial_transcript(context);
    let mut challenges = Vec::with_capacity(expected_round_count);
    let mut claim = ExtensionFieldElement::ZERO;
    for (round_index, round) in proof.round_polynomials.iter().enumerate() {
        if round.evaluations_at_zero_one_two[0].add(round.evaluations_at_zero_one_two[1]) != claim {
            return Err(RelationSumcheckVerificationError::RoundClaimMismatch { round_index });
        }
        append_round(&mut transcript, round_index, round);
        let challenge =
            derive_extension_challenge(ROUND_CHALLENGE_DOMAIN, &transcript, round_index);
        claim = evaluate_degree_two_round(*round, challenge);
        challenges.push(challenge);
    }
    Ok(challenges)
}

pub(crate) fn verify_with_authenticated_terminal_evaluations(
    context: RelationSumcheckContext<'_>,
    proof: &RelationSumcheckProof,
    terminal_evaluations: TerminalWitnessEvaluations,
) -> Result<VerifiedRelationSumcheck, RelationSumcheckVerificationError> {
    let terminal_point = terminal_point(context, proof)?;
    let equality_point = equality_random_point(context);
    let equality_at_terminal = equality_point
        .iter()
        .zip(&terminal_point)
        .map(|(&left, &right)| {
            left.mul(right).add(
                ExtensionFieldElement::ONE
                    .sub(left)
                    .mul(ExtensionFieldElement::ONE.sub(right)),
            )
        })
        .fold(ExtensionFieldElement::ONE, ExtensionFieldElement::mul);
    let terminal_residual = terminal_evaluations
        .low_digit
        .add(terminal_evaluations.high_digit.mul_base(MATERIAL_RADIX))
        .sub(terminal_evaluations.shifted_secret)
        .add(ExtensionFieldElement::ONE)
        .sub(
            terminal_evaluations
                .negative_indicator
                .mul_base(CIPHERTEXT_MODULUS),
        );

    let mut transcript = initial_transcript(context);
    let mut terminal_claim = ExtensionFieldElement::ZERO;
    for (round_index, round) in proof.round_polynomials.iter().enumerate() {
        append_round(&mut transcript, round_index, round);
        let challenge =
            derive_extension_challenge(ROUND_CHALLENGE_DOMAIN, &transcript, round_index);
        terminal_claim = evaluate_degree_two_round(*round, challenge);
    }
    if terminal_claim != equality_at_terminal.mul(terminal_residual) {
        return Err(RelationSumcheckVerificationError::TerminalRelationMismatch);
    }
    Ok(VerifiedRelationSumcheck {
        terminal_point,
        terminal_claim,
    })
}

pub(crate) fn evaluate_witness_columns_at(
    geometry: ArenaGeometry,
    point: &[ExtensionFieldElement],
) -> TerminalWitnessEvaluations {
    assert_eq!(point.len(), geometry.relation_variable_count() as usize);
    let relation_count = geometry.relation_evaluation_count();
    let mut evaluations = [ExtensionFieldElement::ZERO; 4];
    for relation_index in 0..relation_count {
        let weight = multilinear_weight(point, relation_index);
        for (component_index, evaluation) in evaluations.iter_mut().enumerate() {
            let value =
                stacked_value_at(geometry, component_index * relation_count + relation_index);
            *evaluation = evaluation.add(weight.mul_base(value));
        }
    }
    TerminalWitnessEvaluations {
        low_digit: evaluations[0],
        high_digit: evaluations[1],
        shifted_secret: evaluations[2],
        negative_indicator: evaluations[3],
    }
}

pub(crate) fn canonical_proof_bytes(proof: &RelationSumcheckProof) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + proof.round_polynomials.len() * 120);
    bytes.extend_from_slice(b"SLBRSC01");
    bytes.extend_from_slice(
        &u32::try_from(proof.round_polynomials.len())
            .expect("the proof round count fits u32")
            .to_le_bytes(),
    );
    for round in &proof.round_polynomials {
        for evaluation in round.evaluations_at_zero_one_two {
            bytes.extend_from_slice(&evaluation.to_canonical_bytes());
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash_framed_parts_512;

    fn context<'a>(
        geometry: ArenaGeometry,
        statement: &'a [u8],
        root: &'a [u8; 64],
    ) -> RelationSumcheckContext<'a> {
        RelationSumcheckContext {
            geometry,
            canonical_statement: statement,
            witness_commitment_root: root,
        }
    }

    #[test]
    fn field_candidate_selection_rejects_noncanonical_values() {
        assert_eq!(
            first_canonical_base_field_candidate(&[
                GOLDILOCKS_MODULUS,
                u64::MAX,
                GOLDILOCKS_MODULUS - 1,
            ]),
            Some(GOLDILOCKS_MODULUS - 1)
        );
        assert_eq!(
            first_canonical_base_field_candidate(&[GOLDILOCKS_MODULUS, u64::MAX]),
            None
        );
    }

    #[test]
    fn bounded_and_resident_provers_emit_identical_canonical_bytes() {
        let geometry = ArenaGeometry::new(2, 6);
        let root = hash_framed_parts_512("test/raw-root", &[b"fixture"]);
        let context = context(geometry, b"affine relation test statement", &root);
        let resident = prove_bounded(context, geometry.relation_variable_count());
        for held_variables in [0, 1, 3, 5] {
            let bounded = prove_bounded(context, held_variables);
            assert_eq!(
                canonical_proof_bytes(&bounded),
                canonical_proof_bytes(&resident)
            );
        }
    }

    #[test]
    fn verifier_accepts_the_valid_affine_relation() {
        let geometry = ArenaGeometry::new(2, 6);
        let root = hash_framed_parts_512("test/raw-root", &[b"valid"]);
        let context = context(geometry, b"valid affine statement", &root);
        let proof = prove_bounded(context, 4);
        let point = terminal_point(context, &proof).expect("derive terminal point");
        let openings = evaluate_witness_columns_at(geometry, &point);
        let verified = verify_with_authenticated_terminal_evaluations(context, &proof, openings)
            .expect("the valid affine relation verifies");
        assert_eq!(verified.terminal_point, point);
        assert_eq!(verified.terminal_claim, ExtensionFieldElement::ZERO);
    }

    #[test]
    fn verifier_rejects_round_and_terminal_mutations() {
        let geometry = ArenaGeometry::new(1, 5);
        let root = hash_framed_parts_512("test/raw-root", &[b"mutations"]);
        let context = context(geometry, b"mutation statement", &root);
        let proof = prove_bounded(context, 3);
        let point = terminal_point(context, &proof).expect("derive terminal point");
        let openings = evaluate_witness_columns_at(geometry, &point);

        let mut round_mutation = proof.clone();
        round_mutation.round_polynomials[0].evaluations_at_zero_one_two[0] =
            ExtensionFieldElement::ONE;
        assert!(matches!(
            verify_with_authenticated_terminal_evaluations(context, &round_mutation, openings),
            Err(RelationSumcheckVerificationError::RoundClaimMismatch { .. })
        ));

        let mut opening_mutation = openings;
        opening_mutation.shifted_secret = opening_mutation
            .shifted_secret
            .add(ExtensionFieldElement::ONE);
        assert_eq!(
            verify_with_authenticated_terminal_evaluations(context, &proof, opening_mutation),
            Err(RelationSumcheckVerificationError::TerminalRelationMismatch)
        );
    }

    #[test]
    fn raw_root_cannot_authenticate_caller_supplied_terminal_evaluations() {
        let geometry = ArenaGeometry::new(1, 5);
        let root = hash_framed_parts_512("test/raw-root", &[b"unrelated committed bytes"]);
        let context = context(geometry, b"authentication-boundary statement", &root);
        let zero_round = RoundPolynomial {
            evaluations_at_zero_one_two: [ExtensionFieldElement::ZERO; 3],
        };
        let forged_proof = RelationSumcheckProof {
            round_polynomials: vec![zero_round; geometry.relation_variable_count() as usize],
        };
        let terminal =
            terminal_point(context, &forged_proof).expect("derive forged terminal point");
        let committed_witness_evaluations = evaluate_witness_columns_at(geometry, &terminal);
        let caller_supplied_evaluations = TerminalWitnessEvaluations {
            low_digit: ExtensionFieldElement::ZERO,
            high_digit: ExtensionFieldElement::ZERO,
            shifted_secret: ExtensionFieldElement::ONE,
            negative_indicator: ExtensionFieldElement::ZERO,
        };

        assert_ne!(
            committed_witness_evaluations, caller_supplied_evaluations,
            "the forged evaluations must not accidentally equal the committed witness"
        );
        assert!(
            verify_with_authenticated_terminal_evaluations(
                context,
                &forged_proof,
                caller_supplied_evaluations,
            )
            .is_ok(),
            "the arithmetic verifier deliberately relies on a separate PCS to authenticate openings"
        );
    }

    #[test]
    fn statement_and_root_change_the_terminal_query() {
        let geometry = ArenaGeometry::new(1, 5);
        let first_root = hash_framed_parts_512("test/raw-root", &[b"first"]);
        let second_root = hash_framed_parts_512("test/raw-root", &[b"second"]);
        let first = context(geometry, b"first statement", &first_root);
        let second = context(geometry, b"second statement", &second_root);
        let proof = prove_bounded(first, 3);
        assert_ne!(
            terminal_point(first, &proof).expect("first point"),
            terminal_point(second, &proof).expect("second point")
        );
    }
}
