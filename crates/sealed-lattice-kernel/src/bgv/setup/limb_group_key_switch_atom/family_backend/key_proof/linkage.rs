//! BDLOP same-secret linkage for key-bearing atom proofs.
//!
//! The statement carries one accepted source constant commitment from the
//! original VSS coefficient material. The atom invokes the setup proof's
//! established degree-four, two-repetition BDLOP lincheck unchanged. Its
//! canonical base-field equations are lifted into the atom proof field with a
//! bounded quotient. The quotient depends on the post-base-commitment
//! lincheck challenges, so its two range-checked chunks are committed in the
//! auxiliary round. A final atom-field batching challenge is drawn only after
//! that auxiliary commitment.

use super::*;
#[cfg(test)]
use crate::bgv::setup::commitment::SETUP_COMMITMENT_HIDING_SECRET_WIDTH;
#[cfg(test)]
use crate::bgv::setup::commitment::setup_commitment_randomness_coefficient_bound;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_RANDOMNESS_WIDTH,
    SETUP_COMMITMENT_ROW_COUNT, setup_commitment_root,
};
use crate::bgv::setup::trustee_evaluation_key_proof::{
    SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE, SAME_SECRET_LINKAGE_ATOM_LINCHECK_REPETITIONS,
    SameSecretLinkageAtomFieldForms, SameSecretLinkageStatement,
    build_same_secret_linkage_atom_field_forms,
};

const CARRY_CHUNK_COUNT: usize = 2;
const CARRY_SHIFT_MULTIPLIER: usize = 8;
#[cfg(test)]
const CARRY_EXCLUSIVE_BOUND_MULTIPLIER: usize = 16;

pub(in super::super) struct LinkageStatement<'a> {
    pub(in super::super) linkage: &'a SameSecretLinkageStatement,
}

#[cfg(test)]
pub(in super::super) struct LinkageWitness<'a> {
    pub(in super::super) negative_indicator: &'a [i64],
    pub(in super::super) randomness_by_commitment_limb: &'a [Vec<Vec<i64>>],
}

fn invalid_linkage(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in super::super) struct LinkageLayout {
    pub(super) low_carry_chunk_bit_count: usize,
}

pub(in super::super) fn linkage_layout(ring_degree: usize) -> CanonicalResult<LinkageLayout> {
    if !ring_degree.is_power_of_two() {
        return Err(invalid_linkage(
            "the BDLOP linkage requires a power-of-two ring degree",
        ));
    }
    if linkage_claim_count() > ring_degree {
        return Err(invalid_linkage(
            "the BDLOP linkage claim count exceeds the trace domain",
        ));
    }
    Ok(LinkageLayout {
        // The low chunk ranges over [0, 2N); the high chunk is separately
        // constrained to three bits, proving the exact total range [0, 16N).
        low_carry_chunk_bit_count: ring_degree.ilog2() as usize + 1,
    })
}

pub(super) fn carry_chunk_bit_count(layout: &LinkageLayout, chunk: usize) -> usize {
    match chunk {
        0 => layout.low_carry_chunk_bit_count,
        1 => 3,
        _ => 0,
    }
}

fn total_carry_bit_count(layout: &LinkageLayout) -> usize {
    carry_chunk_bit_count(layout, 0) + carry_chunk_bit_count(layout, 1)
}

pub(super) fn linkage_claim_count() -> usize {
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() * SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE
}

pub(in super::super) fn linkage_base_column_count(_layout: &LinkageLayout) -> usize {
    1 + 2 * SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() * SETUP_COMMITMENT_RANDOMNESS_WIDTH
}

pub(in super::super) fn linkage_aux_column_count(layout: &LinkageLayout) -> usize {
    CARRY_CHUNK_COUNT + total_carry_bit_count(layout)
}

pub(in super::super) fn linkage_support_constraint_count(layout: &LinkageLayout) -> usize {
    1 + 2 * SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() * SETUP_COMMITMENT_RANDOMNESS_WIDTH
        + CARRY_CHUNK_COUNT
        + total_carry_bit_count(layout)
}

pub(super) const LINK_NEG: usize = 0;

fn flattened_randomness_position(commitment_limb_position: usize, column: usize) -> usize {
    commitment_limb_position * SETUP_COMMITMENT_RANDOMNESS_WIDTH + column
}

pub(super) fn link_randomness(commitment_limb_position: usize, column: usize) -> usize {
    1 + 2 * flattened_randomness_position(commitment_limb_position, column)
}

pub(super) fn link_randomness_square(commitment_limb_position: usize, column: usize) -> usize {
    2 + 2 * flattened_randomness_position(commitment_limb_position, column)
}

pub(super) fn aux_carry_chunk(chunk: usize) -> usize {
    chunk
}

pub(super) fn aux_carry_bit(layout: &LinkageLayout, chunk: usize, bit: usize) -> usize {
    CARRY_CHUNK_COUNT
        + if chunk == 0 {
            0
        } else {
            carry_chunk_bit_count(layout, 0)
        }
        + bit
}

pub(super) fn carry_chunk_base(ring_degree: usize) -> u64 {
    (ring_degree as u64) * 2
}

fn carry_shift(ring_degree: usize) -> i128 {
    (CARRY_SHIFT_MULTIPLIER * ring_degree) as i128
}

#[cfg(test)]
pub(in super::super) struct LinkageWitnessValues {
    pub(super) negative_indicator: Vec<i64>,
    pub(super) randomness_by_commitment_limb: Vec<Vec<Vec<i64>>>,
    pub(super) carry_chunks: Option<Vec<Vec<u64>>>,
    pub(super) carry_bits: Option<Vec<Vec<Vec<u64>>>>,
}

fn validate_statement(statement: &LinkageStatement<'_>, ring_degree: usize) -> CanonicalResult<()> {
    let linkage = statement.linkage;
    if linkage.commitments.len() != 1 {
        return Err(invalid_linkage(
            "the key-bearing BDLOP linkage requires exactly one source constant commitment",
        ));
    }
    let commitment = &linkage.commitments[0];
    if commitment.ring_degree != ring_degree {
        return Err(invalid_linkage(
            "the BDLOP linkage commitment ring degree does not match the key relation",
        ));
    }
    if commitment.limbs.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
        || commitment.limbs.iter().any(|limb| {
            limb.rows.len() != SETUP_COMMITMENT_ROW_COUNT
                || limb.rows.iter().any(|row| row.len() != ring_degree)
        })
    {
        return Err(invalid_linkage(
            "the BDLOP linkage commitment does not match the canonical three-field shape",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(in super::super) fn build_linkage_witness_values(
    statement: &LinkageStatement<'_>,
    witness: &LinkageWitness<'_>,
    secret: &[i64],
    ring_degree: usize,
    _layout: &LinkageLayout,
) -> CanonicalResult<LinkageWitnessValues> {
    validate_statement(statement, ring_degree)?;
    if secret.len() != ring_degree || witness.negative_indicator.len() != ring_degree {
        return Err(invalid_linkage(
            "the BDLOP linkage secret and sign indicator must match the ring degree",
        ));
    }
    if witness.randomness_by_commitment_limb.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
        || witness
            .randomness_by_commitment_limb
            .iter()
            .any(|randomness_by_column| {
                randomness_by_column.len() != SETUP_COMMITMENT_RANDOMNESS_WIDTH
                    || randomness_by_column
                        .iter()
                        .any(|column| column.len() != ring_degree)
            })
    {
        return Err(invalid_linkage(
            "the BDLOP linkage opening randomness does not match the canonical shape",
        ));
    }
    for (indicator, secret_value) in witness.negative_indicator.iter().zip(secret.iter()) {
        if *indicator != i64::from(*secret_value < 0) {
            return Err(invalid_linkage(
                "the BDLOP linkage sign indicator does not match the key secret",
            ));
        }
    }
    for randomness_by_column in witness.randomness_by_commitment_limb {
        for (randomness_column_index, randomness_column) in randomness_by_column.iter().enumerate()
        {
            let coefficient_bound =
                setup_commitment_randomness_coefficient_bound(randomness_column_index)
                    .expect("a canonical commitment column has a support bound");
            if randomness_column
                .iter()
                .any(|value| i128::from(*value).unsigned_abs() > coefficient_bound as u128)
            {
                return Err(invalid_linkage(
                    "the BDLOP linkage opening randomness exceeds its selected distribution support",
                ));
            }
        }
    }
    Ok(LinkageWitnessValues {
        negative_indicator: witness.negative_indicator.to_vec(),
        randomness_by_commitment_limb: witness.randomness_by_commitment_limb.to_vec(),
        carry_chunks: None,
        carry_bits: None,
    })
}

pub(in super::super) struct LinkageFieldChallenges {
    lincheck_challenges: Vec<[u64; SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE]>,
    linkage_alpha: Vec<[u64; SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE]>,
}

pub(in super::super) struct LinkageChallenges {
    fields: Vec<LinkageFieldChallenges>,
}

fn draw_nonzero_extension_element(
    transcript: &mut Transcript,
    label: &str,
    modulus: u64,
) -> CanonicalResult<[u64; SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE]> {
    for _ in 0..transcript.maximum_candidate_draws_per_output() {
        let residues = transcript.challenge_residues(
            label,
            modulus,
            SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE,
        )?;
        let element: [u64; SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE] = residues
            .try_into()
            .map_err(|_| invalid_linkage("the transcript returned a wrong extension degree"))?;
        if element.iter().any(|coefficient| *coefficient != 0) {
            return Ok(element);
        }
    }
    Err(invalid_linkage(
        "the key-switch atom nonzero extension challenge draw limit was exhausted",
    ))
}

fn draw_extension_elements(
    transcript: &mut Transcript,
    label: &str,
    modulus: u64,
    count: usize,
) -> CanonicalResult<Vec<[u64; SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE]>> {
    (0..count)
        .map(|_| {
            transcript
                .challenge_residues(label, modulus, SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE)
                .and_then(|residues| {
                    residues.try_into().map_err(|_| {
                        invalid_linkage("the transcript returned a wrong extension degree")
                    })
                })
        })
        .collect()
}

pub(in super::super) fn draw_linkage_challenges(
    transcript: &mut Transcript,
    statement: &LinkageStatement<'_>,
    ring_degree: usize,
) -> CanonicalResult<LinkageChallenges> {
    validate_statement(statement, ring_degree)?;
    let fields = statement.linkage.commitments[0]
        .limbs
        .iter()
        .map(|limb| {
            let lincheck_challenges = (0..SAME_SECRET_LINKAGE_ATOM_LINCHECK_REPETITIONS)
                .map(|_| {
                    draw_nonzero_extension_element(transcript, "key-linkage-lincheck", limb.modulus)
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            let linkage_alpha = draw_extension_elements(
                transcript,
                "key-linkage-alpha",
                limb.modulus,
                SETUP_COMMITMENT_ROW_COUNT * SAME_SECRET_LINKAGE_ATOM_LINCHECK_REPETITIONS,
            )?;
            Ok(LinkageFieldChallenges {
                lincheck_challenges,
                linkage_alpha,
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    Ok(LinkageChallenges { fields })
}

struct LinkageClaim {
    commitment_limb_position: usize,
    modulus: u64,
    target: u64,
    secret_form: Vec<u64>,
    negative_form: Vec<u64>,
    randomness_forms: Vec<Vec<u64>>,
}

pub(in super::super) struct LinkagePublicForms {
    claims: Vec<LinkageClaim>,
}

pub(in super::super) fn build_linkage_public_forms(
    statement: &LinkageStatement<'_>,
    challenges: &LinkageChallenges,
    ring_degree: usize,
) -> CanonicalResult<LinkagePublicForms> {
    validate_statement(statement, ring_degree)?;
    if challenges.fields.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
        return Err(invalid_linkage(
            "the BDLOP linkage challenge fields do not match the commitment fields",
        ));
    }
    let mut claims = Vec::with_capacity(linkage_claim_count());
    for (commitment_field, field_challenges) in challenges.fields.iter().enumerate() {
        let field_forms: SameSecretLinkageAtomFieldForms =
            build_same_secret_linkage_atom_field_forms(
                statement.linkage,
                commitment_field,
                &field_challenges.lincheck_challenges,
                &field_challenges.linkage_alpha,
            )?;
        if field_forms.witness_vectors.len() != 2 + SETUP_COMMITMENT_RANDOMNESS_WIDTH
            || field_forms
                .witness_vectors
                .iter()
                .any(|vector| vector.len() != ring_degree)
        {
            return Err(invalid_linkage(
                "the established BDLOP lincheck returned an unexpected witness-vector shape",
            ));
        }
        for extension_coordinate in 0..SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE {
            claims.push(LinkageClaim {
                commitment_limb_position: commitment_field,
                modulus: field_forms.modulus,
                target: field_forms.target[extension_coordinate],
                secret_form: field_forms.witness_vectors[0]
                    .iter()
                    .map(|element| element[extension_coordinate])
                    .collect(),
                negative_form: field_forms.witness_vectors[1]
                    .iter()
                    .map(|element| element[extension_coordinate])
                    .collect(),
                randomness_forms: field_forms.witness_vectors[2..]
                    .iter()
                    .map(|vector| {
                        vector
                            .iter()
                            .map(|element| element[extension_coordinate])
                            .collect()
                    })
                    .collect(),
            });
        }
    }
    Ok(LinkagePublicForms { claims })
}

#[cfg(test)]
pub(in super::super) fn populate_linkage_reduced_witness(
    values: &mut LinkageWitnessValues,
    public_forms: &LinkagePublicForms,
    secret: &[i64],
    ring_degree: usize,
    layout: &LinkageLayout,
) -> CanonicalResult<()> {
    if public_forms.claims.len() != linkage_claim_count() {
        return Err(invalid_linkage(
            "the BDLOP linkage public form count does not match the canonical claim count",
        ));
    }
    let mut carry_chunks = vec![vec![0_u64; ring_degree]; CARRY_CHUNK_COUNT];
    let mut carry_bits = (0..CARRY_CHUNK_COUNT)
        .map(|chunk| vec![vec![0_u64; ring_degree]; carry_chunk_bit_count(layout, chunk)])
        .collect::<Vec<_>>();
    let chunk_base = u128::from(carry_chunk_base(ring_degree));
    let exclusive_bound = (CARRY_EXCLUSIVE_BOUND_MULTIPLIER * ring_degree) as i128;
    for (claim_index, claim) in public_forms.claims.iter().enumerate() {
        let dot_signed = |form: &[u64], witness: &[i64]| -> i128 {
            form.iter()
                .zip(witness.iter())
                .map(|(coefficient, value)| i128::from(*coefficient) * i128::from(*value))
                .sum()
        };
        let mut difference = dot_signed(&claim.secret_form, secret)
            + dot_signed(&claim.negative_form, &values.negative_indicator)
            - i128::from(claim.target);
        let randomness_by_column = values
            .randomness_by_commitment_limb
            .get(claim.commitment_limb_position)
            .ok_or_else(|| {
                invalid_linkage(
                    "the BDLOP linkage claim references a missing commitment-limb opening",
                )
            })?;
        for (form, randomness) in claim
            .randomness_forms
            .iter()
            .zip(randomness_by_column.iter())
        {
            difference += dot_signed(form, randomness);
        }
        let modulus = i128::from(claim.modulus);
        if difference.rem_euclid(modulus) != 0 {
            return Err(invalid_linkage(
                "the key secret and opening randomness do not open the BDLOP constant commitment",
            ));
        }
        let shifted_carry = difference / modulus + carry_shift(ring_degree);
        if !(0..exclusive_bound).contains(&shifted_carry) {
            return Err(invalid_linkage(
                "the BDLOP linkage quotient exceeds its proven no-wrap bound",
            ));
        }
        let mut remaining = u128::try_from(shifted_carry)
            .map_err(|_| invalid_linkage("the shifted BDLOP quotient is negative"))?;
        for chunk in 0..CARRY_CHUNK_COUNT {
            let chunk_value = (remaining % chunk_base) as u64;
            remaining /= chunk_base;
            carry_chunks[chunk][claim_index] = chunk_value;
            for bit in 0..carry_chunk_bit_count(layout, chunk) {
                carry_bits[chunk][bit][claim_index] = (chunk_value >> bit) & 1;
            }
        }
        if remaining != 0 {
            return Err(invalid_linkage(
                "the BDLOP linkage quotient does not fit its two committed chunks",
            ));
        }
    }
    values.carry_chunks = Some(carry_chunks);
    values.carry_bits = Some(carry_bits);
    Ok(())
}

#[cfg(test)]
pub(super) fn linkage_base_value_column<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    _layout: &LinkageLayout,
    values: &LinkageWitnessValues,
    offset: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    if offset == LINK_NEG {
        return values
            .negative_indicator
            .iter()
            .map(|value| parameters.signed_word_to_element(*value))
            .collect();
    }
    let randomness_position = (offset - 1) / 2;
    let commitment_limb_position = randomness_position / SETUP_COMMITMENT_RANDOMNESS_WIDTH;
    let randomness_column = randomness_position % SETUP_COMMITMENT_RANDOMNESS_WIDTH;
    let randomness =
        &values.randomness_by_commitment_limb[commitment_limb_position][randomness_column];
    if (offset - 1).is_multiple_of(2) {
        randomness
            .iter()
            .map(|value| parameters.signed_word_to_element(*value))
            .collect()
    } else {
        randomness
            .iter()
            .map(|value| parameters.signed_word_to_element(value * value))
            .collect()
    }
}

#[cfg(test)]
pub(super) fn linkage_aux_value_column<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    layout: &LinkageLayout,
    values: &LinkageWitnessValues,
    offset: usize,
) -> CanonicalResult<Vec<[u64; LIMB_COUNT]>> {
    let chunks = values.carry_chunks.as_ref().ok_or_else(|| {
        invalid_linkage("the BDLOP linkage quotient was not derived before the auxiliary round")
    })?;
    let bits = values.carry_bits.as_ref().ok_or_else(|| {
        invalid_linkage(
            "the BDLOP linkage quotient bits were not derived before the auxiliary round",
        )
    })?;
    if offset < CARRY_CHUNK_COUNT {
        return Ok(chunks[offset]
            .iter()
            .map(|value| parameters.unsigned_word_to_element(*value))
            .collect());
    }
    let bit_offset = offset - CARRY_CHUNK_COUNT;
    let low_bit_count = carry_chunk_bit_count(layout, 0);
    let (chunk, bit) = if bit_offset < low_bit_count {
        (0, bit_offset)
    } else {
        (1, bit_offset - low_bit_count)
    };
    Ok(bits[chunk][bit]
        .iter()
        .map(|value| parameters.unsigned_word_to_element(*value))
        .collect())
}

pub(in super::super) struct LinkageConstraintContext {
    pub(super) layout: LinkageLayout,
}

impl LinkageConstraintContext {
    pub(super) fn layout(&self) -> &LinkageLayout {
        &self.layout
    }
}

pub(in super::super) fn linkage_constraint_context(
    ring_degree: usize,
) -> CanonicalResult<LinkageConstraintContext> {
    Ok(LinkageConstraintContext {
        layout: linkage_layout(ring_degree)?,
    })
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn push_linkage_support_values<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    context: &LinkageConstraintContext,
    base_values: &[[u64; LIMB_COUNT]],
    aux_values: &[[u64; LIMB_COUNT]],
    base_start: usize,
    aux_start: usize,
    _challenge: &[u64; LIMB_COUNT],
    constraints: &mut Vec<[u64; LIMB_COUNT]>,
) {
    let one = parameters.one();
    let negative_indicator = base_values[base_start + LINK_NEG];
    constraints.push(parameters.multiply(
        &negative_indicator,
        &parameters.subtract(&negative_indicator, &one),
    ));
    for commitment_limb_position in 0..SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
        for randomness_column in 0..SETUP_COMMITMENT_RANDOMNESS_WIDTH {
            let randomness = base_values
                [base_start + link_randomness(commitment_limb_position, randomness_column)];
            let randomness_square = base_values
                [base_start + link_randomness_square(commitment_limb_position, randomness_column)];
            constraints.push(parameters.subtract(
                &randomness_square,
                &parameters.multiply(&randomness, &randomness),
            ));
            let square_minus_one = parameters.subtract(&randomness_square, &one);
            constraints.push(parameters.multiply(&randomness, &square_minus_one));
        }
    }
    let two = parameters.unsigned_word_to_element(2);
    for chunk in 0..CARRY_CHUNK_COUNT {
        let mut reconstruction = aux_values[aux_start + aux_carry_chunk(chunk)];
        let mut power = one;
        for bit in 0..carry_chunk_bit_count(&context.layout, chunk) {
            let bit_value = aux_values[aux_start + aux_carry_bit(&context.layout, chunk, bit)];
            reconstruction =
                parameters.subtract(&reconstruction, &parameters.multiply(&power, &bit_value));
            power = parameters.multiply(&power, &two);
        }
        constraints.push(reconstruction);
    }
    for chunk in 0..CARRY_CHUNK_COUNT {
        for bit in 0..carry_chunk_bit_count(&context.layout, chunk) {
            let bit_value = aux_values[aux_start + aux_carry_bit(&context.layout, chunk, bit)];
            constraints
                .push(parameters.multiply(&bit_value, &parameters.subtract(&bit_value, &one)));
        }
    }
}

pub(in super::super) struct LinkageForms<const LIMB_COUNT: usize> {
    pub(super) secret_form: Vec<[u64; LIMB_COUNT]>,
    pub(super) negative_form: Vec<[u64; LIMB_COUNT]>,
    pub(super) randomness_forms: Vec<Vec<[u64; LIMB_COUNT]>>,
    pub(super) carry_chunk_forms: Vec<Vec<[u64; LIMB_COUNT]>>,
    pub(super) target: [u64; LIMB_COUNT],
}

pub(in super::super) fn build_linkage_forms<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    public_forms: &LinkagePublicForms,
    ring_degree: usize,
    weights: &[[u64; LIMB_COUNT]],
) -> CanonicalResult<LinkageForms<LIMB_COUNT>> {
    if weights.len() != public_forms.claims.len() {
        return Err(invalid_linkage(
            "the BDLOP linkage batching-weight count does not match the claim count",
        ));
    }
    let mut secret_form = vec![parameters.zero(); ring_degree];
    let mut negative_form = vec![parameters.zero(); ring_degree];
    let mut randomness_forms = vec![
        vec![parameters.zero(); ring_degree];
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
            * SETUP_COMMITMENT_RANDOMNESS_WIDTH
    ];
    let mut carry_chunk_forms = vec![vec![parameters.zero(); ring_degree]; CARRY_CHUNK_COUNT];
    let mut target = parameters.zero();
    let chunk_base = carry_chunk_base(ring_degree);
    for (claim_index, (claim, weight)) in public_forms.claims.iter().zip(weights.iter()).enumerate()
    {
        let add_scaled_form = |destination: &mut [[u64; LIMB_COUNT]], source: &[u64]| {
            for (destination_value, source_value) in destination.iter_mut().zip(source.iter()) {
                *destination_value = parameters.add(
                    destination_value,
                    &parameters
                        .multiply(weight, &parameters.unsigned_word_to_element(*source_value)),
                );
            }
        };
        add_scaled_form(&mut secret_form, &claim.secret_form);
        add_scaled_form(&mut negative_form, &claim.negative_form);
        let first_randomness_position =
            claim.commitment_limb_position * SETUP_COMMITMENT_RANDOMNESS_WIDTH;
        for (destination, source) in randomness_forms[first_randomness_position
            ..first_randomness_position + SETUP_COMMITMENT_RANDOMNESS_WIDTH]
            .iter_mut()
            .zip(claim.randomness_forms.iter())
        {
            add_scaled_form(destination, source);
        }
        let modulus = parameters.unsigned_word_to_element(claim.modulus);
        let mut chunk_power = parameters.one();
        for chunk_form in &mut carry_chunk_forms {
            let coefficient = parameters
                .negate(&parameters.multiply(weight, &parameters.multiply(&modulus, &chunk_power)));
            chunk_form[claim_index] = parameters.add(&chunk_form[claim_index], &coefficient);
            chunk_power = parameters.multiply(
                &chunk_power,
                &parameters.unsigned_word_to_element(chunk_base),
            );
        }
        let adjusted_target = parameters.subtract(
            &parameters.unsigned_word_to_element(claim.target),
            &parameters.multiply(
                &modulus,
                &parameters.unsigned_word_to_element(carry_shift(ring_degree) as u64),
            ),
        );
        target = parameters.add(&target, &parameters.multiply(weight, &adjusted_target));
    }
    Ok(LinkageForms {
        secret_form,
        negative_form,
        randomness_forms,
        carry_chunk_forms,
        target,
    })
}

pub(in super::super) fn absorb_linkage_statement(
    transcript: &mut Transcript,
    statement: &LinkageStatement<'_>,
) -> CanonicalResult<()> {
    let linkage = statement.linkage;
    let commitment = linkage
        .commitments
        .first()
        .ok_or_else(|| invalid_linkage("the BDLOP linkage commitment is missing"))?;
    transcript.absorb(
        "linkage-seed-hash",
        linkage.public_matrix_seed_hash.as_bytes(),
    );
    transcript.absorb_u64(
        "linkage-source-limb",
        commitment.source_rns_limb_index as u64,
    );
    transcript.absorb(
        "linkage-commitment-root",
        setup_commitment_root(commitment)?.as_bytes(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::setup::limb_group_key_switch_atom::proof_field::{
        SELECTED_KEY_SWITCH_PROOF_FIELD_LIMBS, selected_key_switch_proof_field_parameters,
    };

    const TEST_RING_DEGREE: usize = 128;

    fn support_constraints(
        base_values: &[[u64; SELECTED_KEY_SWITCH_PROOF_FIELD_LIMBS]],
        aux_values: &[[u64; SELECTED_KEY_SWITCH_PROOF_FIELD_LIMBS]],
    ) -> Vec<[u64; SELECTED_KEY_SWITCH_PROOF_FIELD_LIMBS]> {
        let parameters = selected_key_switch_proof_field_parameters();
        let context = linkage_constraint_context(TEST_RING_DEGREE).expect("context");
        let mut constraints = Vec::new();
        push_linkage_support_values(
            &parameters,
            &context,
            base_values,
            aux_values,
            0,
            0,
            &parameters.unsigned_word_to_element(19),
            &mut constraints,
        );
        constraints
    }

    #[test]
    fn verifier_support_enforces_each_bdlop_randomness_distribution() {
        let parameters = selected_key_switch_proof_field_parameters();
        let layout = linkage_layout(TEST_RING_DEGREE).expect("layout");
        let mut base_values = vec![parameters.zero(); linkage_base_column_count(&layout)];
        let aux_values = vec![parameters.zero(); linkage_aux_column_count(&layout)];
        base_values[link_randomness(0, 0)] = parameters.unsigned_word_to_element(2);
        base_values[link_randomness_square(0, 0)] = parameters.unsigned_word_to_element(4);

        let constraints = support_constraints(&base_values, &aux_values);
        assert_eq!(
            constraints[1],
            parameters.zero(),
            "the supplied square is internally consistent"
        );
        assert_ne!(
            constraints[2],
            parameters.zero(),
            "the purpose-11 ternary relation must reject randomness value two"
        );

        let purpose_twelve_column = SETUP_COMMITMENT_HIDING_SECRET_WIDTH;
        let mut purpose_twelve_base_values =
            vec![parameters.zero(); linkage_base_column_count(&layout)];
        purpose_twelve_base_values[link_randomness(0, purpose_twelve_column)] =
            parameters.unsigned_word_to_element(2);
        purpose_twelve_base_values[link_randomness_square(0, purpose_twelve_column)] =
            parameters.unsigned_word_to_element(4);
        assert!(
            support_constraints(&purpose_twelve_base_values, &aux_values)
                .iter()
                .any(|constraint| *constraint != parameters.zero()),
            "the purpose-12 ternary relation must reject randomness value two"
        );

        purpose_twelve_base_values[link_randomness(0, purpose_twelve_column)] =
            parameters.negate(&parameters.one());
        purpose_twelve_base_values[link_randomness_square(0, purpose_twelve_column)] =
            parameters.one();
        assert!(
            support_constraints(&purpose_twelve_base_values, &aux_values)
                .iter()
                .all(|constraint| *constraint == parameters.zero()),
            "the purpose-12 ternary relation must accept support endpoint minus one"
        );
    }

    #[test]
    fn verifier_support_proves_the_exact_sixteen_n_quotient_bound() {
        let parameters = selected_key_switch_proof_field_parameters();
        let layout = linkage_layout(TEST_RING_DEGREE).expect("layout");
        let base_values = vec![parameters.zero(); linkage_base_column_count(&layout)];
        let mut aux_values = vec![parameters.zero(); linkage_aux_column_count(&layout)];

        // Seven is the largest accepted high chunk: three committed bits
        // reconstruct it, giving a total shifted quotient below 16N.
        aux_values[aux_carry_chunk(1)] = parameters.unsigned_word_to_element(7);
        for bit in 0..3 {
            aux_values[aux_carry_bit(&layout, 1, bit)] = parameters.unsigned_word_to_element(1);
        }
        let accepted_constraints = support_constraints(&base_values, &aux_values);
        assert!(
            accepted_constraints
                .iter()
                .all(|constraint| *constraint == parameters.zero())
        );

        // Eight would reach 16N when multiplied by the 2N chunk base. No
        // fourth bit exists, so its reconstruction constraint is nonzero.
        aux_values[aux_carry_chunk(1)] = parameters.unsigned_word_to_element(8);
        for bit in 0..3 {
            aux_values[aux_carry_bit(&layout, 1, bit)] = parameters.zero();
        }
        let rejected_constraints = support_constraints(&base_values, &aux_values);
        assert!(
            rejected_constraints
                .iter()
                .any(|constraint| *constraint != parameters.zero())
        );
    }
}
