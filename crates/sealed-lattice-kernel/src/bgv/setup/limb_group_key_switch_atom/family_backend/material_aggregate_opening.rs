//! Batched linear-evaluation opening for the committed key-switch material.
//!
//! Proves `Z = sum_j <delta_j, col_j>` for a set of committed columns `col_j`
//! (each a masked trace polynomial committed as a coset codeword in one salted
//! Merkle tree) against public per-column challenge vectors `delta_j`. On the
//! trace subgroup `H` the mask is a `Z_H` multiple, so `col_j(h)` is the material
//! value and `sum_{h in H} delta_j(h) col_j(h) = <delta_j, material_j>`. The
//! opening is a masked univariate sumcheck plus a radix-2 FRI proximity argument
//! over the same coset and rate the atom proof uses, reusing its domain, Merkle,
//! FRI, and polynomial machinery. The columns are already committed (their atom
//! base root), so the opening recommits nothing new: it opens those columns at a
//! fresh transcript-derived query set against the supplied root and binds their
//! opened values to the claimed sum through the sumcheck.
//!
//! The aggregate binding uses this: with `delta` drawn after every trustee
//! commitment and the published aggregate, `Z = sum_{trustee, digit}
//! <delta_digit, B_col[trustee][digit]>` proven here equals `<delta, sum_trustee
//! recombined_B_trustee>`, which `material_aggregate::material_aggregate_identity_
//! holds` checks against the runtime key and wrap multiples. A forged runtime key
//! or wrap fails that check; a tampered or dropped column fails this opening.

use super::super::proof_field::ProofFieldParameters;
use super::column_commitment::{ColumnOpening, verify_column_opening};
use super::domain::{CyclicDomain, coset_offset};
use super::low_degree::{FriParameters, FriProof, fri_verify_queries, fri_verify_structure};
use super::merkle::MerkleDigest;
use super::polynomial;
use super::transcript::Transcript;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

// Prover-side imports: the batched opening prover and its column/quotient
// commitment and FRI-answer machinery. The creation-side aggregate binding
// (`material_aggregate_creation`) drives these to produce the transported
// openings; the acceptance path only verifies.
#[cfg(test)]
use super::column_commitment::StreamedColumnCommitmentBuilder;
#[cfg(test)]
use super::domain::coset_evaluate_coefficients;
#[cfg(test)]
use super::low_degree::{fri_answer, fri_commit};
#[cfg(test)]
use super::merkle::sorted_unique_indices;

const OPENING_PROTOCOL_LABEL: &str =
    "sealed-lattice/setup/key-switch-atom/material-aggregate-opening";
const OPENING_FRI_RATE_BLOWUP: usize = 4;
// Quotient columns: the sumcheck quotient and the sumcheck helper g.
const OPENING_QUOTIENT_SUMCHECK: usize = 0;
const OPENING_QUOTIENT_G: usize = 1;
const OPENING_QUOTIENT_COUNT: usize = 2;

fn invalid_opening(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

pub(super) struct LinearEvaluationOpeningParameters {
    pub(super) query_count: usize,
}

pub(super) struct LinearEvaluationOpeningProof<const LIMB_COUNT: usize> {
    pub(super) claimed_sum: [u64; LIMB_COUNT],
    pub(super) quotient_root: MerkleDigest,
    pub(super) fri: FriProof<LIMB_COUNT>,
    pub(super) column_opening: ColumnOpening<LIMB_COUNT>,
    pub(super) quotient_opening: ColumnOpening<LIMB_COUNT>,
}

// Canonical, length-framed binary codec for the linear-evaluation opening proof,
// reusing the sibling `proof_codec` writer, reader, and sub-object codecs so the
// framing, self-description, and strict decode match the atom-family key proof.
// The field order below is the wire order; decode reads the same order and calls
// `reader.finish()` to reject any trailing bytes.
//
// The creation-side aggregate binding (`material_aggregate_creation`) produces
// these bytes for transport; the acceptance path only ever decodes them (see
// `decode_linear_evaluation_opening_proof`). Kept alongside
// `prove_linear_evaluation_opening` on the non-test path.
#[cfg(test)]
pub(super) fn encode_linear_evaluation_opening_proof<const LIMB_COUNT: usize>(
    proof: &LinearEvaluationOpeningProof<LIMB_COUNT>,
) -> CanonicalResult<Vec<u8>> {
    use super::proof_codec::{Writer, write_column_opening, write_fri};
    let mut writer = Writer::new();
    writer.write_field(&proof.claimed_sum);
    writer.write_digest(&proof.quotient_root);
    write_fri(&mut writer, &proof.fri)?;
    write_column_opening(&mut writer, &proof.column_opening)?;
    write_column_opening(&mut writer, &proof.quotient_opening)?;
    Ok(writer.bytes)
}

pub(super) fn decode_linear_evaluation_opening_proof<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    bytes: &[u8],
) -> CanonicalResult<LinearEvaluationOpeningProof<LIMB_COUNT>> {
    use super::proof_codec::{Reader, read_column_opening, read_fri};
    let mut reader = Reader::new(bytes, parameters)?;
    let claimed_sum = reader.read_field()?;
    let quotient_root = reader.read_digest()?;
    let fri = read_fri(&mut reader)?;
    let column_opening = read_column_opening(&mut reader)?;
    let quotient_opening = read_column_opening(&mut reader)?;
    reader.finish()?;
    Ok(LinearEvaluationOpeningProof {
        claimed_sum,
        quotient_root,
        fri,
        column_opening,
        quotient_opening,
    })
}

// The trace and coset sizes: the trace is the ring, the coset is
// `OPENING_FRI_RATE_BLOWUP * 2 * ring_degree` (rate 1/4), matching the atom
// backend so the committed columns share the coset the opening reads.
fn opening_layout(ring_degree: usize) -> CanonicalResult<(usize, usize)> {
    if !ring_degree.is_power_of_two() || ring_degree < 2 {
        return Err(invalid_opening("ring degree must be a power of two >= 2"));
    }
    let coset_size = OPENING_FRI_RATE_BLOWUP * 2 * ring_degree;
    if coset_size > super::domain::MAX_TWO_ADIC_ORDER {
        return Err(invalid_opening(
            "opening coset exceeds the field two-adic order at this ring degree",
        ));
    }
    Ok((ring_degree, coset_size))
}

// The trace-subgroup vanishing polynomial `Z_H(x) = x^trace_size - 1`. Used by
// the opening prover and the module tests; the verifier evaluates the vanishing
// polynomial pointwise through `polynomial::vanishing_at`.
#[cfg(test)]
fn vanishing_polynomial<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_size: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let mut vanishing = vec![parameters.zero(); trace_size + 1];
    vanishing[0] = parameters.negate(&parameters.one());
    vanishing[trace_size] = parameters.one();
    vanishing
}

// Degree-adjustment shift for the sumcheck helper g (ethSTARK-style), matching
// the atom backend: g re-enters the combined FRI shifted by `x^{trace_size + 1}`
// so a helper above degree `trace_size - 2` reaches the coset degree bound and
// FRI rejects, closing the univariate-sumcheck soundness gap.
fn g_degree_adjustment_shift(trace_size: usize) -> usize {
    trace_size + 1
}

// The batched linear-evaluation opening prover. `column_coefficients[j]` is the
// masked coefficient form of committed column j (the same coefficients the atom
// commitment used, so the recomputed root matches); `delta_forms[j]` is column
// j's public challenge vector as values over `H` (length ring_degree). Returns
// the recomputed column root and the proof. `Z` is derived from the sumcheck, not
// supplied, so the prover cannot claim a sum inconsistent with the columns.
//
// The creation-side aggregate binding (`material_aggregate_creation`) proves
// these openings; the acceptance path only verifies (see
// `verify_linear_evaluation_opening`).
#[cfg(test)]
pub(super) fn prove_linear_evaluation_opening<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    column_coefficients: &[Vec<[u64; LIMB_COUNT]>],
    delta_forms: &[Vec<[u64; LIMB_COUNT]>],
    opening_parameters: &LinearEvaluationOpeningParameters,
    salt_seed: &mut u64,
) -> CanonicalResult<(MerkleDigest, LinearEvaluationOpeningProof<LIMB_COUNT>)> {
    let column_count = column_coefficients.len();
    if column_count == 0 || delta_forms.len() != column_count {
        return Err(invalid_opening(
            "column and delta counts must match and be non-empty",
        ));
    }
    for delta in delta_forms {
        if delta.len() != ring_degree {
            return Err(invalid_opening("delta form length must match ring degree"));
        }
    }
    let (trace_size, coset_size) = opening_layout(ring_degree)?;
    let trace_domain = CyclicDomain::new(parameters, trace_size)?;
    let coset_domain = CyclicDomain::new(parameters, coset_size)?;
    let offset = coset_offset(parameters);

    // Round 1: commit the columns (recomputing the atom base root) and cache
    // their codewords for the combination and opening passes.
    let mut column_builder =
        StreamedColumnCommitmentBuilder::begin(coset_size, column_count, salt_seed)?;
    let mut column_codewords = Vec::with_capacity(column_count);
    for coefficients in column_coefficients {
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, coefficients);
        column_builder.absorb_column(&codeword)?;
        column_codewords.push(codeword);
    }
    let column_commitment = column_builder.finalize()?;
    let column_root = column_commitment.root();

    let mut transcript = Transcript::new(OPENING_PROTOCOL_LABEL);
    transcript.absorb_u64("ring-degree", ring_degree as u64);
    transcript.absorb_u64("column-count", column_count as u64);
    for delta in delta_forms {
        transcript.absorb_field_elements("delta-form", delta);
    }
    transcript.absorb_digest("column-root", &column_root);

    // Sumcheck: f = sum_j delta_j(x) * col_j(x); sum_H f = sum_j <delta_j, col_j
    // on H> = Z. Each delta form is interpolated to a trace polynomial and
    // multiplied into the masked column coefficients.
    let mut f = vec![parameters.zero()];
    for (delta, coefficients) in delta_forms.iter().zip(column_coefficients.iter()) {
        let delta_polynomial = trace_domain.interpolate(delta);
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::multiply_via_ntt(parameters, &delta_polynomial, coefficients),
        );
    }
    let vanishing = vanishing_polynomial(parameters, trace_size);
    let quotient_sumcheck = polynomial::divide_by_vanishing(parameters, &f, trace_size);
    let mut remainder = polynomial::subtract(
        parameters,
        &f,
        &polynomial::multiply_via_ntt(parameters, &quotient_sumcheck, &vanishing),
    );
    drop(f);
    polynomial::trim(&mut remainder);
    let remainder_constant = remainder
        .first()
        .copied()
        .unwrap_or_else(|| parameters.zero());
    // sum_H f = trace_size * (constant term of f modulo Z_H).
    let claimed_sum = parameters.multiply(
        &parameters.unsigned_word_to_element(trace_size as u64),
        &remainder_constant,
    );
    // g is the sumcheck helper: remainder(x) = remainder_constant + x g(x).
    let helper_g = if remainder.len() > 1 {
        remainder[1..].to_vec()
    } else {
        vec![parameters.zero()]
    };

    // Round 2: commit the quotients (sumcheck quotient and helper g).
    let quotient_coefficients = [quotient_sumcheck, helper_g];
    let mut quotient_builder =
        StreamedColumnCommitmentBuilder::begin(coset_size, OPENING_QUOTIENT_COUNT, salt_seed)?;
    for coefficients in &quotient_coefficients {
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, coefficients);
        quotient_builder.absorb_column(&codeword)?;
    }
    let quotient_commitment = quotient_builder.finalize()?;
    transcript.absorb_digest("quotient-root", &quotient_commitment.root());
    transcript.absorb_field_elements("claimed-sum", &[claimed_sum]);

    // Combination weights: one per column, one per quotient, plus one for the g
    // degree-adjustment term.
    let weights = transcript.challenge_field_elements(
        parameters,
        "opening-combination",
        column_count + OPENING_QUOTIENT_COUNT + 1,
    );

    // Combination pass: the weighted sum of every committed codeword.
    let mut combination = vec![parameters.zero(); coset_size];
    let accumulate = |combination: &mut Vec<[u64; LIMB_COUNT]>,
                      weight: &[u64; LIMB_COUNT],
                      codeword: &[[u64; LIMB_COUNT]]| {
        for (slot, value) in combination.iter_mut().zip(codeword.iter()) {
            *slot = parameters.add(slot, &parameters.multiply(weight, value));
        }
    };
    let mut weight_index = 0;
    for codeword in &column_codewords {
        accumulate(&mut combination, &weights[weight_index], codeword);
        weight_index += 1;
    }
    let mut quotient_codewords = Vec::with_capacity(OPENING_QUOTIENT_COUNT);
    for coefficients in &quotient_coefficients {
        let codeword = coset_evaluate_coefficients(&coset_domain, &offset, coefficients);
        accumulate(&mut combination, &weights[weight_index], &codeword);
        quotient_codewords.push(codeword);
        weight_index += 1;
    }
    // g degree adjustment: re-enter g shifted by x^{trace_size + 1}. The shifted
    // codeword is derived from g's coefficients and is not committed; the verifier
    // reconstructs its value from the opened g column.
    let shift = g_degree_adjustment_shift(trace_size);
    let mut shifted_g_coefficients = vec![parameters.zero(); shift];
    shifted_g_coefficients.extend_from_slice(&quotient_coefficients[OPENING_QUOTIENT_G]);
    let shifted_g_codeword =
        coset_evaluate_coefficients(&coset_domain, &offset, &shifted_g_coefficients);
    accumulate(
        &mut combination,
        &weights[weight_index],
        &shifted_g_codeword,
    );

    let fri_commitment = fri_commit(
        parameters,
        &mut transcript,
        &combination,
        &offset,
        salt_seed,
    )?;
    drop(combination);
    let query_positions =
        transcript.challenge_positions("opening-query", coset_size, opening_parameters.query_count);
    let fri = fri_answer(&fri_commitment, &query_positions);

    // Opening pass: collect the columns and quotients at the opened positions.
    let half = coset_size / 2;
    let mut open_indices = Vec::with_capacity(query_positions.len() * 2);
    for &position in &query_positions {
        let folded = position % half;
        open_indices.push(folded);
        open_indices.push(folded + half);
    }
    let sorted = sorted_unique_indices(open_indices.iter().copied());
    let mut column_rows = vec![Vec::with_capacity(column_count); sorted.len()];
    for codeword in &column_codewords {
        for (row, &index) in column_rows.iter_mut().zip(sorted.iter()) {
            row.push(codeword[index]);
        }
    }
    let mut quotient_rows = vec![Vec::with_capacity(OPENING_QUOTIENT_COUNT); sorted.len()];
    for codeword in &quotient_codewords {
        for (row, &index) in quotient_rows.iter_mut().zip(sorted.iter()) {
            row.push(codeword[index]);
        }
    }
    let column_opening = column_commitment.open_rows(&sorted, column_rows)?;
    let quotient_opening = quotient_commitment.open_rows(&sorted, quotient_rows)?;

    Ok((
        column_root,
        LinearEvaluationOpeningProof {
            claimed_sum,
            quotient_root: quotient_commitment.root(),
            fri,
            column_opening,
            quotient_opening,
        },
    ))
}

// Verify a batched linear-evaluation opening against the committed column root
// and the public delta forms. Returns the proven `Z` on success, `None` on any
// failure (fail-closed). The caller feeds `Z` into the aggregate identity check.
pub(super) fn verify_linear_evaluation_opening<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    column_root: &MerkleDigest,
    delta_forms: &[Vec<[u64; LIMB_COUNT]>],
    proof: &LinearEvaluationOpeningProof<LIMB_COUNT>,
    opening_parameters: &LinearEvaluationOpeningParameters,
) -> Option<[u64; LIMB_COUNT]> {
    let column_count = delta_forms.len();
    if column_count == 0 {
        return None;
    }
    for delta in delta_forms {
        if delta.len() != ring_degree {
            return None;
        }
    }
    let (trace_size, coset_size) = opening_layout(ring_degree).ok()?;
    let trace_domain = CyclicDomain::new(parameters, trace_size).ok()?;
    let coset_domain = CyclicDomain::new(parameters, coset_size).ok()?;
    let offset = coset_offset(parameters);

    let mut transcript = Transcript::new(OPENING_PROTOCOL_LABEL);
    transcript.absorb_u64("ring-degree", ring_degree as u64);
    transcript.absorb_u64("column-count", column_count as u64);
    for delta in delta_forms {
        transcript.absorb_field_elements("delta-form", delta);
    }
    transcript.absorb_digest("column-root", column_root);
    transcript.absorb_digest("quotient-root", &proof.quotient_root);
    transcript.absorb_field_elements("claimed-sum", &[proof.claimed_sum]);
    let weights = transcript.challenge_field_elements(
        parameters,
        "opening-combination",
        column_count + OPENING_QUOTIENT_COUNT + 1,
    );

    let fri_parameters = FriParameters {
        blowup: OPENING_FRI_RATE_BLOWUP,
    };
    let verification = fri_verify_structure(
        parameters,
        &mut transcript,
        &proof.fri,
        coset_size,
        &offset,
        &fri_parameters,
    )
    .ok()??;
    let query_positions =
        transcript.challenge_positions("opening-query", coset_size, opening_parameters.query_count);
    if !fri_verify_queries(parameters, &verification, &proof.fri, &query_positions) {
        return None;
    }

    let column_rows =
        verify_column_opening(column_root, coset_size, column_count, &proof.column_opening)?;
    let quotient_rows = verify_column_opening(
        &proof.quotient_root,
        coset_size,
        OPENING_QUOTIENT_COUNT,
        &proof.quotient_opening,
    )?;

    // Evaluate each delta polynomial at the opened coset points.
    let opened_indices: Vec<usize> = column_rows.keys().copied().collect();
    let x_of_index: std::collections::BTreeMap<usize, [u64; LIMB_COUNT]> = opened_indices
        .iter()
        .map(|&index| {
            (
                index,
                parameters.multiply(&offset, &coset_domain.point(index)),
            )
        })
        .collect();
    let delta_at_index: Vec<std::collections::BTreeMap<usize, [u64; LIMB_COUNT]>> = delta_forms
        .iter()
        .map(|delta| {
            let delta_polynomial = trace_domain.interpolate(delta);
            opened_indices
                .iter()
                .map(|&index| {
                    (
                        index,
                        polynomial::evaluate(parameters, &delta_polynomial, &x_of_index[&index]),
                    )
                })
                .collect()
        })
        .collect();

    let size_inverse = parameters.inverse(&parameters.unsigned_word_to_element(trace_size as u64));
    let claimed_over_size = parameters.multiply(&proof.claimed_sum, &size_inverse);
    let shift = g_degree_adjustment_shift(trace_size);
    let mut shift_exponent = [0_u64; LIMB_COUNT];
    shift_exponent[0] = shift as u64;

    let half = coset_size / 2;
    for (query_index, &position) in query_positions.iter().enumerate() {
        let folded = position % half;
        let sibling = folded + half;
        let layers = &proof.fri.query_answers[query_index].layers;
        if layers.is_empty() {
            return None;
        }
        let layer_zero = &layers[0];
        for (index, expected) in [
            (folded, layer_zero.value),
            (sibling, layer_zero.sibling_value),
        ] {
            let column_values = column_rows.get(&index)?;
            let quotient_values = quotient_rows.get(&index)?;
            if column_values.len() != column_count
                || quotient_values.len() != OPENING_QUOTIENT_COUNT
            {
                return None;
            }
            let x = x_of_index[&index];

            // Combination check: combined(x) equals the opened FRI layer-0 value.
            let mut combined = parameters.zero();
            let mut weight_index = 0;
            for column_value in column_values {
                combined = parameters.add(
                    &combined,
                    &parameters.multiply(&weights[weight_index], column_value),
                );
                weight_index += 1;
            }
            for quotient_value in quotient_values {
                combined = parameters.add(
                    &combined,
                    &parameters.multiply(&weights[weight_index], quotient_value),
                );
                weight_index += 1;
            }
            let x_pow_shift = parameters.power(&x, &shift_exponent);
            combined = parameters.add(
                &combined,
                &parameters.multiply(
                    &weights[weight_index],
                    &parameters.multiply(&x_pow_shift, &quotient_values[OPENING_QUOTIENT_G]),
                ),
            );
            if combined != expected {
                return None;
            }

            // Sumcheck check: f(x) = Z/|H| + x g(x) + Z_H(x) q_sc(x), where f(x) is
            // reconstructed from the opened columns and the public delta forms.
            let mut f_x = parameters.zero();
            for (column_index, column_value) in column_values.iter().enumerate() {
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(&delta_at_index[column_index][&index], column_value),
                );
            }
            let vanishing_x = polynomial::vanishing_at(parameters, &x, trace_size);
            let sumcheck_rhs = parameters.add(
                &parameters.add(
                    &claimed_over_size,
                    &parameters.multiply(&x, &quotient_values[OPENING_QUOTIENT_G]),
                ),
                &parameters.multiply(&vanishing_x, &quotient_values[OPENING_QUOTIENT_SUMCHECK]),
            );
            if f_x != sumcheck_rhs {
                return None;
            }
        }
    }

    Some(proof.claimed_sum)
}

#[cfg(test)]
mod tests {
    use super::super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    // Build masked column coefficients from on-H material values with a simple
    // deterministic mask (a Z_H multiple, vanishing on H) so the columns exercise
    // the masking path the atom commitment uses.
    fn masked_column(
        parameters: &ProofFieldParameters<13>,
        trace_domain: &CyclicDomain<'_, 13>,
        values: &[[u64; 13]],
        trace_size: usize,
        mask_seed: u64,
    ) -> Vec<[u64; 13]> {
        let coefficients = trace_domain.interpolate(values);
        let mut mask = Vec::with_capacity(4);
        let mut state = mask_seed;
        for _ in 0..4 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            mask.push(parameters.unsigned_word_to_element(state));
        }
        let vanishing = vanishing_polynomial(parameters, trace_size);
        let mask_multiple = polynomial::multiply_via_ntt(parameters, &mask, &vanishing);
        polynomial::add(parameters, &coefficients, &mask_multiple)
    }

    fn field_vector(
        parameters: &ProofFieldParameters<13>,
        len: usize,
        seed: u64,
    ) -> Vec<[u64; 13]> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                parameters.unsigned_word_to_element(state)
            })
            .collect()
    }

    fn inner_product(
        parameters: &ProofFieldParameters<13>,
        a: &[[u64; 13]],
        b: &[[u64; 13]],
    ) -> [u64; 13] {
        let mut acc = parameters.zero();
        for (x, y) in a.iter().zip(b.iter()) {
            acc = parameters.add(&acc, &parameters.multiply(x, y));
        }
        acc
    }

    #[test]
    fn honest_linear_evaluation_opening_round_trips_and_rejects_tampering() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (trace_size, _coset_size) = opening_layout(ring_degree).expect("layout");
        let trace_domain = CyclicDomain::new(&parameters, trace_size).expect("trace domain");
        let column_count = 5;

        // Material values per column, their delta challenge vectors, and the
        // masked committed coefficients.
        let material: Vec<Vec<[u64; 13]>> = (0..column_count)
            .map(|j| field_vector(&parameters, ring_degree, 0x100 + j as u64))
            .collect();
        let delta_forms: Vec<Vec<[u64; 13]>> = (0..column_count)
            .map(|j| field_vector(&parameters, ring_degree, 0x900 + j as u64))
            .collect();
        let column_coefficients: Vec<Vec<[u64; 13]>> = material
            .iter()
            .enumerate()
            .map(|(j, values)| {
                masked_column(
                    &parameters,
                    &trace_domain,
                    values,
                    trace_size,
                    0x5000 + j as u64,
                )
            })
            .collect();

        // The true sum the opening must prove.
        let mut expected_sum = parameters.zero();
        for (delta, values) in delta_forms.iter().zip(material.iter()) {
            expected_sum =
                parameters.add(&expected_sum, &inner_product(&parameters, delta, values));
        }

        let opening_parameters = LinearEvaluationOpeningParameters { query_count: 40 };
        let mut salt_seed = 0xa11ce;
        let (column_root, mut proof) = prove_linear_evaluation_opening(
            &parameters,
            ring_degree,
            &column_coefficients,
            &delta_forms,
            &opening_parameters,
            &mut salt_seed,
        )
        .expect("prove");

        assert_eq!(
            proof.claimed_sum, expected_sum,
            "the proven sum must equal the true linear evaluation"
        );
        assert_eq!(
            verify_linear_evaluation_opening(
                &parameters,
                ring_degree,
                &column_root,
                &delta_forms,
                &proof,
                &opening_parameters,
            ),
            Some(expected_sum),
            "an honest opening must verify and return the proven sum"
        );

        // Verifying under a different delta than the one proven fails (the
        // transcript-bound delta drove the challenges).
        let mut other_delta = delta_forms.clone();
        other_delta[2][7] = parameters.add(&other_delta[2][7], &parameters.one());
        assert!(
            verify_linear_evaluation_opening(
                &parameters,
                ring_degree,
                &column_root,
                &other_delta,
                &proof,
                &opening_parameters,
            )
            .is_none(),
            "an opening must not verify under a different delta"
        );

        // A wrong column root fails the column opening authentication. The
        // quotient root is a valid but different digest, so it stands in.
        assert!(
            verify_linear_evaluation_opening(
                &parameters,
                ring_degree,
                &proof.quotient_root,
                &delta_forms,
                &proof,
                &opening_parameters,
            )
            .is_none(),
            "an opening must not verify against a different column root"
        );

        // Tampered claimed sum: the sumcheck constant no longer matches (done
        // last, mutating in place).
        proof.claimed_sum = parameters.add(&proof.claimed_sum, &parameters.one());
        assert!(
            verify_linear_evaluation_opening(
                &parameters,
                ring_degree,
                &column_root,
                &delta_forms,
                &proof,
                &opening_parameters,
            )
            .is_none(),
            "a tampered claimed sum must be rejected"
        );
    }

    // Build one honest opening the same way the round-trip test above does, and
    // return everything a verifier needs: the recomputed column root, the public
    // delta forms, the opening parameters, and the proof.
    fn honest_opening() -> (
        ProofFieldParameters<13>,
        usize,
        MerkleDigest,
        Vec<Vec<[u64; 13]>>,
        LinearEvaluationOpeningParameters,
        LinearEvaluationOpeningProof<13>,
    ) {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (trace_size, _coset_size) = opening_layout(ring_degree).expect("layout");
        let trace_domain = CyclicDomain::new(&parameters, trace_size).expect("trace domain");
        let column_count = 5;

        let material: Vec<Vec<[u64; 13]>> = (0..column_count)
            .map(|column_index| field_vector(&parameters, ring_degree, 0x100 + column_index as u64))
            .collect();
        let delta_forms: Vec<Vec<[u64; 13]>> = (0..column_count)
            .map(|column_index| field_vector(&parameters, ring_degree, 0x900 + column_index as u64))
            .collect();
        let column_coefficients: Vec<Vec<[u64; 13]>> = material
            .iter()
            .enumerate()
            .map(|(column_index, values)| {
                masked_column(
                    &parameters,
                    &trace_domain,
                    values,
                    trace_size,
                    0x5000 + column_index as u64,
                )
            })
            .collect();

        let opening_parameters = LinearEvaluationOpeningParameters { query_count: 40 };
        let mut salt_seed = 0xa11ce;
        let (column_root, proof) = prove_linear_evaluation_opening(
            &parameters,
            ring_degree,
            &column_coefficients,
            &delta_forms,
            &opening_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        (
            parameters,
            ring_degree,
            column_root,
            delta_forms,
            opening_parameters,
            proof,
        )
    }

    #[test]
    fn linear_evaluation_opening_codec_round_trips_and_the_decoded_proof_verifies() {
        let (parameters, ring_degree, column_root, delta_forms, opening_parameters, proof) =
            honest_opening();

        // The proven sum the honest opening establishes; the decoded proof must
        // re-verify to exactly this Z.
        let expected_z = verify_linear_evaluation_opening(
            &parameters,
            ring_degree,
            &column_root,
            &delta_forms,
            &proof,
            &opening_parameters,
        )
        .expect("the honest opening must verify before encoding");

        let bytes = encode_linear_evaluation_opening_proof(&proof).expect("encode");
        let decoded = decode_linear_evaluation_opening_proof(&parameters, &bytes).expect("decode");

        // Re-encoding the decoded proof reproduces the exact bytes (canonical).
        let reencoded = encode_linear_evaluation_opening_proof(&decoded).expect("re-encode");
        assert_eq!(bytes, reencoded, "the opening encoding must be canonical");

        // The decoded proof re-verifies to the same Z against the same root and
        // delta forms.
        assert_eq!(
            verify_linear_evaluation_opening(
                &parameters,
                ring_degree,
                &column_root,
                &delta_forms,
                &decoded,
                &opening_parameters,
            ),
            Some(expected_z),
            "the decoded opening must re-verify to the same proven sum"
        );
    }

    #[test]
    fn linear_evaluation_opening_codec_rejects_truncated_and_trailing_bytes() {
        let (parameters, _ring_degree, _column_root, _delta_forms, _opening_parameters, proof) =
            honest_opening();
        let bytes = encode_linear_evaluation_opening_proof(&proof).expect("encode");

        // Dropping the final byte truncates the stream: strict decode must fail.
        assert!(
            decode_linear_evaluation_opening_proof(&parameters, &bytes[..bytes.len() - 1]).is_err(),
            "a truncated opening stream must be rejected"
        );

        // Appending a stray byte leaves trailing input: `reader.finish()` must
        // reject it.
        let mut with_trailing = bytes.clone();
        with_trailing.push(0);
        assert!(
            decode_linear_evaluation_opening_proof(&parameters, &with_trailing).is_err(),
            "an opening stream with trailing bytes must be rejected"
        );
    }
}
