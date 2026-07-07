//! Aggregate-binding wrapper for the committed key-switch material (S1).
//!
//! This wires the two already-built primitives in this backend into one
//! aggregate check for the published runtime key:
//!
//! - `material_aggregate_opening` proves, per trustee, the batched linear
//!   evaluation `z_i = sum_digit <delta_digit, recombined_B[trustee][digit]>`
//!   against that trustee's committed material columns.
//! - `material_aggregate` checks the aggregate identity
//!   `sum_i z_i == <delta, R + w * Q_L>`, where `R` is the centered CRT
//!   recombination of the runtime key and `w` are the per-coefficient wrap
//!   multiples bounded by `ceil(roster_size / 2)`.
//!
//! The whole binding rests on Fiat-Shamir plus Reed-Solomon distance: `delta`
//! is drawn only after every trustee material root, the published runtime key,
//! and the wrap multiples are absorbed, so a prover cannot choose the material
//! or the aggregate to fit a favourable challenge. A forged runtime key or wrap
//! moves the reconstructed sum `S = R + w * Q_L`, and a dropped or tampered
//! trustee contribution moves the proven total; either breaks the single
//! identity except with probability about `1 / |F_p|` (Schwartz-Zippel). There
//! is no homomorphic commitment; every layer is hash-binding.

use super::super::limb_group_statement::LimbGroupContext;
use super::super::proof_field::{ProofFieldParameters, sixteen_limb_group_field_parameters};
use super::material_aggregate::material_aggregate_identity_holds;
use super::material_aggregate_opening::{
    LinearEvaluationOpeningParameters, LinearEvaluationOpeningProof,
    decode_linear_evaluation_opening_proof, verify_linear_evaluation_opening,
};
use super::merkle::{MERKLE_DIGEST_BYTES, MerkleDigest};
use super::transcript::Transcript;
use crate::bgv::parameters::DATA_PRIMES;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

// The cyclic domain and the opening prover are used by the aggregate prover
// `prove_material_aggregate` (driven by the creation-side aggregate binding in
// `material_aggregate_creation`); the verifier and its wrapper never prove.
use super::domain::CyclicDomain;
use super::material_aggregate_opening::prove_linear_evaluation_opening;

const AGGREGATE_DELTA_LABEL: &str =
    "sealed-lattice/setup/key-switch-atom/material-aggregate-delta-v1";

// Used by the aggregate prover; the acceptance-path wrapper reports its own
// fail-closed refusals through `aggregate_binding_refusal`.
fn inconsistent_aggregate(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// Draw the aggregate challenge vector `delta[digit][coeff]` (length `ring_degree`
// per digit). This helper is byte-for-byte identical between the prover and the
// verifier, which is what binds them to the same Fiat-Shamir transcript.
//
// SOUNDNESS CRITICAL: delta must be drawn only after every material root, the
// published runtime key, and the wrap multiples are absorbed. Absorbing them
// first means the prover cannot pick material, a runtime key, or wraps to suit
// an already-known challenge, so the aggregate identity binds by Schwartz-Zippel.
//
// The absorb order is fixed and shared by both sides:
//   1. the ring degree,
//   2. the digit count,
//   3. the material root count (the roster size),
//   4. each material root, in trustee order, as a digest,
//   5. the runtime key, as raw residue words in a fixed [digit][limb][coeff]
//      order (one `absorb_u64` per residue),
//   6. the wrap multiples, as `i64 as u64` words in a fixed [digit][coeff]
//      order (one `absorb_u64` per wrap).
fn draw_delta<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    digit_count: usize,
    material_roots: &[MerkleDigest],
    runtime_key_by_digit: &[Vec<Vec<u64>>],
    wrap_multiples: &[Vec<i64>],
) -> Vec<Vec<[u64; LIMB_COUNT]>> {
    let mut transcript = Transcript::new(AGGREGATE_DELTA_LABEL);
    transcript.absorb_u64("ring-degree", ring_degree as u64);
    transcript.absorb_u64("digit-count", digit_count as u64);
    transcript.absorb_u64("material-root-count", material_roots.len() as u64);
    for root in material_roots {
        transcript.absorb_digest("material-root", root);
    }
    for digit in runtime_key_by_digit {
        for limb in digit {
            for &residue in limb {
                transcript.absorb_u64("runtime-key", residue);
            }
        }
    }
    for digit in wrap_multiples {
        for &wrap in digit {
            transcript.absorb_u64("wrap", wrap as u64);
        }
    }

    let flat = transcript.challenge_field_elements(
        parameters,
        "material-aggregate-delta",
        digit_count.saturating_mul(ring_degree),
    );
    flat.chunks_exact(ring_degree)
        .map(|chunk| chunk.to_vec())
        .collect()
}

// Recombine the published runtime key per digit into centered CRT proof-field
// elements: `recombined[digit][coeff]` is the centered representative of the
// runtime key coefficient modulo the limb-group modulus `Q_L`.
fn recombine_runtime_key<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    group: &LimbGroupContext<LIMB_COUNT>,
    ring_degree: usize,
    runtime_key_by_digit: &[Vec<Vec<u64>>],
) -> CanonicalResult<Vec<Vec<[u64; LIMB_COUNT]>>> {
    let mut recombined = Vec::with_capacity(runtime_key_by_digit.len());
    for digit in runtime_key_by_digit {
        recombined.push(group.recombine_centered(parameters, digit, ring_degree)?);
    }
    Ok(recombined)
}

// The largest wrap multiple magnitude a roster of `roster_size` centered mod-Q_L
// summands can produce: each summand is in `(-Q_L/2, Q_L/2]`, so the sum is in
// `(-n*Q_L/2, n*Q_L/2]`, hence `|w| <= ceil(n/2)`. This mirrors the bound
// `material_aggregate` enforces on the verify side, so a wrap the prover finds
// here is always in the range the identity check accepts. Used only by the
// test-gated aggregate prover; the acceptance-path wrapper range-checks the
// wrap multiples before the call and the identity check enforces the bound again.
fn maximum_wrap_multiple_magnitude(roster_size: usize) -> i64 {
    roster_size.div_ceil(2) as i64
}

// Verify the S1 aggregate binding for one published runtime key. Fail-closed:
// returns `false` on any shape mismatch, a failed trustee opening, or a broken
// aggregate identity.
//
// `material_roots[i]` and `openings[i]` are trustee `i`'s committed material
// root and its batched linear-evaluation opening. `runtime_key_by_digit` is the
// published aggregate as per-limb residues; `wrap_multiples` are the public
// per-coefficient wrap multiples. Every trustee shares the single `delta` drawn
// after all of these are absorbed, so `delta` itself is the per-column challenge
// set for each trustee's opening.
pub(super) fn verify_material_aggregate<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    group: &LimbGroupContext<LIMB_COUNT>,
    ring_degree: usize,
    roster_size: usize,
    material_roots: &[MerkleDigest],
    runtime_key_by_digit: &[Vec<Vec<u64>>],
    wrap_multiples: &[Vec<i64>],
    openings: &[LinearEvaluationOpeningProof<LIMB_COUNT>],
    query_count: usize,
) -> bool {
    if roster_size == 0 || material_roots.len() != roster_size || openings.len() != roster_size {
        return false;
    }
    let digit_count = runtime_key_by_digit.len();
    if digit_count == 0 || wrap_multiples.len() != digit_count {
        return false;
    }

    let Ok(recombined_runtime_key) =
        recombine_runtime_key(parameters, group, ring_degree, runtime_key_by_digit)
    else {
        return false;
    };

    let delta = draw_delta(
        parameters,
        ring_degree,
        digit_count,
        material_roots,
        runtime_key_by_digit,
        wrap_multiples,
    );

    // Every trustee's opening is checked against the same `delta`: `delta[digit]`
    // is the challenge vector for that trustee's digit-`digit` material column.
    let opening_parameters = LinearEvaluationOpeningParameters { query_count };
    let mut evaluation_sum = parameters.zero();
    for (root, opening) in material_roots.iter().zip(openings.iter()) {
        let Some(trustee_evaluation) = verify_linear_evaluation_opening(
            parameters,
            ring_degree,
            root,
            &delta,
            opening,
            &opening_parameters,
        ) else {
            return false;
        };
        evaluation_sum = parameters.add(&evaluation_sum, &trustee_evaluation);
    }

    material_aggregate_identity_holds(
        parameters,
        &recombined_runtime_key,
        &group.group_modulus_element(parameters),
        wrap_multiples,
        roster_size,
        &delta,
        &evaluation_sum,
    )
}

// Prove the S1 aggregate binding: recover the integer coefficient sum from the
// trustee material columns, solve each per-coefficient wrap multiple against the
// published runtime key, then open every trustee's batched linear evaluation
// under the shared `delta`.
//
// `material_columns_by_trustee[i][digit]` are the masked coefficients of trustee
// `i`'s digit-`digit` material column, and `material_commit_salt_seeds[i]` is the
// salt seed that trustee's atom material commitment used. Both come from the shared
// `key_proof::regenerate_material_commitment_inputs` helper, so opening under that
// salt reproduces the atom proof's `KeyFriProof.material_root` exactly. The
// recomputed root is asserted to equal `material_roots[i]` (which the caller took
// from the atom proof), so the aggregate opens the ATOM-VERIFIED material rather
// than a fresh commitment. Returns the recomputed material roots (so the verifier
// and this prover agree on the exact roots and thus the delta transcript), the
// wrap multiples, and the openings.
#[allow(clippy::type_complexity)]
pub(super) fn prove_material_aggregate<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    group: &LimbGroupContext<LIMB_COUNT>,
    ring_degree: usize,
    roster_size: usize,
    material_columns_by_trustee: &[Vec<Vec<[u64; LIMB_COUNT]>>],
    material_roots: &[MerkleDigest],
    material_commit_salt_seeds: &[u64],
    runtime_key_by_digit: &[Vec<Vec<u64>>],
    query_count: usize,
) -> CanonicalResult<(
    Vec<MerkleDigest>,
    Vec<Vec<i64>>,
    Vec<LinearEvaluationOpeningProof<LIMB_COUNT>>,
)> {
    if roster_size == 0
        || material_columns_by_trustee.len() != roster_size
        || material_roots.len() != roster_size
        || material_commit_salt_seeds.len() != roster_size
    {
        return Err(inconsistent_aggregate(
            "roster size must be positive and match the material, root, and salt counts",
        ));
    }
    let digit_count = runtime_key_by_digit.len();
    if digit_count == 0 {
        return Err(inconsistent_aggregate(
            "the runtime key must have at least one digit",
        ));
    }
    for columns in material_columns_by_trustee {
        if columns.len() != digit_count {
            return Err(inconsistent_aggregate(
                "each trustee must contribute one material column per digit",
            ));
        }
    }

    let recombined_runtime_key =
        recombine_runtime_key(parameters, group, ring_degree, runtime_key_by_digit)?;

    // Recover each trustee's on-`H` material values from its masked column. The
    // mask is a `Z_H = x^ring_degree - 1` multiple, so the masked polynomial has
    // more than `ring_degree` coefficients, but on `H` (order `ring_degree`)
    // `x^ring_degree = 1`, so its values on `H` equal those of its cyclic
    // reduction modulo `x^ring_degree - 1`. Folding the high coefficients back
    // (`reduced[i mod ring_degree] += coeff[i]`) cancels the `Z_H` multiple
    // exactly, leaving the interpolation of the material, whose evaluation on `H`
    // is the material itself. The integer coefficient sum `S[digit][coeff]` is
    // the sum of these material values across trustees, as a proof-field element.
    let trace_domain = CyclicDomain::new(parameters, ring_degree)?;
    let mut coefficient_sum = vec![vec![parameters.zero(); ring_degree]; digit_count];
    for columns in material_columns_by_trustee {
        for (digit, column) in columns.iter().enumerate() {
            let mut reduced = vec![parameters.zero(); ring_degree];
            for (index, coefficient) in column.iter().enumerate() {
                let folded = index % ring_degree;
                reduced[folded] = parameters.add(&reduced[folded], coefficient);
            }
            let on_trace = trace_domain.evaluate(&reduced);
            for (accumulator, value) in coefficient_sum[digit].iter_mut().zip(on_trace.iter()) {
                *accumulator = parameters.add(accumulator, value);
            }
        }
    }

    // Solve each wrap multiple: `diff = S - R = wrap * Q_L` in the field, and
    // `wrap` is the unique integer in `[-max, max]` with
    // `signed_word_to_element(wrap) * Q_L == diff`. Since `S = R + wrap * Q_L`
    // holds exactly in the integers with `|wrap| <= ceil(n/2)`, exactly one
    // candidate matches; searching the small window avoids any big-integer
    // division.
    let group_modulus = group.group_modulus_element(parameters);
    let max_wrap = maximum_wrap_multiple_magnitude(roster_size);
    let mut wrap_multiples = Vec::with_capacity(digit_count);
    for digit in 0..digit_count {
        let recombined_digit = &recombined_runtime_key[digit];
        if recombined_digit.len() != ring_degree {
            return Err(inconsistent_aggregate(
                "recombined runtime key digit length does not match the ring degree",
            ));
        }
        let mut wrap_digit = Vec::with_capacity(ring_degree);
        for coefficient in 0..ring_degree {
            let difference = parameters.subtract(
                &coefficient_sum[digit][coefficient],
                &recombined_digit[coefficient],
            );
            let mut resolved: Option<i64> = None;
            for candidate in -max_wrap..=max_wrap {
                let candidate_contribution = parameters.multiply(
                    &parameters.signed_word_to_element(candidate),
                    &group_modulus,
                );
                if candidate_contribution == difference {
                    resolved = Some(candidate);
                    break;
                }
            }
            let Some(wrap) = resolved else {
                return Err(inconsistent_aggregate(
                    "no wrap multiple within the roster bound reconciles the runtime key with the material sum",
                ));
            };
            wrap_digit.push(wrap);
        }
        wrap_multiples.push(wrap_digit);
    }

    // Draw delta only after the material roots, runtime key, and the wraps just
    // computed are absorbed, matching the verifier's transcript exactly.
    let delta = draw_delta(
        parameters,
        ring_degree,
        digit_count,
        material_roots,
        runtime_key_by_digit,
        &wrap_multiples,
    );

    // Open each trustee's batched linear evaluation under the shared delta. The
    // opening's column commitment is seeded with that trustee's atom material-commit
    // salt seed, so the recomputed column root reproduces the atom proof's
    // `KeyFriProof.material_root`. The recomputed root is asserted to equal the
    // supplied material root (which the caller took from the atom proof), so a
    // mismatch between the aggregated material and the atom-verified material is
    // refused fail-closed rather than published.
    let opening_parameters = LinearEvaluationOpeningParameters { query_count };
    let mut recomputed_roots = Vec::with_capacity(roster_size);
    let mut openings = Vec::with_capacity(roster_size);
    for (trustee_index, columns) in material_columns_by_trustee.iter().enumerate() {
        let mut trustee_salt_seed = material_commit_salt_seeds[trustee_index];
        let (recomputed_root, opening) = prove_linear_evaluation_opening(
            parameters,
            ring_degree,
            columns,
            &delta,
            &opening_parameters,
            &mut trustee_salt_seed,
        )?;
        if recomputed_root != material_roots[trustee_index] {
            return Err(inconsistent_aggregate(
                "the recomputed material column root does not match the supplied atom material root",
            ));
        }
        recomputed_roots.push(recomputed_root);
        openings.push(opening);
    }

    Ok((recomputed_roots, wrap_multiples, openings))
}

// One key-group's aggregate-binding inputs, as the accepted-setup verifier
// gathers them from the setup package and the transported openings before the
// aggregate check runs. `group_start_limb` and `group_limb_count` identify the
// consecutive `DATA_PRIMES` slice this atom-proof group covers, so a key wider
// than one limb group is bound one group at a time (the same split the schedule
// prover uses). `runtime_key_by_digit` is `[digit][group-limb][coeff]`: the
// published aggregate residues already restricted to this group's limbs.
// `material_roots[i]` and `opening_bytes[i]` are trustee `i`'s committed material
// root (from that trustee's atom proof) and the encoded batched linear-evaluation
// opening for this key group. `wrap_multiples` is `[digit][coeff]`.
pub(crate) struct AggregateBindingGroupInputs<'a> {
    pub(crate) group_start_limb: usize,
    pub(crate) group_limb_count: usize,
    pub(crate) ring_degree: usize,
    pub(crate) roster_size: usize,
    pub(crate) query_count: usize,
    pub(crate) material_roots: &'a [MerkleDigest],
    pub(crate) runtime_key_by_digit: &'a [Vec<Vec<u64>>],
    pub(crate) wrap_multiples: &'a [Vec<i64>],
    pub(crate) opening_bytes: &'a [Vec<u8>],
}

// Fail-closed error the acceptance-path wrapper returns when the aggregate
// binding does not hold or an input is malformed. The wrapper never returns an
// acceptance status field; a returned `Ok(())` is itself the positive result and
// any refusal is an `Err` the caller maps into its structured refusal.
fn aggregate_binding_refusal(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// The acceptance-path wrapper: decode the transported opening bytes, build the
// limb group for the key-group's `DATA_PRIMES` slice on the sixteen-limb-group
// proof field, and run the S1 aggregate binding. This is the single `pub(crate)`
// surface the eval-key verifier calls; the opening proof type and the inner
// `verify_material_aggregate` stay `pub(super)`, so the crate boundary only sees
// plain data in and a fail-closed result out.
//
// Fail-closed: any decode failure, shape mismatch, group-construction failure,
// or a broken aggregate identity returns `Err`. A returned `Ok(())` means the
// published runtime-key residues for this group equal the trustee-summed
// committed material bound by every trustee's opening under one Fiat-Shamir
// challenge - never a self-attested status.
pub(crate) fn verify_material_aggregate_group_binding(
    inputs: &AggregateBindingGroupInputs<'_>,
) -> CanonicalResult<()> {
    if inputs.roster_size == 0 {
        return Err(aggregate_binding_refusal(
            "aggregate binding requires a positive roster size",
        ));
    }
    if inputs.material_roots.len() != inputs.roster_size
        || inputs.opening_bytes.len() != inputs.roster_size
    {
        return Err(aggregate_binding_refusal(
            "aggregate binding requires one material root and one opening per trustee",
        ));
    }
    if inputs.group_limb_count == 0 {
        return Err(aggregate_binding_refusal(
            "aggregate binding key group must cover at least one limb",
        ));
    }
    let group_end_limb = inputs
        .group_start_limb
        .checked_add(inputs.group_limb_count)
        .filter(|end| *end <= DATA_PRIMES.len())
        .ok_or_else(|| {
            aggregate_binding_refusal("aggregate binding key group is outside the data prime basis")
        })?;

    let parameters = sixteen_limb_group_field_parameters();
    let group_primes = &DATA_PRIMES[inputs.group_start_limb..group_end_limb];
    let group = LimbGroupContext::new(&parameters, group_primes)
        .map_err(|error| aggregate_binding_refusal(&error.message))?;

    // Decode every trustee's transported opening. The proof type is `pub(super)`,
    // so decoding here keeps it inside `family_backend`.
    let mut openings = Vec::with_capacity(inputs.roster_size);
    for bytes in inputs.opening_bytes {
        let opening = decode_linear_evaluation_opening_proof(&parameters, bytes)?;
        openings.push(opening);
    }

    if verify_material_aggregate(
        &parameters,
        &group,
        inputs.ring_degree,
        inputs.roster_size,
        inputs.material_roots,
        inputs.runtime_key_by_digit,
        inputs.wrap_multiples,
        &openings,
        inputs.query_count,
    ) {
        Ok(())
    } else {
        Err(aggregate_binding_refusal(
            "published runtime key does not match the committed-material aggregate for this key group",
        ))
    }
}

// The Merkle digest width the acceptance path decodes a transported hex material
// root into before handing it to the aggregate binding, re-exported so the
// caller reads it from the one canonical definition.
pub(crate) const AGGREGATE_MATERIAL_ROOT_BYTES: usize = MERKLE_DIGEST_BYTES;

// Decode a canonical hex material-root string into the fixed-width digest the
// aggregate binding consumes. Fail-closed on any non-hex or wrong-width input.
pub(crate) fn material_root_from_hex(material_root_hex: &str) -> CanonicalResult<MerkleDigest> {
    let bytes = crate::transcript_core::decode_hex(material_root_hex)?;
    if bytes.len() != AGGREGATE_MATERIAL_ROOT_BYTES {
        return Err(aggregate_binding_refusal(
            "aggregate binding material root is not a full Merkle digest",
        ));
    }
    let mut digest = [0_u8; MERKLE_DIGEST_BYTES];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

#[cfg(test)]
mod tests {
    // `sixteen_limb_group_field_parameters`, `CyclicDomain`, `DATA_PRIMES`, and
    // `prove_linear_evaluation_opening` are re-exported into scope by the parent
    // module's `use` items through `use super::*`, so this test module only
    // imports the polynomial helpers it uses directly.
    use super::super::polynomial;
    use super::*;

    const RING_DEGREE: usize = 64;
    const ROSTER_SIZE: usize = 4;
    const DIGIT_COUNT: usize = 2;
    const QUERY_COUNT: usize = 40;
    const SALT_SEED: u64 = 0x5ea1_ed_a770;

    // The trace-subgroup vanishing polynomial `Z_H(x) = x^ring_degree - 1`.
    fn vanishing_polynomial(parameters: &ProofFieldParameters<13>) -> Vec<[u64; 13]> {
        let mut vanishing = vec![parameters.zero(); RING_DEGREE + 1];
        vanishing[0] = parameters.negate(&parameters.one());
        vanishing[RING_DEGREE] = parameters.one();
        vanishing
    }

    // Mask small on-`H` integer material values into committed coefficients: the
    // values are interpolated to a trace polynomial, then a deterministic `Z_H`
    // multiple (which vanishes on `H`) is added, so the on-`H` values are still
    // the material while the coefficients carry the mask the atom commitment
    // records.
    fn masked_material_column(
        parameters: &ProofFieldParameters<13>,
        trace_domain: &CyclicDomain<'_, 13>,
        material_values: &[u64],
        mask_seed: u64,
    ) -> Vec<[u64; 13]> {
        let values: Vec<[u64; 13]> = material_values
            .iter()
            .map(|value| parameters.unsigned_word_to_element(*value))
            .collect();
        let coefficients = trace_domain.interpolate(&values);
        let mut mask = Vec::with_capacity(4);
        let mut state = mask_seed;
        for _ in 0..4 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            mask.push(parameters.unsigned_word_to_element(state));
        }
        let mask_multiple =
            polynomial::multiply_via_ntt(parameters, &mask, &vanishing_polynomial(parameters));
        polynomial::add(parameters, &coefficients, &mask_multiple)
    }

    // A deterministic small non-negative material value in `[0, 1000)`.
    fn small_material_value(trustee: usize, digit: usize, coefficient: usize) -> u64 {
        let mut state = 0x1234_5678_u64
            .wrapping_add(trustee as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add((digit as u64) << 20)
            .wrapping_add(coefficient as u64);
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state % 1000
    }

    // Build a full honest instance: per-trustee small integer material, the
    // masked committed columns, each trustee's committed root, and the runtime
    // key formed as the per-limb residue of the integer material sum.
    #[allow(clippy::type_complexity)]
    fn honest_instance(
        parameters: &ProofFieldParameters<13>,
    ) -> (
        Vec<Vec<Vec<[u64; 13]>>>,
        Vec<MerkleDigest>,
        Vec<Vec<Vec<u64>>>,
    ) {
        let trace_domain = CyclicDomain::new(parameters, RING_DEGREE).expect("trace domain");

        // Integer material values per trustee, digit, coefficient.
        let mut material_integers = vec![vec![vec![0_u64; RING_DEGREE]; DIGIT_COUNT]; ROSTER_SIZE];
        for (trustee, digits) in material_integers.iter_mut().enumerate() {
            for (digit, coefficients) in digits.iter_mut().enumerate() {
                for (coefficient, slot) in coefficients.iter_mut().enumerate() {
                    *slot = small_material_value(trustee, digit, coefficient);
                }
            }
        }

        // Masked committed columns per trustee.
        let material_columns_by_trustee: Vec<Vec<Vec<[u64; 13]>>> = material_integers
            .iter()
            .enumerate()
            .map(|(trustee, digits)| {
                digits
                    .iter()
                    .enumerate()
                    .map(|(digit, values)| {
                        masked_material_column(
                            parameters,
                            &trace_domain,
                            values,
                            0x7000 + (trustee as u64) * 16 + digit as u64,
                        )
                    })
                    .collect()
            })
            .collect();

        // Each trustee's committed root: the column commitment is delta-
        // independent, so a single opening with a placeholder delta and the
        // trustee's fixed salt seed produces the same root the aggregate prover
        // recomputes. The placeholder delta vector shape matches the digit count.
        let placeholder_delta: Vec<Vec<[u64; 13]>> =
            vec![vec![parameters.one(); RING_DEGREE]; DIGIT_COUNT];
        let opening_parameters = LinearEvaluationOpeningParameters {
            query_count: QUERY_COUNT,
        };
        let material_roots: Vec<MerkleDigest> = material_columns_by_trustee
            .iter()
            .enumerate()
            .map(|(trustee, columns)| {
                let mut trustee_salt_seed = SALT_SEED.wrapping_add(trustee as u64);
                let (root, _proof) = prove_linear_evaluation_opening(
                    parameters,
                    RING_DEGREE,
                    columns,
                    &placeholder_delta,
                    &opening_parameters,
                    &mut trustee_salt_seed,
                )
                .expect("commit material column");
                root
            })
            .collect();

        // Runtime key: the per-limb residue of the integer material sum. Because
        // the material integers are small non-negative values, the sum is small
        // relative to each ~47-bit level prime, so the residue is the sum itself
        // here; the recombination and wrap search still exercise the full path.
        let runtime_key_by_digit: Vec<Vec<Vec<u64>>> = (0..DIGIT_COUNT)
            .map(|digit| {
                (0..2)
                    .map(|limb| {
                        let prime = DATA_PRIMES[limb];
                        (0..RING_DEGREE)
                            .map(|coefficient| {
                                let mut sum = 0_u128;
                                for trustee in 0..ROSTER_SIZE {
                                    sum +=
                                        u128::from(material_integers[trustee][digit][coefficient]);
                                }
                                (sum % u128::from(prime)) as u64
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        (
            material_columns_by_trustee,
            material_roots,
            runtime_key_by_digit,
        )
    }

    #[test]
    fn honest_material_aggregate_round_trips_and_forgeries_are_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        // Level-1 group (two primes): the aggregate arithmetic is modulus-size
        // independent, so two primes exercise the whole path cheaply.
        let group = LimbGroupContext::new(&parameters, &DATA_PRIMES[..2]).expect("group builds");
        let (material_columns_by_trustee, material_roots, runtime_key_by_digit) =
            honest_instance(&parameters);

        // The material-commit salt seed per trustee is exactly the seed
        // `honest_instance` used to commit each trustee's columns, so opening under
        // it reproduces `material_roots[trustee]`.
        let material_commit_salt_seeds: Vec<u64> = (0..ROSTER_SIZE)
            .map(|trustee| SALT_SEED.wrapping_add(trustee as u64))
            .collect();

        let (proved_roots, wrap_multiples, openings) = prove_material_aggregate(
            &parameters,
            &group,
            RING_DEGREE,
            ROSTER_SIZE,
            &material_columns_by_trustee,
            &material_roots,
            &material_commit_salt_seeds,
            &runtime_key_by_digit,
            QUERY_COUNT,
        )
        .expect("aggregate proof");

        // The prover regenerates the same roots the commitment produced.
        assert_eq!(
            proved_roots, material_roots,
            "the aggregate prover must recompute the committed material roots"
        );
        // Every wrap multiple stays within the roster bound ceil(4/2) = 2.
        let max_wrap = maximum_wrap_multiple_magnitude(ROSTER_SIZE);
        for digit in &wrap_multiples {
            for &wrap in digit {
                assert!(
                    wrap.abs() <= max_wrap,
                    "a solved wrap multiple must be within the roster bound"
                );
            }
        }

        // The honest aggregate verifies against the roots the prover returned.
        assert!(
            verify_material_aggregate(
                &parameters,
                &group,
                RING_DEGREE,
                ROSTER_SIZE,
                &proved_roots,
                &runtime_key_by_digit,
                &wrap_multiples,
                &openings,
                QUERY_COUNT,
            ),
            "the honest aggregate binding must verify"
        );

        // (i) Flip one runtime-key residue: the recombined R moves, S no longer
        // reconciles, so the identity check fails.
        let mut forged_runtime_key = runtime_key_by_digit.clone();
        forged_runtime_key[1][0][5] = (forged_runtime_key[1][0][5] + 1) % DATA_PRIMES[0];
        assert!(
            !verify_material_aggregate(
                &parameters,
                &group,
                RING_DEGREE,
                ROSTER_SIZE,
                &proved_roots,
                &forged_runtime_key,
                &wrap_multiples,
                &openings,
                QUERY_COUNT,
            ),
            "a forged runtime-key residue must be rejected"
        );

        // (ii) Flip one in-range wrap multiple: S moves by Q_L and the delta
        // transcript diverges, so verification fails.
        let mut forged_wraps = wrap_multiples.clone();
        forged_wraps[0][3] += 1;
        assert!(
            !verify_material_aggregate(
                &parameters,
                &group,
                RING_DEGREE,
                ROSTER_SIZE,
                &proved_roots,
                &runtime_key_by_digit,
                &forged_wraps,
                &openings,
                QUERY_COUNT,
            ),
            "a forged in-range wrap multiple must be rejected"
        );

        // (iii) An out-of-range wrap multiple is refused by the identity bound.
        let mut out_of_range_wraps = wrap_multiples.clone();
        out_of_range_wraps[0][0] = max_wrap + 1;
        assert!(
            !verify_material_aggregate(
                &parameters,
                &group,
                RING_DEGREE,
                ROSTER_SIZE,
                &proved_roots,
                &runtime_key_by_digit,
                &out_of_range_wraps,
                &openings,
                QUERY_COUNT,
            ),
            "a wrap multiple beyond ceil(n/2) must be refused"
        );

        // (iv) Tamper one opening's claimed sum: its sumcheck constant no longer
        // matches, so that trustee's opening fails and verification fails.
        let mut tampered_openings_first = true;
        let tampered_openings: Vec<LinearEvaluationOpeningProof<13>> = openings
            .into_iter()
            .map(|mut opening| {
                if tampered_openings_first {
                    opening.claimed_sum = parameters.add(&opening.claimed_sum, &parameters.one());
                    tampered_openings_first = false;
                }
                opening
            })
            .collect();
        assert!(
            !verify_material_aggregate(
                &parameters,
                &group,
                RING_DEGREE,
                ROSTER_SIZE,
                &proved_roots,
                &runtime_key_by_digit,
                &wrap_multiples,
                &tampered_openings,
                QUERY_COUNT,
            ),
            "a tampered opening claimed sum must be rejected"
        );
    }
}
