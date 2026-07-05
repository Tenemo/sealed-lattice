//! One round-one key-switch digit atom, proved through the masked FRI
//! polynomial-IOP.
//!
//! The witness columns (secret `S`, error `E`, carry `C`, and the support
//! helpers `S^2`, `E^2`, `(E^2-1)(E^2-4)`, and the carry's bit expansion) are
//! interpolated over the trace subgroup `H`, optionally masked with a random
//! multiple of the vanishing polynomial (which leaves their values on `H`
//! unchanged, so every constraint still holds), and committed as coset
//! codewords. Two obligations are then proved together:
//!
//! - the atom congruence, reduced by `atom_argument` to one inner product
//!   `<L, w> = target`, proved by a univariate sumcheck (`f = Ls S + Le E +
//!   Lc C`, `sum_{H} f = target`, so `f = target/|H| + X g + Z_H q_sc`);
//! - the witness support (ternary `S`, eta-2 `E`, range-bounded `C`), batched
//!   into one polynomial that vanishes on `H`, hence `V = Z_H q_support`.
//!
//! A single random linear combination of every committed column is proved
//! low-degree by one FRI instance; the two algebraic identities are checked
//! pointwise at the shared FRI query positions, and the FRI-tested combination
//! is bound to the opened columns there. Together these give: every column is
//! close to a low-degree polynomial, the identities hold as polynomials, and
//! (with the support constraints pinning the witness to bounded integers) the
//! field congruence is the integer congruence, hence every per-limb key-switch
//! congruence. The masking is the bounded-leakage zero-knowledge layer.

#![allow(clippy::too_many_arguments)]

use super::super::negacyclic_transform::NegacyclicDomain;
use super::super::proof_field::ProofFieldParameters;
use super::atom_reduction::{AtomLinearForm, AtomPublicInputs, reduce_round_one_atom};
use super::column_commitment::{ColumnCommitment, ColumnOpening, verify_column_opening};
use super::domain::{CyclicDomain, coset_evaluate_coefficients, coset_offset};
use super::low_degree::{
    FriParameters, FriProof, fri_answer, fri_commit, fri_verify_queries, fri_verify_structure,
};
use super::merkle::MerkleDigest;
use super::polynomial;
use super::transcript::Transcript;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

const PROTOCOL_LABEL: &str = "sealed-lattice/setup/key-switch-atom/round-one-atom-v1";

// FRI rate is bound_deg / coset_size = 1/4; per-query soundness of both the FRI
// proximity test and the pointwise identity checks is about 1/4, so the query
// count sets the achieved bits. 96 development queries give a testable margin;
// the accepted profile query count is fixed in the family accounting.
const FRI_RATE_BLOWUP: usize = 4;

pub(super) struct AtomFriProofParameters {
    pub(crate) query_count: usize,
    pub(crate) mask_degree: usize,
}

pub(super) struct AtomFriProof<const LIMB_COUNT: usize> {
    pub(crate) base_root: MerkleDigest,
    pub(crate) quotient_root: MerkleDigest,
    pub(crate) fri: FriProof<LIMB_COUNT>,
    pub(crate) base_opening: ColumnOpening<LIMB_COUNT>,
    pub(crate) quotient_opening: ColumnOpening<LIMB_COUNT>,
}

fn invalid_atom(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// Number of bits to represent the shifted carry c + (N+1) in [0, 2N+2].
fn carry_bit_count(ring_degree: usize) -> usize {
    let maximum = 2 * ring_degree + 2;
    (maximum + 1).next_power_of_two().trailing_zeros() as usize
}

// Base column indices.
const COLUMN_SECRET: usize = 0;
const COLUMN_ERROR: usize = 1;
const COLUMN_CARRY: usize = 2;
const COLUMN_SECRET_SQUARE: usize = 3;
const COLUMN_ERROR_SQUARE: usize = 4;
const COLUMN_ERROR_SUPPORT: usize = 5;
const COLUMN_BITS_START: usize = 6;

// Quotient column indices.
const QUOTIENT_SUMCHECK: usize = 0;
const QUOTIENT_G: usize = 1;
const QUOTIENT_SUPPORT: usize = 2;
const QUOTIENT_COLUMN_COUNT: usize = 3;

fn base_column_count(ring_degree: usize) -> usize {
    COLUMN_BITS_START + carry_bit_count(ring_degree)
}

// The domain sizing derived from the ring degree. The committed polynomials
// have degree below `2 * trace_size` (columns after masking and quotients), and
// the coset is `FRI_RATE_BLOWUP` times that bound, giving FRI rate 1/4.
struct Layout {
    trace_size: usize,
    coset_size: usize,
}

fn layout(ring_degree: usize) -> CanonicalResult<Layout> {
    if !ring_degree.is_power_of_two() || ring_degree < 2 {
        return Err(invalid_atom("ring degree must be a power of two >= 2"));
    }
    let trace_size = ring_degree;
    let bound_degree = 2 * trace_size;
    let coset_size = FRI_RATE_BLOWUP * bound_degree;
    if coset_size > super::domain::MAX_TWO_ADIC_ORDER {
        return Err(invalid_atom(
            "atom coset exceeds the field two-adic order (needs column splitting at this ring degree)",
        ));
    }
    Ok(Layout {
        trace_size,
        coset_size,
    })
}

// Deterministic mask stream: a random multiple of Z_H added to a column's
// coefficients. `Z_H = X^m - 1`, so `mask_poly * Z_H` vanishes on H, leaving
// the column's H-values (hence all constraints) unchanged while blinding the
// opened coset values.
fn masked_coefficients<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    coefficients: &[[u64; LIMB_COUNT]],
    trace_size: usize,
    mask_degree: usize,
    salt_seed: &mut u64,
) -> Vec<[u64; LIMB_COUNT]> {
    if mask_degree == 0 {
        return coefficients.to_vec();
    }
    let mut mask = Vec::with_capacity(mask_degree + 1);
    for _ in 0..=mask_degree {
        *salt_seed = salt_seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        mask.push(parameters.unsigned_word_to_element(*salt_seed));
    }
    // Z_H = X^m - 1.
    let mut vanishing = vec![parameters.zero(); trace_size + 1];
    vanishing[0] = parameters.negate(&parameters.one());
    vanishing[trace_size] = parameters.one();
    let mask_multiple = polynomial::multiply_via_ntt(parameters, &mask, &vanishing);
    polynomial::add(parameters, coefficients, &mask_multiple)
}

// Build the base witness column coefficient vectors from the signed witness.
fn build_base_columns<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
    secret: &[i64],
    error: &[i64],
    carry: &[i64],
    mask_degree: usize,
    salt_seed: &mut u64,
) -> CanonicalResult<Vec<Vec<[u64; LIMB_COUNT]>>> {
    let bit_count = carry_bit_count(ring_degree);
    let carry_shift = (ring_degree + 1) as i64;
    let mut secret_values = Vec::with_capacity(ring_degree);
    let mut error_values = Vec::with_capacity(ring_degree);
    let mut carry_values = Vec::with_capacity(ring_degree);
    let mut secret_square_values = Vec::with_capacity(ring_degree);
    let mut error_square_values = Vec::with_capacity(ring_degree);
    let mut error_support_values = Vec::with_capacity(ring_degree);
    let mut bit_values = vec![Vec::with_capacity(ring_degree); bit_count];
    for index in 0..ring_degree {
        let secret_scalar = secret[index];
        let error_scalar = error[index];
        let carry_scalar = carry[index];
        secret_values.push(parameters.signed_word_to_element(secret_scalar));
        error_values.push(parameters.signed_word_to_element(error_scalar));
        carry_values.push(parameters.signed_word_to_element(carry_scalar));
        secret_square_values.push(parameters.signed_word_to_element(secret_scalar * secret_scalar));
        let error_square = error_scalar * error_scalar;
        error_square_values.push(parameters.signed_word_to_element(error_square));
        let support = (error_square - 1) * (error_square - 4);
        error_support_values.push(parameters.signed_word_to_element(support));
        let shifted = carry_scalar + carry_shift;
        if shifted < 0 {
            return Err(invalid_atom("carry is below its range bound"));
        }
        for (bit_index, column) in bit_values.iter_mut().enumerate() {
            let bit = (shifted >> bit_index) & 1;
            column.push(parameters.unsigned_word_to_element(bit as u64));
        }
    }

    let mut columns = Vec::with_capacity(base_column_count(ring_degree));
    for values in [
        &secret_values,
        &error_values,
        &carry_values,
        &secret_square_values,
        &error_square_values,
        &error_support_values,
    ] {
        let coefficients = trace_domain.interpolate(values);
        columns.push(masked_coefficients(
            parameters,
            &coefficients,
            ring_degree,
            mask_degree,
            salt_seed,
        ));
    }
    for column in &bit_values {
        let coefficients = trace_domain.interpolate(column);
        columns.push(masked_coefficients(
            parameters,
            &coefficients,
            ring_degree,
            mask_degree,
            salt_seed,
        ));
    }

    Ok(columns)
}

// Public constants a verifier recomputes: the powers of two for the carry
// reconstruction.
fn power_of_two<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    exponent: usize,
) -> [u64; LIMB_COUNT] {
    parameters.unsigned_word_to_element(1_u64 << exponent)
}

// Evaluate the support constraint polynomial value V(x) at a point, from the
// column values at that point and the constraint-batching challenges.
fn support_value_at<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    column_values: &[[u64; LIMB_COUNT]],
    alpha: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let bit_count = carry_bit_count(ring_degree);
    let secret = column_values[COLUMN_SECRET];
    let error = column_values[COLUMN_ERROR];
    let carry = column_values[COLUMN_CARRY];
    let secret_square = column_values[COLUMN_SECRET_SQUARE];
    let error_square = column_values[COLUMN_ERROR_SQUARE];
    let error_support = column_values[COLUMN_ERROR_SUPPORT];
    let one = parameters.one();

    let mut constraints = Vec::new();
    // Ssq - S*S.
    constraints.push(parameters.subtract(&secret_square, &parameters.multiply(&secret, &secret)));
    // S*(Ssq - 1).
    constraints.push(parameters.multiply(&secret, &parameters.subtract(&secret_square, &one)));
    // Wsq - E*E.
    constraints.push(parameters.subtract(&error_square, &parameters.multiply(&error, &error)));
    // Pcol - (Wsq-1)(Wsq-4).
    let four = parameters.unsigned_word_to_element(4);
    let support_product = parameters.multiply(
        &parameters.subtract(&error_square, &one),
        &parameters.subtract(&error_square, &four),
    );
    constraints.push(parameters.subtract(&error_support, &support_product));
    // E*Pcol.
    constraints.push(parameters.multiply(&error, &error_support));
    // Per-bit binary constraints.
    let mut reconstruction = parameters.add(
        &carry,
        &parameters.unsigned_word_to_element((ring_degree + 1) as u64),
    );
    for bit_index in 0..bit_count {
        let bit = column_values[COLUMN_BITS_START + bit_index];
        constraints.push(parameters.multiply(&bit, &parameters.subtract(&bit, &one)));
        let weighted = parameters.multiply(&bit, &power_of_two(parameters, bit_index));
        reconstruction = parameters.subtract(&reconstruction, &weighted);
    }
    // Reconstruction: C + (N+1) - sum 2^k b_k.
    constraints.push(reconstruction);

    let mut value = parameters.zero();
    for (weight, constraint) in alpha.iter().zip(constraints.iter()) {
        value = parameters.add(&value, &parameters.multiply(weight, constraint));
    }
    value
}

fn support_constraint_count(ring_degree: usize) -> usize {
    5 + carry_bit_count(ring_degree) + 1
}

// The full set of columns as coset codewords, keyed for combination.
struct CosetColumns<const LIMB_COUNT: usize> {
    base: Vec<Vec<[u64; LIMB_COUNT]>>,
    quotient: Vec<Vec<[u64; LIMB_COUNT]>>,
}

// Build the sumcheck and support quotient coefficient vectors from the masked
// base column coefficients and the challenges.
fn build_quotients<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
    base_columns: &[Vec<[u64; LIMB_COUNT]>],
    linear_form_secret: &[[u64; LIMB_COUNT]],
    linear_form_error: &[[u64; LIMB_COUNT]],
    linear_form_carry: &[[u64; LIMB_COUNT]],
    target: &[u64; LIMB_COUNT],
    alpha: &[[u64; LIMB_COUNT]],
) -> CanonicalResult<Vec<Vec<[u64; LIMB_COUNT]>>> {
    let trace_size = ring_degree;
    // Interpolate the public linear-form vectors over H.
    let ls = trace_domain.interpolate(linear_form_secret);
    let le = trace_domain.interpolate(linear_form_error);
    let lc = trace_domain.interpolate(linear_form_carry);
    // f = Ls*S + Le*E + Lc*C.
    let f = polynomial::add(
        parameters,
        &polynomial::add(
            parameters,
            &polynomial::multiply_via_ntt(parameters, &ls, &base_columns[COLUMN_SECRET]),
            &polynomial::multiply_via_ntt(parameters, &le, &base_columns[COLUMN_ERROR]),
        ),
        &polynomial::multiply_via_ntt(parameters, &lc, &base_columns[COLUMN_CARRY]),
    );
    // q_sc = f div Z_H; r = f - q_sc*Z_H (degree < m); check r0 = target/m.
    let q_sc = polynomial::divide_by_vanishing(parameters, &f, trace_size);
    let mut vanishing = vec![parameters.zero(); trace_size + 1];
    vanishing[0] = parameters.negate(&parameters.one());
    vanishing[trace_size] = parameters.one();
    let q_sc_times_vanishing = polynomial::multiply_via_ntt(parameters, &q_sc, &vanishing);
    let mut remainder = polynomial::subtract(parameters, &f, &q_sc_times_vanishing);
    polynomial::trim(&mut remainder);
    let size_inverse = parameters.inverse(&parameters.unsigned_word_to_element(trace_size as u64));
    let target_over_size = parameters.multiply(target, &size_inverse);
    let remainder_constant = remainder
        .first()
        .copied()
        .unwrap_or_else(|| parameters.zero());
    if remainder_constant != target_over_size {
        return Err(invalid_atom(
            "sumcheck remainder constant does not match the target",
        ));
    }
    // g = (r - target/m) / X.
    let mut shifted_remainder = remainder.clone();
    if shifted_remainder.is_empty() {
        shifted_remainder.push(parameters.zero());
    }
    shifted_remainder[0] = parameters.subtract(&shifted_remainder[0], &target_over_size);
    // Divide by X: drop the (zero) constant term.
    let g = shifted_remainder[1..].to_vec();
    let g = if g.is_empty() {
        vec![parameters.zero()]
    } else {
        g
    };

    // Support: V = sum alpha_i * constraint_i(X), each vanishing on H.
    let v = build_support_polynomial(parameters, ring_degree, base_columns, alpha);
    let q_support = polynomial::divide_by_vanishing(parameters, &v, trace_size);
    // Verify V is divisible (remainder zero) for prover-side self-check.
    let q_support_times_vanishing =
        polynomial::multiply_via_ntt(parameters, &q_support, &vanishing);
    let mut support_remainder = polynomial::subtract(parameters, &v, &q_support_times_vanishing);
    polynomial::trim(&mut support_remainder);
    if support_remainder
        .iter()
        .any(|c| c.iter().any(|limb| *limb != 0))
    {
        return Err(invalid_atom(
            "support constraint polynomial does not vanish on the trace subgroup",
        ));
    }

    let mut quotients = vec![Vec::new(); QUOTIENT_COLUMN_COUNT];
    quotients[QUOTIENT_SUMCHECK] = q_sc;
    quotients[QUOTIENT_G] = g;
    quotients[QUOTIENT_SUPPORT] = q_support;
    Ok(quotients)
}

// V(X) = sum alpha_i * constraint_i(X) as a coefficient polynomial.
fn build_support_polynomial<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    base_columns: &[Vec<[u64; LIMB_COUNT]>],
    alpha: &[[u64; LIMB_COUNT]],
) -> Vec<[u64; LIMB_COUNT]> {
    let bit_count = carry_bit_count(ring_degree);
    let one = vec![parameters.one()];
    let secret = &base_columns[COLUMN_SECRET];
    let error = &base_columns[COLUMN_ERROR];
    let carry = &base_columns[COLUMN_CARRY];
    let secret_square = &base_columns[COLUMN_SECRET_SQUARE];
    let error_square = &base_columns[COLUMN_ERROR_SQUARE];
    let error_support = &base_columns[COLUMN_ERROR_SUPPORT];

    let mut constraints: Vec<Vec<[u64; LIMB_COUNT]>> = Vec::new();
    // Ssq - S*S.
    constraints.push(polynomial::subtract(
        parameters,
        secret_square,
        &polynomial::multiply_via_ntt(parameters, secret, secret),
    ));
    // S*(Ssq - 1).
    constraints.push(polynomial::multiply_via_ntt(
        parameters,
        secret,
        &polynomial::subtract(parameters, secret_square, &one),
    ));
    // Wsq - E*E.
    constraints.push(polynomial::subtract(
        parameters,
        error_square,
        &polynomial::multiply_via_ntt(parameters, error, error),
    ));
    // Pcol - (Wsq-1)(Wsq-4).
    let four = vec![parameters.unsigned_word_to_element(4)];
    constraints.push(polynomial::subtract(
        parameters,
        error_support,
        &polynomial::multiply_via_ntt(
            parameters,
            &polynomial::subtract(parameters, error_square, &one),
            &polynomial::subtract(parameters, error_square, &four),
        ),
    ));
    // E*Pcol.
    constraints.push(polynomial::multiply_via_ntt(
        parameters,
        error,
        error_support,
    ));
    // Per-bit binary and reconstruction.
    let shift = vec![parameters.unsigned_word_to_element((ring_degree + 1) as u64)];
    let mut reconstruction = polynomial::add(parameters, carry, &shift);
    for bit_index in 0..bit_count {
        let bit = &base_columns[COLUMN_BITS_START + bit_index];
        constraints.push(polynomial::multiply_via_ntt(
            parameters,
            bit,
            &polynomial::subtract(parameters, bit, &one),
        ));
        let weighted = polynomial::scale(parameters, bit, &power_of_two(parameters, bit_index));
        reconstruction = polynomial::subtract(parameters, &reconstruction, &weighted);
    }
    constraints.push(reconstruction);

    let mut value = vec![parameters.zero()];
    for (weight, constraint) in alpha.iter().zip(constraints.iter()) {
        value = polynomial::add(
            parameters,
            &value,
            &polynomial::scale(parameters, constraint, weight),
        );
    }
    value
}

// The random-combination codeword the FRI proves low-degree, from all coset
// columns and the per-column weights.
fn combination_codeword<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    coset: &CosetColumns<LIMB_COUNT>,
    weights: &[[u64; LIMB_COUNT]],
    coset_size: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let mut codeword = vec![parameters.zero(); coset_size];
    for (weight, column) in weights
        .iter()
        .zip(coset.base.iter().chain(coset.quotient.iter()))
    {
        for (slot, value) in codeword.iter_mut().zip(column.iter()) {
            *slot = parameters.add(slot, &parameters.multiply(weight, value));
        }
    }
    codeword
}

// Combination value at one coset index from the opened column values.
fn combination_at<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    base_values: &[[u64; LIMB_COUNT]],
    quotient_values: &[[u64; LIMB_COUNT]],
    weights: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let mut value = parameters.zero();
    for (weight, column_value) in weights
        .iter()
        .zip(base_values.iter().chain(quotient_values.iter()))
    {
        value = parameters.add(&value, &parameters.multiply(weight, column_value));
    }
    value
}

fn absorb_public_inputs<const LIMB_COUNT: usize>(
    transcript: &mut Transcript,
    ring_degree: usize,
    public: &AtomPublicInputs<'_, LIMB_COUNT>,
) {
    transcript.absorb_u64("ring-degree", ring_degree as u64);
    transcript.absorb_field_elements("recombined-sample", public.recombined_sample);
    transcript.absorb_field_elements("recombined-component-b", public.recombined_component_b);
    transcript.absorb_field_elements("gadget-idempotent", &[public.gadget_idempotent]);
    transcript.absorb_field_elements("group-modulus", &[public.group_modulus]);
    transcript.absorb_field_elements("plaintext-modulus", &[public.plaintext_modulus]);
}

pub(super) fn prove_round_one_atom_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &AtomPublicInputs<'_, LIMB_COUNT>,
    secret: &[i64],
    error: &[i64],
    carry: &[i64],
    proof_parameters: &AtomFriProofParameters,
    salt_seed: &mut u64,
) -> CanonicalResult<AtomFriProof<LIMB_COUNT>> {
    let layout = layout(ring_degree)?;
    let trace_domain = CyclicDomain::new(parameters, layout.trace_size)?;
    let coset_domain = CyclicDomain::new(parameters, layout.coset_size)?;
    let offset = coset_offset(parameters);
    let negacyclic = NegacyclicDomain::new(parameters, ring_degree)?;

    // Base columns (coefficient form, masked) and their coset codewords.
    let base_coefficients = build_base_columns(
        parameters,
        &trace_domain,
        ring_degree,
        secret,
        error,
        carry,
        proof_parameters.mask_degree,
        salt_seed,
    )?;
    let base_codewords = base_coefficients
        .iter()
        .map(|coefficients| coset_evaluate_coefficients(&coset_domain, &offset, coefficients))
        .collect::<Vec<_>>();
    let base_commitment = ColumnCommitment::commit(base_codewords, salt_seed)?;

    let mut transcript = Transcript::new(PROTOCOL_LABEL);
    absorb_public_inputs(&mut transcript, ring_degree, public);
    transcript.absorb_digest("atom-base-root", &base_commitment.root());

    let gamma = transcript.challenge_field_elements(parameters, "atom-gamma", ring_degree);
    let linear_form = reduce_round_one_atom(parameters, &negacyclic, public, &gamma);
    let alpha = transcript.challenge_field_elements(
        parameters,
        "atom-support-alpha",
        support_constraint_count(ring_degree),
    );

    let quotient_coefficients = build_quotients(
        parameters,
        &trace_domain,
        ring_degree,
        &base_coefficients,
        &linear_form.secret_coefficients,
        &linear_form.error_coefficients,
        &linear_form.carry_coefficients,
        &linear_form.target,
        &alpha,
    )?;
    let quotient_codewords = quotient_coefficients
        .iter()
        .map(|coefficients| coset_evaluate_coefficients(&coset_domain, &offset, coefficients))
        .collect::<Vec<_>>();
    let quotient_commitment = ColumnCommitment::commit(quotient_codewords.clone(), salt_seed)?;
    transcript.absorb_digest("atom-quotient-root", &quotient_commitment.root());

    let weights = transcript.challenge_field_elements(
        parameters,
        "atom-combination",
        base_commitment.column_count() + quotient_commitment.column_count(),
    );

    let base_codewords_for_combination = (0..base_commitment.column_count())
        .map(|column| {
            (0..layout.coset_size)
                .map(|index| base_commitment.value(column, index))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let coset = CosetColumns {
        base: base_codewords_for_combination,
        quotient: quotient_codewords,
    };
    let combination = combination_codeword(parameters, &coset, &weights, layout.coset_size);

    let fri_commitment = fri_commit(
        parameters,
        &mut transcript,
        &combination,
        &offset,
        salt_seed,
    )?;
    let query_positions = transcript.challenge_positions(
        "atom-query",
        layout.coset_size,
        proof_parameters.query_count,
    );
    let fri = fri_answer(&fri_commitment, &query_positions);

    // Open base and quotient columns at every layer-0 folding position.
    let half = layout.coset_size / 2;
    let mut open_indices = Vec::with_capacity(query_positions.len() * 2);
    for &position in &query_positions {
        let folded = position % half;
        open_indices.push(folded);
        open_indices.push(folded + half);
    }
    let base_opening = base_commitment.open(&open_indices);
    let quotient_opening = quotient_commitment.open(&open_indices);

    Ok(AtomFriProof {
        base_root: base_commitment.root(),
        quotient_root: quotient_commitment.root(),
        fri,
        base_opening,
        quotient_opening,
    })
}

pub(super) fn verify_round_one_atom_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &AtomPublicInputs<'_, LIMB_COUNT>,
    proof: &AtomFriProof<LIMB_COUNT>,
    proof_parameters: &AtomFriProofParameters,
) -> CanonicalResult<bool> {
    let layout = layout(ring_degree)?;
    let trace_domain = CyclicDomain::new(parameters, layout.trace_size)?;
    let coset_domain = CyclicDomain::new(parameters, layout.coset_size)?;
    let offset = coset_offset(parameters);
    let negacyclic = NegacyclicDomain::new(parameters, ring_degree)?;
    let base_count = base_column_count(ring_degree);

    let mut transcript = Transcript::new(PROTOCOL_LABEL);
    absorb_public_inputs(&mut transcript, ring_degree, public);
    transcript.absorb_digest("atom-base-root", &proof.base_root);
    let gamma = transcript.challenge_field_elements(parameters, "atom-gamma", ring_degree);
    let linear_form: AtomLinearForm<LIMB_COUNT> =
        reduce_round_one_atom(parameters, &negacyclic, public, &gamma);
    let alpha = transcript.challenge_field_elements(
        parameters,
        "atom-support-alpha",
        support_constraint_count(ring_degree),
    );
    transcript.absorb_digest("atom-quotient-root", &proof.quotient_root);
    let weights = transcript.challenge_field_elements(
        parameters,
        "atom-combination",
        base_count + QUOTIENT_COLUMN_COUNT,
    );

    let fri_parameters = FriParameters {
        blowup: FRI_RATE_BLOWUP,
        query_count: proof_parameters.query_count,
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
        "atom-query",
        layout.coset_size,
        proof_parameters.query_count,
    );
    if !fri_verify_queries(parameters, &verification, &proof.fri, &query_positions) {
        return Ok(false);
    }

    // Authenticate the opened columns.
    let Some(base_rows) = verify_column_opening(
        &proof.base_root,
        layout.coset_size,
        base_count,
        &proof.base_opening,
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

    // Precompute the public linear-form polynomials over H.
    let ls = trace_domain.interpolate(&linear_form.secret_coefficients);
    let le = trace_domain.interpolate(&linear_form.error_coefficients);
    let lc = trace_domain.interpolate(&linear_form.carry_coefficients);
    let size_inverse =
        parameters.inverse(&parameters.unsigned_word_to_element(layout.trace_size as u64));
    let target_over_size = parameters.multiply(&linear_form.target, &size_inverse);

    let half = layout.coset_size / 2;
    for (query_index, &position) in query_positions.iter().enumerate() {
        let folded = position % half;
        let sibling = folded + half;
        let fri_answer_layers = &proof.fri.query_answers[query_index].layers;
        if fri_answer_layers.is_empty() {
            return Ok(false);
        }
        let layer_zero = &fri_answer_layers[0];
        for (index, expected_combination) in [
            (folded, layer_zero.value),
            (sibling, layer_zero.sibling_value),
        ] {
            let Some(base_values) = base_rows.get(&index) else {
                return Ok(false);
            };
            let Some(quotient_values) = quotient_rows.get(&index) else {
                return Ok(false);
            };
            // ALI consistency: the FRI-tested combination equals the opened
            // columns' combination at this coset point.
            let combination = combination_at(parameters, base_values, quotient_values, &weights);
            if combination != expected_combination {
                return Ok(false);
            }

            // Pointwise identity checks at the coset point x.
            let x = parameters.multiply(&offset, &coset_domain.point(index));
            let vanishing_x = polynomial::vanishing_at(parameters, &x, layout.trace_size);

            // Sumcheck identity: f(x) = target/m + x g(x) + Z_H(x) q_sc(x).
            let ls_x = polynomial::evaluate(parameters, &ls, &x);
            let le_x = polynomial::evaluate(parameters, &le, &x);
            let lc_x = polynomial::evaluate(parameters, &lc, &x);
            let f_x = parameters.add(
                &parameters.add(
                    &parameters.multiply(&ls_x, &base_values[COLUMN_SECRET]),
                    &parameters.multiply(&le_x, &base_values[COLUMN_ERROR]),
                ),
                &parameters.multiply(&lc_x, &base_values[COLUMN_CARRY]),
            );
            let g_x = quotient_values[QUOTIENT_G];
            let q_sc_x = quotient_values[QUOTIENT_SUMCHECK];
            let sumcheck_rhs = parameters.add(
                &parameters.add(&target_over_size, &parameters.multiply(&x, &g_x)),
                &parameters.multiply(&vanishing_x, &q_sc_x),
            );
            if f_x != sumcheck_rhs {
                return Ok(false);
            }

            // Support identity: V(x) = Z_H(x) q_support(x).
            let v_x = support_value_at(parameters, ring_degree, base_values, &alpha);
            let q_support_x = quotient_values[QUOTIENT_SUPPORT];
            if v_x != parameters.multiply(&vanishing_x, &q_support_x) {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::super::super::negacyclic_transform::NegacyclicDomain;
    use super::super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    // A synthetic round-one atom: (secret, error, carry, sample, component_b,
    // gadget, group_modulus, plaintext).
    type SyntheticAtom = (
        Vec<i64>,
        Vec<i64>,
        Vec<i64>,
        Vec<[u64; 13]>,
        Vec<[u64; 13]>,
        [u64; 13],
        [u64; 13],
        [u64; 13],
    );

    // Build a synthetic round-one atom whose congruence holds exactly.
    fn synthetic_atom(ring_degree: usize) -> SyntheticAtom {
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain");
        let secret: Vec<i64> = (0..ring_degree).map(|i| ((i * 7) % 3) as i64 - 1).collect();
        let error: Vec<i64> = (0..ring_degree).map(|i| ((i * 5) % 5) as i64 - 2).collect();
        let carry: Vec<i64> = (0..ring_degree).map(|i| (i % 3) as i64 - 1).collect();
        let secret_field: Vec<[u64; 13]> = secret
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let error_field: Vec<[u64; 13]> = error
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let carry_field: Vec<[u64; 13]> = carry
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let mut sample = Vec::with_capacity(ring_degree);
        let mut state = 0xa5_u64;
        for _ in 0..ring_degree {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            sample.push(parameters.unsigned_word_to_element(state));
        }
        let gadget_idempotent = parameters.unsigned_word_to_element(0x9e37);
        let group_modulus = parameters.unsigned_word_to_element(1_000_003);
        let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
        let a_times_s = domain.negacyclic_product(&sample, &secret_field);
        // B = t*e + G*s + Q*c - A*s.
        let mut component_b = vec![parameters.zero(); ring_degree];
        for index in 0..ring_degree {
            let t_e = parameters.multiply(&plaintext_modulus, &error_field[index]);
            let g_s = parameters.multiply(&gadget_idempotent, &secret_field[index]);
            let q_c = parameters.multiply(&group_modulus, &carry_field[index]);
            let mut value = parameters.add(&t_e, &g_s);
            value = parameters.add(&value, &q_c);
            value = parameters.subtract(&value, &a_times_s[index]);
            component_b[index] = value;
        }
        (
            secret,
            error,
            carry,
            sample,
            component_b,
            gadget_idempotent,
            group_modulus,
            plaintext_modulus,
        )
    }

    #[test]
    fn honest_round_one_atom_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, error, carry, sample, component_b, gadget, group_modulus, plaintext) =
            synthetic_atom(ring_degree);
        let public = AtomPublicInputs {
            recombined_sample: &sample,
            recombined_component_b: &component_b,
            gadget_idempotent: gadget,
            group_modulus,
            plaintext_modulus: plaintext,
        };
        let proof_parameters = AtomFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x1234;
        let proof = prove_round_one_atom_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &error,
            &carry,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        assert!(
            verify_round_one_atom_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
                .expect("verify")
        );
    }

    #[test]
    fn masked_round_one_atom_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, error, carry, sample, component_b, gadget, group_modulus, plaintext) =
            synthetic_atom(ring_degree);
        let public = AtomPublicInputs {
            recombined_sample: &sample,
            recombined_component_b: &component_b,
            gadget_idempotent: gadget,
            group_modulus,
            plaintext_modulus: plaintext,
        };
        let proof_parameters = AtomFriProofParameters {
            query_count: 40,
            mask_degree: 16,
        };
        let mut salt_seed = 0x99;
        let proof = prove_round_one_atom_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &error,
            &carry,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        assert!(
            verify_round_one_atom_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
                .expect("verify")
        );
    }

    #[test]
    fn tampered_secret_breaks_the_congruence() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, error, carry, sample, component_b, gadget, group_modulus, plaintext) =
            synthetic_atom(ring_degree);
        // Flip one secret coefficient without fixing B: the congruence fails, so
        // either the prover cannot build a valid quotient or the verifier rejects.
        let mut bad_secret = secret.clone();
        bad_secret[4] += 1; // now 2 at that position: non-ternary and breaks the relation
        let public = AtomPublicInputs {
            recombined_sample: &sample,
            recombined_component_b: &component_b,
            gadget_idempotent: gadget,
            group_modulus,
            plaintext_modulus: plaintext,
        };
        let proof_parameters = AtomFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x7;
        let proof = prove_round_one_atom_fri(
            &parameters,
            ring_degree,
            &public,
            &bad_secret,
            &error,
            &carry,
            &proof_parameters,
            &mut salt_seed,
        );
        // The prover's sumcheck/support self-checks may reject outright; if a
        // proof is produced, the verifier must reject it.
        match proof {
            Err(_) => {}
            Ok(proof) => {
                assert!(
                    !verify_round_one_atom_fri(
                        &parameters,
                        ring_degree,
                        &public,
                        &proof,
                        &proof_parameters
                    )
                    .expect("verify")
                );
            }
        }
    }

    #[test]
    fn out_of_range_carry_is_rejected_by_the_prover() {
        // A carry outside |c| <= N+1, with B rebuilt so the congruence still
        // holds: the range support constraint cannot be satisfied, so the
        // prover's support self-check (or the bit range) rejects.
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, error, mut carry, sample, _b, gadget, group_modulus, plaintext) =
            synthetic_atom(ring_degree);
        // Push one carry far out of range.
        carry[2] = (ring_degree as i64) * 10;
        // Rebuild B so the congruence holds with this carry.
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain");
        let secret_field: Vec<[u64; 13]> = secret
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let error_field: Vec<[u64; 13]> = error
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let carry_field: Vec<[u64; 13]> = carry
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let a_times_s = domain.negacyclic_product(&sample, &secret_field);
        let mut component_b = vec![parameters.zero(); ring_degree];
        for index in 0..ring_degree {
            let t_e = parameters.multiply(&plaintext, &error_field[index]);
            let g_s = parameters.multiply(&gadget, &secret_field[index]);
            let q_c = parameters.multiply(&group_modulus, &carry_field[index]);
            let mut value = parameters.add(&t_e, &g_s);
            value = parameters.add(&value, &q_c);
            value = parameters.subtract(&value, &a_times_s[index]);
            component_b[index] = value;
        }
        let public = AtomPublicInputs {
            recombined_sample: &sample,
            recombined_component_b: &component_b,
            gadget_idempotent: gadget,
            group_modulus,
            plaintext_modulus: plaintext,
        };
        let proof_parameters = AtomFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x41;
        // Carry shift keeps the value representable only within the bit width, so
        // the shifted carry exceeds the range: the prover rejects (range support
        // or bit encoding), never producing a passing proof.
        let result = prove_round_one_atom_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &error,
            &carry,
            &proof_parameters,
            &mut salt_seed,
        );
        match result {
            Err(_) => {}
            Ok(proof) => assert!(
                !verify_round_one_atom_fri(
                    &parameters,
                    ring_degree,
                    &public,
                    &proof,
                    &proof_parameters
                )
                .expect("verify"),
                "an out-of-range carry must not yield an accepted proof"
            ),
        }
    }

    #[test]
    fn non_eta2_error_is_rejected_by_the_prover() {
        // An error value 3 (outside {-2..2}) with B rebuilt so the congruence
        // holds: the eta-2 support constraint E*(E^2-1)(E^2-4) cannot vanish, so
        // the prover's support self-check rejects.
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, mut error, carry, sample, _b, gadget, group_modulus, plaintext) =
            synthetic_atom(ring_degree);
        error[5] = 3;
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain");
        let secret_field: Vec<[u64; 13]> = secret
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let error_field: Vec<[u64; 13]> = error
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let carry_field: Vec<[u64; 13]> = carry
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let a_times_s = domain.negacyclic_product(&sample, &secret_field);
        let mut component_b = vec![parameters.zero(); ring_degree];
        for index in 0..ring_degree {
            let t_e = parameters.multiply(&plaintext, &error_field[index]);
            let g_s = parameters.multiply(&gadget, &secret_field[index]);
            let q_c = parameters.multiply(&group_modulus, &carry_field[index]);
            let mut value = parameters.add(&t_e, &g_s);
            value = parameters.add(&value, &q_c);
            value = parameters.subtract(&value, &a_times_s[index]);
            component_b[index] = value;
        }
        let public = AtomPublicInputs {
            recombined_sample: &sample,
            recombined_component_b: &component_b,
            gadget_idempotent: gadget,
            group_modulus,
            plaintext_modulus: plaintext,
        };
        let proof_parameters = AtomFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x53;
        let result = prove_round_one_atom_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &error,
            &carry,
            &proof_parameters,
            &mut salt_seed,
        );
        match result {
            Err(_) => {}
            Ok(proof) => assert!(
                !verify_round_one_atom_fri(
                    &parameters,
                    ring_degree,
                    &public,
                    &proof,
                    &proof_parameters
                )
                .expect("verify"),
                "a non-eta-2 error must not yield an accepted proof"
            ),
        }
    }

    #[test]
    fn tampered_quotient_value_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, error, carry, sample, component_b, gadget, group_modulus, plaintext) =
            synthetic_atom(ring_degree);
        let public = AtomPublicInputs {
            recombined_sample: &sample,
            recombined_component_b: &component_b,
            gadget_idempotent: gadget,
            group_modulus,
            plaintext_modulus: plaintext,
        };
        let proof_parameters = AtomFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x61;
        let mut proof = prove_round_one_atom_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &error,
            &carry,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        // Corrupt a quotient opening: fails Merkle authentication or the ALI
        // consistency / identity check.
        proof.quotient_opening.rows[0].values[QUOTIENT_SUPPORT] = parameters.add(
            &proof.quotient_opening.rows[0].values[QUOTIENT_SUPPORT],
            &parameters.one(),
        );
        assert!(
            !verify_round_one_atom_fri(
                &parameters,
                ring_degree,
                &public,
                &proof,
                &proof_parameters
            )
            .expect("verify")
        );
    }

    #[test]
    fn tampered_proof_value_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, error, carry, sample, component_b, gadget, group_modulus, plaintext) =
            synthetic_atom(ring_degree);
        let public = AtomPublicInputs {
            recombined_sample: &sample,
            recombined_component_b: &component_b,
            gadget_idempotent: gadget,
            group_modulus,
            plaintext_modulus: plaintext,
        };
        let proof_parameters = AtomFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x33;
        let mut proof = prove_round_one_atom_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &error,
            &carry,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        // Corrupt one opened base value: the Merkle authentication fails.
        proof.base_opening.rows[0].values[0] =
            parameters.add(&proof.base_opening.rows[0].values[0], &parameters.one());
        assert!(
            !verify_round_one_atom_fri(
                &parameters,
                ring_degree,
                &public,
                &proof,
                &proof_parameters
            )
            .expect("verify")
        );
    }
}
