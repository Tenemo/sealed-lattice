//! One evaluation key (all digit atoms), proved as one masked FRI
//! polynomial-IOP with the secret committed once and shared across every digit.
//!
//! A key at level `L` has `L + 1` digit atoms sharing one ternary secret `s`;
//! only the per-digit error `e_j`, carry `c_j`, and public material differ. The
//! digit congruences are batched with a per-digit challenge `delta_j` into one
//! inner product over the shared witness `(s || e_0.. || c_0..)`, so the secret
//! is committed and opened once per key, not once per atom - the amortization
//! the per-key byte and memory budgets rely on. The support constraints prove
//! `s` ternary once, and `e_j` eta-2 and `c_j` range-bounded per digit.
//!
//! All three diagonal source shapes are covered (`KeySource`): relinearization
//! round one (`source = s`), Galois rotation (`source = phi_g(s)`), and
//! relinearization round two (`source = s (*) aggregate`). Only the source's
//! contribution to the secret linear form differs; the aggregation, support,
//! commitment, FRI, and masking are shared. The source is absorbed into the
//! transcript, so a proof for one source (or one automorphism element) cannot
//! be replayed as another. The construction, soundness, and masking are the
//! same as `atom_proof` (which proves the single-digit case); this module is
//! the multi-digit generalization.

#![allow(clippy::too_many_arguments)]

use super::super::negacyclic_transform::NegacyclicDomain;
use super::super::proof_field::ProofFieldParameters;
use super::atom_reduction::{AtomPublicInputs, AtomSource, reduce_atom};
use super::column_commitment::{ColumnCommitment, ColumnOpening, verify_column_opening};
use super::domain::{CyclicDomain, coset_evaluate_coefficients, coset_offset};
use super::low_degree::{
    FriParameters, FriProof, fri_answer, fri_commit, fri_verify_queries, fri_verify_structure,
};
use super::merkle::MerkleDigest;
use super::polynomial;
use super::transcript::Transcript;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

const PROTOCOL_LABEL: &str = "sealed-lattice/setup/key-switch-atom/key-v1";
const FRI_RATE_BLOWUP: usize = 4;

pub(super) struct KeyFriProofParameters {
    pub(crate) query_count: usize,
    pub(crate) mask_degree: usize,
}

// Public data for one digit: the recombined sample and component, and the
// digit's gadget idempotent. The group modulus and plaintext modulus are shared.
pub(super) struct DigitPublic<const LIMB_COUNT: usize> {
    pub(crate) recombined_sample: Vec<[u64; LIMB_COUNT]>,
    pub(crate) recombined_component_b: Vec<[u64; LIMB_COUNT]>,
    pub(crate) gadget_idempotent: [u64; LIMB_COUNT],
}

pub(super) struct KeyPublic<const LIMB_COUNT: usize> {
    pub(crate) digits: Vec<DigitPublic<LIMB_COUNT>>,
    pub(crate) group_modulus: [u64; LIMB_COUNT],
    pub(crate) plaintext_modulus: [u64; LIMB_COUNT],
}

// Per-digit witness: the error and carry vectors (the secret is shared).
pub(super) struct DigitWitness {
    pub(crate) error: Vec<i64>,
    pub(crate) carry: Vec<i64>,
}

// The key's diagonal source shape, shared by every digit atom of the key
// (round two carries one public aggregate per digit). Bound into the
// transcript, so a proof for one source cannot be replayed as another.
pub(super) enum KeySource<const LIMB_COUNT: usize> {
    RoundOne,
    Galois {
        galois_element: usize,
    },
    RoundTwo {
        aggregate_by_digit: Vec<Vec<[u64; LIMB_COUNT]>>,
    },
}

impl<const LIMB_COUNT: usize> KeySource<LIMB_COUNT> {
    fn atom_source(&self, digit_index: usize) -> AtomSource<'_, LIMB_COUNT> {
        match self {
            KeySource::RoundOne => AtomSource::RoundOne,
            KeySource::Galois { galois_element } => AtomSource::Galois {
                galois_element: *galois_element,
            },
            KeySource::RoundTwo { aggregate_by_digit } => AtomSource::RoundTwo {
                aggregate: &aggregate_by_digit[digit_index],
            },
        }
    }

    fn absorb(&self, transcript: &mut Transcript) {
        match self {
            KeySource::RoundOne => transcript.absorb_u64("key-source", 1),
            KeySource::Galois { galois_element } => {
                transcript.absorb_u64("key-source", 2);
                transcript.absorb_u64("galois-element", *galois_element as u64);
            }
            KeySource::RoundTwo { aggregate_by_digit } => {
                transcript.absorb_u64("key-source", 3);
                for aggregate in aggregate_by_digit {
                    transcript.absorb_field_elements("round-two-aggregate", aggregate);
                }
            }
        }
    }
}

pub(super) struct KeyFriProof<const LIMB_COUNT: usize> {
    pub(crate) base_root: MerkleDigest,
    pub(crate) quotient_root: MerkleDigest,
    pub(crate) fri: FriProof<LIMB_COUNT>,
    pub(crate) base_opening: ColumnOpening<LIMB_COUNT>,
    pub(crate) quotient_opening: ColumnOpening<LIMB_COUNT>,
}

fn invalid_key(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// The carry range `|c| <= N+1` is proven by decomposing the shifted carry
// `c + (N+1) in [0, 2N+2]` into bits, each range-checked in {0,1}, plus the
// binary reconstruction. Per-bit decomposition is degree-2 and keeps the
// committed carry within `~3N`, below the field's no-wrap exactness bound (the
// proof field is sized so `|residual| < p` for `|c| <= N+1`, and 17 bits at the
// first profile keep the reconstructed carry just inside `3N`; a coarser base
// would overshoot that bound and is unsound, so bits are the tightest safe
// decomposition here).
fn carry_bit_count(ring_degree: usize) -> usize {
    let maximum = 2 * ring_degree + 2;
    (maximum + 1).next_power_of_two().trailing_zeros() as usize
}

// Shared base column indices.
const COLUMN_SECRET: usize = 0;
const COLUMN_SECRET_SQUARE: usize = 1;
const SHARED_COLUMN_COUNT: usize = 2;

// Per-digit block: error, carry, error-square, error-support, then the carry's
// range bits.
const DIGIT_ERROR: usize = 0;
const DIGIT_CARRY: usize = 1;
const DIGIT_ERROR_SQUARE: usize = 2;
const DIGIT_ERROR_SUPPORT: usize = 3;
const DIGIT_BITS_START: usize = 4;

fn digit_block_size(ring_degree: usize) -> usize {
    DIGIT_BITS_START + carry_bit_count(ring_degree)
}

fn base_column_count(ring_degree: usize, digit_count: usize) -> usize {
    SHARED_COLUMN_COUNT + digit_count * digit_block_size(ring_degree)
}

fn digit_column(ring_degree: usize, digit: usize, offset_in_block: usize) -> usize {
    SHARED_COLUMN_COUNT + digit * digit_block_size(ring_degree) + offset_in_block
}

// Quotient columns: one sumcheck quotient, one sumcheck g, one support quotient.
const QUOTIENT_SUMCHECK: usize = 0;
const QUOTIENT_G: usize = 1;
const QUOTIENT_SUPPORT: usize = 2;
const QUOTIENT_COLUMN_COUNT: usize = 3;

struct Layout {
    trace_size: usize,
    coset_size: usize,
}

fn layout(ring_degree: usize) -> CanonicalResult<Layout> {
    if !ring_degree.is_power_of_two() || ring_degree < 2 {
        return Err(invalid_key("ring degree must be a power of two >= 2"));
    }
    // Committed degree bound `2m` covers the masked columns and the support
    // quotient (bit range products are degree 2); the coset is `FRI_RATE_BLOWUP`
    // times that, giving FRI rate 1/4. With the two-adic ceiling at 2^20 the
    // first profile N = 32768 runs unsplit.
    let coset_size = FRI_RATE_BLOWUP * 2 * ring_degree;
    if coset_size > super::domain::MAX_TWO_ADIC_ORDER {
        return Err(invalid_key(
            "key coset exceeds the field two-adic order at this ring degree",
        ));
    }
    Ok(Layout {
        trace_size: ring_degree,
        coset_size,
    })
}

fn vanishing_polynomial<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_size: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let mut vanishing = vec![parameters.zero(); trace_size + 1];
    vanishing[0] = parameters.negate(&parameters.one());
    vanishing[trace_size] = parameters.one();
    vanishing
}

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
    let mask_multiple = polynomial::multiply_via_ntt(
        parameters,
        &mask,
        &vanishing_polynomial(parameters, trace_size),
    );
    polynomial::add(parameters, coefficients, &mask_multiple)
}

// Build all base column coefficient vectors (shared secret block then per-digit
// blocks).
fn build_base_columns<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
    secret: &[i64],
    digits: &[DigitWitness],
    mask_degree: usize,
    salt_seed: &mut u64,
) -> CanonicalResult<Vec<Vec<[u64; LIMB_COUNT]>>> {
    let bit_count = carry_bit_count(ring_degree);
    let carry_shift = (ring_degree + 1) as i64;
    let mut columns = Vec::with_capacity(base_column_count(ring_degree, digits.len()));

    // Shared: S, S^2.
    let secret_values: Vec<[u64; LIMB_COUNT]> = secret
        .iter()
        .map(|v| parameters.signed_word_to_element(*v))
        .collect();
    let secret_square_values: Vec<[u64; LIMB_COUNT]> = secret
        .iter()
        .map(|v| parameters.signed_word_to_element(v * v))
        .collect();
    for values in [&secret_values, &secret_square_values] {
        let coefficients = trace_domain.interpolate(values);
        columns.push(masked_coefficients(
            parameters,
            &coefficients,
            ring_degree,
            mask_degree,
            salt_seed,
        ));
    }

    // Per digit: E_j, C_j, E_j^2, Pcol_j, bits_j.
    for digit in digits {
        if digit.error.len() != ring_degree || digit.carry.len() != ring_degree {
            return Err(invalid_key(
                "digit witness length does not match ring degree",
            ));
        }
        let error_values: Vec<[u64; LIMB_COUNT]> = digit
            .error
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let carry_values: Vec<[u64; LIMB_COUNT]> = digit
            .carry
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let error_square_values: Vec<[u64; LIMB_COUNT]> = digit
            .error
            .iter()
            .map(|v| parameters.signed_word_to_element(v * v))
            .collect();
        let error_support_values: Vec<[u64; LIMB_COUNT]> = digit
            .error
            .iter()
            .map(|v| {
                let square = v * v;
                parameters.signed_word_to_element((square - 1) * (square - 4))
            })
            .collect();
        let mut bit_values = vec![Vec::with_capacity(ring_degree); bit_count];
        for &carry_scalar in &digit.carry {
            let shifted = carry_scalar + carry_shift;
            if shifted < 0 {
                return Err(invalid_key("carry is below its range bound"));
            }
            for (bit_index, column) in bit_values.iter_mut().enumerate() {
                let bit = (shifted >> bit_index) & 1;
                column.push(parameters.unsigned_word_to_element(bit as u64));
            }
        }
        for values in [
            &error_values,
            &carry_values,
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
    }

    Ok(columns)
}

// One support constraint count: ternary (2) + per digit eta-2 (3) + range
// (bits + 1 reconstruction).
fn support_constraint_count(ring_degree: usize, digit_count: usize) -> usize {
    2 + digit_count * (3 + carry_bit_count(ring_degree) + 1)
}

// The place value `2^index` for the carry bit reconstruction.
fn power_of_two<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    index: usize,
) -> [u64; LIMB_COUNT] {
    parameters.unsigned_word_to_element(1_u64 << index)
}

// Build the support constraint polynomials in a fixed order shared by prover
// and verifier.
fn support_constraints<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    digit_count: usize,
    columns: &[Vec<[u64; LIMB_COUNT]>],
) -> Vec<Vec<[u64; LIMB_COUNT]>> {
    let bit_count = carry_bit_count(ring_degree);
    let one = vec![parameters.one()];
    let four = vec![parameters.unsigned_word_to_element(4)];
    let shift = vec![parameters.unsigned_word_to_element((ring_degree + 1) as u64)];
    let secret = &columns[COLUMN_SECRET];
    let secret_square = &columns[COLUMN_SECRET_SQUARE];

    let mut constraints = Vec::new();
    // Ternary: Ssq - S*S, S*(Ssq-1).
    constraints.push(polynomial::subtract(
        parameters,
        secret_square,
        &polynomial::multiply_via_ntt(parameters, secret, secret),
    ));
    constraints.push(polynomial::multiply_via_ntt(
        parameters,
        secret,
        &polynomial::subtract(parameters, secret_square, &one),
    ));
    for digit in 0..digit_count {
        let error = &columns[digit_column(ring_degree, digit, DIGIT_ERROR)];
        let carry = &columns[digit_column(ring_degree, digit, DIGIT_CARRY)];
        let error_square = &columns[digit_column(ring_degree, digit, DIGIT_ERROR_SQUARE)];
        let error_support = &columns[digit_column(ring_degree, digit, DIGIT_ERROR_SUPPORT)];
        // eta-2: Wsq - E*E, Pcol - (Wsq-1)(Wsq-4), E*Pcol.
        constraints.push(polynomial::subtract(
            parameters,
            error_square,
            &polynomial::multiply_via_ntt(parameters, error, error),
        ));
        constraints.push(polynomial::subtract(
            parameters,
            error_support,
            &polynomial::multiply_via_ntt(
                parameters,
                &polynomial::subtract(parameters, error_square, &one),
                &polynomial::subtract(parameters, error_square, &four),
            ),
        ));
        constraints.push(polynomial::multiply_via_ntt(
            parameters,
            error,
            error_support,
        ));
        // range: each bit b in {0,1} via b(b-1) = 0, then the binary
        // reconstruction of the shifted carry.
        let mut reconstruction = polynomial::add(parameters, carry, &shift);
        for bit_index in 0..bit_count {
            let bit = &columns[digit_column(ring_degree, digit, DIGIT_BITS_START + bit_index)];
            constraints.push(polynomial::multiply_via_ntt(
                parameters,
                bit,
                &polynomial::subtract(parameters, bit, &one),
            ));
            let weighted = polynomial::scale(parameters, bit, &power_of_two(parameters, bit_index));
            reconstruction = polynomial::subtract(parameters, &reconstruction, &weighted);
        }
        constraints.push(reconstruction);
    }
    constraints
}

// The support constraint value at one coset point, from opened column values.
fn support_value_at<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    digit_count: usize,
    values: &[[u64; LIMB_COUNT]],
    alpha: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let bit_count = carry_bit_count(ring_degree);
    let one = parameters.one();
    let four = parameters.unsigned_word_to_element(4);
    let secret = values[COLUMN_SECRET];
    let secret_square = values[COLUMN_SECRET_SQUARE];

    let mut constraints = Vec::with_capacity(support_constraint_count(ring_degree, digit_count));
    constraints.push(parameters.subtract(&secret_square, &parameters.multiply(&secret, &secret)));
    constraints.push(parameters.multiply(&secret, &parameters.subtract(&secret_square, &one)));
    for digit in 0..digit_count {
        let error = values[digit_column(ring_degree, digit, DIGIT_ERROR)];
        let carry = values[digit_column(ring_degree, digit, DIGIT_CARRY)];
        let error_square = values[digit_column(ring_degree, digit, DIGIT_ERROR_SQUARE)];
        let error_support = values[digit_column(ring_degree, digit, DIGIT_ERROR_SUPPORT)];
        constraints.push(parameters.subtract(&error_square, &parameters.multiply(&error, &error)));
        let support_product = parameters.multiply(
            &parameters.subtract(&error_square, &one),
            &parameters.subtract(&error_square, &four),
        );
        constraints.push(parameters.subtract(&error_support, &support_product));
        constraints.push(parameters.multiply(&error, &error_support));
        let mut reconstruction = parameters.add(
            &carry,
            &parameters.unsigned_word_to_element((ring_degree + 1) as u64),
        );
        for bit_index in 0..bit_count {
            let bit = values[digit_column(ring_degree, digit, DIGIT_BITS_START + bit_index)];
            constraints.push(parameters.multiply(&bit, &parameters.subtract(&bit, &one)));
            reconstruction = parameters.subtract(
                &reconstruction,
                &parameters.multiply(&bit, &power_of_two(parameters, bit_index)),
            );
        }
        constraints.push(reconstruction);
    }

    let mut value = parameters.zero();
    for (weight, constraint) in alpha.iter().zip(constraints.iter()) {
        value = parameters.add(&value, &parameters.multiply(weight, constraint));
    }
    value
}

// The combined per-digit linear forms, computed by both sides from public data
// and the challenges: the shared secret form Ls (sum_j delta_j L_j.secret),
// per-digit Le_j, Lc_j (delta_j scaled), and the summed target.
struct CombinedForms<const LIMB_COUNT: usize> {
    secret: Vec<[u64; LIMB_COUNT]>,
    error_by_digit: Vec<Vec<[u64; LIMB_COUNT]>>,
    carry_by_digit: Vec<Vec<[u64; LIMB_COUNT]>>,
    target: [u64; LIMB_COUNT],
}

fn combined_forms<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    negacyclic: &NegacyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    gamma: &[[u64; LIMB_COUNT]],
    delta: &[[u64; LIMB_COUNT]],
) -> CombinedForms<LIMB_COUNT> {
    let mut secret = vec![parameters.zero(); ring_degree];
    let mut error_by_digit = Vec::with_capacity(public.digits.len());
    let mut carry_by_digit = Vec::with_capacity(public.digits.len());
    let mut target = parameters.zero();
    for (digit_index, digit) in public.digits.iter().enumerate() {
        let atom_public = AtomPublicInputs {
            recombined_sample: &digit.recombined_sample,
            recombined_component_b: &digit.recombined_component_b,
            gadget_idempotent: digit.gadget_idempotent,
            group_modulus: public.group_modulus,
            plaintext_modulus: public.plaintext_modulus,
        };
        let form = reduce_atom(
            parameters,
            negacyclic,
            &atom_public,
            &source.atom_source(digit_index),
            gamma,
        );
        let weight = delta[digit_index];
        for (accumulator, coefficient) in secret.iter_mut().zip(form.secret_coefficients.iter()) {
            *accumulator = parameters.add(accumulator, &parameters.multiply(&weight, coefficient));
        }
        error_by_digit.push(
            form.error_coefficients
                .iter()
                .map(|c| parameters.multiply(&weight, c))
                .collect(),
        );
        carry_by_digit.push(
            form.carry_coefficients
                .iter()
                .map(|c| parameters.multiply(&weight, c))
                .collect(),
        );
        target = parameters.add(&target, &parameters.multiply(&weight, &form.target));
    }
    CombinedForms {
        secret,
        error_by_digit,
        carry_by_digit,
        target,
    }
}

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

fn absorb_public<const LIMB_COUNT: usize>(
    transcript: &mut Transcript,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
) {
    transcript.absorb_u64("ring-degree", ring_degree as u64);
    transcript.absorb_u64("digit-count", public.digits.len() as u64);
    transcript.absorb_field_elements("group-modulus", &[public.group_modulus]);
    transcript.absorb_field_elements("plaintext-modulus", &[public.plaintext_modulus]);
    for digit in &public.digits {
        transcript.absorb_field_elements("digit-sample", &digit.recombined_sample);
        transcript.absorb_field_elements("digit-component-b", &digit.recombined_component_b);
        transcript.absorb_field_elements("digit-gadget", &[digit.gadget_idempotent]);
    }
    source.absorb(transcript);
}

pub(super) fn prove_round_one_key_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    secret: &[i64],
    digits: &[DigitWitness],
    proof_parameters: &KeyFriProofParameters,
    salt_seed: &mut u64,
) -> CanonicalResult<KeyFriProof<LIMB_COUNT>> {
    prove_key_fri(
        parameters,
        ring_degree,
        public,
        &KeySource::RoundOne,
        secret,
        digits,
        proof_parameters,
        salt_seed,
    )
}

pub(super) fn prove_key_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    secret: &[i64],
    digits: &[DigitWitness],
    proof_parameters: &KeyFriProofParameters,
    salt_seed: &mut u64,
) -> CanonicalResult<KeyFriProof<LIMB_COUNT>> {
    if public.digits.len() != digits.len() || digits.is_empty() {
        return Err(invalid_key("digit public and witness counts must match"));
    }
    let layout = layout(ring_degree)?;
    let digit_count = digits.len();
    let trace_domain = CyclicDomain::new(parameters, layout.trace_size)?;
    let coset_domain = CyclicDomain::new(parameters, layout.coset_size)?;
    let offset = coset_offset(parameters);
    let negacyclic = NegacyclicDomain::new(parameters, ring_degree)?;

    let base_coefficients = build_base_columns(
        parameters,
        &trace_domain,
        ring_degree,
        secret,
        digits,
        proof_parameters.mask_degree,
        salt_seed,
    )?;
    let base_codewords = base_coefficients
        .iter()
        .map(|c| coset_evaluate_coefficients(&coset_domain, &offset, c))
        .collect::<Vec<_>>();
    let base_commitment = ColumnCommitment::commit(base_codewords, salt_seed)?;

    let mut transcript = Transcript::new(PROTOCOL_LABEL);
    absorb_public(&mut transcript, ring_degree, public, source);
    transcript.absorb_digest("key-base-root", &base_commitment.root());
    let gamma = transcript.challenge_field_elements(parameters, "key-gamma", ring_degree);
    let delta = transcript.challenge_field_elements(parameters, "key-delta", digit_count);
    let forms = combined_forms(
        parameters,
        &negacyclic,
        ring_degree,
        public,
        source,
        &gamma,
        &delta,
    );
    let alpha = transcript.challenge_field_elements(
        parameters,
        "key-support-alpha",
        support_constraint_count(ring_degree, digit_count),
    );

    // Sumcheck: f = Ls*S + sum_j (Le_j*E_j + Lc_j*C_j).
    let ls = trace_domain.interpolate(&forms.secret);
    let mut f = polynomial::multiply_via_ntt(parameters, &ls, &base_coefficients[COLUMN_SECRET]);
    for digit in 0..digit_count {
        let le = trace_domain.interpolate(&forms.error_by_digit[digit]);
        let lc = trace_domain.interpolate(&forms.carry_by_digit[digit]);
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::multiply_via_ntt(
                parameters,
                &le,
                &base_coefficients[digit_column(ring_degree, digit, DIGIT_ERROR)],
            ),
        );
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::multiply_via_ntt(
                parameters,
                &lc,
                &base_coefficients[digit_column(ring_degree, digit, DIGIT_CARRY)],
            ),
        );
    }
    let vanishing = vanishing_polynomial(parameters, layout.trace_size);
    let q_sc = polynomial::divide_by_vanishing(parameters, &f, layout.trace_size);
    let mut remainder = polynomial::subtract(
        parameters,
        &f,
        &polynomial::multiply_via_ntt(parameters, &q_sc, &vanishing),
    );
    polynomial::trim(&mut remainder);
    let size_inverse =
        parameters.inverse(&parameters.unsigned_word_to_element(layout.trace_size as u64));
    let target_over_size = parameters.multiply(&forms.target, &size_inverse);
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

    // Support: V = sum alpha_i constraint_i, vanishing on H.
    let constraints = support_constraints(parameters, ring_degree, digit_count, &base_coefficients);
    let mut v = vec![parameters.zero()];
    for (weight, constraint) in alpha.iter().zip(constraints.iter()) {
        v = polynomial::add(
            parameters,
            &v,
            &polynomial::scale(parameters, constraint, weight),
        );
    }
    let q_support = polynomial::divide_by_vanishing(parameters, &v, layout.trace_size);
    let mut support_remainder = polynomial::subtract(
        parameters,
        &v,
        &polynomial::multiply_via_ntt(parameters, &q_support, &vanishing),
    );
    polynomial::trim(&mut support_remainder);
    if support_remainder
        .iter()
        .any(|c| c.iter().any(|limb| *limb != 0))
    {
        return Err(invalid_key("support constraints do not vanish on H"));
    }

    let mut quotient_coefficients = vec![Vec::new(); QUOTIENT_COLUMN_COUNT];
    quotient_coefficients[QUOTIENT_SUMCHECK] = q_sc;
    quotient_coefficients[QUOTIENT_G] = g;
    quotient_coefficients[QUOTIENT_SUPPORT] = q_support;
    let quotient_codewords = quotient_coefficients
        .iter()
        .map(|c| coset_evaluate_coefficients(&coset_domain, &offset, c))
        .collect::<Vec<_>>();
    let quotient_commitment = ColumnCommitment::commit(quotient_codewords.clone(), salt_seed)?;
    transcript.absorb_digest("key-quotient-root", &quotient_commitment.root());

    let base_count = base_commitment.column_count();
    let weights = transcript.challenge_field_elements(
        parameters,
        "key-combination",
        base_count + QUOTIENT_COLUMN_COUNT,
    );

    // Combination codeword: weighted sum of every committed column's codeword.
    let mut combination = vec![parameters.zero(); layout.coset_size];
    for (column, weight) in weights.iter().take(base_count).enumerate() {
        for (slot, index) in combination.iter_mut().zip(0..layout.coset_size) {
            *slot = parameters.add(
                slot,
                &parameters.multiply(weight, &base_commitment.value(column, index)),
            );
        }
    }
    for (quotient, codeword) in quotient_codewords.iter().enumerate() {
        let weight = weights[base_count + quotient];
        for (slot, value) in combination.iter_mut().zip(codeword.iter()) {
            *slot = parameters.add(slot, &parameters.multiply(&weight, value));
        }
    }

    let fri_commitment = fri_commit(
        parameters,
        &mut transcript,
        &combination,
        &offset,
        salt_seed,
    )?;
    let query_positions = transcript.challenge_positions(
        "key-query",
        layout.coset_size,
        proof_parameters.query_count,
    );
    let fri = fri_answer(&fri_commitment, &query_positions);

    let half = layout.coset_size / 2;
    let mut open_indices = Vec::with_capacity(query_positions.len() * 2);
    for &position in &query_positions {
        let folded = position % half;
        open_indices.push(folded);
        open_indices.push(folded + half);
    }
    let base_opening = base_commitment.open(&open_indices);
    let quotient_opening = quotient_commitment.open(&open_indices);

    Ok(KeyFriProof {
        base_root: base_commitment.root(),
        quotient_root: quotient_commitment.root(),
        fri,
        base_opening,
        quotient_opening,
    })
}

pub(super) fn verify_round_one_key_fri<const LIMB_COUNT: usize>(
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
        proof_parameters,
    )
}

pub(super) fn verify_key_fri<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    public: &KeyPublic<LIMB_COUNT>,
    source: &KeySource<LIMB_COUNT>,
    proof: &KeyFriProof<LIMB_COUNT>,
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
    let base_count = base_column_count(ring_degree, digit_count);

    let mut transcript = Transcript::new(PROTOCOL_LABEL);
    absorb_public(&mut transcript, ring_degree, public, source);
    transcript.absorb_digest("key-base-root", &proof.base_root);
    let gamma = transcript.challenge_field_elements(parameters, "key-gamma", ring_degree);
    let delta = transcript.challenge_field_elements(parameters, "key-delta", digit_count);
    let forms = combined_forms(
        parameters,
        &negacyclic,
        ring_degree,
        public,
        source,
        &gamma,
        &delta,
    );
    let alpha = transcript.challenge_field_elements(
        parameters,
        "key-support-alpha",
        support_constraint_count(ring_degree, digit_count),
    );
    transcript.absorb_digest("key-quotient-root", &proof.quotient_root);
    let weights = transcript.challenge_field_elements(
        parameters,
        "key-combination",
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
    let Some(quotient_rows) = verify_column_opening(
        &proof.quotient_root,
        layout.coset_size,
        QUOTIENT_COLUMN_COUNT,
        &proof.quotient_opening,
    ) else {
        return Ok(false);
    };

    // Public linear-form polynomials over H.
    let ls = trace_domain.interpolate(&forms.secret);
    let le_by_digit: Vec<Vec<[u64; LIMB_COUNT]>> = forms
        .error_by_digit
        .iter()
        .map(|form| trace_domain.interpolate(form))
        .collect();
    let lc_by_digit: Vec<Vec<[u64; LIMB_COUNT]>> = forms
        .carry_by_digit
        .iter()
        .map(|form| trace_domain.interpolate(form))
        .collect();
    let size_inverse =
        parameters.inverse(&parameters.unsigned_word_to_element(layout.trace_size as u64));
    let target_over_size = parameters.multiply(&forms.target, &size_inverse);

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
            let Some(quotient_values) = quotient_rows.get(&index) else {
                return Ok(false);
            };
            if combination_at(parameters, base_values, quotient_values, &weights) != expected {
                return Ok(false);
            }
            let x = parameters.multiply(&offset, &coset_domain.point(index));
            let vanishing_x = polynomial::vanishing_at(parameters, &x, layout.trace_size);

            // Sumcheck: f(x) = target/m + x g(x) + Z_H(x) q_sc(x).
            let mut f_x = parameters.multiply(
                &polynomial::evaluate(parameters, &ls, &x),
                &base_values[COLUMN_SECRET],
            );
            for digit in 0..digit_count {
                let le_x = polynomial::evaluate(parameters, &le_by_digit[digit], &x);
                let lc_x = polynomial::evaluate(parameters, &lc_by_digit[digit], &x);
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(
                        &le_x,
                        &base_values[digit_column(ring_degree, digit, DIGIT_ERROR)],
                    ),
                );
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(
                        &lc_x,
                        &base_values[digit_column(ring_degree, digit, DIGIT_CARRY)],
                    ),
                );
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

            // Support: V(x) = Z_H(x) q_support(x).
            let v_x = support_value_at(parameters, ring_degree, digit_count, base_values, &alpha);
            if v_x != parameters.multiply(&vanishing_x, &quotient_values[QUOTIENT_SUPPORT]) {
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

    // Build a synthetic round-one key with `digit_count` digits sharing one
    // ternary secret, whose every digit congruence holds exactly.
    fn synthetic_key(
        ring_degree: usize,
        digit_count: usize,
    ) -> (Vec<i64>, Vec<DigitWitness>, KeyPublic<13>) {
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain");
        let secret: Vec<i64> = (0..ring_degree).map(|i| ((i * 7) % 3) as i64 - 1).collect();
        let secret_field: Vec<[u64; 13]> = secret
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let group_modulus = parameters.unsigned_word_to_element(1_000_003);
        let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
        let mut digits = Vec::with_capacity(digit_count);
        let mut public_digits = Vec::with_capacity(digit_count);
        for digit_index in 0..digit_count {
            let error: Vec<i64> = (0..ring_degree)
                .map(|i| (((i + digit_index) * 5) % 5) as i64 - 2)
                .collect();
            let carry: Vec<i64> = (0..ring_degree)
                .map(|i| ((i + digit_index) % 3) as i64 - 1)
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
            let mut state = 0xa5_u64.wrapping_add(digit_index as u64 * 0x1000);
            for _ in 0..ring_degree {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                sample.push(parameters.unsigned_word_to_element(state));
            }
            let gadget_idempotent =
                parameters.unsigned_word_to_element(0x9e37 + digit_index as u64);
            let a_times_s = domain.negacyclic_product(&sample, &secret_field);
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
            digits.push(DigitWitness { error, carry });
            public_digits.push(DigitPublic {
                recombined_sample: sample,
                recombined_component_b: component_b,
                gadget_idempotent,
            });
        }
        let public = KeyPublic {
            digits: public_digits,
            group_modulus,
            plaintext_modulus,
        };
        (secret, digits, public)
    }

    #[test]
    fn honest_multi_digit_key_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        for digit_count in [1_usize, 3, 8] {
            let (secret, digits, public) = synthetic_key(ring_degree, digit_count);
            let proof_parameters = KeyFriProofParameters {
                query_count: 40,
                mask_degree: 0,
            };
            let mut salt_seed = 0x1234 + digit_count as u64;
            let proof = prove_round_one_key_fri(
                &parameters,
                ring_degree,
                &public,
                &secret,
                &digits,
                &proof_parameters,
                &mut salt_seed,
            )
            .expect("prove");
            assert!(
                verify_round_one_key_fri(
                    &parameters,
                    ring_degree,
                    &public,
                    &proof,
                    &proof_parameters
                )
                .expect("verify"),
                "honest {digit_count}-digit key must verify"
            );
        }
    }

    #[test]
    fn masked_multi_digit_key_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, digits, public) = synthetic_key(ring_degree, 4);
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 16,
        };
        let mut salt_seed = 0x5eed;
        let proof = prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        assert!(
            verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
                .expect("verify")
        );
    }

    #[test]
    fn one_tampered_digit_error_is_caught_by_the_batch() {
        // Flip one digit's error in a way that breaks its congruence (and its
        // eta-2 support). The per-digit batching challenge makes the combined
        // claim miss, and the support constraint fails, so the prover cannot
        // build a valid proof or the verifier rejects.
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, mut digits, public) = synthetic_key(ring_degree, 5);
        digits[2].error[7] = 3; // out of eta-2 range and breaks the congruence
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x9;
        let result = prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        );
        match result {
            Err(_) => {}
            Ok(proof) => assert!(
                !verify_round_one_key_fri(
                    &parameters,
                    ring_degree,
                    &public,
                    &proof,
                    &proof_parameters
                )
                .expect("verify"),
                "a tampered digit must not yield an accepted key proof"
            ),
        }
    }

    #[test]
    fn out_of_range_carry_is_rejected() {
        // A carry outside the range the decomposition represents, with the
        // component rebuilt so the congruence still holds: the range digits
        // cannot reconstruct the shifted carry, so the reconstruction support
        // constraint fails and the prover (or verifier) rejects. This guards the
        // carry-range decomposition against silently admitting a carry large
        // enough to break the field no-wrap exactness bound.
        use super::super::super::negacyclic_transform::NegacyclicDomain;
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain");
        let secret: Vec<i64> = (0..ring_degree).map(|i| ((i * 7) % 3) as i64 - 1).collect();
        let secret_field: Vec<[u64; 13]> = secret
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let group_modulus = parameters.unsigned_word_to_element(1_000_003);
        let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
        let error: Vec<i64> = (0..ring_degree).map(|i| ((i * 5) % 5) as i64 - 2).collect();
        let mut carry: Vec<i64> = (0..ring_degree).map(|i| (i % 3) as i64 - 1).collect();
        // Well beyond |c| <= N+1 and beyond the representable decomposition range.
        carry[3] = (ring_degree as i64) * 3;
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
        let a_times_s = domain.negacyclic_product(&sample, &secret_field);
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
        let public = KeyPublic {
            digits: vec![DigitPublic {
                recombined_sample: sample,
                recombined_component_b: component_b,
                gadget_idempotent,
            }],
            group_modulus,
            plaintext_modulus,
        };
        let digits = vec![DigitWitness { error, carry }];
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x4321;
        let result = prove_key_fri(
            &parameters,
            ring_degree,
            &public,
            &KeySource::RoundOne,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        );
        match result {
            Err(_) => {}
            Ok(proof) => assert!(
                !verify_key_fri(
                    &parameters,
                    ring_degree,
                    &public,
                    &KeySource::RoundOne,
                    &proof,
                    &proof_parameters
                )
                .expect("verify"),
                "an out-of-range carry must not yield an accepted key proof"
            ),
        }
    }

    #[test]
    fn wrong_shared_secret_breaks_every_digit() {
        // A secret that is not the one the components were built from: every
        // digit congruence fails, so the batched claim misses.
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, digits, public) = synthetic_key(ring_degree, 4);
        let mut wrong_secret = secret.clone();
        wrong_secret[3] = if wrong_secret[3] == 1 { -1 } else { 1 };
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0xabc;
        let result = prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &wrong_secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        );
        match result {
            Err(_) => {}
            Ok(proof) => assert!(
                !verify_round_one_key_fri(
                    &parameters,
                    ring_degree,
                    &public,
                    &proof,
                    &proof_parameters
                )
                .expect("verify"),
                "a wrong shared secret must not yield an accepted key proof"
            ),
        }
    }

    // The forward automorphism image phi_g(s): s(X) -> s(X^g), as a length-N
    // signed vector. g is odd, so the coefficient map i -> (i*g mod 2N) is a
    // bijection with the negacyclic sign fold.
    fn phi_g(secret: &[i64], galois_element: usize) -> Vec<i64> {
        let degree = secret.len();
        let ring_order = 2 * degree;
        let mut image = vec![0_i64; degree];
        for (index, &value) in secret.iter().enumerate() {
            let position = (index * galois_element) % ring_order;
            if position < degree {
                image[position] += value;
            } else {
                image[position - degree] -= value;
            }
        }
        image
    }

    // Build a synthetic key for a given source, whose every digit congruence
    // holds exactly: B_j = t*e_j + G_j*source_j + Q*c_j - A_j*s.
    fn synthetic_key_for_source(
        ring_degree: usize,
        digit_count: usize,
        source: &KeySource<13>,
    ) -> (Vec<i64>, Vec<DigitWitness>, KeyPublic<13>) {
        use super::super::super::negacyclic_transform::NegacyclicDomain;
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain");
        let secret: Vec<i64> = (0..ring_degree).map(|i| ((i * 7) % 3) as i64 - 1).collect();
        let secret_field: Vec<[u64; 13]> = secret
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let group_modulus = parameters.unsigned_word_to_element(1_000_003);
        let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
        let mut digits = Vec::new();
        let mut public_digits = Vec::new();
        for digit_index in 0..digit_count {
            let error: Vec<i64> = (0..ring_degree)
                .map(|i| (((i + digit_index) * 5) % 5) as i64 - 2)
                .collect();
            let carry: Vec<i64> = (0..ring_degree)
                .map(|i| ((i + digit_index) % 3) as i64 - 1)
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
            let mut state = 0xa5_u64.wrapping_add(digit_index as u64 * 0x1000);
            for _ in 0..ring_degree {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                sample.push(parameters.unsigned_word_to_element(state));
            }
            let gadget_idempotent =
                parameters.unsigned_word_to_element(0x9e37 + digit_index as u64);
            let a_times_s = domain.negacyclic_product(&sample, &secret_field);

            // source_j as field elements.
            let source_field: Vec<[u64; 13]> = match source {
                KeySource::RoundOne => secret_field.clone(),
                KeySource::Galois { galois_element } => phi_g(&secret, *galois_element)
                    .iter()
                    .map(|v| parameters.signed_word_to_element(*v))
                    .collect(),
                KeySource::RoundTwo { aggregate_by_digit } => {
                    domain.negacyclic_product(&secret_field, &aggregate_by_digit[digit_index])
                }
            };

            let mut component_b = vec![parameters.zero(); ring_degree];
            for index in 0..ring_degree {
                let t_e = parameters.multiply(&plaintext_modulus, &error_field[index]);
                let g_source = parameters.multiply(&gadget_idempotent, &source_field[index]);
                let q_c = parameters.multiply(&group_modulus, &carry_field[index]);
                let mut value = parameters.add(&t_e, &g_source);
                value = parameters.add(&value, &q_c);
                value = parameters.subtract(&value, &a_times_s[index]);
                component_b[index] = value;
            }
            digits.push(DigitWitness { error, carry });
            public_digits.push(DigitPublic {
                recombined_sample: sample,
                recombined_component_b: component_b,
                gadget_idempotent,
            });
        }
        (
            secret,
            digits,
            KeyPublic {
                digits: public_digits,
                group_modulus,
                plaintext_modulus,
            },
        )
    }

    #[test]
    fn honest_galois_key_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let source = KeySource::Galois { galois_element: 5 };
        let (secret, digits, public) = synthetic_key_for_source(ring_degree, 4, &source);
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x6a10;
        let proof = prove_key_fri(
            &parameters,
            ring_degree,
            &public,
            &source,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        assert!(
            verify_key_fri(
                &parameters,
                ring_degree,
                &public,
                &source,
                &proof,
                &proof_parameters
            )
            .expect("verify")
        );
    }

    #[test]
    fn galois_proof_bound_to_its_element() {
        // A Galois proof made with element 5 must not verify as element 7: the
        // element is absorbed into the transcript.
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let source = KeySource::Galois { galois_element: 5 };
        let (secret, digits, public) = synthetic_key_for_source(ring_degree, 3, &source);
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x6a11;
        let proof = prove_key_fri(
            &parameters,
            ring_degree,
            &public,
            &source,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        let other_source = KeySource::Galois { galois_element: 7 };
        assert!(
            !verify_key_fri(
                &parameters,
                ring_degree,
                &public,
                &other_source,
                &proof,
                &proof_parameters
            )
            .expect("verify"),
            "a Galois proof must not verify under a different automorphism element"
        );
    }

    #[test]
    fn honest_round_two_key_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let digit_count = 4;
        // One public aggregate per digit.
        let aggregate_by_digit: Vec<Vec<[u64; 13]>> = (0..digit_count)
            .map(|digit_index| {
                let mut state = 0x3300_u64 + digit_index as u64;
                (0..ring_degree)
                    .map(|_| {
                        state = state
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(7);
                        parameters.unsigned_word_to_element(state)
                    })
                    .collect()
            })
            .collect();
        let source = KeySource::RoundTwo { aggregate_by_digit };
        let (secret, digits, public) = synthetic_key_for_source(ring_degree, digit_count, &source);
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0x7b20;
        let proof = prove_key_fri(
            &parameters,
            ring_degree,
            &public,
            &source,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        assert!(
            verify_key_fri(
                &parameters,
                ring_degree,
                &public,
                &source,
                &proof,
                &proof_parameters
            )
            .expect("verify")
        );
    }
}
