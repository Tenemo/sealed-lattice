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
use super::carry_range_lookup;
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
    pub(crate) aux_root: MerkleDigest,
    pub(crate) quotient_root: MerkleDigest,
    pub(crate) fri: FriProof<LIMB_COUNT>,
    pub(crate) base_opening: ColumnOpening<LIMB_COUNT>,
    pub(crate) aux_opening: ColumnOpening<LIMB_COUNT>,
    pub(crate) quotient_opening: ColumnOpening<LIMB_COUNT>,
    // logUp terminals: the lookup-side total `sum_x sum_d f_d(x)` and one total
    // per table chunk `sum_x f_T_k(x)`. Bound to the committed fraction columns
    // by the batched sumcheck, and cross-checked `lookup = sum_k table_k`.
    pub(crate) lookup_terminal: [u64; LIMB_COUNT],
    pub(crate) table_terminals: Vec<[u64; LIMB_COUNT]>,
}

fn invalid_key(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// The carry range `|c| <= N+1` is proven by a log-derivative (logUp) range
// lookup over the shifted carry `c + (N+1) in [0, 2N+2]`, split into
// `carry_range_lookup::table_count` size-`N` table chunks so every column stays
// in the single trace domain (coset `8N`, FRI rate 1/4 unchanged). The 16-per-
// digit range-bit columns and their binary-reconstruction constraints are gone;
// see `carry_range_lookup` for the identity, the padding-collision defense, and
// the isolated soundness tests. A coarser base decomposition was tried and
// reverted as unsound (a carry could overshoot the field no-wrap bound); the
// lookup certifies membership in the exact range with no overshoot.

// Round-1 base columns: the witness (shared secret plus per-digit blocks) then
// one carry-range multiplicity column per table chunk.
const COLUMN_SECRET: usize = 0;
const COLUMN_SECRET_SQUARE: usize = 1;
const SHARED_COLUMN_COUNT: usize = 2;

// Per-digit block: error, carry, error-square, error-support.
const DIGIT_ERROR: usize = 0;
const DIGIT_CARRY: usize = 1;
const DIGIT_ERROR_SQUARE: usize = 2;
const DIGIT_ERROR_SUPPORT: usize = 3;
const DIGIT_BLOCK_SIZE: usize = 4;

// Index of the first multiplicity column (after all per-digit blocks).
fn base_multiplicity_start(digit_count: usize) -> usize {
    SHARED_COLUMN_COUNT + digit_count * DIGIT_BLOCK_SIZE
}

fn base_column_count(ring_degree: usize, digit_count: usize) -> usize {
    base_multiplicity_start(digit_count) + carry_range_lookup::table_count(ring_degree)
}

fn digit_column(digit: usize, offset_in_block: usize) -> usize {
    SHARED_COLUMN_COUNT + digit * DIGIT_BLOCK_SIZE + offset_in_block
}

fn base_multiplicity_column(digit_count: usize, table_index: usize) -> usize {
    base_multiplicity_start(digit_count) + table_index
}

// Round-2 auxiliary columns (challenge-dependent, committed after the logUp
// challenge is drawn): one lookup fraction column per digit then one table
// fraction column per table chunk.
fn aux_lookup_column(digit: usize) -> usize {
    digit
}

fn aux_table_fraction_column(digit_count: usize, table_index: usize) -> usize {
    digit_count + table_index
}

fn aux_column_count(ring_degree: usize, digit_count: usize) -> usize {
    digit_count + carry_range_lookup::table_count(ring_degree)
}

// Quotient columns: one sumcheck quotient, one sumcheck g, one support quotient.
// The lookup terminals ride the single sumcheck and the fraction pins ride the
// single support composition, so the quotient count is unchanged.
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

// Build the round-1 base column coefficient vectors: the shared secret block,
// the per-digit witness blocks, then one carry-range multiplicity column per
// table chunk. The multiplicity of each table value is the number of shifted
// carries equal to it; an out-of-range carry is simply not counted, which makes
// the logUp balance fail (the sound outcome, exercised by a tamper test).
fn build_base_columns<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
    secret: &[i64],
    digits: &[DigitWitness],
    mask_degree: usize,
    salt_seed: &mut u64,
) -> CanonicalResult<Vec<Vec<[u64; LIMB_COUNT]>>> {
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

    // Per digit: E_j, C_j, E_j^2, Pcol_j.
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
    }

    // Carry-range multiplicity columns (one per table chunk).
    let multiplicity_columns = carry_multiplicity_values(parameters, ring_degree, digits);
    for multiplicity in &multiplicity_columns {
        let coefficients = trace_domain.interpolate(multiplicity);
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

// The carry-range multiplicity value columns (one per table chunk), counting how
// many shifted carries across all digits equal each table value. Out-of-range
// carries are not counted, which makes the logUp balance fail. Deterministic
// from the witness, so both the round-1 base builder and the round-2 aux builder
// derive the same columns.
fn carry_multiplicity_values<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    digits: &[DigitWitness],
) -> Vec<Vec<[u64; LIMB_COUNT]>> {
    let shift = carry_range_lookup::carry_shift(ring_degree);
    let max_shifted = carry_range_lookup::max_shifted_value(ring_degree);
    let mut shifted_in_range = Vec::with_capacity(digits.len() * ring_degree);
    for digit in digits {
        for &carry in &digit.carry {
            let shifted = carry + shift;
            if shifted >= 0 && (shifted as usize) <= max_shifted {
                shifted_in_range.push(shifted as usize);
            }
        }
    }
    carry_range_lookup::multiplicities(parameters, &shifted_in_range, ring_degree)
}

// Build the round-2 auxiliary column coefficient vectors (committed after the
// logUp challenge `mu` is drawn): one lookup fraction column per digit
// `f_d[x] = 1/(mu - (c_d(x) + shift))`, then one table fraction column per chunk
// `f_T_k[x] = m_k(x)/(mu - T_k(x))`. Returns the columns together with the logUp
// terminals (`lookup_terminal = sum_x sum_d f_d`, `table_terminals[k] = sum_x
// f_T_k`), computed from the on-domain values so masking does not affect them.
struct AuxColumns<const LIMB_COUNT: usize> {
    coefficients: Vec<Vec<[u64; LIMB_COUNT]>>,
    lookup_terminal: [u64; LIMB_COUNT],
    table_terminals: Vec<[u64; LIMB_COUNT]>,
}

fn build_aux_columns<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
    digits: &[DigitWitness],
    multiplicity_values: &[Vec<[u64; LIMB_COUNT]>],
    challenge: &[u64; LIMB_COUNT],
    mask_degree: usize,
    salt_seed: &mut u64,
) -> CanonicalResult<AuxColumns<LIMB_COUNT>> {
    let shift = carry_range_lookup::carry_shift(ring_degree);
    let mut coefficients = Vec::with_capacity(aux_column_count(ring_degree, digits.len()));
    let mut lookup_terminal = parameters.zero();

    // Per-digit lookup fractions.
    for digit in digits {
        let shifted_values: Vec<[u64; LIMB_COUNT]> = digit
            .carry
            .iter()
            .map(|carry| parameters.signed_word_to_element(carry + shift))
            .collect();
        let fraction = carry_range_lookup::lookup_fraction_column(parameters, challenge, &shifted_values)
            .ok_or_else(|| invalid_key("logUp challenge collided with a shifted carry"))?;
        lookup_terminal =
            parameters.add(&lookup_terminal, &carry_range_lookup::column_sum(parameters, &fraction));
        let column = trace_domain.interpolate(&fraction);
        coefficients.push(masked_coefficients(
            parameters,
            &column,
            ring_degree,
            mask_degree,
            salt_seed,
        ));
    }

    // Table fractions, one per chunk.
    let mut table_terminals = Vec::with_capacity(multiplicity_values.len());
    for (table_index, multiplicity) in multiplicity_values.iter().enumerate() {
        let table_values = carry_range_lookup::table_values(parameters, ring_degree, table_index);
        let fraction =
            carry_range_lookup::table_fraction_column(parameters, challenge, &table_values, multiplicity)
                .ok_or_else(|| invalid_key("logUp challenge collided with a table value"))?;
        table_terminals.push(carry_range_lookup::column_sum(parameters, &fraction));
        let column = trace_domain.interpolate(&fraction);
        coefficients.push(masked_coefficients(
            parameters,
            &column,
            ring_degree,
            mask_degree,
            salt_seed,
        ));
    }

    Ok(AuxColumns {
        coefficients,
        lookup_terminal,
        table_terminals,
    })
}

// Support constraint count: ternary (2) + per digit [eta-2 (3) + lookup
// fraction pin (1)] + one table fraction pin per chunk.
fn support_constraint_count(ring_degree: usize, digit_count: usize) -> usize {
    2 + digit_count * 4 + carry_range_lookup::table_count(ring_degree)
}

// The public table value polynomials (coefficient form), one per chunk, shared
// by prover and verifier. `T_k` interpolates the chunk's public value column
// over the trace domain; both sides evaluate it at query points like the
// sumcheck linear forms, so no table column is committed and no out-of-range
// value can enter the table.
fn table_value_polynomials<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
    ring_degree: usize,
) -> Vec<Vec<[u64; LIMB_COUNT]>> {
    (0..carry_range_lookup::table_count(ring_degree))
        .map(|table_index| {
            let values = carry_range_lookup::table_values(parameters, ring_degree, table_index);
            trace_domain.interpolate(&values)
        })
        .collect()
}

// Build the support constraint polynomials in a fixed order shared by prover and
// verifier: ternary, then per digit [eta-2 x3, lookup fraction pin], then the
// table fraction pins. The fraction pins are the logUp relation
// `(mu - value) * fraction - multiplicity = 0` (multiplicity is the implicit 1
// for a looked-up carry).
fn support_constraints<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    digit_count: usize,
    base_columns: &[Vec<[u64; LIMB_COUNT]>],
    aux_columns: &[Vec<[u64; LIMB_COUNT]>],
    table_polynomials: &[Vec<[u64; LIMB_COUNT]>],
    challenge: &[u64; LIMB_COUNT],
) -> Vec<Vec<[u64; LIMB_COUNT]>> {
    let one = vec![parameters.one()];
    let four = vec![parameters.unsigned_word_to_element(4)];
    let shift = parameters.unsigned_word_to_element((ring_degree + 1) as u64);
    let challenge_minus_shift = vec![parameters.subtract(challenge, &shift)];
    let challenge_constant = vec![*challenge];
    let secret = &base_columns[COLUMN_SECRET];
    let secret_square = &base_columns[COLUMN_SECRET_SQUARE];

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
        let error = &base_columns[digit_column(digit, DIGIT_ERROR)];
        let carry = &base_columns[digit_column(digit, DIGIT_CARRY)];
        let error_square = &base_columns[digit_column(digit, DIGIT_ERROR_SQUARE)];
        let error_support = &base_columns[digit_column(digit, DIGIT_ERROR_SUPPORT)];
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
        // lookup fraction pin: (mu - shift - C) * f - 1 = 0.
        let fraction = &aux_columns[aux_lookup_column(digit)];
        let denominator = polynomial::subtract(parameters, &challenge_minus_shift, carry);
        constraints.push(polynomial::subtract(
            parameters,
            &polynomial::multiply_via_ntt(parameters, &denominator, fraction),
            &one,
        ));
    }
    // Table fraction pins: (mu - T_k) * f_T_k - m_k = 0.
    for (table_index, table_polynomial) in table_polynomials.iter().enumerate() {
        let fraction = &aux_columns[aux_table_fraction_column(digit_count, table_index)];
        let multiplicity = &base_columns[base_multiplicity_column(digit_count, table_index)];
        let denominator = polynomial::subtract(parameters, &challenge_constant, table_polynomial);
        constraints.push(polynomial::subtract(
            parameters,
            &polynomial::multiply_via_ntt(parameters, &denominator, fraction),
            multiplicity,
        ));
    }
    constraints
}

// The support constraint value at one coset point, from opened base and aux
// values, the public table values evaluated at the point, and the logUp
// challenge. The constraint order matches `support_constraints`.
#[allow(clippy::too_many_arguments)]
fn support_value_at<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    digit_count: usize,
    base_values: &[[u64; LIMB_COUNT]],
    aux_values: &[[u64; LIMB_COUNT]],
    table_values_at_point: &[[u64; LIMB_COUNT]],
    challenge: &[u64; LIMB_COUNT],
    alpha: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let one = parameters.one();
    let four = parameters.unsigned_word_to_element(4);
    let shift = parameters.unsigned_word_to_element((ring_degree + 1) as u64);
    let challenge_minus_shift = parameters.subtract(challenge, &shift);
    let secret = base_values[COLUMN_SECRET];
    let secret_square = base_values[COLUMN_SECRET_SQUARE];

    let mut constraints = Vec::with_capacity(support_constraint_count(ring_degree, digit_count));
    constraints.push(parameters.subtract(&secret_square, &parameters.multiply(&secret, &secret)));
    constraints.push(parameters.multiply(&secret, &parameters.subtract(&secret_square, &one)));
    for digit in 0..digit_count {
        let error = base_values[digit_column(digit, DIGIT_ERROR)];
        let carry = base_values[digit_column(digit, DIGIT_CARRY)];
        let error_square = base_values[digit_column(digit, DIGIT_ERROR_SQUARE)];
        let error_support = base_values[digit_column(digit, DIGIT_ERROR_SUPPORT)];
        constraints.push(parameters.subtract(&error_square, &parameters.multiply(&error, &error)));
        let support_product = parameters.multiply(
            &parameters.subtract(&error_square, &one),
            &parameters.subtract(&error_square, &four),
        );
        constraints.push(parameters.subtract(&error_support, &support_product));
        constraints.push(parameters.multiply(&error, &error_support));
        // lookup fraction pin: (mu - shift - C) * f - 1.
        let fraction = aux_values[aux_lookup_column(digit)];
        let denominator = parameters.subtract(&challenge_minus_shift, &carry);
        constraints.push(parameters.subtract(&parameters.multiply(&denominator, &fraction), &one));
    }
    for (table_index, table_value) in table_values_at_point.iter().enumerate() {
        let fraction = aux_values[aux_table_fraction_column(digit_count, table_index)];
        let multiplicity = base_values[base_multiplicity_column(digit_count, table_index)];
        let denominator = parameters.subtract(challenge, table_value);
        constraints.push(parameters.subtract(
            &parameters.multiply(&denominator, &fraction),
            &multiplicity,
        ));
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
    aux_values: &[[u64; LIMB_COUNT]],
    quotient_values: &[[u64; LIMB_COUNT]],
    weights: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let mut value = parameters.zero();
    for (weight, column_value) in weights.iter().zip(
        base_values
            .iter()
            .chain(aux_values.iter())
            .chain(quotient_values.iter()),
    ) {
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

    let table_count = carry_range_lookup::table_count(ring_degree);

    // Round 1: witness columns plus the carry-range multiplicity columns.
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
    let lookup_challenge = transcript.challenge_field_elements(parameters, "key-lookup-mu", 1);
    let mu = lookup_challenge[0];

    // Round 2: the logUp fraction columns, which depend on `mu`. The lookup and
    // table terminals are computed here and bound into the transcript.
    let multiplicity_values = carry_multiplicity_values(parameters, ring_degree, digits);
    let aux = build_aux_columns(
        parameters,
        &trace_domain,
        ring_degree,
        digits,
        &multiplicity_values,
        &mu,
        proof_parameters.mask_degree,
        salt_seed,
    )?;
    let aux_codewords = aux
        .coefficients
        .iter()
        .map(|c| coset_evaluate_coefficients(&coset_domain, &offset, c))
        .collect::<Vec<_>>();
    let aux_commitment = ColumnCommitment::commit(aux_codewords, salt_seed)?;
    transcript.absorb_digest("key-aux-root", &aux_commitment.root());
    transcript.absorb_field_elements("key-lookup-terminal", &[aux.lookup_terminal]);
    transcript.absorb_field_elements("key-table-terminals", &aux.table_terminals);

    // Batching challenges: one for the lookup terminal, one per table terminal,
    // folded into the single sumcheck; and the support-constraint weights.
    let sum_batch =
        transcript.challenge_field_elements(parameters, "key-sum-batch", 1 + table_count);
    let alpha = transcript.challenge_field_elements(
        parameters,
        "key-support-alpha",
        support_constraint_count(ring_degree, digit_count),
    );

    let forms = combined_forms(
        parameters,
        &negacyclic,
        ring_degree,
        public,
        source,
        &gamma,
        &delta,
    );

    // Sumcheck: f = Ls*S + sum_j (Le_j*E_j + Lc_j*C_j) plus the batched logUp
    // fraction sums, whose target folds in the committed terminals.
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
                &base_coefficients[digit_column(digit, DIGIT_ERROR)],
            ),
        );
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::multiply_via_ntt(
                parameters,
                &lc,
                &base_coefficients[digit_column(digit, DIGIT_CARRY)],
            ),
        );
    }
    let lookup_weight = sum_batch[0];
    for digit in 0..digit_count {
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::scale(
                parameters,
                &aux.coefficients[aux_lookup_column(digit)],
                &lookup_weight,
            ),
        );
    }
    for table_index in 0..table_count {
        f = polynomial::add(
            parameters,
            &f,
            &polynomial::scale(
                parameters,
                &aux.coefficients[aux_table_fraction_column(digit_count, table_index)],
                &sum_batch[1 + table_index],
            ),
        );
    }
    let mut target = parameters.add(
        &forms.target,
        &parameters.multiply(&lookup_weight, &aux.lookup_terminal),
    );
    for table_index in 0..table_count {
        target = parameters.add(
            &target,
            &parameters.multiply(&sum_batch[1 + table_index], &aux.table_terminals[table_index]),
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

    // Support: V = sum alpha_i constraint_i, vanishing on H (ternary, eta-2, and
    // the logUp fraction pins).
    let table_polynomials = table_value_polynomials(parameters, &trace_domain, ring_degree);
    let constraints = support_constraints(
        parameters,
        ring_degree,
        digit_count,
        &base_coefficients,
        &aux.coefficients,
        &table_polynomials,
        &mu,
    );
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

    // Round 3: quotients.
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
    let aux_count = aux_commitment.column_count();
    let weights = transcript.challenge_field_elements(
        parameters,
        "key-combination",
        base_count + aux_count + QUOTIENT_COLUMN_COUNT,
    );

    // Combination codeword: weighted sum of every committed column's codeword,
    // across all three commitment rounds.
    let mut combination = vec![parameters.zero(); layout.coset_size];
    let mut weight_index = 0;
    for column in 0..base_count {
        let weight = weights[weight_index];
        weight_index += 1;
        for (slot, index) in combination.iter_mut().zip(0..layout.coset_size) {
            *slot = parameters.add(
                slot,
                &parameters.multiply(&weight, &base_commitment.value(column, index)),
            );
        }
    }
    for column in 0..aux_count {
        let weight = weights[weight_index];
        weight_index += 1;
        for (slot, index) in combination.iter_mut().zip(0..layout.coset_size) {
            *slot = parameters.add(
                slot,
                &parameters.multiply(&weight, &aux_commitment.value(column, index)),
            );
        }
    }
    for (quotient, codeword) in quotient_codewords.iter().enumerate() {
        let weight = weights[base_count + aux_count + quotient];
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
    let aux_opening = aux_commitment.open(&open_indices);
    let quotient_opening = quotient_commitment.open(&open_indices);

    Ok(KeyFriProof {
        base_root: base_commitment.root(),
        aux_root: aux_commitment.root(),
        quotient_root: quotient_commitment.root(),
        fri,
        base_opening,
        aux_opening,
        quotient_opening,
        lookup_terminal: aux.lookup_terminal,
        table_terminals: aux.table_terminals,
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
    let table_count = carry_range_lookup::table_count(ring_degree);
    let base_count = base_column_count(ring_degree, digit_count);
    let aux_count = aux_column_count(ring_degree, digit_count);

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
    absorb_public(&mut transcript, ring_degree, public, source);
    transcript.absorb_digest("key-base-root", &proof.base_root);
    let gamma = transcript.challenge_field_elements(parameters, "key-gamma", ring_degree);
    let delta = transcript.challenge_field_elements(parameters, "key-delta", digit_count);
    let lookup_challenge = transcript.challenge_field_elements(parameters, "key-lookup-mu", 1);
    let mu = lookup_challenge[0];

    transcript.absorb_digest("key-aux-root", &proof.aux_root);
    transcript.absorb_field_elements("key-lookup-terminal", &[proof.lookup_terminal]);
    transcript.absorb_field_elements("key-table-terminals", &proof.table_terminals);
    let sum_batch =
        transcript.challenge_field_elements(parameters, "key-sum-batch", 1 + table_count);
    let alpha = transcript.challenge_field_elements(
        parameters,
        "key-support-alpha",
        support_constraint_count(ring_degree, digit_count),
    );

    let forms = combined_forms(
        parameters,
        &negacyclic,
        ring_degree,
        public,
        source,
        &gamma,
        &delta,
    );

    transcript.absorb_digest("key-quotient-root", &proof.quotient_root);
    let weights = transcript.challenge_field_elements(
        parameters,
        "key-combination",
        base_count + aux_count + QUOTIENT_COLUMN_COUNT,
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

    // Public linear-form polynomials over H, plus the public table value
    // polynomials for the fraction-pin support constraints.
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
    let table_polynomials = table_value_polynomials(parameters, &trace_domain, ring_degree);
    let size_inverse =
        parameters.inverse(&parameters.unsigned_word_to_element(layout.trace_size as u64));
    // Combined sumcheck target: the atom target plus the batched logUp terminals.
    let mut target = parameters.add(
        &forms.target,
        &parameters.multiply(&sum_batch[0], &proof.lookup_terminal),
    );
    for table_index in 0..table_count {
        target = parameters.add(
            &target,
            &parameters.multiply(&sum_batch[1 + table_index], &proof.table_terminals[table_index]),
        );
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
            let Some(aux_values) = aux_rows.get(&index) else {
                return Ok(false);
            };
            let Some(quotient_values) = quotient_rows.get(&index) else {
                return Ok(false);
            };
            if combination_at(parameters, base_values, aux_values, quotient_values, &weights)
                != expected
            {
                return Ok(false);
            }
            let x = parameters.multiply(&offset, &coset_domain.point(index));
            let vanishing_x = polynomial::vanishing_at(parameters, &x, layout.trace_size);

            // Sumcheck: f(x) = target/m + x g(x) + Z_H(x) q_sc(x), where f folds
            // in the batched logUp fraction columns.
            let mut f_x = parameters.multiply(
                &polynomial::evaluate(parameters, &ls, &x),
                &base_values[COLUMN_SECRET],
            );
            for digit in 0..digit_count {
                let le_x = polynomial::evaluate(parameters, &le_by_digit[digit], &x);
                let lc_x = polynomial::evaluate(parameters, &lc_by_digit[digit], &x);
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(&le_x, &base_values[digit_column(digit, DIGIT_ERROR)]),
                );
                f_x = parameters.add(
                    &f_x,
                    &parameters.multiply(&lc_x, &base_values[digit_column(digit, DIGIT_CARRY)]),
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
            let table_values_at_point: Vec<[u64; LIMB_COUNT]> = table_polynomials
                .iter()
                .map(|table_polynomial| polynomial::evaluate(parameters, table_polynomial, &x))
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
            );
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
        // A carry outside `|c| <= N+1`, with the component rebuilt so the
        // congruence still holds: the shifted carry is not a value in the logUp
        // range table, so its lookup fraction has no matching table term and the
        // multiset balance (the sumcheck-bound terminals plus their cross-check)
        // fails, so the prover or verifier rejects. This guards the carry range
        // against silently admitting a carry large enough to break the field
        // no-wrap exactness bound - the exact failure the reverted base-4
        // decomposition had.
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

    #[test]
    fn tampered_lookup_terminal_is_rejected() {
        // The lookup terminal is bound to the committed fraction columns by the
        // batched sumcheck and cross-checked against the table terminals. Any
        // change (the verifier also re-absorbs it into the transcript) breaks
        // acceptance.
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, digits, public) = synthetic_key(ring_degree, 4);
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0xc0ffee;
        let mut proof = prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        proof.lookup_terminal = parameters.add(&proof.lookup_terminal, &parameters.one());
        assert!(
            !verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
                .expect("verify"),
            "a tampered lookup terminal must not verify"
        );
    }

    #[test]
    fn tampered_table_terminal_is_rejected() {
        // Tampering one table terminal breaks the lookup/table cross-check and
        // the sumcheck binding.
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let (secret, digits, public) = synthetic_key(ring_degree, 4);
        let proof_parameters = KeyFriProofParameters {
            query_count: 40,
            mask_degree: 0,
        };
        let mut salt_seed = 0xbadf00d;
        let mut proof = prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        proof.table_terminals[0] = parameters.add(&proof.table_terminals[0], &parameters.one());
        assert!(
            !verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
                .expect("verify"),
            "a tampered table terminal must not verify"
        );
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
