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
//! be replayed as another. A one-digit key uses the same layout as the general
//! case.

#![allow(clippy::too_many_arguments)]

use super::super::negacyclic_transform::NegacyclicDomain;
use super::super::proof_field::ProofFieldParameters;
use super::atom_reduction::{AtomPublicInputs, AtomSource, reduce_atom};
use super::carry_range_lookup;
#[cfg(test)]
use super::column_commitment::StreamedColumnCommitmentBuilder;
use super::column_commitment::{ColumnOpening, verify_column_opening};
#[cfg(test)]
use super::domain::coset_evaluate_coefficients;
use super::domain::{CyclicDomain, CyclicDomainGeometry, coset_offset};
#[cfg(test)]
use super::domain::{coset_evaluate_coefficients_in_place, coset_evaluate_coefficients_into};
use super::low_degree::{
    FINAL_LAYER_MAX_SIZE, FriParameters, FriProof, fri_verify_queries, fri_verify_structure,
};
#[cfg(test)]
use super::low_degree::{fri_answer, fri_commit};
use super::merkle::MerkleDigest;
#[cfg(test)]
use super::merkle::sorted_unique_indices;
use super::polynomial;
#[cfg(test)]
use super::private_randomness::PrivateProofRandomness;
use super::transcript::Transcript;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

const PROTOCOL_LABEL: &str = "sealed-lattice/setup/key-switch-atom/key";
const FRI_RATE_BLOWUP: usize = 4;

// The all-zero statement binding the round-one test wrappers absorb; real
// schedule proofs bind the statement hash and the key's schedule index.
#[cfg(test)]
pub(super) const ZERO_STATEMENT_BINDING: [u8; 64] = [0_u8; 64];

pub(super) struct KeyFriProofParameters {
    pub(crate) query_count: usize,
    #[cfg(test)]
    pub(crate) mask_degree: usize,
}

pub(super) struct KeyFriProofDecodingShape {
    pub(super) fri_layer_count: usize,
    pub(super) fri_final_coefficient_count: usize,
    pub(super) query_count: usize,
    pub(super) base_column_count: usize,
    pub(super) material_column_count: usize,
    pub(super) auxiliary_column_count: usize,
    pub(super) quotient_column_count: usize,
    pub(super) table_terminal_count: usize,
}

pub(super) fn key_fri_proof_decoding_shape(
    ring_degree: usize,
    digit_count: usize,
    linkage_present: bool,
    query_count: usize,
) -> CanonicalResult<KeyFriProofDecodingShape> {
    let layout = layout(ring_degree)?;
    let linkage_layout = linkage_present
        .then(|| linkage::linkage_layout(ring_degree))
        .transpose()?;
    let mut fri_final_coefficient_count = layout.coset_size;
    let mut fri_layer_count = 0;
    while fri_final_coefficient_count > FINAL_LAYER_MAX_SIZE {
        fri_final_coefficient_count /= 2;
        fri_layer_count += 1;
    }
    Ok(KeyFriProofDecodingShape {
        fri_layer_count,
        fri_final_coefficient_count,
        query_count,
        base_column_count: base_column_count(ring_degree, digit_count, linkage_layout.as_ref()),
        material_column_count: material_column_count(digit_count),
        auxiliary_column_count: aux_column_count(ring_degree, digit_count, linkage_layout.as_ref()),
        quotient_column_count: QUOTIENT_COLUMN_COUNT,
        table_terminal_count: carry_range_lookup::table_count(ring_degree),
    })
}

// Public data for one digit: the recombined sample and component, and the
// digit's gadget idempotent. The group modulus and plaintext modulus are shared.
pub(super) struct DigitPublic<const LIMB_COUNT: usize> {
    pub(crate) recombined_sample: Vec<[u64; LIMB_COUNT]>,
    #[cfg(test)]
    pub(crate) recombined_component_b: Vec<[u64; LIMB_COUNT]>,
    pub(crate) gadget_idempotent: [u64; LIMB_COUNT],
}

pub(super) struct KeyPublic<const LIMB_COUNT: usize> {
    pub(crate) digits: Vec<DigitPublic<LIMB_COUNT>>,
    pub(crate) group_modulus: [u64; LIMB_COUNT],
    pub(crate) plaintext_modulus: [u64; LIMB_COUNT],
}

// Per-digit witness: the error and carry vectors (the secret is shared).
#[cfg(test)]
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
    // The material commitment root: one masked column per digit holding the
    // recombined component material `B_j`, committed before `gamma` is drawn so
    // the material is fixed prior to its reduction challenge.
    pub(crate) material_root: MerkleDigest,
    pub(crate) aux_root: MerkleDigest,
    pub(crate) quotient_root: MerkleDigest,
    pub(crate) fri: FriProof<LIMB_COUNT>,
    pub(crate) base_opening: ColumnOpening<LIMB_COUNT>,
    pub(crate) material_opening: ColumnOpening<LIMB_COUNT>,
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

// Round-1 base columns: the witness (shared secret plus per-digit blocks) then
// one carry-range multiplicity column per table chunk.
const COLUMN_SECRET: usize = 0;
const COLUMN_SECRET_SQUARE: usize = 1;
const SHARED_COLUMN_COUNT: usize = 2;

// Per-digit block: error, carry, error-square, error-support. The recombined
// component material `B_j` is committed separately, in its own material Merkle
// group (one masked column per digit), not in this base block. `B_j` carries no
// support constraint of its own: it is bound only by the relation, because the
// batched sumcheck folds the committed `B_col_j` on its left-hand side (with the
// per-digit weight `delta_j * gamma`) instead of the raw public component
// material entering the sumcheck target. A committed material that does not
// equal the correct component makes `B + A(*)s - t e - G source - Q c = 0` miss,
// so the sumcheck rejects it.
const DIGIT_ERROR: usize = 0;
const DIGIT_CARRY: usize = 1;
const DIGIT_ERROR_SQUARE: usize = 2;
const DIGIT_ERROR_SUPPORT: usize = 3;
const DIGIT_BLOCK_SIZE: usize = 4;

fn base_multiplicity_start(digit_count: usize) -> usize {
    SHARED_COLUMN_COUNT + digit_count * DIGIT_BLOCK_SIZE
}

fn base_linkage_start(ring_degree: usize, digit_count: usize) -> usize {
    base_multiplicity_start(digit_count) + carry_range_lookup::table_count(ring_degree)
}

fn base_column_count(
    ring_degree: usize,
    digit_count: usize,
    linkage_layout: Option<&linkage::LinkageLayout>,
) -> usize {
    base_linkage_start(ring_degree, digit_count)
        + linkage_layout
            .map(linkage::linkage_base_column_count)
            .unwrap_or(0)
}

fn digit_column(digit: usize, offset_in_block: usize) -> usize {
    SHARED_COLUMN_COUNT + digit * DIGIT_BLOCK_SIZE + offset_in_block
}

// The material commitment holds one masked column per digit: digit `d`'s column
// is the masked coefficients of the recombined component material `B_d`,
// committed exactly like a base column. The batched sumcheck folds each column
// on its left-hand side, so the committed material is load-bearing for the
// relation and needs no separate support constraint.
fn material_column_count(digit_count: usize) -> usize {
    digit_count
}

fn base_multiplicity_column(digit_count: usize, table_index: usize) -> usize {
    base_multiplicity_start(digit_count) + table_index
}

// Round-2 auxiliary columns (challenge-dependent, committed after the logUp
// challenge is drawn): one lookup fraction column per digit, then one table
// fraction column per table chunk.
fn aux_lookup_column(digit: usize) -> usize {
    digit
}

fn aux_table_fraction_column(digit_count: usize, table_index: usize) -> usize {
    digit_count + table_index
}

fn aux_linkage_start(ring_degree: usize, digit_count: usize) -> usize {
    digit_count + carry_range_lookup::table_count(ring_degree)
}

fn aux_column_count(
    ring_degree: usize,
    digit_count: usize,
    linkage_layout: Option<&linkage::LinkageLayout>,
) -> usize {
    aux_linkage_start(ring_degree, digit_count)
        + linkage_layout
            .map(linkage::linkage_aux_column_count)
            .unwrap_or(0)
}

// Quotient columns: one sumcheck quotient, one sumcheck g, one support quotient.
// The lookup terminals ride the single sumcheck and the fraction pins ride the
// single support composition, so the quotient count is unchanged.
const QUOTIENT_SUMCHECK: usize = 0;
const QUOTIENT_G: usize = 1;
const QUOTIENT_SUPPORT: usize = 2;
const QUOTIENT_COLUMN_COUNT: usize = 3;

// The sumcheck identity requires `deg(g) <= trace_size - 2`, while combined
// FRI permits degree below `2 * trace_size`. Shifting `g` by
// `x^(trace_size + 1)` keeps an honest `g` below that bound but pushes the first
// forbidden coefficient to degree `2 * trace_size`, where FRI rejects it.
pub(super) fn g_degree_adjustment_shift(trace_size: usize) -> usize {
    trace_size + 1
}

struct Layout {
    trace_size: usize,
    coset_size: usize,
}

fn layout(ring_degree: usize) -> CanonicalResult<Layout> {
    if !ring_degree.is_power_of_two() || ring_degree < 2 {
        return Err(invalid_key("ring degree must be a power of two >= 2"));
    }
    // Committed degree bound `2m` covers the masked columns and the quadratic
    // support and fraction constraints. The coset is `FRI_RATE_BLOWUP` times
    // that bound, giving FRI rate 1/4; N = 65536 therefore runs unsplit below
    // the 2^20 domain ceiling.
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

#[cfg(test)]
mod columns;
mod constraints;
mod linkage;
#[cfg(test)]
mod prove;
mod verify;

pub(super) use linkage::LinkageStatement;
#[cfg(test)]
pub(super) use linkage::LinkageWitness;
#[cfg(test)]
pub(super) use prove::prove_key_fri_with_negacyclic_domain;
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) use prove::{begin_key_prover_phase_timing, finish_key_prover_phase_timing};
#[cfg(test)]
pub(super) use prove::{prove_key_fri, prove_key_fri_with_component_b, prove_round_one_key_fri};
pub(super) use verify::verify_key_fri_with_negacyclic_domain;
#[cfg(test)]
pub(super) use verify::{verify_key_fri, verify_round_one_key_fri};

#[cfg(test)]
mod tests;
