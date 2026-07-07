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
//! family's single construction (a one-digit key is the smallest case).

#![allow(clippy::too_many_arguments)]

use super::super::negacyclic_transform::NegacyclicDomain;
use super::super::proof_field::ProofFieldParameters;
use super::atom_reduction::{AtomPublicInputs, AtomSource, reduce_atom};
use super::carry_range_lookup;
use super::column_commitment::{
    ColumnOpening, StreamedColumnCommitmentBuilder, verify_column_opening,
};
use super::domain::{CyclicDomain, coset_evaluate_coefficients, coset_offset};
use super::low_degree::{
    FriParameters, FriProof, fri_answer, fri_commit, fri_verify_queries, fri_verify_structure,
};
use super::merkle::{MerkleDigest, sorted_unique_indices};
use super::polynomial;
use super::transcript::Transcript;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

const PROTOCOL_LABEL: &str = "sealed-lattice/setup/key-switch-atom/key-v1";
const FRI_RATE_BLOWUP: usize = 4;

// The all-zero statement binding the round-one test wrappers absorb; real
// schedule proofs bind the statement hash and the key's schedule index.
#[cfg(test)]
pub(super) const ZERO_STATEMENT_BINDING: [u8; 64] = [0_u8; 64];

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
    // The MATERIAL commitment root: one masked column per digit holding the
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

// Per-digit block: error, carry, error-square, error-support. The recombined
// component material `B_j` is committed separately, in its own MATERIAL Merkle
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

// Index of the first multiplicity column (after all per-digit blocks).
fn base_multiplicity_start(digit_count: usize) -> usize {
    SHARED_COLUMN_COUNT + digit_count * DIGIT_BLOCK_SIZE
}

// Index of the first linkage base column (after the multiplicity columns).
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

// The MATERIAL commitment holds one masked column per digit: digit `d`'s column
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

// Index of the first linkage aux fraction column.
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

// Degree-adjustment shift for the univariate-sumcheck helper `g`. The sumcheck
// identity is `f(x) = target/m + x g(x) + Z_H(x) q_sc(x)`; its soundness
// (`sum_H f = target`) requires `deg(g) <= |H| - 2 = trace_size - 2`, otherwise
// the spare coefficient `g_{trace_size-1}` lets `sum_H x g(x)` be nonzero and a
// prover can certify a false sum. The combined FRI only bounds every column to
// `< 2 * trace_size`, which does not pin `g` tightly. So `g` re-enters the
// combination shifted by `x^{trace_size + 1}`: an honest `g` (degree
// `<= trace_size - 2`) reaches at most degree `2 * trace_size - 1`, still under
// the bound, while a degree-`(trace_size - 1)` `g` reaches `2 * trace_size` and
// FRI rejects. Derived from `(2 * trace_size - 1) - (trace_size - 2)`.
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

mod columns;
mod constraints;
mod linkage;
mod prove;
mod verify;

pub(super) use linkage::{LinkageLayout, LinkageStatement, LinkageWitness};
pub(super) use prove::prove_key_fri;
// The single-source material-commitment regeneration the S1/S2 aggregate binding
// reuses to open exactly the atom proof's committed material.
pub(super) use prove::regenerate_material_commitment_inputs;
#[cfg(test)]
pub(super) use prove::{prove_key_fri_with_component_b, prove_round_one_key_fri};
pub(super) use verify::verify_key_fri;
#[cfg(test)]
pub(super) use verify::verify_round_one_key_fri;

// The key-switch atom linkage layout for a ring degree. Key-bearing statements
// always carry the linkage block, so the aggregate binding uses this to compute
// the same `base_column_count` the atom prover's column plan uses. Kept as a thin
// re-export so the layout construction has one home in `linkage`.
pub(super) fn key_switch_linkage_layout(
    ring_degree: usize,
) -> crate::encoding::CanonicalResult<LinkageLayout> {
    linkage::linkage_layout(ring_degree)
}

#[cfg(test)]
mod tests;
