//! Same-secret linkage block: binds the key proof's committed secret `S` to one
//! verified same-secret bridge target constant commitment (the compact
//! VssPublic family), natively in `F_p`.
//!
//! The bridge (verified separately, fail-closed at the package layer) proves
//! all its target constant commitments open to one short secret across the
//! Q_share limbs. This block opens ONE of those commitments against the key
//! relation secret, which suffices: commitment binding forces the opened digit
//! columns to equal the bridge's, so `s + neg*q = s* + neg**q` over the
//! integers with both secrets ternary and both indicators binary, giving
//! `s = s*` exactly.
//!
//! Hosted relations, all inside the key proof's existing machinery:
//!
//! - For every commitment modulus `q_c` (three) and output coordinate `o`
//!   (sixteen), the LIVE sampler's coordinate equation lifted to the integers:
//!   `sum_d <row_{c,o,d}, D_d> + sum_r <row_{c,o,r}, R_r> - t_{c,o}
//!    = q_c * carry_{c,o}`, with `D_d` the two base-3^17 message digit columns,
//!   `R_r` the two signed ternary randomness columns (their canonical-residue
//!   lift folds into the carry), and the rows produced by the SAME
//!   `projection_terms` sampler the commitment verification uses - the matrix
//!   is never re-implemented. The 48 scalar claims batch into the existing
//!   univariate sumcheck with one challenge weight each; the carries live in
//!   one committed column (one slot per claim) reached through public
//!   indicator forms.
//! - Message consistency (vanishing on `H`): `D_0 + 3^17 D_1 - S - q*NEG = 0`,
//!   tying the digit columns to the SAME committed secret column the key
//!   congruences use, with `NEG` the binary negative indicator
//!   (`message = s mod q`, canonically lifted).
//! - Support: `NEG` binary; randomness ternary via the shared `[0, 2N+2]`
//!   logUp table (shifted `r + 1 in {0,1,2}`); digit and carry magnitudes via
//!   base-`B` chunk decompositions whose chunks feed the same shared table
//!   (`B = 2^floor(log2(2N+2))`). Chunked range checks bound magnitudes up to a
//!   factor-two slack over the canonical encodings; the recorded commitment
//!   estimator run covers the slacked bound with wide margin, and the `F_p`
//!   no-wrap margin is astronomically larger.

use super::*;
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::vss_commitment::{
    ProjectionTermsInput, VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES,
    VSS_PUBLIC_MESSAGE_DIGIT_BASE, VSS_PUBLIC_MESSAGE_DIGIT_COUNT,
    VSS_PUBLIC_OUTPUT_COORDINATE_COUNT, VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT, projection_terms,
    vss_public_canonical_message_digit_columns, vss_public_message_coverage_terms_per_coordinate,
    vss_public_message_digit_column_label, vss_public_randomness_column_label,
};

// The public linkage statement: which bridge target constant commitment the
// secret is bound to, and its full coordinate set. The caller (the schedule
// layer) is responsible for having verified the bridge and for binding the
// commitment root into the statement context; this block proves the opening
// relation against the coordinates.
pub(in super::super) struct LinkageStatement<'a> {
    pub(in super::super) public_matrix_seed_hash: &'a str,
    pub(in super::super) source_rns_limb_index: usize,
    pub(in super::super) source_message_modulus: u64,
    // coordinates_by_commitment_modulus[c][o], `c` indexing the commitment
    // modulus list, `o` the output coordinate.
    pub(in super::super) coordinates_by_commitment_modulus: &'a [Vec<u64>],
}

// The private linkage witness: the binary negative indicator of the secret and
// the commitment's two ternary opening randomness columns. The message digit
// columns are derived from the secret and the indicator.
pub(in super::super) struct LinkageWitness<'a> {
    pub(in super::super) negative_indicator: &'a [i64],
    pub(in super::super) randomness_by_column: &'a [Vec<i64>],
}

fn invalid_linkage(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// The committed linkage carry is shifted by this amount so it is non-negative:
// the signed randomness columns can pull one coordinate's integer numerator
// down by at most `2 * 32 * q_c` (two sparse weight-32 rows of residues times
// ternary values) plus the subtracted coordinate `t < q_c`, so the true carry
// is bounded below by `-65` and the shift covers it with margin.
pub(super) const LINKAGE_CARRY_SHIFT: i128 = 128;

// The chunk bit width for range decompositions: the largest power of two whose
// values stay inside the shared `[0, 2N+2]` lookup table.
pub(super) fn chunk_bits(ring_degree: usize) -> usize {
    let table_maximum = carry_range_lookup::max_shifted_value(ring_degree) as u64;
    (63 - table_maximum.leading_zeros() as usize).max(1)
}

// The linkage claim count: one scalar congruence per (commitment modulus,
// output coordinate).
pub(super) fn linkage_claim_count() -> usize {
    VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES.len() * VSS_PUBLIC_OUTPUT_COORDINATE_COUNT
}

// The commitment moduli (three data primes by profile).
pub(super) fn commitment_moduli() -> Vec<u64> {
    VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|index| DATA_PRIMES[*index])
        .collect()
}

// Chunk counts for the digit and carry range decompositions, derived from the
// ring degree and the (public) sampler shape so prover and verifier agree.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in super::super) struct LinkageLayout {
    pub(super) digit_chunk_count: usize,
    pub(super) carry_chunk_count: usize,
}

pub(in super::super) fn linkage_layout(ring_degree: usize) -> CanonicalResult<LinkageLayout> {
    if linkage_claim_count() > ring_degree {
        return Err(invalid_linkage(
            "linkage claim count exceeds the trace domain",
        ));
    }
    let bits = chunk_bits(ring_degree);
    // Digits are below 3^17 < 2^27.
    let digit_chunk_count = 27_usize.div_ceil(bits);
    // Carry magnitude bound (see the module doc): the digit rows contribute at
    // most `2 * coverage_terms * (3^17 - 1)` after division by `q_c`, and the
    // signed-randomness canonical lift contributes the sampled row residues
    // (below `64 * q_c` before division). A generous fixed margin keeps both
    // sides on one public bound.
    let coverage_terms = vss_public_message_coverage_terms_per_coordinate(ring_degree)?;
    let digit_part = 2u128 * coverage_terms as u128 * (VSS_PUBLIC_MESSAGE_DIGIT_BASE as u128 - 1);
    let carry_bound = digit_part + 2 * 64 + 2;
    let carry_bits = 128 - carry_bound.leading_zeros() as usize + 6;
    let carry_chunk_count = carry_bits.div_ceil(bits);
    Ok(LinkageLayout {
        digit_chunk_count,
        carry_chunk_count,
    })
}

// Base linkage column count: NEG, two digit columns, their chunks, two
// randomness columns, the carry column, and its chunks.
pub(in super::super) fn linkage_base_column_count(layout: &LinkageLayout) -> usize {
    1 + VSS_PUBLIC_MESSAGE_DIGIT_COUNT * (1 + layout.digit_chunk_count)
        + VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT
        + 1
        + layout.carry_chunk_count
}

// Aux linkage fraction column count: one per looked-up column (digit chunks,
// shifted randomness, carry chunks).
pub(in super::super) fn linkage_aux_column_count(layout: &LinkageLayout) -> usize {
    VSS_PUBLIC_MESSAGE_DIGIT_COUNT * layout.digit_chunk_count
        + VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT
        + layout.carry_chunk_count
}

// Support constraints this block appends: NEG binary, message consistency, one
// reconstruction per digit, one carry reconstruction, and the fraction pins.
pub(in super::super) fn linkage_support_constraint_count(layout: &LinkageLayout) -> usize {
    1 + 1 + VSS_PUBLIC_MESSAGE_DIGIT_COUNT + 1 + linkage_aux_column_count(layout)
}

// Offsets inside the base linkage block, in committed order.
pub(super) const LINK_NEG: usize = 0;
pub(super) fn link_digit(digit_index: usize) -> usize {
    1 + digit_index
}
pub(super) fn link_digit_chunk(layout: &LinkageLayout, digit_index: usize, chunk: usize) -> usize {
    1 + VSS_PUBLIC_MESSAGE_DIGIT_COUNT + digit_index * layout.digit_chunk_count + chunk
}
pub(super) fn link_randomness(layout: &LinkageLayout, column: usize) -> usize {
    1 + VSS_PUBLIC_MESSAGE_DIGIT_COUNT * (1 + layout.digit_chunk_count) + column
}
pub(super) fn link_carry(layout: &LinkageLayout) -> usize {
    link_randomness(layout, VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT)
}
pub(super) fn link_carry_chunk(layout: &LinkageLayout, chunk: usize) -> usize {
    link_carry(layout) + 1 + chunk
}

// The derived linkage witness value columns, all length `ring_degree`
// (claim-indexed columns are zero-padded past the claim count). Small enough to
// retain in the plan (raw values, never coset codewords).
pub(in super::super) struct LinkageWitnessValues {
    pub(super) negative_indicator: Vec<i64>,
    pub(super) digit_columns: Vec<Vec<u64>>,
    pub(super) digit_chunks: Vec<Vec<Vec<u64>>>,
    pub(super) randomness: Vec<Vec<i64>>,
    pub(super) carries: Vec<u64>,
    pub(super) carry_chunks: Vec<Vec<u64>>,
}

// Every value this block feeds the shared range lookup (for the multiplicity
// columns): digit chunks, shifted randomness, carry chunks - every position,
// padding zeros included (zero is a table value).
pub(in super::super) fn linkage_lookup_values(values: &LinkageWitnessValues) -> Vec<usize> {
    let mut looked_up = Vec::new();
    for digit_chunks in &values.digit_chunks {
        for chunk_column in digit_chunks {
            looked_up.extend(chunk_column.iter().map(|value| *value as usize));
        }
    }
    for randomness_column in &values.randomness {
        looked_up.extend(randomness_column.iter().map(|value| (value + 1) as usize));
    }
    for chunk_column in &values.carry_chunks {
        looked_up.extend(chunk_column.iter().map(|value| *value as usize));
    }
    looked_up
}

// Build the derived witness values from the statement, the secret, and the
// linkage witness, verifying every hosted relation as it goes (the opening
// equations against the LIVE sampler, the canonical message encoding, and the
// range bounds); a violation means the supplied witness does not open the
// commitment and the prover refuses.
pub(in super::super) fn build_linkage_witness_values(
    statement: &LinkageStatement<'_>,
    witness: &LinkageWitness<'_>,
    secret: &[i64],
    ring_degree: usize,
    layout: &LinkageLayout,
) -> CanonicalResult<LinkageWitnessValues> {
    if witness.negative_indicator.len() != ring_degree {
        return Err(invalid_linkage(
            "linkage negative indicator length must match the ring degree",
        ));
    }
    if witness.randomness_by_column.len() != VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT
        || witness
            .randomness_by_column
            .iter()
            .any(|column| column.len() != ring_degree)
    {
        return Err(invalid_linkage(
            "linkage randomness columns must match the profile shape",
        ));
    }
    if statement.coordinates_by_commitment_modulus.len()
        != VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES.len()
        || statement
            .coordinates_by_commitment_modulus
            .iter()
            .any(|coordinates| coordinates.len() != VSS_PUBLIC_OUTPUT_COORDINATE_COUNT)
    {
        return Err(invalid_linkage(
            "linkage coordinates must cover every commitment modulus and output coordinate",
        ));
    }
    for (indicator, secret_value) in witness.negative_indicator.iter().zip(secret.iter()) {
        let expected = i64::from(*secret_value < 0);
        if *indicator != expected {
            return Err(invalid_linkage(
                "linkage negative indicator does not match the secret's signs",
            ));
        }
    }
    for column in witness.randomness_by_column {
        if column.iter().any(|value| value.unsigned_abs() > 1) {
            return Err(invalid_linkage("linkage randomness must be ternary"));
        }
    }

    // The canonical message and its digit columns, via the live encoder.
    let modulus = statement.source_message_modulus;
    let message: Vec<u64> = secret
        .iter()
        .map(|value| (*value as i128).rem_euclid(modulus as i128) as u64)
        .collect();
    let digit_columns = vss_public_canonical_message_digit_columns(&message, ring_degree)?;

    let bits = chunk_bits(ring_degree);
    let chunk_mask = (1u64 << bits) - 1;
    let chunk_columns = |values: &[u64], chunk_count: usize| -> Vec<Vec<u64>> {
        (0..chunk_count)
            .map(|chunk| {
                values
                    .iter()
                    .map(|value| (value >> (bits * chunk)) & chunk_mask)
                    .collect()
            })
            .collect()
    };
    let digit_chunks: Vec<Vec<Vec<u64>>> = digit_columns
        .iter()
        .map(|column| chunk_columns(column, layout.digit_chunk_count))
        .collect();
    for (digit_column, chunks) in digit_columns.iter().zip(digit_chunks.iter()) {
        for (position, value) in digit_column.iter().enumerate() {
            let mut reconstructed = 0u64;
            for (chunk_index, chunk_column) in chunks.iter().enumerate() {
                reconstructed += chunk_column[position] << (bits * chunk_index);
            }
            if reconstructed != *value {
                return Err(invalid_linkage(
                    "linkage digit chunk decomposition does not reconstruct",
                ));
            }
        }
    }

    // The carries, one per (commitment modulus, output coordinate), from the
    // LIVE sampler rows.
    let moduli = commitment_moduli();
    let mut carries = vec![0u64; ring_degree];
    for (modulus_position, commitment_modulus) in moduli.iter().enumerate() {
        for coordinate in 0..VSS_PUBLIC_OUTPUT_COORDINATE_COUNT {
            let mut numerator: i128 = 0;
            for (digit_index, digit_column) in digit_columns.iter().enumerate() {
                let label = vss_public_message_digit_column_label(digit_index)?;
                let terms = projection_terms(ProjectionTermsInput {
                    public_matrix_seed_hash: statement.public_matrix_seed_hash,
                    rns_limb_index: statement.source_rns_limb_index,
                    commitment_modulus_index: modulus_position,
                    output_coordinate_index: coordinate,
                    input_column: &label,
                    ring_degree,
                    modulus: *commitment_modulus,
                })?;
                for (position, residue) in terms {
                    numerator += digit_column[position] as i128 * residue as i128;
                }
            }
            for randomness_column in 0..VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT {
                let label = vss_public_randomness_column_label(randomness_column)?;
                let terms = projection_terms(ProjectionTermsInput {
                    public_matrix_seed_hash: statement.public_matrix_seed_hash,
                    rns_limb_index: statement.source_rns_limb_index,
                    commitment_modulus_index: modulus_position,
                    output_coordinate_index: coordinate,
                    input_column: label,
                    ring_degree,
                    modulus: *commitment_modulus,
                })?;
                for (position, residue) in terms {
                    numerator += witness.randomness_by_column[randomness_column][position] as i128
                        * residue as i128;
                }
            }
            numerator -=
                statement.coordinates_by_commitment_modulus[modulus_position][coordinate] as i128;
            let modulus_wide = *commitment_modulus as i128;
            if numerator.rem_euclid(modulus_wide) != 0 {
                return Err(invalid_linkage(
                    "linkage witness does not open the commitment coordinates",
                ));
            }
            let shifted_carry = numerator / modulus_wide + LINKAGE_CARRY_SHIFT;
            if shifted_carry < 0 {
                return Err(invalid_linkage(
                    "linkage carry falls below its shifted magnitude model",
                ));
            }
            carries[modulus_position * VSS_PUBLIC_OUTPUT_COORDINATE_COUNT + coordinate] =
                u64::try_from(shifted_carry)
                    .map_err(|_| invalid_linkage("linkage carry exceeds its magnitude bound"))?;
        }
    }
    let carry_chunks = chunk_columns(&carries, layout.carry_chunk_count);
    for (position, value) in carries.iter().enumerate() {
        let mut reconstructed = 0u64;
        for (chunk_index, chunk_column) in carry_chunks.iter().enumerate() {
            reconstructed += chunk_column[position] << (bits * chunk_index);
        }
        if reconstructed != *value {
            return Err(invalid_linkage(
                "linkage carry chunk decomposition does not reconstruct",
            ));
        }
    }

    Ok(LinkageWitnessValues {
        negative_indicator: witness.negative_indicator.to_vec(),
        digit_columns,
        digit_chunks,
        randomness: witness.randomness_by_column.to_vec(),
        carries,
        carry_chunks,
    })
}

// The unmasked value column for one base linkage offset, in committed order:
// NEG, the digit columns, their chunks, the randomness columns, the carry
// column, then its chunks.
pub(super) fn linkage_base_value_column<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    layout: &LinkageLayout,
    values: &LinkageWitnessValues,
    offset: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let digit_count = VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
    let chunk_block = digit_count * layout.digit_chunk_count;
    if offset == LINK_NEG {
        return values
            .negative_indicator
            .iter()
            .map(|value| parameters.signed_word_to_element(*value))
            .collect();
    }
    if offset < 1 + digit_count {
        return values.digit_columns[offset - 1]
            .iter()
            .map(|value| parameters.unsigned_word_to_element(*value))
            .collect();
    }
    if offset < 1 + digit_count + chunk_block {
        let chunk_offset = offset - 1 - digit_count;
        let digit_index = chunk_offset / layout.digit_chunk_count;
        let chunk = chunk_offset % layout.digit_chunk_count;
        return values.digit_chunks[digit_index][chunk]
            .iter()
            .map(|value| parameters.unsigned_word_to_element(*value))
            .collect();
    }
    let randomness_start = 1 + digit_count + chunk_block;
    if offset < randomness_start + VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT {
        return values.randomness[offset - randomness_start]
            .iter()
            .map(|value| parameters.signed_word_to_element(*value))
            .collect();
    }
    let carry_offset = randomness_start + VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT;
    if offset == carry_offset {
        return values
            .carries
            .iter()
            .map(|value| parameters.unsigned_word_to_element(*value))
            .collect();
    }
    values.carry_chunks[offset - carry_offset - 1]
        .iter()
        .map(|value| parameters.unsigned_word_to_element(*value))
        .collect()
}

// The looked-up value column behind one aux linkage fraction offset (digit
// chunks, then shifted randomness, then carry chunks).
pub(super) fn linkage_lookup_value_column<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    layout: &LinkageLayout,
    values: &LinkageWitnessValues,
    offset: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let chunk_block = VSS_PUBLIC_MESSAGE_DIGIT_COUNT * layout.digit_chunk_count;
    if offset < chunk_block {
        let digit_index = offset / layout.digit_chunk_count;
        let chunk = offset % layout.digit_chunk_count;
        return values.digit_chunks[digit_index][chunk]
            .iter()
            .map(|value| parameters.unsigned_word_to_element(*value))
            .collect();
    }
    if offset < chunk_block + VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT {
        return values.randomness[offset - chunk_block]
            .iter()
            .map(|value| parameters.signed_word_to_element(value + 1))
            .collect();
    }
    values.carry_chunks[offset - chunk_block - VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT]
        .iter()
        .map(|value| parameters.unsigned_word_to_element(*value))
        .collect()
}

// The public constants the linkage support constraints need, shared by the
// prover's polynomial form and the verifier's point form.
pub(in super::super) struct LinkageConstraintContext<const LIMB_COUNT: usize> {
    pub(super) layout: LinkageLayout,
    pub(super) source_modulus_element: [u64; LIMB_COUNT],
    pub(super) digit_base_element: [u64; LIMB_COUNT],
    pub(super) chunk_base_element: [u64; LIMB_COUNT],
}

impl<const LIMB_COUNT: usize> LinkageConstraintContext<LIMB_COUNT> {
    pub(super) fn layout(&self) -> &LinkageLayout {
        &self.layout
    }
}

pub(in super::super) fn linkage_constraint_context<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    source_message_modulus: u64,
) -> CanonicalResult<LinkageConstraintContext<LIMB_COUNT>> {
    Ok(LinkageConstraintContext {
        layout: linkage_layout(ring_degree)?,
        source_modulus_element: parameters.unsigned_word_to_element(source_message_modulus),
        digit_base_element: parameters.unsigned_word_to_element(VSS_PUBLIC_MESSAGE_DIGIT_BASE),
        chunk_base_element: parameters.unsigned_word_to_element(1_u64 << chunk_bits(ring_degree)),
    })
}

// Push the linkage support constraint VALUES at one opened point, in the fixed
// order the prover's polynomial form mirrors: NEG binary, message consistency,
// digit reconstructions, carry reconstruction, then the fraction pins.
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn push_linkage_support_values<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    context: &LinkageConstraintContext<LIMB_COUNT>,
    base_values: &[[u64; LIMB_COUNT]],
    aux_values: &[[u64; LIMB_COUNT]],
    base_start: usize,
    aux_start: usize,
    secret_value: &[u64; LIMB_COUNT],
    challenge: &[u64; LIMB_COUNT],
    constraints: &mut Vec<[u64; LIMB_COUNT]>,
) {
    let layout = &context.layout;
    let one = parameters.one();
    let negative_indicator = base_values[base_start + LINK_NEG];
    // NEG binary.
    constraints.push(parameters.multiply(
        &negative_indicator,
        &parameters.subtract(&negative_indicator, &one),
    ));
    // Message consistency: D0 + base*D1 - S - q*NEG.
    let mut message = base_values[base_start + link_digit(0)];
    message = parameters.add(
        &message,
        &parameters.multiply(
            &context.digit_base_element,
            &base_values[base_start + link_digit(1)],
        ),
    );
    message = parameters.subtract(&message, secret_value);
    message = parameters.subtract(
        &message,
        &parameters.multiply(&context.source_modulus_element, &negative_indicator),
    );
    constraints.push(message);
    // Digit reconstructions.
    for digit_index in 0..VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
        let mut reconstruction = base_values[base_start + link_digit(digit_index)];
        let mut power = one;
        for chunk in 0..layout.digit_chunk_count {
            reconstruction = parameters.subtract(
                &reconstruction,
                &parameters.multiply(
                    &power,
                    &base_values[base_start + link_digit_chunk(layout, digit_index, chunk)],
                ),
            );
            power = parameters.multiply(&power, &context.chunk_base_element);
        }
        constraints.push(reconstruction);
    }
    // Carry reconstruction.
    let mut carry_reconstruction = base_values[base_start + link_carry(layout)];
    let mut power = one;
    for chunk in 0..layout.carry_chunk_count {
        carry_reconstruction = parameters.subtract(
            &carry_reconstruction,
            &parameters.multiply(
                &power,
                &base_values[base_start + link_carry_chunk(layout, chunk)],
            ),
        );
        power = parameters.multiply(&power, &context.chunk_base_element);
    }
    constraints.push(carry_reconstruction);
    // Fraction pins: (mu - value) * f - 1 (shifted randomness subtracts one
    // more from the challenge, since the looked-up value is r + 1).
    for offset in 0..linkage_aux_column_count(layout) {
        let fraction = aux_values[aux_start + offset];
        let value = linkage_pin_value(parameters, layout, base_values, base_start, offset);
        let denominator = parameters.subtract(challenge, &value);
        constraints.push(parameters.subtract(&parameters.multiply(&denominator, &fraction), &one));
    }
}

// The committed value one aux linkage fraction pin runs against, expressed
// from the BASE columns at the same point (shifted randomness adds one).
fn linkage_pin_value<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    layout: &LinkageLayout,
    base_values: &[[u64; LIMB_COUNT]],
    base_start: usize,
    offset: usize,
) -> [u64; LIMB_COUNT] {
    let chunk_block = VSS_PUBLIC_MESSAGE_DIGIT_COUNT * layout.digit_chunk_count;
    if offset < chunk_block {
        let digit_index = offset / layout.digit_chunk_count;
        let chunk = offset % layout.digit_chunk_count;
        return base_values[base_start + link_digit_chunk(layout, digit_index, chunk)];
    }
    if offset < chunk_block + VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT {
        let randomness = base_values[base_start + link_randomness(layout, offset - chunk_block)];
        return parameters.add(&randomness, &parameters.one());
    }
    base_values[base_start
        + link_carry_chunk(
            layout,
            offset - chunk_block - VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
        )]
}

// The public linkage forms: for each linkage witness column consumed by the
// batched sumcheck (two digit columns, two randomness columns, the carry
// column), the challenge-weighted public vector over the trace domain, plus the
// batched target. Both sides derive the rows from the LIVE sampler.
pub(in super::super) struct LinkageForms<const LIMB_COUNT: usize> {
    pub(super) digit_forms: Vec<Vec<[u64; LIMB_COUNT]>>,
    pub(super) randomness_forms: Vec<Vec<[u64; LIMB_COUNT]>>,
    pub(super) carry_form: Vec<[u64; LIMB_COUNT]>,
    pub(super) target: [u64; LIMB_COUNT],
}

pub(in super::super) fn build_linkage_forms<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    statement: &LinkageStatement<'_>,
    ring_degree: usize,
    weights: &[[u64; LIMB_COUNT]],
) -> CanonicalResult<LinkageForms<LIMB_COUNT>> {
    if weights.len() != linkage_claim_count() {
        return Err(invalid_linkage(
            "linkage weight count must match the claim count",
        ));
    }
    let moduli = commitment_moduli();
    let mut digit_forms =
        vec![vec![parameters.zero(); ring_degree]; VSS_PUBLIC_MESSAGE_DIGIT_COUNT];
    let mut randomness_forms =
        vec![vec![parameters.zero(); ring_degree]; VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT];
    let mut carry_form = vec![parameters.zero(); ring_degree];
    let mut target = parameters.zero();

    for (modulus_position, commitment_modulus) in moduli.iter().enumerate() {
        let modulus_element = parameters.unsigned_word_to_element(*commitment_modulus);
        for coordinate in 0..VSS_PUBLIC_OUTPUT_COORDINATE_COUNT {
            let claim = modulus_position * VSS_PUBLIC_OUTPUT_COORDINATE_COUNT + coordinate;
            let weight = weights[claim];
            for (digit_index, digit_form) in digit_forms.iter_mut().enumerate() {
                let label = vss_public_message_digit_column_label(digit_index)?;
                let terms = projection_terms(ProjectionTermsInput {
                    public_matrix_seed_hash: statement.public_matrix_seed_hash,
                    rns_limb_index: statement.source_rns_limb_index,
                    commitment_modulus_index: modulus_position,
                    output_coordinate_index: coordinate,
                    input_column: &label,
                    ring_degree,
                    modulus: *commitment_modulus,
                })?;
                for (position, residue) in terms {
                    let contribution =
                        parameters.multiply(&weight, &parameters.unsigned_word_to_element(residue));
                    digit_form[position] = parameters.add(&digit_form[position], &contribution);
                }
            }
            for (randomness_column, randomness_form) in randomness_forms.iter_mut().enumerate() {
                let label = vss_public_randomness_column_label(randomness_column)?;
                let terms = projection_terms(ProjectionTermsInput {
                    public_matrix_seed_hash: statement.public_matrix_seed_hash,
                    rns_limb_index: statement.source_rns_limb_index,
                    commitment_modulus_index: modulus_position,
                    output_coordinate_index: coordinate,
                    input_column: label,
                    ring_degree,
                    modulus: *commitment_modulus,
                })?;
                for (position, residue) in terms {
                    let contribution =
                        parameters.multiply(&weight, &parameters.unsigned_word_to_element(residue));
                    randomness_form[position] =
                        parameters.add(&randomness_form[position], &contribution);
                }
            }
            // Carry slot: `- q_c * shifted_carry` at the claim's packed
            // position (the committed carry is shifted by LINKAGE_CARRY_SHIFT).
            let negated = parameters.negate(&parameters.multiply(&weight, &modulus_element));
            carry_form[claim] = parameters.add(&carry_form[claim], &negated);
            // Target: the public coordinate, minus the shift's contribution
            // (`<row, cols> - q_c*(sc - SHIFT) = t` becomes
            // `<row, cols> - q_c*sc = t - q_c*SHIFT`).
            let coordinate_element = parameters.unsigned_word_to_element(
                statement.coordinates_by_commitment_modulus[modulus_position][coordinate],
            );
            let shift_offset = parameters.multiply(
                &modulus_element,
                &parameters.unsigned_word_to_element(LINKAGE_CARRY_SHIFT as u64),
            );
            let adjusted = parameters.subtract(&coordinate_element, &shift_offset);
            target = parameters.add(&target, &parameters.multiply(&weight, &adjusted));
        }
    }

    Ok(LinkageForms {
        digit_forms,
        randomness_forms,
        carry_form,
        target,
    })
}

// Absorb the linkage statement into the transcript so a proof for one
// commitment (or seed, or limb) cannot be replayed as another.
pub(in super::super) fn absorb_linkage_statement(
    transcript: &mut Transcript,
    statement: &LinkageStatement<'_>,
) {
    transcript.absorb(
        "linkage-seed-hash",
        statement.public_matrix_seed_hash.as_bytes(),
    );
    transcript.absorb_u64(
        "linkage-source-limb",
        statement.source_rns_limb_index as u64,
    );
    transcript.absorb_u64("linkage-source-modulus", statement.source_message_modulus);
    for coordinates in statement.coordinates_by_commitment_modulus {
        for coordinate in coordinates {
            transcript.absorb_u64("linkage-coordinate", *coordinate);
        }
    }
}
