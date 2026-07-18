//! logUp range lookup proving every digit carry lies in `|c| <= N + 1`.
//!
//! The shifted carry `c + (N + 1)` lands in `[0, 2N + 2]`. One fraction column
//! per digit plus public table columns enforce the log-derivative identity
//! (Haboeck, eprint 2022/1530):
//!
//! ```text
//!   sum_lookups 1/(mu - v)  =  sum_table m_v/(mu - v),
//! ```
//!
//! For matching multisets the identity holds. A carry outside the table adds a
//! left-side term with no matching public table value; the verifier checks the
//! resulting balance at the transcript-derived challenge `mu`.
//!
//! ## Table split (keeps every column in the single trace domain)
//!
//! The range `[0, 2N + 2]` has `2N + 3` values, more than one size-`N` domain
//! can enumerate. It is split into `ceil((2N + 3)/N) = 3` contiguous chunks,
//! each enumerated over its own size-`N` domain:
//!
//! - table 0 holds `[0, N)`;
//! - table 1 holds `[N, 2N)`;
//! - table 2 holds `[2N, 2N + 2]` (three real values) with the remaining rows
//!   repeating the in-range padding value `2N`.
//!
//! Every table column uses the same domain `H_N` as the witness columns, so the
//! argument stays within the `8N` coset and every column is masked uniformly.
//!
//! The table value columns are public: both prover and verifier interpolate
//! them and evaluate at query points, exactly like the sumcheck linear forms.
//! Because they are public and only ever hold values in `[0, 2N + 2]`, a
//! malicious prover cannot smuggle an out-of-range value into the table (a
//! padding row's value is in range, so a nonzero padding multiplicity only
//! inflates that in-range value's count, which then fails the multiset balance
//! unless it matches real carries).
//!
//! ## Sums, not accumulators
//!
//! For a column `f` of degree `< N` (before masking) over `H_N`,
//! `sum_{x in H_N} f(x) = N * f_0` (the constant coefficient), and the
//! `Z_H`-multiple mask does not change the on-`H_N` sum. So the univariate
//! sumcheck already in the backend certifies each terminal
//! `sum_{x in H_N} f(x)` directly; no running-sum accumulator, next-row access,
//! or boundary selector is needed. The per-digit lookup fractions and the table
//! fractions are batched into the single sumcheck with independent challenges,
//! and the terminals satisfy `terminal_lookup = sum_k terminal_table_k`, checked
//! once per key.

use super::super::proof_field::ProofFieldParameters;

#[cfg(test)]
pub(super) fn carry_shift(ring_degree: usize) -> i64 {
    (ring_degree + 1) as i64
}

pub(super) fn max_shifted_value(ring_degree: usize) -> usize {
    2 * ring_degree + 2
}

pub(super) fn table_count(ring_degree: usize) -> usize {
    (max_shifted_value(ring_degree) + 1).div_ceil(ring_degree)
}

// The public value column for table chunk `table_index`, length `N`:
// `T_k[i] = k*N + i` while that is a real (in-range) table value, then the
// in-range padding value `k*N` (which is always `<= 2N + 2`) for the rest. No
// entry ever exceeds `2N + 2`, so the table can only certify in-range values.
pub(super) fn table_values<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    table_index: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let base = table_index * ring_degree;
    let max_value = max_shifted_value(ring_degree);
    (0..ring_degree)
        .map(|row| {
            let candidate = base + row;
            let value = if candidate <= max_value {
                candidate
            } else {
                base
            };
            parameters.unsigned_word_to_element(value as u64)
        })
        .collect()
}

// Count, for every table value, how many shifted carries equal it, returning one
// multiplicity column per table chunk (each length `N`, aligned to
// `table_values`). A shifted carry outside `[0, 2N + 2]` remains uncounted, so
// the multiset balance fails.
#[cfg(test)]
pub(super) fn multiplicities<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    shifted_carries: &[usize],
    ring_degree: usize,
) -> Vec<Vec<[u64; LIMB_COUNT]>> {
    let count = table_count(ring_degree);
    let max_value = max_shifted_value(ring_degree);
    let mut counts = vec![vec![0u64; ring_degree]; count];
    for &value in shifted_carries {
        if value <= max_value {
            counts[value / ring_degree][value % ring_degree] += 1;
        }
    }
    counts
        .into_iter()
        .map(|table| {
            table
                .into_iter()
                .map(|c| parameters.unsigned_word_to_element(c))
                .collect()
        })
        .collect()
}

// The reciprocal `1/(mu - value)` for one field value. `mu` is drawn from the
// transcript after the witness and table multiplicities are committed. A zero
// denominator is surfaced as `None`.
#[cfg(test)]
pub(super) fn reciprocal<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    challenge: &[u64; LIMB_COUNT],
    value: &[u64; LIMB_COUNT],
) -> Option<[u64; LIMB_COUNT]> {
    let denominator = parameters.subtract(challenge, value);
    if denominator.iter().all(|limb| *limb == 0) {
        return None;
    }
    Some(parameters.inverse(&denominator))
}

// All reciprocals `1/(mu - v_i)` for one column via Montgomery's batch-inversion
// trick: one field inversion plus three multiplications per element, instead of
// one exponentiation-cost inversion per element. Returns `None` if any
// denominator is zero.
#[cfg(test)]
pub(super) fn batch_reciprocals<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    challenge: &[u64; LIMB_COUNT],
    values: &[[u64; LIMB_COUNT]],
) -> Option<Vec<[u64; LIMB_COUNT]>> {
    if values.is_empty() {
        return Some(Vec::new());
    }
    let mut denominators = Vec::with_capacity(values.len());
    for value in values {
        let denominator = parameters.subtract(challenge, value);
        if denominator.iter().all(|limb| *limb == 0) {
            return None;
        }
        denominators.push(denominator);
    }
    let mut prefix_products = Vec::with_capacity(denominators.len());
    let mut running = parameters.one();
    for denominator in &denominators {
        running = parameters.multiply(&running, denominator);
        prefix_products.push(running);
    }
    let mut suffix_inverse = parameters.inverse(prefix_products.last().expect("non-empty column"));
    let mut reciprocals = vec![parameters.zero(); denominators.len()];
    for index in (0..denominators.len()).rev() {
        let prefix_before = if index == 0 {
            parameters.one()
        } else {
            prefix_products[index - 1]
        };
        reciprocals[index] = parameters.multiply(&suffix_inverse, &prefix_before);
        suffix_inverse = parameters.multiply(&suffix_inverse, &denominators[index]);
    }
    Some(reciprocals)
}

// The per-digit lookup fraction column `f_d[x] = 1/(mu - shifted_c_d(x))` over
// the trace domain (length `N`).
#[cfg(test)]
pub(super) fn lookup_fraction_column<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    challenge: &[u64; LIMB_COUNT],
    shifted_carry_values: &[[u64; LIMB_COUNT]],
) -> Option<Vec<[u64; LIMB_COUNT]>> {
    batch_reciprocals(parameters, challenge, shifted_carry_values)
}

// The table fraction column `f_T[x] = m(x)/(mu - T(x))` over a table chunk's
// domain. Padding rows carry multiplicity zero, so their fraction is zero
// regardless of the (in-range) padding value.
#[cfg(test)]
pub(super) fn table_fraction_column<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    challenge: &[u64; LIMB_COUNT],
    table_column: &[[u64; LIMB_COUNT]],
    multiplicity_column: &[[u64; LIMB_COUNT]],
) -> Option<Vec<[u64; LIMB_COUNT]>> {
    let reciprocals = batch_reciprocals(parameters, challenge, table_column)?;
    Some(
        reciprocals
            .iter()
            .zip(multiplicity_column.iter())
            .map(|(recip, multiplicity)| parameters.multiply(multiplicity, recip))
            .collect(),
    )
}

// The sum of a fraction column's values, i.e. its logUp terminal
// `sum_x f(x)`.
#[cfg(test)]
pub(super) fn column_sum<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    column: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    column.iter().fold(parameters.zero(), |accumulated, value| {
        parameters.add(&accumulated, value)
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::proof_field::selected_key_switch_proof_field_parameters;
    use super::*;

    // A deterministic pseudo-random challenge, standing in for the transcript
    // draw; the identity is checked as a function of this random point.
    fn sample_challenge(parameters: &ProofFieldParameters<13>, seed: u64) -> [u64; 13] {
        let mut state = seed;
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        parameters.unsigned_word_to_element(state | 1)
    }

    // The full logUp balance for a set of shifted carries: the sum of lookup
    // reciprocals must equal the sum of every table chunk's fraction column.
    fn balance(
        parameters: &ProofFieldParameters<13>,
        ring_degree: usize,
        shifted: &[usize],
        challenge: &[u64; 13],
    ) -> ([u64; 13], [u64; 13]) {
        let shifted_field: Vec<[u64; 13]> = shifted
            .iter()
            .map(|value| parameters.unsigned_word_to_element(*value as u64))
            .collect();
        let lookup = lookup_fraction_column(parameters, challenge, &shifted_field).expect("lookup");
        let multiplicity_columns = multiplicities(parameters, shifted, ring_degree);
        let mut table_total = parameters.zero();
        for (table_index, multiplicity_column) in multiplicity_columns.iter().enumerate() {
            let table_column = table_values(parameters, ring_degree, table_index);
            let fraction =
                table_fraction_column(parameters, challenge, &table_column, multiplicity_column)
                    .expect("table fraction");
            table_total = parameters.add(&table_total, &column_sum(parameters, &fraction));
        }
        (column_sum(parameters, &lookup), table_total)
    }

    #[test]
    fn honest_in_range_carries_balance() {
        let parameters = selected_key_switch_proof_field_parameters();
        for ring_degree in [64_usize, 128, 256] {
            // Carries spanning the whole legal band `[-(N+1), N+1]`, including
            // both extremes (shifted 0 and 2N+2) and the values whose shifts
            // land at each chunk boundary, so every chunk and the padding are
            // exercised: shifts 0 (t0), N-1 (t0), N (t1), 2N-1 (t1), 2N (t2),
            // 2N+2 (t2).
            let degree = ring_degree as i64;
            let carries: Vec<i64> = vec![
                -(degree + 1), // shifted 0     -> table 0 first
                -2,            // shifted N-1   -> table 0 last
                -1,            // shifted N     -> table 1 first
                0,             // shifted N+1   -> table 1
                degree - 2,    // shifted 2N-1  -> table 1 last
                degree - 1,    // shifted 2N    -> table 2 first
                degree,        // shifted 2N+1  -> table 2
                degree + 1,    // shifted 2N+2  -> table 2 last real
            ];
            let shifted: Vec<usize> = carries
                .iter()
                .map(|carry| (carry + carry_shift(ring_degree)) as usize)
                .collect();
            assert_eq!(table_count(ring_degree), 3);
            for seed in [1_u64, 7, 4242, 999_983] {
                let challenge = sample_challenge(&parameters, seed);
                let (lookup_total, table_total) =
                    balance(&parameters, ring_degree, &shifted, &challenge);
                assert_eq!(
                    lookup_total, table_total,
                    "honest in-range carries must satisfy the logUp balance at every challenge"
                );
            }
        }
    }

    #[test]
    fn out_of_range_carry_breaks_the_balance() {
        // A shifted value of 2N+3 is one past the table's largest entry. Its
        // pole 1/(mu - (2N+3)) has no matching table term, so the balance fails
        // at the sampled challenges.
        let parameters = selected_key_switch_proof_field_parameters();
        let ring_degree = 64;
        let out_of_range = max_shifted_value(ring_degree) + 1;
        let shifted = vec![0_usize, 5, ring_degree, 2 * ring_degree, out_of_range];
        for seed in [2_u64, 13, 55_555] {
            let challenge = sample_challenge(&parameters, seed);
            let (lookup_total, table_total) =
                balance(&parameters, ring_degree, &shifted, &challenge);
            assert_ne!(
                lookup_total, table_total,
                "an out-of-range carry must break the logUp balance"
            );
        }
    }

    #[test]
    fn far_out_of_range_carry_aligned_to_a_padding_slot_breaks_the_balance() {
        // Adversarial: a malicious prover targets an out-of-range value that
        // happens to sit at the same domain row as a padding slot of table 2,
        // then inflates that padding row's multiplicity to try to match it.
        // Because the public table value at every padding row is in range (not
        // the out-of-range value), the balance still fails. Directly tests the
        // padding-collision defense.
        let parameters = selected_key_switch_proof_field_parameters();
        let ring_degree = 64;
        // Table 2 spans domain rows for values [2N, 3N); real entries are the
        // first three (2N, 2N+1, 2N+2); row 3.. are padding. Pick an
        // out-of-range value 2N+3 that a naive continued enumeration would place
        // at padding row 3 of table 2.
        let out_of_range = 2 * ring_degree + 3;
        assert!(out_of_range > max_shifted_value(ring_degree));
        let challenge = sample_challenge(&parameters, 271_828);

        let shifted_field = parameters.unsigned_word_to_element(out_of_range as u64);
        let lookup =
            lookup_fraction_column(&parameters, &challenge, &[shifted_field]).expect("lookup");
        let lookup_total = column_sum(&parameters, &lookup);

        let multiplicity_columns = multiplicities(&parameters, &[], ring_degree);
        // Force table 2's padding row 3 multiplicity to 1 in an attempt to
        // certify the out-of-range value.
        let mut tampered = multiplicity_columns;
        tampered[2][3] = parameters.one();
        // That row's public table value is the in-range padding value 2N, not
        // 2N+3.
        let table_two = table_values(&parameters, ring_degree, 2);
        assert_eq!(
            table_two[3],
            parameters.unsigned_word_to_element((2 * ring_degree) as u64)
        );
        let mut table_total = parameters.zero();
        for (table_index, multiplicity_column) in tampered.iter().enumerate() {
            let table_column = table_values(&parameters, ring_degree, table_index);
            let fraction =
                table_fraction_column(&parameters, &challenge, &table_column, multiplicity_column)
                    .expect("table fraction");
            table_total = parameters.add(&table_total, &column_sum(&parameters, &fraction));
        }
        assert_ne!(
            lookup_total, table_total,
            "inflating an in-range padding multiplicity must not certify an out-of-range carry"
        );
    }

    #[test]
    fn wrong_multiplicity_breaks_the_balance() {
        // The right set of values but a corrupted multiplicity (one value
        // over-counted) must fail: the balance pins each value's multiplicity
        // exactly.
        let parameters = selected_key_switch_proof_field_parameters();
        let ring_degree = 64;
        let shifted = vec![3_usize, 3, ring_degree + 1, 2 * ring_degree + 2];
        let challenge = sample_challenge(&parameters, 31_337);
        let shifted_field: Vec<[u64; 13]> = shifted
            .iter()
            .map(|value| parameters.unsigned_word_to_element(*value as u64))
            .collect();
        let lookup_total = column_sum(
            &parameters,
            &lookup_fraction_column(&parameters, &challenge, &shifted_field).expect("lookup"),
        );
        let mut multiplicity_columns = multiplicities(&parameters, &shifted, ring_degree);
        // Corrupt: claim value 3 appears three times instead of two.
        multiplicity_columns[0][3] = parameters.add(&multiplicity_columns[0][3], &parameters.one());
        let mut table_total = parameters.zero();
        for (table_index, multiplicity_column) in multiplicity_columns.iter().enumerate() {
            let table_column = table_values(&parameters, ring_degree, table_index);
            let fraction =
                table_fraction_column(&parameters, &challenge, &table_column, multiplicity_column)
                    .expect("table fraction");
            table_total = parameters.add(&table_total, &column_sum(&parameters, &fraction));
        }
        assert_ne!(
            lookup_total, table_total,
            "an over-counted multiplicity must break the logUp balance"
        );
    }

    #[test]
    fn multiplicities_account_for_every_carry() {
        // Every in-range carry is counted exactly once across the chunks.
        let parameters = selected_key_switch_proof_field_parameters();
        let ring_degree = 128;
        let shifted: Vec<usize> = (0..=max_shifted_value(ring_degree)).collect();
        let multiplicity_columns = multiplicities(&parameters, &shifted, ring_degree);
        let mut total = parameters.zero();
        for multiplicity_column in &multiplicity_columns {
            total = parameters.add(&total, &column_sum(&parameters, multiplicity_column));
        }
        assert_eq!(
            total,
            parameters.unsigned_word_to_element(shifted.len() as u64),
            "multiplicities must sum to the number of carries"
        );
    }

    #[test]
    fn batch_reciprocals_match_per_element_inversion() {
        // Montgomery's trick must agree with the direct per-element inverse on
        // every element, including repeated values.
        let parameters = selected_key_switch_proof_field_parameters();
        let challenge = sample_challenge(&parameters, 777);
        let values: Vec<[u64; 13]> = [0_u64, 5, 5, 130, 129, 1, 42]
            .iter()
            .map(|value| parameters.unsigned_word_to_element(*value))
            .collect();
        let batch = batch_reciprocals(&parameters, &challenge, &values).expect("batch");
        for (value, batched) in values.iter().zip(batch.iter()) {
            let direct = reciprocal(&parameters, &challenge, value).expect("direct");
            assert_eq!(
                *batched, direct,
                "batch inversion must match direct inversion"
            );
        }
        // A zero denominator (challenge equals a value) is surfaced as None.
        let colliding = vec![challenge];
        assert!(batch_reciprocals(&parameters, &challenge, &colliding).is_none());
    }

    #[test]
    fn fraction_pin_holds_for_table_and_lookup() {
        // The fraction-pin relation each support constraint enforces:
        // (mu - value) * fraction - multiplicity == 0.
        let parameters = selected_key_switch_proof_field_parameters();
        let challenge = sample_challenge(&parameters, 90_210);
        // Lookup pin: multiplicity is the implicit 1.
        let value = parameters.unsigned_word_to_element(42);
        let fraction = reciprocal(&parameters, &challenge, &value).expect("recip");
        let pinned = parameters.subtract(
            &parameters.multiply(&parameters.subtract(&challenge, &value), &fraction),
            &parameters.one(),
        );
        assert_eq!(pinned, parameters.zero(), "lookup fraction pin must hold");
        // Table pin: multiplicity 3.
        let multiplicity = parameters.unsigned_word_to_element(3);
        let table_fraction = parameters.multiply(&multiplicity, &fraction);
        let table_pinned = parameters.subtract(
            &parameters.multiply(&parameters.subtract(&challenge, &value), &table_fraction),
            &multiplicity,
        );
        assert_eq!(
            table_pinned,
            parameters.zero(),
            "table fraction pin must hold"
        );
    }
}
