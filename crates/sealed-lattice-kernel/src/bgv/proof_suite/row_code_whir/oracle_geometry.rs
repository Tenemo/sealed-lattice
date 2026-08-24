//! Checked aggregate-oracle geometry and transcript query sampling.

use p3_challenger::CanSampleUniformBits;

use super::ExtensionFieldChallenger;

pub(super) fn sample_distinct_query_indices(
    domain_size: usize,
    folding_factor: usize,
    query_count: usize,
    challenger: &mut ExtensionFieldChallenger,
) -> Result<Vec<usize>, String> {
    let folded_domain_size = domain_size
        .checked_shr(
            u32::try_from(folding_factor)
                .map_err(|_| "aggregate-wide WHIR folding factor exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "aggregate-wide WHIR folded query domain overflowed".to_owned())?;
    if folded_domain_size == 0 || !folded_domain_size.is_power_of_two() {
        return Err(
            "aggregate-wide WHIR folded query domain is not a nonzero power of two".to_owned(),
        );
    }
    let bit_length = folded_domain_size.ilog2() as usize;
    let target_count = query_count.min(folded_domain_size);
    let mut indices = Vec::with_capacity(target_count);
    while indices.len() < target_count {
        let candidate = challenger
            .sample_uniform_bits::<true>(bit_length)
            .map_err(|_| {
                "aggregate-wide WHIR query sampling unexpectedly requested resampling".to_owned()
            })?;
        if !indices.contains(&candidate) {
            indices.push(candidate);
        }
    }
    indices.sort_unstable();
    Ok(indices)
}

pub(super) fn checked_power_of_two(exponent: usize, label: &str) -> Result<usize, String> {
    1_usize
        .checked_shl(u32::try_from(exponent).map_err(|_| format!("{label} exponent exceeds u32"))?)
        .ok_or_else(|| format!("{label} overflowed"))
}

pub(super) fn logical_column_selector_index(
    logical_column_index: usize,
    table_width: usize,
) -> Result<usize, String> {
    if !table_width.is_power_of_two() || logical_column_index >= table_width {
        return Err("aggregate source column selector is outside the table".to_owned());
    }
    let selector_variable_count = table_width.ilog2() as usize;
    Ok(logical_column_index.reverse_bits() >> (usize::BITS as usize - selector_variable_count))
}

#[cfg(test)]
pub(super) fn interleaved_source_index(
    local_index: usize,
    logical_column_index: usize,
    table_width: usize,
) -> Result<usize, String> {
    let selector_index = logical_column_selector_index(logical_column_index, table_width)?;
    local_index
        .checked_mul(table_width)
        .and_then(|index| index.checked_add(selector_index))
        .ok_or_else(|| "aggregate source interleaved index overflowed".to_owned())
}
