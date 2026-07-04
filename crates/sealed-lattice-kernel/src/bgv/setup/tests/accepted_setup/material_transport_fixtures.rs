use super::*;

pub(super) fn append_vss_material_binary_header(
    output: &mut Vec<u8>,
    ring_degree: usize,
    participant_count: u64,
    decryption_threshold: u64,
) {
    output.extend(b"SLVSSMAT");
    append_varuint(output, 1);
    append_varuint(output, participant_count);
    append_varuint(output, decryption_threshold);
    append_varuint(output, DATA_PRIMES.len() as u64);
    append_varuint(output, ring_degree as u64);
    append_varuint(output, SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64);
    append_varuint(output, SETUP_COMMITMENT_ROW_COUNT as u64);
}

pub(super) fn vss_material_binary_total_byte_length(
    ring_degree: usize,
    participant_count: u64,
    decryption_threshold: u64,
) -> u64 {
    let mut header = Vec::new();
    append_vss_material_binary_header(
        &mut header,
        ring_degree,
        participant_count,
        decryption_threshold,
    );
    let coordinate_byte_length = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            (0..DATA_PRIMES.len()).flat_map(move |rns_limb_index| {
                (0..decryption_threshold).map(move |shamir_coefficient_index| {
                    let mut coordinate_bytes = Vec::new();
                    append_varuint(&mut coordinate_bytes, source_trustee_roster_position);
                    append_varuint(&mut coordinate_bytes, rns_limb_index as u64);
                    append_varuint(&mut coordinate_bytes, shamir_coefficient_index);
                    coordinate_bytes.len() as u64
                })
            })
        })
        .sum::<u64>();
    let commitment_limb_byte_length = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| {
            let mut index_bytes = Vec::new();
            append_varuint(&mut index_bytes, *commitment_modulus_index as u64);
            index_bytes.len() as u64
                + 8
                + (SETUP_COMMITMENT_ROW_COUNT as u64 * ring_degree as u64 * 8)
        })
        .sum::<u64>();
    let material_record_count = participant_count * DATA_PRIMES.len() as u64 * decryption_threshold;

    header.len() as u64
        + coordinate_byte_length
        + material_record_count * commitment_limb_byte_length
}
