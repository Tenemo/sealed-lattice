use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SetupProofLnpTboxZ34SeedMaterial {
    pub(super) seed_material_hash: String,
    pub(super) challenge_seed_hex: String,
    pub(super) challenge_seed_hash: String,
    pub(super) challenge_tail_hash: String,
    pub(super) challenge_row_domain_hash: String,
    pub(super) challenge_z3_row_set_hash: String,
    pub(super) challenge_z4_row_set_hash: String,
}

pub(super) fn setup_proof_lnp_tbox_z34_seed_material(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    t_b_coefficients: &[BigUint],
) -> CanonicalResult<SetupProofLnpTboxZ34SeedMaterial> {
    validate_hash_string(statement_hash_hex, "setupProofLnpTboxZ34.statementHash")?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofLnpTboxZ34.relationCommitmentHash",
    )?;
    let message_polynomial_count = setup_proof_lnp_tbox_message_polynomial_count(layout)?;
    let seed_polynomial_count = setup_proof_lnp_tbox_z34_seed_polynomial_count(layout)?;
    let expected_coefficient_count = layout
        .t_b_polynomial_count
        .checked_mul(layout.proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox tB coefficient count overflowed"))?;
    if t_b_coefficients.len() != expected_coefficient_count {
        return Err(setup_proof_error(
            "setup proof LNP tbox tB coefficient count does not match the layout",
        ));
    }

    let ty3_start = message_polynomial_count;
    let ty4_start = ty3_start
        .checked_add(seed_polynomial_count)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox ty4 offset overflowed"))?;
    let tbeta_start = ty4_start
        .checked_add(seed_polynomial_count)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox beta offset overflowed"))?;
    let challenge_tail_start = tbeta_start.checked_add(1).ok_or_else(|| {
        setup_proof_error("setup proof LNP tbox challenge-tail offset overflowed")
    })?;
    let challenge_tail_polynomial_count =
        setup_proof_lnp_tbox_challenge_tail_polynomial_count(layout)?;
    let ty3_coefficients = t_b_polynomial_slice(
        t_b_coefficients,
        layout.proof_ring_degree,
        ty3_start,
        seed_polynomial_count,
    )?;
    let ty4_coefficients = t_b_polynomial_slice(
        t_b_coefficients,
        layout.proof_ring_degree,
        ty4_start,
        seed_polynomial_count,
    )?;
    let tbeta_coefficients =
        t_b_polynomial_slice(t_b_coefficients, layout.proof_ring_degree, tbeta_start, 1)?;
    let challenge_tail_coefficients = t_b_polynomial_slice(
        t_b_coefficients,
        layout.proof_ring_degree,
        challenge_tail_start,
        challenge_tail_polynomial_count,
    )?;

    let seed_material_bytes = encode_setup_proof_lnp_tbox_z34_seed_material(
        layout,
        &[ty3_coefficients, ty4_coefficients, tbeta_coefficients],
    )?;
    let seed_material_hash = hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-seed-material-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            &seed_material_bytes,
        ],
    );
    let challenge_seed_bytes = setup_proof_lnp_tbox_z34_challenge_seed_bytes(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &seed_material_bytes,
    );
    let challenge_seed_hex = to_hex(&challenge_seed_bytes);
    let challenge_seed_hash = hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-challenge-seed-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            statement_hash_hex.as_bytes(),
            relation_commitment_hash_hex.as_bytes(),
            seed_material_hash.as_bytes(),
            &challenge_seed_bytes,
        ],
    );
    let challenge_tail_bytes =
        encode_setup_proof_lnp_tbox_z34_seed_material(layout, &[challenge_tail_coefficients])?;
    let challenge_tail_hash = hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-challenge-tail-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            seed_material_hash.as_bytes(),
            &challenge_tail_bytes,
        ],
    );
    let challenge_row_domain_hash =
        setup_proof_lnp_tbox_z34_challenge_row_domain_hash(layout, &challenge_seed_bytes)?;
    let challenge_z3_row_set_hash = setup_proof_lnp_tbox_z34_challenge_row_set_hash(
        layout,
        "z3",
        &challenge_seed_bytes,
        SETUP_PROOF_LNP_TBOX_Z34_R_ROW_DOMAIN_START,
        SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS,
        setup_proof_lnp_tbox_z34_row_column_count(layout, layout.z3_polynomial_count, "z3")?,
    )?;
    let challenge_z4_row_set_hash = setup_proof_lnp_tbox_z34_challenge_row_set_hash(
        layout,
        "z4",
        &challenge_seed_bytes,
        SETUP_PROOF_LNP_TBOX_Z34_RPRIME_ROW_DOMAIN_START,
        SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS,
        setup_proof_lnp_tbox_z34_row_column_count(layout, layout.z4_polynomial_count, "z4")?,
    )?;

    Ok(SetupProofLnpTboxZ34SeedMaterial {
        seed_material_hash,
        challenge_seed_hex,
        challenge_seed_hash,
        challenge_tail_hash,
        challenge_row_domain_hash,
        challenge_z3_row_set_hash,
        challenge_z4_row_set_hash,
    })
}

fn setup_proof_lnp_tbox_z34_challenge_seed_bytes(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    seed_material_bytes: &[u8],
) -> [u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT] {
    let seed = hash512(
        "sealed-lattice/setup/lnp-tbox-z34-challenge-seed-bytes-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            statement_hash_hex.as_bytes(),
            relation_commitment_hash_hex.as_bytes(),
            seed_material_bytes,
        ],
    );
    let mut challenge_seed_bytes = [0_u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT];
    challenge_seed_bytes
        .copy_from_slice(&seed[..SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT]);

    challenge_seed_bytes
}

fn setup_proof_lnp_tbox_z34_challenge_row_domain_hash(
    layout: &SetupProofLnpTboxLayout,
    challenge_seed_bytes: &[u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT],
) -> CanonicalResult<String> {
    let row_domain_schedule = setup_proof_lnp_tbox_z34_row_domain_schedule_bytes()?;
    Ok(hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-row-domain-schedule-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            challenge_seed_bytes,
            &row_domain_schedule,
        ],
    ))
}

fn setup_proof_lnp_tbox_z34_row_domain_schedule_bytes() -> CanonicalResult<Vec<u8>> {
    let mut encoded = Vec::new();
    for value in [
        SETUP_PROOF_LNP_TBOX_Z34_BRANDOM_K,
        SETUP_PROOF_LNP_TBOX_Z34_R_ROW_DOMAIN_START,
        SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS as u64,
        SETUP_PROOF_LNP_TBOX_Z34_RPRIME_ROW_DOMAIN_START,
        SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS as u64,
    ] {
        append_varuint(&mut encoded, value);
    }

    Ok(encoded)
}

fn setup_proof_lnp_tbox_z34_challenge_row_set_hash(
    layout: &SetupProofLnpTboxLayout,
    row_set_label: &str,
    challenge_seed_bytes: &[u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT],
    row_domain_start: u64,
    row_domain_count: usize,
    row_column_count: usize,
) -> CanonicalResult<String> {
    let row_set_bytes = setup_proof_lnp_tbox_z34_challenge_row_set_bytes(
        challenge_seed_bytes,
        row_domain_start,
        row_domain_count,
        row_column_count,
    )?;
    Ok(hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-row-set-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            row_set_label.as_bytes(),
            challenge_seed_bytes,
            &row_set_bytes,
        ],
    ))
}

fn setup_proof_lnp_tbox_z34_challenge_row_set_bytes(
    challenge_seed_bytes: &[u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT],
    row_domain_start: u64,
    row_domain_count: usize,
    row_column_count: usize,
) -> CanonicalResult<Vec<u8>> {
    if row_domain_count == 0 || row_column_count == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3/z4 challenge row set dimensions must be positive",
        ));
    }
    let row_domain_count_u64 = u64::try_from(row_domain_count)
        .map_err(|_| setup_proof_error("setup proof LNP tbox z3/z4 row-domain count overflowed"))?;
    let row_column_count_u64 = u64::try_from(row_column_count)
        .map_err(|_| setup_proof_error("setup proof LNP tbox z3/z4 row-column count overflowed"))?;
    let row_byte_count = row_domain_count
        .checked_mul(row_column_count)
        .ok_or_else(|| {
            setup_proof_error("setup proof LNP tbox z3/z4 row-set byte count overflowed")
        })?;
    let mut encoded = Vec::with_capacity(row_byte_count.saturating_add(40));
    append_varuint(&mut encoded, SETUP_PROOF_LNP_TBOX_Z34_BRANDOM_K);
    append_varuint(&mut encoded, row_domain_start);
    append_varuint(&mut encoded, row_domain_count_u64);
    append_varuint(&mut encoded, row_column_count_u64);
    for row_offset in 0..row_domain_count {
        let row_domain = row_domain_start
            .checked_add(u64::try_from(row_offset).map_err(|_| {
                setup_proof_error("setup proof LNP tbox z3/z4 row offset overflowed")
            })?)
            .ok_or_else(|| setup_proof_error("setup proof LNP tbox z3/z4 row domain overflowed"))?;
        let row = setup_proof_lnp_tbox_z34_brandom_row(
            challenge_seed_bytes,
            row_domain,
            row_column_count,
        )?;
        for coefficient in row {
            encoded.push(match coefficient {
                -1 => 0xff,
                0 => 0,
                1 => 1,
                _ => {
                    return Err(setup_proof_error(
                        "setup proof LNP tbox z3/z4 brandom coefficient is outside {-1,0,1}",
                    ));
                }
            });
        }
    }

    Ok(encoded)
}

pub(super) fn setup_proof_lnp_tbox_z34_brandom_row(
    challenge_seed_bytes: &[u8; SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT],
    row_domain: u64,
    row_column_count: usize,
) -> CanonicalResult<Vec<i8>> {
    if row_column_count == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3/z4 brandom row width must be positive",
        ));
    }
    let brandom_k = usize::try_from(SETUP_PROOF_LNP_TBOX_Z34_BRANDOM_K).map_err(|_| {
        setup_proof_error("setup proof LNP tbox z3/z4 brandom k does not fit usize")
    })?;
    if brandom_k == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3/z4 brandom k must be positive",
        ));
    }
    let one_plane_bit_count = row_column_count.checked_mul(brandom_k).ok_or_else(|| {
        setup_proof_error("setup proof LNP tbox z3/z4 brandom bit count overflowed")
    })?;
    let total_bit_count = one_plane_bit_count.checked_mul(2).ok_or_else(|| {
        setup_proof_error("setup proof LNP tbox z3/z4 brandom total bit count overflowed")
    })?;
    let random_byte_count = total_bit_count.div_ceil(8);
    let mut shake = Shake128::default();
    shake.update(challenge_seed_bytes);
    shake.update(&row_domain.to_le_bytes());
    let mut random_bytes = vec![0_u8; random_byte_count];
    shake.finalize_xof().read(&mut random_bytes);

    let mut row = Vec::with_capacity(row_column_count);
    for column_index in 0..row_column_count {
        let mut coefficient = 0_i8;
        for bit_index in 0..brandom_k {
            let add_bit_index = column_index
                .checked_mul(brandom_k)
                .and_then(|start| start.checked_add(bit_index))
                .ok_or_else(|| {
                    setup_proof_error("setup proof LNP tbox z3/z4 add bit index overflowed")
                })?;
            if setup_proof_lnp_tbox_z34_brandom_bit(&random_bytes, add_bit_index) {
                coefficient = coefficient.checked_add(1).ok_or_else(|| {
                    setup_proof_error("setup proof LNP tbox z3/z4 brandom coefficient overflowed")
                })?;
            }
            let subtract_bit_index =
                one_plane_bit_count
                    .checked_add(add_bit_index)
                    .ok_or_else(|| {
                        setup_proof_error(
                            "setup proof LNP tbox z3/z4 subtract bit index overflowed",
                        )
                    })?;
            if setup_proof_lnp_tbox_z34_brandom_bit(&random_bytes, subtract_bit_index) {
                coefficient = coefficient.checked_sub(1).ok_or_else(|| {
                    setup_proof_error("setup proof LNP tbox z3/z4 brandom coefficient underflowed")
                })?;
            }
        }
        row.push(coefficient);
    }

    Ok(row)
}

fn setup_proof_lnp_tbox_z34_brandom_bit(random_bytes: &[u8], bit_index: usize) -> bool {
    let byte = random_bytes[bit_index / 8];
    ((byte >> (bit_index % 8)) & 1) == 1
}

fn t_b_polynomial_slice(
    coefficients: &[BigUint],
    proof_ring_degree: usize,
    polynomial_start: usize,
    polynomial_count: usize,
) -> CanonicalResult<&[BigUint]> {
    let coefficient_start = polynomial_start
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP tB slice start overflowed"))?;
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP tB slice length overflowed"))?;
    let coefficient_end = coefficient_start
        .checked_add(coefficient_count)
        .ok_or_else(|| setup_proof_error("setup proof LNP tB slice end overflowed"))?;
    coefficients
        .get(coefficient_start..coefficient_end)
        .ok_or_else(|| {
            setup_proof_error("setup proof LNP tB seed-material slice is outside the tB vector")
        })
}

fn encode_setup_proof_lnp_tbox_z34_seed_material(
    layout: &SetupProofLnpTboxLayout,
    coefficient_slices: &[&[BigUint]],
) -> CanonicalResult<Vec<u8>> {
    let mut writer = LnpBitWriter::new();
    for coefficients in coefficient_slices {
        for coefficient in *coefficients {
            writer.write_big_uint_le_bits(coefficient, layout.proof_modulus_bit_count)?;
        }
    }
    writer.finish_with_lazer_padding();

    Ok(writer.into_bytes())
}

pub(super) fn setup_proof_lnp_tbox_generated_suffix_bytes(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    prefix_bytes: &[u8],
) -> CanonicalResult<Vec<u8>> {
    setup_proof_lnp_tbox_generated_suffix(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        prefix_bytes,
    )
}

fn setup_proof_lnp_tbox_generated_suffix(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    prefix_bytes: &[u8],
) -> CanonicalResult<Vec<u8>> {
    let expected_prefix_byte_count = setup_proof_lnp_tbox_commitment_prefix_byte_count(layout)?;
    if prefix_bytes.len() != expected_prefix_byte_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof LNP tbox generated suffix requires exactly the commitment prefix bytes",
        ));
    }
    let (_z34_seed_material, challenge_material) =
        setup_proof_lnp_tbox_z34_seed_and_challenge_from_prefix(
            layout,
            statement_hash_hex,
            relation_commitment_hash_hex,
            prefix_bytes,
        )?;
    let suffix_seed = setup_proof_lnp_tbox_generated_suffix_seed(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        prefix_bytes,
        &challenge_material.lower_protocol_challenge_hash,
    )?;
    let mut writer = LnpBitWriter::new();
    encode_lnp_tbox_challenge_coefficients(
        &mut writer,
        &challenge_material.challenge_coefficients,
    )?;
    encode_lnp_tbox_generated_hint_polyvec(
        &mut writer,
        &suffix_seed,
        layout.hint_polynomial_count,
        layout.proof_ring_degree,
    )?;
    encode_lnp_tbox_generated_gaussian_polyvec(
        &mut writer,
        &suffix_seed,
        LnpTboxGeneratedGaussianPolyvecEncoding {
            field_name: "z1",
            polynomial_count: layout.z1_polynomial_count,
            proof_ring_degree: layout.proof_ring_degree,
            log2_standard_deviation: layout.z1_log2_standard_deviation,
            coefficient_bound: 3,
            check_coefficient_count: 0,
        },
    )?;
    encode_lnp_tbox_generated_gaussian_polyvec(
        &mut writer,
        &suffix_seed,
        LnpTboxGeneratedGaussianPolyvecEncoding {
            field_name: "z21",
            polynomial_count: layout.z21_polynomial_count,
            proof_ring_degree: layout.proof_ring_degree,
            log2_standard_deviation: layout.z21_log2_standard_deviation,
            coefficient_bound: 3,
            check_coefficient_count: 0,
        },
    )?;
    let z34_check_coefficient_count = setup_proof_lnp_tbox_z34_check_coefficient_count(layout)?;
    let z3_check_coefficients = encode_lnp_tbox_generated_gaussian_polyvec(
        &mut writer,
        &suffix_seed,
        LnpTboxGeneratedGaussianPolyvecEncoding {
            field_name: "z3",
            polynomial_count: layout.z3_polynomial_count,
            proof_ring_degree: layout.proof_ring_degree,
            log2_standard_deviation: layout.z3_log2_standard_deviation,
            coefficient_bound: 1,
            check_coefficient_count: z34_check_coefficient_count,
        },
    )?;
    let z4_check_coefficients = encode_lnp_tbox_generated_gaussian_polyvec(
        &mut writer,
        &suffix_seed,
        LnpTboxGeneratedGaussianPolyvecEncoding {
            field_name: "z4",
            polynomial_count: layout.z4_polynomial_count,
            proof_ring_degree: layout.proof_ring_degree,
            log2_standard_deviation: layout.z4_log2_standard_deviation,
            coefficient_bound: 1,
            check_coefficient_count: z34_check_coefficient_count,
        },
    )?;
    writer.finish_with_lazer_padding();
    let z3_l2_squared = gaussian_l2_squared(&z3_check_coefficients);
    let z4_infinity_norm = gaussian_infinity_norm(&z4_check_coefficients);
    verify_lnp_tbox_z34_norm_bounds(layout, &z3_l2_squared, &z4_infinity_norm)?;

    Ok(writer.into_bytes())
}

fn setup_proof_lnp_tbox_generated_suffix_seed(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    prefix_bytes: &[u8],
    lower_protocol_challenge_hash: &str,
) -> CanonicalResult<[u8; 64]> {
    validate_hash_string(statement_hash_hex, "setupProofLnpTboxSuffix.statementHash")?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofLnpTboxSuffix.relationCommitmentHash",
    )?;
    validate_hash_string(
        lower_protocol_challenge_hash,
        "setupProofLnpTboxSuffix.lowerProtocolChallengeHash",
    )?;
    Ok(hash512(
        "sealed-lattice/setup/lnp-tbox-generated-suffix-seed-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            statement_hash_hex.as_bytes(),
            relation_commitment_hash_hex.as_bytes(),
            lower_protocol_challenge_hash.as_bytes(),
            prefix_bytes,
        ],
    ))
}

fn encode_lnp_tbox_challenge_coefficients(
    writer: &mut LnpBitWriter,
    challenge_coefficients: &[i64],
) -> CanonicalResult<()> {
    for coefficient in challenge_coefficients {
        let shifted = coefficient
            .checked_add(
                i64::try_from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND)
                    .expect("fixed challenge coefficient bound fits i64"),
            )
            .ok_or_else(|| setup_proof_error("setup proof LNP challenge shift overflowed"))?;
        let shifted = u64::try_from(shifted)
            .map_err(|_| setup_proof_error("setup proof LNP challenge coefficient is negative"))?;
        writer.write_u64_le_bits(shifted, SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE)?;
    }

    Ok(())
}

fn encode_lnp_tbox_generated_hint_polyvec(
    writer: &mut LnpBitWriter,
    suffix_seed: &[u8; 64],
    polynomial_count: usize,
    proof_ring_degree: usize,
) -> CanonicalResult<()> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP hint count overflowed"))?;
    for coefficient_index in 0..coefficient_count {
        let value = generated_lnp_tbox_small_signed_value(
            suffix_seed,
            "hint",
            coefficient_index,
            1,
            Some(1),
        )?;
        let value = i64::try_from(value)
            .map_err(|_| setup_proof_error("setup proof LNP generated hint does not fit i64"))?;
        encode_lnp_tbox_hint_coefficient(writer, value)?;
    }

    Ok(())
}

fn encode_lnp_tbox_hint_coefficient(writer: &mut LnpBitWriter, value: i64) -> CanonicalResult<()> {
    match value {
        0 => {
            writer.write_bit(false);
            writer.write_bit(false);
        }
        1 => {
            writer.write_bit(false);
            writer.write_bit(true);
        }
        -1 => {
            writer.write_bit(true);
            writer.write_bit(false);
        }
        value if value >= 2 => {
            writer.write_bit(true);
            writer.write_bit(true);
            let extension_zero_count = usize::try_from(
                value
                    .checked_mul(2)
                    .and_then(|doubled| doubled.checked_sub(4))
                    .ok_or_else(|| {
                        setup_proof_error("setup proof LNP hint extension overflowed")
                    })?,
            )
            .map_err(|_| setup_proof_error("setup proof LNP hint extension is negative"))?;
            for _ in 0..extension_zero_count {
                writer.write_bit(false);
            }
            writer.write_bit(true);
        }
        value => {
            writer.write_bit(true);
            writer.write_bit(true);
            let extension_zero_count = usize::try_from(
                value
                    .checked_neg()
                    .and_then(|magnitude| magnitude.checked_mul(2))
                    .and_then(|doubled| doubled.checked_sub(3))
                    .ok_or_else(|| {
                        setup_proof_error("setup proof LNP hint extension overflowed")
                    })?,
            )
            .map_err(|_| setup_proof_error("setup proof LNP hint extension is negative"))?;
            for _ in 0..extension_zero_count {
                writer.write_bit(false);
            }
            writer.write_bit(true);
        }
    }

    Ok(())
}

struct LnpTboxGeneratedGaussianPolyvecEncoding<'a> {
    field_name: &'a str,
    polynomial_count: usize,
    proof_ring_degree: usize,
    log2_standard_deviation: usize,
    coefficient_bound: i128,
    check_coefficient_count: usize,
}

fn encode_lnp_tbox_generated_gaussian_polyvec(
    writer: &mut LnpBitWriter,
    suffix_seed: &[u8; 64],
    encoding: LnpTboxGeneratedGaussianPolyvecEncoding<'_>,
) -> CanonicalResult<Vec<LnpTboxGaussianCoefficient>> {
    let LnpTboxGeneratedGaussianPolyvecEncoding {
        field_name,
        polynomial_count,
        proof_ring_degree,
        log2_standard_deviation,
        coefficient_bound,
        check_coefficient_count,
    } = encoding;
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| {
            setup_proof_error(format!(
                "setup proof LNP {field_name} coefficient count overflowed"
            ))
        })?;
    if check_coefficient_count > coefficient_count {
        return Err(setup_proof_error(format!(
            "setup proof LNP {field_name} check coefficient count exceeds generated vector length"
        )));
    }
    let mut check_coefficients = Vec::with_capacity(check_coefficient_count);
    for coefficient_index in 0..coefficient_count {
        let value = generated_lnp_tbox_small_signed_value(
            suffix_seed,
            field_name,
            coefficient_index,
            coefficient_bound,
            Some(match field_name {
                "z21" | "z4" => -1,
                _ => 1,
            }),
        )?;
        let coefficient =
            encode_lnp_tbox_gaussian_coefficient(writer, value, log2_standard_deviation)?;
        if coefficient_index < check_coefficient_count {
            check_coefficients.push(coefficient);
        }
    }

    Ok(check_coefficients)
}

fn generated_lnp_tbox_small_signed_value(
    suffix_seed: &[u8; 64],
    field_name: &str,
    coefficient_index: usize,
    inclusive_bound: i128,
    first_coefficient_value: Option<i128>,
) -> CanonicalResult<i128> {
    if inclusive_bound < 0 {
        return Err(setup_proof_error(
            "setup proof LNP generated suffix bound must be nonnegative",
        ));
    }
    if coefficient_index == 0
        && let Some(value) = first_coefficient_value
    {
        return Ok(value.clamp(-inclusive_bound, inclusive_bound));
    }
    let coefficient_index_bytes = u64::try_from(coefficient_index)
        .map_err(|_| setup_proof_error("setup proof LNP suffix coefficient index overflowed"))?
        .to_le_bytes();
    let block = hash512(
        "sealed-lattice/setup/lnp-tbox-generated-suffix-coefficient-v1",
        &[suffix_seed, field_name.as_bytes(), &coefficient_index_bytes],
    );
    let modulus = u128::try_from(
        inclusive_bound
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| setup_proof_error("setup proof LNP suffix bound overflowed"))?,
    )
    .map_err(|_| setup_proof_error("setup proof LNP suffix modulus does not fit u128"))?;
    let mut random_bytes = [0_u8; 16];
    random_bytes.copy_from_slice(&block[..16]);
    let sample = u128::from_le_bytes(random_bytes) % modulus;
    i128::try_from(sample)
        .map(|value| value - inclusive_bound)
        .map_err(|_| setup_proof_error("setup proof LNP suffix sample does not fit i128"))
}

fn encode_lnp_tbox_gaussian_coefficient(
    writer: &mut LnpBitWriter,
    value: i128,
    log2_standard_deviation: usize,
) -> CanonicalResult<LnpTboxGaussianCoefficient> {
    let low_bit_count = log2_standard_deviation
        .checked_add(1)
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian low-bit count overflowed"))?;
    if low_bit_count == 0 || low_bit_count > u64::BITS as usize {
        return Err(setup_proof_error(
            "setup proof LNP Gaussian low-bit count is outside the supported encoding range",
        ));
    }
    let range = 1_i128
        .checked_shl(u32::try_from(low_bit_count).map_err(|_| {
            setup_proof_error("setup proof LNP Gaussian low-bit count does not fit u32")
        })?)
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian range overflowed"))?;
    let half_range = range / 2;
    let mut low_value = value % range;
    if low_value >= half_range {
        low_value -= range;
    }
    if low_value < -half_range {
        low_value += range;
    }
    let quotient = value
        .checked_sub(low_value)
        .and_then(|high_value| high_value.checked_div(range))
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian quotient overflowed"))?;
    let unary_ones = if quotient <= 0 {
        usize::try_from(
            quotient
                .checked_neg()
                .and_then(|value| value.checked_mul(2))
                .ok_or_else(|| {
                    setup_proof_error("setup proof LNP Gaussian unary quotient overflowed")
                })?,
        )
        .map_err(|_| setup_proof_error("setup proof LNP Gaussian unary quotient overflowed"))?
    } else {
        usize::try_from(
            quotient
                .checked_mul(2)
                .and_then(|value| value.checked_sub(1))
                .ok_or_else(|| {
                    setup_proof_error("setup proof LNP Gaussian unary quotient overflowed")
                })?,
        )
        .map_err(|_| setup_proof_error("setup proof LNP Gaussian unary quotient overflowed"))?
    };
    for _ in 0..unary_ones {
        writer.write_bit(true);
    }
    writer.write_bit(false);
    let low_bits_mask = (1_u128 << low_bit_count) - 1;
    let low_bits = u64::try_from((low_value as u128) & low_bits_mask)
        .map_err(|_| setup_proof_error("setup proof LNP Gaussian low bits do not fit u64"))?;
    writer.write_u64_le_bits(low_bits, low_bit_count)?;

    Ok(LnpTboxGaussianCoefficient {
        unary_ones,
        low_bits,
        low_bit_count,
        value,
    })
}
