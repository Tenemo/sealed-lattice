use super::*;

pub(crate) fn setup_proof_lnp_tbox_commitment_prefix_byte_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    validate_lnp_tbox_layout(layout)?;
    let compressed_bit_count = layout
        .proof_modulus_bit_count
        .checked_sub(layout.compression_dropped_bits)
        .ok_or_else(|| setup_proof_error("setup proof compressed tA1 bit count underflowed"))?;
    let prefix_bit_count = layout
        .t_b_polynomial_count
        .checked_mul(layout.proof_ring_degree)
        .and_then(|count| count.checked_mul(layout.proof_modulus_bit_count))
        .and_then(|count| {
            layout
                .h_polynomial_count
                .checked_mul(layout.proof_ring_degree)
                .and_then(|h_count| h_count.checked_mul(layout.proof_modulus_bit_count))
                .and_then(|h_bits| count.checked_add(h_bits))
        })
        .and_then(|count| {
            layout
                .t_a1_polynomial_count
                .checked_mul(layout.proof_ring_degree)
                .and_then(|t_a1_count| t_a1_count.checked_mul(compressed_bit_count))
                .and_then(|t_a1_bits| count.checked_add(t_a1_bits))
        })
        .ok_or_else(|| {
            setup_proof_error("setup proof LNP tbox commitment prefix size overflowed")
        })?;
    if prefix_bit_count % 8 != 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox commitment prefix must end on a byte boundary",
        ));
    }

    Ok(prefix_bit_count / 8)
}

pub(crate) fn setup_proof_lnp_tbox_commitment_prefix_hash(
    layout: &SetupProofLnpTboxLayout,
    proof_bytes: &[u8],
) -> CanonicalResult<String> {
    let prefix_byte_count = setup_proof_lnp_tbox_commitment_prefix_byte_count(layout)?;
    let Some(prefix_bytes) = proof_bytes.get(..prefix_byte_count) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof LNP tbox proof ended before the commitment prefix",
        ));
    };

    Ok(hash512_hex(
        layout.tbox_commitment_prefix_hash_domain,
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            prefix_bytes,
        ],
    ))
}

pub(in crate::bgv::setup) fn setup_proof_lnp_tbox_prefix_binding_seed(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    tbox_parameter_profile_hash: &str,
    encoded_relation_commitments: &[u8],
) -> CanonicalResult<String> {
    validate_lnp_tbox_layout(layout)?;
    validate_hash_string(statement_hash_hex, "setupProofLnpTboxPrefix.statementHash")?;
    validate_hash_string(
        tbox_parameter_profile_hash,
        "setupProofLnpTboxPrefix.parameterProfileHash",
    )?;
    if encoded_relation_commitments.is_empty() {
        return Err(setup_proof_error(
            "setup proof LNP tbox prefix binding requires relation commitments",
        ));
    }

    Ok(hash512_hex(
        "sealed-lattice/setup/lnp-tbox-prefix-binding-seed-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            statement_hash_hex.as_bytes(),
            tbox_parameter_profile_hash.as_bytes(),
            encoded_relation_commitments,
        ],
    ))
}

pub(in crate::bgv::setup) fn setup_proof_lnp_tbox_h_coefficient_must_be_zero(
    coefficient_index: usize,
    proof_ring_degree: usize,
) -> bool {
    if proof_ring_degree == 0 {
        return false;
    }
    let coefficient_position = coefficient_index % proof_ring_degree;
    coefficient_position == 0 || coefficient_position == proof_ring_degree / 2
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "returned by the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) struct SetupProofLnpTboxDecodedSummary {
    pub(crate) decoded_size_bytes: usize,
    pub(crate) t_b_coefficients: Vec<BigUint>,
    pub(crate) h_coefficients: Vec<BigUint>,
    pub(crate) t_a1_compressed_coefficients: Vec<BigUint>,
    pub(crate) challenge_coefficients: Vec<i64>,
    pub(crate) hint_coefficients: Vec<LnpTboxHintCoefficient>,
    pub(crate) z1_coefficients: Vec<LnpTboxGaussianCoefficient>,
    pub(crate) z21_coefficients: Vec<LnpTboxGaussianCoefficient>,
    pub(crate) z3_coefficients: Vec<LnpTboxGaussianCoefficient>,
    pub(crate) z4_coefficients: Vec<LnpTboxGaussianCoefficient>,
    pub(crate) z3_l2_squared: BigUint,
    pub(crate) z4_infinity_norm: BigUint,
    pub(crate) z34_seed_material_hash: String,
    pub(crate) z34_challenge_seed_hex: String,
    pub(crate) z34_challenge_seed_hash: String,
    pub(crate) z34_challenge_tail_hash: String,
    pub(crate) z34_challenge_row_domain_hash: String,
    pub(crate) z34_challenge_z3_row_set_hash: String,
    pub(crate) z34_challenge_z4_row_set_hash: String,
    pub(crate) tbox_lower_protocol_challenge_hash: String,
    pub(crate) z34_z3_check_window_hash: String,
    pub(crate) z34_z4_check_window_hash: String,
}

#[allow(
    dead_code,
    reason = "entry point for the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) fn verify_setup_proof_lnp_tbox_proof_bytes(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    proof_bytes: &[u8],
) -> CanonicalResult<SetupProofLnpTboxDecodedSummary> {
    validate_lnp_tbox_layout(layout)?;
    validate_hash_string(statement_hash_hex, "setupProofLnpTbox.statementHash")?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofLnpTbox.relationCommitmentHash",
    )?;

    let mut reader = LnpBitReader::new(proof_bytes);
    let t_b_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.t_b_polynomial_count,
        layout.proof_ring_degree,
        &layout.proof_modulus,
        layout.proof_modulus_bit_count,
        "tB",
    )?;
    let z34_seed_material = setup_proof_lnp_tbox_z34_seed_material(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &t_b_coefficients,
    )?;
    let challenge_material = setup_proof_lnp_tbox_challenge_material(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &z34_seed_material,
    )?;
    let h_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.h_polynomial_count,
        layout.proof_ring_degree,
        &layout.proof_modulus,
        layout.proof_modulus_bit_count,
        "h",
    )?;
    verify_lnp_tbox_h_forced_zero_coefficients(&h_coefficients, layout.proof_ring_degree)?;
    let compressed_bit_count = layout
        .proof_modulus_bit_count
        .checked_sub(layout.compression_dropped_bits)
        .ok_or_else(|| setup_proof_error("setup proof compressed tA1 bit count underflowed"))?;
    let compressed_modulus = BigUint::one() << compressed_bit_count;
    let t_a1_compressed_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.t_a1_polynomial_count,
        layout.proof_ring_degree,
        &compressed_modulus,
        compressed_bit_count,
        "tA1",
    )?;
    let decoded_challenge = decode_centered_challenge_polynomial(&mut reader, layout)?;
    if decoded_challenge != challenge_material.challenge_coefficients {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof LNP tbox challenge does not match the z34-bound lower-protocol transcript sampler",
        ));
    }
    let hint_coefficients = decode_hint_polyvec(
        &mut reader,
        layout.hint_polynomial_count,
        layout.proof_ring_degree,
    )?;
    verify_lnp_tbox_hint_coefficients(&hint_coefficients)?;
    let z1_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z1_polynomial_count,
        layout.proof_ring_degree,
        layout.z1_log2_standard_deviation,
        "z1",
    )?;
    verify_lnp_tbox_gaussian_l2_bound(
        layout,
        &z1_coefficients,
        layout.z1_log2_standard_deviation,
        "z1",
    )?;
    let z21_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z21_polynomial_count,
        layout.proof_ring_degree,
        layout.z21_log2_standard_deviation,
        "z21",
    )?;
    verify_lnp_tbox_gaussian_l2_bound(
        layout,
        &z21_coefficients,
        layout.z21_log2_standard_deviation,
        "z21",
    )?;
    let z3_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z3_polynomial_count,
        layout.proof_ring_degree,
        layout.z3_log2_standard_deviation,
        "z3",
    )?;
    let z34_check_coefficient_count = setup_proof_lnp_tbox_z34_check_coefficient_count(layout)?;
    let z3_l2_squared = gaussian_l2_squared(gaussian_coefficient_prefix(
        &z3_coefficients,
        z34_check_coefficient_count,
        "z3",
    )?);
    let z34_z3_check_window_hash = setup_proof_lnp_tbox_z34_check_window_hash(
        layout,
        "z3",
        gaussian_coefficient_prefix(&z3_coefficients, z34_check_coefficient_count, "z3")?,
    )?;
    let z4_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z4_polynomial_count,
        layout.proof_ring_degree,
        layout.z4_log2_standard_deviation,
        "z4",
    )?;
    let z4_infinity_norm = gaussian_infinity_norm(gaussian_coefficient_prefix(
        &z4_coefficients,
        z34_check_coefficient_count,
        "z4",
    )?);
    let z34_z4_check_window_hash = setup_proof_lnp_tbox_z34_check_window_hash(
        layout,
        "z4",
        gaussian_coefficient_prefix(&z4_coefficients, z34_check_coefficient_count, "z4")?,
    )?;
    verify_lnp_tbox_z34_norm_bounds(layout, &z3_l2_squared, &z4_infinity_norm)?;
    reader.finish_with_lazer_padding()?;
    verify_generated_lnp_tbox_suffix_bytes(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        proof_bytes,
    )?;

    Ok(SetupProofLnpTboxDecodedSummary {
        decoded_size_bytes: proof_bytes.len(),
        t_b_coefficients,
        h_coefficients,
        t_a1_compressed_coefficients,
        challenge_coefficients: decoded_challenge,
        hint_coefficients,
        z1_coefficients,
        z21_coefficients,
        z3_coefficients,
        z4_coefficients,
        z3_l2_squared,
        z4_infinity_norm,
        z34_seed_material_hash: z34_seed_material.seed_material_hash,
        z34_challenge_seed_hex: z34_seed_material.challenge_seed_hex,
        z34_challenge_seed_hash: z34_seed_material.challenge_seed_hash,
        z34_challenge_tail_hash: z34_seed_material.challenge_tail_hash,
        z34_challenge_row_domain_hash: z34_seed_material.challenge_row_domain_hash,
        z34_challenge_z3_row_set_hash: z34_seed_material.challenge_z3_row_set_hash,
        z34_challenge_z4_row_set_hash: z34_seed_material.challenge_z4_row_set_hash,
        tbox_lower_protocol_challenge_hash: challenge_material.lower_protocol_challenge_hash,
        z34_z3_check_window_hash,
        z34_z4_check_window_hash,
    })
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
pub(super) fn validate_lnp_tbox_layout(layout: &SetupProofLnpTboxLayout) -> CanonicalResult<()> {
    if !SETUP_PROOF_FAMILIES.contains(&layout.proof_family) {
        return Err(setup_proof_error(
            "setup proof LNP tbox layout proof family is not in the fixed profile",
        ));
    }
    if !matches!(layout.proof_ring_degree, 64 | 128) {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof ring degree must be 64 or 128",
        ));
    }
    if layout.proof_ring_degree != SETUP_PROOF_LNP_PROOF_RING_DEGREE {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof ring degree does not match the fixed first-profile challenge shape",
        ));
    }
    let seed_polynomial_count = setup_proof_lnp_tbox_z34_seed_polynomial_count(layout)?;
    setup_proof_lnp_tbox_message_polynomial_count(layout)?;
    let challenge_modulus = setup_proof_challenge_modulus();
    if layout.proof_modulus <= challenge_modulus {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof modulus must be larger than the challenge modulus",
        ));
    }
    if layout.proof_modulus.bits() > layout.proof_modulus_bit_count as u64 {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof modulus does not fit its declared bit count",
        ));
    }
    if layout.proof_modulus_bit_count == 0
        || layout.compression_dropped_bits >= layout.proof_modulus_bit_count
    {
        return Err(setup_proof_error(
            "setup proof LNP tbox compression parameters are invalid",
        ));
    }
    if layout.h_polynomial_count == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox h polynomial count must be non-zero",
        ));
    }
    if layout.z3_polynomial_count != seed_polynomial_count {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3 polynomial count must equal the LaZer 256-coefficient check vector width",
        ));
    }
    if layout.z4_polynomial_count != seed_polynomial_count {
        return Err(setup_proof_error(
            "setup proof LNP tbox z4 polynomial count must equal the LaZer 256-coefficient check vector width",
        ));
    }
    if layout.t_a1_polynomial_count != layout.hint_polynomial_count {
        return Err(setup_proof_error(
            "setup proof LNP tbox tA1 and hint polynomial counts must match the AB-DLOP commitment row count",
        ));
    }
    for (name, count) in [
        ("tB", layout.t_b_polynomial_count),
        ("h", layout.h_polynomial_count),
        ("tA1", layout.t_a1_polynomial_count),
        ("hint", layout.hint_polynomial_count),
        ("z1", layout.z1_polynomial_count),
        ("z21", layout.z21_polynomial_count),
        ("z3", layout.z3_polynomial_count),
        ("z4", layout.z4_polynomial_count),
    ] {
        if count == 0 {
            return Err(setup_proof_error(format!(
                "setup proof LNP tbox {name} polynomial count must be non-zero",
            )));
        }
    }
    let z34_check_coefficient_count = setup_proof_lnp_tbox_z34_check_coefficient_count(layout)?;
    for (name, count) in [
        ("z3", layout.z3_polynomial_count),
        ("z4", layout.z4_polynomial_count),
    ] {
        let coefficient_count = count.checked_mul(layout.proof_ring_degree).ok_or_else(|| {
            setup_proof_error(format!(
                "setup proof LNP tbox {name} coefficient count overflowed"
            ))
        })?;
        if coefficient_count < z34_check_coefficient_count {
            return Err(setup_proof_error(format!(
                "setup proof LNP tbox {name} vector is too small for the z3/z4 check window",
            )));
        }
    }
    for (name, bit_count) in [
        ("z1", layout.z1_log2_standard_deviation),
        ("z21", layout.z21_log2_standard_deviation),
        ("z3", layout.z3_log2_standard_deviation),
        ("z4", layout.z4_log2_standard_deviation),
    ] {
        if bit_count > 61 {
            return Err(setup_proof_error(format!(
                "setup proof LNP tbox {name} standard-deviation bit count is outside the supported range",
            )));
        }
    }

    Ok(())
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
pub(super) fn decode_uniform_polyvec(
    reader: &mut LnpBitReader<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
    modulus: &BigUint,
    bit_count: usize,
    field_name: &str,
) -> CanonicalResult<Vec<BigUint>> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox coefficient count overflowed"))?;
    let mut coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let value = reader.read_big_uint_le_bits(bit_count)?;
        if &value >= modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("setup proof LNP tbox {field_name} residue is not canonical"),
            ));
        }
        coefficients.push(value);
    }

    Ok(coefficients)
}

fn verify_lnp_tbox_hint_coefficients(
    coefficients: &[LnpTboxHintCoefficient],
) -> CanonicalResult<()> {
    for coefficient in coefficients {
        if coefficient.value.unsigned_abs() > 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "setup proof LNP tbox hint coefficient exceeds the generated first-profile range",
            ));
        }
    }

    Ok(())
}

pub(super) fn verify_lnp_tbox_h_forced_zero_coefficients(
    coefficients: &[BigUint],
    proof_ring_degree: usize,
) -> CanonicalResult<()> {
    for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
        if setup_proof_lnp_tbox_h_coefficient_must_be_zero(coefficient_index, proof_ring_degree)
            && !coefficient.is_zero()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "setup proof LNP tbox h coefficients at positions 0 and d/2 must be zero",
            ));
        }
    }

    Ok(())
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn decode_centered_challenge_polynomial(
    reader: &mut LnpBitReader<'_>,
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<Vec<i64>> {
    let modulus = setup_proof_challenge_modulus();
    let mut coefficients = Vec::with_capacity(layout.proof_ring_degree);
    for _ in 0..layout.proof_ring_degree {
        let value = reader.read_big_uint_le_bits(SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE)?;
        if value >= modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "setup proof LNP tbox challenge coefficient is not canonical",
            ));
        }
        let residue = big_uint_to_u64(&value, "setup proof LNP challenge residue")?;
        let coefficient = i64::try_from(residue)
            .map_err(|_| setup_proof_error("setup proof LNP challenge residue does not fit i64"))?
            - i64::try_from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND)
                .expect("fixed challenge coefficient bound fits i64");
        coefficients.push(coefficient);
    }

    Ok(coefficients)
}

fn verify_lnp_tbox_gaussian_l2_bound(
    layout: &SetupProofLnpTboxLayout,
    coefficients: &[LnpTboxGaussianCoefficient],
    log2_standard_deviation: usize,
    field_name: &str,
) -> CanonicalResult<()> {
    let l2_squared = gaussian_l2_squared(coefficients);
    let coefficient_count = u64::try_from(coefficients.len()).map_err(|_| {
        setup_proof_error(format!(
            "setup proof LNP tbox {field_name} coefficient count overflowed"
        ))
    })?;
    let bound =
        generated_lnp_tbox_gaussian_l2_squared_bound(coefficient_count, log2_standard_deviation)?;
    if l2_squared > bound {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("setup proof LNP tbox {field_name} L2-squared exceeds the generated bound"),
        ));
    }
    if coefficients
        .iter()
        .any(|coefficient| coefficient.low_bit_count != log2_standard_deviation + 1)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("setup proof LNP tbox {field_name} Gaussian coding width is not canonical"),
        ));
    }
    if layout.proof_ring_degree == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof ring degree must be positive",
        ));
    }

    Ok(())
}

fn generated_lnp_tbox_gaussian_l2_squared_bound(
    coefficient_count: u64,
    log2_standard_deviation: usize,
) -> CanonicalResult<BigUint> {
    let doubled_exponent = log2_standard_deviation
        .checked_mul(2)
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian bound exponent overflowed"))?;
    let numerator = BigUint::from(
        SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR
            * 2
            * coefficient_count,
    ) << doubled_exponent;
    let denominator = BigUint::from(
        SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR,
    );

    Ok(numerator / denominator)
}

fn verify_generated_lnp_tbox_suffix_bytes(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    proof_bytes: &[u8],
) -> CanonicalResult<()> {
    let prefix_byte_count = setup_proof_lnp_tbox_commitment_prefix_byte_count(layout)?;
    let Some(prefix_bytes) = proof_bytes.get(..prefix_byte_count) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof LNP tbox proof ended before the commitment prefix",
        ));
    };
    let actual_suffix_bytes = proof_bytes.get(prefix_byte_count..).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof LNP tbox proof ended before the generated suffix",
        )
    })?;
    let expected_suffix_bytes = setup_proof_lnp_tbox_generated_suffix_bytes(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        prefix_bytes,
    )?;
    if actual_suffix_bytes != expected_suffix_bytes.as_slice() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof LNP tbox generated suffix does not match the lower-protocol transcript",
        ));
    }

    Ok(())
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn decode_hint_polyvec(
    reader: &mut LnpBitReader<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
) -> CanonicalResult<Vec<LnpTboxHintCoefficient>> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP hint coefficient count overflowed"))?;
    let mut coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let first_bit = reader.read_bit()?;
        let second_bit = reader.read_bit()?;
        let mut extension_zero_count = 0_usize;
        if first_bit && second_bit {
            while !reader.read_bit()? {
                extension_zero_count = extension_zero_count.checked_add(1).ok_or_else(|| {
                    setup_proof_error("setup proof LNP hint unary extension overflowed")
                })?;
            }
        }
        let value = decode_lnp_tbox_hint_value(first_bit, second_bit, extension_zero_count)?;
        coefficients.push(LnpTboxHintCoefficient {
            first_bit,
            second_bit,
            extension_zero_count,
            value,
        });
    }

    Ok(coefficients)
}

pub(super) fn decode_lnp_tbox_hint_value(
    first_bit: bool,
    second_bit: bool,
    extension_zero_count: usize,
) -> CanonicalResult<i64> {
    match (first_bit, second_bit) {
        (false, false) => Ok(0),
        (false, true) => Ok(1),
        (true, false) => Ok(-1),
        (true, true) => {
            let extension = i64::try_from(extension_zero_count).map_err(|_| {
                setup_proof_error("setup proof LNP hint extension does not fit i64")
            })?;
            if extension_zero_count.is_multiple_of(2) {
                extension
                    .checked_add(4)
                    .and_then(|value| value.checked_div(2))
                    .ok_or_else(|| setup_proof_error("setup proof LNP hint value overflowed"))
            } else {
                extension
                    .checked_add(3)
                    .and_then(|value| value.checked_div(2))
                    .and_then(i64::checked_neg)
                    .ok_or_else(|| setup_proof_error("setup proof LNP hint value overflowed"))
            }
        }
    }
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn decode_gaussian_polyvec(
    reader: &mut LnpBitReader<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
    log2_standard_deviation: usize,
    field_name: &str,
) -> CanonicalResult<Vec<LnpTboxGaussianCoefficient>> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| {
            setup_proof_error(format!(
                "setup proof LNP {field_name} coefficient count overflowed",
            ))
        })?;
    let low_bit_count = log2_standard_deviation.checked_add(1).ok_or_else(|| {
        setup_proof_error(format!(
            "setup proof LNP {field_name} low-bit count overflowed",
        ))
    })?;
    let mut coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let mut unary_ones = 0_usize;
        while reader.read_bit()? {
            unary_ones = unary_ones.checked_add(1).ok_or_else(|| {
                setup_proof_error(format!(
                    "setup proof LNP {field_name} unary coefficient overflowed"
                ))
            })?;
        }
        let low_bits = reader.read_u64_le_bits(low_bit_count)?;
        let value = decode_lnp_tbox_gaussian_value(unary_ones, low_bits, low_bit_count)?;
        coefficients.push(LnpTboxGaussianCoefficient {
            unary_ones,
            low_bits,
            low_bit_count,
            value,
        });
    }

    Ok(coefficients)
}

pub(super) fn decode_lnp_tbox_gaussian_value(
    unary_ones: usize,
    low_bits: u64,
    low_bit_count: usize,
) -> CanonicalResult<i128> {
    if low_bit_count == 0 || low_bit_count > 127 {
        return Err(setup_proof_error(
            "setup proof LNP Gaussian low-bit count is outside the supported range",
        ));
    }
    let quotient_magnitude = i128::try_from(unary_ones / 2).map_err(|_| {
        setup_proof_error("setup proof LNP Gaussian unary quotient does not fit i128")
    })?;
    let quotient = if unary_ones.is_multiple_of(2) {
        quotient_magnitude.checked_neg().ok_or_else(|| {
            setup_proof_error("setup proof LNP Gaussian quotient negation overflowed")
        })?
    } else {
        quotient_magnitude
            .checked_add(1)
            .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian quotient overflowed"))?
    };
    let range = 1_i128
        .checked_shl(u32::try_from(low_bit_count).map_err(|_| {
            setup_proof_error("setup proof LNP Gaussian low-bit count does not fit u32")
        })?)
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian range overflowed"))?;
    let low_value = decode_twos_complement_bits(low_bits, low_bit_count)?;

    quotient
        .checked_mul(range)
        .and_then(|high_value| high_value.checked_add(low_value))
        .ok_or_else(|| setup_proof_error("setup proof LNP Gaussian value overflowed"))
}

fn decode_twos_complement_bits(value: u64, bit_count: usize) -> CanonicalResult<i128> {
    if bit_count == 0 || bit_count > u64::BITS as usize {
        return Err(setup_proof_error(
            "setup proof LNP two's-complement bit count is outside the supported range",
        ));
    }
    let unsigned_value = i128::from(value);
    let sign_bit = 1_u64
        .checked_shl(
            u32::try_from(bit_count - 1)
                .map_err(|_| setup_proof_error("setup proof LNP sign-bit index overflowed"))?,
        )
        .ok_or_else(|| setup_proof_error("setup proof LNP sign bit overflowed"))?;
    if value & sign_bit == 0 {
        return Ok(unsigned_value);
    }

    let range = 1_i128
        .checked_shl(u32::try_from(bit_count).map_err(|_| {
            setup_proof_error("setup proof LNP two's-complement range bit count overflowed")
        })?)
        .ok_or_else(|| setup_proof_error("setup proof LNP two's-complement range overflowed"))?;
    unsigned_value
        .checked_sub(range)
        .ok_or_else(|| setup_proof_error("setup proof LNP two's-complement value overflowed"))
}

fn gaussian_coefficient_prefix<'a>(
    coefficients: &'a [LnpTboxGaussianCoefficient],
    prefix_count: usize,
    field_name: &str,
) -> CanonicalResult<&'a [LnpTboxGaussianCoefficient]> {
    coefficients.get(..prefix_count).ok_or_else(|| {
        setup_proof_error(format!(
            "setup proof LNP tbox {field_name} vector is too short for the z3/z4 check window",
        ))
    })
}

pub(super) fn verify_lnp_tbox_z34_norm_bounds(
    layout: &SetupProofLnpTboxLayout,
    z3_l2_squared: &BigUint,
    z4_infinity_norm: &BigUint,
) -> CanonicalResult<()> {
    let z3_l2_squared_bound = setup_proof_lnp_tbox_z3_l2_squared_bound(layout)?;
    if z3_l2_squared > &z3_l2_squared_bound {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof LNP tbox z3 L2-squared exceeds the generated check_z34 bound",
        ));
    }

    let z4_infinity_norm_bound = setup_proof_lnp_tbox_z4_infinity_norm_bound(layout)?;
    if z4_infinity_norm > &z4_infinity_norm_bound {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof LNP tbox z4 infinity norm exceeds the generated check_z34 bound",
        ));
    }

    Ok(())
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn setup_proof_challenge_modulus() -> BigUint {
    BigUint::from(
        SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .expect("fixed challenge modulus fits u64"),
    )
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn big_uint_to_u64(value: &BigUint, label: &str) -> CanonicalResult<u64> {
    let digits = value.to_u64_digits();
    match digits.as_slice() {
        [] => Ok(0),
        [digit] => Ok(*digit),
        _ => Err(setup_proof_error(format!("{label} does not fit u64"))),
    }
}
