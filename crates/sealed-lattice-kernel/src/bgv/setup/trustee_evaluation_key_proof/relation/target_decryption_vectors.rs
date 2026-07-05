use super::super::*;
use super::*;
use crate::bgv::setup::vss_commitment::{
    ProjectionTermsInput, VSS_PUBLIC_MESSAGE_DIGIT_COUNT, VSS_PUBLIC_OUTPUT_COORDINATE_COUNT,
    VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT, VssPublicMessageEncodingLayout, projection_terms,
    vss_public_message_digit_column_label, vss_public_message_digit_weight,
};

fn vss_public_message_encoding_offsets(
    layouts: &[VssPublicMessageEncodingLayout],
) -> CanonicalResult<Vec<usize>> {
    let mut offsets = Vec::with_capacity(layouts.len() + 1);
    let mut offset = 0_usize;
    offsets.push(offset);
    for layout in layouts {
        offset = offset
            .checked_add(layout.encoding_column_count())
            .ok_or_else(|| {
                invalid_succinct_setup_proof("target-decryption vector layout overflowed")
            })?;
        offsets.push(offset);
    }

    Ok(offsets)
}

fn vss_public_message_encoding_total(offsets: &[usize]) -> usize {
    offsets.last().copied().unwrap_or(0)
}

fn target_decryption_message_vector_index(
    offsets: &[usize],
    message_index: usize,
    encoding_column: usize,
) -> CanonicalResult<usize> {
    let start = offsets.get(message_index).copied().ok_or_else(|| {
        invalid_succinct_setup_proof("target-decryption message index is outside the vector layout")
    })?;
    let end = offsets.get(message_index + 1).copied().ok_or_else(|| {
        invalid_succinct_setup_proof("target-decryption message index is outside the vector layout")
    })?;
    if start + encoding_column >= end {
        return Err(invalid_succinct_setup_proof(
            "target-decryption message encoding column is outside the vector layout",
        ));
    }

    Ok(start + encoding_column)
}

fn target_decryption_decoder_digit_count(
    layout: VssPublicMessageEncodingLayout,
) -> CanonicalResult<usize> {
    let mut count = 0_usize;
    for digit_index in 0..VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
        if layout.digit_trit_count(digit_index)? > 0 {
            count += 1;
        }
    }

    Ok(count)
}

pub(crate) struct TargetDecryptionSharePublicVectorInput<'a> {
    pub(crate) proof_statement: &'a TrusteeEvaluationKeyStatement,
    pub(crate) statement: &'a TargetDecryptionShareStatement,
    pub(crate) limb_index: usize,
    pub(crate) modulus: u64,
    pub(crate) ring_degree: usize,
    pub(crate) relation_alpha: &'a [ChallengeExtensionElement],
    pub(crate) u_power_vectors: &'a [Vec<ChallengeExtensionElement>],
}

pub(crate) fn build_target_decryption_share_public_vectors(
    input: TargetDecryptionSharePublicVectorInput<'_>,
    tower: &ChallengeExtensionTower,
) -> CanonicalResult<(
    ChallengeExtensionElement,
    Vec<Vec<ChallengeExtensionElement>>,
)> {
    if tower.modulus != input.modulus {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share tower modulus does not match the active field",
        ));
    }
    if input.ring_degree == 0 {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share ring degree must be positive",
        ));
    }
    if input.u_power_vectors.len() != LINCHECK_REPETITIONS {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share lincheck repetition count does not match the profile",
        ));
    }
    if input
        .u_power_vectors
        .iter()
        .any(|vector| vector.len() != input.ring_degree)
    {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share lincheck vector length does not match the ring degree",
        ));
    }

    let message_count = input
        .proof_statement
        .target_decryption_message_count(input.limb_index);
    let message_global_indices = (0..message_count)
        .map(|local_message_index| {
            input
                .proof_statement
                .target_decryption_message_global_index(input.limb_index, local_message_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "target-decryption message column is missing from the statement layout",
                    )
                })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let message_encoding_layouts = message_global_indices
        .iter()
        .map(|global_message_index| {
            input
                .proof_statement
                .target_decryption_message_encoding_layout(input.limb_index, *global_message_index)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let message_encoding_offsets = vss_public_message_encoding_offsets(&message_encoding_layouts)?;
    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); input.ring_degree];
    let mut relation_claim = ChallengeExtensionTower::zero();
    let mut message_encoding_vectors =
        vec![extension_zero_vector(); vss_public_message_encoding_total(&message_encoding_offsets)];

    let commitment_relation_count =
        if input.limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
            message_count * VSS_PUBLIC_OUTPUT_COORDINATE_COUNT
        } else {
            0
        };
    let randomness_count = input
        .proof_statement
        .target_decryption_randomness_count(input.limb_index);
    let mut randomness_vectors = vec![extension_zero_vector(); randomness_count];
    let active_target_limb = input
        .statement
        .limb_statements
        .iter()
        .find(|limb_statement| limb_statement.target_rns_limb_index == input.limb_index);
    let target_relation_count = active_target_limb
        .map(|limb_statement| limb_statement.role_statements.len() * LINCHECK_REPETITIONS)
        .unwrap_or(0);
    let decoder_relation_count =
        message_encoding_layouts
            .iter()
            .try_fold(0_usize, |sum, layout| {
                sum.checked_add(target_decryption_decoder_digit_count(*layout)?)
                    .ok_or_else(|| {
                        invalid_succinct_setup_proof(
                            "target-decryption decoder relation count overflowed",
                        )
                    })
            })?
            * LINCHECK_REPETITIONS;
    let decoder_relation_offset = commitment_relation_count + target_relation_count;
    if input.relation_alpha.len() != decoder_relation_offset + decoder_relation_count {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share challenge count does not match the relation count",
        ));
    }

    if commitment_relation_count > 0 {
        for (commitment_index, (target_rns_limb_index, commitment)) in input
            .statement
            .limb_statements
            .iter()
            .flat_map(|limb_statement| {
                std::iter::once((
                    limb_statement.target_rns_limb_index,
                    &limb_statement.aggregate_commitment,
                ))
                .chain(limb_statement.role_statements.iter().flat_map(
                    move |role_statement| {
                        role_statement
                            .smudging_commitments
                            .iter()
                            .map(move |commitment| {
                                (limb_statement.target_rns_limb_index, commitment)
                            })
                    },
                ))
            })
            .enumerate()
        {
            let coordinates = commitment
                .coordinates_by_commitment_modulus
                .get(input.limb_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "target-decryption compact commitment does not cover the commitment field",
                    )
                })?;
            if coordinates.len() != VSS_PUBLIC_OUTPUT_COORDINATE_COUNT {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption compact commitment coordinate count does not match the profile",
                ));
            }
            for (output_coordinate_index, coordinate) in coordinates.iter().enumerate() {
                if *coordinate >= input.modulus {
                    return Err(invalid_succinct_setup_proof(
                        "target-decryption compact commitment coordinate is outside the commitment field",
                    ));
                }
                let alpha_index =
                    commitment_index * VSS_PUBLIC_OUTPUT_COORDINATE_COUNT + output_coordinate_index;
                let alpha_value = &input.relation_alpha[alpha_index];
                relation_claim =
                    tower.add(&relation_claim, &tower.scale_base(alpha_value, *coordinate));
                for digit_index in 0..VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
                    let input_column = vss_public_message_digit_column_label(digit_index)?;
                    let digit_vector_index = target_decryption_message_vector_index(
                        &message_encoding_offsets,
                        commitment_index,
                        message_encoding_layouts[commitment_index]
                            .digit_encoding_column(digit_index)?,
                    )?;
                    add_projection_vector(
                        AddProjectionVectorInput {
                            target: &mut message_encoding_vectors[digit_vector_index],
                            scale: alpha_value,
                            public_matrix_seed_hash: &input.statement.public_matrix_seed_hash,
                            rns_limb_index: target_rns_limb_index,
                            commitment_modulus_index: input.limb_index,
                            output_coordinate_index,
                            input_column: &input_column,
                            ring_degree: input.ring_degree,
                            modulus: input.modulus,
                        },
                        tower,
                    )?;
                }
                for randomness_column_index in 0..VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT {
                    let input_column = format!("randomness:{randomness_column_index}");
                    let randomness_index = commitment_index * VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT
                        + randomness_column_index;
                    add_projection_vector(
                        AddProjectionVectorInput {
                            target: &mut randomness_vectors[randomness_index],
                            scale: alpha_value,
                            public_matrix_seed_hash: &input.statement.public_matrix_seed_hash,
                            rns_limb_index: target_rns_limb_index,
                            commitment_modulus_index: input.limb_index,
                            output_coordinate_index,
                            input_column: &input_column,
                            ring_degree: input.ring_degree,
                            modulus: input.modulus,
                        },
                        tower,
                    )?;
                }
            }
        }
    }

    if let Some(limb_statement) = active_target_limb {
        let interpolation_point = input.statement.interpolation_point % input.modulus;
        let plaintext_multiple = input.statement.plaintext_multiple % input.modulus;
        let coefficient_offset = signed_value_residue(
            input.statement.smudging_signed_coefficient_offset,
            input.modulus,
        );
        let limb_message_offset = input
            .proof_statement
            .target_decryption_local_message_offset(
                input.limb_index,
                limb_statement.target_rns_limb_index,
            )
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "target-decryption message columns are missing for the active target limb",
                )
            })?;
        let mut smudging_message_offset = limb_message_offset + 1;
        for (role_index, role_statement) in limb_statement.role_statements.iter().enumerate() {
            if role_statement.target_ciphertext_component_one.len() != input.ring_degree
                || role_statement.released_partial_decryption.len() != input.ring_degree
            {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption share target vectors do not match the ring degree",
                ));
            }
            let mut interpolation_power = interpolation_point;
            let mut smudging_scales = Vec::with_capacity(role_statement.smudging_commitments.len());
            for _ in 0..role_statement.smudging_commitments.len() {
                smudging_scales.push(mul_mod_fast(
                    plaintext_multiple,
                    interpolation_power,
                    input.modulus,
                ));
                interpolation_power =
                    mul_mod_fast(interpolation_power, interpolation_point, input.modulus);
            }

            for (repetition, u_powers) in input.u_power_vectors.iter().enumerate() {
                let alpha_value = &input.relation_alpha
                    [commitment_relation_count + role_index * LINCHECK_REPETITIONS + repetition];
                let scaled_u = u_powers
                    .iter()
                    .map(|value| tower.mul(alpha_value, value))
                    .collect::<Vec<_>>();
                let aggregate_factor = negacyclic_transpose_product_extension(
                    &role_statement.target_ciphertext_component_one,
                    &scaled_u,
                    input.modulus,
                )?;
                add_scaled_extension_vector_to_message_digits(
                    AddScaledExtensionVectorToMessageDigitsInput {
                        message_encoding_vectors: &mut message_encoding_vectors,
                        message_encoding_offsets: &message_encoding_offsets,
                        message_encoding_layouts: &message_encoding_layouts,
                        message_index: limb_message_offset,
                        source: &aggregate_factor,
                        coefficient: 1,
                        modulus: input.modulus,
                    },
                    tower,
                )?;

                let mut scaled_u_sum = ChallengeExtensionTower::zero();
                for (scaled_u_value, released_partial) in scaled_u
                    .iter()
                    .zip(role_statement.released_partial_decryption.iter())
                {
                    relation_claim = tower.add(
                        &relation_claim,
                        &tower.scale_base(scaled_u_value, *released_partial),
                    );
                    scaled_u_sum = tower.add(&scaled_u_sum, scaled_u_value);
                }

                for (smudging_index, smudging_scale) in smudging_scales.iter().enumerate() {
                    add_scaled_extension_vector_to_message_digits(
                        AddScaledExtensionVectorToMessageDigitsInput {
                            message_encoding_vectors: &mut message_encoding_vectors,
                            message_encoding_offsets: &message_encoding_offsets,
                            message_encoding_layouts: &message_encoding_layouts,
                            message_index: smudging_message_offset + smudging_index,
                            source: &scaled_u,
                            coefficient: *smudging_scale,
                            modulus: input.modulus,
                        },
                        tower,
                    )?;
                    let offset_scale =
                        mul_mod_fast(*smudging_scale, coefficient_offset, input.modulus);
                    relation_claim = tower.add(
                        &relation_claim,
                        &tower.scale_base(&scaled_u_sum, offset_scale),
                    );
                }
            }
            smudging_message_offset += role_statement.smudging_commitments.len();
        }
    }

    if decoder_relation_count > 0 {
        let mut decoder_relation_index = 0_usize;
        for (message_index, message_encoding_layout) in message_encoding_layouts.iter().enumerate()
        {
            for digit_index in 0..VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
                let trit_count = message_encoding_layout.digit_trit_count(digit_index)?;
                if trit_count == 0 {
                    continue;
                }
                for (repetition, u_powers) in input.u_power_vectors.iter().enumerate() {
                    let alpha_index = decoder_relation_offset
                        + decoder_relation_index * LINCHECK_REPETITIONS
                        + repetition;
                    let alpha_value = &input.relation_alpha[alpha_index];
                    let scaled_u = u_powers
                        .iter()
                        .map(|value| tower.mul(alpha_value, value))
                        .collect::<Vec<_>>();
                    let digit_vector_index = target_decryption_message_vector_index(
                        &message_encoding_offsets,
                        message_index,
                        message_encoding_layout.digit_encoding_column(digit_index)?,
                    )?;
                    add_scaled_extension_basis_vector(
                        &mut message_encoding_vectors[digit_vector_index],
                        &scaled_u,
                        1,
                        tower,
                    );
                    let mut trit_weight = 1_u64 % input.modulus;
                    for trit_index in 0..trit_count {
                        let trit_vector_index = target_decryption_message_vector_index(
                            &message_encoding_offsets,
                            message_index,
                            message_encoding_layout
                                .trit_encoding_column(digit_index, trit_index)?,
                        )?;
                        add_scaled_extension_basis_vector(
                            &mut message_encoding_vectors[trit_vector_index],
                            &scaled_u,
                            sub_mod_fast(0, trit_weight, input.modulus),
                            tower,
                        );
                        trit_weight = mul_mod_fast(trit_weight, 3, input.modulus);
                    }
                }
                decoder_relation_index += 1;
            }
        }
    }

    let mut vectors = Vec::with_capacity(message_encoding_vectors.len() + randomness_vectors.len());
    vectors.extend(message_encoding_vectors);
    vectors.extend(randomness_vectors);

    Ok((relation_claim, vectors))
}

struct AddProjectionVectorInput<'a, 'b> {
    target: &'a mut [ChallengeExtensionElement],
    scale: &'b ChallengeExtensionElement,
    public_matrix_seed_hash: &'b str,
    rns_limb_index: usize,
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    input_column: &'b str,
    ring_degree: usize,
    modulus: u64,
}

struct AddScaledExtensionVectorToMessageDigitsInput<'a> {
    message_encoding_vectors: &'a mut [Vec<ChallengeExtensionElement>],
    message_encoding_offsets: &'a [usize],
    message_encoding_layouts: &'a [VssPublicMessageEncodingLayout],
    message_index: usize,
    source: &'a [ChallengeExtensionElement],
    coefficient: u64,
    modulus: u64,
}

fn add_projection_vector(
    input: AddProjectionVectorInput<'_, '_>,
    tower: &ChallengeExtensionTower,
) -> CanonicalResult<()> {
    for (ring_coefficient_index, matrix_residue) in projection_terms(ProjectionTermsInput {
        public_matrix_seed_hash: input.public_matrix_seed_hash,
        rns_limb_index: input.rns_limb_index,
        commitment_modulus_index: input.commitment_modulus_index,
        output_coordinate_index: input.output_coordinate_index,
        input_column: input.input_column,
        ring_degree: input.ring_degree,
        modulus: input.modulus,
    })? {
        input.target[ring_coefficient_index] = tower.add(
            &input.target[ring_coefficient_index],
            &tower.scale_base(input.scale, matrix_residue),
        );
    }

    Ok(())
}

fn add_scaled_extension_basis_vector(
    target: &mut [ChallengeExtensionElement],
    source: &[ChallengeExtensionElement],
    coefficient: u64,
    tower: &ChallengeExtensionTower,
) {
    for (target_value, source_value) in target.iter_mut().zip(source.iter()) {
        *target_value = tower.add(target_value, &tower.scale_base(source_value, coefficient));
    }
}

fn add_scaled_extension_vector_to_message_digits(
    input: AddScaledExtensionVectorToMessageDigitsInput<'_>,
    tower: &ChallengeExtensionTower,
) -> CanonicalResult<()> {
    let message_encoding_layout = *input
        .message_encoding_layouts
        .get(input.message_index)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "target-decryption message index is outside the vector layout",
            )
        })?;
    for digit_index in 0..VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
        let digit_weight = vss_public_message_digit_weight(digit_index, input.modulus)?;
        let vector_index = target_decryption_message_vector_index(
            input.message_encoding_offsets,
            input.message_index,
            message_encoding_layout.digit_encoding_column(digit_index)?,
        )?;
        add_scaled_extension_basis_vector(
            &mut input.message_encoding_vectors[vector_index],
            input.source,
            mul_mod_fast(input.coefficient, digit_weight, input.modulus),
            tower,
        );
    }

    Ok(())
}
