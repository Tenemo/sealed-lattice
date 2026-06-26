use super::super::*;
use super::*;
use crate::bgv::setup::compact_vss_commitment::{
    COMPACT_VSS_OUTPUT_COORDINATE_COUNT, COMPACT_VSS_RANDOMNESS_COLUMN_COUNT,
    CompactProjectionTermsInput, compact_projection_terms,
};

const TARGET_DECRYPTION_MESSAGE_COLUMN_LABEL: &str = "message";

pub(crate) struct TargetDecryptionSharePublicVectorInput<'a> {
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

    let smudging_commitment_count = input.statement.smudging_commitments.len();
    let message_count = 1 + smudging_commitment_count;
    let randomness_count = message_count * COMPACT_VSS_RANDOMNESS_COLUMN_COUNT;
    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); input.ring_degree];
    let mut relation_claim = ChallengeExtensionTower::zero();
    let mut message_vectors = vec![extension_zero_vector(); message_count];
    let mut randomness_vectors = vec![extension_zero_vector(); randomness_count];

    let commitment_relation_count =
        if input.limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
            message_count * COMPACT_VSS_OUTPUT_COORDINATE_COUNT
        } else {
            0
        };
    let target_relation_count = if input.limb_index == input.statement.target_rns_limb_index {
        LINCHECK_REPETITIONS
    } else {
        0
    };
    if input.relation_alpha.len() != commitment_relation_count + target_relation_count {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share challenge count does not match the relation count",
        ));
    }

    if commitment_relation_count > 0 {
        for (commitment_index, commitment) in std::iter::once(&input.statement.aggregate_commitment)
            .chain(input.statement.smudging_commitments.iter())
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
            if coordinates.len() != COMPACT_VSS_OUTPUT_COORDINATE_COUNT {
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
                let alpha_index = commitment_index * COMPACT_VSS_OUTPUT_COORDINATE_COUNT
                    + output_coordinate_index;
                let alpha_value = &input.relation_alpha[alpha_index];
                relation_claim =
                    tower.add(&relation_claim, &tower.scale_base(alpha_value, *coordinate));
                add_compact_projection_vector(
                    AddCompactProjectionVectorInput {
                        target: &mut message_vectors[commitment_index],
                        scale: alpha_value,
                        public_matrix_seed_hash: &input.statement.public_matrix_seed_hash,
                        rns_limb_index: input.statement.target_rns_limb_index,
                        commitment_modulus_index: input.limb_index,
                        output_coordinate_index,
                        input_column: TARGET_DECRYPTION_MESSAGE_COLUMN_LABEL,
                        ring_degree: input.ring_degree,
                        modulus: input.modulus,
                    },
                    tower,
                )?;
                for randomness_column_index in 0..COMPACT_VSS_RANDOMNESS_COLUMN_COUNT {
                    let input_column = format!("randomness:{randomness_column_index}");
                    let randomness_index = commitment_index * COMPACT_VSS_RANDOMNESS_COLUMN_COUNT
                        + randomness_column_index;
                    add_compact_projection_vector(
                        AddCompactProjectionVectorInput {
                            target: &mut randomness_vectors[randomness_index],
                            scale: alpha_value,
                            public_matrix_seed_hash: &input.statement.public_matrix_seed_hash,
                            rns_limb_index: input.statement.target_rns_limb_index,
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

    if target_relation_count > 0 {
        if input.statement.target_ciphertext_component_one.len() != input.ring_degree
            || input.statement.released_partial_decryption.len() != input.ring_degree
        {
            return Err(invalid_succinct_setup_proof(
                "target-decryption share target vectors do not match the ring degree",
            ));
        }
        let interpolation_point = input.statement.interpolation_point % input.modulus;
        let plaintext_multiple = input.statement.plaintext_multiple % input.modulus;
        let coefficient_offset = signed_value_residue(
            input.statement.smudging_signed_coefficient_offset,
            input.modulus,
        );
        let mut interpolation_power = interpolation_point;
        let mut smudging_scales = Vec::with_capacity(smudging_commitment_count);
        for _ in 0..smudging_commitment_count {
            smudging_scales.push(mul_mod_fast(
                plaintext_multiple,
                interpolation_power,
                input.modulus,
            ));
            interpolation_power =
                mul_mod_fast(interpolation_power, interpolation_point, input.modulus);
        }

        for (repetition, u_powers) in input.u_power_vectors.iter().enumerate() {
            let alpha_value = &input.relation_alpha[commitment_relation_count + repetition];
            let scaled_u = u_powers
                .iter()
                .map(|value| tower.mul(alpha_value, value))
                .collect::<Vec<_>>();
            let aggregate_factor = negacyclic_transpose_product_extension(
                &input.statement.target_ciphertext_component_one,
                &scaled_u,
                input.modulus,
            )?;
            add_extension_vector(&mut message_vectors[0], &aggregate_factor, tower);

            let mut scaled_u_sum = ChallengeExtensionTower::zero();
            for (scaled_u_value, released_partial) in scaled_u
                .iter()
                .zip(input.statement.released_partial_decryption.iter())
            {
                relation_claim = tower.add(
                    &relation_claim,
                    &tower.scale_base(scaled_u_value, *released_partial),
                );
                scaled_u_sum = tower.add(&scaled_u_sum, scaled_u_value);
            }

            for (smudging_index, smudging_scale) in smudging_scales.iter().enumerate() {
                add_scaled_extension_basis_vector(
                    &mut message_vectors[1 + smudging_index],
                    &scaled_u,
                    *smudging_scale,
                    tower,
                );
                let offset_scale = mul_mod_fast(*smudging_scale, coefficient_offset, input.modulus);
                relation_claim = tower.add(
                    &relation_claim,
                    &tower.scale_base(&scaled_u_sum, offset_scale),
                );
            }
        }
    }

    let mut vectors = Vec::with_capacity(message_vectors.len() + randomness_vectors.len());
    vectors.extend(message_vectors);
    vectors.extend(randomness_vectors);

    Ok((relation_claim, vectors))
}

struct AddCompactProjectionVectorInput<'a, 'b> {
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

fn add_compact_projection_vector(
    input: AddCompactProjectionVectorInput<'_, '_>,
    tower: &ChallengeExtensionTower,
) -> CanonicalResult<()> {
    for (ring_coefficient_index, matrix_residue) in
        compact_projection_terms(CompactProjectionTermsInput {
            public_matrix_seed_hash: input.public_matrix_seed_hash,
            rns_limb_index: input.rns_limb_index,
            commitment_modulus_index: input.commitment_modulus_index,
            output_coordinate_index: input.output_coordinate_index,
            input_column: input.input_column,
            ring_degree: input.ring_degree,
            modulus: input.modulus,
        })?
    {
        input.target[ring_coefficient_index] = tower.add(
            &input.target[ring_coefficient_index],
            &tower.scale_base(input.scale, matrix_residue),
        );
    }

    Ok(())
}

fn add_extension_vector(
    target: &mut [ChallengeExtensionElement],
    source: &[ChallengeExtensionElement],
    tower: &ChallengeExtensionTower,
) {
    for (target_value, source_value) in target.iter_mut().zip(source.iter()) {
        *target_value = tower.add(target_value, source_value);
    }
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
