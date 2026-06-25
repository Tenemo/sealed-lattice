use super::super::*;
use super::*;
use crate::bgv::setup::compact_vss_commitment::{
    COMPACT_VSS_OUTPUT_COORDINATE_COUNT, COMPACT_VSS_RANDOMNESS_COLUMN_COUNT,
    CompactProjectionTermsInput, compact_projection_terms,
};

const COMPACT_VSS_MESSAGE_COLUMN_LABEL: &str = "message";

#[derive(Clone)]
pub(crate) struct CompactVssShareLinkageCommitment {
    pub(crate) coordinates_by_commitment_modulus: Vec<Vec<u64>>,
}

pub(crate) struct CompactVssShareLinkagePublicVectorInput<'a> {
    pub(crate) public_matrix_seed_hash: &'a str,
    pub(crate) rns_limb_index: usize,
    pub(crate) commitment_modulus_index: usize,
    pub(crate) modulus: u64,
    pub(crate) source_message_modulus: u64,
    pub(crate) recipient_roster_position: u64,
    pub(crate) ring_degree: usize,
    pub(crate) coefficient_commitments: &'a [CompactVssShareLinkageCommitment],
    pub(crate) recipient_share_commitment: &'a CompactVssShareLinkageCommitment,
    pub(crate) relation_alpha: &'a [ChallengeExtensionElement],
}

// Compact source-to-recipient share linkage vectors for one commitment field.
// The vector order is every Shamir coefficient message, the recipient share
// message, the recipient share carry, every coefficient opening-randomness
// column, and finally the recipient share opening-randomness columns.
pub(crate) fn build_compact_vss_share_linkage_public_vectors(
    input: CompactVssShareLinkagePublicVectorInput<'_>,
    tower: &ChallengeExtensionTower,
) -> CanonicalResult<(
    ChallengeExtensionElement,
    Vec<Vec<ChallengeExtensionElement>>,
)> {
    if input.ring_degree == 0 {
        return Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage ring degree must be positive",
        ));
    }
    if input.source_message_modulus == 0 {
        return Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage source modulus must be positive",
        ));
    }
    if input.coefficient_commitments.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage requires coefficient commitments",
        ));
    }
    if tower.modulus != input.modulus {
        return Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage tower modulus does not match the commitment field",
        ));
    }
    for commitment in input
        .coefficient_commitments
        .iter()
        .chain(std::iter::once(input.recipient_share_commitment))
    {
        let coordinates = commitment
            .coordinates_by_commitment_modulus
            .get(input.commitment_modulus_index)
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "compact VSS commitment does not cover the selected commitment field",
                )
            })?;
        if coordinates.len() != COMPACT_VSS_OUTPUT_COORDINATE_COUNT {
            return Err(invalid_succinct_setup_proof(
                "compact VSS commitment coordinate count does not match the profile",
            ));
        }
        if coordinates
            .iter()
            .any(|coordinate| *coordinate >= input.modulus)
        {
            return Err(invalid_succinct_setup_proof(
                "compact VSS commitment coordinate is outside the commitment field",
            ));
        }
    }

    let commitment_count = input.coefficient_commitments.len() + 1;
    let commitment_relation_count = commitment_count * COMPACT_VSS_OUTPUT_COORDINATE_COUNT;
    let share_relation_index = commitment_relation_count;
    let relation_count = commitment_relation_count + 1;
    if input.relation_alpha.len() != relation_count {
        return Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage challenge count does not match the relation count",
        ));
    }

    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); input.ring_degree];
    let mut relation_claim = ChallengeExtensionTower::zero();
    let mut coefficient_message_vectors =
        vec![extension_zero_vector(); input.coefficient_commitments.len()];
    let mut recipient_share_message_vector = extension_zero_vector();
    let mut recipient_share_carry_vector = extension_zero_vector();
    let mut coefficient_randomness_vectors = vec![
        extension_zero_vector();
        input.coefficient_commitments.len()
            * COMPACT_VSS_RANDOMNESS_COLUMN_COUNT
    ];
    let mut recipient_share_randomness_vectors =
        vec![extension_zero_vector(); COMPACT_VSS_RANDOMNESS_COLUMN_COUNT];

    for (commitment_index, commitment) in input
        .coefficient_commitments
        .iter()
        .chain(std::iter::once(input.recipient_share_commitment))
        .enumerate()
    {
        let coordinates =
            &commitment.coordinates_by_commitment_modulus[input.commitment_modulus_index];
        for (output_coordinate_index, coordinate) in coordinates.iter().enumerate() {
            let alpha_value = &input.relation_alpha
                [commitment_index * COMPACT_VSS_OUTPUT_COORDINATE_COUNT + output_coordinate_index];
            relation_claim =
                tower.add(&relation_claim, &tower.scale_base(alpha_value, *coordinate));
            let message_vector = if commitment_index < input.coefficient_commitments.len() {
                &mut coefficient_message_vectors[commitment_index]
            } else {
                &mut recipient_share_message_vector
            };
            add_compact_projection_vector(
                AddCompactProjectionVectorInput {
                    target: message_vector,
                    scale: alpha_value,
                    public_matrix_seed_hash: input.public_matrix_seed_hash,
                    rns_limb_index: input.rns_limb_index,
                    commitment_modulus_index: input.commitment_modulus_index,
                    output_coordinate_index,
                    input_column: COMPACT_VSS_MESSAGE_COLUMN_LABEL,
                    ring_degree: input.ring_degree,
                    modulus: input.modulus,
                },
                tower,
            )?;
            for randomness_column_index in 0..COMPACT_VSS_RANDOMNESS_COLUMN_COUNT {
                let input_column = format!("randomness:{randomness_column_index}");
                let randomness_vector = if commitment_index < input.coefficient_commitments.len() {
                    &mut coefficient_randomness_vectors[commitment_index
                        * COMPACT_VSS_RANDOMNESS_COLUMN_COUNT
                        + randomness_column_index]
                } else {
                    &mut recipient_share_randomness_vectors[randomness_column_index]
                };
                add_compact_projection_vector(
                    AddCompactProjectionVectorInput {
                        target: randomness_vector,
                        scale: alpha_value,
                        public_matrix_seed_hash: input.public_matrix_seed_hash,
                        rns_limb_index: input.rns_limb_index,
                        commitment_modulus_index: input.commitment_modulus_index,
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

    let trustee_point = canonical_trustee_point(
        usize::try_from(input.recipient_roster_position).map_err(|_| {
            invalid_succinct_setup_proof("compact VSS recipient roster position does not fit usize")
        })?,
        input.source_message_modulus,
    )?;
    let mut trustee_point_power = 1_u128;
    let share_alpha = &input.relation_alpha[share_relation_index];
    for coefficient_message_vector in &mut coefficient_message_vectors {
        let power_modulus_residue = (trustee_point_power % u128::from(input.modulus)) as u64;
        add_scaled_basis_vector(
            coefficient_message_vector,
            share_alpha,
            power_modulus_residue,
            tower,
        );
        trustee_point_power = trustee_point_power
            .checked_mul(u128::from(trustee_point))
            .ok_or_else(|| {
                invalid_succinct_setup_proof("compact VSS trustee point power overflowed")
            })?;
    }
    add_scaled_basis_vector(
        &mut recipient_share_message_vector,
        share_alpha,
        input.modulus - 1,
        tower,
    );
    let source_modulus_residue = input.source_message_modulus % input.modulus;
    let negated_source_modulus = if source_modulus_residue == 0 {
        0
    } else {
        input.modulus - source_modulus_residue
    };
    add_scaled_basis_vector(
        &mut recipient_share_carry_vector,
        share_alpha,
        negated_source_modulus,
        tower,
    );

    let mut vectors = Vec::with_capacity(
        input.coefficient_commitments.len()
            + 2
            + coefficient_randomness_vectors.len()
            + recipient_share_randomness_vectors.len(),
    );
    vectors.extend(coefficient_message_vectors);
    vectors.push(recipient_share_message_vector);
    vectors.push(recipient_share_carry_vector);
    vectors.extend(coefficient_randomness_vectors);
    vectors.extend(recipient_share_randomness_vectors);

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

fn add_scaled_basis_vector(
    target: &mut [ChallengeExtensionElement],
    scale: &ChallengeExtensionElement,
    coefficient: u64,
    tower: &ChallengeExtensionTower,
) {
    for target_value in target {
        *target_value = tower.add(target_value, &tower.scale_base(scale, coefficient));
    }
}
