use super::super::*;
use super::*;
use crate::bgv::setup::compact_vss_commitment::{
    COMPACT_VSS_MESSAGE_DIGIT_COUNT, COMPACT_VSS_OUTPUT_COORDINATE_COUNT,
    COMPACT_VSS_RANDOMNESS_COLUMN_COUNT, CompactProjectionTermsInput,
    CompactVssMessageEncodingLayout, compact_projection_terms,
    compact_vss_message_digit_column_label, compact_vss_message_digit_weight,
    compact_vss_message_encoding_layout,
};

#[derive(Clone, PartialEq, Eq)]
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
    pub(crate) u_power_vectors: &'a [Vec<ChallengeExtensionElement>],
}

struct CompactVssShareLinkageItemView<'a> {
    source_rns_limb_index: usize,
    source_message_modulus: u64,
    recipient_roster_position: u64,
    coefficient_commitments: &'a [CompactVssShareLinkageCommitment],
    coefficient_slot_indices: Vec<usize>,
    recipient_share_commitment: &'a CompactVssShareLinkageCommitment,
}

fn compact_vss_message_encoding_offsets(
    layouts: &[CompactVssMessageEncodingLayout],
) -> CanonicalResult<Vec<usize>> {
    let mut offsets = Vec::with_capacity(layouts.len() + 1);
    let mut offset = 0_usize;
    offsets.push(offset);
    for layout in layouts {
        offset = offset
            .checked_add(layout.encoding_column_count())
            .ok_or_else(|| invalid_succinct_setup_proof("compact VSS vector layout overflowed"))?;
        offsets.push(offset);
    }

    Ok(offsets)
}

fn compact_vss_message_vector_index(
    offsets: &[usize],
    message_index: usize,
    encoding_column: usize,
) -> CanonicalResult<usize> {
    let start = offsets.get(message_index).copied().ok_or_else(|| {
        invalid_succinct_setup_proof("compact VSS message index is outside the vector layout")
    })?;
    let end = offsets.get(message_index + 1).copied().ok_or_else(|| {
        invalid_succinct_setup_proof("compact VSS message index is outside the vector layout")
    })?;
    if start + encoding_column >= end {
        return Err(invalid_succinct_setup_proof(
            "compact VSS message encoding column is outside the vector layout",
        ));
    }

    Ok(start + encoding_column)
}

fn compact_vss_message_encoding_total(offsets: &[usize]) -> usize {
    offsets.last().copied().unwrap_or(0)
}

fn compact_vss_decoder_digit_count(layout: CompactVssMessageEncodingLayout) -> usize {
    (0..COMPACT_VSS_MESSAGE_DIGIT_COUNT)
        .filter(|digit_index| layout.digit_trit_count(*digit_index).unwrap_or(0) > 0)
        .count()
}

pub(crate) struct CompactSameSecretBridgePublicVectorInput<'a> {
    pub(crate) public_matrix_seed_hash: &'a str,
    pub(crate) commitment_modulus_index: usize,
    pub(crate) modulus: u64,
    pub(crate) ring_degree: usize,
    pub(crate) target_rns_primes: &'a [u64],
    pub(crate) target_constant_commitments: &'a [CompactVssShareLinkageCommitment],
    pub(crate) relation_alpha: &'a [ChallengeExtensionElement],
    pub(crate) u_power_vectors: &'a [Vec<ChallengeExtensionElement>],
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
    if input.u_power_vectors.len() != LINCHECK_REPETITIONS {
        return Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage lincheck repetition count does not match the profile",
        ));
    }
    if input
        .u_power_vectors
        .iter()
        .any(|vector| vector.len() != input.ring_degree)
    {
        return Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage lincheck vector length does not match the ring degree",
        ));
    }

    let commitment_relation_count = commitment_count * COMPACT_VSS_OUTPUT_COORDINATE_COUNT;
    let share_relation_count = LINCHECK_REPETITIONS;
    let coefficient_message_encoding_layout =
        compact_vss_message_encoding_layout(input.source_message_modulus)?;
    let recipient_message_encoding_layout =
        compact_vss_message_encoding_layout(input.source_message_modulus)?;
    let decoder_relation_count = (input.coefficient_commitments.len()
        * compact_vss_decoder_digit_count(coefficient_message_encoding_layout)
        + compact_vss_decoder_digit_count(recipient_message_encoding_layout))
        * LINCHECK_REPETITIONS;
    let decoder_relation_offset = commitment_relation_count + share_relation_count;
    let relation_count = decoder_relation_offset + decoder_relation_count;
    if input.relation_alpha.len() != relation_count {
        return Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage challenge count does not match the relation count",
        ));
    }

    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); input.ring_degree];
    let mut relation_claim = ChallengeExtensionTower::zero();
    let mut message_encoding_layouts =
        vec![coefficient_message_encoding_layout; input.coefficient_commitments.len()];
    message_encoding_layouts.push(recipient_message_encoding_layout);
    let message_encoding_offsets = compact_vss_message_encoding_offsets(&message_encoding_layouts)?;
    let mut message_encoding_vectors =
        vec![
            extension_zero_vector();
            compact_vss_message_encoding_total(&message_encoding_offsets)
        ];
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
            for digit_index in 0..COMPACT_VSS_MESSAGE_DIGIT_COUNT {
                let input_column = compact_vss_message_digit_column_label(digit_index)?;
                let message_encoding_layout = message_encoding_layouts[commitment_index];
                let digit_vector_index = compact_vss_message_vector_index(
                    &message_encoding_offsets,
                    commitment_index,
                    message_encoding_layout.digit_encoding_column(digit_index)?,
                )?;
                let digit_vector = &mut message_encoding_vectors[digit_vector_index];
                add_compact_projection_vector(
                    AddCompactProjectionVectorInput {
                        target: digit_vector,
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
    let source_modulus_residue = input.source_message_modulus % input.modulus;
    let negated_source_modulus = if source_modulus_residue == 0 {
        0
    } else {
        input.modulus - source_modulus_residue
    };
    for (repetition, u_powers) in input.u_power_vectors.iter().enumerate() {
        let share_alpha = &input.relation_alpha[commitment_relation_count + repetition];
        let mut combined_u = extension_zero_vector();
        for (target_value, source_value) in combined_u.iter_mut().zip(u_powers.iter()) {
            *target_value = tower.add(target_value, &tower.mul(share_alpha, source_value));
        }
        let mut trustee_point_power = 1_u128;
        for (coefficient_index, message_encoding_layout) in message_encoding_layouts
            .iter()
            .copied()
            .take(input.coefficient_commitments.len())
            .enumerate()
        {
            let power_modulus_residue = (trustee_point_power % u128::from(input.modulus)) as u64;
            for digit_index in 0..COMPACT_VSS_MESSAGE_DIGIT_COUNT {
                let digit_weight = compact_vss_message_digit_weight(digit_index, input.modulus)?;
                let scale = mul_mod_fast(power_modulus_residue, digit_weight, input.modulus);
                let digit_vector_index = compact_vss_message_vector_index(
                    &message_encoding_offsets,
                    coefficient_index,
                    message_encoding_layout.digit_encoding_column(digit_index)?,
                )?;
                add_scaled_extension_basis_vector(
                    &mut message_encoding_vectors[digit_vector_index],
                    &combined_u,
                    scale,
                    tower,
                );
            }
            trustee_point_power = trustee_point_power
                .checked_mul(u128::from(trustee_point))
                .ok_or_else(|| {
                    invalid_succinct_setup_proof("compact VSS trustee point power overflowed")
                })?;
        }
        let recipient_message_index = input.coefficient_commitments.len();
        for digit_index in 0..COMPACT_VSS_MESSAGE_DIGIT_COUNT {
            let digit_weight = compact_vss_message_digit_weight(digit_index, input.modulus)?;
            let negated_digit_weight = if digit_weight == 0 {
                0
            } else {
                input.modulus - digit_weight
            };
            let digit_vector_index = compact_vss_message_vector_index(
                &message_encoding_offsets,
                recipient_message_index,
                recipient_message_encoding_layout.digit_encoding_column(digit_index)?,
            )?;
            add_scaled_extension_basis_vector(
                &mut message_encoding_vectors[digit_vector_index],
                &combined_u,
                negated_digit_weight,
                tower,
            );
        }
        add_scaled_extension_basis_vector(
            &mut recipient_share_carry_vector,
            &combined_u,
            negated_source_modulus,
            tower,
        );
    }

    if decoder_relation_count > 0 {
        let mut decoder_relation_index = 0_usize;
        for (message_index, message_encoding_layout) in message_encoding_layouts.iter().enumerate()
        {
            for digit_index in 0..COMPACT_VSS_MESSAGE_DIGIT_COUNT {
                let trit_count = message_encoding_layout.digit_trit_count(digit_index)?;
                if trit_count == 0 {
                    continue;
                }
                for (repetition, u_powers) in input.u_power_vectors.iter().enumerate() {
                    let alpha_index = decoder_relation_offset
                        + decoder_relation_index * LINCHECK_REPETITIONS
                        + repetition;
                    let alpha_value = &input.relation_alpha[alpha_index];
                    let mut combined_u = extension_zero_vector();
                    for (target_value, source_value) in combined_u.iter_mut().zip(u_powers.iter()) {
                        *target_value =
                            tower.add(target_value, &tower.mul(alpha_value, source_value));
                    }
                    let digit_vector_index = compact_vss_message_vector_index(
                        &message_encoding_offsets,
                        message_index,
                        message_encoding_layout.digit_encoding_column(digit_index)?,
                    )?;
                    add_scaled_extension_basis_vector(
                        &mut message_encoding_vectors[digit_vector_index],
                        &combined_u,
                        1,
                        tower,
                    );
                    let mut trit_weight = 1_u64 % input.modulus;
                    for trit_index in 0..trit_count {
                        let negated_trit_weight = if trit_weight == 0 {
                            0
                        } else {
                            input.modulus - trit_weight
                        };
                        let trit_vector_index = compact_vss_message_vector_index(
                            &message_encoding_offsets,
                            message_index,
                            message_encoding_layout
                                .trit_encoding_column(digit_index, trit_index)?,
                        )?;
                        add_scaled_extension_basis_vector(
                            &mut message_encoding_vectors[trit_vector_index],
                            &combined_u,
                            negated_trit_weight,
                            tower,
                        );
                        trit_weight = mul_mod_fast(trit_weight, 3, input.modulus);
                    }
                }
                decoder_relation_index += 1;
            }
        }
    }

    let mut vectors = Vec::with_capacity(
        message_encoding_vectors.len()
            + 1
            + coefficient_randomness_vectors.len()
            + recipient_share_randomness_vectors.len(),
    );
    vectors.extend(message_encoding_vectors);
    vectors.push(recipient_share_carry_vector);
    vectors.extend(coefficient_randomness_vectors);
    vectors.extend(recipient_share_randomness_vectors);

    Ok((relation_claim, vectors))
}

pub(crate) fn build_compact_vss_share_linkage_batch_public_vectors(
    statement: &CompactVssShareLinkageStatement,
    commitment_modulus_index: usize,
    modulus: u64,
    ring_degree: usize,
    relation_alpha: &[ChallengeExtensionElement],
    u_power_vectors: &[Vec<ChallengeExtensionElement>],
    tower: &ChallengeExtensionTower,
) -> CanonicalResult<(
    ChallengeExtensionElement,
    Vec<Vec<ChallengeExtensionElement>>,
)> {
    let coefficient_slot_indices_by_item = statement.coefficient_witness_slot_indices_by_item();
    let mut items = Vec::with_capacity(statement.item_count());
    items.push(CompactVssShareLinkageItemView {
        source_rns_limb_index: statement.source_rns_limb_index,
        source_message_modulus: statement.source_message_modulus,
        recipient_roster_position: statement.recipient_roster_position,
        coefficient_commitments: &statement.coefficient_commitments,
        coefficient_slot_indices: coefficient_slot_indices_by_item
            .first()
            .cloned()
            .unwrap_or_default(),
        recipient_share_commitment: &statement.recipient_share_commitment,
    });
    for (item, coefficient_slot_indices) in statement
        .additional_linkage_items
        .iter()
        .zip(coefficient_slot_indices_by_item.iter().skip(1))
    {
        items.push(CompactVssShareLinkageItemView {
            source_rns_limb_index: item.source_rns_limb_index,
            source_message_modulus: item.source_message_modulus,
            recipient_roster_position: item.recipient_roster_position,
            coefficient_commitments: &item.coefficient_commitments,
            coefficient_slot_indices: coefficient_slot_indices.clone(),
            recipient_share_commitment: &item.recipient_share_commitment,
        });
    }

    let expected_relation_count = items
        .iter()
        .map(|item| {
            let coefficient_layout =
                compact_vss_message_encoding_layout(item.source_message_modulus)?;
            let recipient_layout =
                compact_vss_message_encoding_layout(item.source_message_modulus)?;
            let decoder_relation_count = (item.coefficient_commitments.len()
                * compact_vss_decoder_digit_count(coefficient_layout)
                + compact_vss_decoder_digit_count(recipient_layout))
                * LINCHECK_REPETITIONS;
            Ok(
                (item.coefficient_commitments.len() + 1) * COMPACT_VSS_OUTPUT_COORDINATE_COUNT
                    + LINCHECK_REPETITIONS
                    + decoder_relation_count,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?
        .into_iter()
        .sum::<usize>();
    if relation_alpha.len() != expected_relation_count {
        return Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage challenge count does not match the batched relation count",
        ));
    }
    let proof_ring_degree = statement.packed_ring_degree(ring_degree)?;
    if u_power_vectors.len() != LINCHECK_REPETITIONS
        || u_power_vectors
            .iter()
            .any(|vector| vector.len() != proof_ring_degree)
    {
        return Err(invalid_succinct_setup_proof(
            "compact VSS batched lincheck vector length does not match the proof ring degree",
        ));
    }

    let mut relation_alpha_offset = 0_usize;
    let mut relation_claim = ChallengeExtensionTower::zero();
    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); proof_ring_degree];
    let coefficient_column_count = statement.unique_coefficient_witness_slot_count();
    let coefficient_slots = statement.coefficient_witness_slots();
    let message_bounds = statement.packed_message_bounds();
    if message_bounds.len() != coefficient_column_count + statement.item_count() {
        return Err(invalid_succinct_setup_proof(
            "compact VSS packed message bounds do not match the packed column layout",
        ));
    }
    let message_encoding_layouts = message_bounds
        .iter()
        .map(|message_bound| compact_vss_message_encoding_layout(*message_bound))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let message_encoding_offsets = compact_vss_message_encoding_offsets(&message_encoding_layouts)?;
    let mut message_encoding_vectors =
        vec![
            extension_zero_vector();
            compact_vss_message_encoding_total(&message_encoding_offsets)
        ];
    let mut recipient_share_carry_vectors = vec![extension_zero_vector(); statement.item_count()];
    let mut coefficient_randomness_vectors = vec![
        extension_zero_vector();
        coefficient_column_count
            * COMPACT_VSS_RANDOMNESS_COLUMN_COUNT
    ];
    let mut recipient_share_randomness_vectors =
        vec![extension_zero_vector(); statement.item_count() * COMPACT_VSS_RANDOMNESS_COLUMN_COUNT];

    for (item_index, item) in items.into_iter().enumerate() {
        if item.coefficient_slot_indices.len() != item.coefficient_commitments.len()
            || item
                .coefficient_slot_indices
                .iter()
                .any(|slot_index| *slot_index >= coefficient_slots.len())
        {
            return Err(invalid_succinct_setup_proof(
                "compact VSS coefficient witness slot layout does not match the item",
            ));
        }
        let item_coefficient_message_encoding_layout =
            compact_vss_message_encoding_layout(item.source_message_modulus)?;
        let item_recipient_message_encoding_layout =
            compact_vss_message_encoding_layout(item.source_message_modulus)?;
        for coefficient_slot_index in &item.coefficient_slot_indices {
            let message_encoding_layout = message_encoding_layouts
                .get(*coefficient_slot_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "compact VSS item coefficient slot is outside the packed column layout",
                    )
                })?;
            if message_encoding_layout.encoding_column_count()
                != item_coefficient_message_encoding_layout.encoding_column_count()
            {
                return Err(invalid_succinct_setup_proof(
                    "compact VSS item message layout does not match the packed column layout",
                ));
            }
        }
        let recipient_message_position = coefficient_column_count + item_index;
        let recipient_message_encoding_layout = message_encoding_layouts
            .get(recipient_message_position)
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "compact VSS recipient item is outside the packed column layout",
                )
            })?;
        if recipient_message_encoding_layout.encoding_column_count()
            != item_recipient_message_encoding_layout.encoding_column_count()
        {
            return Err(invalid_succinct_setup_proof(
                "compact VSS recipient message layout does not match the packed column layout",
            ));
        }
        let item_decoder_relation_count = (item.coefficient_commitments.len()
            * compact_vss_decoder_digit_count(item_coefficient_message_encoding_layout)
            + compact_vss_decoder_digit_count(item_recipient_message_encoding_layout))
            * LINCHECK_REPETITIONS;
        let item_relation_count = (item.coefficient_commitments.len() + 1)
            * COMPACT_VSS_OUTPUT_COORDINATE_COUNT
            + LINCHECK_REPETITIONS
            + item_decoder_relation_count;
        let (item_claim, item_vectors) = build_compact_vss_share_linkage_public_vectors(
            CompactVssShareLinkagePublicVectorInput {
                public_matrix_seed_hash: &statement.public_matrix_seed_hash,
                rns_limb_index: item.source_rns_limb_index,
                commitment_modulus_index,
                modulus,
                source_message_modulus: item.source_message_modulus,
                recipient_roster_position: item.recipient_roster_position,
                ring_degree,
                coefficient_commitments: item.coefficient_commitments,
                recipient_share_commitment: item.recipient_share_commitment,
                relation_alpha: &relation_alpha
                    [relation_alpha_offset..relation_alpha_offset + item_relation_count],
                u_power_vectors,
            },
            tower,
        )?;
        relation_claim = tower.add(&relation_claim, &item_claim);
        relation_alpha_offset += item_relation_count;

        let mut item_vectors = item_vectors.into_iter();
        for coefficient_slot_index in &item.coefficient_slot_indices {
            for encoding_column in
                0..item_coefficient_message_encoding_layout.encoding_column_count()
            {
                let item_vector = item_vectors.next().ok_or_else(|| {
                    invalid_succinct_setup_proof("compact VSS batch vectors ended unexpectedly")
                })?;
                let vector_index = compact_vss_message_vector_index(
                    &message_encoding_offsets,
                    *coefficient_slot_index,
                    encoding_column,
                )?;
                add_extension_vector(
                    &mut message_encoding_vectors[vector_index],
                    &item_vector,
                    tower,
                )?;
            }
        }
        for encoding_column in 0..item_recipient_message_encoding_layout.encoding_column_count() {
            let item_vector = item_vectors.next().ok_or_else(|| {
                invalid_succinct_setup_proof("compact VSS batch vectors ended unexpectedly")
            })?;
            let vector_index = compact_vss_message_vector_index(
                &message_encoding_offsets,
                recipient_message_position,
                encoding_column,
            )?;
            add_extension_vector(
                &mut message_encoding_vectors[vector_index],
                &item_vector,
                tower,
            )?;
        }
        let carry_vector = item_vectors.next().ok_or_else(|| {
            invalid_succinct_setup_proof("compact VSS batch vectors ended unexpectedly")
        })?;
        add_extension_vector(
            &mut recipient_share_carry_vectors[item_index],
            &carry_vector,
            tower,
        )?;
        for coefficient_slot_index in &item.coefficient_slot_indices {
            for randomness_column_index in 0..COMPACT_VSS_RANDOMNESS_COLUMN_COUNT {
                let item_vector = item_vectors.next().ok_or_else(|| {
                    invalid_succinct_setup_proof("compact VSS batch vectors ended unexpectedly")
                })?;
                let vector_index = coefficient_slot_index * COMPACT_VSS_RANDOMNESS_COLUMN_COUNT
                    + randomness_column_index;
                add_extension_vector(
                    &mut coefficient_randomness_vectors[vector_index],
                    &item_vector,
                    tower,
                )?;
            }
        }
        for randomness_column_index in 0..COMPACT_VSS_RANDOMNESS_COLUMN_COUNT {
            let item_vector = item_vectors.next().ok_or_else(|| {
                invalid_succinct_setup_proof("compact VSS batch vectors ended unexpectedly")
            })?;
            let vector_index =
                item_index * COMPACT_VSS_RANDOMNESS_COLUMN_COUNT + randomness_column_index;
            add_extension_vector(
                &mut recipient_share_randomness_vectors[vector_index],
                &item_vector,
                tower,
            )?;
        }
        if item_vectors.next().is_some() {
            return Err(invalid_succinct_setup_proof(
                "compact VSS batch vectors contain unexpected extra columns",
            ));
        }
    }
    if relation_alpha_offset != relation_alpha.len() {
        return Err(invalid_succinct_setup_proof(
            "compact VSS batch relation challenge offset did not consume every challenge",
        ));
    }

    let mut vectors = Vec::with_capacity(
        message_encoding_vectors.len()
            + recipient_share_carry_vectors.len()
            + coefficient_randomness_vectors.len()
            + recipient_share_randomness_vectors.len(),
    );
    vectors.extend(message_encoding_vectors);
    vectors.extend(recipient_share_carry_vectors);
    vectors.extend(coefficient_randomness_vectors);
    vectors.extend(recipient_share_randomness_vectors);

    Ok((relation_claim, vectors))
}

// Compact same-secret bridge vectors for one commitment field. The vector
// order is the signed ternary secret, the binary negative indicator, and each
// compact target-constant opening-randomness column in target limb order.
pub(crate) fn build_compact_same_secret_bridge_public_vectors(
    input: CompactSameSecretBridgePublicVectorInput<'_>,
    tower: &ChallengeExtensionTower,
) -> CanonicalResult<(
    ChallengeExtensionElement,
    Vec<Vec<ChallengeExtensionElement>>,
)> {
    if input.ring_degree == 0 {
        return Err(invalid_succinct_setup_proof(
            "compact same-secret bridge ring degree must be positive",
        ));
    }
    if tower.modulus != input.modulus {
        return Err(invalid_succinct_setup_proof(
            "compact same-secret bridge tower modulus does not match the commitment field",
        ));
    }
    if input.target_rns_primes.is_empty()
        || input.target_rns_primes.len() != input.target_constant_commitments.len()
    {
        return Err(invalid_succinct_setup_proof(
            "compact same-secret bridge target primes and commitments must be aligned",
        ));
    }
    for commitment in input.target_constant_commitments {
        let coordinates = commitment
            .coordinates_by_commitment_modulus
            .get(input.commitment_modulus_index)
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "compact same-secret bridge commitment does not cover the selected commitment field",
                )
            })?;
        if coordinates.len() != COMPACT_VSS_OUTPUT_COORDINATE_COUNT {
            return Err(invalid_succinct_setup_proof(
                "compact same-secret bridge coordinate count does not match the profile",
            ));
        }
        if coordinates
            .iter()
            .any(|coordinate| *coordinate >= input.modulus)
        {
            return Err(invalid_succinct_setup_proof(
                "compact same-secret bridge coordinate is outside the commitment field",
            ));
        }
    }

    if input.u_power_vectors.len() != LINCHECK_REPETITIONS {
        return Err(invalid_succinct_setup_proof(
            "compact same-secret bridge lincheck repetition count does not match the profile",
        ));
    }
    if input
        .u_power_vectors
        .iter()
        .any(|vector| vector.len() != input.ring_degree)
    {
        return Err(invalid_succinct_setup_proof(
            "compact same-secret bridge lincheck vector length does not match the ring degree",
        ));
    }

    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); input.ring_degree];
    let mut relation_claim = ChallengeExtensionTower::zero();
    let mut secret_vector = extension_zero_vector();
    let mut negative_indicator_vector = extension_zero_vector();
    let message_encoding_layouts = input
        .target_rns_primes
        .iter()
        .map(|target_rns_prime| compact_vss_message_encoding_layout(*target_rns_prime))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let target_count = input.target_constant_commitments.len();
    let commitment_relation_count = target_count * COMPACT_VSS_OUTPUT_COORDINATE_COUNT;
    let bridge_relation_count = target_count * LINCHECK_REPETITIONS;
    let decoder_relation_count = message_encoding_layouts
        .iter()
        .copied()
        .map(compact_vss_decoder_digit_count)
        .sum::<usize>()
        * LINCHECK_REPETITIONS;
    let relation_count = commitment_relation_count + bridge_relation_count + decoder_relation_count;
    if input.relation_alpha.len() != relation_count {
        return Err(invalid_succinct_setup_proof(
            "compact same-secret bridge challenge count does not match the relation count",
        ));
    }

    let message_encoding_offsets = compact_vss_message_encoding_offsets(&message_encoding_layouts)?;
    let mut message_encoding_vectors =
        vec![
            extension_zero_vector();
            compact_vss_message_encoding_total(&message_encoding_offsets)
        ];
    let mut randomness_vectors =
        vec![extension_zero_vector(); target_count * COMPACT_VSS_RANDOMNESS_COLUMN_COUNT];

    for (target_rns_limb_index, (target_rns_prime, commitment)) in input
        .target_rns_primes
        .iter()
        .zip(input.target_constant_commitments.iter())
        .enumerate()
    {
        let message_encoding_layout = message_encoding_layouts[target_rns_limb_index];
        let coordinates =
            &commitment.coordinates_by_commitment_modulus[input.commitment_modulus_index];
        for (output_coordinate_index, coordinate) in coordinates.iter().enumerate() {
            let alpha_index = target_rns_limb_index * COMPACT_VSS_OUTPUT_COORDINATE_COUNT
                + output_coordinate_index;
            let alpha_value = &input.relation_alpha[alpha_index];
            relation_claim =
                tower.add(&relation_claim, &tower.scale_base(alpha_value, *coordinate));
            for digit_index in 0..COMPACT_VSS_MESSAGE_DIGIT_COUNT {
                let input_column = compact_vss_message_digit_column_label(digit_index)?;
                let digit_vector_index = compact_vss_message_vector_index(
                    &message_encoding_offsets,
                    target_rns_limb_index,
                    message_encoding_layout.digit_encoding_column(digit_index)?,
                )?;
                add_compact_projection_vector(
                    AddCompactProjectionVectorInput {
                        target: &mut message_encoding_vectors[digit_vector_index],
                        scale: alpha_value,
                        public_matrix_seed_hash: input.public_matrix_seed_hash,
                        rns_limb_index: target_rns_limb_index,
                        commitment_modulus_index: input.commitment_modulus_index,
                        output_coordinate_index,
                        input_column: &input_column,
                        ring_degree: input.ring_degree,
                        modulus: input.modulus,
                    },
                    tower,
                )?;
            }
            for randomness_column_index in 0..COMPACT_VSS_RANDOMNESS_COLUMN_COUNT {
                let input_column = format!("randomness:{randomness_column_index}");
                let randomness_vector = &mut randomness_vectors[target_rns_limb_index
                    * COMPACT_VSS_RANDOMNESS_COLUMN_COUNT
                    + randomness_column_index];
                add_compact_projection_vector(
                    AddCompactProjectionVectorInput {
                        target: randomness_vector,
                        scale: alpha_value,
                        public_matrix_seed_hash: input.public_matrix_seed_hash,
                        rns_limb_index: target_rns_limb_index,
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
        let bridge_relation_offset =
            commitment_relation_count + target_rns_limb_index * LINCHECK_REPETITIONS;
        let target_prime_residue = *target_rns_prime % input.modulus;
        for (repetition, u_powers) in input.u_power_vectors.iter().enumerate() {
            let alpha_value = &input.relation_alpha[bridge_relation_offset + repetition];
            let scaled_u = u_powers
                .iter()
                .map(|value| tower.mul(alpha_value, value))
                .collect::<Vec<_>>();
            add_scaled_extension_basis_vector(
                &mut secret_vector,
                &scaled_u,
                sub_mod_fast(0, 1, input.modulus),
                tower,
            );
            add_scaled_extension_basis_vector(
                &mut negative_indicator_vector,
                &scaled_u,
                sub_mod_fast(0, target_prime_residue, input.modulus),
                tower,
            );
            for digit_index in 0..COMPACT_VSS_MESSAGE_DIGIT_COUNT {
                let digit_weight = compact_vss_message_digit_weight(digit_index, input.modulus)?;
                let digit_vector_index = compact_vss_message_vector_index(
                    &message_encoding_offsets,
                    target_rns_limb_index,
                    message_encoding_layout.digit_encoding_column(digit_index)?,
                )?;
                add_scaled_extension_basis_vector(
                    &mut message_encoding_vectors[digit_vector_index],
                    &scaled_u,
                    digit_weight,
                    tower,
                );
            }
        }
    }

    if decoder_relation_count > 0 {
        let decoder_relation_offset = commitment_relation_count + bridge_relation_count;
        let mut decoder_relation_index = 0_usize;
        for (target_rns_limb_index, message_encoding_layout) in
            message_encoding_layouts.iter().enumerate()
        {
            for digit_index in 0..COMPACT_VSS_MESSAGE_DIGIT_COUNT {
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
                    let digit_vector_index = compact_vss_message_vector_index(
                        &message_encoding_offsets,
                        target_rns_limb_index,
                        message_encoding_layout.digit_encoding_column(digit_index)?,
                    )?;
                    add_extension_vector(
                        &mut message_encoding_vectors[digit_vector_index],
                        &scaled_u,
                        tower,
                    )?;
                    let mut trit_weight = 1_u64;
                    for trit_index in 0..trit_count {
                        let trit_vector_index = compact_vss_message_vector_index(
                            &message_encoding_offsets,
                            target_rns_limb_index,
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

    let mut vectors =
        Vec::with_capacity(2 + message_encoding_vectors.len() + randomness_vectors.len());
    vectors.push(secret_vector);
    vectors.push(negative_indicator_vector);
    vectors.extend(message_encoding_vectors);
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

fn add_extension_vector(
    target: &mut [ChallengeExtensionElement],
    source: &[ChallengeExtensionElement],
    tower: &ChallengeExtensionTower,
) -> CanonicalResult<()> {
    if target.len() != source.len() {
        return Err(invalid_succinct_setup_proof(
            "compact VSS batch vector length does not match the shared coefficient column",
        ));
    }
    for (target_value, source_value) in target.iter_mut().zip(source) {
        *target_value = tower.add(target_value, source_value);
    }

    Ok(())
}
