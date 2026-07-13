use super::super::evaluation_domain::EvaluationDomainPlan;
use super::super::relation::{
    LimbColumnLayout, PrivateVssShareStatement, SetupProofStatement,
    TargetDecryptionShareStatement, TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness,
    VssShareLinkageStatement, private_vss_share_lifted_carry_bound,
    vss_share_linkage_lincheck_roster_position,
};
use super::super::{TRACE_SPLIT, invalid_succinct_setup_proof, signed_value_residue};
use super::claim_masking::{mask_digit_columns, masked_half_coefficients};
use super::salted_tree::{SaltedTree, commit_salted_extension_row_pairs};
use super::{COLUMN_MASK_DOMAIN, LEAF_SALT_DOMAIN};
use crate::bgv::evaluator::engine::negacyclic_mul;
use crate::bgv::evaluator::prg::DeterministicSampler;
use crate::bgv::modular_arithmetic::{add_mod_fast, mul_mod_fast};
use crate::bgv::setup::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH;
use crate::encoding::CanonicalResult;

fn signed_residue_vector(coefficients: &[i64], modulus: u64) -> Vec<u64> {
    coefficients
        .iter()
        .map(|coefficient| signed_value_residue(*coefficient, modulus))
        .collect()
}

fn vss_public_message_encoding_vectors_with_layout(
    coefficients: &[i64],
    message_bound: u64,
    modulus: u64,
    layout: crate::bgv::setup::vss_commitment::VssPublicMessageEncodingLayout,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let unsigned_coefficients = coefficients
        .iter()
        .map(|coefficient| {
            u64::try_from(*coefficient)
                .map_err(|_| invalid_succinct_setup_proof("VSS message coefficient is negative"))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    vss_public_message_encoding_vectors_from_unsigned(
        &unsigned_coefficients,
        message_bound,
        modulus,
        layout,
    )
}

fn vss_public_message_encoding_vectors_from_unsigned(
    coefficients: &[u64],
    message_bound: u64,
    modulus: u64,
    layout: crate::bgv::setup::vss_commitment::VssPublicMessageEncodingLayout,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let mut columns = vec![vec![0_u64; coefficients.len()]; layout.encoding_column_count()];
    for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
        if *coefficient >= message_bound {
            return Err(invalid_succinct_setup_proof(
                "VSS message coefficient is outside the statement bound",
            ));
        }
        let digits = crate::bgv::setup::vss_commitment::vss_public_message_digits(*coefficient)?;
        for (digit_index, digit) in digits.iter().enumerate() {
            let digit_column = layout.digit_encoding_column(digit_index)?;
            columns[digit_column][coefficient_index] = *digit % modulus;
            let trit_count = layout.digit_trit_count(digit_index)?;
            if trit_count == 0 {
                continue;
            }
            let trits =
                crate::bgv::setup::vss_commitment::vss_public_message_digit_trits_for_count(
                    *digit, trit_count,
                )?;
            for (trit_index, trit) in trits.iter().enumerate() {
                let trit_column = layout.trit_encoding_column(digit_index, trit_index)?;
                columns[trit_column][coefficient_index] = *trit % modulus;
            }
        }
    }

    Ok(columns)
}

fn vss_public_recipient_share_messages_by_item(
    witness: &TrusteeEvaluationKeyWitness,
) -> Vec<&[i64]> {
    witness
        .vss_public_recipient_share_messages_by_item()
        .iter()
        .map(Vec::as_slice)
        .collect()
}

fn vss_public_carry_witnesses_by_item(witness: &TrusteeEvaluationKeyWitness) -> Vec<&[i64]> {
    witness
        .vss_public_carry_witnesses_by_item()
        .iter()
        .map(Vec::as_slice)
        .collect()
}
pub(super) struct LimbWitnessCommitment {
    pub(super) plan: EvaluationDomainPlan,
    pub(super) layout: LimbColumnLayout,
    // Mask digit logical vectors.
    // Masked coefficients (length trace + mask degree) per physical column.
    pub(super) masked_coefficients: Vec<Vec<u64>>,
    // Extension evaluations per physical column.
    pub(super) extension_columns: Vec<Vec<u64>>,
    pub(super) salted: SaltedTree,
}

pub(super) fn build_limb_witness_commitment(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    bound_message_coefficients: &[Vec<u64>],
    limb_index: usize,
    modulus: u64,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<LimbWitnessCommitment> {
    let layout = LimbColumnLayout::new(statement, limb_index)?;
    let plan = EvaluationDomainPlan::new(modulus, layout.trace_size)?;

    let trace_size = layout.trace_size;
    let mut masked_coefficients = Vec::with_capacity(layout.phase_one_physical_count());
    let mut extension_columns = Vec::with_capacity(layout.phase_one_physical_count());
    let mut append_logical_vector = |logical_vector: &[u64]| {
        debug_assert_eq!(logical_vector.len(), layout.ring_degree);
        for half in 0..TRACE_SPLIT {
            let physical_index = masked_coefficients.len();
            let half_values = &logical_vector[half * trace_size..(half + 1) * trace_size];
            let mut mask_sampler = DeterministicSampler::new(
                COLUMN_MASK_DOMAIN,
                &[
                    proof_randomness_seed_hex.as_bytes(),
                    &(limb_index as u64).to_le_bytes(),
                    &(physical_index as u64).to_le_bytes(),
                ],
            );
            let coefficients = masked_half_coefficients(&plan, half_values, &mut mask_sampler);
            extension_columns.push(plan.extension_evaluations_from_coefficients(&coefficients));
            masked_coefficients.push(coefficients);
        }
    };

    // Assemble the physical half-columns in layout order: secret halves, then
    // per error position the error halves, then the error-square halves, then
    // the linkage columns and the mask digit halves. Each logical vector is
    // converted and extended once, then dropped before the next logical vector.
    if layout.private_vss_active() {
        for coefficient_messages in witness.private_vss_coefficient_messages_by_shamir_index() {
            let logical_vector = signed_residue_vector(coefficient_messages, modulus);
            append_logical_vector(&logical_vector);
        }
        let carry_vector = signed_residue_vector(witness.private_vss_carry_witnesses(), modulus);
        append_logical_vector(&carry_vector);
        for randomness_columns in witness.private_vss_opening_randomness_by_shamir_index() {
            for column in randomness_columns {
                let logical_vector = signed_residue_vector(column, modulus);
                append_logical_vector(&logical_vector);
            }
        }
    } else if layout.vss_public_active() {
        let vss_share_linkage = statement.vss_share_linkage().ok_or_else(|| {
            invalid_succinct_setup_proof("VSS witness layout requires a share-linkage statement")
        })?;
        let coefficient_slots = vss_share_linkage.coefficient_witness_slots();
        if coefficient_slots.len()
            != witness
                .vss_public_coefficient_messages_by_shamir_index()
                .len()
        {
            return Err(invalid_succinct_setup_proof(
                "VSS coefficient witness count does not match the statement",
            ));
        }
        let item_count = vss_share_linkage.item_count();
        let coefficient_slot_indices_by_item =
            vss_share_linkage.coefficient_witness_slot_indices_by_item();
        let recipient_messages_by_item = vss_public_recipient_share_messages_by_item(witness);
        let carry_witnesses_by_item = vss_public_carry_witnesses_by_item(witness);
        if coefficient_slot_indices_by_item.len() != item_count
            || recipient_messages_by_item.len() != item_count
            || carry_witnesses_by_item.len() != item_count
        {
            return Err(invalid_succinct_setup_proof(
                "VSS packed witness item count does not match the statement",
            ));
        }
        let message_bounds = vss_share_linkage.packed_message_bounds();
        if message_bounds.len() != layout.vss_public_message_vector_count() {
            return Err(invalid_succinct_setup_proof(
                "VSS packed message bounds do not match the column layout",
            ));
        }
        let validate_vss_public_vector =
            |source: &[i64], field_name: &str| -> CanonicalResult<()> {
                if source.len() != layout.base_ring_degree {
                    return Err(invalid_succinct_setup_proof(format!(
                        "{field_name} length does not match the base ring degree"
                    )));
                }

                Ok(())
            };
        for (coefficient_slot_index, message_bound) in message_bounds
            .iter()
            .copied()
            .take(layout.vss_public_coefficient_columns)
            .enumerate()
        {
            let coefficient_messages = witness
                .vss_public_coefficient_messages_by_shamir_index()
                .get(coefficient_slot_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "VSS coefficient witness slot is outside the witness",
                    )
                })?;
            validate_vss_public_vector(coefficient_messages, "VSS coefficient message witness")?;
            for logical_vector in vss_public_message_encoding_vectors_with_layout(
                coefficient_messages,
                message_bound,
                modulus,
                layout.vss_public_message_encoding_layout(coefficient_slot_index),
            )? {
                append_logical_vector(&logical_vector);
            }
        }
        for (item_index, recipient_messages) in recipient_messages_by_item.iter().enumerate() {
            validate_vss_public_vector(recipient_messages, "VSS recipient message witness")?;
            let recipient_message_position = layout.vss_public_coefficient_columns + item_index;
            for logical_vector in vss_public_message_encoding_vectors_with_layout(
                recipient_messages,
                message_bounds[recipient_message_position],
                modulus,
                layout.vss_public_message_encoding_layout(recipient_message_position),
            )? {
                append_logical_vector(&logical_vector);
            }
        }
        for carry_witnesses in carry_witnesses_by_item {
            validate_vss_public_vector(carry_witnesses, "VSS carry witness")?;
            let carry_vector = signed_residue_vector(carry_witnesses, modulus);
            append_logical_vector(&carry_vector);
        }
    } else if layout.same_secret_bridge_active() {
        let bridge = statement.same_secret_bridge().ok_or_else(|| {
            invalid_succinct_setup_proof("same-secret bridge layout requires a bridge statement")
        })?;
        let secret_vector = signed_residue_vector(witness.secret_coefficients(), modulus);
        append_logical_vector(&secret_vector);
        let negative_indicator_vector =
            signed_residue_vector(witness.negative_indicator_coefficients(), modulus);
        append_logical_vector(&negative_indicator_vector);
        if bound_message_coefficients.len() != bridge.bridge_rns_primes.len() {
            return Err(invalid_succinct_setup_proof(
                "same-secret bridge committed messages do not match its target primes",
            ));
        }
        for (target_rns_prime, target_message_coefficients) in bridge
            .bridge_rns_primes
            .iter()
            .zip(bound_message_coefficients)
        {
            for logical_vector in vss_public_message_encoding_vectors_from_unsigned(
                target_message_coefficients,
                *target_rns_prime,
                modulus,
                crate::bgv::setup::vss_commitment::vss_public_message_encoding_layout(
                    *target_rns_prime,
                )?,
            )? {
                append_logical_vector(&logical_vector);
            }
        }
        for randomness_columns in witness.opening_randomness_by_limb() {
            for column in randomness_columns {
                let logical_vector = signed_residue_vector(column, modulus);
                append_logical_vector(&logical_vector);
            }
        }
    } else if layout.target_decryption_active() {
        for local_message_index in 0..layout.target_decryption_message_columns {
            let global_message_index = statement
                .target_decryption_message_global_index(limb_index, local_message_index)
                .expect("target-decryption message column is in the layout");
            let message_vector = &witness.target_decryption_message_vectors()[global_message_index];
            let message_bound = statement
                .target_decryption_message_bound(global_message_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "target-decryption message bound is missing for the active message",
                    )
                })?;
            let message_encoding_layout = statement
                .target_decryption_message_encoding_layout(limb_index, global_message_index)?;
            for logical_vector in vss_public_message_encoding_vectors_with_layout(
                message_vector,
                message_bound,
                modulus,
                message_encoding_layout,
            )? {
                append_logical_vector(&logical_vector);
            }
        }
    } else {
        let secret_vector = signed_residue_vector(witness.secret_coefficients(), modulus);
        append_logical_vector(&secret_vector);
        for (key_index, digit_count) in &layout.active_keys {
            for digit_index in 0..*digit_count {
                let error_vector = signed_residue_vector(
                    &witness.error_coefficients_by_key()[*key_index][digit_index],
                    modulus,
                );
                append_logical_vector(&error_vector);
            }
        }
        for (key_index, digit_count) in &layout.active_keys {
            for digit_index in 0..*digit_count {
                let error_square_vector = witness.error_coefficients_by_key()[*key_index]
                    [digit_index]
                    .iter()
                    .map(|coefficient| {
                        let residue = signed_value_residue(*coefficient, modulus);
                        mul_mod_fast(residue, residue, modulus)
                    })
                    .collect::<Vec<_>>();
                append_logical_vector(&error_square_vector);
            }
        }
        if layout.linkage_active() || layout.same_secret_bridge_material_active() {
            let negative_indicator_vector =
                signed_residue_vector(witness.negative_indicator_coefficients(), modulus);
            append_logical_vector(&negative_indicator_vector);
            if let Some(bridge) = statement.same_secret_bridge() {
                if bound_message_coefficients.len() != bridge.bridge_rns_primes.len() {
                    return Err(invalid_succinct_setup_proof(
                        "same-secret bridge committed messages do not match its target primes",
                    ));
                }
                for (target_rns_prime, target_message_coefficients) in bridge
                    .bridge_rns_primes
                    .iter()
                    .zip(bound_message_coefficients)
                {
                    for logical_vector in vss_public_message_encoding_vectors_from_unsigned(
                        target_message_coefficients,
                        *target_rns_prime,
                        modulus,
                        crate::bgv::setup::vss_commitment::vss_public_message_encoding_layout(
                            *target_rns_prime,
                        )?,
                    )? {
                        append_logical_vector(&logical_vector);
                    }
                }
            }
            if layout.linkage_active() {
                for randomness_columns in witness.opening_randomness_by_limb() {
                    for column in randomness_columns {
                        let logical_vector = signed_residue_vector(column, modulus);
                        append_logical_vector(&logical_vector);
                    }
                }
            }
        }
    }
    let mask_columns = mask_digit_columns(statement, &layout, proof_randomness_seed_hex);
    for logical_vector in &mask_columns {
        append_logical_vector(logical_vector);
    }
    debug_assert_eq!(masked_coefficients.len(), layout.phase_one_physical_count());
    debug_assert_eq!(extension_columns.len(), layout.phase_one_physical_count());
    let mut salt_sampler = DeterministicSampler::new(
        LEAF_SALT_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            b"phase-one",
            &(limb_index as u64).to_le_bytes(),
        ],
    );
    let salted = commit_salted_extension_row_pairs(
        &extension_columns,
        plan.extension_size,
        &mut salt_sampler,
    )?;

    Ok(LimbWitnessCommitment {
        plan,
        layout,
        masked_coefficients,
        extension_columns,
        salted,
    })
}

pub(super) fn validate_witness_support(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
) -> CanonicalResult<()> {
    match (&statement.proof, witness) {
        (
            SetupProofStatement::PublicKeyShare { .. },
            TrusteeEvaluationKeyWitness::PublicKeyShare { .. },
        ) => {
            validate_key_bearing_witness(statement, witness)?;
            validate_linkage_witness(0, 0, witness, statement.ring_degree)
        }
        (
            SetupProofStatement::PrivateVssShare(private_vss_share),
            TrusteeEvaluationKeyWitness::PrivateVssShare { .. },
        ) => validate_private_vss_witness(private_vss_share, witness, statement.ring_degree),
        (
            SetupProofStatement::VssShareLinkage(vss_share_linkage),
            TrusteeEvaluationKeyWitness::VssShareLinkage { .. },
        ) => validate_vss_public_witness(vss_share_linkage, witness, statement.ring_degree),
        (
            SetupProofStatement::SameSecretBridge {
                same_secret_linkage,
                ..
            },
            TrusteeEvaluationKeyWitness::SameSecretBridge { .. },
        ) => validate_same_secret_bridge_witness(
            same_secret_linkage.commitments.len(),
            SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            witness,
            statement.ring_degree,
        ),
        (
            SetupProofStatement::TargetDecryptionShare(target_decryption_share),
            TrusteeEvaluationKeyWitness::TargetDecryptionShare { .. },
        ) => validate_target_decryption_share_witness(
            target_decryption_share,
            witness,
            statement.ring_degree,
        ),
        (
            SetupProofStatement::TrusteeEvaluationKey {
                same_secret_linkage,
                ..
            },
            TrusteeEvaluationKeyWitness::TrusteeEvaluationKey { .. },
        ) => {
            validate_key_bearing_witness(statement, witness)?;
            validate_linkage_witness(
                same_secret_linkage.commitments.len(),
                SETUP_COMMITMENT_RANDOMNESS_WIDTH,
                witness,
                statement.ring_degree,
            )
        },
        _ => Err(invalid_succinct_setup_proof(
            "witness family does not match the proof statement family",
        )),
    }
}

fn validate_key_bearing_witness(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
) -> CanonicalResult<()> {
    if witness.secret_coefficients().len() != statement.ring_degree
        || witness.error_coefficients_by_key().len() != statement.keys().len()
    {
        return Err(invalid_succinct_setup_proof(
            "witness shape does not match the statement",
        ));
    }
    if witness
        .secret_coefficients()
        .iter()
        .any(|coefficient| !(-1..=1).contains(coefficient))
    {
        return Err(invalid_succinct_setup_proof(
            "witness secret must be ternary",
        ));
    }
    for (key, errors) in statement
        .keys()
        .iter()
        .zip(witness.error_coefficients_by_key().iter())
    {
        if errors.len() != key.digit_count()
            || errors
                .iter()
                .any(|digit_errors| digit_errors.len() != statement.ring_degree)
        {
            return Err(invalid_succinct_setup_proof(
                "witness error shape does not match a key descriptor",
            ));
        }
        if errors
            .iter()
            .flatten()
            .any(|coefficient| !(-2..=2).contains(coefficient))
        {
            return Err(invalid_succinct_setup_proof(
                "witness errors must stay in the centered binomial support",
            ));
        }
    }
    Ok(())
}

fn validate_linkage_witness(
    commitment_count: usize,
    randomness_column_count: usize,
    witness: &TrusteeEvaluationKeyWitness,
    ring_degree: usize,
) -> CanonicalResult<()> {
    if witness.negative_indicator_coefficients().len() != ring_degree
        || witness
            .negative_indicator_coefficients()
            .iter()
            .any(|coefficient| !(0..=1).contains(coefficient))
    {
        return Err(invalid_succinct_setup_proof(
            "witness negative indicator must be binary at the ring degree",
        ));
    }
    if witness.opening_randomness_by_limb().len() != commitment_count
        || witness.opening_randomness_by_limb().iter().any(|columns| {
            columns.len() != randomness_column_count
                || columns.iter().any(|column| {
                    column.len() != ring_degree
                        || column
                            .iter()
                            .any(|coefficient| !(-1..=1).contains(coefficient))
                })
        })
    {
        return Err(invalid_succinct_setup_proof(
            "witness opening randomness must be ternary per commitment and column",
        ));
    }

    Ok(())
}

fn validate_same_secret_bridge_witness(
    commitment_count: usize,
    randomness_column_count: usize,
    witness: &TrusteeEvaluationKeyWitness,
    ring_degree: usize,
) -> CanonicalResult<()> {
    if witness.secret_coefficients().len() != ring_degree
        || witness
            .secret_coefficients()
            .iter()
            .any(|coefficient| !(-1..=1).contains(coefficient))
    {
        return Err(invalid_succinct_setup_proof(
            "same-secret bridge secret must be ternary at the ring degree",
        ));
    }

    validate_linkage_witness(
        commitment_count,
        randomness_column_count,
        witness,
        ring_degree,
    )
}

fn validate_target_decryption_share_witness(
    statement: &super::super::relation::TargetDecryptionShareStatement,
    witness: &TrusteeEvaluationKeyWitness,
    ring_degree: usize,
) -> CanonicalResult<()> {
    let message_count = statement
        .limb_statements
        .iter()
        .map(|limb_statement| {
            1 + limb_statement
                .role_statements
                .iter()
                .map(|role_statement| role_statement.smudging_commitments.len())
                .sum::<usize>()
        })
        .sum::<usize>();
    // Committed-material commitments carry no algebraic opening randomness;
    // the trees hide via their masks and salts.
    if witness.target_decryption_message_vectors().len() != message_count {
        return Err(invalid_succinct_setup_proof(
            "target-decryption witness shape does not match the statement",
        ));
    }
    let aggregate_message_bound_i64 = i64::try_from(statement.aggregate_message_coefficient_bound)
        .map_err(|_| {
            invalid_succinct_setup_proof(
                "target-decryption aggregate message bound does not fit i64",
            )
        })?;
    let message_bound_i64 =
        i64::try_from(statement.smudging_message_coefficient_bound).map_err(|_| {
            invalid_succinct_setup_proof("target-decryption smudging bound does not fit i64")
        })?;

    let mut limb_message_offset = 0;
    for limb_statement in &statement.limb_statements {
        let target_prime_i64 = i64::try_from(limb_statement.target_rns_prime).map_err(|_| {
            invalid_succinct_setup_proof("target-decryption target prime does not fit i64")
        })?;
        let aggregate_messages = &witness.target_decryption_message_vectors()[limb_message_offset];
        if aggregate_messages.len() != ring_degree
            || aggregate_messages
                .iter()
                .any(|coefficient| *coefficient < 0 || *coefficient >= aggregate_message_bound_i64)
        {
            return Err(invalid_succinct_setup_proof(
                "target-decryption aggregate-share witness is outside the aggregate message bound",
            ));
        }
        let aggregate_share = aggregate_messages
            .iter()
            .map(|coefficient| {
                let residue = coefficient.rem_euclid(target_prime_i64);
                u64::try_from(residue).map_err(|_| {
                    invalid_succinct_setup_proof(
                        "target-decryption aggregate-share coefficient does not fit u64",
                    )
                })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let plaintext_multiple = statement.plaintext_multiple % limb_statement.target_rns_prime;
        let mut smudging_message_offset = limb_message_offset + 1;
        for role_statement in &limb_statement.role_statements {
            let mut expected_partial = negacyclic_mul(
                &role_statement.target_ciphertext_component_one,
                &aggregate_share,
                limb_statement.target_rns_prime,
            )?;
            let mut interpolation_power =
                statement.interpolation_point % limb_statement.target_rns_prime;
            for smudging_message in witness.target_decryption_message_vectors()
                [smudging_message_offset
                    ..smudging_message_offset + role_statement.smudging_commitments.len()]
                .iter()
            {
                if smudging_message.len() != ring_degree
                    || smudging_message
                        .iter()
                        .any(|coefficient| *coefficient < 0 || *coefficient >= message_bound_i64)
                {
                    return Err(invalid_succinct_setup_proof(
                        "target-decryption smudging message vector is outside the encoded coefficient range",
                    ));
                }
                let smudging_scale = mul_mod_fast(
                    plaintext_multiple,
                    interpolation_power,
                    limb_statement.target_rns_prime,
                );
                for (partial, encoded_coefficient) in
                    expected_partial.iter_mut().zip(smudging_message)
                {
                    let signed_coefficient = encoded_coefficient
                        .checked_sub(statement.smudging_signed_coefficient_offset)
                        .ok_or_else(|| {
                            invalid_succinct_setup_proof(
                                "target-decryption smudging coefficient decoding overflowed",
                            )
                        })?;
                    let smudging_residue =
                        signed_value_residue(signed_coefficient, limb_statement.target_rns_prime);
                    let smudging_term = mul_mod_fast(
                        smudging_scale,
                        smudging_residue,
                        limb_statement.target_rns_prime,
                    );
                    *partial =
                        add_mod_fast(*partial, smudging_term, limb_statement.target_rns_prime);
                }
                interpolation_power = mul_mod_fast(
                    interpolation_power,
                    statement.interpolation_point % limb_statement.target_rns_prime,
                    limb_statement.target_rns_prime,
                );
            }
            if expected_partial != role_statement.released_partial_decryption {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption witness does not reconstruct the released partial",
                ));
            }
            smudging_message_offset += role_statement.smudging_commitments.len();
        }
        limb_message_offset = smudging_message_offset;
    }

    Ok(())
}

fn validate_vss_public_witness(
    statement: &super::super::relation::VssShareLinkageStatement,
    witness: &TrusteeEvaluationKeyWitness,
    ring_degree: usize,
) -> CanonicalResult<()> {
    let item_count = statement.item_count();
    let coefficient_slots = statement.coefficient_witness_slots();
    let coefficient_count = coefficient_slots.len();
    let coefficient_slot_indices_by_item = statement.coefficient_witness_slot_indices_by_item();
    let recipient_share_messages_by_item = vss_public_recipient_share_messages_by_item(witness);
    let carry_witnesses_by_item = vss_public_carry_witnesses_by_item(witness);
    // Committed-material commitments carry no algebraic opening randomness;
    // the trees hide via their masks and salts, so no randomness columns are
    // part of the witness.
    if witness
        .vss_public_coefficient_messages_by_shamir_index()
        .len()
        != coefficient_count
        || coefficient_slot_indices_by_item.len() != item_count
        || recipient_share_messages_by_item.len() != item_count
        || carry_witnesses_by_item.len() != item_count
    {
        return Err(invalid_succinct_setup_proof(
            "VSS witness shape does not match the statement",
        ));
    }
    for (slot_index, (coefficient_slot, messages)) in coefficient_slots
        .iter()
        .zip(
            witness
                .vss_public_coefficient_messages_by_shamir_index()
                .iter(),
        )
        .enumerate()
    {
        let source_modulus_i64 = i64::try_from(coefficient_slot.source_message_modulus)
            .map_err(|_| invalid_succinct_setup_proof("VSS source modulus does not fit i64"))?;
        if messages.len() != ring_degree
            || messages
                .iter()
                .any(|coefficient| *coefficient < 0 || *coefficient >= source_modulus_i64)
        {
            return Err(invalid_succinct_setup_proof(format!(
                "VSS witness for shared coefficient slot {slot_index} has the wrong shape"
            )));
        }
    }
    for item_index in 0..item_count {
        let (
            recipient_roster_position,
            source_message_modulus,
            item_coefficient_count,
            item_coefficient_slot_indices,
        ) = if item_index == 0 {
            (
                statement.recipient_roster_position,
                statement.source_message_modulus,
                statement.coefficient_commitments.len(),
                &coefficient_slot_indices_by_item[0],
            )
        } else {
            let item = &statement.additional_linkage_items[item_index - 1];
            (
                item.recipient_roster_position,
                item.source_message_modulus,
                item.coefficient_commitments.len(),
                &coefficient_slot_indices_by_item[item_index],
            )
        };
        if item_coefficient_slot_indices.len() != item_coefficient_count
            || item_coefficient_slot_indices
                .iter()
                .any(|slot_index| *slot_index >= coefficient_count)
        {
            return Err(invalid_succinct_setup_proof(
                "VSS coefficient witness slot layout does not match the item",
            ));
        }
        let source_modulus_i64 = i64::try_from(source_message_modulus)
            .map_err(|_| invalid_succinct_setup_proof("VSS source modulus does not fit i64"))?;
        let recipient_share_messages = recipient_share_messages_by_item[item_index];
        let carry_witnesses = carry_witnesses_by_item[item_index];
        if recipient_share_messages.len() != ring_degree
            || carry_witnesses.len() != ring_degree
            || recipient_share_messages
                .iter()
                .any(|coefficient| *coefficient < 0 || *coefficient >= source_modulus_i64)
        {
            return Err(invalid_succinct_setup_proof(
                "VSS recipient share witness has the wrong shape",
            ));
        }
        let lincheck_roster_position = vss_share_linkage_lincheck_roster_position(
            statement.is_threshold_aggregate,
            recipient_roster_position,
        );
        let carry_bound =
            private_vss_share_lifted_carry_bound(lincheck_roster_position, item_coefficient_count)?;
        for carry in carry_witnesses {
            let carry_i128 = i128::from(*carry);
            if carry_i128 < 0 || carry_i128 > carry_bound {
                return Err(invalid_succinct_setup_proof(
                    "VSS carry witness is outside the accepted bound",
                ));
            }
        }
        let trustee_point = i128::from(crate::bgv::setup::sharing::canonical_trustee_point(
            usize::try_from(lincheck_roster_position).map_err(|_| {
                invalid_succinct_setup_proof("VSS recipient roster position does not fit usize")
            })?,
            source_message_modulus,
        )?);
        let mut powers = Vec::with_capacity(item_coefficient_count);
        let mut power = 1_i128;
        for _ in 0..item_coefficient_count {
            powers.push(power);
            power = power
                .checked_mul(trustee_point)
                .ok_or_else(|| invalid_succinct_setup_proof("VSS point power overflowed"))?;
        }
        for coefficient_position in 0..ring_degree {
            let mut left = 0_i128;
            for (coefficient_slot_index, trustee_point_power) in
                item_coefficient_slot_indices.iter().zip(powers.iter())
            {
                let messages = &witness.vss_public_coefficient_messages_by_shamir_index()
                    [*coefficient_slot_index];
                left = left
                    .checked_add(
                        trustee_point_power
                            .checked_mul(i128::from(messages[coefficient_position]))
                            .ok_or_else(|| {
                                invalid_succinct_setup_proof(
                                    "VSS lifted message product overflowed",
                                )
                            })?,
                    )
                    .ok_or_else(|| invalid_succinct_setup_proof("VSS lifted sum overflowed"))?;
            }
            left = left
                .checked_sub(i128::from(recipient_share_messages[coefficient_position]))
                .ok_or_else(|| invalid_succinct_setup_proof("VSS lifted share overflowed"))?;
            left = left
                .checked_sub(
                    i128::from(source_message_modulus)
                        .checked_mul(i128::from(carry_witnesses[coefficient_position]))
                        .ok_or_else(|| {
                            invalid_succinct_setup_proof("VSS lifted carry overflowed")
                        })?,
                )
                .ok_or_else(|| invalid_succinct_setup_proof("VSS lifted relation overflowed"))?;
            if left != 0 {
                return Err(invalid_succinct_setup_proof(format!(
                    "VSS lifted relation failed for item {item_index} at coefficient {coefficient_position}"
                )));
            }
        }
    }

    Ok(())
}

fn validate_private_vss_witness(
    statement: &super::super::relation::PrivateVssShareStatement,
    witness: &TrusteeEvaluationKeyWitness,
    ring_degree: usize,
) -> CanonicalResult<()> {
    let coefficient_count = statement.coefficient_commitments.len();
    if witness
        .private_vss_coefficient_messages_by_shamir_index()
        .len()
        != coefficient_count
        || witness
            .private_vss_opening_randomness_by_shamir_index()
            .len()
            != coefficient_count
        || witness.private_vss_carry_witnesses().len() != ring_degree
    {
        return Err(invalid_succinct_setup_proof(
            "private VSS witness shape does not match the statement",
        ));
    }
    let source_modulus_i64 = i64::try_from(statement.source_message_modulus)
        .map_err(|_| invalid_succinct_setup_proof("private VSS source modulus does not fit i64"))?;
    for (coefficient_index, (messages, randomness_columns)) in witness
        .private_vss_coefficient_messages_by_shamir_index()
        .iter()
        .zip(
            witness
                .private_vss_opening_randomness_by_shamir_index()
                .iter(),
        )
        .enumerate()
    {
        if messages.len() != ring_degree
            || messages
                .iter()
                .any(|coefficient| *coefficient < 0 || *coefficient >= source_modulus_i64)
            || randomness_columns.len() != SETUP_COMMITMENT_RANDOMNESS_WIDTH
            || randomness_columns.iter().any(|column| {
                column.len() != ring_degree
                    || column
                        .iter()
                        .any(|coefficient| !(-1..=1).contains(coefficient))
            })
        {
            return Err(invalid_succinct_setup_proof(format!(
                "private VSS witness for Shamir coefficient {coefficient_index} has the wrong shape"
            )));
        }
    }
    let carry_bound = private_vss_share_lifted_carry_bound(
        statement.recipient_roster_position,
        coefficient_count,
    )?;
    for carry in witness.private_vss_carry_witnesses() {
        let carry_i128 = i128::from(*carry);
        if carry_i128 < 0 || carry_i128 > carry_bound {
            return Err(invalid_succinct_setup_proof(
                "private VSS carry witness is outside the accepted bound",
            ));
        }
    }
    let trustee_point = i128::from(crate::bgv::setup::sharing::canonical_trustee_point(
        usize::try_from(statement.recipient_roster_position).map_err(|_| {
            invalid_succinct_setup_proof("private VSS recipient roster position does not fit usize")
        })?,
        statement.source_message_modulus,
    )?);
    let mut powers = Vec::with_capacity(coefficient_count);
    let mut power = 1_i128;
    for _ in 0..coefficient_count {
        powers.push(power);
        power = power
            .checked_mul(trustee_point)
            .ok_or_else(|| invalid_succinct_setup_proof("private VSS point power overflowed"))?;
    }
    for coefficient_position in 0..ring_degree {
        let mut left = 0_i128;
        for (messages, trustee_point_power) in witness
            .private_vss_coefficient_messages_by_shamir_index()
            .iter()
            .zip(powers.iter())
        {
            left = left
                .checked_add(
                    trustee_point_power
                        .checked_mul(i128::from(messages[coefficient_position]))
                        .ok_or_else(|| {
                            invalid_succinct_setup_proof(
                                "private VSS lifted message product overflowed",
                            )
                        })?,
                )
                .ok_or_else(|| invalid_succinct_setup_proof("private VSS lifted sum overflowed"))?;
        }
        left = left
            .checked_sub(
                i128::from(statement.source_message_modulus)
                    .checked_mul(i128::from(
                        witness.private_vss_carry_witnesses()[coefficient_position],
                    ))
                    .ok_or_else(|| {
                        invalid_succinct_setup_proof("private VSS lifted carry overflowed")
                    })?,
            )
            .ok_or_else(|| {
                invalid_succinct_setup_proof("private VSS lifted relation overflowed")
            })?;
        if left != i128::from(statement.share_values[coefficient_position]) {
            return Err(invalid_succinct_setup_proof(format!(
                "private VSS lifted relation failed at coefficient {coefficient_position}"
            )));
        }
    }

    Ok(())
}
