use super::super::evaluation_domain::EvaluationDomainPlan;
use super::super::relation::{
    LimbColumnLayout, TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness,
    private_vss_share_lifted_carry_bound,
};
use super::super::*;
use super::claim_masking::{mask_digit_columns, masked_half_coefficients};
use super::salted_tree::{SaltedTree, commit_salted_extension_rows};
use super::*;
use crate::bgv::evaluator::prg::DeterministicSampler;
use crate::bgv::setup::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH;

// Logical witness vectors in local layout order as residue vectors mod q. For
// private VSS: the Shamir coefficient messages, the carry, and the
// per-coefficient opening-randomness columns. For the standard family: the
// secret, the active keys' error vectors, and in the commitment fields the
// negative indicator and the per-commitment opening-randomness columns. This is
// the full trace width, which for private VSS exceeds consistency_vector_count()
// because the message columns are committed witnesses without a consistency
// claim.
fn logical_witness_residues(
    witness: &TrusteeEvaluationKeyWitness,
    layout: &LimbColumnLayout,
    modulus: u64,
) -> Vec<Vec<u64>> {
    let logical_column_count = if layout.private_vss_active() {
        layout.private_vss_logical_columns()
    } else {
        layout.consistency_vector_count()
    };
    let mut vectors = Vec::with_capacity(logical_column_count);
    if layout.private_vss_active() {
        for coefficient_messages in &witness.private_vss_coefficient_messages_by_shamir_index {
            vectors.push(
                coefficient_messages
                    .iter()
                    .map(|coefficient| signed_value_residue(*coefficient, modulus))
                    .collect::<Vec<_>>(),
            );
        }
        vectors.push(
            witness
                .private_vss_carry_witnesses
                .iter()
                .map(|coefficient| signed_value_residue(*coefficient, modulus))
                .collect::<Vec<_>>(),
        );
        for randomness_columns in &witness.private_vss_opening_randomness_by_shamir_index {
            for column in randomness_columns {
                vectors.push(
                    column
                        .iter()
                        .map(|coefficient| signed_value_residue(*coefficient, modulus))
                        .collect::<Vec<_>>(),
                );
            }
        }

        return vectors;
    }
    vectors.push(
        witness
            .secret_coefficients
            .iter()
            .map(|coefficient| signed_value_residue(*coefficient, modulus))
            .collect::<Vec<_>>(),
    );
    for (key_index, digit_count) in &layout.active_keys {
        for digit_index in 0..*digit_count {
            vectors.push(
                witness.error_coefficients_by_key[*key_index][digit_index]
                    .iter()
                    .map(|coefficient| signed_value_residue(*coefficient, modulus))
                    .collect::<Vec<_>>(),
            );
        }
    }
    if layout.linkage_active() {
        vectors.push(
            witness
                .negative_indicator_coefficients
                .iter()
                .map(|coefficient| signed_value_residue(*coefficient, modulus))
                .collect::<Vec<_>>(),
        );
        for randomness_columns in &witness.opening_randomness_by_limb {
            for column in randomness_columns {
                vectors.push(
                    column
                        .iter()
                        .map(|coefficient| signed_value_residue(*coefficient, modulus))
                        .collect::<Vec<_>>(),
                );
            }
        }
    }

    vectors
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
    limb_index: usize,
    modulus: u64,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<LimbWitnessCommitment> {
    let layout = LimbColumnLayout::new(statement, limb_index)?;
    let plan = EvaluationDomainPlan::new(modulus, layout.trace_size)?;
    let logical_witness = logical_witness_residues(witness, &layout, modulus);
    let mask_columns = mask_digit_columns(statement, &layout, proof_randomness_seed_hex);

    // Assemble the physical half-columns in layout order: secret halves, then
    // per error position the error halves, then the error-square halves, then
    // the mask digit halves. The grouped push order below matches the layout's
    // physical index functions exactly.
    let trace_size = layout.trace_size;
    let mut physical_halves: Vec<&[u64]> = Vec::with_capacity(layout.phase_one_physical_count());
    let error_squares_storage: Vec<Vec<u64>>;
    if layout.private_vss_active() {
        for logical_vector in &logical_witness {
            for half in 0..TRACE_SPLIT {
                physical_halves.push(&logical_vector[half * trace_size..(half + 1) * trace_size]);
            }
        }
    } else {
        error_squares_storage = (0..layout.total_error_columns)
            .map(|error_position| {
                logical_witness[1 + error_position]
                    .iter()
                    .map(|value| mul_mod_fast(*value, *value, modulus))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for half in 0..TRACE_SPLIT {
            physical_halves.push(&logical_witness[0][half * trace_size..(half + 1) * trace_size]);
        }
        for error_position in 0..layout.total_error_columns {
            let error = &logical_witness[1 + error_position];
            for half in 0..TRACE_SPLIT {
                physical_halves.push(&error[half * trace_size..(half + 1) * trace_size]);
            }
        }
        for error_square in &error_squares_storage {
            for half in 0..TRACE_SPLIT {
                physical_halves.push(&error_square[half * trace_size..(half + 1) * trace_size]);
            }
        }
        if layout.linkage_active() {
            for linkage_vector in &logical_witness[1 + layout.total_error_columns..] {
                for half in 0..TRACE_SPLIT {
                    physical_halves
                        .push(&linkage_vector[half * trace_size..(half + 1) * trace_size]);
                }
            }
        }
    }
    for mask_column in &mask_columns {
        for half in 0..TRACE_SPLIT {
            physical_halves.push(&mask_column[half * trace_size..(half + 1) * trace_size]);
        }
    }
    debug_assert_eq!(physical_halves.len(), layout.phase_one_physical_count());

    let mut masked_coefficients = Vec::with_capacity(physical_halves.len());
    let mut extension_columns = Vec::with_capacity(physical_halves.len());
    for (physical_index, half_values) in physical_halves.iter().enumerate() {
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
    let mut salt_sampler = DeterministicSampler::new(
        LEAF_SALT_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            b"phase-one",
            &(limb_index as u64).to_le_bytes(),
        ],
    );
    let salted =
        commit_salted_extension_rows(&extension_columns, plan.extension_size, &mut salt_sampler)?;

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
    if let Some(private_vss_share) = &statement.private_vss_share {
        if !witness.secret_coefficients.is_empty()
            || !witness.error_coefficients_by_key.is_empty()
            || !witness.negative_indicator_coefficients.is_empty()
            || !witness.opening_randomness_by_limb.is_empty()
        {
            return Err(invalid_succinct_setup_proof(
                "private VSS witness must not include key or same-secret linkage material",
            ));
        }
        return validate_private_vss_witness(private_vss_share, witness, statement.ring_degree);
    }
    if witness.secret_coefficients.len() != statement.ring_degree
        || witness.error_coefficients_by_key.len() != statement.keys.len()
    {
        return Err(invalid_succinct_setup_proof(
            "witness shape does not match the statement",
        ));
    }
    if witness
        .secret_coefficients
        .iter()
        .any(|coefficient| !(-1..=1).contains(coefficient))
    {
        return Err(invalid_succinct_setup_proof(
            "witness secret must be ternary",
        ));
    }
    for (key, errors) in statement
        .keys
        .iter()
        .zip(witness.error_coefficients_by_key.iter())
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
    match &statement.same_secret_linkage {
        Some(linkage) => {
            if witness.negative_indicator_coefficients.len() != statement.ring_degree
                || witness
                    .negative_indicator_coefficients
                    .iter()
                    .any(|coefficient| !(0..=1).contains(coefficient))
            {
                return Err(invalid_succinct_setup_proof(
                    "witness negative indicator must be binary at the ring degree",
                ));
            }
            if witness.opening_randomness_by_limb.len() != linkage.commitments.len()
                || witness.opening_randomness_by_limb.iter().any(|columns| {
                    columns.len()
                        != crate::bgv::setup::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH
                        || columns.iter().any(|column| {
                            column.len() != statement.ring_degree
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
        }
        None => {
            if !witness.negative_indicator_coefficients.is_empty()
                || !witness.opening_randomness_by_limb.is_empty()
            {
                return Err(invalid_succinct_setup_proof(
                    "witness linkage material requires a same-secret linkage statement",
                ));
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
        .private_vss_coefficient_messages_by_shamir_index
        .len()
        != coefficient_count
        || witness.private_vss_opening_randomness_by_shamir_index.len() != coefficient_count
        || witness.private_vss_carry_witnesses.len() != ring_degree
    {
        return Err(invalid_succinct_setup_proof(
            "private VSS witness shape does not match the statement",
        ));
    }
    let source_modulus_i64 = i64::try_from(statement.source_message_modulus)
        .map_err(|_| invalid_succinct_setup_proof("private VSS source modulus does not fit i64"))?;
    for (coefficient_index, (messages, randomness_columns)) in witness
        .private_vss_coefficient_messages_by_shamir_index
        .iter()
        .zip(
            witness
                .private_vss_opening_randomness_by_shamir_index
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
    for carry in &witness.private_vss_carry_witnesses {
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
            .private_vss_coefficient_messages_by_shamir_index
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
                        witness.private_vss_carry_witnesses[coefficient_position],
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
