use super::super::evaluation_domain::EvaluationDomainPlan;
use super::super::merkle_commitment::{WITNESS_TREE_ORDINAL_BASE, limb_tree_context};
use super::super::relation::{
    LimbColumnLayout, SetupProofStatement, TrusteeEvaluationKeyStatement,
    TrusteeEvaluationKeyWitness, private_vss_share_lifted_carry_bound,
};
use super::super::{TRACE_SPLIT, invalid_succinct_setup_proof, signed_value_residue};
use super::claim_masking::{mask_digit_columns, masked_half_coefficients};
use super::salted_tree::{SaltedTree, commit_salted_extension_row_pairs};
use super::{COLUMN_MASK_DOMAIN, LEAF_SALT_DOMAIN};
use crate::bgv::evaluator::prg::DeterministicSampler;
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_RANDOMNESS_WIDTH, setup_commitment_randomness_coefficient_bound,
};
use crate::encoding::CanonicalResult;

fn signed_residue_vector(coefficients: &[i64], modulus: u64) -> Vec<u64> {
    coefficients
        .iter()
        .map(|coefficient| signed_value_residue(*coefficient, modulus))
        .collect()
}

pub(super) struct LimbWitnessCommitment {
    pub(super) plan: EvaluationDomainPlan,
    pub(super) layout: LimbColumnLayout,
    pub(super) masked_coefficients: Vec<Vec<u64>>,
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
    if !layout.private_vss_active() {
        return Err(invalid_succinct_setup_proof(
            "the shared per-limb witness engine is reserved for private VSS proofs",
        ));
    }
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

    for coefficient_messages in witness.private_vss_coefficient_messages_by_shamir_index() {
        append_logical_vector(&signed_residue_vector(coefficient_messages, modulus));
    }
    append_logical_vector(&signed_residue_vector(
        witness.private_vss_carry_witnesses(),
        modulus,
    ));
    for randomness_by_commitment_limb in
        witness.private_vss_opening_randomness_by_shamir_index_and_commitment_limb()
    {
        let randomness_by_column =
            randomness_by_commitment_limb
                .get(limb_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "private VSS witness is missing the current commitment-limb opening tape",
                    )
                })?;
        for column in randomness_by_column {
            append_logical_vector(&signed_residue_vector(column, modulus));
        }
    }
    for logical_vector in mask_digit_columns(statement, &layout, proof_randomness_seed_hex) {
        append_logical_vector(&logical_vector);
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
        limb_tree_context(
            statement.application_statement_schema_identifier(),
            WITNESS_TREE_ORDINAL_BASE,
            limb_index,
        )?,
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
            SetupProofStatement::PrivateVssShare(private_vss_share),
            TrusteeEvaluationKeyWitness::PrivateVssShare { .. },
        ) => validate_private_vss_witness(private_vss_share, witness, statement.ring_degree),
        _ => Err(invalid_succinct_setup_proof(
            "the shared per-limb prover accepts only private VSS witnesses",
        )),
    }
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
            .private_vss_opening_randomness_by_shamir_index_and_commitment_limb()
            .len()
            != coefficient_count
        || witness.private_vss_carry_witnesses().len() != ring_degree
    {
        return Err(invalid_succinct_setup_proof(
            "private VSS witness shape does not match the statement",
        ));
    }
    let source_message_modulus = DATA_PRIMES[statement.source_rns_limb_index];
    let source_modulus_i64 = i64::try_from(source_message_modulus)
        .map_err(|_| invalid_succinct_setup_proof("private VSS source modulus does not fit i64"))?;
    for (coefficient_index, (messages, randomness_by_commitment_limb)) in witness
        .private_vss_coefficient_messages_by_shamir_index()
        .iter()
        .zip(
            witness
                .private_vss_opening_randomness_by_shamir_index_and_commitment_limb()
                .iter(),
        )
        .enumerate()
    {
        if messages.len() != ring_degree
            || messages
                .iter()
                .any(|coefficient| *coefficient < 0 || *coefficient >= source_modulus_i64)
            || randomness_by_commitment_limb.len()
                != crate::bgv::setup::commitment::SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
            || randomness_by_commitment_limb
                .iter()
                .any(|randomness_by_column| {
                    randomness_by_column.len() != SETUP_COMMITMENT_RANDOMNESS_WIDTH
                        || randomness_by_column.iter().enumerate().any(
                            |(randomness_column_index, column)| {
                                let coefficient_bound =
                                    setup_commitment_randomness_coefficient_bound(
                                        randomness_column_index,
                                    )
                                    .expect("a canonical commitment column has a support bound");
                                column.len() != ring_degree
                                    || column.iter().any(|coefficient| {
                                        i128::from(*coefficient).unsigned_abs()
                                            > coefficient_bound as u128
                                    })
                            },
                        )
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
        source_message_modulus,
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
        let mut lifted_sum = 0_i128;
        for (messages, trustee_point_power) in witness
            .private_vss_coefficient_messages_by_shamir_index()
            .iter()
            .zip(powers.iter())
        {
            lifted_sum = lifted_sum
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
        lifted_sum = lifted_sum
            .checked_sub(
                i128::from(source_message_modulus)
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
        if lifted_sum != i128::from(statement.share_values[coefficient_position]) {
            return Err(invalid_succinct_setup_proof(format!(
                "private VSS lifted relation failed at coefficient {coefficient_position}"
            )));
        }
    }
    Ok(())
}
