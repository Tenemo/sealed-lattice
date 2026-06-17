use super::*;
use crate::bgv::modular_arithmetic::{add_mod_fast, mul_mod_fast};
use std::sync::Arc;

pub(super) const DIRECT_BALLOT_COMMITTED_RANDOMIZER_COLUMN: usize = 0;
pub(super) const DIRECT_BALLOT_COMMITTED_FIRST_ERROR_COLUMN: usize = 1;
pub(super) const DIRECT_BALLOT_COMMITTED_FIRST_ERROR_SQUARE_COLUMN: usize = 2;
pub(super) const DIRECT_BALLOT_COMMITTED_SECOND_ERROR_COLUMN: usize = 3;
pub(super) const DIRECT_BALLOT_COMMITTED_SECOND_ERROR_SQUARE_COLUMN: usize = 4;
pub(super) const DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN: usize = 5;
pub(super) const DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_COUNT: usize = 8;
pub(super) const DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_START_COLUMN: usize = 6;
pub(super) const DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_SLACK_BIT_START_COLUMN: usize =
    DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_START_COLUMN
        + DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_COUNT;
pub(super) const DIRECT_BALLOT_COMMITTED_SCORE_COLUMN: usize =
    DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_SLACK_BIT_START_COLUMN
        + DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_COUNT;
pub(super) const DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN: usize =
    DIRECT_BALLOT_COMMITTED_SCORE_COLUMN + 1;
pub(super) const DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN: usize =
    DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN + 1;
pub(super) const DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_DIGIT_RADIX: u64 = 3;
pub(super) const DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_TERNARY_DIGIT_COUNT: usize = 41;
pub(super) const DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SHIFTED_DIGIT_START_COLUMN: usize =
    DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN + 1;
pub(super) const DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SLACK_DIGIT_START_COLUMN: usize =
    DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SHIFTED_DIGIT_START_COLUMN
        + DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_TERNARY_DIGIT_COUNT;
pub(super) const DIRECT_BALLOT_COMMITTED_COLUMN_COUNT: usize =
    DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SLACK_DIGIT_START_COLUMN
        + DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_TERNARY_DIGIT_COUNT;
pub(super) const DIRECT_BALLOT_COMMITTED_TRACE_SPLIT: usize = 2;

pub(super) struct DirectBallotCommittedBatchedLinearClaim {
    pub(super) coefficient_columns: Vec<Vec<u64>>,
    pub(super) public_offset: u64,
}

#[derive(Clone)]
enum DirectBallotCommittedLinearClaimPlan {
    OneHotRowSum {
        limb_index: usize,
        modulus: u64,
        option_index: usize,
    },
    ScoreLinkage {
        limb_index: usize,
        modulus: u64,
        option_index: usize,
    },
    ProjectedBgv {
        row_index: usize,
        row: Arc<DirectBallotProjectedBgvRelationRow>,
    },
    ProjectedBgvNoWrap {
        verifier_limb_index: usize,
        verifier_modulus: u64,
        row_index: usize,
        row: Arc<DirectBallotProjectedBgvRelationRow>,
    },
}

pub(super) fn verify_direct_ballot_committed_support_witness(
    witness_vector: &DirectBallotWitnessVector,
    modulus: u64,
) -> CanonicalResult<()> {
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    let columns = direct_ballot_committed_witness_columns(witness_vector, modulus)?;
    verify_direct_ballot_committed_support_columns(&columns, modulus)
}

pub(super) fn verify_direct_ballot_committed_linear_witness(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    let claim_plans =
        direct_ballot_committed_linear_claim_plans(statement_hash, public_key, ballot)?;
    let mut columns_by_limb = Vec::with_capacity(DATA_PRIMES.len());
    for modulus in DATA_PRIMES {
        columns_by_limb.push(direct_ballot_committed_witness_columns(
            witness_vector,
            modulus,
        )?);
    }
    for claim_plan in &claim_plans {
        let limb_index = claim_plan.limb_index();
        let columns = columns_by_limb.get(limb_index).ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed linear claim references a missing limb",
            )
        })?;
        verify_direct_ballot_committed_linear_claim(claim_plan, columns, witness_vector)?;
    }

    Ok(())
}

impl DirectBallotCommittedLinearClaimPlan {
    fn limb_index(&self) -> usize {
        match self {
            Self::OneHotRowSum { limb_index, .. } | Self::ScoreLinkage { limb_index, .. } => {
                *limb_index
            }
            Self::ProjectedBgv { row, .. } => row.limb_index,
            Self::ProjectedBgvNoWrap {
                verifier_limb_index,
                ..
            } => *verifier_limb_index,
        }
    }
}

fn direct_ballot_committed_linear_claim_plans(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<Vec<DirectBallotCommittedLinearClaimPlan>> {
    let projected_bgv_rows = direct_ballot_committed_projected_bgv_rows_for_linear_claims(
        statement_hash,
        public_key,
        ballot,
    )?;
    let mut plans = Vec::with_capacity(
        DATA_PRIMES.len() * DIRECT_BALLOT_OPTION_COUNT * 2 + projected_bgv_rows.len(),
    );
    for (limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        for option_index in 0..DIRECT_BALLOT_OPTION_COUNT {
            plans.push(DirectBallotCommittedLinearClaimPlan::OneHotRowSum {
                limb_index,
                modulus,
                option_index,
            });
            plans.push(DirectBallotCommittedLinearClaimPlan::ScoreLinkage {
                limb_index,
                modulus,
                option_index,
            });
        }
    }
    for (row_index, row) in projected_bgv_rows.iter().cloned().enumerate() {
        plans.push(DirectBallotCommittedLinearClaimPlan::ProjectedBgv {
            row_index,
            row: row.clone(),
        });
        for (verifier_limb_index, verifier_modulus) in DATA_PRIMES.iter().copied().enumerate() {
            if verifier_limb_index != row.limb_index {
                plans.push(DirectBallotCommittedLinearClaimPlan::ProjectedBgvNoWrap {
                    verifier_limb_index,
                    verifier_modulus,
                    row_index,
                    row: row.clone(),
                });
            }
        }
    }

    Ok(plans)
}

pub(super) fn direct_ballot_committed_projected_bgv_rows_for_linear_claims(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<Vec<Arc<DirectBallotProjectedBgvRelationRow>>> {
    Ok(compile_direct_ballot_projected_bgv_relation_rows(
        statement_hash,
        public_key,
        ballot,
        DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
    )?
    .into_iter()
    .map(Arc::new)
    .collect())
}

pub(super) fn direct_ballot_committed_batched_linear_claim_challenge_count(
    projected_bgv_rows: &[Arc<DirectBallotProjectedBgvRelationRow>],
    verifier_limb_index: usize,
) -> CanonicalResult<usize> {
    if verifier_limb_index >= DATA_PRIMES.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed linear claim references a missing limb",
        ));
    }
    if projected_bgv_rows
        .iter()
        .any(|row| row.limb_index >= DATA_PRIMES.len())
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed linear claim references a projected BGV row outside the profile",
        ));
    }
    DIRECT_BALLOT_OPTION_COUNT
        .checked_mul(2)
        .and_then(|option_claim_count| option_claim_count.checked_add(projected_bgv_rows.len()))
        .ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed linear claim count overflowed",
            )
        })
}

pub(super) fn direct_ballot_committed_batched_linear_claims(
    projected_bgv_rows: &[Arc<DirectBallotProjectedBgvRelationRow>],
    verifier_limb_index: usize,
    verifier_modulus: u64,
    single_batch_challenge_count: usize,
    batching_challenges: &[u64],
) -> CanonicalResult<Vec<DirectBallotCommittedBatchedLinearClaim>> {
    let claim_plans = direct_ballot_committed_linear_claim_plans_for_limb(
        projected_bgv_rows,
        verifier_limb_index,
        verifier_modulus,
    )?;
    if claim_plans.len() != single_batch_challenge_count {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed linear claim challenge count does not match the profile",
        ));
    }
    if single_batch_challenge_count == 0 {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed linear claim batch must not be empty",
        ));
    }
    if !batching_challenges
        .len()
        .is_multiple_of(single_batch_challenge_count)
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed linear claim batch challenge count does not match the profile",
        ));
    }

    let batch_count = batching_challenges.len() / single_batch_challenge_count;
    if batch_count == 0 {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed linear claim batch count must not be empty",
        ));
    }
    let mut coefficient_columns_by_batch =
        vec![
            vec![vec![0_u64; POLYNOMIAL_DEGREE]; DIRECT_BALLOT_COMMITTED_COLUMN_COUNT];
            batch_count
        ];
    let mut public_offsets = vec![0_u64; batch_count];
    for (claim_index, claim_plan) in claim_plans.iter().enumerate() {
        accumulate_direct_ballot_committed_linear_claim_batches(
            claim_index,
            claim_plan,
            verifier_modulus,
            single_batch_challenge_count,
            batching_challenges,
            &mut coefficient_columns_by_batch,
            &mut public_offsets,
        )?;
    }

    Ok(coefficient_columns_by_batch
        .into_iter()
        .zip(public_offsets)
        .map(
            |(coefficient_columns, public_offset)| DirectBallotCommittedBatchedLinearClaim {
                coefficient_columns,
                public_offset,
            },
        )
        .collect())
}

fn direct_ballot_committed_linear_claim_plans_for_limb(
    projected_bgv_rows: &[Arc<DirectBallotProjectedBgvRelationRow>],
    verifier_limb_index: usize,
    verifier_modulus: u64,
) -> CanonicalResult<Vec<DirectBallotCommittedLinearClaimPlan>> {
    if verifier_limb_index >= DATA_PRIMES.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed linear claim references a missing limb",
        ));
    }

    let mut plans = Vec::with_capacity(DIRECT_BALLOT_OPTION_COUNT * 2 + projected_bgv_rows.len());
    for option_index in 0..DIRECT_BALLOT_OPTION_COUNT {
        plans.push(DirectBallotCommittedLinearClaimPlan::OneHotRowSum {
            limb_index: verifier_limb_index,
            modulus: verifier_modulus,
            option_index,
        });
        plans.push(DirectBallotCommittedLinearClaimPlan::ScoreLinkage {
            limb_index: verifier_limb_index,
            modulus: verifier_modulus,
            option_index,
        });
    }
    for (row_index, row) in projected_bgv_rows.iter().cloned().enumerate() {
        if row.limb_index >= DATA_PRIMES.len() {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed linear claim references a projected BGV row outside the profile",
            ));
        }
        if row.limb_index == verifier_limb_index {
            if row.modulus != verifier_modulus {
                return Err(invalid_direct_ballot_relation_proof(
                    "direct ballot committed linear claim modulus does not match the verifier limb",
                ));
            }
            plans.push(DirectBallotCommittedLinearClaimPlan::ProjectedBgv { row_index, row });
        } else {
            plans.push(DirectBallotCommittedLinearClaimPlan::ProjectedBgvNoWrap {
                verifier_limb_index,
                verifier_modulus,
                row_index,
                row,
            });
        }
    }

    Ok(plans)
}

pub(super) fn direct_ballot_committed_witness_columns(
    witness_vector: &DirectBallotWitnessVector,
    modulus: u64,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let mut columns = vec![vec![0_u64; POLYNOMIAL_DEGREE]; DIRECT_BALLOT_COMMITTED_COLUMN_COUNT];
    let encoder_carry_bound =
        direct_ballot_encoder_arithmetic_bounds()?.encoding_carry_coefficient_maximum;
    verify_direct_ballot_committed_encoder_carry_bound(encoder_carry_bound)?;
    let projected_bgv_carry_bound =
        direct_ballot_projected_bgv_no_wrap_committed_carry_maximum_abs()?;
    verify_direct_ballot_committed_projected_bgv_carry_bound(projected_bgv_carry_bound, modulus)?;
    columns[DIRECT_BALLOT_COMMITTED_RANDOMIZER_COLUMN] =
        residues_from_bigints(&witness_vector.randomizer_coefficients, modulus)?;
    columns[DIRECT_BALLOT_COMMITTED_FIRST_ERROR_COLUMN] =
        residues_from_bigints(&witness_vector.error_zero_coefficients, modulus)?;
    columns[DIRECT_BALLOT_COMMITTED_SECOND_ERROR_COLUMN] =
        residues_from_bigints(&witness_vector.error_one_coefficients, modulus)?;
    columns[DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN] =
        residues_from_bigints(&witness_vector.encoding_carry_coefficients, modulus)?;
    for (coefficient_index, carry_coefficient) in witness_vector
        .encoding_carry_coefficients
        .iter()
        .enumerate()
    {
        let carry = carry_coefficient.to_u64().ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed encoding carry coefficient is outside the unsigned range",
            )
        })?;
        if carry > encoder_carry_bound {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed encoding carry coefficient exceeds the encoder arithmetic bound",
            ));
        }
        write_committed_unsigned_bit_columns(
            &mut columns,
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_START_COLUMN,
            coefficient_index,
            carry,
        )?;
        write_committed_unsigned_bit_columns(
            &mut columns,
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_SLACK_BIT_START_COLUMN,
            coefficient_index,
            encoder_carry_bound - carry,
        )?;
    }
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let first_error = columns[DIRECT_BALLOT_COMMITTED_FIRST_ERROR_COLUMN][coefficient_index];
        let second_error = columns[DIRECT_BALLOT_COMMITTED_SECOND_ERROR_COLUMN][coefficient_index];
        columns[DIRECT_BALLOT_COMMITTED_FIRST_ERROR_SQUARE_COLUMN][coefficient_index] =
            mul_mod(first_error, first_error, modulus)?;
        columns[DIRECT_BALLOT_COMMITTED_SECOND_ERROR_SQUARE_COLUMN][coefficient_index] =
            mul_mod(second_error, second_error, modulus)?;
    }
    for (option_index, score) in witness_vector.score_coefficients.iter().enumerate() {
        columns[DIRECT_BALLOT_COMMITTED_SCORE_COLUMN][option_index] =
            signed_bigint_residue(score, modulus)?;
    }
    for (option_index, row) in witness_vector.one_hot_coefficients.iter().enumerate() {
        for (bucket_index, entry) in row.iter().enumerate() {
            let packed_index = direct_ballot_one_hot_packed_index(option_index, bucket_index)?;
            columns[DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN][packed_index] =
                signed_bigint_residue(entry, modulus)?;
        }
    }
    if witness_vector.bgv_no_wrap_carry_scalars.len() > POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed witness cannot pack every projected BGV carry scalar",
        ));
    }
    for (carry_index, carry) in witness_vector.bgv_no_wrap_carry_scalars.iter().enumerate() {
        columns[DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN][carry_index] =
            signed_bigint_residue(carry, modulus)?;
    }
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let carry = witness_vector
            .bgv_no_wrap_carry_scalars
            .get(coefficient_index)
            .cloned()
            .unwrap_or_else(BigInt::zero);
        write_committed_projected_bgv_carry_range_columns(
            &mut columns,
            coefficient_index,
            &carry,
            projected_bgv_carry_bound,
        )?;
    }

    Ok(columns)
}

fn verify_direct_ballot_committed_support_columns(
    columns: &[Vec<u64>],
    modulus: u64,
) -> CanonicalResult<()> {
    verify_direct_ballot_committed_column_shape(columns, modulus)?;
    let physical_columns = direct_ballot_committed_physical_columns(columns, modulus)?;
    verify_direct_ballot_committed_physical_support_columns(&physical_columns, modulus)?;
    verify_one_hot_booleanity_and_score_columns(
        &columns[DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN],
        &columns[DIRECT_BALLOT_COMMITTED_SCORE_COLUMN],
        modulus,
    )?;
    verify_committed_packed_column_shape(
        &columns[DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN],
        direct_ballot_projected_bgv_no_wrap_carry_scalar_count(),
        "projected BGV no-wrap carry",
    )
}

fn verify_direct_ballot_committed_projected_bgv_row(
    row_index: usize,
    row: &DirectBallotProjectedBgvRelationRow,
    columns: &[Vec<u64>],
) -> CanonicalResult<()> {
    verify_direct_ballot_committed_column_shape(columns, row.modulus)?;
    let linear_value = evaluate_direct_ballot_committed_projected_bgv_linear_part(row, columns)?;
    let checked_value = add_mod(linear_value, row.public_offset, row.modulus)?;
    if checked_value != 0 {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "direct ballot committed projected BGV relation limb {} {} projection {} row {row_index} failed",
            row.limb_index,
            row.component.label(),
            row.projection_index
        )));
    }

    Ok(())
}

pub(super) fn direct_ballot_committed_physical_columns(
    logical_columns: &[Vec<u64>],
    modulus: u64,
) -> CanonicalResult<Vec<Vec<u64>>> {
    verify_direct_ballot_committed_column_shape(logical_columns, modulus)?;
    let trace_size = direct_ballot_committed_trace_size()?;
    let mut physical_columns =
        Vec::with_capacity(logical_columns.len() * DIRECT_BALLOT_COMMITTED_TRACE_SPLIT);
    for logical_column in logical_columns {
        for half in 0..DIRECT_BALLOT_COMMITTED_TRACE_SPLIT {
            let start = half * trace_size;
            physical_columns.push(logical_column[start..start + trace_size].to_vec());
        }
    }

    Ok(physical_columns)
}

fn verify_direct_ballot_committed_physical_support_columns(
    physical_columns: &[Vec<u64>],
    modulus: u64,
) -> CanonicalResult<()> {
    let trace_size = direct_ballot_committed_trace_size()?;
    let encoder_carry_bound =
        direct_ballot_encoder_arithmetic_bounds()?.encoding_carry_coefficient_maximum;
    verify_direct_ballot_committed_encoder_carry_bound(encoder_carry_bound)?;
    let projected_bgv_carry_bound =
        direct_ballot_projected_bgv_no_wrap_committed_carry_maximum_abs()?;
    verify_direct_ballot_committed_projected_bgv_carry_bound(projected_bgv_carry_bound, modulus)?;
    if physical_columns.len()
        != DIRECT_BALLOT_COMMITTED_COLUMN_COUNT * DIRECT_BALLOT_COMMITTED_TRACE_SPLIT
        || physical_columns
            .iter()
            .any(|column| column.len() != trace_size)
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed physical columns do not match the fixed trace layout",
        ));
    }
    for half in 0..DIRECT_BALLOT_COMMITTED_TRACE_SPLIT {
        let randomizer_column = &physical_columns[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_RANDOMIZER_COLUMN,
            half,
        )?];
        let first_error_column = &physical_columns[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_FIRST_ERROR_COLUMN,
            half,
        )?];
        let first_error_square_column = &physical_columns[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_FIRST_ERROR_SQUARE_COLUMN,
            half,
        )?];
        let second_error_column = &physical_columns[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_SECOND_ERROR_COLUMN,
            half,
        )?];
        let second_error_square_column = &physical_columns
            [direct_ballot_committed_physical_column(
                DIRECT_BALLOT_COMMITTED_SECOND_ERROR_SQUARE_COLUMN,
                half,
            )?];
        let encoding_carry_column = &physical_columns[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN,
            half,
        )?];
        let encoding_carry_bit_columns = committed_bit_physical_columns(
            physical_columns,
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_START_COLUMN,
            half,
        )?;
        let encoding_carry_slack_bit_columns = committed_bit_physical_columns(
            physical_columns,
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_SLACK_BIT_START_COLUMN,
            half,
        )?;
        let projected_bgv_carry_column = &physical_columns
            [direct_ballot_committed_physical_column(
                DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN,
                half,
            )?];
        let projected_bgv_carry_shifted_digit_columns = committed_digit_physical_columns(
            physical_columns,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SHIFTED_DIGIT_START_COLUMN,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_TERNARY_DIGIT_COUNT,
            half,
        )?;
        let projected_bgv_carry_slack_digit_columns = committed_digit_physical_columns(
            physical_columns,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SLACK_DIGIT_START_COLUMN,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_TERNARY_DIGIT_COUNT,
            half,
        )?;
        let one_hot_column = &physical_columns[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN,
            half,
        )?];
        for half_position in 0..trace_size {
            let coefficient_index = half * trace_size + half_position;
            if ternary_support_value(randomizer_column[half_position], modulus)? != 0 {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed randomizer support row failed at coefficient {coefficient_index}"
                )));
            }
            verify_direct_ballot_committed_error_support_value(
                first_error_column[half_position],
                first_error_square_column[half_position],
                modulus,
                "first error",
                coefficient_index,
            )?;
            verify_direct_ballot_committed_error_support_value(
                second_error_column[half_position],
                second_error_square_column[half_position],
                modulus,
                "second error",
                coefficient_index,
            )?;
            verify_direct_ballot_committed_unsigned_bit_columns(
                &encoding_carry_bit_columns,
                half_position,
                modulus,
                "encoding carry bit",
                coefficient_index,
            )?;
            verify_direct_ballot_committed_unsigned_bit_columns(
                &encoding_carry_slack_bit_columns,
                half_position,
                modulus,
                "encoding carry slack bit",
                coefficient_index,
            )?;
            let encoding_carry_bit_sum =
                committed_unsigned_bit_sum(&encoding_carry_bit_columns, half_position, modulus)?;
            let encoding_carry_slack_bit_sum = committed_unsigned_bit_sum(
                &encoding_carry_slack_bit_columns,
                half_position,
                modulus,
            )?;
            if encoding_carry_column[half_position] != encoding_carry_bit_sum {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed encoding carry bit decomposition row failed at coefficient {coefficient_index}"
                )));
            }
            if sub_mod(
                add_mod(
                    encoding_carry_column[half_position],
                    encoding_carry_slack_bit_sum,
                    modulus,
                )?,
                encoder_carry_bound % modulus,
                modulus,
            )? != 0
            {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed encoding carry range row failed at coefficient {coefficient_index}"
                )));
            }
            verify_direct_ballot_committed_ternary_digit_columns(
                &projected_bgv_carry_shifted_digit_columns,
                half_position,
                modulus,
                "projected BGV carry shifted digit",
                coefficient_index,
            )?;
            verify_direct_ballot_committed_ternary_digit_columns(
                &projected_bgv_carry_slack_digit_columns,
                half_position,
                modulus,
                "projected BGV carry slack digit",
                coefficient_index,
            )?;
            let projected_bgv_carry_shifted_sum = committed_ternary_digit_sum(
                &projected_bgv_carry_shifted_digit_columns,
                half_position,
                modulus,
            )?;
            let projected_bgv_carry_slack_sum = committed_ternary_digit_sum(
                &projected_bgv_carry_slack_digit_columns,
                half_position,
                modulus,
            )?;
            if sub_mod(
                add_mod(
                    projected_bgv_carry_column[half_position],
                    projected_bgv_carry_bound % modulus,
                    modulus,
                )?,
                projected_bgv_carry_shifted_sum,
                modulus,
            )? != 0
            {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed projected BGV carry shifted decomposition row failed at coefficient {coefficient_index}"
                )));
            }
            if sub_mod(
                add_mod(
                    projected_bgv_carry_shifted_sum,
                    projected_bgv_carry_slack_sum,
                    modulus,
                )?,
                direct_ballot_committed_projected_bgv_carry_twice_bound_modulus(
                    projected_bgv_carry_bound,
                    modulus,
                )?,
                modulus,
            )? != 0
            {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed projected BGV carry range row failed at coefficient {coefficient_index}"
                )));
            }
            if boolean_support_value(one_hot_column[half_position], modulus)? != 0 {
                let option_index = coefficient_index / DIRECT_BALLOT_SCORE_BUCKET_COUNT;
                let bucket_index = coefficient_index % DIRECT_BALLOT_SCORE_BUCKET_COUNT;
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed one-hot Booleanity row failed at option {option_index} bucket {bucket_index}"
                )));
            }
        }
    }

    Ok(())
}

pub(super) fn direct_ballot_committed_trace_size() -> CanonicalResult<usize> {
    if !POLYNOMIAL_DEGREE.is_multiple_of(DIRECT_BALLOT_COMMITTED_TRACE_SPLIT) {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace split does not divide the polynomial degree",
        ));
    }

    Ok(POLYNOMIAL_DEGREE / DIRECT_BALLOT_COMMITTED_TRACE_SPLIT)
}

pub(super) fn direct_ballot_committed_physical_column(
    logical_column: usize,
    half: usize,
) -> CanonicalResult<usize> {
    if logical_column >= DIRECT_BALLOT_COMMITTED_COLUMN_COUNT
        || half >= DIRECT_BALLOT_COMMITTED_TRACE_SPLIT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed physical column index is outside the fixed layout",
        ));
    }
    logical_column
        .checked_mul(DIRECT_BALLOT_COMMITTED_TRACE_SPLIT)
        .and_then(|base| base.checked_add(half))
        .ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed physical column index overflowed",
            )
        })
}

fn direct_ballot_committed_unsigned_bit_bound() -> u64 {
    (1_u64 << DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_COUNT) - 1
}

pub(super) fn verify_direct_ballot_committed_encoder_carry_bound(
    maximum: u64,
) -> CanonicalResult<()> {
    if maximum > direct_ballot_committed_unsigned_bit_bound() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed encoding carry bit width is too small for the encoder arithmetic bound",
        ));
    }

    Ok(())
}

pub(super) fn verify_direct_ballot_committed_projected_bgv_carry_bound(
    maximum_abs: u64,
    modulus: u64,
) -> CanonicalResult<()> {
    let twice_bound = u128::from(maximum_abs).checked_mul(2).ok_or_else(|| {
        invalid_direct_ballot_relation_proof(
            "direct ballot committed projected BGV carry bound overflowed",
        )
    })?;
    if twice_bound >= direct_ballot_committed_projected_bgv_carry_radix_capacity()? {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed projected BGV carry digit width is too small for the no-wrap bound",
        ));
    }
    if twice_bound >= u128::from(modulus) {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed projected BGV carry range exceeds the verifier field modulus",
        ));
    }

    Ok(())
}

pub(super) fn direct_ballot_committed_projected_bgv_carry_twice_bound_modulus(
    maximum_abs: u64,
    modulus: u64,
) -> CanonicalResult<u64> {
    let twice_bound = u128::from(maximum_abs).checked_mul(2).ok_or_else(|| {
        invalid_direct_ballot_relation_proof(
            "direct ballot committed projected BGV carry bound overflowed",
        )
    })?;

    Ok((twice_bound % u128::from(modulus)) as u64)
}

pub(super) fn direct_ballot_committed_projected_bgv_carry_radix_capacity() -> CanonicalResult<u128>
{
    let mut capacity = 1_u128;
    for _ in 0..DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_TERNARY_DIGIT_COUNT {
        capacity = capacity
            .checked_mul(u128::from(
                DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_DIGIT_RADIX,
            ))
            .ok_or_else(|| {
                invalid_direct_ballot_relation_proof(
                    "direct ballot committed projected BGV carry radix capacity overflowed",
                )
            })?;
    }

    Ok(capacity)
}

fn write_committed_projected_bgv_carry_range_columns(
    columns: &mut [Vec<u64>],
    coefficient_index: usize,
    carry: &BigInt,
    maximum_abs: u64,
) -> CanonicalResult<()> {
    let maximum_abs_bigint = BigInt::from(maximum_abs);
    if carry.abs() > maximum_abs_bigint {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed projected BGV carry scalar exceeds the no-wrap bound",
        ));
    }
    let carry_i128 = carry.to_i128().ok_or_else(|| {
        invalid_direct_ballot_relation_proof(
            "direct ballot committed projected BGV carry scalar exceeds the fixed range encoding",
        )
    })?;
    let shifted_carry = carry_i128
        .checked_add(i128::from(maximum_abs))
        .ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed projected BGV shifted carry overflowed",
            )
        })?;
    let shifted_carry = u128::try_from(shifted_carry).map_err(|_| {
        invalid_direct_ballot_relation_proof(
            "direct ballot committed projected BGV shifted carry is negative",
        )
    })?;
    let twice_bound = u128::from(maximum_abs).checked_mul(2).ok_or_else(|| {
        invalid_direct_ballot_relation_proof(
            "direct ballot committed projected BGV carry bound overflowed",
        )
    })?;
    let slack = twice_bound.checked_sub(shifted_carry).ok_or_else(|| {
        invalid_direct_ballot_relation_proof(
            "direct ballot committed projected BGV shifted carry exceeds the range slack",
        )
    })?;
    write_committed_ternary_digit_columns(
        columns,
        DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SHIFTED_DIGIT_START_COLUMN,
        coefficient_index,
        shifted_carry,
    )?;
    write_committed_ternary_digit_columns(
        columns,
        DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SLACK_DIGIT_START_COLUMN,
        coefficient_index,
        slack,
    )
}

fn write_committed_unsigned_bit_columns(
    columns: &mut [Vec<u64>],
    start_column: usize,
    coefficient_index: usize,
    value: u64,
) -> CanonicalResult<()> {
    if value > direct_ballot_committed_unsigned_bit_bound() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed unsigned bit decomposition value exceeds the bit width",
        ));
    }
    for bit_index in 0..DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_COUNT {
        let Some(column) = columns.get_mut(start_column + bit_index) else {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed unsigned bit column is outside the fixed layout",
            ));
        };
        let Some(entry) = column.get_mut(coefficient_index) else {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed unsigned bit row is outside the fixed layout",
            ));
        };
        *entry = (value >> bit_index) & 1;
    }

    Ok(())
}

fn write_committed_ternary_digit_columns(
    columns: &mut [Vec<u64>],
    start_column: usize,
    coefficient_index: usize,
    mut value: u128,
) -> CanonicalResult<()> {
    if value >= direct_ballot_committed_projected_bgv_carry_radix_capacity()? {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed ternary digit decomposition value exceeds the digit width",
        ));
    }
    let radix = u128::from(DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_DIGIT_RADIX);
    for digit_index in 0..DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_TERNARY_DIGIT_COUNT {
        let Some(column) = columns.get_mut(start_column + digit_index) else {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed ternary digit column is outside the fixed layout",
            ));
        };
        let Some(entry) = column.get_mut(coefficient_index) else {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed ternary digit row is outside the fixed layout",
            ));
        };
        *entry = u64::try_from(value % radix).map_err(|_| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed ternary digit does not fit a field element",
            )
        })?;
        value /= radix;
    }
    if value != 0 {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed ternary digit decomposition did not consume the full value",
        ));
    }

    Ok(())
}

fn committed_bit_physical_columns(
    physical_columns: &[Vec<u64>],
    start_column: usize,
    half: usize,
) -> CanonicalResult<Vec<&[u64]>> {
    let mut bit_columns = Vec::with_capacity(DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_COUNT);
    for bit_index in 0..DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_COUNT {
        bit_columns.push(
            physical_columns
                .get(direct_ballot_committed_physical_column(
                    start_column + bit_index,
                    half,
                )?)
                .ok_or_else(|| {
                    invalid_direct_ballot_relation_proof(
                        "direct ballot committed unsigned bit physical column is outside the fixed layout",
                    )
                })?
                .as_slice(),
        );
    }

    Ok(bit_columns)
}

fn committed_digit_physical_columns(
    physical_columns: &[Vec<u64>],
    start_column: usize,
    digit_count: usize,
    half: usize,
) -> CanonicalResult<Vec<&[u64]>> {
    let mut digit_columns = Vec::with_capacity(digit_count);
    for digit_index in 0..digit_count {
        digit_columns.push(
            physical_columns
                .get(direct_ballot_committed_physical_column(
                    start_column + digit_index,
                    half,
                )?)
                .ok_or_else(|| {
                    invalid_direct_ballot_relation_proof(
                        "direct ballot committed digit physical column is outside the fixed layout",
                    )
                })?
                .as_slice(),
        );
    }

    Ok(digit_columns)
}

fn verify_direct_ballot_committed_unsigned_bit_columns(
    bit_columns: &[&[u64]],
    position: usize,
    modulus: u64,
    label: &str,
    coefficient_index: usize,
) -> CanonicalResult<()> {
    for (bit_index, bit_column) in bit_columns.iter().enumerate() {
        if boolean_support_value(bit_column[position], modulus)? != 0 {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot committed {label} Booleanity row failed at coefficient {coefficient_index} bit {bit_index}"
            )));
        }
    }

    Ok(())
}

fn verify_direct_ballot_committed_ternary_digit_columns(
    digit_columns: &[&[u64]],
    position: usize,
    modulus: u64,
    label: &str,
    coefficient_index: usize,
) -> CanonicalResult<()> {
    for (digit_index, digit_column) in digit_columns.iter().enumerate() {
        if ternary_digit_support_value(digit_column[position], modulus)? != 0 {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot committed {label} support row failed at coefficient {coefficient_index} digit {digit_index}"
            )));
        }
    }

    Ok(())
}

fn committed_unsigned_bit_sum(
    bit_columns: &[&[u64]],
    position: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    let mut sum = 0_u64;
    for (bit_index, bit_column) in bit_columns.iter().enumerate() {
        let weight = (1_u64 << bit_index) % modulus;
        sum = add_mod(
            sum,
            mul_mod(bit_column[position], weight, modulus)?,
            modulus,
        )?;
    }

    Ok(sum)
}

fn committed_ternary_digit_sum(
    digit_columns: &[&[u64]],
    position: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    let mut sum = 0_u64;
    let mut weight = 1_u64;
    for digit_column in digit_columns {
        sum = add_mod(
            sum,
            mul_mod(digit_column[position], weight, modulus)?,
            modulus,
        )?;
        weight = mul_mod(
            weight,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_DIGIT_RADIX % modulus,
            modulus,
        )?;
    }

    Ok(sum)
}

fn verify_direct_ballot_committed_error_support_value(
    error: u64,
    error_square: u64,
    modulus: u64,
    label: &str,
    coefficient_index: usize,
) -> CanonicalResult<()> {
    let square_difference = sub_mod(error_square, mul_mod(error, error, modulus)?, modulus)?;
    if square_difference != 0 {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "direct ballot committed {label} square row failed at coefficient {coefficient_index}"
        )));
    }
    if centered_binomial_eta_two_support_value(error, error_square, modulus)? != 0 {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "direct ballot committed {label} support row failed at coefficient {coefficient_index}"
        )));
    }

    Ok(())
}

fn verify_direct_ballot_committed_linear_claim(
    claim_plan: &DirectBallotCommittedLinearClaimPlan,
    columns: &[Vec<u64>],
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    match claim_plan {
        DirectBallotCommittedLinearClaimPlan::OneHotRowSum {
            modulus,
            option_index,
            ..
        } => {
            verify_direct_ballot_committed_column_shape(columns, *modulus)?;
            let mut bucket_sum = 0_u64;
            for bucket_index in 0..DIRECT_BALLOT_SCORE_BUCKET_COUNT {
                let packed_index = direct_ballot_one_hot_packed_index(*option_index, bucket_index)?;
                bucket_sum = add_mod(
                    bucket_sum,
                    columns[DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN][packed_index],
                    *modulus,
                )?;
            }
            if bucket_sum != 1 {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed linear one-hot row sum failed at option {option_index}"
                )));
            }
        }
        DirectBallotCommittedLinearClaimPlan::ScoreLinkage {
            modulus,
            option_index,
            ..
        } => {
            verify_direct_ballot_committed_column_shape(columns, *modulus)?;
            let mut weighted_sum = 0_u64;
            for bucket_index in 0..DIRECT_BALLOT_SCORE_BUCKET_COUNT {
                let packed_index = direct_ballot_one_hot_packed_index(*option_index, bucket_index)?;
                let bucket_weight = u64::try_from(bucket_index + 1).map_err(|_| {
                    invalid_direct_ballot_relation_proof(
                        "direct ballot score bucket index does not fit a field element",
                    )
                })?;
                weighted_sum = add_mod(
                    weighted_sum,
                    mul_mod(
                        bucket_weight,
                        columns[DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN][packed_index],
                        *modulus,
                    )?,
                    *modulus,
                )?;
            }
            if weighted_sum != columns[DIRECT_BALLOT_COMMITTED_SCORE_COLUMN][*option_index] {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed linear score linkage failed at option {option_index}"
                )));
            }
        }
        DirectBallotCommittedLinearClaimPlan::ProjectedBgv { row_index, row } => {
            verify_direct_ballot_committed_projected_bgv_row(*row_index, row, columns)?;
            let committed_linear_value =
                evaluate_direct_ballot_committed_projected_bgv_linear_part(row, columns)?;
            let fixed_backend_linear_value =
                evaluate_direct_ballot_projected_bgv_relation_linear_part(row, witness_vector)?;
            if committed_linear_value != fixed_backend_linear_value {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed projected BGV row {} {} projection {} does not match the fixed witness evaluator",
                    row.limb_index,
                    row.component.label(),
                    row.projection_index
                )));
            }
            let committed_carry_residue = columns
                [DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN]
                .get(*row_index)
                .ok_or_else(|| {
                    invalid_direct_ballot_relation_proof(
                        "direct ballot committed projected BGV carry column is missing a row",
                    )
                })?;
            let witness_carry_residue = signed_bigint_residue(
                &witness_vector.bgv_no_wrap_carry_scalars[*row_index],
                row.modulus,
            )?;
            if *committed_carry_residue != witness_carry_residue {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed projected BGV carry row {row_index} does not match the witness carry scalar"
                )));
            }
        }
        DirectBallotCommittedLinearClaimPlan::ProjectedBgvNoWrap {
            verifier_modulus,
            row_index,
            row,
            ..
        } => {
            let committed_linear_value =
                evaluate_direct_ballot_committed_projected_bgv_no_wrap_linear_part(
                    *row_index,
                    row,
                    columns,
                    *verifier_modulus,
                )?;
            let public_offset = sub_mod(
                0,
                row.ciphertext_projection % *verifier_modulus,
                *verifier_modulus,
            )?;
            if add_mod(committed_linear_value, public_offset, *verifier_modulus)? != 0 {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed projected BGV no-wrap row {} {} projection {} failed in verifier limb {}",
                    row.limb_index,
                    row.component.label(),
                    row.projection_index,
                    claim_plan.limb_index()
                )));
            }
        }
    }

    Ok(())
}

fn accumulate_direct_ballot_committed_linear_claim_batches(
    claim_index: usize,
    claim_plan: &DirectBallotCommittedLinearClaimPlan,
    verifier_modulus: u64,
    single_batch_challenge_count: usize,
    batching_challenges: &[u64],
    coefficient_columns_by_batch: &mut [Vec<Vec<u64>>],
    public_offsets: &mut [u64],
) -> CanonicalResult<()> {
    if coefficient_columns_by_batch.len() != public_offsets.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed linear claim batch shapes do not match",
        ));
    }
    match claim_plan {
        DirectBallotCommittedLinearClaimPlan::OneHotRowSum { option_index, .. } => {
            for bucket_index in 0..DIRECT_BALLOT_SCORE_BUCKET_COUNT {
                let packed_index = direct_ballot_one_hot_packed_index(*option_index, bucket_index)?;
                add_batched_linear_coefficient_batches(
                    coefficient_columns_by_batch,
                    DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN,
                    packed_index,
                    1,
                    claim_index,
                    single_batch_challenge_count,
                    batching_challenges,
                    verifier_modulus,
                )?;
            }
            add_batched_linear_public_offset_batches(
                public_offsets,
                sub_mod(0, 1, verifier_modulus)?,
                claim_index,
                single_batch_challenge_count,
                batching_challenges,
                verifier_modulus,
            )?;
        }
        DirectBallotCommittedLinearClaimPlan::ScoreLinkage { option_index, .. } => {
            for bucket_index in 0..DIRECT_BALLOT_SCORE_BUCKET_COUNT {
                let packed_index = direct_ballot_one_hot_packed_index(*option_index, bucket_index)?;
                let bucket_weight = u64::try_from(bucket_index + 1).map_err(|_| {
                    invalid_direct_ballot_relation_proof(
                        "direct ballot score bucket index does not fit a field element",
                    )
                })?;
                add_batched_linear_coefficient_batches(
                    coefficient_columns_by_batch,
                    DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN,
                    packed_index,
                    bucket_weight % verifier_modulus,
                    claim_index,
                    single_batch_challenge_count,
                    batching_challenges,
                    verifier_modulus,
                )?;
            }
            add_batched_linear_coefficient_batches(
                coefficient_columns_by_batch,
                DIRECT_BALLOT_COMMITTED_SCORE_COLUMN,
                *option_index,
                sub_mod(0, 1, verifier_modulus)?,
                claim_index,
                single_batch_challenge_count,
                batching_challenges,
                verifier_modulus,
            )?;
        }
        DirectBallotCommittedLinearClaimPlan::ProjectedBgv { row, .. } => {
            accumulate_direct_ballot_committed_projected_bgv_field_claim_batches(
                row,
                claim_index,
                single_batch_challenge_count,
                batching_challenges,
                coefficient_columns_by_batch,
                public_offsets,
            )?;
        }
        DirectBallotCommittedLinearClaimPlan::ProjectedBgvNoWrap { row_index, row, .. } => {
            accumulate_direct_ballot_committed_projected_bgv_no_wrap_claim_batches(
                *row_index,
                row,
                verifier_modulus,
                claim_index,
                single_batch_challenge_count,
                batching_challenges,
                coefficient_columns_by_batch,
                public_offsets,
            )?;
        }
    }

    Ok(())
}

fn accumulate_direct_ballot_committed_projected_bgv_field_claim_batches(
    row: &DirectBallotProjectedBgvRelationRow,
    claim_index: usize,
    single_batch_challenge_count: usize,
    batching_challenges: &[u64],
    coefficient_columns_by_batch: &mut [Vec<Vec<u64>>],
    public_offsets: &mut [u64],
) -> CanonicalResult<()> {
    add_batched_polynomial_coefficients_batches(
        coefficient_columns_by_batch,
        DIRECT_BALLOT_COMMITTED_RANDOMIZER_COLUMN,
        &row.public_key_projection_coefficients,
        1,
        claim_index,
        single_batch_challenge_count,
        batching_challenges,
        row.modulus,
    )?;
    match row.component {
        DirectBallotProjectedBgvComponent::ComponentZero => {
            let plaintext_scale = PLAINTEXT_MODULUS % row.modulus;
            add_batched_polynomial_coefficients_batches(
                coefficient_columns_by_batch,
                DIRECT_BALLOT_COMMITTED_FIRST_ERROR_COLUMN,
                &row.projection_coefficients,
                plaintext_scale,
                claim_index,
                single_batch_challenge_count,
                batching_challenges,
                row.modulus,
            )?;
            add_batched_polynomial_coefficients_batches(
                coefficient_columns_by_batch,
                DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN,
                &row.projection_coefficients,
                sub_mod(0, plaintext_scale, row.modulus)?,
                claim_index,
                single_batch_challenge_count,
                batching_challenges,
                row.modulus,
            )?;
            for (option_index, score_coefficient) in row.score_coefficients.iter().enumerate() {
                add_batched_linear_coefficient_batches(
                    coefficient_columns_by_batch,
                    DIRECT_BALLOT_COMMITTED_SCORE_COLUMN,
                    option_index,
                    *score_coefficient,
                    claim_index,
                    single_batch_challenge_count,
                    batching_challenges,
                    row.modulus,
                )?;
            }
        }
        DirectBallotProjectedBgvComponent::ComponentOne => {
            add_batched_polynomial_coefficients_batches(
                coefficient_columns_by_batch,
                DIRECT_BALLOT_COMMITTED_SECOND_ERROR_COLUMN,
                &row.projection_coefficients,
                PLAINTEXT_MODULUS % row.modulus,
                claim_index,
                single_batch_challenge_count,
                batching_challenges,
                row.modulus,
            )?;
        }
    }
    add_batched_linear_public_offset_batches(
        public_offsets,
        row.public_offset,
        claim_index,
        single_batch_challenge_count,
        batching_challenges,
        row.modulus,
    )
}

fn accumulate_direct_ballot_committed_projected_bgv_no_wrap_claim_batches(
    row_index: usize,
    row: &DirectBallotProjectedBgvRelationRow,
    verifier_modulus: u64,
    claim_index: usize,
    single_batch_challenge_count: usize,
    batching_challenges: &[u64],
    coefficient_columns_by_batch: &mut [Vec<Vec<u64>>],
    public_offsets: &mut [u64],
) -> CanonicalResult<()> {
    add_batched_polynomial_coefficients_batches(
        coefficient_columns_by_batch,
        DIRECT_BALLOT_COMMITTED_RANDOMIZER_COLUMN,
        &row.public_key_projection_coefficients,
        1,
        claim_index,
        single_batch_challenge_count,
        batching_challenges,
        verifier_modulus,
    )?;
    match row.component {
        DirectBallotProjectedBgvComponent::ComponentZero => {
            let plaintext_scale = PLAINTEXT_MODULUS % verifier_modulus;
            add_batched_polynomial_coefficients_batches(
                coefficient_columns_by_batch,
                DIRECT_BALLOT_COMMITTED_FIRST_ERROR_COLUMN,
                &row.projection_coefficients,
                plaintext_scale,
                claim_index,
                single_batch_challenge_count,
                batching_challenges,
                verifier_modulus,
            )?;
            add_batched_polynomial_coefficients_batches(
                coefficient_columns_by_batch,
                DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN,
                &row.projection_coefficients,
                sub_mod(0, plaintext_scale, verifier_modulus)?,
                claim_index,
                single_batch_challenge_count,
                batching_challenges,
                verifier_modulus,
            )?;
            for (option_index, score_coefficient) in row.score_coefficients.iter().enumerate() {
                add_batched_linear_coefficient_batches(
                    coefficient_columns_by_batch,
                    DIRECT_BALLOT_COMMITTED_SCORE_COLUMN,
                    option_index,
                    *score_coefficient % verifier_modulus,
                    claim_index,
                    single_batch_challenge_count,
                    batching_challenges,
                    verifier_modulus,
                )?;
            }
        }
        DirectBallotProjectedBgvComponent::ComponentOne => {
            add_batched_polynomial_coefficients_batches(
                coefficient_columns_by_batch,
                DIRECT_BALLOT_COMMITTED_SECOND_ERROR_COLUMN,
                &row.projection_coefficients,
                PLAINTEXT_MODULUS % verifier_modulus,
                claim_index,
                single_batch_challenge_count,
                batching_challenges,
                verifier_modulus,
            )?;
        }
    }
    add_batched_linear_coefficient_batches(
        coefficient_columns_by_batch,
        DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN,
        row_index,
        sub_mod(0, row.modulus % verifier_modulus, verifier_modulus)?,
        claim_index,
        single_batch_challenge_count,
        batching_challenges,
        verifier_modulus,
    )?;
    add_batched_linear_public_offset_batches(
        public_offsets,
        sub_mod(
            0,
            row.ciphertext_projection % verifier_modulus,
            verifier_modulus,
        )?,
        claim_index,
        single_batch_challenge_count,
        batching_challenges,
        verifier_modulus,
    )
}

fn add_batched_polynomial_coefficients_batches(
    coefficient_columns_by_batch: &mut [Vec<Vec<u64>>],
    column_index: usize,
    coefficients: &[u64],
    scalar: u64,
    claim_index: usize,
    single_batch_challenge_count: usize,
    batching_challenges: &[u64],
    modulus: u64,
) -> CanonicalResult<()> {
    if coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed linear polynomial coefficient count does not match the ring degree",
        ));
    }
    let scalar_residue = scalar % modulus;
    let combined_scalars = (0..coefficient_columns_by_batch.len())
        .map(|batch_index| {
            let challenge_residue = batched_claim_challenge_residue(
                batching_challenges,
                single_batch_challenge_count,
                batch_index,
                claim_index,
                modulus,
            )?;
            Ok(mul_mod_fast(scalar_residue, challenge_residue, modulus))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    if combined_scalars
        .iter()
        .all(|combined_scalar| *combined_scalar == 0)
    {
        return Ok(());
    }

    for coefficient_columns in coefficient_columns_by_batch.iter() {
        let column = coefficient_columns.get(column_index).ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed linear claim references an unknown column",
            )
        })?;
        if column.len() != POLYNOMIAL_DEGREE {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed linear claim column shape does not match the ring degree",
            ));
        }
    }

    let mut columns = coefficient_columns_by_batch
        .iter_mut()
        .map(|coefficient_columns| {
            coefficient_columns.get_mut(column_index).ok_or_else(|| {
                invalid_direct_ballot_relation_proof(
                    "direct ballot committed linear claim references an unknown column",
                )
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
        let coefficient_residue = *coefficient % modulus;
        if coefficient_residue == 0 {
            continue;
        }
        for (column, combined_scalar) in columns.iter_mut().zip(combined_scalars.iter()) {
            if *combined_scalar == 0 {
                continue;
            }
            let contribution = mul_mod_fast(coefficient_residue, *combined_scalar, modulus);
            column[coefficient_index] =
                add_mod_fast(column[coefficient_index], contribution, modulus);
        }
    }

    Ok(())
}

fn add_batched_linear_coefficient_batches(
    coefficient_columns_by_batch: &mut [Vec<Vec<u64>>],
    column_index: usize,
    coefficient_index: usize,
    coefficient: u64,
    claim_index: usize,
    single_batch_challenge_count: usize,
    batching_challenges: &[u64],
    modulus: u64,
) -> CanonicalResult<()> {
    let coefficient_residue = coefficient % modulus;
    for (batch_index, coefficient_columns) in coefficient_columns_by_batch.iter_mut().enumerate() {
        let column = coefficient_columns.get_mut(column_index).ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed linear claim references an unknown column",
            )
        })?;
        let slot = column.get_mut(coefficient_index).ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed linear claim references a row outside the trace",
            )
        })?;
        let challenge_residue = batched_claim_challenge_residue(
            batching_challenges,
            single_batch_challenge_count,
            batch_index,
            claim_index,
            modulus,
        )?;
        let contribution = mul_mod_fast(coefficient_residue, challenge_residue, modulus);
        *slot = add_mod_fast(*slot, contribution, modulus);
    }

    Ok(())
}

fn add_batched_linear_public_offset_batches(
    public_offsets: &mut [u64],
    offset: u64,
    claim_index: usize,
    single_batch_challenge_count: usize,
    batching_challenges: &[u64],
    modulus: u64,
) -> CanonicalResult<()> {
    let offset_residue = offset % modulus;
    for (batch_index, public_offset) in public_offsets.iter_mut().enumerate() {
        let challenge_residue = batched_claim_challenge_residue(
            batching_challenges,
            single_batch_challenge_count,
            batch_index,
            claim_index,
            modulus,
        )?;
        let contribution = mul_mod_fast(offset_residue, challenge_residue, modulus);
        *public_offset = add_mod_fast(*public_offset, contribution, modulus);
    }

    Ok(())
}

fn batched_claim_challenge_residue(
    batching_challenges: &[u64],
    single_batch_challenge_count: usize,
    batch_index: usize,
    claim_index: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    if single_batch_challenge_count == 0 || claim_index >= single_batch_challenge_count {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed linear claim challenge index is invalid",
        ));
    }
    let challenge_index = batch_index
        .checked_mul(single_batch_challenge_count)
        .and_then(|batch_offset| batch_offset.checked_add(claim_index))
        .ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed linear claim challenge index overflowed",
            )
        })?;
    let challenge = batching_challenges.get(challenge_index).ok_or_else(|| {
        invalid_direct_ballot_relation_proof(
            "direct ballot committed linear claim challenge count does not match the profile",
        )
    })?;

    Ok(*challenge % modulus)
}

fn evaluate_direct_ballot_committed_projected_bgv_linear_part(
    row: &DirectBallotProjectedBgvRelationRow,
    columns: &[Vec<u64>],
) -> CanonicalResult<u64> {
    verify_direct_ballot_committed_column_shape(columns, row.modulus)?;
    let mut residual = residue_linear_combination(
        &row.public_key_projection_coefficients,
        &columns[DIRECT_BALLOT_COMMITTED_RANDOMIZER_COLUMN],
        row.modulus,
        "direct ballot committed projected BGV randomizer relation",
    )?;

    match row.component {
        DirectBallotProjectedBgvComponent::ComponentZero => {
            residual = add_mod(
                residual,
                plaintext_scaled_residue_projection(
                    &row.projection_coefficients,
                    &columns[DIRECT_BALLOT_COMMITTED_FIRST_ERROR_COLUMN],
                    row.modulus,
                    "direct ballot committed projected BGV first error relation",
                )?,
                row.modulus,
            )?;
            residual = sub_mod(
                residual,
                plaintext_scaled_residue_projection(
                    &row.projection_coefficients,
                    &columns[DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN],
                    row.modulus,
                    "direct ballot committed projected BGV encoding carry relation",
                )?,
                row.modulus,
            )?;
            residual = add_mod(
                residual,
                score_column_linear_combination(
                    &row.score_coefficients,
                    &columns[DIRECT_BALLOT_COMMITTED_SCORE_COLUMN],
                    row.modulus,
                )?,
                row.modulus,
            )?;
        }
        DirectBallotProjectedBgvComponent::ComponentOne => {
            residual = add_mod(
                residual,
                plaintext_scaled_residue_projection(
                    &row.projection_coefficients,
                    &columns[DIRECT_BALLOT_COMMITTED_SECOND_ERROR_COLUMN],
                    row.modulus,
                    "direct ballot committed projected BGV second error relation",
                )?,
                row.modulus,
            )?;
        }
    }

    Ok(residual)
}

fn evaluate_direct_ballot_committed_projected_bgv_no_wrap_linear_part(
    row_index: usize,
    row: &DirectBallotProjectedBgvRelationRow,
    columns: &[Vec<u64>],
    verifier_modulus: u64,
) -> CanonicalResult<u64> {
    verify_direct_ballot_committed_column_shape(columns, verifier_modulus)?;
    let mut residual = residue_linear_combination(
        &row.public_key_projection_coefficients
            .iter()
            .map(|coefficient| *coefficient % verifier_modulus)
            .collect::<Vec<_>>(),
        &columns[DIRECT_BALLOT_COMMITTED_RANDOMIZER_COLUMN],
        verifier_modulus,
        "direct ballot committed projected BGV no-wrap randomizer relation",
    )?;

    match row.component {
        DirectBallotProjectedBgvComponent::ComponentZero => {
            residual = add_mod(
                residual,
                plaintext_scaled_residue_projection(
                    &row.projection_coefficients
                        .iter()
                        .map(|coefficient| *coefficient % verifier_modulus)
                        .collect::<Vec<_>>(),
                    &columns[DIRECT_BALLOT_COMMITTED_FIRST_ERROR_COLUMN],
                    verifier_modulus,
                    "direct ballot committed projected BGV no-wrap first error relation",
                )?,
                verifier_modulus,
            )?;
            residual = sub_mod(
                residual,
                plaintext_scaled_residue_projection(
                    &row.projection_coefficients
                        .iter()
                        .map(|coefficient| *coefficient % verifier_modulus)
                        .collect::<Vec<_>>(),
                    &columns[DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN],
                    verifier_modulus,
                    "direct ballot committed projected BGV no-wrap encoding carry relation",
                )?,
                verifier_modulus,
            )?;
            residual = add_mod(
                residual,
                score_column_linear_combination(
                    &row.score_coefficients
                        .iter()
                        .map(|coefficient| *coefficient % verifier_modulus)
                        .collect::<Vec<_>>(),
                    &columns[DIRECT_BALLOT_COMMITTED_SCORE_COLUMN],
                    verifier_modulus,
                )?,
                verifier_modulus,
            )?;
        }
        DirectBallotProjectedBgvComponent::ComponentOne => {
            residual = add_mod(
                residual,
                plaintext_scaled_residue_projection(
                    &row.projection_coefficients
                        .iter()
                        .map(|coefficient| *coefficient % verifier_modulus)
                        .collect::<Vec<_>>(),
                    &columns[DIRECT_BALLOT_COMMITTED_SECOND_ERROR_COLUMN],
                    verifier_modulus,
                    "direct ballot committed projected BGV no-wrap second error relation",
                )?,
                verifier_modulus,
            )?;
        }
    }

    let carry = columns[DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN]
        .get(row_index)
        .ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed projected BGV carry column is missing a no-wrap row",
            )
        })?;
    residual = sub_mod(
        residual,
        mul_mod(row.modulus % verifier_modulus, *carry, verifier_modulus)?,
        verifier_modulus,
    )?;

    Ok(residual)
}

fn verify_direct_ballot_committed_column_shape(
    columns: &[Vec<u64>],
    modulus: u64,
) -> CanonicalResult<()> {
    if columns.len() != DIRECT_BALLOT_COMMITTED_COLUMN_COUNT
        || columns
            .iter()
            .any(|column| column.len() != POLYNOMIAL_DEGREE)
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed witness columns do not match the fixed layout",
        ));
    }
    for (column_index, column) in columns.iter().enumerate() {
        if column.iter().any(|value| *value >= modulus) {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot committed witness column {column_index} contains a non-canonical residue"
            )));
        }
    }

    Ok(())
}

fn verify_one_hot_booleanity_and_score_columns(
    one_hot_column: &[u64],
    score_column: &[u64],
    modulus: u64,
) -> CanonicalResult<()> {
    for (option_index, score) in score_column
        .iter()
        .enumerate()
        .take(DIRECT_BALLOT_OPTION_COUNT)
    {
        let mut bucket_sum = 0_u64;
        let mut weighted_sum = 0_u64;
        for bucket_index in 0..DIRECT_BALLOT_SCORE_BUCKET_COUNT {
            let packed_index = direct_ballot_one_hot_packed_index(option_index, bucket_index)?;
            let entry = one_hot_column[packed_index];
            if boolean_support_value(entry, modulus)? != 0 {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot committed one-hot Booleanity row failed at option {option_index} bucket {bucket_index}"
                )));
            }
            bucket_sum = add_mod(bucket_sum, entry, modulus)?;
            let score_weight = u64::try_from(bucket_index + 1).map_err(|_| {
                invalid_direct_ballot_relation_proof(
                    "direct ballot score bucket index does not fit a field element",
                )
            })?;
            weighted_sum = add_mod(
                weighted_sum,
                mul_mod(score_weight, entry, modulus)?,
                modulus,
            )?;
        }
        if bucket_sum != 1 {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot committed one-hot row sum failed at option {option_index}"
            )));
        }
        if weighted_sum != *score {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot committed one-hot score linkage failed at option {option_index}"
            )));
        }
    }
    verify_committed_packed_column_shape(
        one_hot_column,
        DIRECT_BALLOT_OPTION_COUNT * DIRECT_BALLOT_SCORE_BUCKET_COUNT,
        "one-hot",
    )?;
    verify_committed_packed_column_shape(score_column, DIRECT_BALLOT_OPTION_COUNT, "score")
}

fn verify_committed_packed_column_shape(
    column: &[u64],
    active_entry_count: usize,
    label: &str,
) -> CanonicalResult<()> {
    if column[active_entry_count..].iter().any(|value| *value != 0) {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "direct ballot committed {label} column has a non-zero reserved entry"
        )));
    }

    Ok(())
}

fn direct_ballot_one_hot_packed_index(
    option_index: usize,
    bucket_index: usize,
) -> CanonicalResult<usize> {
    if option_index >= DIRECT_BALLOT_OPTION_COUNT
        || bucket_index >= DIRECT_BALLOT_SCORE_BUCKET_COUNT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot one-hot packed index is outside the fixed layout",
        ));
    }
    option_index
        .checked_mul(DIRECT_BALLOT_SCORE_BUCKET_COUNT)
        .and_then(|base| base.checked_add(bucket_index))
        .ok_or_else(|| {
            invalid_direct_ballot_relation_proof("direct ballot one-hot index overflowed")
        })
}

fn residues_from_bigints(values: &[BigInt], modulus: u64) -> CanonicalResult<Vec<u64>> {
    values
        .iter()
        .map(|value| signed_bigint_residue(value, modulus))
        .collect()
}

fn residue_linear_combination(
    coefficients: &[u64],
    values: &[u64],
    modulus: u64,
    label: &str,
) -> CanonicalResult<u64> {
    if coefficients.len() != values.len() {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} coefficient count does not match the committed column length"
        )));
    }
    let mut result = 0_u64;
    for (coefficient, value) in coefficients.iter().zip(values.iter()) {
        result = add_mod(result, mul_mod(*coefficient, *value, modulus)?, modulus)?;
    }

    Ok(result)
}

fn plaintext_scaled_residue_projection(
    coefficients: &[u64],
    values: &[u64],
    modulus: u64,
    label: &str,
) -> CanonicalResult<u64> {
    mul_mod(
        PLAINTEXT_MODULUS % modulus,
        residue_linear_combination(coefficients, values, modulus, label)?,
        modulus,
    )
}

fn score_column_linear_combination(
    coefficients: &[u64],
    score_column: &[u64],
    modulus: u64,
) -> CanonicalResult<u64> {
    if coefficients.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed projected BGV score coefficient count does not match the option count",
        ));
    }
    let mut result = 0_u64;
    for (coefficient, score) in coefficients
        .iter()
        .zip(score_column[..DIRECT_BALLOT_OPTION_COUNT].iter())
    {
        result = add_mod(result, mul_mod(*coefficient, *score, modulus)?, modulus)?;
    }

    Ok(result)
}

pub(super) fn boolean_support_value(value: u64, modulus: u64) -> CanonicalResult<u64> {
    sub_mod(mul_mod(value, value, modulus)?, value, modulus)
}

pub(super) fn ternary_support_value(value: u64, modulus: u64) -> CanonicalResult<u64> {
    let square = mul_mod(value, value, modulus)?;
    sub_mod(mul_mod(square, value, modulus)?, value, modulus)
}

pub(super) fn ternary_digit_support_value(value: u64, modulus: u64) -> CanonicalResult<u64> {
    mul_mod(
        value,
        mul_mod(
            sub_mod(value, 1, modulus)?,
            sub_mod(value, 2 % modulus, modulus)?,
            modulus,
        )?,
        modulus,
    )
}

pub(super) fn centered_binomial_eta_two_support_value(
    value: u64,
    value_square: u64,
    modulus: u64,
) -> CanonicalResult<u64> {
    let minus_one = sub_mod(value_square, 1, modulus)?;
    let minus_four = sub_mod(value_square, 4 % modulus, modulus)?;
    mul_mod(value, mul_mod(minus_one, minus_four, modulus)?, modulus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_ballot_committed_support_rows_accept_valid_witness() {
        let witness = committed_support_test_witness();

        verify_direct_ballot_committed_support_witness(&witness, DATA_PRIMES[0])
            .expect("valid committed support witness");
    }

    #[test]
    fn direct_ballot_committed_support_rows_reject_randomizer_outside_support() {
        let mut witness = committed_support_test_witness();
        witness.randomizer_coefficients[13] = BigInt::from(2_u8);

        let error = verify_direct_ballot_committed_support_witness(&witness, DATA_PRIMES[0])
            .expect_err("invalid randomizer must be rejected");

        assert!(
            error
                .message
                .contains("committed randomizer support row failed at coefficient 13")
        );
    }

    #[test]
    fn direct_ballot_committed_support_rows_reject_error_outside_support() {
        let mut witness = committed_support_test_witness();
        witness.error_zero_coefficients[21] = BigInt::from(3_u8);

        let error = verify_direct_ballot_committed_support_witness(&witness, DATA_PRIMES[0])
            .expect_err("invalid error coefficient must be rejected");

        assert!(
            error
                .message
                .contains("committed first error support row failed at coefficient 21")
        );
    }

    #[test]
    fn direct_ballot_committed_support_rows_reject_inconsistent_error_square() {
        let witness = committed_support_test_witness();
        let mut columns =
            direct_ballot_committed_witness_columns(&witness, DATA_PRIMES[0]).expect("columns");
        columns[DIRECT_BALLOT_COMMITTED_SECOND_ERROR_SQUARE_COLUMN][34] = 7;

        let error = verify_direct_ballot_committed_support_columns(&columns, DATA_PRIMES[0])
            .expect_err("inconsistent square column must be rejected");

        assert!(
            error
                .message
                .contains("committed second error square row failed at coefficient 34")
        );
    }

    #[test]
    fn direct_ballot_committed_support_rows_reject_encoder_carry_outside_range() {
        let witness = committed_support_test_witness();
        let encoder_carry_bound = direct_ballot_encoder_arithmetic_bounds()
            .expect("encoder bounds")
            .encoding_carry_coefficient_maximum;
        let mut columns =
            direct_ballot_committed_witness_columns(&witness, DATA_PRIMES[0]).expect("columns");
        let out_of_range_carry = encoder_carry_bound + 1;
        columns[DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN][17] = out_of_range_carry;
        write_committed_unsigned_bit_columns(
            &mut columns,
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_START_COLUMN,
            17,
            out_of_range_carry,
        )
        .expect("carry bits");

        let error = verify_direct_ballot_committed_support_columns(&columns, DATA_PRIMES[0])
            .expect_err("out-of-range encoder carry must be rejected");

        assert!(
            error
                .message
                .contains("committed encoding carry range row failed at coefficient 17")
        );

        let witness = committed_support_test_witness();
        let mut columns =
            direct_ballot_committed_witness_columns(&witness, DATA_PRIMES[0]).expect("columns");
        columns[DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN][19] = DATA_PRIMES[0] - 1;

        let error = verify_direct_ballot_committed_support_columns(&columns, DATA_PRIMES[0])
            .expect_err("negative encoder carry residue must be rejected");

        assert!(
            error.message.contains(
                "committed encoding carry bit decomposition row failed at coefficient 19"
            )
        );
    }

    #[test]
    fn direct_ballot_committed_support_rows_reject_one_hot_and_score_tampering() {
        let mut witness = committed_support_test_witness();
        witness.one_hot_coefficients[4][3] = BigInt::from(2_u8);

        let booleanity_error =
            verify_direct_ballot_committed_support_witness(&witness, DATA_PRIMES[0])
                .expect_err("non-Boolean one-hot entry must be rejected");

        assert!(
            booleanity_error
                .message
                .contains("committed one-hot Booleanity row failed at option 4 bucket 3")
        );

        let witness = committed_support_test_witness();
        let mut columns =
            direct_ballot_committed_witness_columns(&witness, DATA_PRIMES[0]).expect("columns");
        columns[DIRECT_BALLOT_COMMITTED_SCORE_COLUMN][7] = 9;

        let linkage_error =
            verify_direct_ballot_committed_support_columns(&columns, DATA_PRIMES[0])
                .expect_err("score linkage tampering must be rejected");

        assert!(
            linkage_error
                .message
                .contains("committed one-hot score linkage failed at option 7")
        );
    }

    #[test]
    fn direct_ballot_committed_support_rows_reject_reserved_column_entries() {
        let witness = committed_support_test_witness();
        let mut columns =
            direct_ballot_committed_witness_columns(&witness, DATA_PRIMES[0]).expect("columns");
        let first_reserved_one_hot_entry =
            DIRECT_BALLOT_OPTION_COUNT * DIRECT_BALLOT_SCORE_BUCKET_COUNT;
        columns[DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN][first_reserved_one_hot_entry] = 1;

        let error = verify_direct_ballot_committed_support_columns(&columns, DATA_PRIMES[0])
            .expect_err("reserved one-hot slot must be rejected");

        assert!(
            error
                .message
                .contains("committed one-hot column has a non-zero reserved entry")
        );
    }

    #[test]
    fn direct_ballot_committed_projected_bgv_row_rejects_score_and_carry_tampering() {
        let modulus = DATA_PRIMES[0];
        let witness = committed_support_test_witness();
        let mut projection_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        projection_coefficients[0] = 1;
        let mut public_key_projection_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        public_key_projection_coefficients[0] = 3;
        let mut score_coefficients = vec![0_u64; DIRECT_BALLOT_OPTION_COUNT];
        score_coefficients[0] = 5;
        let randomizer_value = signed_bigint_residue(&witness.randomizer_coefficients[0], modulus)
            .expect("randomizer residue");
        let first_error_value = signed_bigint_residue(&witness.error_zero_coefficients[0], modulus)
            .expect("first error residue");
        let score_value =
            signed_bigint_residue(&witness.score_coefficients[0], modulus).expect("score residue");
        let expected_linear = add_mod(
            add_mod(
                mul_mod(3, randomizer_value, modulus).expect("randomizer term"),
                mul_mod(PLAINTEXT_MODULUS % modulus, first_error_value, modulus)
                    .expect("error term"),
                modulus,
            )
            .expect("linear prefix"),
            mul_mod(5, score_value, modulus).expect("score term"),
            modulus,
        )
        .expect("linear value");
        let row = DirectBallotProjectedBgvRelationRow {
            limb_index: 0,
            component: DirectBallotProjectedBgvComponent::ComponentZero,
            projection_index: 0,
            modulus,
            projection_coefficients,
            public_key_projection_coefficients,
            score_coefficients,
            ciphertext_projection: 0,
            public_offset: sub_mod(0, expected_linear, modulus).expect("public offset"),
        };
        let columns = direct_ballot_committed_witness_columns(&witness, modulus).expect("columns");

        verify_direct_ballot_committed_projected_bgv_row(0, &row, &columns)
            .expect("valid committed projected BGV row");

        let mut score_tampered_columns = columns.clone();
        score_tampered_columns[DIRECT_BALLOT_COMMITTED_SCORE_COLUMN][0] = add_mod(
            score_tampered_columns[DIRECT_BALLOT_COMMITTED_SCORE_COLUMN][0],
            1,
            modulus,
        )
        .expect("tampered score");
        let score_error =
            verify_direct_ballot_committed_projected_bgv_row(0, &row, &score_tampered_columns)
                .expect_err("score tampering must reject");
        assert!(score_error.message.contains(
            "committed projected BGV relation limb 0 component zero projection 0 row 0 failed"
        ));

        let mut carry_tampered_columns = columns;
        carry_tampered_columns[DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN][0] = add_mod(
            carry_tampered_columns[DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN][0],
            1,
            modulus,
        )
        .expect("tampered carry");
        let carry_error =
            verify_direct_ballot_committed_projected_bgv_row(0, &row, &carry_tampered_columns)
                .expect_err("encoding-carry tampering must reject");
        assert!(carry_error.message.contains(
            "committed projected BGV relation limb 0 component zero projection 0 row 0 failed"
        ));
    }

    #[test]
    fn direct_ballot_committed_linear_claims_reject_score_row_tampering() {
        let modulus = DATA_PRIMES[0];
        let witness = committed_support_test_witness();
        let mut columns =
            direct_ballot_committed_witness_columns(&witness, modulus).expect("columns");
        let row_sum_plan = DirectBallotCommittedLinearClaimPlan::OneHotRowSum {
            limb_index: 0,
            modulus,
            option_index: 2,
        };
        let score_linkage_plan = DirectBallotCommittedLinearClaimPlan::ScoreLinkage {
            limb_index: 0,
            modulus,
            option_index: 2,
        };

        verify_direct_ballot_committed_linear_claim(&row_sum_plan, &columns, &witness)
            .expect("valid row-sum claim");
        verify_direct_ballot_committed_linear_claim(&score_linkage_plan, &columns, &witness)
            .expect("valid score-linkage claim");

        let selected_bucket = 2 % DIRECT_BALLOT_SCORE_BUCKET_COUNT;
        let selected_index =
            direct_ballot_one_hot_packed_index(2, selected_bucket).expect("selected index");
        columns[DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN][selected_index] = 0;
        let row_sum_error =
            verify_direct_ballot_committed_linear_claim(&row_sum_plan, &columns, &witness)
                .expect_err("row-sum tampering must reject");
        assert!(
            row_sum_error
                .message
                .contains("committed linear one-hot row sum failed at option 2")
        );

        let mut columns =
            direct_ballot_committed_witness_columns(&witness, modulus).expect("columns");
        columns[DIRECT_BALLOT_COMMITTED_SCORE_COLUMN][2] =
            add_mod(columns[DIRECT_BALLOT_COMMITTED_SCORE_COLUMN][2], 1, modulus)
                .expect("tampered score");
        let score_error =
            verify_direct_ballot_committed_linear_claim(&score_linkage_plan, &columns, &witness)
                .expect_err("score-linkage tampering must reject");
        assert!(
            score_error
                .message
                .contains("committed linear score linkage failed at option 2")
        );
    }

    #[test]
    fn direct_ballot_committed_support_rows_reject_projected_bgv_carry_range_tampering() {
        let modulus = DATA_PRIMES[0];
        let witness = committed_support_test_witness();
        let carry_bound =
            direct_ballot_projected_bgv_no_wrap_committed_carry_maximum_abs().expect("bound");

        let mut columns =
            direct_ballot_committed_witness_columns(&witness, modulus).expect("columns");
        let positive_overflow_index = 11;
        let positive_overflow = u128::from(carry_bound) + 1;
        columns[DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN][positive_overflow_index] =
            u64::try_from(positive_overflow).expect("positive overflow fits u64") % modulus;
        write_committed_ternary_digit_columns(
            &mut columns,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SHIFTED_DIGIT_START_COLUMN,
            positive_overflow_index,
            u128::from(carry_bound) + positive_overflow,
        )
        .expect("shifted digits");
        write_committed_ternary_digit_columns(
            &mut columns,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SLACK_DIGIT_START_COLUMN,
            positive_overflow_index,
            0,
        )
        .expect("slack digits");

        let error = verify_direct_ballot_committed_support_columns(&columns, modulus)
            .expect_err("positive carry overflow must be rejected");
        assert!(
            error
                .message
                .contains("committed projected BGV carry range row failed at coefficient 11")
        );

        let mut columns =
            direct_ballot_committed_witness_columns(&witness, modulus).expect("columns");
        let negative_overflow_index = 13;
        let negative_overflow_magnitude = carry_bound + 1;
        columns[DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN][negative_overflow_index] =
            sub_mod(0, negative_overflow_magnitude % modulus, modulus)
                .expect("negative overflow residue");
        write_committed_ternary_digit_columns(
            &mut columns,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SHIFTED_DIGIT_START_COLUMN,
            negative_overflow_index,
            0,
        )
        .expect("shifted digits");
        write_committed_ternary_digit_columns(
            &mut columns,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SLACK_DIGIT_START_COLUMN,
            negative_overflow_index,
            u128::from(carry_bound) * 2,
        )
        .expect("slack digits");

        let error = verify_direct_ballot_committed_support_columns(&columns, modulus)
            .expect_err("negative carry overflow must be rejected");
        assert!(error.message.contains(
            "committed projected BGV carry shifted decomposition row failed at coefficient 13"
        ));

        let mut columns =
            direct_ballot_committed_witness_columns(&witness, modulus).expect("columns");
        columns[DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SHIFTED_DIGIT_START_COLUMN][17] =
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_DIGIT_RADIX;

        let error = verify_direct_ballot_committed_support_columns(&columns, modulus)
            .expect_err("non-radix digit must be rejected");
        assert!(error.message.contains(
            "committed projected BGV carry shifted digit support row failed at coefficient 17 digit 0"
        ));
    }

    fn committed_support_test_witness() -> DirectBallotWitnessVector {
        let randomizer_coefficients = (0..POLYNOMIAL_DEGREE)
            .map(|coefficient_index| match coefficient_index % 3 {
                0 => BigInt::from(-1),
                1 => BigInt::from(0),
                _ => BigInt::from(1),
            })
            .collect();
        let error_zero_coefficients = (0..POLYNOMIAL_DEGREE)
            .map(|coefficient_index| BigInt::from((coefficient_index % 5) as i64 - 2))
            .collect();
        let error_one_coefficients = (0..POLYNOMIAL_DEGREE)
            .map(|coefficient_index| BigInt::from(2_i64 - (coefficient_index % 5) as i64))
            .collect();
        let encoding_carry_coefficients = vec![BigInt::zero(); POLYNOMIAL_DEGREE];
        let mut score_coefficients = Vec::with_capacity(DIRECT_BALLOT_OPTION_COUNT);
        let mut one_hot_coefficients = Vec::with_capacity(DIRECT_BALLOT_OPTION_COUNT);
        for option_index in 0..DIRECT_BALLOT_OPTION_COUNT {
            let bucket_index = option_index % DIRECT_BALLOT_SCORE_BUCKET_COUNT;
            score_coefficients.push(BigInt::from(bucket_index + 1));
            let mut row = vec![BigInt::zero(); DIRECT_BALLOT_SCORE_BUCKET_COUNT];
            row[bucket_index] = BigInt::from(1_u8);
            one_hot_coefficients.push(row);
        }
        let bgv_no_wrap_carry_scalars =
            vec![BigInt::zero(); direct_ballot_projected_bgv_no_wrap_carry_scalar_count()];

        DirectBallotWitnessVector {
            randomizer_coefficients,
            error_zero_coefficients,
            error_one_coefficients,
            encoding_carry_coefficients,
            score_coefficients,
            one_hot_coefficients,
            bgv_no_wrap_carry_scalars,
        }
    }
}
