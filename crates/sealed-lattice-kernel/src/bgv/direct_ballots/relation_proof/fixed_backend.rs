use super::*;

const DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTION_DOMAIN: &str =
    "sealed-lattice/direct-encrypted-ballot/projected-bgv-relation-projection-v1";
pub(in crate::bgv::direct_ballots) const DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT: usize =
    3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DirectBallotProjectedBgvComponent {
    ComponentZero,
    ComponentOne,
}

impl DirectBallotProjectedBgvComponent {
    pub(super) fn index(self) -> usize {
        match self {
            Self::ComponentZero => 0,
            Self::ComponentOne => 1,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::ComponentZero => "component zero",
            Self::ComponentOne => "component one",
        }
    }

    fn domain_tag(self) -> &'static [u8] {
        match self {
            Self::ComponentZero => b"component-zero",
            Self::ComponentOne => b"component-one",
        }
    }
}

#[derive(Clone)]
pub(super) struct DirectBallotProjectedBgvRelationRow {
    pub(super) limb_index: usize,
    pub(super) component: DirectBallotProjectedBgvComponent,
    pub(super) projection_index: usize,
    pub(super) modulus: u64,
    pub(super) projection_coefficients: Vec<u64>,
    pub(super) public_key_projection_coefficients: Vec<u64>,
    pub(super) score_coefficients: Vec<u64>,
    pub(super) ciphertext_projection: u64,
    pub(super) public_offset: u64,
}

struct DirectBallotProjectedBgvNoWrapCarryBounds {
    witness_quotient_maximum_abs: BigInt,
    mask_quotient_maximum_abs: BigInt,
    response_quotient_maximum_abs: BigInt,
}

struct DirectBallotProjectedBgvCoefficientBounds {
    randomizer_coefficient_maximum_abs: BigInt,
    error_coefficient_maximum_abs: BigInt,
    encoding_carry_coefficient_maximum_abs: BigInt,
    score_coefficient_maximum_abs: BigInt,
}

struct DirectBallotProjectedBgvRelationRowInput<'a> {
    statement_hash: &'a [u8; 64],
    public_component: &'a [u64],
    ciphertext_component: &'a [u64],
    score_encoding_basis: &'a [Vec<u64>],
    limb_index: usize,
    component: DirectBallotProjectedBgvComponent,
    projection_index: usize,
    modulus: u64,
}

pub(super) fn evaluate_direct_ballot_projected_bgv_relation_commitments(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<Vec<DirectBallotBgvRelationCommitment>> {
    let rows = compile_direct_ballot_projected_bgv_relation_rows(
        statement_hash,
        public_key,
        ballot,
        DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
    )?;
    let mut commitments = DATA_PRIMES
        .iter()
        .map(|_| DirectBallotBgvRelationCommitment {
            component_zero: Vec::with_capacity(
                DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
            ),
            component_one: Vec::with_capacity(
                DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
            ),
        })
        .collect::<Vec<_>>();

    for row in rows {
        let commitment_value =
            evaluate_direct_ballot_projected_bgv_relation_linear_part(&row, witness_vector)?;
        match row.component {
            DirectBallotProjectedBgvComponent::ComponentZero => {
                commitments[row.limb_index]
                    .component_zero
                    .push(commitment_value);
            }
            DirectBallotProjectedBgvComponent::ComponentOne => {
                commitments[row.limb_index]
                    .component_one
                    .push(commitment_value);
            }
        }
    }

    Ok(commitments)
}

pub(super) fn verify_direct_ballot_projected_bgv_relation_response(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    challenge: &BigInt,
    commitments: &[DirectBallotBgvRelationCommitment],
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    if commitments.len() != DATA_PRIMES.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV commitment count must match the data-prime count",
        ));
    }
    let rows = compile_direct_ballot_projected_bgv_relation_rows(
        statement_hash,
        public_key,
        ballot,
        DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
    )?;

    for (row_index, row) in rows.iter().enumerate() {
        let component_commitments = match row.component {
            DirectBallotProjectedBgvComponent::ComponentZero => {
                &commitments[row.limb_index].component_zero
            }
            DirectBallotProjectedBgvComponent::ComponentOne => {
                &commitments[row.limb_index].component_one
            }
        };
        if component_commitments.len()
            != DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT
        {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot projected BGV relation limb {} {} commitment count does not match the proof profile",
                row.limb_index,
                row.component.label(),
            )));
        }
        let response_linear_value =
            evaluate_direct_ballot_projected_bgv_relation_linear_part(row, response_vector)?;
        let challenge_residue = challenge_residue(challenge, row.modulus)?;
        let checked_value = add_mod(
            response_linear_value,
            mul_mod(challenge_residue, row.public_offset, row.modulus)?,
            row.modulus,
        )?;
        if checked_value != component_commitments[row.projection_index] {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot projected BGV relation limb {} {} projection {} failed",
                row.limb_index,
                row.component.label(),
                row.projection_index
            )));
        }
        let no_wrap_carry = response_vector
            .bgv_no_wrap_carry_scalars
            .get(row_index)
            .ok_or_else(|| {
                invalid_direct_ballot_relation_proof(
                    "direct ballot projected BGV no-wrap carry response is missing a row",
                )
            })?;
        let response_integer_value =
            evaluate_direct_ballot_projected_bgv_relation_integer_linear_part(
                row,
                response_vector,
            )?;
        let checked_no_wrap_value = response_integer_value
            - challenge * BigInt::from(row.ciphertext_projection)
            - BigInt::from(row.modulus) * no_wrap_carry;
        let carry_bounds = direct_ballot_projected_bgv_no_wrap_carry_bounds(row)?;
        validate_direct_ballot_projected_bgv_no_wrap_carry_bound(
            no_wrap_carry,
            &carry_bounds.response_quotient_maximum_abs,
            &format!(
                "direct ballot projected BGV no-wrap carry response limb {} {} projection {}",
                row.limb_index,
                row.component.label(),
                row.projection_index
            ),
        )?;
        if checked_no_wrap_value != BigInt::from(component_commitments[row.projection_index]) {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot projected BGV no-wrap relation limb {} {} projection {} failed",
                row.limb_index,
                row.component.label(),
                row.projection_index
            )));
        }
    }

    Ok(())
}

pub(super) fn verify_direct_ballot_projected_bgv_relation_witness(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    witness_vector: &DirectBallotWitnessVector,
    projections_per_limb_component: usize,
) -> CanonicalResult<()> {
    let rows = compile_direct_ballot_projected_bgv_relation_rows(
        statement_hash,
        public_key,
        ballot,
        projections_per_limb_component,
    )?;

    for row in rows {
        let residual = evaluate_direct_ballot_projected_bgv_relation_row(&row, witness_vector)?;
        if residual != 0 {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot projected BGV relation limb {} {} projection {} failed",
                row.limb_index,
                row.component.label(),
                row.projection_index
            )));
        }
    }

    Ok(())
}

pub(super) fn direct_ballot_projected_bgv_witness_no_wrap_carry_scalars(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<Vec<BigInt>> {
    let rows = compile_direct_ballot_projected_bgv_relation_rows(
        statement_hash,
        public_key,
        ballot,
        DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
    )?;
    let mut carry_scalars = Vec::with_capacity(rows.len());
    for row in &rows {
        let lifted_value =
            evaluate_direct_ballot_projected_bgv_relation_integer_linear_part(row, witness_vector)?
                - BigInt::from(row.ciphertext_projection);
        let (carry_scalar, remainder) = euclidean_division_by_modulus(&lifted_value, row.modulus)?;
        if !remainder.is_zero() {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot projected BGV witness no-wrap carry limb {} {} projection {} is not exact",
                row.limb_index,
                row.component.label(),
                row.projection_index
            )));
        }
        validate_signed_bigint_fixed_width(
            &carry_scalar,
            DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES,
            "direct ballot projected BGV witness no-wrap carry",
        )?;
        let carry_bounds = direct_ballot_projected_bgv_no_wrap_carry_bounds(row)?;
        validate_direct_ballot_projected_bgv_no_wrap_carry_bound(
            &carry_scalar,
            &carry_bounds.witness_quotient_maximum_abs,
            &format!(
                "direct ballot projected BGV witness no-wrap carry limb {} {} projection {}",
                row.limb_index,
                row.component.label(),
                row.projection_index
            ),
        )?;
        carry_scalars.push(carry_scalar);
    }

    Ok(carry_scalars)
}

pub(super) fn direct_ballot_projected_bgv_mask_no_wrap_carry_scalars(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    mask_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<Vec<BigInt>> {
    let rows = compile_direct_ballot_projected_bgv_relation_rows(
        statement_hash,
        public_key,
        ballot,
        DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
    )?;
    let mut carry_scalars = Vec::with_capacity(rows.len());
    for row in &rows {
        let lifted_value =
            evaluate_direct_ballot_projected_bgv_relation_integer_linear_part(row, mask_vector)?;
        let modular_commitment =
            evaluate_direct_ballot_projected_bgv_relation_linear_part(row, mask_vector)?;
        let (carry_scalar, remainder) = euclidean_division_by_modulus(&lifted_value, row.modulus)?;
        if remainder != BigInt::from(modular_commitment) {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot projected BGV mask no-wrap carry limb {} {} projection {} does not match its residue commitment",
                row.limb_index,
                row.component.label(),
                row.projection_index
            )));
        }
        validate_signed_bigint_fixed_width(
            &carry_scalar,
            DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES,
            "direct ballot projected BGV mask no-wrap carry",
        )?;
        let carry_bounds = direct_ballot_projected_bgv_no_wrap_carry_bounds(row)?;
        validate_direct_ballot_projected_bgv_no_wrap_carry_bound(
            &carry_scalar,
            &carry_bounds.mask_quotient_maximum_abs,
            &format!(
                "direct ballot projected BGV mask no-wrap carry limb {} {} projection {}",
                row.limb_index,
                row.component.label(),
                row.projection_index
            ),
        )?;
        carry_scalars.push(carry_scalar);
    }

    Ok(carry_scalars)
}

pub(super) fn compile_direct_ballot_projected_bgv_relation_rows(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    projections_per_limb_component: usize,
) -> CanonicalResult<Vec<DirectBallotProjectedBgvRelationRow>> {
    if projections_per_limb_component == 0 {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV relation requires at least one projection",
        ));
    }

    let (public_component_zero, public_component_one) = public_key.public_key_components();
    validate_direct_ballot_projected_bgv_relation_shape(
        public_component_zero,
        public_component_one,
        ballot,
    )?;

    let score_encoding_basis = direct_ballot_score_encoding_basis()?;
    let mut rows = Vec::with_capacity(
        DATA_PRIMES
            .len()
            .checked_mul(2)
            .and_then(|count| count.checked_mul(projections_per_limb_component))
            .ok_or_else(|| {
                invalid_direct_ballot_relation_proof(
                    "direct ballot projected BGV relation row count overflowed",
                )
            })?,
    );
    for (limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        for component in [
            DirectBallotProjectedBgvComponent::ComponentZero,
            DirectBallotProjectedBgvComponent::ComponentOne,
        ] {
            let public_component = match component {
                DirectBallotProjectedBgvComponent::ComponentZero => {
                    &public_component_zero[limb_index]
                }
                DirectBallotProjectedBgvComponent::ComponentOne => {
                    &public_component_one[limb_index]
                }
            };
            let ciphertext_component = &ballot.ciphertext.components[component.index()][limb_index];
            for projection_index in 0..projections_per_limb_component {
                rows.push(compile_direct_ballot_projected_bgv_relation_row(
                    DirectBallotProjectedBgvRelationRowInput {
                        statement_hash,
                        public_component,
                        ciphertext_component,
                        score_encoding_basis,
                        limb_index,
                        component,
                        projection_index,
                        modulus,
                    },
                )?);
            }
        }
    }

    Ok(rows)
}

fn compile_direct_ballot_projected_bgv_relation_row(
    input: DirectBallotProjectedBgvRelationRowInput<'_>,
) -> CanonicalResult<DirectBallotProjectedBgvRelationRow> {
    validate_residue_polynomial_shape(
        input.public_component,
        input.modulus,
        "direct ballot projected BGV public key component",
    )?;
    validate_residue_polynomial_shape(
        input.ciphertext_component,
        input.modulus,
        "direct ballot projected BGV ciphertext component",
    )?;

    let projection_coefficients = sample_direct_ballot_projected_bgv_projection(
        input.statement_hash,
        input.limb_index,
        input.component,
        input.projection_index,
        input.modulus,
    )?;
    let public_key_projection_coefficients = negacyclic_adjoint_multiply(
        input.public_component,
        &projection_coefficients,
        input.modulus,
    )?;
    let ciphertext_projection = residue_dot_product(
        &projection_coefficients,
        input.ciphertext_component,
        input.modulus,
        "direct ballot projected BGV ciphertext projection",
    )?;
    let public_offset = sub_mod(0, ciphertext_projection, input.modulus)?;
    let score_coefficients = match input.component {
        DirectBallotProjectedBgvComponent::ComponentZero => input
            .score_encoding_basis
            .iter()
            .enumerate()
            .map(|(option_index, basis_polynomial)| {
                residue_dot_product(
                    &projection_coefficients,
                    basis_polynomial,
                    input.modulus,
                    &format!("direct ballot projected BGV score basis option {option_index}"),
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
        DirectBallotProjectedBgvComponent::ComponentOne => {
            vec![0; DIRECT_BALLOT_OPTION_COUNT]
        }
    };

    Ok(DirectBallotProjectedBgvRelationRow {
        limb_index: input.limb_index,
        component: input.component,
        projection_index: input.projection_index,
        modulus: input.modulus,
        projection_coefficients,
        public_key_projection_coefficients,
        score_coefficients,
        ciphertext_projection,
        public_offset,
    })
}

fn evaluate_direct_ballot_projected_bgv_relation_row(
    row: &DirectBallotProjectedBgvRelationRow,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<u64> {
    let linear_part =
        evaluate_direct_ballot_projected_bgv_relation_linear_part(row, witness_vector)?;
    add_mod(linear_part, row.public_offset, row.modulus)
}

pub(super) fn evaluate_direct_ballot_projected_bgv_relation_linear_part(
    row: &DirectBallotProjectedBgvRelationRow,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<u64> {
    validate_direct_ballot_witness_vector_base_shape(witness_vector)?;
    if row.score_coefficients.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV row score coefficient count does not match the option count",
        ));
    }

    let mut residual = 0_u64;
    residual = add_mod(
        residual,
        signed_polynomial_linear_combination(
            &row.public_key_projection_coefficients,
            &witness_vector.randomizer_coefficients,
            row.modulus,
            "direct ballot projected BGV randomizer relation",
        )?,
        row.modulus,
    )?;

    match row.component {
        DirectBallotProjectedBgvComponent::ComponentZero => {
            residual = add_mod(
                residual,
                plaintext_scaled_projection(
                    &row.projection_coefficients,
                    &witness_vector.error_zero_coefficients,
                    row.modulus,
                    "direct ballot projected BGV first error relation",
                )?,
                row.modulus,
            )?;
            let scaled_carry_projection = plaintext_scaled_projection(
                &row.projection_coefficients,
                &witness_vector.encoding_carry_coefficients,
                row.modulus,
                "direct ballot projected BGV encoding carry relation",
            )?;
            residual = sub_mod(residual, scaled_carry_projection, row.modulus)?;
            residual = add_mod(
                residual,
                score_linear_combination(
                    &row.score_coefficients,
                    &witness_vector.score_coefficients,
                    row.modulus,
                )?,
                row.modulus,
            )?;
        }
        DirectBallotProjectedBgvComponent::ComponentOne => {
            residual = add_mod(
                residual,
                plaintext_scaled_projection(
                    &row.projection_coefficients,
                    &witness_vector.error_one_coefficients,
                    row.modulus,
                    "direct ballot projected BGV second error relation",
                )?,
                row.modulus,
            )?;
        }
    }

    Ok(residual)
}

pub(super) fn evaluate_direct_ballot_projected_bgv_relation_integer_linear_part(
    row: &DirectBallotProjectedBgvRelationRow,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<BigInt> {
    validate_direct_ballot_witness_vector_base_shape(witness_vector)?;
    if row.score_coefficients.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV row score coefficient count does not match the option count",
        ));
    }

    let mut lifted_value = signed_polynomial_integer_linear_combination(
        &row.public_key_projection_coefficients,
        &witness_vector.randomizer_coefficients,
        row.modulus,
        "direct ballot projected BGV integer randomizer relation",
    )?;

    match row.component {
        DirectBallotProjectedBgvComponent::ComponentZero => {
            lifted_value += plaintext_scaled_integer_projection(
                &row.projection_coefficients,
                &witness_vector.error_zero_coefficients,
                row.modulus,
                "direct ballot projected BGV integer first error relation",
            )?;
            lifted_value -= plaintext_scaled_integer_projection(
                &row.projection_coefficients,
                &witness_vector.encoding_carry_coefficients,
                row.modulus,
                "direct ballot projected BGV integer encoding carry relation",
            )?;
            lifted_value += score_integer_linear_combination(
                &row.score_coefficients,
                &witness_vector.score_coefficients,
                row.modulus,
            )?;
        }
        DirectBallotProjectedBgvComponent::ComponentOne => {
            lifted_value += plaintext_scaled_integer_projection(
                &row.projection_coefficients,
                &witness_vector.error_one_coefficients,
                row.modulus,
                "direct ballot projected BGV integer second error relation",
            )?;
        }
    }

    Ok(lifted_value)
}

fn direct_ballot_projected_bgv_no_wrap_carry_bounds(
    row: &DirectBallotProjectedBgvRelationRow,
) -> CanonicalResult<DirectBallotProjectedBgvNoWrapCarryBounds> {
    let encoder_bounds = direct_ballot_encoder_arithmetic_bounds()?;
    let witness_coefficient_bounds = DirectBallotProjectedBgvCoefficientBounds {
        randomizer_coefficient_maximum_abs: BigInt::from(1_u8),
        error_coefficient_maximum_abs: BigInt::from(2_u8),
        encoding_carry_coefficient_maximum_abs: BigInt::from(
            encoder_bounds.encoding_carry_coefficient_maximum,
        ),
        score_coefficient_maximum_abs: BigInt::from(DIRECT_BALLOT_MAXIMUM_SCORE),
    };
    let mask_coefficient_maximum_abs =
        maximum_unsigned_bigint_with_bits(DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS);
    let mask_coefficient_bounds = DirectBallotProjectedBgvCoefficientBounds {
        randomizer_coefficient_maximum_abs: mask_coefficient_maximum_abs.clone(),
        error_coefficient_maximum_abs: mask_coefficient_maximum_abs.clone(),
        encoding_carry_coefficient_maximum_abs: mask_coefficient_maximum_abs.clone(),
        score_coefficient_maximum_abs: mask_coefficient_maximum_abs,
    };
    let witness_linear_maximum_abs =
        direct_ballot_projected_bgv_linear_maximum_abs(row, &witness_coefficient_bounds)?;
    let mask_linear_maximum_abs =
        direct_ballot_projected_bgv_linear_maximum_abs(row, &mask_coefficient_bounds)?;
    let witness_numerator_maximum_abs =
        witness_linear_maximum_abs + BigInt::from(row.ciphertext_projection);
    let witness_quotient_maximum_abs =
        ceil_div_nonnegative_bigint_by_u64(&witness_numerator_maximum_abs, row.modulus)?;
    let mask_quotient_maximum_abs =
        ceil_div_nonnegative_bigint_by_u64(&mask_linear_maximum_abs, row.modulus)?;
    let challenge_maximum =
        maximum_unsigned_bigint_with_bits(DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS as usize);
    let response_quotient_maximum_abs =
        &mask_quotient_maximum_abs + challenge_maximum * &witness_quotient_maximum_abs;

    Ok(DirectBallotProjectedBgvNoWrapCarryBounds {
        witness_quotient_maximum_abs,
        mask_quotient_maximum_abs,
        response_quotient_maximum_abs,
    })
}

pub(super) fn direct_ballot_projected_bgv_no_wrap_committed_carry_maximum_abs()
-> CanonicalResult<u64> {
    let encoder_bounds = direct_ballot_encoder_arithmetic_bounds()?;
    let mut witness_quotient_maximum_abs = BigInt::zero();

    for modulus in DATA_PRIMES {
        let modulus_minus_one = BigInt::from(modulus - 1);
        let polynomial_projection_sum = BigInt::from(POLYNOMIAL_DEGREE) * &modulus_minus_one;
        let score_projection_sum = BigInt::from(DIRECT_BALLOT_OPTION_COUNT) * &modulus_minus_one;
        let component_zero_witness_linear_maximum_abs = &polynomial_projection_sum
            + BigInt::from(PLAINTEXT_MODULUS) * &polynomial_projection_sum * BigInt::from(2_u8)
            + BigInt::from(PLAINTEXT_MODULUS)
                * &polynomial_projection_sum
                * BigInt::from(encoder_bounds.encoding_carry_coefficient_maximum)
            + &score_projection_sum * BigInt::from(DIRECT_BALLOT_MAXIMUM_SCORE);
        let component_one_witness_linear_maximum_abs = &polynomial_projection_sum
            + BigInt::from(PLAINTEXT_MODULUS) * &polynomial_projection_sum * BigInt::from(2_u8);

        for witness_linear_maximum_abs in [
            component_zero_witness_linear_maximum_abs,
            component_one_witness_linear_maximum_abs,
        ] {
            let numerator_maximum_abs = witness_linear_maximum_abs + &modulus_minus_one;
            witness_quotient_maximum_abs = witness_quotient_maximum_abs.max(
                ceil_div_nonnegative_bigint_by_u64(&numerator_maximum_abs, modulus)?,
            );
        }
    }

    witness_quotient_maximum_abs.to_u64().ok_or_else(|| {
        invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV committed no-wrap carry bound exceeds the fixed range encoding",
        )
    })
}

fn direct_ballot_projected_bgv_linear_maximum_abs(
    row: &DirectBallotProjectedBgvRelationRow,
    coefficient_bounds: &DirectBallotProjectedBgvCoefficientBounds,
) -> CanonicalResult<BigInt> {
    let public_key_projection_coefficient_sum = residue_coefficient_sum(
        &row.public_key_projection_coefficients,
        row.modulus,
        "direct ballot projected BGV public-key projection",
    )?;
    let projection_coefficient_sum = residue_coefficient_sum(
        &row.projection_coefficients,
        row.modulus,
        "direct ballot projected BGV row projection",
    )?;
    let mut maximum_abs = public_key_projection_coefficient_sum
        * &coefficient_bounds.randomizer_coefficient_maximum_abs;

    match row.component {
        DirectBallotProjectedBgvComponent::ComponentZero => {
            let plaintext_scaled_projection_coefficient_sum =
                BigInt::from(PLAINTEXT_MODULUS) * &projection_coefficient_sum;
            maximum_abs += &plaintext_scaled_projection_coefficient_sum
                * &coefficient_bounds.error_coefficient_maximum_abs;
            maximum_abs += &plaintext_scaled_projection_coefficient_sum
                * &coefficient_bounds.encoding_carry_coefficient_maximum_abs;
            maximum_abs += residue_coefficient_sum(
                &row.score_coefficients,
                row.modulus,
                "direct ballot projected BGV score coefficients",
            )? * &coefficient_bounds.score_coefficient_maximum_abs;
        }
        DirectBallotProjectedBgvComponent::ComponentOne => {
            maximum_abs += BigInt::from(PLAINTEXT_MODULUS)
                * projection_coefficient_sum
                * &coefficient_bounds.error_coefficient_maximum_abs;
        }
    }

    Ok(maximum_abs)
}

fn validate_direct_ballot_projected_bgv_no_wrap_carry_bound(
    carry_scalar: &BigInt,
    maximum_abs: &BigInt,
    label: &str,
) -> CanonicalResult<()> {
    if carry_scalar.abs() > *maximum_abs {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} exceeds the arithmetic quotient bound"
        )));
    }

    Ok(())
}

fn validate_direct_ballot_projected_bgv_relation_shape(
    public_component_zero: &[Vec<u64>],
    public_component_one: &[Vec<u64>],
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<()> {
    if public_component_zero.len() != DATA_PRIMES.len()
        || public_component_one.len() != DATA_PRIMES.len()
        || ballot.ciphertext.components.len() != 2
        || ballot.ciphertext.components[0].len() != DATA_PRIMES.len()
        || ballot.ciphertext.components[1].len() != DATA_PRIMES.len()
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV relation requires a full public key and ciphertext",
        ));
    }

    for (limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        validate_residue_polynomial_shape(
            &public_component_zero[limb_index],
            modulus,
            "direct ballot projected BGV public key component zero",
        )?;
        validate_residue_polynomial_shape(
            &public_component_one[limb_index],
            modulus,
            "direct ballot projected BGV public key component one",
        )?;
        validate_residue_polynomial_shape(
            &ballot.ciphertext.components[0][limb_index],
            modulus,
            "direct ballot projected BGV ciphertext component zero",
        )?;
        validate_residue_polynomial_shape(
            &ballot.ciphertext.components[1][limb_index],
            modulus,
            "direct ballot projected BGV ciphertext component one",
        )?;
    }

    Ok(())
}

fn negacyclic_adjoint_multiply(
    public_component: &[u64],
    projection_coefficients: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    validate_residue_polynomial_shape(
        public_component,
        modulus,
        "direct ballot projected BGV public key adjoint input",
    )?;
    validate_residue_polynomial_shape(
        projection_coefficients,
        modulus,
        "direct ballot projected BGV projection input",
    )?;

    let mut adjoint_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    adjoint_coefficients[0] = public_component[0];
    for coefficient_index in 1..POLYNOMIAL_DEGREE {
        let reflected_coefficient = public_component[POLYNOMIAL_DEGREE - coefficient_index];
        adjoint_coefficients[coefficient_index] = if reflected_coefficient == 0 {
            0
        } else {
            modulus - reflected_coefficient
        };
    }

    negacyclic_mul(&adjoint_coefficients, projection_coefficients, modulus)
}

fn sample_direct_ballot_projected_bgv_projection(
    statement_hash: &[u8; 64],
    limb_index: usize,
    component: DirectBallotProjectedBgvComponent,
    projection_index: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    if modulus <= 1 {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV relation modulus must be greater than one",
        ));
    }

    (0..POLYNOMIAL_DEGREE)
        .map(|coefficient_index| {
            sample_direct_ballot_projected_bgv_projection_coefficient(
                statement_hash,
                limb_index,
                component,
                projection_index,
                coefficient_index,
                modulus,
            )
        })
        .collect()
}

fn sample_direct_ballot_projected_bgv_projection_coefficient(
    statement_hash: &[u8; 64],
    limb_index: usize,
    component: DirectBallotProjectedBgvComponent,
    projection_index: usize,
    coefficient_index: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    let limb_index_bytes = usize_to_u64_bytes(limb_index)?;
    let projection_index_bytes = usize_to_u64_bytes(projection_index)?;
    let coefficient_index_bytes = usize_to_u64_bytes(coefficient_index)?;
    let modulus_bytes = modulus.to_le_bytes();
    let accepted_zone = (1_u128 << 64) - ((1_u128 << 64) % u128::from(modulus));

    for block_index in 0..usize::MAX {
        let block_index_bytes = usize_to_u64_bytes(block_index)?;
        let hash_block = hash512(
            DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTION_DOMAIN,
            &[
                statement_hash,
                &limb_index_bytes,
                &modulus_bytes,
                component.domain_tag(),
                &projection_index_bytes,
                &coefficient_index_bytes,
                &block_index_bytes,
            ],
        );
        for candidate_bytes in hash_block.chunks_exact(8) {
            let mut candidate_array = [0_u8; 8];
            candidate_array.copy_from_slice(candidate_bytes);
            let candidate = u64::from_le_bytes(candidate_array);
            if u128::from(candidate) < accepted_zone {
                return Ok((u128::from(candidate) % u128::from(modulus)) as u64);
            }
        }
    }

    Err(invalid_direct_ballot_relation_proof(
        "direct ballot projected BGV projection sampler exhausted its counter space",
    ))
}

fn plaintext_scaled_projection(
    projection_coefficients: &[u64],
    witness_coefficients: &[BigInt],
    modulus: u64,
    label: &str,
) -> CanonicalResult<u64> {
    let projection = signed_polynomial_linear_combination(
        projection_coefficients,
        witness_coefficients,
        modulus,
        label,
    )?;
    mul_mod(PLAINTEXT_MODULUS % modulus, projection, modulus)
}

fn score_linear_combination(
    score_coefficients: &[u64],
    score_witnesses: &[BigInt],
    modulus: u64,
) -> CanonicalResult<u64> {
    if score_coefficients.len() != DIRECT_BALLOT_OPTION_COUNT
        || score_witnesses.len() != DIRECT_BALLOT_OPTION_COUNT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV score relation must have one scalar per option",
        ));
    }

    let mut output = 0_u64;
    for (score_coefficient, score_witness) in score_coefficients.iter().zip(score_witnesses) {
        if *score_coefficient >= modulus {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot projected BGV score coefficient is not canonical",
            ));
        }
        output = add_mod(
            output,
            mul_mod(
                *score_coefficient,
                signed_bigint_residue(score_witness, modulus)?,
                modulus,
            )?,
            modulus,
        )?;
    }

    Ok(output)
}

fn plaintext_scaled_integer_projection(
    projection_coefficients: &[u64],
    witness_coefficients: &[BigInt],
    modulus: u64,
    label: &str,
) -> CanonicalResult<BigInt> {
    Ok(BigInt::from(PLAINTEXT_MODULUS)
        * signed_polynomial_integer_linear_combination(
            projection_coefficients,
            witness_coefficients,
            modulus,
            label,
        )?)
}

fn score_integer_linear_combination(
    score_coefficients: &[u64],
    score_witnesses: &[BigInt],
    modulus: u64,
) -> CanonicalResult<BigInt> {
    if score_coefficients.len() != DIRECT_BALLOT_OPTION_COUNT
        || score_witnesses.len() != DIRECT_BALLOT_OPTION_COUNT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV score relation must have one scalar per option",
        ));
    }

    let mut output = BigInt::zero();
    for (score_coefficient, score_witness) in score_coefficients.iter().zip(score_witnesses) {
        if *score_coefficient >= modulus {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot projected BGV score coefficient is not canonical",
            ));
        }
        output += BigInt::from(*score_coefficient) * score_witness;
    }

    Ok(output)
}

fn signed_polynomial_integer_linear_combination(
    coefficients: &[u64],
    witness_coefficients: &[BigInt],
    modulus: u64,
    label: &str,
) -> CanonicalResult<BigInt> {
    if coefficients.len() != POLYNOMIAL_DEGREE || witness_coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} must match the polynomial degree"
        )));
    }

    let mut output = BigInt::zero();
    for (coefficient, witness_coefficient) in coefficients.iter().zip(witness_coefficients) {
        if *coefficient >= modulus {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "{label} coefficient is not canonical"
            )));
        }
        output += BigInt::from(*coefficient) * witness_coefficient;
    }

    Ok(output)
}

fn signed_polynomial_linear_combination(
    coefficients: &[u64],
    witness_coefficients: &[BigInt],
    modulus: u64,
    label: &str,
) -> CanonicalResult<u64> {
    if coefficients.len() != POLYNOMIAL_DEGREE || witness_coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} must match the polynomial degree"
        )));
    }

    let mut output = 0_u64;
    for (coefficient, witness_coefficient) in coefficients.iter().zip(witness_coefficients) {
        if *coefficient >= modulus {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "{label} coefficient is not canonical"
            )));
        }
        output = add_mod(
            output,
            mul_mod(
                *coefficient,
                signed_bigint_residue(witness_coefficient, modulus)?,
                modulus,
            )?,
            modulus,
        )?;
    }

    Ok(output)
}

fn residue_coefficient_sum(
    coefficients: &[u64],
    modulus: u64,
    label: &str,
) -> CanonicalResult<BigInt> {
    let mut sum = BigInt::zero();
    for coefficient in coefficients {
        if *coefficient >= modulus {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "{label} coefficient is not canonical"
            )));
        }
        sum += BigInt::from(*coefficient);
    }

    Ok(sum)
}

fn maximum_unsigned_bigint_with_bits(bit_count: usize) -> BigInt {
    (BigInt::from(1_u8) << bit_count) - BigInt::from(1_u8)
}

fn ceil_div_nonnegative_bigint_by_u64(value: &BigInt, modulus: u64) -> CanonicalResult<BigInt> {
    if value.sign() == Sign::Minus {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV quotient bound input must be non-negative",
        ));
    }
    if modulus <= 1 {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV quotient bound modulus must be greater than one",
        ));
    }
    let modulus_bigint = BigInt::from(modulus);
    Ok((value + &modulus_bigint - BigInt::from(1_u8)) / modulus_bigint)
}

fn euclidean_division_by_modulus(
    value: &BigInt,
    modulus: u64,
) -> CanonicalResult<(BigInt, BigInt)> {
    if modulus <= 1 {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot projected BGV no-wrap modulus must be greater than one",
        ));
    }
    let modulus_bigint = BigInt::from(modulus);
    let mut quotient = value / &modulus_bigint;
    let mut remainder = value % &modulus_bigint;
    if remainder.sign() == Sign::Minus {
        remainder += &modulus_bigint;
        quotient -= 1;
    }

    Ok((quotient, remainder))
}

fn residue_dot_product(
    left: &[u64],
    right: &[u64],
    modulus: u64,
    label: &str,
) -> CanonicalResult<u64> {
    if left.len() != POLYNOMIAL_DEGREE || right.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} must match the polynomial degree"
        )));
    }

    let mut output = 0_u64;
    for (left_coefficient, right_coefficient) in left.iter().zip(right) {
        if *left_coefficient >= modulus || *right_coefficient >= modulus {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "{label} coefficient is not canonical"
            )));
        }
        output = add_mod(
            output,
            mul_mod(*left_coefficient, *right_coefficient, modulus)?,
            modulus,
        )?;
    }

    Ok(output)
}

fn validate_residue_polynomial_shape(
    polynomial: &[u64],
    modulus: u64,
    label: &str,
) -> CanonicalResult<()> {
    if polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} must match the polynomial degree"
        )));
    }
    if polynomial.iter().any(|coefficient| *coefficient >= modulus) {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} has a non-canonical coefficient"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::bgv::setup::public_bgv_key_from_passive_setup_package;

    const PROJECTED_RELATION_TEST_SETUP_SEED: &str =
        "direct-ballot-projected-bgv-relation-test-seed";

    struct ProjectedRelationFixture {
        setup_package: Value,
        public_key: BgvPublicKey,
        ballot: DirectEncryptedBallot,
    }

    fn projected_relation_fixture() -> &'static ProjectedRelationFixture {
        static FIXTURE: OnceLock<ProjectedRelationFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let setup_package =
                crate::bgv::commands::generate_bgv_passive_setup_from_request(&json!({
                    "ceremonyId": "direct-ballot-projected-bgv-relation-test-ceremony",
                    "manifestHash": derive_protocol_hash(
                        "ElectionManifestHash",
                        &json!({ "manifest": "direct ballot projected BGV relation test" }),
                    ).expect("manifest hash"),
                    "rosterHash": derive_protocol_hash(
                        "RosterHash",
                        &json!({ "roster": "direct ballot projected BGV relation test" }),
                    ).expect("roster hash"),
                    "thresholdProfileHash": derive_protocol_hash(
                        "ThresholdProfileHash",
                        &json!({ "threshold": "direct ballot projected BGV relation test" }),
                    ).expect("threshold hash"),
                    "participants": [
                        { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 0 },
                        { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 1 },
                        { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 2 }
                    ],
                    "setupSeed": PROJECTED_RELATION_TEST_SETUP_SEED
                }))
                .expect("setup package");
            let public_key =
                public_bgv_key_from_passive_setup_package(&setup_package).expect("public key");
            let ballot = super::super::super::encrypt_direct_ballot(
                &setup_package,
                &public_key,
                super::super::super::DirectBallotInput {
                    voter_identity: "projected-relation-voter".to_string(),
                    voter_roster_position: 0,
                    action_context_hash: derive_protocol_hash(
                        "ActionContextHash",
                        &json!({ "action": "direct ballot projected BGV relation test" }),
                    )
                    .expect("action context hash"),
                    recovery_epoch: 0,
                    device_epoch: 0,
                    scores: vec![10, 1, 9, 2, 8, 3, 7, 4, 6, 5, 5, 6, 4, 7, 3, 8, 2, 9, 1, 10],
                    one_hot_witnesses: None,
                    encryption_seed_hex: hash512_hex(
                        "sealed-lattice/direct-encrypted-ballot/projected-relation-test-seed-v1",
                        &[PROJECTED_RELATION_TEST_SETUP_SEED.as_bytes()],
                    )[..64]
                        .to_string(),
                },
            )
            .expect("ballot");

            ProjectedRelationFixture {
                setup_package,
                public_key,
                ballot,
            }
        })
    }

    #[test]
    fn direct_ballot_projected_bgv_rows_match_valid_witness() {
        let fixture = projected_relation_fixture();
        let statement_hash = direct_ballot_relation_statement_hash(
            &fixture.setup_package,
            &fixture.public_key,
            &fixture.ballot,
        )
        .expect("statement hash");
        let witness_vector =
            direct_ballot_witness_vector(&statement_hash, &fixture.public_key, &fixture.ballot)
                .expect("witness");

        verify_direct_ballot_projected_bgv_relation_witness(
            &statement_hash,
            &fixture.public_key,
            &fixture.ballot,
            &witness_vector,
            1,
        )
        .expect("projected BGV relation verifies");
    }

    #[test]
    fn direct_ballot_projected_bgv_rows_reject_public_and_witness_mutations() {
        let fixture = projected_relation_fixture();
        let statement_hash = direct_ballot_relation_statement_hash(
            &fixture.setup_package,
            &fixture.public_key,
            &fixture.ballot,
        )
        .expect("statement hash");
        let witness_vector =
            direct_ballot_witness_vector(&statement_hash, &fixture.public_key, &fixture.ballot)
                .expect("witness");
        let row = first_projected_component_zero_row(&statement_hash, fixture);
        assert_eq!(
            evaluate_direct_ballot_projected_bgv_relation_row(&row, &witness_vector)
                .expect("valid row"),
            0
        );

        let mutation_coefficient_index = row
            .projection_coefficients
            .iter()
            .position(|coefficient| *coefficient != 0)
            .expect("projection has a non-zero coefficient");
        let mut mutated_ballot = fixture.ballot.clone();
        mutated_ballot.ciphertext.components[row.component.index()][row.limb_index]
            [mutation_coefficient_index] = add_mod(
            mutated_ballot.ciphertext.components[row.component.index()][row.limb_index]
                [mutation_coefficient_index],
            1,
            row.modulus,
        )
        .expect("mutated ciphertext residue");
        let (public_component_zero, _) = fixture.public_key.public_key_components();
        let mutated_row = compile_direct_ballot_projected_bgv_relation_row(
            DirectBallotProjectedBgvRelationRowInput {
                statement_hash: &statement_hash,
                public_component: &public_component_zero[row.limb_index],
                ciphertext_component: &mutated_ballot.ciphertext.components[row.component.index()]
                    [row.limb_index],
                score_encoding_basis: direct_ballot_score_encoding_basis()
                    .expect("score encoding basis"),
                limb_index: row.limb_index,
                component: row.component,
                projection_index: row.projection_index,
                modulus: row.modulus,
            },
        )
        .expect("mutated row");
        assert_ne!(
            evaluate_direct_ballot_projected_bgv_relation_row(&mutated_row, &witness_vector)
                .expect("mutated ciphertext row"),
            0
        );

        let mut mutated_error_witness = witness_vector.clone();
        mutated_error_witness.error_zero_coefficients[mutation_coefficient_index] += 1_u8;
        assert_ne!(
            evaluate_direct_ballot_projected_bgv_relation_row(&row, &mutated_error_witness)
                .expect("mutated error witness row"),
            0
        );

        let mut mutated_carry_witness = witness_vector.clone();
        mutated_carry_witness.encoding_carry_coefficients[mutation_coefficient_index] += 1_u8;
        assert_ne!(
            evaluate_direct_ballot_projected_bgv_relation_row(&row, &mutated_carry_witness)
                .expect("mutated carry witness row"),
            0
        );

        let score_mutation_index = row
            .score_coefficients
            .iter()
            .position(|coefficient| *coefficient != 0)
            .expect("score projection has a non-zero coefficient");
        let mut mutated_score_witness = witness_vector.clone();
        mutated_score_witness.score_coefficients[score_mutation_index] += 1_u8;
        assert_ne!(
            evaluate_direct_ballot_projected_bgv_relation_row(&row, &mutated_score_witness)
                .expect("mutated score witness row"),
            0
        );
    }

    #[test]
    fn direct_ballot_projected_bgv_adjoint_matches_full_product_projection() {
        let fixture = projected_relation_fixture();
        let statement_hash = direct_ballot_relation_statement_hash(
            &fixture.setup_package,
            &fixture.public_key,
            &fixture.ballot,
        )
        .expect("statement hash");
        let (public_component_zero, _) = fixture.public_key.public_key_components();
        let modulus = DATA_PRIMES[DATA_PRIMES.len() / 2];
        let limb_index = DATA_PRIMES.len() / 2;
        let projection_coefficients = sample_direct_ballot_projected_bgv_projection(
            &statement_hash,
            limb_index,
            DirectBallotProjectedBgvComponent::ComponentZero,
            3,
            modulus,
        )
        .expect("projection");
        let randomizer_residues = signed_polynomial_residues(
            &direct_ballot_witness_vector(&statement_hash, &fixture.public_key, &fixture.ballot)
                .expect("witness")
                .randomizer_coefficients,
            modulus,
            "projected BGV test randomizer",
        )
        .expect("randomizer residues");
        let full_product = negacyclic_mul(
            &public_component_zero[limb_index],
            &randomizer_residues,
            modulus,
        )
        .expect("full product");
        let full_projection = residue_dot_product(
            &projection_coefficients,
            &full_product,
            modulus,
            "projected BGV full product",
        )
        .expect("full projection");
        let adjoint_projection_coefficients = negacyclic_adjoint_multiply(
            &public_component_zero[limb_index],
            &projection_coefficients,
            modulus,
        )
        .expect("adjoint product");
        let adjoint_projection = residue_dot_product(
            &adjoint_projection_coefficients,
            &randomizer_residues,
            modulus,
            "projected BGV adjoint product",
        )
        .expect("adjoint projection");

        assert_eq!(full_projection, adjoint_projection);
    }

    #[test]
    fn direct_ballot_projected_bgv_no_wrap_bounds_cover_fixture_and_reject_overflow() {
        let fixture = projected_relation_fixture();
        let statement_hash = direct_ballot_relation_statement_hash(
            &fixture.setup_package,
            &fixture.public_key,
            &fixture.ballot,
        )
        .expect("statement hash");
        let witness_vector =
            direct_ballot_witness_vector(&statement_hash, &fixture.public_key, &fixture.ballot)
                .expect("witness");
        let proof_randomness_seed_hex = hash512_hex(
            "sealed-lattice/direct-encrypted-ballot/projected-bgv-bound-test-seed-v1",
            &[PROJECTED_RELATION_TEST_SETUP_SEED.as_bytes()],
        )[..64]
            .to_string();
        let mask_vector = sample_direct_ballot_relation_mask_vector(
            &statement_hash,
            &fixture.public_key,
            &fixture.ballot,
            &proof_randomness_seed_hex,
        )
        .expect("mask vector");
        let rows = compile_direct_ballot_projected_bgv_relation_rows(
            &statement_hash,
            &fixture.public_key,
            &fixture.ballot,
            DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
        )
        .expect("projected rows");
        let maximum_challenge =
            maximum_unsigned_bigint_with_bits(DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS as usize);

        for (row_index, row) in rows.iter().enumerate() {
            let bounds =
                direct_ballot_projected_bgv_no_wrap_carry_bounds(row).expect("carry bounds");
            validate_direct_ballot_projected_bgv_no_wrap_carry_bound(
                &witness_vector.bgv_no_wrap_carry_scalars[row_index],
                &bounds.witness_quotient_maximum_abs,
                "fixture witness carry",
            )
            .expect("witness carry is bounded");
            validate_direct_ballot_projected_bgv_no_wrap_carry_bound(
                &mask_vector.bgv_no_wrap_carry_scalars[row_index],
                &bounds.mask_quotient_maximum_abs,
                "fixture mask carry",
            )
            .expect("mask carry is bounded");

            let maximum_response_carry = &mask_vector.bgv_no_wrap_carry_scalars[row_index]
                + &maximum_challenge * &witness_vector.bgv_no_wrap_carry_scalars[row_index];
            validate_direct_ballot_projected_bgv_no_wrap_carry_bound(
                &maximum_response_carry,
                &bounds.response_quotient_maximum_abs,
                "fixture response carry",
            )
            .expect("response carry is bounded");

            let oversized_response_carry = &bounds.response_quotient_maximum_abs + 1_u8;
            let error = validate_direct_ballot_projected_bgv_no_wrap_carry_bound(
                &oversized_response_carry,
                &bounds.response_quotient_maximum_abs,
                "oversized response carry",
            )
            .expect_err("oversized carry must reject");
            assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
            assert!(
                error
                    .message
                    .contains("exceeds the arithmetic quotient bound")
            );
        }
    }

    fn first_projected_component_zero_row(
        statement_hash: &[u8; 64],
        fixture: &ProjectedRelationFixture,
    ) -> DirectBallotProjectedBgvRelationRow {
        let (public_component_zero, _) = fixture.public_key.public_key_components();
        compile_direct_ballot_projected_bgv_relation_row(DirectBallotProjectedBgvRelationRowInput {
            statement_hash,
            public_component: &public_component_zero[0],
            ciphertext_component: &fixture.ballot.ciphertext.components[0][0],
            score_encoding_basis: direct_ballot_score_encoding_basis()
                .expect("score encoding basis"),
            limb_index: 0,
            component: DirectBallotProjectedBgvComponent::ComponentZero,
            projection_index: 0,
            modulus: DATA_PRIMES[0],
        })
        .expect("projected relation row")
    }
}
