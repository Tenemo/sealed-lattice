use super::opening::*;
use super::*;

pub(in super::super) fn linear_combination_setup_commitments(
    terms: &[(&SetupCommitmentValue, u128)],
) -> CanonicalResult<SetupCommitmentValue> {
    let Some((first_commitment, _)) = terms.first() else {
        return Err(invalid_commitment_input(
            "at least one commitment is required for a linear combination",
        ));
    };
    let mut combined_commitment = (*first_commitment).clone();
    for limb in &mut combined_commitment.limbs {
        for row in &mut limb.rows {
            row.fill(0);
        }
    }

    for (commitment, scalar) in terms {
        validate_same_commitment_domain(first_commitment, commitment)?;
        for (combined_limb, term_limb) in combined_commitment
            .limbs
            .iter_mut()
            .zip(commitment.limbs.iter())
        {
            let modulus = combined_limb.modulus;
            let scalar_residue = u64::try_from(*scalar % u128::from(modulus)).map_err(|_| {
                invalid_commitment_input("commitment linear-combination scalar does not fit u64")
            })?;
            for (combined_row, term_row) in combined_limb.rows.iter_mut().zip(term_limb.rows.iter())
            {
                for (combined_value, term_value) in combined_row.iter_mut().zip(term_row.iter()) {
                    *combined_value = add_mod_fast(
                        *combined_value,
                        mul_mod_fast(*term_value, scalar_residue, modulus),
                        modulus,
                    );
                }
            }
        }
    }

    Ok(combined_commitment)
}
