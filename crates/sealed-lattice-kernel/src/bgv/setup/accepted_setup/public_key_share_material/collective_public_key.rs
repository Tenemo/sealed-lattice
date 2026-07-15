use super::*;

pub(super) fn verify_collective_public_key_coefficients(
    aggregate_object: &Value,
    material_bindings: &BTreeMap<u64, PublicKeyShareMaterialBinding>,
    ring_degree: usize,
    participant_count: u64,
) -> CanonicalResult<()> {
    if material_bindings.len() != participant_count as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public-key aggregation requires one verified share material record per trustee",
        ));
    }
    let aggregate_limbs = aggregate_object
        .get("aggregateCoefficientVectorsLittleEndianHexByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collectivePublicKey.aggregateCoefficientVectorsLittleEndianHexByLimb is required",
            )
        })?;
    if aggregate_limbs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key must contain one aggregate coefficient vector per Q_share limb",
        ));
    }
    for (rns_limb_index, aggregate_limb) in aggregate_limbs.iter().enumerate() {
        let coefficients = coefficient_vector_from_le_hex(
            aggregate_limb.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "collective public-key coefficient vectors must be strings",
                )
            })?,
            ring_degree,
            "collective public-key coefficient vector width does not match the material ring degree",
        )?;
        let modulus = DATA_PRIMES[rns_limb_index];
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= modulus)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collective public-key aggregate contains non-canonical Q_share residues",
            ));
        }
        let mut expected_coefficients = vec![0_u64; ring_degree];
        for material_binding in material_bindings.values() {
            let share_coefficients = material_binding
                .coefficients_by_limb
                .get(rns_limb_index)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material is missing an aggregate limb",
                    )
                })?;
            if share_coefficients.len() != ring_degree {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material width does not match collective public-key width",
                ));
            }
            // Each share b_i already equals p*e_i - a*s_i over its limb against the common a, so the modular sum is the collective public key B = p*E - a*S with collective secret S = sum of s_i.
            for (coefficient_index, share_coefficient) in share_coefficients.iter().enumerate() {
                expected_coefficients[coefficient_index] = add_mod(
                    expected_coefficients[coefficient_index],
                    *share_coefficient,
                    modulus,
                )?;
            }
        }
        if coefficients != expected_coefficients {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "collective public-key aggregate coefficients must equal the sum of verified public-key shares",
            ));
        }
    }

    Ok(())
}
