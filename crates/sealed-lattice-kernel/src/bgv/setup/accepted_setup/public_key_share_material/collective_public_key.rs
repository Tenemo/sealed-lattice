use super::*;

pub(in crate::bgv::setup) fn accepted_setup_collective_public_key_from_package(
    setup_package: &Value,
) -> CanonicalResult<BgvPublicKey> {
    let aggregate_object = setup_package.get("collectivePublicKey").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "collectivePublicKey was required before accepted public-key runtime loading",
        )
    })?;
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before accepted public-key runtime loading",
        )
    })?;
    let public_matrix_seed_hash = value_string(common_randomness, "publicMatrixSeedHash")?;
    if value_string(aggregate_object, "publicMatrixSeedHash")? != public_matrix_seed_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "collective public key must bind the accepted public matrix seed",
        ));
    }
    let roster = super::accepted_roster_from_package(setup_package);
    let expected_public_derivations = derive_collective_bgv_setup_public_derivations(
        public_matrix_seed_hash,
        roster.decryption_threshold,
    )?;
    if common_randomness.get("publicDerivations") != Some(&expected_public_derivations) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted public-key runtime loading requires canonical public derivations",
        ));
    }
    let expected_public_a = derive_bgv_public_a_polynomial(public_matrix_seed_hash)?;
    if value_string(aggregate_object, "publicAPolynomialRoot")?
        != value_string(&expected_public_a, "publicPolynomialRoot")?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "collective public key must bind the accepted BGV public a polynomial",
        ));
    }
    if value_u64(aggregate_object, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "accepted collective public-key runtime material requires full-ring aggregate coefficients",
        ));
    }
    let public_b = collective_public_key_component_b_from_aggregate_object(aggregate_object)?;
    let public_a = DATA_PRIMES
        .iter()
        .copied()
        .map(|modulus| {
            dense_public_residues(public_matrix_seed_hash, "accepted-bgv-public-a", modulus)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    BgvPublicKey::from_components(public_b, public_a)
}

pub(super) fn collective_public_key_component_b_from_aggregate_object(
    aggregate_object: &Value,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let aggregate_limbs = aggregate_object
        .get("aggregateCoefficientVectorsByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collectivePublicKey.aggregateCoefficientVectorsByLimb is required",
            )
        })?;
    if aggregate_limbs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key must contain one runtime component-b limb per Q_share prime",
        ));
    }
    let mut public_b = Vec::with_capacity(DATA_PRIMES.len());
    for (rns_limb_index, aggregate_limb) in aggregate_limbs.iter().enumerate() {
        if aggregate_limb.get("rnsLimbIndex").and_then(Value::as_u64) != Some(rns_limb_index as u64)
            || aggregate_limb.get("rnsPrime").and_then(Value::as_u64)
                != Some(DATA_PRIMES[rns_limb_index])
            || aggregate_limb.get("component").and_then(Value::as_str) != Some("b")
            || aggregate_limb
                .get("coefficientByteLength")
                .and_then(Value::as_u64)
                != Some((POLYNOMIAL_DEGREE * 8) as u64)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "collective public-key runtime limb metadata must follow Q_share order",
            ));
        }
        let coefficients = coefficient_vector_from_le_hex(
            value_string(aggregate_limb, "coefficientsLeHex")?,
            POLYNOMIAL_DEGREE,
            "collective public-key runtime coefficient vector width must match the full ring degree",
        )?;
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= DATA_PRIMES[rns_limb_index])
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collective public-key runtime component contains non-canonical Q_share residues",
            ));
        }
        let coefficient_hash = public_key_share_coefficient_vector_hash(&coefficients);
        if aggregate_limb
            .get("coefficientVectorHash512")
            .and_then(Value::as_str)
            != Some(coefficient_hash.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "collective public-key runtime component hash must match the aggregate coefficients",
            ));
        }
        public_b.push(coefficients);
    }

    Ok(public_b)
}

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
        .get("aggregateCoefficientVectorsByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collectivePublicKey.aggregateCoefficientVectorsByLimb is required",
            )
        })?;
    if aggregate_limbs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key must contain one aggregate coefficient vector per Q_share limb",
        ));
    }
    let expected_share_material_roots = material_bindings
        .values()
        .map(|binding| {
            json!({
                "trusteeIdentity": binding.trustee_identity,
                "trusteeRosterPosition": binding.trustee_roster_position,
                "publicKeyShareRoot": binding.public_key_share_root,
                "publicKeyShareMaterialRoot": binding.public_key_share_material_root,
            })
        })
        .collect::<Vec<_>>();
    if aggregate_object.get("sourceShareMaterialRoots")
        != Some(&Value::Array(expected_share_material_roots))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "collective public key must bind the ordered verified share material roots",
        ));
    }
    for (rns_limb_index, aggregate_limb) in aggregate_limbs.iter().enumerate() {
        if aggregate_limb.get("rnsLimbIndex").and_then(Value::as_u64) != Some(rns_limb_index as u64)
            || aggregate_limb.get("rnsPrime").and_then(Value::as_u64)
                != Some(DATA_PRIMES[rns_limb_index])
            || aggregate_limb.get("component").and_then(Value::as_str) != Some("b")
            || aggregate_limb
                .get("coefficientByteLength")
                .and_then(Value::as_u64)
                != Some((ring_degree * 8) as u64)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "collective public-key aggregate limb metadata must follow Q_share order",
            ));
        }
        let coefficients = coefficient_vector_from_le_hex(
            value_string(aggregate_limb, "coefficientsLeHex")?,
            ring_degree,
            "collective public-key coefficient vector width does not match the material ring degree",
        )?;
        let modulus = DATA_PRIMES[rns_limb_index];
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
        let coefficient_hash = public_key_share_coefficient_vector_hash(&coefficients);
        if aggregate_limb
            .get("coefficientVectorHash512")
            .and_then(Value::as_str)
            != Some(coefficient_hash.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "collective public-key aggregate coefficient hash must match the aggregate coefficients",
            ));
        }
    }

    Ok(())
}
